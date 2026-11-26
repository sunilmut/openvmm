// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::deferred::DeferredToken;
use chipset_device::pci::PciConfigByteEnable;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Wake};
use test_with_tracing::test;
use vmcore::save_restore::SaveRestore;

#[derive(Default)]
struct Ports {
    active: Arc<Mutex<Vec<RangeInclusive<u16>>>>,
}

struct PortLease {
    active: Arc<Mutex<Vec<RangeInclusive<u16>>>>,
    range: RangeInclusive<u16>,
}

impl Drop for PortLease {
    fn drop(&mut self) {
        self.active.lock().retain(|r| *r != self.range);
    }
}

impl RegisterHostIoPortFastPath for Ports {
    fn register(&self, range: RangeInclusive<u16>) -> Box<dyn Send> {
        self.active.lock().push(range.clone());
        Box::new(PortLease {
            active: self.active.clone(),
            range,
        })
    }
}

enum HostRequest {
    Read(u16, mesh::OneshotSender<u32>),
    Write(u16, u32, mesh::OneshotSender<()>),
}

#[derive(Default)]
struct Host {
    requests: Mutex<VecDeque<HostRequest>>,
}

#[async_trait::async_trait]
impl ProxyVgaPciCfgAccess for Host {
    async fn vga_proxy_pci_read(&self, offset: u16) -> u32 {
        let (send, recv) = mesh::oneshot();
        self.requests
            .lock()
            .push_back(HostRequest::Read(offset, send));
        recv.await.unwrap()
    }

    async fn vga_proxy_pci_write(&self, offset: u16, value: u32) {
        let (send, recv) = mesh::oneshot();
        self.requests
            .lock()
            .push_back(HostRequest::Write(offset, value, send));
        recv.await.unwrap()
    }
}

impl Host {
    // Observe the next request at the host interface, not proxy-device state.
    fn next(&self) -> HostRequest {
        self.requests.lock().pop_front().unwrap()
    }
}

#[derive(Default)]
struct WakeFlag(AtomicBool);

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// Require an asynchronously completed PCI operation.
fn deferred(result: IoResult) -> DeferredToken {
    let IoResult::Defer(token) = result else {
        panic!("expected deferred PCI access");
    };
    token
}

// Test: Register VGA fast-path ports, reject a straddling PIO and drop queued IO.
// Expected: Read buffers stay unchanged, the outstanding read reports NoResponse,
//       and dropping the device releases every host port lease.
#[test]
fn host_port_leases_and_abandoned_reads_follow_device_lifetime() {
    let ports = Ports::default();
    let mut device = VgaProxyDevice::new(Arc::new(Host::default()), &ports);
    assert_eq!(
        *ports.active.lock(),
        [0x4ae8..=0x4ae9, 0x3b0..=0x3bf, 0x3c0..=0x3cf, 0x3d0..=0x3df]
    );
    let mut bytes = [0xa5; 2];
    let pio = device.supports_pio().unwrap();
    assert!(matches!(
        pio.io_read(0x3cf, &mut bytes),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert_eq!(bytes, [0xa5; 2]);
    assert!(matches!(
        pio.io_write(0x3cf, &[1, 2]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert_eq!(pio.get_static_regions()[2].1, 0x3c0..=0x3cf);
    let mut value = 0;
    let mut token = deferred(device.supports_pci().unwrap().pci_cfg_read(
        0x10,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
    ));
    drop(device);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        token.poll_read(&mut cx, &mut [0; 4]),
        Poll::Ready(Err(IoError::NoResponse))
    ));
    assert!(ports.active.lock().is_empty());
}

// Test: Complete two host reads out of order across a proxy lifecycle transition.
// Expected: Each token receives its own exact DWORD, pending buffers stay intact,
//       and host/queue readiness wakes the poller without losing accepted work.
#[test]
fn pending_reads_keep_their_identity_across_lifecycle_transitions() {
    let host = Arc::new(Host::default());
    let mut device = VgaProxyDevice::new(host.clone(), &Ports::default());
    let wake = Arc::new(WakeFlag::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    device.supports_poll_device().unwrap().poll_device(&mut cx);
    let mut value = 0;
    let mut first = deferred(device.pci_cfg_read(
        0x10,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
    ));
    assert!(wake.0.swap(false, Ordering::SeqCst));
    let mut second = deferred(device.pci_cfg_read(
        0x14,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
    ));
    device.poll_device(&mut cx);
    let HostRequest::Read(0x10, first_reply) = host.next() else {
        panic!("expected the first host read");
    };
    let HostRequest::Read(0x14, second_reply) = host.next() else {
        panic!("expected the second host read");
    };
    let mut bytes = [0xa5; 4];
    assert!(first.poll_read(&mut cx, &mut bytes).is_pending());
    second_reply.send(0x55667788);
    assert!(wake.0.swap(false, Ordering::SeqCst));
    device.poll_device(&mut cx);
    assert!(matches!(
        second.poll_read(&mut cx, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [0x88, 0x77, 0x66, 0x55]);
    bytes.fill(0xa5);
    assert!(first.poll_read(&mut cx, &mut bytes).is_pending());
    assert_eq!(bytes, [0xa5; 4]);
    device.start();
    assert!(std::pin::pin!(device.stop()).poll(&mut cx).is_ready());
    let saved = device.save().unwrap();
    device.restore(saved).unwrap();
    assert!(std::pin::pin!(device.reset()).poll(&mut cx).is_ready());
    device.start();
    first_reply.send(0x11223344);
    device.poll_device(&mut cx);
    assert!(matches!(
        first.poll_read(&mut cx, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [0x44, 0x33, 0x22, 0x11]);
}

// Test: Forward full, single-lane and noncontiguous-lane PCI writes.
// Expected: Full writes bypass a host read; partial writes preserve disabled
//       lanes, and completion is withheld until the host acknowledges the write.
#[test]
fn writes_preserve_byte_lanes_and_wait_for_host_acknowledgment() {
    for (enable, value, expected) in [
        (PciConfigByteEnable::FULL, 0x11223344, 0x11223344),
        (PciConfigByteEnable::BYTE2, 0x00550000, 0xa155c3d4),
        (
            PciConfigByteEnable::new(0b0101).unwrap(),
            0x11223344,
            0xa122c344,
        ),
    ] {
        let host = Arc::new(Host::default());
        let mut device = VgaProxyDevice::new(host.clone(), &Ports::default());
        let mut cx = Context::from_waker(Waker::noop());
        let mut token =
            deferred(device.pci_cfg_write(0x10, ByteEnabledDwordWrite::new(value, enable)));
        device.poll_device(&mut cx);
        if !enable.is_full() {
            let HostRequest::Read(0x10, reply) = host.next() else {
                panic!("expected the partial-write host read");
            };
            assert!(token.poll_write(&mut cx).is_pending());
            reply.send(0xa1b2c3d4);
            device.poll_device(&mut cx);
        }
        let HostRequest::Write(0x10, value, reply) = host.next() else {
            panic!("expected the host write");
        };
        assert_eq!(value, expected);
        assert!(token.poll_write(&mut cx).is_pending());
        reply.send(());
        device.poll_device(&mut cx);
        assert!(matches!(token.poll_write(&mut cx), Poll::Ready(Ok(()))));
    }
}

struct CommandStatus(AtomicU32);

#[async_trait::async_trait]
impl ProxyVgaPciCfgAccess for CommandStatus {
    async fn vga_proxy_pci_read(&self, offset: u16) -> u32 {
        assert_eq!(offset, 4);
        self.0.load(Ordering::SeqCst)
    }

    async fn vga_proxy_pci_write(&self, offset: u16, value: u32) {
        assert_eq!(offset, 4);
        // Model PCI Status write-one-to-clear bits beside the writable Command.
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                Some((old & !value & 0xffff0000) | (value & 0xffff))
            })
            .unwrap();
    }
}

// IGNORED: Reproduced a product bug: a partial write echoes unselected W1C
//       Status bits back to the host, clearing them during a Command-only write.
//
// Test: Enable memory decoding while a PCI Status parity-error bit is set.
// Expected: A low-word Command write leaves the unselected W1C Status bit set.
#[test]
#[ignore = "product bug: partial Command writes clear unselected W1C Status bits"]
fn command_write_does_not_clear_unselected_pci_status() {
    let host = Arc::new(CommandStatus(AtomicU32::new(0x80000000)));
    let mut device = VgaProxyDevice::new(host.clone(), &Ports::default());
    let mut cx = Context::from_waker(Waker::noop());
    let mut token = deferred(device.pci_cfg_write(
        4,
        ByteEnabledDwordWrite::new(2, PciConfigByteEnable::LOW_WORD),
    ));
    device.poll_device(&mut cx);
    assert!(matches!(token.poll_write(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(host.0.load(Ordering::SeqCst), 0x80000002);
}
