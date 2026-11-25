// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ChipsetDevice;
use crate::io::IoError;
use crate::io::IoResult;
use crate::io::deferred::defer_read;
use crate::io::deferred::defer_write;
use crate::mmio::MmioIntercept;
use crate::mmio::RegisterMmioIntercept;
use crate::pci::ByteEnabledDwordRead;
use crate::pci::ByteEnabledDwordWrite;
use crate::pci::PciConfigAccessType;
use crate::pci::PciConfigAddress;
use crate::pci::PciConfigByteEnable;
use crate::pci::PciConfigSpace;
use crate::pio::PortIoIntercept;
use crate::pio::RegisterPortIoIntercept;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Test: Poll a deferred read before and after the device supplies its data.
// Expected: The caller is woken and receives exactly the completed bytes.
#[test]
fn deferred_read_wakes_and_delivers_data() {
    let (complete, mut token) = defer_read();
    let wake = Arc::new(WakeCounter::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut bytes = [0x55; 3];
    assert!(token.poll_read(&mut cx, &mut bytes).is_pending());
    assert_eq!(bytes, [0x55; 3]);
    complete.complete(&[1, 2, 3]);
    assert!(wake.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        token.poll_read(&mut cx, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [1, 2, 3]);
}

// Test: Complete a deferred read with an error or drop its device-side sender.
// Expected: The caller receives the right error without overwriting its buffer.
#[test]
fn deferred_read_errors_preserve_the_output_buffer() {
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0x55; 2];
    let (complete, mut token) = defer_read();
    complete.complete_error(IoError::InvalidRegister);
    assert!(matches!(
        token.poll_read(&mut cx, &mut bytes),
        Poll::Ready(Err(IoError::InvalidRegister))
    ));
    let (complete, mut token) = defer_read();
    drop(complete);
    assert!(matches!(
        token.poll_read(&mut cx, &mut bytes),
        Poll::Ready(Err(IoError::NoResponse))
    ));
    assert_eq!(bytes, [0x55; 2]);
}

// Test: Poll deferred writes across success, device failure, and sender loss.
// Expected: Pending writes complete with their corresponding public result.
#[test]
fn deferred_writes_report_completion_and_errors() {
    let mut cx = Context::from_waker(Waker::noop());
    let (complete, mut token) = defer_write();
    assert!(token.poll_write(&mut cx).is_pending());
    complete.complete();
    assert!(matches!(token.poll_write(&mut cx), Poll::Ready(Ok(()))));
    let (complete, mut token) = defer_write();
    complete.complete_error(IoError::UnalignedAccess);
    assert!(matches!(
        token.poll_write(&mut cx),
        Poll::Ready(Err(IoError::UnalignedAccess))
    ));
    let (complete, mut token) = defer_write();
    drop(complete);
    assert!(matches!(
        token.poll_write(&mut cx),
        Poll::Ready(Err(IoError::NoResponse))
    ));
}

// Test: Await the convenience futures for deferred reads and writes.
// Expected: Each future waits for device completion and forwards its result.
#[test]
fn deferred_futures_wait_for_completion() {
    let mut cx = Context::from_waker(Waker::noop());
    let (complete, token) = defer_read();
    let mut bytes = [0; 2];
    {
        let mut future = pin!(token.read_future(&mut bytes));
        assert!(future.as_mut().poll(&mut cx).is_pending());
        complete.complete(&[4, 5]);
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    assert_eq!(bytes, [4, 5]);
    let (complete, token) = defer_write();
    let mut future = pin!(token.write_future());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    complete.complete();
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
}

// Test: Complete a deferred read with the wrong number of bytes.
// Expected: Polling rejects the mismatched transfer length.
#[test]
#[should_panic(expected = "defer size mismatch")]
fn deferred_read_rejects_mismatched_sizes() {
    let (complete, mut token) = defer_read();
    complete.complete(&[1]);
    let _ = token.poll_read(&mut Context::from_waker(Waker::noop()), &mut [0; 2]);
}

// Test: Poll a write token as a read.
// Expected: The token rejects the operation-type mismatch.
#[test]
#[should_panic(expected = "defer type mismatch")]
fn write_token_rejects_read_polling() {
    let (_complete, mut token) = defer_write();
    let _ = token.poll_read(&mut Context::from_waker(Waker::noop()), &mut []);
}

// Test: Poll a read token as a write.
// Expected: The token rejects the operation-type mismatch.
#[test]
#[should_panic(expected = "defer type mismatch")]
fn read_token_rejects_write_polling() {
    let (_complete, mut token) = defer_read();
    let _ = token.poll_write(&mut Context::from_waker(Waker::noop()));
}

// Test: Merge all valid PCI lane selections into an existing DWORD.
// Expected: Enabled lanes change and disabled lanes keep their original bytes.
#[test]
fn pci_byte_enables_merge_only_selected_lanes() {
    assert!(PciConfigByteEnable::new(0).is_none());
    assert!(PciConfigByteEnable::new(16).is_none());
    for bits in 1..16 {
        let lanes = PciConfigByteEnable::new(bits).unwrap();
        let mut expected = [0x11u8; 4];
        for (index, byte) in expected.iter_mut().enumerate() {
            if bits & (1 << index) != 0 {
                *byte = 0x99;
            }
        }
        assert_eq!(
            lanes.merge(0x11111111, 0x99999999),
            u32::from_le_bytes(expected)
        );
        assert_eq!(lanes.extract(0x99999999), lanes.mask() & 0x99999999);
        assert_eq!(lanes.is_full(), bits == 15);
        assert_eq!(lanes.restrict(PciConfigByteEnable::FULL), Some(lanes));
        assert!(lanes.exclude(PciConfigByteEnable::FULL).is_none());
    }
}

// Test: Convert PCI intercept buffers to byte-enabled DWORD writes.
// Expected: Each legal access maps bytes to the proper lanes and merges correctly.
#[test]
fn pci_write_buffers_preserve_lane_positions() {
    for (lanes, bytes, expected) in [
        (PciConfigByteEnable::BYTE0, vec![0x11], 0x11),
        (PciConfigByteEnable::BYTE3, vec![0x44], 0x44000000),
        (PciConfigByteEnable::HIGH_WORD, vec![0x33, 0x44], 0x44330000),
        (
            PciConfigByteEnable::FULL,
            vec![0x11, 0x22, 0x33, 0x44],
            0x44332211,
        ),
    ] {
        let value = ByteEnabledDwordWrite::from_intercept_buffer(lanes, &bytes);
        assert_eq!(value.as_valid_byte_slice(), bytes);
        assert_eq!(value.byte_enable(), lanes);
        assert_eq!(value.valid_mask(), lanes.mask());
        assert_eq!(value.is_full(), lanes.is_full());
        assert_eq!(value.extract(), expected);
        assert_eq!(value.extract_low(), expected as u16);
        assert_eq!(value.extract_high(), (expected >> 16) as u16);
        let mut current = 0xaabbccdd;
        value.merge_into(&mut current);
        assert_eq!(current, lanes.merge(0xaabbccdd, expected));
        assert_eq!(value.merge_low(0xccdd), current as u16);
        assert_eq!(value.merge_high(0xaabb), (current >> 16) as u16);
    }
    assert_eq!(
        ByteEnabledDwordWrite::with_all_bytes_enabled(0x12345678).merge(0),
        0x12345678
    );
}

// Test: Set PCI read results through each supported byte-source representation.
// Expected: Only the selected byte lanes are written into the caller's DWORD.
#[test]
fn pci_reads_preserve_disabled_lanes() {
    let mut value = 0xaabbccdd;
    {
        let mut read = ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::HIGH_WORD);
        assert_eq!(read.byte_enable(), PciConfigByteEnable::HIGH_WORD);
        assert_eq!(read.valid_mask(), 0xffff0000);
        read.set_low_high(0x1122, 0x3344);
        assert_eq!(read.extract(), 0x33440000);
        assert_eq!(read.reborrow().extract_high(), 0x3344);
        assert_eq!(read.reborrow().extract_low(), 0);
        read.set_bytes(1, 2, 3, 4);
        read.reborrow()
            .into_valid_byte_slice()
            .copy_from_slice(&[0x66, 0x77]);
        let mut buffer = [0; 2];
        read.fill_intercept_buffer(&mut buffer);
        assert_eq!(buffer, [0x66, 0x77]);
    }
    assert_eq!(value, 0x7766ccdd);
}

// Test: Restrict and exclude lanes from an existing PCI read.
// Expected: Nested reads cannot modify lanes excluded by their parent.
#[test]
fn nested_pci_reads_respect_lane_intersections() {
    let mut value = 0;
    let mut read = ByteEnabledDwordRead::with_all_bytes_enabled(&mut value);
    read.restrict(PciConfigByteEnable::LOW_WORD)
        .unwrap()
        .set(0x11223344);
    read.exclude(PciConfigByteEnable::LOW_WORD)
        .unwrap()
        .set(0x55667788);
    let mut low = read.restrict(PciConfigByteEnable::LOW_WORD).unwrap();
    assert!(low.restrict(PciConfigByteEnable::HIGH_WORD).is_none());
    assert!(low.exclude(PciConfigByteEnable::FULL).is_none());
    assert_eq!(value, 0x55663344);
}

#[derive(Default)]
struct Endpoint {
    writes: Vec<(u16, u32)>,
}

impl ChipsetDevice for Endpoint {}

impl PciConfigSpace for Endpoint {
    fn pci_cfg_read(&mut self, offset: u16, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
        value.set(u32::from(offset) | 0x12340000);
        IoResult::Ok
    }

    fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> IoResult {
        self.writes.push((offset, value.extract()));
        IoResult::Ok
    }
}

// Test: Route type-0 function-zero accesses and accesses to absent functions.
// Expected: Only endpoint accesses reach callbacks; absent reads return all ones.
#[test]
fn pci_default_routing_dispatches_only_the_endpoint() {
    let mut endpoint = Endpoint::default();
    for (kind, devfn, expected) in [
        (PciConfigAccessType::Type0, 0, 0x1234000c),
        (PciConfigAccessType::Type0, 1, u32::MAX),
        (PciConfigAccessType::Type1, 0, u32::MAX),
    ] {
        let address = PciConfigAddress::new(2, devfn, 3).unwrap();
        let mut value = 0;
        endpoint
            .pci_cfg_read_with_routing(
                kind,
                address,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
            )
            .unwrap();
        assert_eq!(value, expected);
        endpoint
            .pci_cfg_write_with_routing(
                kind,
                address,
                ByteEnabledDwordWrite::with_all_bytes_enabled(42),
            )
            .unwrap();
    }
    assert_eq!(endpoint.writes, [(12, 42)]);
    assert!(endpoint.suggested_bdf().is_none());
    assert!(PciConfigAddress::new(0, 0, 1024).is_none());
}

// Test: Host a device without optional bus or interrupt capabilities.
// Expected: Capability discovery advertises no unsupported callback interfaces.
#[test]
fn minimal_device_does_not_advertise_optional_interfaces() {
    let mut device = Endpoint::default();
    assert!(device.supports_pio().is_none());
    assert!(device.supports_mmio().is_none());
    assert!(device.supports_pci().is_none());
    assert!(device.supports_poll_device().is_none());
    assert!(device.supports_line_interrupt_target().is_none());
    assert!(device.supports_handle_eoi().is_none());
    assert!(device.supports_acknowledge_pic_interrupt().is_none());
    assert!(device.supports_tdisp_host().is_none());
    assert!(device.supports_tdisp_relay().is_none());
}

// Test: Use externally managed MMIO regions through map and unmap requests.
// Expected: The no-op registration never creates a local address mapping.
#[test]
fn externally_managed_mmio_never_creates_a_mapping() {
    let mut registration = crate::mmio::ExternallyManagedMmioIntercepts;
    let mut region = registration.new_io_region("test", 16);
    assert_eq!(region.region_name(), "(noop)");
    assert_eq!(region.len(), 0);
    region.map(0x1000);
    assert_eq!(region.addr(), None);
    assert_eq!(region.offset_of(0x1000), None);
    region.unmap();
    assert_eq!(region.addr(), None);
}

// Test: Use externally managed port regions through map and unmap requests.
// Expected: The no-op registration never creates a local port mapping.
#[test]
fn externally_managed_pio_never_creates_a_mapping() {
    let mut registration = crate::pio::ExternallyManagedPortIoIntercepts;
    let mut region = registration.new_io_region("test", 16);
    assert_eq!(region.region_name(), "(noop)");
    assert_eq!(region.len(), 0);
    region.map(0x100);
    assert_eq!(region.addr(), None);
    assert_eq!(region.offset_of(0x100), None);
    region.unmap();
    assert_eq!(region.addr(), None);
}

impl MmioIntercept for Endpoint {
    fn mmio_read(&mut self, _addr: u64, _data: &mut [u8]) -> IoResult {
        IoResult::Err(IoError::InvalidRegister)
    }
    fn mmio_write(&mut self, _addr: u64, _data: &[u8]) -> IoResult {
        IoResult::Err(IoError::InvalidRegister)
    }
}

impl PortIoIntercept for Endpoint {
    fn io_read(&mut self, _port: u16, _data: &mut [u8]) -> IoResult {
        IoResult::Err(IoError::InvalidRegister)
    }
    fn io_write(&mut self, _port: u16, _data: &[u8]) -> IoResult {
        IoResult::Err(IoError::InvalidRegister)
    }
}

// Test: Query static regions for a device that declares no fixed bus mappings.
// Expected: Both buses require explicit registration instead of implicit regions.
#[test]
fn devices_without_static_regions_require_explicit_registration() {
    let mut endpoint = Endpoint::default();
    assert!(MmioIntercept::get_static_regions(&mut endpoint).is_empty());
    assert!(PortIoIntercept::get_static_regions(&mut endpoint).is_empty());
}

// Test: Convert immediate IO completion and error results to standard results.
// Expected: Success and the exact device error are forwarded synchronously.
#[test]
fn immediate_io_results_preserve_errors() {
    assert!(IoResult::Ok.now_or_never().is_ok());
    assert!(matches!(
        IoResult::Err(IoError::InvalidAccessSize).now_or_never(),
        Err(IoError::InvalidAccessSize)
    ));
}

// Test: Force an error result through the success-only IO assertion.
// Expected: The assertion rejects the failed IO.
#[test]
#[should_panic(expected = "unexpected IO result")]
fn io_unwrap_rejects_errors() {
    IoResult::Err(IoError::InvalidRegister).unwrap();
}

// Test: Force a deferred result through the synchronous IO conversion.
// Expected: Conversion rejects a request that has not completed synchronously.
#[test]
#[should_panic(expected = "unexpected IO result")]
fn immediate_io_conversion_rejects_deferred_requests() {
    let (_complete, token) = defer_write();
    let _ = IoResult::Defer(token).now_or_never();
}

// Test: Probe absent PCI functions with byte, word, and DWORD accesses, then
//       issue writes through the same routes.
// Expected: Selected read bytes report no device, other bytes stay untouched,
//       and no write reaches the endpoint callback.
#[test]
fn absent_pci_routes_preserve_subword_access_boundaries() {
    let mut endpoint = Endpoint::default();
    for (kind, devfn) in [
        (PciConfigAccessType::Type0, 1),
        (PciConfigAccessType::Type0, u8::MAX),
        (PciConfigAccessType::Type1, 0),
    ] {
        let address = PciConfigAddress::new(0, devfn, 0).unwrap();
        for (offset, len) in [(0, 1), (1, 1), (2, 1), (3, 1), (0, 2), (2, 2), (0, 4)] {
            let lanes = PciConfigByteEnable::from_offset_len(offset, len).unwrap();
            let initial = [0x12, 0x34, 0x56, 0x78];
            let mut value = u32::from_le_bytes(initial);
            endpoint
                .pci_cfg_read_with_routing(
                    kind,
                    address,
                    ByteEnabledDwordRead::new(&mut value, lanes),
                )
                .unwrap();
            let mut expected = initial;
            expected[usize::from(offset)..usize::from(offset) + len].fill(0xff);
            assert_eq!(value.to_le_bytes(), expected);
            endpoint
                .pci_cfg_write_with_routing(
                    kind,
                    address,
                    ByteEnabledDwordWrite::from_intercept_buffer(lanes, &[0x5a; 4][..len]),
                )
                .unwrap();
        }
    }
    assert!(endpoint.writes.is_empty());
}
