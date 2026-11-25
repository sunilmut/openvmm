// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::deferred::{DeferredRead, DeferredWrite, defer_read, defer_write};
use chipset_device::mmio::MmioIntercept;
use chipset_device::pci::PciConfigSpace;
use chipset_device::pio::PortIoIntercept;
use chipset_device::poll_device::PollDevice;
use parking_lot::Mutex;
use std::ops::RangeInclusive;
use test_with_tracing::test;

mod action_tests;
mod deferred_tests;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Access {
    MmioRead(u64, usize),
    MmioWrite(u64, Vec<u8>),
    PioRead(u16, usize),
    PioWrite(u16, Vec<u8>),
    PciRead(u16, u8),
    PciWrite(u16, u32, u8),
    Poll,
}

enum Pending {
    Read(DeferredRead, Vec<u8>),
    Write(DeferredWrite),
}

struct RecordingDevice {
    accesses: Arc<Mutex<Vec<Access>>>,
    fail: bool,
    defer_polls: Option<usize>,
    remaining: usize,
    pending: Option<Pending>,
}

impl RecordingDevice {
    fn maybe_defer(&mut self, data: Option<Vec<u8>>) -> Option<DeferredToken> {
        self.remaining = self.defer_polls?;
        let (pending, token) = match data {
            Some(data) => {
                let (done, token) = defer_read();
                (Pending::Read(done, data), token)
            }
            None => {
                let (done, token) = defer_write();
                (Pending::Write(done), token)
            }
        };
        self.pending = Some(pending);
        Some(token)
    }
}

impl ChipsetDevice for RecordingDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        Some(self)
    }
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }
    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        Some(self)
    }
}

impl MmioIntercept for RecordingDevice {
    fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> IoResult {
        self.accesses
            .lock()
            .push(Access::MmioRead(addr, data.len()));
        if let Some(token) = self.maybe_defer(Some(vec![0xa0; data.len()])) {
            return IoResult::Defer(token);
        }
        data.copy_from_slice(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x86, 0x97][..data.len()]);
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        self.accesses
            .lock()
            .push(Access::MmioWrite(addr, data.to_vec()));
        if let Some(token) = self.maybe_defer(None) {
            return IoResult::Defer(token);
        }
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u64>)] {
        &[("mmio-probe", 0x1000..=0x100f)]
    }
}

impl PortIoIntercept for RecordingDevice {
    fn io_read(&mut self, addr: u16, data: &mut [u8]) -> IoResult {
        self.accesses.lock().push(Access::PioRead(addr, data.len()));
        if let Some(token) = self.maybe_defer(Some(vec![0x91; data.len()])) {
            return IoResult::Defer(token);
        }
        data.copy_from_slice(&[0x91, 0x82, 0x73, 0x64][..data.len()]);
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn io_write(&mut self, addr: u16, data: &[u8]) -> IoResult {
        self.accesses
            .lock()
            .push(Access::PioWrite(addr, data.to_vec()));
        if let Some(token) = self.maybe_defer(None) {
            return IoResult::Defer(token);
        }
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u16>)] {
        &[("pio-probe", 0x200..=0x207)]
    }
}

impl PciConfigSpace for RecordingDevice {
    fn pci_cfg_read(&mut self, offset: u16, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
        self.accesses
            .lock()
            .push(Access::PciRead(offset, value.byte_enable().bits()));
        if let Some(token) = self.maybe_defer(Some(vec![0x11, 0x22, 0x33, 0x44])) {
            return IoResult::Defer(token);
        }
        value.set(0x44332211);
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> IoResult {
        self.accesses.lock().push(Access::PciWrite(
            offset,
            value.extract(),
            value.byte_enable().bits(),
        ));
        if let Some(token) = self.maybe_defer(None) {
            return IoResult::Defer(token);
        }
        if self.fail {
            IoResult::Err(IoError::InvalidRegister)
        } else {
            IoResult::Ok
        }
    }
    fn suggested_bdf(&mut self) -> Option<(u8, u8, u8)> {
        Some((2, 3, 1))
    }
}

impl PollDevice for RecordingDevice {
    fn poll_device(&mut self, _cx: &mut Context<'_>) {
        self.accesses.lock().push(Access::Poll);
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining != 0 {
            return;
        }
        match self.pending.take() {
            Some(Pending::Read(done, bytes)) => {
                if self.fail {
                    done.complete_error(IoError::NoResponse);
                } else {
                    done.complete(&bytes);
                }
            }
            Some(Pending::Write(done)) => {
                if self.fail {
                    done.complete_error(IoError::NoResponse);
                } else {
                    done.complete();
                }
            }
            None => {}
        }
    }
}

fn configured_chipset(
    fail: bool,
    defer_polls: Option<usize>,
    budget: usize,
) -> (FuzzChipset, Arc<Mutex<Vec<Access>>>) {
    let mut chipset = FuzzChipset::new(budget);
    let accesses = Arc::new(Mutex::new(Vec::new()));
    let device = chipset
        .device_builder("recording-device")
        .add(|_| RecordingDevice {
            accesses: accesses.clone(),
            fail,
            defer_polls,
            remaining: 0,
            pending: None,
        })
        .unwrap();
    drop(device);
    (chipset, accesses)
}

fn chipset(fail: bool) -> (FuzzChipset, Arc<Mutex<Vec<Access>>>) {
    configured_chipset(fail, None, 4)
}

// Test: Register a recording device, drop the caller's device handle, and dispatch reads/writes at inclusive MMIO/PIO boundaries and adjacent holes.
// Expected: The chipset retains the device, returns exact read bytes, forwards full addresses and payloads once, and leaves buffers untouched for unclaimed addresses.
#[test]
fn mmio_and_pio_dispatch_preserve_data_boundaries_and_device_lifetime() {
    let (chipset, accesses) = chipset(false);
    let mut mmio = [0; 4];
    assert_eq!(chipset.mmio_read(0x1000, &mut mmio), Some(()));
    assert_eq!(mmio, [0xa0, 0xb1, 0xc2, 0xd3]);
    let mut last = [0];
    assert_eq!(chipset.mmio_read(0x100f, &mut last), Some(()));
    assert_eq!(last, [0xa0]);
    assert_eq!(chipset.mmio_read(0x1010, &mut last), None);
    assert_eq!(last, [0xa0]);
    assert_eq!(
        chipset.exec_action(ChipsetAction::MmioWrite {
            addr: 0x1005,
            val: vec![0, 0xff, 3]
        }),
        Some(())
    );
    let mut pio = [0; 2];
    assert_eq!(chipset.pio_read(0x200, &mut pio), Some(()));
    assert_eq!(pio, [0x91, 0x82]);
    assert_eq!(chipset.pio_read(0x207, &mut last), Some(()));
    assert_eq!(last, [0x91]);
    assert_eq!(chipset.pio_read(0x208, &mut last), None);
    assert_eq!(last, [0x91]);
    assert_eq!(
        chipset.exec_action(ChipsetAction::PortIoWrite {
            addr: 0x203,
            val: vec![0xff, 0]
        }),
        Some(())
    );
    assert_eq!(
        *accesses.lock(),
        [
            Access::MmioRead(0x1000, 4),
            Access::MmioRead(0x100f, 1),
            Access::MmioWrite(0x1005, vec![0, 0xff, 3]),
            Access::PioRead(0x200, 2),
            Access::PioRead(0x207, 1),
            Access::PioWrite(0x203, vec![0xff, 0]),
        ]
    );
}

// Test: Dispatch reads and writes to a device returning errors, plus accesses to an empty chipset.
// Expected: Claimed failed MMIO/PIO reads become all ones, writes remain claimed without panicking, and missing routes return None without touching caller data.
#[test]
fn device_errors_use_open_bus_reads_and_missing_routes_are_unclaimed() {
    let (chipset, accesses) = chipset(true);
    let mut bytes = [0x5a; 4];
    assert_eq!(chipset.mmio_read(0x1000, &mut bytes), Some(()));
    assert_eq!(bytes, [0xff; 4]);
    bytes.fill(0x5a);
    assert_eq!(chipset.pio_read(0x200, &mut bytes), Some(()));
    assert_eq!(bytes, [0xff; 4]);
    assert_eq!(chipset.mmio_write(0x1001, &[1, 2]), Some(()));
    assert_eq!(chipset.pio_write(0x201, &[3, 4]), Some(()));
    assert_eq!(
        *accesses.lock(),
        [
            Access::MmioRead(0x1000, 4),
            Access::PioRead(0x200, 4),
            Access::MmioWrite(0x1001, vec![1, 2]),
            Access::PioWrite(0x201, vec![3, 4])
        ]
    );
    let empty = FuzzChipset::default();
    bytes.fill(0x5a);
    assert_eq!(empty.mmio_read(0x1000, &mut bytes), None);
    assert_eq!(empty.pio_read(0x200, &mut bytes), None);
    assert_eq!(empty.mmio_write(0x1000, &[1]), None);
    assert_eq!(empty.pio_write(0x200, &[1]), None);
    assert_eq!(bytes, [0x5a; 4]);
}
