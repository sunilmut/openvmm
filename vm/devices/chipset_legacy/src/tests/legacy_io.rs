// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::piix4_pci_bus::Piix4PciBus;
use crate::piix4_uhci::Piix4UsbUhciStub;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

// Test: Access CF9 directly and as part of the wider PCI address register.
// Expected: Only single-byte reset commands reset the machine; PCI addressing survives restore.
#[test]
fn pci_reset_port_does_not_intercept_wide_pci_address_accesses() {
    let mut ports = PioRegistrar::default();
    let resets = Arc::new(AtomicUsize::new(0));
    let recorded = resets.clone();
    let mut device = Piix4PciBus::new(
        &mut ports,
        Box::new(move || {
            recorded.fetch_add(1, Ordering::SeqCst);
        }),
    );
    assert_eq!(ports.base("addr"), Some(0xcf8));
    assert_eq!(ports.base("data"), Some(0xcfc));
    let address = 0x80000600u32.to_le_bytes();
    device.io_write(0xcf8, &address).unwrap();
    assert_eq!(read8(&mut device, 0xcf9), 0);
    assert_eq!(resets.load(Ordering::SeqCst), 0);
    write8(&mut device, 0xcf9, 1);
    assert_eq!(resets.load(Ordering::SeqCst), 0);
    for command in [2, 4, 6] {
        write8(&mut device, 0xcf9, command);
    }
    assert_eq!(resets.load(Ordering::SeqCst), 3);
    let mut value = [0; 4];
    device.io_read(0xcf8, &mut value).unwrap();
    assert_eq!(value, address);
    device.io_read(0xcfc, &mut value).unwrap();
    assert_eq!(value, [0xff; 4]);
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    device.io_read(0xcf8, &mut value).unwrap();
    assert_eq!(value, [0; 4]);
    device.restore(saved).unwrap();
    device.io_read(0xcf8, &mut value).unwrap();
    assert_eq!(value, address);
}

// Test: Probe and try to program the deliberately hidden UHCI stub.
// Expected: Identification stays absent and all stub registers remain hardwired across restore.
#[test]
fn usb_stub_remains_hidden_after_configuration_writes_and_restore() {
    let mut device = Piix4UsbUhciStub::new();
    let registers = [
        (0, u32::MAX),
        (4, 0x02800000),
        (8, 0),
        (0xc, 0),
        (0x20, 0),
        (0x3c, 0x4ff),
        (0x30, 0),
        (0x80, 0),
    ];
    for (offset, expected) in registers {
        assert_eq!(pci_read(&mut device, offset), expected);
        pci_write(&mut device, offset, u32::MAX);
        assert_eq!(pci_read(&mut device, offset), expected);
    }
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    device.restore(saved).unwrap();
    for (offset, expected) in registers {
        assert_eq!(pci_read(&mut device, offset), expected);
    }
}
