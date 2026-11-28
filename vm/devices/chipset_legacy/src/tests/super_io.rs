// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::winbond83977_sio::MaybeStubFloppyDiskController;
use crate::winbond83977_sio::Winbond83977FloppySioDevice;
use floppy::DriveRibbon;
use guestmem::GuestMemory;
use test_with_tracing::test;
use vmcore::isa_dma_channel::FloatingDmaChannel;
use vmcore::line_interrupt::LineInterrupt;

type StubSio = Winbond83977FloppySioDevice<floppy_pcat_stub::StubFloppyDiskController>;

fn new_sio<Fdc: MaybeStubFloppyDiskController>() -> Winbond83977FloppySioDevice<Fdc> {
    let mut ports = PioRegistrar::default();
    Winbond83977FloppySioDevice::new(
        GuestMemory::allocate(4096),
        LineInterrupt::detached(),
        &mut ports,
        DriveRibbon::None,
        DriveRibbon::None,
        Box::new(FloatingDmaChannel),
        Box::new(FloatingDmaChannel),
    )
    .unwrap()
}

fn enter(device: &mut StubSio) {
    write8(device, 0x3f0, 0x87);
    write8(device, 0x3f0, 0x87);
}

fn config_read(device: &mut StubSio, register: u8) -> u8 {
    write8(device, 0x3f0, register);
    read8(device, 0x3f1)
}

fn config_write(device: &mut StubSio, register: u8, value: u8) {
    write8(device, 0x3f0, register);
    write8(device, 0x3f1, value);
}

// Test: Interrupt the SIO unlock sequence and use both mirrored configuration ports.
// Expected: Incomplete handshakes fall back to floppy I/O; a complete sequence exposes SIO.
#[test]
fn sio_handshake_and_mirrored_ports_preserve_floppy_fallback() {
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    assert_eq!(read8(&mut device, 0x3f1), 0xfc);
    write8(&mut device, 0x3f0, 0x87);
    assert_eq!(read8(&mut device, 0x3f1), 0xfc);
    write8(&mut device, 0x3f0, 0x87);
    write8(&mut device, 0x3f0, 0x20);
    assert_eq!(read8(&mut device, 0x3f1), 0xfc);
    write8(&mut device, 0x370, 0x87);
    write8(&mut device, 0x3f0, 0x87);
    assert_eq!(config_read(&mut device, 0x20), 0x97);
    write8(&mut device, 0x370, 0x21);
    assert_eq!(read8(&mut device, 0x371), 0x71);
    write8(&mut device, 0x370, 0xaa);
    assert_eq!(read8(&mut device, 0x371), 0xfc);
    for port in [0x3f0, 0x3f1, 0x370, 0x371] {
        assert!(matches!(
            device.io_read(port, &mut [0; 2]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert!(matches!(
            device.io_write(port, &[]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    assert!(matches!(
        device.io_read(0x380, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.io_write(0x380, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Configure one logical device and save the complete SIO/floppy aggregate.
// Expected: Other devices stay independent and restore retains configuration, selection, and FDC state.
#[test]
fn sio_logical_device_configuration_and_floppy_state_survive_restore() {
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    write8(&mut device, 0x3f2, 0x1c);
    write8(&mut device, 0x372, 0x2c);
    enter(&mut device);
    config_write(&mut device, 0x07, 2);
    let registers = [
        (0x30, 1),
        (0x60, 0x12),
        (0x61, 0x34),
        (0x62, 0x56),
        (0x63, 0x78),
        (0x70, 5),
        (0x72, 7),
        (0x74, 1),
        (0x75, 3),
        (0xf0, 0xa0),
        (0xf1, 0xa1),
        (0xf2, 0xa2),
        (0xf3, 0xa3),
        (0xf4, 0xa4),
        (0xf5, 0xa5),
    ];
    for (register, value) in registers {
        config_write(&mut device, register, value);
        assert_eq!(config_read(&mut device, register), value);
    }
    assert_eq!(config_read(&mut device, 0x71), 2);
    assert_eq!(config_read(&mut device, 0x73), 2);
    config_write(&mut device, 0x07, 3);
    assert_eq!(config_read(&mut device, 0x60), 2);
    assert_eq!(config_read(&mut device, 0x61), 0xf8);
    config_write(&mut device, 0x07, 2);
    assert_eq!(config_read(&mut device, 0xf5), 0xa5);
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    enter(&mut device);
    config_write(&mut device, 0x07, 2);
    assert_eq!(config_read(&mut device, 0x60), 3);
    assert_eq!(read8(&mut device, 0x3f2), 0);
    assert_eq!(read8(&mut device, 0x372), 0);
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    device.restore(saved).unwrap();
    assert_eq!(read8(&mut device, 0x3f1), 0xa5);
    for (register, expected) in registers {
        assert_eq!(config_read(&mut device, register), expected);
    }
    assert_eq!(read8(&mut device, 0x3f2), 0x1c);
    assert_eq!(read8(&mut device, 0x372), 0x2c);
}

// Test: Resume a half-complete unlock sequence and address unsupported logical devices.
// Expected: Restore retains handshake progress, invalid selections are isolated, and parallel stays off.
#[test]
fn sio_restores_handshake_and_ignores_unsupported_device_configuration() {
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    write8(&mut device, 0x3f0, 0x87);
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    device.restore(saved).unwrap();
    write8(&mut device, 0x3f0, 0x87);
    assert_eq!(config_read(&mut device, 0x20), 0x97);
    config_write(&mut device, 0x20, 0);
    assert_eq!(config_read(&mut device, 0x20), 0x97);
    config_write(&mut device, 0x22, 0xff);
    config_write(&mut device, 0x24, 0xc4);
    config_write(&mut device, 0x07, 0xff);
    config_write(&mut device, 0x60, 0xff);
    assert_eq!(config_read(&mut device, 0x60), 0);
    config_write(&mut device, 0x07, 1);
    config_write(&mut device, 0x30, 1);
    assert_eq!(config_read(&mut device, 0x30), 0);
    config_write(&mut device, 0x07, 2);
    config_write(&mut device, 0x30, 0xfe);
    assert_eq!(config_read(&mut device, 0x30), 0);
    config_write(&mut device, 0x30, 3);
    assert_eq!(config_read(&mut device, 0x30), 1);
    write8(&mut device, 0x3f0, 0xaa);
    let idle = device.save().unwrap();
    let mut device = new_sio::<floppy_pcat_stub::StubFloppyDiskController>();
    enter(&mut device);
    device.restore(idle).unwrap();
    assert_eq!(read8(&mut device, 0x3f1), 0xfc);
}

// Test: Leave VERSION replies pending on both full floppy controllers, then
//       consume the primary reply before the secondary reply.
// Expected: Both return the enhanced-controller version, and consuming one
//       controller's reply does not drain or change the other's ready reply.
#[test]
fn sio_forwards_commands_to_both_full_floppy_controllers() {
    let mut device = new_sio::<floppy::FloppyDiskController>();
    for base in [0x3f0, 0x370] {
        write8(&mut device, base + 2, 4);
        write8(&mut device, base + 5, 0x10);
    }
    assert_eq!(read8(&mut device, 0x3f4) & 0xc0, 0xc0);
    assert_eq!(read8(&mut device, 0x374) & 0xc0, 0xc0);
    assert_eq!(read8(&mut device, 0x3f5), 0x90);
    assert_eq!(read8(&mut device, 0x3f4) & 0xc0, 0x80);
    assert_eq!(read8(&mut device, 0x374) & 0xc0, 0xc0);
    assert_eq!(read8(&mut device, 0x375), 0x90);
    assert_eq!(read8(&mut device, 0x374) & 0xc0, 0x80);
}
