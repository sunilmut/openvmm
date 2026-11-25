// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::pci::PciConfigByteEnable;
use test_with_tracing::test;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveRestore;

// Read the complete guest-visible PCI configuration DWORD.
fn config(device: &mut IdeDevice, offset: u16) -> u32 {
    let mut value = 0;
    device
        .pci_cfg_read(
            offset,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
        )
        .unwrap();
    value
}

// Test: Partially update each timing register and attempt to overwrite PCI IDs.
// Expected: Enabled lanes change independently; the hardware identity stays fixed.
#[test]
fn timing_byte_enables_and_read_only_identity_are_preserved() {
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Hard);
    for offset in [0x40, 0x44, 0x48] {
        device
            .pci_cfg_write(
                offset,
                ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234_5678),
            )
            .unwrap();
        device
            .pci_cfg_write(
                offset,
                ByteEnabledDwordWrite::new(0xabcd_0000, PciConfigByteEnable::HIGH_WORD),
            )
            .unwrap();
        assert_eq!(config(&mut device, offset), 0xabcd_5678);
    }
    for (offset, expected) in [(0, 0x7111_8086), (8, 0x0101_8001), (0xf8, 0xf30)] {
        device
            .pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(0))
            .unwrap();
        assert_eq!(config(&mut device, offset), expected);
    }
    assert_eq!(config(&mut device, 0x0c), 0);
    let mut value = 0xdead_beef;
    assert!(matches!(
        device.pci_cfg_read(
            0xfc,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(value, 0xdead_beef);
}

// Test: Program a BAR with reserved bits, enable I/O, and disable it again.
// Expected: The BAR is masked, only supported command bits stick, and I/O is gated.
#[test]
fn pci_command_controls_bus_master_register_access() {
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Hard);
    assert!(matches!(
        device.io_read(0xc000, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    device
        .pci_cfg_write(
            0x20,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0xffff_abcd),
        )
        .unwrap();
    assert_eq!(config(&mut device, 0x20), 0xabc1);
    device
        .pci_cfg_write(
            4,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0xffff_ffff),
        )
        .unwrap();
    assert_eq!(config(&mut device, 4) & 0xffff, 5);
    device.io_write(0xabc0, &[9]).unwrap();
    let mut command = [0];
    device.io_read(0xabc0, &mut command).unwrap();
    assert_eq!(command, [9]);
    device
        .pci_cfg_write(4, ByteEnabledDwordWrite::with_all_bytes_enabled(0))
        .unwrap();
    assert!(matches!(
        device.io_read(0xabc0, &mut command),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Exercise the secondary task file and identify its attached disk.
// Expected: Register bytes, status, and identification use the secondary channel.
#[async_test]
async fn secondary_channel_registers_and_identification_reach_the_disk() {
    let file = NamedTempFile::new().unwrap();
    file.as_file().set_len(64 * 1024).unwrap();
    let disk = Disk::new(FileDisk::open(file.reopen().unwrap(), false).unwrap()).unwrap();
    let mut device = IdeDevice::new(
        GuestMemory::empty(),
        &mut ExternallyManagedPortIoIntercepts,
        [None, None],
        [Some(DriveMedia::hard_disk(disk)), None],
        LineInterrupt::detached(),
        LineInterrupt::detached(),
    )
    .unwrap();
    for (port, byte) in [
        (IdeIoPort::SEC_DEVICE_HEAD, 0x40),
        (IdeIoPort::SEC_SECTOR_COUNT, 7),
        (IdeIoPort::SEC_SECTOR_NUM, 3),
        (IdeIoPort::SEC_CYLINDER_LSB, 5),
        (IdeIoPort::SEC_CYLINDER_MSB, 6),
    ] {
        device.io_write(port.0, &[byte]).unwrap();
        let mut actual = [0];
        device.io_read(port.0, &mut actual).unwrap();
        assert_eq!(actual[0], byte);
    }
    device
        .io_write(IdeIoPort::SEC_ERROR_FEATURES.0, &[0])
        .unwrap();
    device
        .io_write(IdeIoPort::SEC_ALT_STATUS_DEVICE_CTL.0, &[0])
        .unwrap();
    let mut status = [0];
    device
        .io_read(IdeIoPort::SEC_ALT_STATUS_DEVICE_CTL.0, &mut status)
        .unwrap();
    assert!(Status::from_bits(status[0]).drdy());
    device
        .io_read(IdeIoPort::SEC_ERROR_FEATURES.0, &mut status)
        .unwrap();
    assert_eq!(status[0] & 4, 0);
    device
        .io_write(
            IdeIoPort::SEC_STATUS_CMD.0,
            &[IdeCommand::IDENTIFY_DEVICE.0],
        )
        .unwrap();
    let path = IdePath {
        channel: 1,
        drive: 0,
    };
    assert!(get_status(&mut device, &path).drq());
    let mut response = [0; 512];
    device
        .io_read(IdeIoPort::SEC_DATA.0, &mut response)
        .unwrap();
    let features = protocol::IdeFeatures::read_from_bytes(&response).unwrap();
    assert_eq!(&features.firmware_revision, b".1.1 1  ");
    assert!(!get_status(&mut device, &path).drq());
}

// Test: Restore snapshots into controllers with a missing or unexpected disk.
// Expected: Both topology mismatches report invalid saved state instead of success.
#[test]
fn snapshots_reject_missing_and_unexpected_drives() {
    for source_has_drive in [false, true] {
        let (mut populated, _, _, _) = ide_test_setup(None, DriveType::Hard);
        let mut empty = IdeDevice::new(
            GuestMemory::empty(),
            &mut ExternallyManagedPortIoIntercepts,
            [None, None],
            [None, None],
            LineInterrupt::detached(),
            LineInterrupt::detached(),
        )
        .unwrap();
        let result = if source_has_drive {
            empty.restore(populated.save().unwrap())
        } else {
            populated.restore(empty.save().unwrap())
        };
        assert!(matches!(result, Err(RestoreError::InvalidSavedState(_))));
    }
}
