// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn controller() -> IdeDevice {
    let mut device = IdeDevice::new(
        GuestMemory::empty(),
        &mut ExternallyManagedPortIoIntercepts,
        [None, None],
        [None, None],
        LineInterrupt::detached(),
        LineInterrupt::detached(),
    )
    .unwrap();
    device
        .pci_cfg_write(
            HeaderType00::BAR4.0,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0xc000),
        )
        .unwrap();
    device
        .pci_cfg_write(
            HeaderType00::STATUS_COMMAND.0,
            ByteEnabledDwordWrite::with_all_bytes_enabled(5),
        )
        .unwrap();
    device
}

// Test: Update the PRD pointer with full and partial writes, then an invalid byte.
// Expected: Alignment bits clear, untouched halves survive, and channels stay apart.
#[test]
fn descriptor_pointer_partial_writes_preserve_other_bits() {
    let mut device = controller();
    let mut pointer = [0; 4];
    for (port, data, expected) in [
        (
            0xc004,
            0x1234_567bu32.to_le_bytes().to_vec(),
            0x1234_5678u32,
        ),
        (0xc004, 0xabcfu16.to_le_bytes().to_vec(), 0x1234_abcc),
        (0xc006, 0x9abcu16.to_le_bytes().to_vec(), 0x9abc_abcc),
    ] {
        device.io_write(port, &data).unwrap();
        device.io_read(0xc004, &mut pointer).unwrap();
        assert_eq!(u32::from_le_bytes(pointer), expected);
    }
    assert!(matches!(
        device.io_write(0xc004, &[0xff]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    device.io_read(0xc004, &mut pointer).unwrap();
    assert_eq!(u32::from_le_bytes(pointer), 0x9abc_abcc);
    device.io_read(0xc00c, &mut pointer).unwrap();
    assert_eq!(pointer, [0; 4]);
}

// Test: Change DMA direction during a transfer and after stopping each channel.
// Expected: Direction stays latched until restart; active tracks start/stop.
#[test]
fn dma_direction_changes_only_after_restart() {
    let mut device = controller();
    for port in [0xc000, 0xc008] {
        for (written, expected_command, expected_active) in
            [(9, 9, 1), (1, 9, 1), (0, 8, 0), (1, 1, 1), (0, 0, 0)]
        {
            device.io_write(port, &[written]).unwrap();
            let mut command = [0];
            device.io_read(port, &mut command).unwrap();
            assert_eq!(command[0], expected_command);
            let mut status = [0];
            device.io_read(port + 2, &mut status).unwrap();
            assert_eq!(status[0] & 1, expected_active);
        }
    }
}
