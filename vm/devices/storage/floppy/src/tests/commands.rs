// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::support::*;
use super::*;
use test_with_tracing::test;

// Test: Read each supported image's last sector on a track, then cross the track boundary.
// Expected: Geometry is inferred correctly and invalid sectors fail without reaching the backend.
#[test]
fn mounted_image_geometry_controls_accepted_sector_ranges() {
    for (size_kib, sectors) in [
        (360, 9),
        (720, 9),
        (1200, 15),
        (1440, 18),
        (1680, 21),
        (1840, 23),
    ] {
        let disk = TestDisk::new(size_kib * 1024);
        let mut rig = Rig::with_disk(disk.clone());
        rig.issue(&[0xe6, 0, 0, 0, sectors, 2, sectors, 0x1b, 0xff]);
        rig.poll();
        assert_eq!(rig.result()[0] & 0xc0, 0);
        assert_eq!(
            disk.state.lock().requests,
            [Request::Read(u64::from(sectors - 1), 512)]
        );
        let mut actual = [0; 512];
        rig.memory.read_at(DMA_ADDRESS, &mut actual).unwrap();
        assert_eq!(actual, [0x5a; 512]);
        disk.state.lock().requests.clear();
        rig.issue(&[0xe6, 0, 0, 0, sectors + 1, 2, 0xff, 0x1b, 0xff]);
        assert_ne!(rig.result()[1] & 4, 0);
        assert!(disk.state.lock().requests.is_empty());
    }
}

// Test: Reject nonstandard media sizes and attaching more than one drive.
// Expected: Construction returns typed errors instead of silently adopting unsupported geometry.
#[test]
fn invalid_media_size_and_multiple_drive_ribbons_are_rejected() {
    let disk = Disk::new(TestDisk::new(512)).unwrap();
    assert!(DriveRibbon::from_vec(vec![disk.clone(), disk.clone()]).is_err());
    assert!(matches!(
        DriveRibbon::from_vec(Vec::new()).unwrap(),
        DriveRibbon::None
    ));
    let drive = DriveRibbon::from_vec(vec![disk]).unwrap();
    let result = FloppyDiskController::new(
        GuestMemory::empty(),
        LineInterrupt::detached(),
        &mut ExternallyManagedPortIoIntercepts,
        0x3f0,
        drive,
        Box::new(FloatingDmaChannel),
    );
    assert!(matches!(
        result,
        Err(NewFloppyDiskControllerError::NonStandardDisk(512))
    ));
}

// Test: Exercise the supported read/write command aliases with no media inserted.
// Expected: Each completes with an error and releases the FIFO for the next command.
#[test]
fn missing_media_reports_errors_for_all_supported_transfer_aliases() {
    let mut rig = Rig::without_disk();
    for opcode in [0xe6, 0xc6, 0xcc, 0x46, 0x66, 0x42, 0xe5, 0xc5, 0xc9, 0x45] {
        rig.transfer(opcode, 0, 0, 1);
        assert_ne!(rig.result()[1] & 4, 0);
    }
    rig.issue(&[0x4d, 0, 2, 18, 0x1b, 0]);
    assert_ne!(rig.result()[1] & 4, 0);
    assert!(rig.dma.lock().requests.is_empty());
}

// Test: Send out-of-range sectors, end-of-track values, and cylinders with media mounted.
// Expected: Reads and writes report errors rather than issuing successful out-of-bounds transfers.
#[test]
fn invalid_transfer_positions_report_error_and_recover() {
    for opcode in [0xe6, 0xc5] {
        let mut rig = Rig::with_disk(TestDisk::new(IMAGE_SIZE));
        for (cylinder, sector, end) in [(0, 0, 18), (0, 19, 18), (0, 2, 1), (81, 1, 18)] {
            rig.issue(&[opcode, 0, cylinder, 0, sector, 2, end, 0x1b, 0xff]);
            rig.poll();
            assert_ne!(rig.result()[1] & 4, 0);
        }
        rig.transfer(opcode, 0, 0, 1);
        rig.poll();
        assert_eq!(rig.result()[0] & 0xc0, 0);
    }
}

// Test: Request non-DMA mode before a read and a write on the legacy DMA-backed implementation.
// Expected: Both transfers still complete through DMA and return the FIFO to idle.
#[test]
fn specify_non_dma_mode_preserves_legacy_dma_backed_transfers() {
    let mut rig = Rig::with_disk(TestDisk::new(IMAGE_SIZE));
    rig.issue(&[3, 0x20, 0x80]);
    assert_eq!(rig.read(0x3f4), 0x80);
    for opcode in [0xe6, 0xc5] {
        rig.transfer(opcode, 0, 0, 1);
        rig.poll();
        assert_eq!(rig.result()[0] & 0xc0, 0);
    }
    assert_eq!(
        rig.dma.lock().requests,
        [IsaDmaDirection::Write, IsaDmaDirection::Read]
    );
    assert_eq!(rig.dma.lock().completions, 2);
}

// Test: Send unsupported extended commands with their full parameter lists.
// Expected: Each returns invalid-command status instead of leaving a partial command queued.
#[test]
fn unsupported_extended_commands_drain_parameters_and_allow_the_next_command() {
    let mut rig = Rig::without_disk();
    for (opcode, parameters) in [
        (0x16, 8),
        (0xd1, 8),
        (0xf1, 8),
        (0x19, 8),
        (0x1d, 8),
        (0x8e, 6),
        (0xcf, 2),
        (0x8f, 2),
        (0x17, 1),
        (0x33, 1),
        (0x2e, 0),
        (0xad, 5),
    ] {
        rig.issue(&[opcode]);
        for index in 0..parameters {
            assert_eq!(rig.read(0x3f4) & 0x50, 0x10);
            rig.issue(&[0]);
            if index + 1 == parameters {
                assert_eq!(rig.read(0x3f4) & 0x50, 0x50);
            }
        }
        assert_eq!(rig.read(0x3f5), 0x80);
        rig.issue(&[0x10]);
        assert_eq!(rig.read(0x3f5), 0x90);
        assert_eq!(rig.read(0x3f4), 0x80);
    }
    for (command, result) in [(0x14, 0), (0x94, 0x10), (0x18, 1)] {
        rig.issue(&[command]);
        assert_eq!(rig.read(0x3f5), result);
    }
    rig.issue(&[0x13, 0, 0x57, 0]);
    rig.issue(&[0x12, 0]);
    assert_eq!(rig.read(0x3f4), 0x80);
    rig.issue(&[0x10]);
    assert_eq!(rig.read(0x3f5), 0x90);
}

// Test: Seek with head selection, restore pending seek status, and then recalibrate.
// Expected: Restored IRQ and cylinder/head information agree; recalibration returns to cylinder zero.
#[test]
fn seek_status_and_interrupt_level_survive_restore_before_recalibration() {
    let mut rig = Rig::without_disk();
    rig.issue(&[0x0f, 4, 37]);
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    let saved = rig.device.save().unwrap();
    rig.write(0x3f2, 0);
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    rig.device.restore(saved).unwrap();
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    rig.issue(&[8]);
    assert_eq!(rig.read(0x3f5), 0x24);
    assert_eq!(rig.read(0x3f5), 37);
    rig.issue(&[7, 4]);
    rig.issue(&[8]);
    assert_eq!(rig.read(0x3f5), 0x24);
    assert_eq!(rig.read(0x3f5), 0);
    rig.issue(&[0x0f, 7, 80]);
    rig.issue(&[8]);
    assert_eq!(rig.read(0x3f5), 0x24);
    assert_eq!(rig.read(0x3f5), 0);
}

// Test: Change DMA interrupt gating and perform a DSR software reset.
// Expected: Gating updates IRQ, reset preserves DOR, and all four reset statuses can be acknowledged.
#[test]
fn interrupt_gating_and_dsr_reset_preserve_digital_output() {
    let mut rig = Rig::without_disk();
    rig.write(0x3f2, 4);
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    rig.write(0x3f2, 0x1c);
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    rig.write(0x3f4, 0x80);
    assert_eq!(rig.read(0x3f2), 0x1c);
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    for drive in 0..4 {
        rig.issue(&[8]);
        assert_eq!(rig.read(0x3f5), 0xc0 | drive);
        assert_eq!(rig.read(0x3f5), 0);
    }
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    assert_eq!(rig.read(0x3f7), 0xff);
    for (port, expected) in [(0x3f0, 0xff), (0x3f1, 0xfc), (0x3f3, 0xff)] {
        rig.write(port, 0x55);
        assert_eq!(rig.read(port), expected);
    }
    rig.write(0x3f7, 0x55);
    assert!(matches!(
        rig.device.io_read(0x3f6, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        rig.device.io_write(0x3f6, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Read head identification and write-protect/track-zero drive status.
// Expected: Guest-visible result fields identify the selected head and media protection.
#[test]
fn read_id_and_drive_status_report_head_and_write_protection() {
    let mut rig = Rig::with_disk(TestDisk::read_only(IMAGE_SIZE));
    rig.issue(&[0x4a, 4]);
    assert_eq!(rig.result(), [4, 0, 0, 0, 1, 1, 2]);
    rig.issue(&[4, 4]);
    assert_eq!(rig.read(0x3f5), 0x7c);
    assert_eq!(rig.read(0x3f7), 0x7f);
}

// IGNORED: handle_dump_registers pushes fields in result order, but FIFO reads
//       pop from the end. The observed ten-byte result is reversed.
//
// Test: Dump a nonzero cylinder and programmed timing parameters.
// Expected: DUMP REGISTERS returns cylinder fields first, then SPECIFY bytes in command order.
#[test]
#[ignore = "product bug: DUMP REGISTERS results are reversed by the output FIFO"]
fn dump_registers_reports_fields_in_controller_result_order() {
    let mut rig = Rig::without_disk();
    rig.issue(&[0x0f, 0, 12]);
    rig.issue(&[3, 0xa5, 0xd3]);
    rig.issue(&[0x0e]);
    let result: Vec<_> = (0..10).map(|_| rig.read(0x3f5)).collect();
    assert_eq!(result, [12, 0, 0, 0, 0xa5, 0xd3, 0, 0, 0, 0]);
}

// IGNORED: RESTORE needs seventeen input bytes including its opcode, but the
//       command FIFO holds sixteen. Receiving the final parameter panics.
//
// Test: Receive all sixteen RESTORE parameters from the guest.
// Expected: The unsupported command returns invalid-command status without overflowing the FIFO.
#[test]
#[ignore = "product bug: RESTORE opcode plus parameters overflows the 16-byte FIFO"]
fn restore_command_parameter_count_does_not_overflow_the_fifo() {
    let mut rig = Rig::without_disk();
    rig.issue(&[0x4e]);
    rig.issue(&[0; 16]);
    assert_eq!(rig.read(0x3f5), 0x80);
}
