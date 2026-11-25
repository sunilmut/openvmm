// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vmcore::save_restore::SaveRestore;

// Program both halves of the ATA extended task file, high bytes first.
fn address_lba48(device: &mut IdeDevice, lba: u64, sectors: u16) {
    let bytes = lba.to_le_bytes();
    for (count, address) in [
        ((sectors >> 8) as u8, &bytes[3..6]),
        (sectors as u8, &bytes[..3]),
    ] {
        device
            .io_write(IdeIoPort::PRI_SECTOR_COUNT.0, &[count])
            .unwrap();
        for (port, byte) in [
            IdeIoPort::PRI_SECTOR_NUM,
            IdeIoPort::PRI_CYLINDER_LSB,
            IdeIoPort::PRI_CYLINDER_MSB,
        ]
        .into_iter()
        .zip(address)
        {
            device.io_write(port.0, &[*byte]).unwrap();
        }
    }
    device
        .io_write(IdeIoPort::PRI_DEVICE_HEAD.0, &[0x40])
        .unwrap();
}

// Read a task-file byte through the guest-visible register interface.
fn register(device: &mut IdeDevice, port: IdeIoPort) -> u8 {
    let mut value = [0];
    device.io_read(port.0, &mut value).unwrap();
    value[0]
}

// Enable the bus-master I/O window without starting a transfer.
fn enable_dma(device: &mut IdeDevice) {
    for (offset, value) in [
        (HeaderType00::BAR4.0, 0xc000),
        (HeaderType00::STATUS_COMMAND.0, 5),
    ] {
        device
            .pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(value))
            .unwrap();
    }
}

// Test: Save a partially consumed two-sector read, reset, and resume it.
// Expected: The remaining bytes and following sector match uninterrupted media.
#[async_test]
async fn hard_disk_read_resumes_at_the_saved_byte_and_sector() {
    let path = IdePath::default();
    let (mut device, _, contents, geometry) = ide_test_setup(None, DriveType::Hard);
    write_command_params(&mut device, &path, 0, 2, Addressing::Lba28Bit, &geometry);
    execute_command(&mut device, &path, IdeCommand::READ_SECTORS.0);
    assert!(check_command_ready(&mut device, &path).await.drq());
    let mut actual = vec![0; 1024];
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut actual[..200])
        .unwrap();
    let saved = device.save().unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut actual[200..512])
        .unwrap();
    assert!(check_command_ready(&mut device, &path).await.drq());
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut actual[512..])
        .unwrap();
    let status = check_status_loop(&mut device, &path).await;
    assert!(!status.err());
    assert_eq!(actual, contents.as_bytes()[..1024]);
    assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_NUM), 2);
}

// IGNORED: Saving a partial PIO write retains only the unwritten buffer tail.
//          Restore restarts that tail at byte zero, losing the original prefix.
//
// Test: Save a sector after writing its first 200 bytes, reset, and finish it.
// Expected: Media contains the original prefix followed by the remaining bytes.
#[async_test]
#[ignore = "partial PIO write snapshots lose bytes already supplied by the guest"]
async fn hard_disk_write_snapshot_preserves_the_already_written_prefix() {
    let path = IdePath::default();
    let (mut device, mut file, _, geometry) = ide_test_setup(None, DriveType::Hard);
    write_command_params(&mut device, &path, 0, 1, Addressing::Lba28Bit, &geometry);
    execute_command(&mut device, &path, IdeCommand::WRITE_SECTORS.0);
    let mut expected = [0x73; 512];
    expected[..200].fill(0xa6);
    device
        .io_write(IdeIoPort::PRI_DATA.0, &expected[..200])
        .unwrap();
    let saved = device.save().unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    device
        .io_write(IdeIoPort::PRI_DATA.0, &expected[200..])
        .unwrap();
    assert!(!check_status_loop(&mut device, &path).await.err());
    let mut actual = [0; 512];
    file.read_exact(&mut actual).unwrap();
    assert_eq!(actual, expected);
}

// Test: Read high-order task-file bytes and then write a command-block register.
// Expected: HOB selects the high bytes; the subsequent write selects low bytes.
#[test]
fn extended_task_file_high_bytes_do_not_replace_low_bytes() {
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Hard);
    address_lba48(&mut device, 0x1234_5678_9abc, 0xdef0);
    device
        .io_write(IdeIoPort::PRI_ALT_STATUS_DEVICE_CTL.0, &[0x80])
        .unwrap();
    for (port, expected) in [
        (IdeIoPort::PRI_SECTOR_COUNT, 0xde),
        (IdeIoPort::PRI_SECTOR_NUM, 0x56),
        (IdeIoPort::PRI_CYLINDER_LSB, 0x34),
        (IdeIoPort::PRI_CYLINDER_MSB, 0x12),
    ] {
        assert_eq!(register(&mut device, port), expected);
    }
    device
        .io_write(IdeIoPort::PRI_ERROR_FEATURES.0, &[0])
        .unwrap();
    for (port, expected) in [
        (IdeIoPort::PRI_SECTOR_COUNT, 0xf0),
        (IdeIoPort::PRI_SECTOR_NUM, 0xbc),
        (IdeIoPort::PRI_CYLINDER_LSB, 0x9a),
        (IdeIoPort::PRI_CYLINDER_MSB, 0x78),
    ] {
        assert_eq!(register(&mut device, port), expected);
    }
}

// Test: Read through extended sector and block commands from a nonzero LBA.
// Expected: Both commands return exactly the requested sector and finish cleanly.
#[async_test]
async fn extended_pio_reads_return_the_requested_sector() {
    for command in [
        IdeCommand::READ_MULTI_SECTORS_EXT,
        IdeCommand::READ_MULTI_BLOCKS_EXT,
    ] {
        let path = IdePath::default();
        let (mut device, _, contents, _) = ide_test_setup(None, DriveType::Hard);
        address_lba48(&mut device, 3, 1);
        execute_command(&mut device, &path, command.0);
        assert!(check_command_ready(&mut device, &path).await.drq());
        let mut actual = [0; 512];
        device.io_read(IdeIoPort::PRI_DATA.0, &mut actual).unwrap();
        assert!(!check_status_loop(&mut device, &path).await.err());
        assert_eq!(actual, contents.as_bytes()[1536..2048]);
        assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_NUM), 4);
    }
}

// Test: Write extended sector/block commands, including force-unit-access mode.
// Expected: Every command persists its payload without changing adjacent media.
#[async_test]
async fn extended_pio_writes_preserve_adjacent_sectors() {
    for command in [
        IdeCommand::WRITE_MULTI_SECTORS_EXT,
        IdeCommand::WRITE_MULTI_BLOCKS_EXT,
        IdeCommand::WRITE_MULTIPLE_BLOCKS_EXT_FUA,
    ] {
        let path = IdePath::default();
        let (mut device, mut file, contents, _) = ide_test_setup(None, DriveType::Hard);
        address_lba48(&mut device, 1, 1);
        execute_command(&mut device, &path, command.0);
        assert!(check_command_ready(&mut device, &path).await.drq());
        device
            .io_write(IdeIoPort::PRI_DATA.0, &[0x7d; 512])
            .unwrap();
        assert!(!check_status_loop(&mut device, &path).await.err());
        let mut actual = [0; 1536];
        file.read_exact(&mut actual).unwrap();
        assert_eq!(actual[..512], contents.as_bytes()[..512]);
        assert_eq!(actual[512..1024], [0x7d; 512]);
        assert_eq!(actual[1024..], contents.as_bytes()[1024..1536]);
    }
}

// Test: Verify media with legacy and extended commands, then flush both modes.
// Expected: Verification consumes sectors without PIO data; flushes finish cleanly.
#[async_test]
async fn verify_and_flush_commands_complete_without_a_data_phase() {
    let path = IdePath::default();
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Hard);
    for command in [
        IdeCommand::VERIFY_MULTI_SECTORS,
        IdeCommand::VERIFY_MULTI_SECTORS_EXT,
    ] {
        address_lba48(&mut device, 1, 2);
        execute_command(&mut device, &path, command.0);
        let status = check_status_loop(&mut device, &path).await;
        assert!(!status.err());
        assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_NUM), 3);
    }
    for command in [IdeCommand::FLUSH_CACHE, IdeCommand::FLUSH_CACHE_EXT] {
        execute_command(&mut device, &path, command.0);
        assert!(!check_status_loop(&mut device, &path).await.err());
    }
}

// Test: Reject a command crossing the disk end, then issue a valid read.
// Expected: The bad location sets ERR; a new command clears it and returns data.
#[async_test]
async fn invalid_media_range_does_not_poison_later_commands() {
    let path = IdePath::default();
    let (mut device, _, contents, geometry) = ide_test_setup(None, DriveType::Hard);
    address_lba48(&mut device, geometry.total_sectors - 1, 2);
    execute_command(&mut device, &path, IdeCommand::READ_MULTI_SECTORS_EXT.0);
    assert!(get_status(&mut device, &path).err());
    address_lba48(&mut device, 0, 1);
    execute_command(&mut device, &path, IdeCommand::READ_MULTI_BLOCKS_EXT.0);
    let status = check_command_ready(&mut device, &path).await;
    assert!(!status.err() && status.drq());
    let mut actual = [0; 512];
    device.io_read(IdeIoPort::PRI_DATA.0, &mut actual).unwrap();
    assert_eq!(actual, contents.as_bytes()[..512]);
}

// Test: Restore an interrupted IDENTIFY response from an optical drive.
// Expected: Its remaining identification bytes match the uninterrupted response.
#[async_test]
async fn optical_identification_snapshot_preserves_unread_bytes() {
    let path = IdePath::default();
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Optical);
    execute_command(&mut device, &path, IdeCommand::IDENTIFY_PACKET_DEVICE.0);
    assert!(get_status(&mut device, &path).drq());
    let mut prefix = [0; 200];
    device.io_read(IdeIoPort::PRI_DATA.0, &mut prefix).unwrap();
    assert_eq!(u16::from_le_bytes(prefix[..2].try_into().unwrap()), 0x85c0);
    let saved = device.save().unwrap();
    let mut expected = [0; 312];
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut expected)
        .unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    let mut actual = [0; 312];
    device.io_read(IdeIoPort::PRI_DATA.0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let status = get_status(&mut device, &path);
    assert!(!status.drq() && !status.err() && status.drdy());
    assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_COUNT), 3);
}

// Test: Save an optical INQUIRY response after reading only its first ten bytes.
// Expected: Restore preserves the response tail and the final packet completion.
#[async_test]
async fn optical_packet_snapshot_preserves_data_and_completion() {
    let path = IdePath::default();
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Optical);
    let mut cdb = [0; 12];
    cdb[0] = 0x12;
    cdb[4] = 36;
    assert!(atapi_packet_command(&mut device, &path, &cdb).await.drq());
    let mut prefix = [0; 10];
    device.io_read(IdeIoPort::PRI_DATA.0, &mut prefix).unwrap();
    assert_eq!(prefix[0] & 0x1f, 5);
    let saved = device.save().unwrap();
    let mut expected = [0; 26];
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut expected)
        .unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    let mut actual = [0; 26];
    device.io_read(IdeIoPort::PRI_DATA.0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    assert!(!get_status(&mut device, &path).drq());
    assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_COUNT), 3);
}

// Test: Snapshot an optical DMA response before starting the bus-master engine.
// Expected: The restored response reaches guest RAM and signals DMA completion.
#[async_test]
async fn optical_dma_snapshot_delivers_the_saved_response() {
    let path = IdePath::default();
    let gm = GuestMemory::allocate(16384);
    let (mut device, _, _, _) = ide_test_setup(Some(gm.clone()), DriveType::Optical);
    enable_dma(&mut device);
    gm.write_plain(
        0x1000,
        &BusMasterDmaDesc {
            mem_physical_base: 0x2000,
            byte_count: 36,
            unused: 0,
            end_of_table: 0x80,
        },
    )
    .unwrap();
    device.io_write(0xc004, &0x1000u32.to_le_bytes()).unwrap();
    device
        .io_write(IdeIoPort::PRI_ERROR_FEATURES.0, &[1])
        .unwrap();
    let mut cdb = [0; 12];
    cdb[0] = 0x12;
    cdb[4] = 36;
    assert!(atapi_packet_command(&mut device, &path, &cdb).await.drq());
    let saved = device.save().unwrap();
    let mut expected = [0; 36];
    device
        .io_read(IdeIoPort::PRI_DATA.0, &mut expected)
        .unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    device.io_write(0xc000, &[9]).unwrap();
    let status = check_status_loop(&mut device, &path).await;
    assert!(!status.err());
    let mut actual = [0; 36];
    gm.read_at(0x2000, &mut actual).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(register(&mut device, IdeIoPort(0xc002)) & 7, 4);
}

// Test: Restore an armed DMA engine, then start a hard-disk read.
// Expected: The saved descriptor pointer and direction deliver the correct data.
#[async_test]
async fn armed_dma_engine_survives_snapshot_before_the_command() {
    let path = IdePath::default();
    let gm = GuestMemory::allocate(16384);
    let (mut device, _, contents, _) = ide_test_setup(Some(gm.clone()), DriveType::Hard);
    enable_dma(&mut device);
    gm.write_plain(
        0x1000,
        &BusMasterDmaDesc {
            mem_physical_base: 0x2000,
            byte_count: 512,
            unused: 0,
            end_of_table: 0x80,
        },
    )
    .unwrap();
    device.io_write(0xc004, &0x1000u32.to_le_bytes()).unwrap();
    device.io_write(0xc000, &[9]).unwrap();
    let saved = device.save().unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    address_lba48(&mut device, 2, 1);
    execute_command(&mut device, &path, IdeCommand::READ_DMA_EXT.0);
    assert!(!check_status_loop(&mut device, &path).await.err());
    let mut actual = [0; 512];
    gm.read_at(0x2000, &mut actual).unwrap();
    assert_eq!(actual, contents.as_bytes()[1024..1536]);
    assert_eq!(register(&mut device, IdeIoPort(0xc002)) & 7, 4);
}

// Test: Select an absent optical slave, then recover from an invalid ATA command.
// Expected: The absent target reads zero; the optical signature and retry survive.
#[async_test]
async fn optical_selection_and_invalid_commands_preserve_recovery() {
    let path = IdePath::default();
    let (mut device, _, _, _) = ide_test_setup(None, DriveType::Optical);
    device
        .io_write(IdeIoPort::PRI_DEVICE_HEAD.0, &[0x10])
        .unwrap();
    assert_eq!(get_status(&mut device, &path).into_bits(), 0);
    execute_command(&mut device, &path, IdeCommand::CHECK_POWER_MODE.0);
    device.io_write(IdeIoPort::PRI_DEVICE_HEAD.0, &[0]).unwrap();
    execute_command(&mut device, &path, IdeCommand::IDENTIFY_DEVICE.0);
    assert!(get_status(&mut device, &path).err());
    assert_eq!(register(&mut device, IdeIoPort::PRI_ERROR_FEATURES) & 4, 4);
    assert_eq!(register(&mut device, IdeIoPort::PRI_CYLINDER_LSB), 0x14);
    assert_eq!(register(&mut device, IdeIoPort::PRI_CYLINDER_MSB), 0xeb);
    execute_command(&mut device, &path, IdeCommand::CHECK_POWER_MODE.0);
    assert!(!get_status(&mut device, &path).err());
    assert_eq!(register(&mut device, IdeIoPort::PRI_SECTOR_COUNT), 0xff);
}

// Test: Save a DMA write before guest bytes arrive, including force-unit-access.
// Expected: Restored commands read the guest payload and write only the target sector.
#[async_test]
async fn dma_write_snapshot_preserves_pending_command_and_direction() {
    for command in [IdeCommand::WRITE_DMA_EXT, IdeCommand::WRITE_DMA_FUA_EXT] {
        let path = IdePath::default();
        let gm = GuestMemory::allocate(16384);
        let (mut device, mut file, contents, _) = ide_test_setup(Some(gm.clone()), DriveType::Hard);
        enable_dma(&mut device);
        gm.write_at(0x2000, &[0x96; 512]).unwrap();
        gm.write_plain(
            0x1000,
            &BusMasterDmaDesc {
                mem_physical_base: 0x2000,
                byte_count: 512,
                unused: 0,
                end_of_table: 0x80,
            },
        )
        .unwrap();
        device.io_write(0xc004, &0x1000u32.to_le_bytes()).unwrap();
        address_lba48(&mut device, 1, 1);
        execute_command(&mut device, &path, command.0);
        assert!(get_status(&mut device, &path).drq());
        let saved = device.save().unwrap();
        device.reset().await;
        device.restore(saved).unwrap();
        device.io_write(0xc000, &[1]).unwrap();
        assert!(!check_status_loop(&mut device, &path).await.err());
        let mut actual = [0; 1536];
        file.read_exact(&mut actual).unwrap();
        assert_eq!(actual[..512], contents.as_bytes()[..512]);
        assert_eq!(actual[512..1024], [0x96; 512]);
        assert_eq!(actual[1024..], contents.as_bytes()[1024..1536]);
    }
}

// Prepare readable data without starting DMA; retain an uninterrupted oracle.
async fn ready_dma_read(drive_type: DriveType) -> (IdeDevice, GuestMemory, Vec<u8>) {
    let path = IdePath::default();
    let gm = GuestMemory::allocate(16384);
    let (mut device, _, contents, _) = ide_test_setup(Some(gm.clone()), drive_type);
    enable_dma(&mut device);
    let expected = match drive_type {
        DriveType::Hard => {
            address_lba48(&mut device, 0, 1);
            execute_command(&mut device, &path, IdeCommand::READ_DMA_EXT.0);
            assert!(check_command_ready(&mut device, &path).await.drq());
            contents.as_bytes()[..512].to_vec()
        }
        DriveType::Optical => {
            let mut cdb = [0; 12];
            cdb[0] = 0x12;
            cdb[4] = 36;
            assert!(atapi_packet_command(&mut device, &path, &cdb).await.drq());
            let mut expected = vec![0; 36];
            device
                .io_read(IdeIoPort::PRI_DATA.0, &mut expected)
                .unwrap();
            device
                .io_write(IdeIoPort::PRI_ERROR_FEATURES.0, &[1])
                .unwrap();
            assert!(atapi_packet_command(&mut device, &path, &cdb).await.drq());
            expected
        }
    };
    (device, gm, expected)
}

// Test: DMA through an unmapped descriptor table or an unmapped data buffer.
// Expected: Both drive types stop DMA and clear the data phase without touching RAM.
#[async_test]
async fn inaccessible_dma_memory_stops_without_partial_guest_writes() {
    for drive_type in [DriveType::Hard, DriveType::Optical] {
        for invalid_table in [false, true] {
            let (mut device, gm, expected) = ready_dma_read(drive_type).await;
            gm.write_at(0x2000, &[0x93; 512]).unwrap();
            gm.write_plain(
                0x1000,
                &BusMasterDmaDesc {
                    mem_physical_base: 0x10000,
                    byte_count: expected.len().try_into().unwrap(),
                    unused: 0,
                    end_of_table: 0x80,
                },
            )
            .unwrap();
            let table: u32 = if invalid_table { 0x10000 } else { 0x1000 };
            device.io_write(0xc004, &table.to_le_bytes()).unwrap();
            device.io_write(0xc000, &[9]).unwrap();
            assert_eq!(register(&mut device, IdeIoPort(0xc002)) & 1, 0);
            let status = get_status(&mut device, &IdePath::default());
            assert!(!status.bsy() && !status.drq());
            let mut actual = [0; 512];
            gm.read_at(0x2000, &mut actual).unwrap();
            assert_eq!(actual, [0x93; 512]);
        }
    }
}

// Test: End a DMA descriptor before consuming the complete disk or packet response.
// Expected: Only the described prefix reaches RAM; both DMA and the command finish.
#[async_test]
async fn short_dma_descriptors_do_not_overwrite_the_guest_buffer_tail() {
    for drive_type in [DriveType::Hard, DriveType::Optical] {
        let (mut device, gm, expected) = ready_dma_read(drive_type).await;
        gm.write_at(0x2000, &[0x93; 512]).unwrap();
        gm.write_plain(
            0x1000,
            &BusMasterDmaDesc {
                mem_physical_base: 0x2000,
                byte_count: 16,
                unused: 0,
                end_of_table: 0x80,
            },
        )
        .unwrap();
        device.io_write(0xc004, &0x1000u32.to_le_bytes()).unwrap();
        device.io_write(0xc000, &[9]).unwrap();
        let status = check_status_loop(&mut device, &IdePath::default()).await;
        assert!(!status.err());
        assert_eq!(register(&mut device, IdeIoPort(0xc002)) & 7, 4);
        let mut actual = [0; 512];
        gm.read_at(0x2000, &mut actual).unwrap();
        assert_eq!(actual[..16], expected[..16]);
        assert_eq!(actual[16..], [0x93; 496]);
    }
}

// Submit a BIOS fast-path command and wait for its deferred port write.
async fn enlightened_read(
    device: &mut IdeDevice,
    gm: &GuestMemory,
    command: &protocol::EnlightenedInt13Command,
) -> protocol::EnlightenedInt13Command {
    gm.write_plain(0, command).unwrap();
    let IoResult::Defer(mut completion) =
        device.io_write(IdeIoPort::PRI_ENLIGHTENED.0, &0u32.to_le_bytes())
    else {
        panic!("expected deferred enlightened read");
    };
    poll_fn(|cx| {
        device.poll_device(cx);
        completion.poll_write(cx)
    })
    .await
    .unwrap();
    gm.read_plain(0).unwrap()
}

// Test: Run an out-of-range BIOS read and then a valid read on each drive type.
// Expected: Failure writes ERR back without copying data; a valid retry returns media.
#[async_test]
async fn enlightened_read_errors_report_status_and_allow_a_valid_retry() {
    for drive_type in [DriveType::Hard, DriveType::Optical] {
        let gm = GuestMemory::allocate(16384);
        let (mut device, _, contents, _) = ide_test_setup(Some(gm.clone()), drive_type);
        gm.write_at(0x2000, &[0x93; 512]).unwrap();
        gm.write_plain(
            0x1000,
            &BusMasterDmaDesc {
                mem_physical_base: 0x2000,
                byte_count: 512,
                unused: 0,
                end_of_table: 0x80,
            },
        )
        .unwrap();
        let mut command = protocol::EnlightenedInt13Command {
            command: IdeCommand::READ_DMA_EXT,
            device_head: DeviceHeadReg::new().with_lba(true),
            flags: 0,
            result_status: 0,
            lba_low: u32::MAX,
            lba_high: 0,
            block_count: 1,
            byte_count: 512,
            data_buffer: if drive_type == DriveType::Hard {
                0x1000
            } else {
                0x2000
            },
            skip_bytes_head: 0,
            skip_bytes_tail: 0,
        };
        let failed = enlightened_read(&mut device, &gm, &command).await;
        assert!(Status::from_bits(failed.result_status).err());
        let mut actual = [0; 512];
        gm.read_at(0x2000, &mut actual).unwrap();
        assert_eq!(actual, [0x93; 512]);
        execute_command(
            &mut device,
            &IdePath::default(),
            IdeCommand::CHECK_POWER_MODE.0,
        );
        command.lba_low = 0;
        let completed = enlightened_read(&mut device, &gm, &command).await;
        assert_eq!(completed.result_status, 0);
        gm.read_at(0x2000, &mut actual).unwrap();
        assert_eq!(actual, contents.as_bytes()[..512]);
    }
}
