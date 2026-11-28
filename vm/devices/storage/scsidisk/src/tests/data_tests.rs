// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{TestDisk, new_scsi_disk};
use crate::{SimpleScsiDisk, scsi};
use disk_backend::Disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};
use scsidisk_resources::DiskParameters;

fn request(size: u8, write: bool, start: u64, count: u32, fua: bool) -> Request {
    let mut cdb = [0; 16];
    cdb[0] = match (size, write) {
        (6, false) => 0x08,
        (6, true) => 0x0a,
        (10, false) => 0x28,
        (10, true) => 0x2a,
        (12, false) => 0xa8,
        (12, true) => 0xaa,
        (16, false) => 0x88,
        (16, true) => 0x8a,
        _ => panic!("unsupported test CDB size"),
    };
    match size {
        6 => {
            cdb[1] = (start >> 16) as u8 & 0x1f;
            cdb[2..4].copy_from_slice(&(start as u16).to_be_bytes());
            cdb[4] = count as u8;
        }
        10 | 12 => {
            cdb[1] = if fua { 8 } else { 0 };
            cdb[2..6].copy_from_slice(&(start as u32).to_be_bytes());
            if size == 10 {
                cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            } else {
                cdb[6..10].copy_from_slice(&count.to_be_bytes());
            }
        }
        16 => {
            cdb[1] = if fua { 8 } else { 0 };
            cdb[2..10].copy_from_slice(&start.to_be_bytes());
            cdb[10..14].copy_from_slice(&count.to_be_bytes());
        }
        _ => unreachable!(),
    }
    Request { cdb, srb_flags: 0 }
}

// Test: Write/read three sectors using every supported CDB length and both applicable FUA settings.
// Expected: Exact payload, disk offset, transfer length, FUA, and all adjacent guest/disk bytes are preserved.
#[async_test]
async fn read_write_variants_transfer_exact_ranges_and_forward_fua() {
    for size in [6, 10, 12, 16] {
        for fua in [false, true] {
            if size == 6 && fua {
                continue;
            }
            let (disk, state) = new_scsi_disk(
                512, 4096, 16, /* read_only: */ false, /* storage: */ true,
                /* pr: */ false,
            );
            state.lock().storage.fill(0x5c);
            let payload: Vec<u8> = (0..1536).map(|index| (index % 251) as u8).collect();
            let memory = GuestMemory::allocate(4096);
            memory.write_at(0, &[0xa5; 4096]).unwrap();
            memory.write_at(64, &payload).unwrap();
            let buffers = OwnedRequestBuffers::linear(64, 1600, false);
            let result = disk
                .execute_scsi(&buffers.buffer(&memory), &request(size, true, 5, 3, fua))
                .await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
            assert_eq!(result.tx, 1536);
            let mut expected_disk = vec![0x5c; 8192];
            expected_disk[2560..4096].copy_from_slice(&payload);
            assert_eq!(state.lock().storage, expected_disk);
            assert_eq!(state.lock().is_fua_set, fua);
            let mut actual_guest = [0; 4096];
            memory.read_at(0, &mut actual_guest).unwrap();
            let mut expected_guest = [0xa5; 4096];
            expected_guest[64..1600].copy_from_slice(&payload);
            assert_eq!(actual_guest, expected_guest);
            memory.write_at(0, &[0xa5; 4096]).unwrap();
            let buffers = OwnedRequestBuffers::linear(64, 1600, true);
            let result = disk
                .execute_scsi(&buffers.buffer(&memory), &request(size, false, 5, 3, fua))
                .await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
            assert_eq!(result.tx, 1536);
            memory.read_at(0, &mut actual_guest).unwrap();
            assert_eq!(actual_guest, expected_guest);
            assert_eq!(state.lock().storage, expected_disk);
        }
    }
}

// Test: Read/write beyond capacity, across its end, or with a buffer smaller than the block count.
// Expected: Every CDB form reports ILLEGAL BLOCK with no transfer or guest/backing-storage mutation.
#[async_test]
async fn invalid_transfer_ranges_preserve_guest_and_backing_memory() {
    for size in [6, 10, 12, 16] {
        for write in [false, true] {
            for (start, count, buffer_len) in [(16, 1, 512), (15, 2, 1024), (0, 2, 512)] {
                let (disk, state) = new_scsi_disk(
                    512, 4096, 16, /* read_only: */ false, /* storage: */ true,
                    /* pr: */ false,
                );
                state.lock().storage.fill(0x5c);
                let memory = GuestMemory::allocate(4096);
                memory.write_at(0, &[0xa5; 4096]).unwrap();
                let buffers = OwnedRequestBuffers::linear(0, buffer_len, !write);
                let result = disk
                    .execute_scsi(
                        &buffers.buffer(&memory),
                        &request(size, write, start, count, false),
                    )
                    .await;
                assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
                assert_eq!(result.tx, 0);
                let sense = result.sense_data.unwrap();
                assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
                assert_eq!(
                    sense.additional_sense_code,
                    scsi::AdditionalSenseCode::ILLEGAL_BLOCK
                );
                let mut actual = [0; 4096];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, [0xa5; 4096]);
                assert_eq!(state.lock().storage, vec![0x5c; 8192]);
            }
        }
    }
}

// Test: Use relative-address READ/WRITE(10/12), which this virtual disk does not support.
// Expected: INVALID CDB is returned without changing any disk bytes.
#[async_test]
async fn relative_transfer_addresses_are_rejected() {
    for size in [10, 12] {
        for write in [false, true] {
            let (disk, state) = new_scsi_disk(
                512, 4096, 16, /* read_only: */ false, /* storage: */ true,
                /* pr: */ false,
            );
            let memory = GuestMemory::allocate(4096);
            let buffers = OwnedRequestBuffers::linear(0, 512, !write);
            let mut request = request(size, write, 0, 1, false);
            request.cdb[1] = 1;
            let result = disk.execute_scsi(&buffers.buffer(&memory), &request).await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(
                result.sense_data.unwrap().additional_sense_code,
                scsi::AdditionalSenseCode::INVALID_CDB
            );
            assert_eq!(result.tx, 0);
            assert_eq!(state.lock().storage, vec![0; 8192]);
        }
    }
}

// Test: Attempt each WRITE form on a read-only backing disk.
// Expected: DATA PROTECT/WRITE PROTECT is reported before storage changes, with zero transfer.
#[async_test]
async fn write_variants_respect_read_only_media() {
    for size in [6, 10, 12, 16] {
        let (disk, state) = new_scsi_disk(
            512, 4096, 16, /* read_only: */ true, /* storage: */ true,
            /* pr: */ false,
        );
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 512]).unwrap();
        let buffers = OwnedRequestBuffers::linear(0, 512, false);
        let result = disk
            .execute_scsi(&buffers.buffer(&memory), &request(size, true, 0, 1, false))
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(sense.header.sense_key, scsi::SenseKey::DATA_PROTECT);
        assert_eq!(
            sense.additional_sense_code,
            scsi::AdditionalSenseCode::WRITE_PROTECT
        );
        assert_eq!(state.lock().storage, vec![0; 8192]);
    }
}

// Test: Place a valid READ/WRITE(16) transfer in an unbacked guest page.
// Expected: Guest-memory errors return typed invalid requests and do not corrupt backing storage.
#[async_test]
async fn transfer_memory_faults_return_scsi_errors_without_storage_corruption() {
    for write in [false, true] {
        let (disk, state) = new_scsi_disk(
            512, 4096, 16, /* read_only: */ false, /* storage: */ true,
            /* pr: */ false,
        );
        let memory = GuestMemory::allocate(4096);
        let buffers = OwnedRequestBuffers::linear(8192, 512, !write);
        let result = disk
            .execute_scsi(&buffers.buffer(&memory), &request(16, write, 0, 1, false))
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
        assert_eq!(result.tx, 0);
        assert_eq!(state.lock().storage, vec![0; 8192]);
    }
}

// Test: WRITE SAME(10/16) three sectors from a guest buffer containing extra, different bytes.
// Expected: Only the first sector repeats, FUA is forwarded, and all sectors outside the request survive.
#[async_test]
async fn write_same_repeats_only_the_first_sector_and_preserves_neighbors() {
    for size in [10, 16] {
        for fua in [false, true] {
            let (disk, state) = new_scsi_disk(
                512, 4096, 16, /* read_only: */ false, /* storage: */ true,
                /* pr: */ false,
            );
            state.lock().storage.fill(0x5c);
            let memory = GuestMemory::allocate(4096);
            memory.write_at(0, &[0xa5; 4096]).unwrap();
            let pattern: Vec<u8> = (0..512).map(|index| (index % 251) as u8).collect();
            memory.write_at(64, &pattern).unwrap();
            let buffers = OwnedRequestBuffers::linear(64, 1024, false);
            let mut request = request(size, true, 5, 3, fua);
            request.cdb[0] = if size == 10 { 0x41 } else { 0x93 };
            let result = disk.execute_scsi(&buffers.buffer(&memory), &request).await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
            assert_eq!(result.tx, 1536);
            let mut expected = vec![0x5c; 8192];
            for sector in 5..8 {
                expected[sector * 512..(sector + 1) * 512].copy_from_slice(&pattern);
            }
            assert_eq!(state.lock().storage, expected);
            assert_eq!(state.lock().is_fua_set, fua);
            let mut actual = [0; 4096];
            memory.read_at(0, &mut actual).unwrap();
            let mut expected_guest = [0xa5; 4096];
            expected_guest[64..576].copy_from_slice(&pattern);
            assert_eq!(actual, expected_guest);
        }
    }
}

// Test: Reject WRITE SAME beyond capacity, above transfer limits, with short input, or relative addressing.
// Expected: Invalid requests do not change the backing disk and report the appropriate illegal-request sense.
#[async_test]
async fn write_same_invalid_ranges_sizes_and_parameters_preserve_storage() {
    for size in [10, 16] {
        for (start, count, input_len, relative, max_transfer, additional) in [
            (
                15,
                2,
                512,
                false,
                8192,
                scsi::AdditionalSenseCode::ILLEGAL_BLOCK,
            ),
            (
                0,
                3,
                512,
                false,
                1024,
                scsi::AdditionalSenseCode::ILLEGAL_BLOCK,
            ),
            (
                0,
                1,
                511,
                false,
                8192,
                scsi::AdditionalSenseCode::INVALID_CDB,
            ),
            (
                0,
                1,
                512,
                true,
                8192,
                scsi::AdditionalSenseCode::INVALID_CDB,
            ),
        ] {
            if size == 16 && relative {
                continue;
            }
            let (backing, state) = TestDisk::new(
                512, 4096, 16, /* read_only: */ false, /* storage: */ true,
            );
            let disk = SimpleScsiDisk::new(
                Disk::new(backing).unwrap(),
                DiskParameters {
                    max_transfer_length: Some(max_transfer),
                    ..Default::default()
                },
            );
            let memory = GuestMemory::allocate(4096);
            let buffers = OwnedRequestBuffers::linear(0, input_len, false);
            let mut request = request(size, true, start, count, false);
            request.cdb[0] = if size == 10 { 0x41 } else { 0x93 };
            request.cdb[1] = u8::from(relative);
            let result = disk.execute_scsi(&buffers.buffer(&memory), &request).await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(result.tx, 0);
            assert_eq!(result.sense_data.unwrap().additional_sense_code, additional);
            assert_eq!(state.lock().storage, vec![0; 8192]);
        }
    }
}

// Test: SYNCHRONIZE CACHE(10/16), start, stop, and an unsupported immediate stop.
// Expected: Each synchronization and ordinary stop flushes once; start/immediate rejection do not flush.
#[async_test]
async fn cache_sync_and_start_stop_have_distinct_flush_effects() {
    let (disk, state) = new_scsi_disk(
        512, 4096, 16, /* read_only: */ false, /* storage: */ false, /* pr: */ false,
    );
    let memory = GuestMemory::allocate(4096);
    let buffers = OwnedRequestBuffers::linear(0, 0, false);
    for (operation, immediate, start, expected_calls, success) in [
        (0x35, 0, 0, 1, true),
        (0x91, 0, 0, 2, true),
        (0x1b, 0, 1, 2, true),
        (0x1b, 0, 0, 3, true),
        (0x1b, 1, 0, 3, false),
    ] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        cdb[1] = immediate;
        cdb[4] = start;
        let result = disk
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status == scsi::ScsiStatus::GOOD, success);
        assert_eq!(result.tx, 0);
        assert_eq!(state.lock().sync_cache_calls, expected_calls);
        if !success {
            assert_eq!(
                result.sense_data.unwrap().additional_sense_code,
                scsi::AdditionalSenseCode::INVALID_CDB
            );
        }
    }
}

// Test: Inject a backend cache-flush failure for both synchronization CDB forms and stop.
// Expected: A failed flush is reported as a failed command rather than successful durable completion.
#[async_test]
async fn cache_flush_errors_are_propagated_to_the_initiator() {
    let (mut backing, state) = TestDisk::new(
        512, 4096, 16, /* read_only: */ false, /* storage: */ false,
    );
    backing.fail_sync = true;
    let disk = SimpleScsiDisk::new(Disk::new(backing).unwrap(), Default::default());
    let memory = GuestMemory::allocate(4096);
    let buffers = OwnedRequestBuffers::linear(0, 0, false);
    for (index, operation) in [0x35, 0x91, 0x1b].into_iter().enumerate() {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        let result = disk
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::ERROR);
        assert_eq!(result.tx, 0);
        assert_eq!(state.lock().sync_cache_calls, index + 1);
    }
}
