// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{TestDisk, TestDiskStorageState};
use crate::{SimpleScsiDisk, scsi};
use disk_backend::{Disk, UnmapBehavior};
use guestmem::GuestMemory;
use pal_async::async_test;
use parking_lot::Mutex;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request, ScsiResult};
use scsidisk_resources::DiskParameters;
use std::sync::Arc;

fn configured_disk(
    sectors: u64,
    read_only: bool,
    behavior: UnmapBehavior,
    fail: bool,
) -> (SimpleScsiDisk, Arc<Mutex<TestDiskStorageState>>) {
    let (mut backing, state) = TestDisk::new(512, 4096, sectors, read_only, false);
    backing.unmap_behavior = behavior;
    backing.fail_unmap = fail;
    (
        SimpleScsiDisk::new(
            Disk::new(backing).unwrap(),
            DiskParameters {
                unmap: Some(true),
                ..Default::default()
            },
        ),
        state,
    )
}

fn parameter_list(ranges: &[(u64, u32)]) -> Vec<u8> {
    let mut bytes = vec![0; 8 + ranges.len() * 16];
    let length = bytes.len();
    bytes[..2].copy_from_slice(&((length - 2) as u16).to_be_bytes());
    bytes[2..4].copy_from_slice(&((length - 8) as u16).to_be_bytes());
    for (index, &(start, count)) in ranges.iter().enumerate() {
        let offset = 8 + index * 16;
        bytes[offset..offset + 8].copy_from_slice(&start.to_be_bytes());
        bytes[offset + 8..offset + 12].copy_from_slice(&count.to_be_bytes());
    }
    bytes
}

async fn execute_unmap(
    disk: &SimpleScsiDisk,
    parameters: &[u8],
    allocation: u16,
    flags: u32,
) -> ScsiResult {
    let memory = GuestMemory::allocate(parameters.len().max(4096));
    memory.write_at(0, parameters).unwrap();
    let buffers = OwnedRequestBuffers::linear(0, parameters.len(), false);
    let mut cdb = [0; 16];
    cdb[0] = 0x42;
    cdb[7..9].copy_from_slice(&allocation.to_be_bytes());
    let result = disk
        .execute_scsi(
            &buffers.buffer(&memory),
            &Request {
                cdb,
                srb_flags: flags,
            },
        )
        .await;
    let mut actual = vec![0; parameters.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(
        actual, parameters,
        "UNMAP must not overwrite its parameter list"
    );
    result
}

// Test: Submit multiple UNMAP descriptors, including an empty range, with each block-level flag.
// Expected: Only nonempty ranges reach the backend, in order, with the original flag and no data transfer.
#[async_test]
async fn unmap_dispatches_nonempty_descriptors_in_order_and_forwards_block_level_flag() {
    for (flags, block_level_only) in [(0, false), (scsi::SRB_FLAGS_BLOCK_LEVEL_ONLY, true)] {
        let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
        let parameters = parameter_list(&[(3, 4), (12, 0), (21, 5)]);
        let result = execute_unmap(&disk, &parameters, parameters.len() as u16, flags).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
        assert_eq!(result.tx, 0);
        assert_eq!(
            state.lock().unmap_calls,
            [(3, 4, block_level_only), (21, 5, block_level_only)]
        );
    }
}

// Test: Submit empty lists and zero-length descriptors before and after useful ranges.
// Expected: Empty work succeeds without backend calls and never prevents later nonempty work.
#[async_test]
async fn empty_lists_and_zero_length_descriptors_are_noops() {
    for (ranges, expected) in [
        (vec![], vec![]),
        (vec![(0, 0)], vec![]),
        (vec![(10, 0), (3, 4), (20, 0)], vec![(3, 4, false)]),
    ] {
        let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
        let parameters = parameter_list(&ranges);
        let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        assert_eq!(result.tx, 0);
        assert_eq!(state.lock().unmap_calls, expected);
    }
}

// Test: Submit mismatched CDB allocation, list length, and descriptor-length fields.
// Expected: Every malformed list is rejected as an illegal request before any backend UNMAP.
#[async_test]
async fn malformed_parameter_lengths_never_reach_the_backend() {
    let valid = parameter_list(&[(3, 4)]);
    let mut wrong_data_length = valid.clone();
    wrong_data_length[..2].copy_from_slice(&0u16.to_be_bytes());
    let mut wrong_descriptor_length = valid.clone();
    wrong_descriptor_length[2..4].copy_from_slice(&0u16.to_be_bytes());
    for (parameters, allocation) in [
        (vec![0; 7], 7),
        (valid.clone(), 0),
        (valid.clone(), 23),
        (valid, 25),
        (wrong_data_length, 24),
        (wrong_descriptor_length, 24),
    ] {
        let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
        let result = execute_unmap(&disk, &parameters, allocation, 0).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
        assert_eq!(result.tx, 0);
        assert_eq!(
            result.sense_data.unwrap().header.sense_key,
            scsi::SenseKey::ILLEGAL_REQUEST
        );
        assert!(state.lock().unmap_calls.is_empty());
    }
}

// Test: Submit descriptors starting beyond capacity or extending beyond its final sector.
// Expected: ILLEGAL BLOCK is reported and no out-of-range UNMAP reaches the backing disk.
#[async_test]
async fn out_of_range_descriptors_are_rejected_without_backend_calls() {
    for range in [(64, 0), (64, 1), (63, 2), (0, 65), (u64::MAX, 1)] {
        let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
        let parameters = parameter_list(&[range]);
        let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
        assert_eq!(
            sense.additional_sense_code,
            scsi::AdditionalSenseCode::ILLEGAL_BLOCK
        );
        assert!(state.lock().unmap_calls.is_empty());
    }
}

// Test: Put an invalid descriptor between valid UNMAP descriptors.
// Expected: Only the accepted prefix reaches the backend; the invalid and following ranges do not.
#[async_test]
async fn invalid_later_descriptor_stops_further_dispatch() {
    let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
    let parameters = parameter_list(&[(3, 4), (63, 2), (21, 5)]);
    let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
    assert_eq!(
        result.sense_data.unwrap().additional_sense_code,
        scsi::AdditionalSenseCode::ILLEGAL_BLOCK
    );
    assert_eq!(state.lock().unmap_calls, [(3, 4, false)]);
}

// Test: Request more than the backend's 32-bit byte-length limit in one UNMAP descriptor.
// Expected: Adjacent subranges cover the exact request once without gaps, overlap, or oversized dispatch.
#[async_test]
async fn large_unmap_is_split_into_exact_adjacent_subranges() {
    let (disk, state) = configured_disk(20_000_000, false, UnmapBehavior::Unspecified, false);
    let parameters = parameter_list(&[(2, 8_388_610)]);
    let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
    assert_eq!(result.tx, 0);
    assert_eq!(
        state.lock().unmap_calls,
        [(2, 8_388_607, false), (8_388_609, 3, false)]
    );
}

// Test: Inject a backend UNMAP failure for every valid range in a multi-descriptor request.
// Expected: Best-effort discard continues to later ranges and reports successful command completion.
#[async_test]
async fn best_effort_backend_failures_do_not_stop_later_unmaps() {
    let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, true);
    let parameters = parameter_list(&[(3, 4), (21, 5)]);
    let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
    assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
    assert_eq!(state.lock().unmap_calls, [(3, 4, false), (21, 5, false)]);
}

// Test: Send UNMAP to read-only media and to an explicitly supported but ignored-discard backend.
// Expected: Read-only media reports write protection; an ignored discard is a successful backend no-op.
#[async_test]
async fn read_only_and_ignored_backends_have_distinct_unmap_results() {
    for (read_only, behavior) in [
        (true, UnmapBehavior::Unspecified),
        (false, UnmapBehavior::Ignored),
    ] {
        let (disk, state) = configured_disk(64, read_only, behavior, false);
        let parameters = parameter_list(&[(3, 4)]);
        let result = execute_unmap(&disk, &parameters, parameters.len() as u16, 0).await;
        if read_only {
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            let sense = result.sense_data.unwrap();
            assert_eq!(sense.header.sense_key, scsi::SenseKey::DATA_PROTECT);
            assert_eq!(
                sense.additional_sense_code,
                scsi::AdditionalSenseCode::WRITE_PROTECT
            );
        } else {
            assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        }
        assert_eq!(result.tx, 0);
        assert!(state.lock().unmap_calls.is_empty());
    }
}

// Test: Place a syntactically valid UNMAP parameter range entirely outside guest memory.
// Expected: A typed invalid-request result is returned without panicking or dispatching a discard.
#[async_test]
async fn unmap_parameter_memory_fault_does_not_dispatch() {
    let (disk, state) = configured_disk(64, false, UnmapBehavior::Unspecified, false);
    let memory = GuestMemory::allocate(4096);
    let buffers = OwnedRequestBuffers::linear(8192, 24, false);
    let mut cdb = [0; 16];
    cdb[0] = 0x42;
    cdb[7..9].copy_from_slice(&24u16.to_be_bytes());
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
        .await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
    assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
    assert_eq!(result.tx, 0);
    assert!(state.lock().unmap_calls.is_empty());
}

// Test: Split high-LBA UNMAP requests on 512-byte and 4 KiB disks, then discard the final sector.
// Expected: Backend ranges retain all LBA bits, use sector-sized chunk limits, and stay within capacity.
#[async_test]
async fn high_lba_unmap_chunking_preserves_sector_units_and_capacity_boundary() {
    for sector_size in [512u32, 4096] {
        let start = (1u64 << 40) + 3;
        let chunk = u32::MAX / sector_size;
        let count = chunk + 3;
        let capacity = start + u64::from(count) + 8;
        let (mut backing, state) = TestDisk::new(sector_size, 4096, capacity, false, false);
        backing.unmap_behavior = UnmapBehavior::Unspecified;
        let disk = SimpleScsiDisk::new(
            Disk::new(backing).unwrap(),
            DiskParameters {
                unmap: Some(true),
                ..Default::default()
            },
        );
        let parameters = parameter_list(&[(start, count), (capacity - 1, 1)]);
        let result = execute_unmap(
            &disk,
            &parameters,
            parameters.len() as u16,
            scsi::SRB_FLAGS_BLOCK_LEVEL_ONLY,
        )
        .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
        assert!(result.sense_data.is_none());
        assert_eq!(result.tx, 0);
        assert_eq!(
            state.lock().unmap_calls,
            [
                (start, u64::from(chunk), true),
                (start + u64::from(chunk), 3, true),
                (capacity - 1, 1, true),
            ],
            "sector size {sector_size}"
        );
    }
}
