// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::TestDisk;
use crate::{SimpleScsiDisk, scsi};
use disk_backend::Disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};
use scsidisk_resources::DiskParameters;

fn disk(sectors: u64, enabled: bool) -> SimpleScsiDisk {
    let (backing, _) = TestDisk::new(
        512, 512, sectors, /* read_only: */ false, /* storage: */ false,
    );
    SimpleScsiDisk::new(
        Disk::new(backing).unwrap(),
        DiskParameters {
            get_lba_status: enabled,
            ..Default::default()
        },
    )
}

fn request(start: u64, allocation: u32, flags: u32) -> Request {
    let mut cdb = [0; 16];
    cdb[..2].copy_from_slice(&[0x9e, 0x12]);
    cdb[2..10].copy_from_slice(&start.to_be_bytes());
    cdb[10..14].copy_from_slice(&allocation.to_be_bytes());
    Request {
        cdb,
        srb_flags: flags,
    }
}

async fn check_response(sectors: u64, start: u64, allocation: usize, ranges: &[(u64, u32)]) {
    let disk = disk(sectors, true);
    let mut expected = vec![0; 8 + ranges.len() * 16];
    let parameter_length = (expected.len() - 4) as u32;
    expected[..4].copy_from_slice(&parameter_length.to_be_bytes());
    for (index, &(start, count)) in ranges.iter().enumerate() {
        let offset = 8 + index * 16;
        expected[offset..offset + 8].copy_from_slice(&start.to_be_bytes());
        expected[offset + 8..offset + 12].copy_from_slice(&count.to_be_bytes());
    }
    for flags in [0, scsi::SRB_FLAGS_CONSOLIDATEABLE_BLOCKS_ONLY] {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, allocation, true);
        let result = disk
            .execute_scsi(
                &buffers.buffer(&memory),
                &request(start, allocation as u32, flags),
            )
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
        assert_eq!(result.tx, expected.len());
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        let mut guarded_expected = [0xa5; 256];
        guarded_expected[16..16 + expected.len()].copy_from_slice(&expected);
        assert_eq!(
            actual, guarded_expected,
            "sectors {sectors}, start {start}, allocation {allocation}"
        );
    }
}

// Test: Request mapped LBA status at the start, middle, and final sector of a fixed disk.
// Expected: One mapped descriptor covers exactly the remaining sectors with big-endian wire fields.
#[async_test]
async fn mapped_ranges_cover_exactly_the_remaining_disk() {
    for start in [0, 1, 1023] {
        check_response(1024, start, 24, &[(start, (1024 - start) as u32)]).await;
        check_response(1024, start, 128, &[(start, (1024 - start) as u32)]).await;
    }
}

// Test: Describe mapped disks requiring one, two, or three 32-bit block-count descriptors.
// Expected: Adjacent descriptors cover the requested suffix exactly, including an unaligned first LBA.
#[async_test]
async fn large_mapped_ranges_split_without_losing_or_duplicating_sectors() {
    let maximum = u64::from(u32::MAX);
    check_response(maximum, 0, 128, &[(0, u32::MAX)]).await;
    check_response(maximum + 10, 0, 128, &[(0, u32::MAX), (maximum, 10)]).await;
    check_response(maximum + 10, 5, 128, &[(5, u32::MAX), (maximum + 5, 5)]).await;
    check_response(
        maximum * 2 + 10,
        0,
        128,
        &[(0, u32::MAX), (maximum, u32::MAX), (maximum * 2, 10)],
    )
    .await;
}

// Test: Limit a multi-descriptor mapped response to space for one descriptor.
// Expected: The first complete descriptor is returned without exceeding allocation or guest guards.
#[async_test]
async fn allocation_limits_the_number_of_complete_descriptors() {
    check_response(u64::from(u32::MAX) + 10, 0, 24, &[(0, u32::MAX)]).await;
}

// Test: Issue GET LBA STATUS with a zero allocation at a valid starting LBA.
// Expected: The SCSI-defined zero-allocation special case succeeds without writing or transferring data.
#[async_test]
async fn zero_allocation_completes_without_data() {
    let disk = disk(64, true);
    let memory = GuestMemory::allocate(4096);
    let buffers = OwnedRequestBuffers::linear(0, 0, true);
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &request(0, 0, 0))
        .await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
    assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
    assert_eq!(result.tx, 0);
}

// Test: Request disabled capability, invalid starting LBAs, undersized responses, or mismatched lengths.
// Expected: Illegal requests report zero transfer and leave the entire mapped destination unchanged.
#[async_test]
async fn invalid_lba_status_requests_preserve_guest_output() {
    for (sectors, enabled, start, allocation, buffer_len) in [
        (64, false, 0, 24, 24),
        (64, true, 64, 24, 24),
        (64, true, u64::MAX, 24, 24),
        (0, true, 0, 24, 24),
        (64, true, 0, 23, 23),
        (64, true, 0, 24, 25),
    ] {
        let disk = disk(sectors, enabled);
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 64]).unwrap();
        let buffers = OwnedRequestBuffers::linear(0, buffer_len, true);
        let result = disk
            .execute_scsi(&buffers.buffer(&memory), &request(start, allocation, 0))
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
        assert_eq!(
            result.sense_data.unwrap().header.sense_key,
            scsi::SenseKey::ILLEGAL_REQUEST
        );
        assert_eq!(result.tx, 0);
        let mut actual = [0; 64];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 64]);
    }
}

// Test: Return a valid mapped-range response into an unbacked guest page.
// Expected: Guest-memory failure is a typed invalid SCSI request rather than success or a panic.
#[async_test]
async fn inaccessible_response_memory_returns_a_scsi_error() {
    let disk = disk(64, true);
    let memory = GuestMemory::allocate(4096);
    let buffers = OwnedRequestBuffers::linear(8192, 24, true);
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &request(0, 24, 0))
        .await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
    assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
    assert_eq!(result.tx, 0);
}
