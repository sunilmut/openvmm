// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use pal_async::async_test;

// Test: Read DVD capacity with the same ISO size backed by 512/1024/2048-byte sectors.
// Expected: The guest always sees sixteen 2048-byte sectors and untouched response-buffer guards.
#[async_test]
async fn dvd_capacity_is_independent_of_backing_sector_size() {
    for backing_sector in [512, 1024, 2048] {
        let (dvd, _) = new_scsi_dvd(
            backing_sector,
            backing_sector,
            16 * (2048 / backing_sector) as u64,
            false,
        );
        let mut cdb = [0; 16];
        cdb[0] = 0x25;
        check_response(&dvd, cdb, 128, &[0, 0, 0, 15, 0, 0, 8, 0]).await;
    }
}

// Test: Request the optical drive's single-session TOC using LBA and MSF addressing.
// Expected: Both responses identify track one, with a zero LBA or a two-second MSF lead-in address.
#[async_test]
async fn dvd_session_toc_encodes_lba_and_msf_track_addresses() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for msf in [false, true] {
        let mut expected = [0, 10, 1, 1, 0, 0x14, 1, 0, 0, 0, 0, 0];
        if msf {
            expected[10] = 2;
        }
        for allocation in [0, 1, 4, 11, 12, 32] {
            let mut cdb = [0; 16];
            cdb[0] = 0x43;
            cdb[1] = if msf { 2 } else { 0 };
            cdb[2] = 1;
            cdb[7..9].copy_from_slice(&(allocation as u16).to_be_bytes());
            check_response(&dvd, cdb, 128, &expected[..allocation.min(expected.len())]).await;
        }
    }
}

// Test: Request mechanism status and buffer capacity at multiple allocations.
// Expected: Fixed optical-device fields retain their wire values and replies truncate without overwrites.
#[async_test]
async fn dvd_small_status_replies_have_stable_fields_and_allocation_bounds() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mechanism = vec![0; 8];
    let mut buffer_capacity = vec![0; 12];
    buffer_capacity[1] = 10;
    for (operation, length_offset, expected) in [(0xbd, 8, mechanism), (0x5c, 7, buffer_capacity)] {
        for allocation in [
            0,
            1,
            4,
            expected.len() - 1,
            expected.len(),
            expected.len() + 8,
        ] {
            let mut cdb = [0; 16];
            cdb[0] = operation;
            cdb[length_offset..length_offset + 2]
                .copy_from_slice(&(allocation as u16).to_be_bytes());
            check_response(&dvd, cdb, 128, &expected[..allocation.min(expected.len())]).await;
        }
    }
    let mut cdb = [0; 16];
    cdb[0] = 0x5c;
    cdb[1] = 1;
    cdb[8] = 12;
    check_response(&dvd, cdb, 128, &[0, 10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).await;
    cdb = [0; 16];
    cdb[0] = 0xb6;
    check_response(&dvd, cdb, 0, &[]).await;
}

// Test: Known product bug: request full disc information when zero OPC entries are reported.
// Expected: The declared 34-byte response is returned without an unadvertised OPC placeholder.
#[async_test]
#[ignore = "known product bug: disc information emits an OPC entry despite declaring zero entries"]
async fn known_bug_disc_information_transfer_matches_its_declared_length() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut expected = [0; 34];
    expected[..8].copy_from_slice(&[0, 32, 14, 1, 1, 1, 1, 0x20]);
    let mut cdb = [0; 16];
    cdb[0] = 0x51;
    cdb[8] = 128;
    check_response(&dvd, cdb, 128, &expected).await;
}
