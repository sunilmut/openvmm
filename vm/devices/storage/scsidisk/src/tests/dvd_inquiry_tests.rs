// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::scsi;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};

fn inquiry(flags: u8, page: u8, allocation: u16) -> [u8; 16] {
    let mut cdb = [0; 16];
    cdb[..3].copy_from_slice(&[0x12, flags, page]);
    cdb[3..5].copy_from_slice(&allocation.to_be_bytes());
    cdb
}

// Test: Request standard DVD identity and supported/device-identifier VPD pages at header/body boundaries.
// Expected: Removable DVD identity, vendor/product/revision, supported pages, and the binary identifier match literal bytes.
#[async_test]
async fn dvd_inquiry_reports_exact_standard_and_vpd_identities() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut standard = vec![0; 36];
    standard[..8].copy_from_slice(&[5, 0x80, 0, 2, 31, 0, 0, 0]);
    standard[8..16].copy_from_slice(b"Msft    ");
    standard[16..32].copy_from_slice(b"Virtual DVD-ROM ");
    standard[32..36].copy_from_slice(b"1.0 ");
    let mut identifiers = vec![5, 0x83, 0, 28, 1, 1, 0, 24];
    identifiers.extend_from_slice(b"Msft    ");
    identifiers.extend_from_slice(&[
        0x73, 5, 0xe3, 0x43, 0x77, 3, 0x54, 0x46, 0x94, 0x95, 0x7d, 0x7c, 0xed, 0x62, 0x4a, 0x7d,
    ]);
    for (flags, page, expected) in [
        (0, 0, standard),
        (1, 0, vec![5, 0, 0, 2, 0, 0x83]),
        (1, 0x83, identifiers),
    ] {
        let mut allocations = vec![4, 5, expected.len() - 1, expected.len()];
        if flags == 1 {
            allocations.push(128);
        }
        for allocation in allocations {
            check_response(
                &dvd,
                inquiry(flags, page, allocation as u16),
                128,
                &expected[..allocation.min(expected.len())],
            )
            .await;
        }
    }
}

// Test: Request nonzero standard pages, unsupported VPD, incomplete VPD headers, and oversized allocations.
// Expected: Exact invalid-CDB/overrun statuses transfer nothing and leave every response byte untouched.
#[async_test]
async fn invalid_dvd_inquiry_requests_preserve_guest_output() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (cdb, expected_status) in [
        (inquiry(0, 1, 128), scsi::srb::SrbStatus::ERROR),
        (inquiry(1, 0x80, 128), scsi::srb::SrbStatus::ERROR),
        (inquiry(1, 0, 3), scsi::srb::SrbStatus::DATA_OVERRUN),
        (inquiry(0, 0, 129), scsi::srb::SrbStatus::DATA_OVERRUN),
    ] {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 128, true);
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, expected_status);
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 256]);
    }
}

// Test: Return standard and both VPD replies into unbacked and page-crossing response ranges.
// Expected: Header/body guest-memory failures become INVALID_REQUEST/INVALID_CDB rather than false success or panic.
#[async_test]
async fn dvd_inquiry_memory_faults_are_typed_errors() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for cdb in [
        inquiry(0, 0, 128),
        inquiry(1, 0, 128),
        inquiry(1, 0x83, 128),
    ] {
        for buffers in [
            OwnedRequestBuffers::new_unaligned(&[2], 0, 128),
            OwnedRequestBuffers::new_unaligned(&[0, 1], 4092, 128),
        ] {
            let memory = GuestMemory::allocate(4096);
            let result = dvd
                .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
                .await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
            assert_eq!(result.tx, 0);
            let sense = result.sense_data.unwrap();
            assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
            assert_eq!(
                sense.additional_sense_code,
                scsi::AdditionalSenseCode::INVALID_CDB
            );
        }
    }
}

// Test: Request DVD sense with empty, truncated, exact, and larger allocations.
// Expected: The DVD's no-sense reply truncates at allocation or its fixed 18-byte size and leaves guards intact.
#[async_test]
async fn dvd_request_sense_respects_allocation_and_fixed_response_size() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut expected = [0; 18];
    expected[0] = 0x70;
    expected[7] = 10;
    for allocation in [0, 1, 7, 8, 17, 18, 32] {
        let mut cdb = [0; 16];
        cdb[0] = 3;
        cdb[4] = allocation;
        check_response(&dvd, cdb, 128, &expected[..usize::from(allocation).min(18)]).await;
    }
}

// Test: Known product bug: request more standard DVD INQUIRY bytes than its declared 36-byte identity.
// Expected: Transfer stops at additional-length plus five and leaves the rest of the response buffer untouched.
#[async_test]
#[ignore = "known product bug: DVD INQUIRY transfers 104 bytes while declaring a 36-byte identity"]
async fn known_bug_dvd_standard_inquiry_transfer_matches_declared_identity_length() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let memory = GuestMemory::allocate(4096);
    memory.write_at(0, &[0xa5; 256]).unwrap();
    let buffers = OwnedRequestBuffers::linear(0, 128, true);
    let result = dvd
        .execute_scsi(
            &buffers.buffer(&memory),
            &Request {
                cdb: inquiry(0, 0, 128),
                srb_flags: 0,
            },
        )
        .await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
    assert_eq!(result.tx, 36);
    let mut actual = [0; 256];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual[4], 31);
    assert_eq!(&actual[36..], &[0xa5; 220]);
}
