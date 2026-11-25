// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::{atapi_scsi::AtapiScsiDisk, scsi};
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request, ScsiResult, ScsiSaveRestore};
use std::sync::Arc;

fn dvd() -> AtapiScsiDisk {
    let (inner, _) = new_scsi_dvd(2048, 2048, 1024, false);
    AtapiScsiDisk::new(Arc::new(inner))
}

async fn command(
    disk: &dyn AsyncScsiDisk,
    cdb: [u8; 16],
    buffer_len: usize,
) -> (ScsiResult, [u8; 256]) {
    let memory = GuestMemory::allocate(4096);
    memory.write_at(0, &[0xa5; 256]).unwrap();
    let buffers = OwnedRequestBuffers::new_unaligned(&[0], 16, buffer_len);
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
        .await;
    let mut actual = [0; 256];
    memory.read_at(0, &mut actual).unwrap();
    (result, actual)
}

fn sense_request(allocation: u16) -> [u8; 16] {
    let mut cdb = [0; 16];
    cdb[0] = 3;
    cdb[3..5].copy_from_slice(&allocation.to_be_bytes());
    cdb
}

fn expected_sense(illegal: bool) -> [u8; 18] {
    let mut expected = [0; 18];
    expected[0] = 0x70;
    expected[7] = 10;
    if illegal {
        expected[2] = 5;
        expected[12] = 0x20;
    }
    expected
}

// Test: Forward DVD capacity requests, seek without media, and reject commands outside the ATAPI allowlist.
// Expected: Forwarded payloads survive unchanged; SEEK is a no-op; rejected commands never touch the output buffer.
#[async_test]
async fn atapi_forwards_capacity_but_filters_unsupported_commands() {
    let disk = dvd();
    let mut cdb = [0; 16];
    cdb[0] = 0x25;
    check_response(&disk, cdb, 128, &[0, 0, 3, 0xff, 0, 0, 8, 0]).await;
    let disk = AtapiScsiDisk::new(Arc::new(crate::scsidvd::SimpleScsiDvd::new(None)));
    cdb[0] = 0x2b;
    check_response(&disk, cdb, 0, &[]).await;
    for operation in [0xff, 0x2a, 0x35, 0x52, 0xac] {
        cdb[0] = operation;
        let (result, actual) = command(&disk, cdb, 128).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
        assert_eq!(
            sense.additional_sense_code,
            scsi::AdditionalSenseCode::ILLEGAL_COMMAND
        );
        assert_eq!(actual, [0xa5; 256]);
    }
}

// Test: Retrieve the wrapper's saved illegal-command sense at short and full allocations, then retrieve it again.
// Expected: REQUEST SENSE reports and consumes the error exactly once with byte-exact guarded replies.
#[async_test]
async fn atapi_request_sense_consumes_the_wrapper_error_once() {
    for allocation in [8, 17, 18, 32] {
        let disk = dvd();
        let mut illegal = [0; 16];
        illegal[0] = 0xff;
        let _ = command(&disk, illegal, 0).await;
        let expected = expected_sense(true);
        check_response(
            &disk,
            sense_request(allocation),
            128,
            &expected[..usize::from(allocation).min(18)],
        )
        .await;
        check_response(&disk, sense_request(18), 128, &expected_sense(false)).await;
    }
}

// Test: Save wrapper sense over a DVD child, clear the nexus, then restore and request sense.
// Expected: Nexus clearing removes the wrapper error and restoring the saved state reinstates it once.
#[async_test]
async fn atapi_saved_sense_survives_restore_and_clear_nexus_removes_it() {
    let disk = dvd();
    let mut illegal = [0; 16];
    illegal[0] = 0xff;
    let _ = command(&disk, illegal, 0).await;
    let saved = disk.save().unwrap().unwrap();
    disk.clear_nexus_state();
    check_response(&disk, sense_request(18), 128, &expected_sense(false)).await;
    disk.restore(&saved).unwrap();
    check_response(&disk, sense_request(18), 128, &expected_sense(true)).await;
    check_response(&disk, sense_request(18), 128, &expected_sense(false)).await;
}

// Test: Request the ATAPI LUN list with zero, exact, and larger allocations.
// Expected: A successful reply lists exactly LUN zero, or transfers nothing for zero allocation.
#[async_test]
async fn atapi_report_luns_returns_one_zero_lun_without_overwriting_guards() {
    let disk = dvd();
    for allocation in [0u32, 16, 32, 128] {
        let mut cdb = [0; 16];
        cdb[0] = 0xa0;
        cdb[6..10].copy_from_slice(&allocation.to_be_bytes());
        let expected = [0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        check_response(
            &disk,
            cdb,
            128,
            if allocation == 0 { &[] } else { &expected },
        )
        .await;
    }
}

// Test: Supply too-small sense/LUN allocations and allocations exceeding the guest response buffer.
// Expected: The wrapper returns CHECK CONDITION/ERROR, zero transfer, and leaves all guest bytes unchanged.
#[async_test]
async fn invalid_atapi_allocations_return_errors_without_writes() {
    let disk = dvd();
    let mut cases = vec![sense_request(0), sense_request(7), sense_request(129)];
    for allocation in [1u32, 15, 129] {
        let mut cdb = [0; 16];
        cdb[0] = 0xa0;
        cdb[6..10].copy_from_slice(&allocation.to_be_bytes());
        cases.push(cdb);
    }
    for cdb in cases {
        let (result, actual) = command(&disk, cdb, 128).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::ERROR);
        assert_eq!(result.tx, 0);
        assert_eq!(actual, [0xa5; 256]);
    }
}

// Test: Return sense and LUN replies into an unbacked guest page.
// Expected: Guest-memory faults become INVALID_REQUEST/INVALID_CDB results rather than panics or false success.
#[async_test]
async fn atapi_response_memory_faults_are_typed_errors() {
    let disk = dvd();
    let mut luns = [0; 16];
    luns[0] = 0xa0;
    luns[9] = 16;
    for cdb in [sense_request(18), luns] {
        let memory = GuestMemory::allocate(4096);
        let buffers = OwnedRequestBuffers::new_unaligned(&[1], 0, 128);
        let result = disk
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
