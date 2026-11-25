// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::scsi;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};

fn pages() -> Vec<Vec<u8>> {
    let mut recovery = vec![0; 12];
    recovery[..2].copy_from_slice(&[1, 10]);
    let mut power = vec![0; 12];
    power[..2].copy_from_slice(&[0x1a, 10]);
    vec![
        recovery,
        power,
        vec![0x1d, 10, 0, 0, 0, 0, 0, 5, 0, 20, 0, 10],
    ]
}

// Test: Request current/default recovery, power, inactivity, and all DVD mode pages at truncation boundaries.
// Expected: Exact mode headers and page payloads retain timeout values, ordering, and guarded allocation limits.
#[async_test]
async fn dvd_mode_sense_returns_exact_individual_and_combined_pages() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut cases = pages();
    cases.push(pages().into_iter().flatten().collect());
    for (code, body) in [1, 0x1a, 0x1d, 0x3f].into_iter().zip(cases) {
        let mut expected = vec![0; 8];
        expected[1] = (body.len() + 6) as u8;
        expected.extend(body);
        for page_control in [0, 0x80] {
            for allocation in [0, 1, 7, 8, 9, expected.len() - 1, expected.len(), 128] {
                let mut cdb = [0; 16];
                cdb[0] = 0x5a;
                cdb[2] = code | page_control;
                cdb[7..9].copy_from_slice(&(allocation as u16).to_be_bytes());
                check_response(&dvd, cdb, 128, &expected[..allocation.min(expected.len())]).await;
            }
        }
    }
}

// Test: Select each supported DVD mode page, empty parameters, and a header-only parameter list.
// Expected: Accepted input is not modified and the documented default mode pages remain stable.
#[async_test]
async fn dvd_mode_select_accepts_supported_pages_without_modifying_parameters() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut parameters = vec![vec![], vec![0; 8]];
    parameters.extend(pages().into_iter().map(|page| {
        let mut data = vec![0; 8];
        data.extend(page);
        data
    }));
    for data in parameters {
        let memory = GuestMemory::allocate(4096);
        let mut expected = [0xa5; 256];
        expected[16..16 + data.len()].copy_from_slice(&data);
        memory.write_at(0, &expected).unwrap();
        let buffers = OwnedRequestBuffers::new_unaligned(&[0], 16, data.len());
        let mut cdb = [0; 16];
        cdb[0] = 0x55;
        cdb[1] = 0x10;
        cdb[7..9].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
    let mut cdb = [0; 16];
    cdb[0] = 0x5a;
    cdb[2] = 0x3f;
    cdb[8] = 128;
    let mut expected = vec![0, 42, 0, 0, 0, 0, 0, 0];
    expected.extend(pages().into_iter().flatten());
    check_response(&dvd, cdb, 128, &expected).await;
}

// Test: Supply truncated, saved, unsupported, and overrun DVD MODE SELECT parameters.
// Expected: Typed error status and zero transfer preserve the entire parameter list and surrounding memory.
#[async_test]
async fn invalid_dvd_mode_select_parameters_are_rejected_without_writes() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (length, flags, page, expected_status) in [
        (1, 0x10, 1, scsi::srb::SrbStatus::ERROR),
        (7, 0x10, 1, scsi::srb::SrbStatus::ERROR),
        (9, 0x10, 1, scsi::srb::SrbStatus::ERROR),
        (19, 0x10, 1, scsi::srb::SrbStatus::ERROR),
        (20, 0x11, 1, scsi::srb::SrbStatus::ERROR),
        (20, 0x10, 0xff, scsi::srb::SrbStatus::INVALID_REQUEST),
        (21, 0x10, 1, scsi::srb::SrbStatus::DATA_OVERRUN),
    ] {
        let memory = GuestMemory::allocate(4096);
        let mut expected = [0xa5; 256];
        expected[16..36].fill(0);
        expected[24] = page;
        expected[25] = 10;
        memory.write_at(0, &expected).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 20, false);
        let mut cdb = [0; 16];
        cdb[0] = 0x55;
        cdb[1] = flags;
        cdb[8] = length;
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(
            result.scsi_status,
            scsi::ScsiStatus::CHECK_CONDITION,
            "{cdb:?}"
        );
        assert_eq!(result.srb_status, expected_status, "{cdb:?}");
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

// Test: Request saved or unsupported DVD mode pages, or more bytes than fit in the response buffer.
// Expected: Invalid/saved-page and overrun failures leave the response and guards untouched.
#[async_test]
async fn invalid_dvd_mode_sense_requests_preserve_guest_memory() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (page, allocation, expected_status) in [
        (0xc1, 128, scsi::srb::SrbStatus::ERROR),
        (0x2a, 128, scsi::srb::SrbStatus::ERROR),
        (1, 129, scsi::srb::SrbStatus::DATA_OVERRUN),
    ] {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 128, true);
        let mut cdb = [0; 16];
        cdb[0] = 0x5a;
        cdb[2] = page;
        cdb[8] = allocation;
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
