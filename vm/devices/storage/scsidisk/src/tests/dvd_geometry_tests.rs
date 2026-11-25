// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::scsi;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};

// Test: Request allocated prefixes of physical, copyright, and manufacturing DVD structures.
// Expected: Single-layer DVD-ROM identity, physical start sector, and unprotected copyright fields match the wire format.
#[async_test]
async fn dvd_structure_prefixes_encode_single_layer_unprotected_media() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (format, expected) in [
        (
            0,
            vec![
                8, 2, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (1, vec![0, 6, 0, 0, 0, 0, 0]),
        (4, vec![8, 2, 0, 0]),
    ] {
        for allocation in 0..=expected.len() {
            let mut cdb = [0; 16];
            cdb[0] = 0xad;
            cdb[7] = format;
            cdb[8..10].copy_from_slice(&(allocation as u16).to_be_bytes());
            check_response(&dvd, cdb, 128, &expected[..allocation]).await;
        }
    }
}

// Test: Supply unsupported track/session/open requests, DVD media/layer/format, and performance modes.
// Expected: Commands fail with zero transfer, typed request/overrun status, and no response-buffer mutation.
#[async_test]
async fn invalid_optical_geometry_requests_preserve_output_and_report_errors() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut cases = Vec::new();
    for flags in [0, 1, 2, 3, 5] {
        let mut cdb = [0; 16];
        cdb[0] = 0x52;
        cdb[1] = flags;
        cdb[8] = 48;
        cases.push((
            cdb,
            if flags == 3 {
                scsi::srb::SrbStatus::INVALID_REQUEST
            } else {
                scsi::srb::SrbStatus::ERROR
            },
        ));
    }
    for (media, layer, format) in [(1, 0, 0), (0, 1, 0), (0, 0, 3), (0, 0, 0xff)] {
        let mut cdb = [0; 16];
        cdb[0] = 0xad;
        cdb[1] = media;
        cdb[6] = layer;
        cdb[7] = format;
        cdb[9] = 64;
        cases.push((
            cdb,
            if layer != 0 || format == 3 {
                scsi::srb::SrbStatus::INVALID_REQUEST
            } else {
                scsi::srb::SrbStatus::ERROR
            },
        ));
    }
    for (flags, data_type) in [(0, 0), (0x14, 0), (0x13, 0), (0x10, 1)] {
        let mut cdb = [0; 16];
        cdb[0] = 0xac;
        cdb[1] = flags;
        cdb[9] = 1;
        cdb[10] = data_type;
        cases.push((
            cdb,
            if data_type == 0 {
                scsi::srb::SrbStatus::INVALID_REQUEST
            } else {
                scsi::srb::SrbStatus::ERROR
            },
        ));
    }
    for (operation, length_offset) in [
        (0x52, 7),
        (0xad, 8),
        (0x51, 7),
        (0x5c, 7),
        (0xbd, 8),
        (0x43, 7),
    ] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        cdb[length_offset + 1] = 129;
        cases.push((cdb, scsi::srb::SrbStatus::DATA_OVERRUN));
    }
    let mut disc = [0; 16];
    disc[0] = 0x51;
    disc[1] = 1;
    disc[8] = 32;
    cases.push((disc, scsi::srb::SrbStatus::ERROR));
    for (cdb, expected_status) in cases {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 128, true);
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(
            result.scsi_status,
            scsi::ScsiStatus::CHECK_CONDITION,
            "{cdb:?}"
        );
        assert_eq!(result.srb_status, expected_status, "{cdb:?}");
        assert_eq!(result.tx, 0, "{cdb:?}");
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 256], "{cdb:?}");
    }
}

// Test: Set streaming bounds at first/last DVD blocks, outside capacity, with reset-default, and malformed lengths.
// Expected: Valid/default requests succeed, invalid bounds/lengths fail precisely, and all input bytes remain unchanged.
#[async_test]
async fn dvd_streaming_validates_descriptor_bounds_and_reset_default_semantics() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (length, flags, start, end, expected_status) in [
        (28, 0, 0u32, 1023u32, scsi::srb::SrbStatus::SUCCESS),
        (28, 0, 1023, 1023, scsi::srb::SrbStatus::SUCCESS),
        (28, 0, 1024, 1024, scsi::srb::SrbStatus::INVALID_REQUEST),
        (28, 0, 0, 1024, scsi::srb::SrbStatus::INVALID_REQUEST),
        (28, 4, u32::MAX, u32::MAX, scsi::srb::SrbStatus::SUCCESS),
        (27, 0, 0, 0, scsi::srb::SrbStatus::ERROR),
        (29, 0, 0, 0, scsi::srb::SrbStatus::DATA_OVERRUN),
    ] {
        let memory = GuestMemory::allocate(4096);
        let mut expected = [0xa5; 256];
        expected[16..44].fill(0);
        expected[16] = flags;
        expected[20..24].copy_from_slice(&start.to_be_bytes());
        expected[24..28].copy_from_slice(&end.to_be_bytes());
        memory.write_at(0, &expected).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 28, false);
        let mut cdb = [0; 16];
        cdb[0] = 0xb6;
        cdb[10] = length;
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(
            result.scsi_status,
            if expected_status == scsi::srb::SrbStatus::SUCCESS {
                scsi::ScsiStatus::GOOD
            } else {
                scsi::ScsiStatus::CHECK_CONDITION
            }
        );
        assert_eq!(result.srb_status, expected_status);
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}
