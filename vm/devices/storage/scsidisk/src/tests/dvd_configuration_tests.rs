// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::new_scsi_dvd;
use crate::{scsi, scsidvd::SimpleScsiDvd};
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};

fn feature_pages(present: bool) -> Vec<(u16, Vec<u8>)> {
    let current = u8::from(present);
    vec![
        (0, vec![0, 0, 3, 8, 0, 16, current, 0, 0, 8, 0, 0]),
        (1, vec![0, 1, 0x0b, 8, 0, 0, 0, 0, 0, 0, 0, 0]),
        (3, vec![0, 3, 7, 4, 0x39, 0, 0, 0]),
        (0x10, vec![0, 0x10, current, 8, 0, 0, 8, 0, 0, 16, 1, 0]),
        (0x1e, vec![0, 0x1e, 8, 4, 0, 0, 0, 0]),
        (0x1f, vec![0, 0x1f, 4 | current, 4, 0, 0, 0, 0]),
        (0x100, vec![1, 0, 3, 0]),
        (0x105, vec![1, 5, 7, 4, 1, 0, 2, 0]),
        (0x107, vec![1, 7, 0x16 | current, 4, 16, 0, 0, 0]),
    ]
}

async fn configuration(
    dvd: &SimpleScsiDvd,
    request_type: u8,
    feature: u16,
    allocation: usize,
) -> Vec<u8> {
    let memory = GuestMemory::allocate(4096);
    memory.write_at(0, &[0xa5; 512]).unwrap();
    let buffers = OwnedRequestBuffers::new_unaligned(&[0], 16, 480);
    let mut cdb = [0; 16];
    cdb[0] = 0x46;
    cdb[1] = request_type;
    cdb[2..4].copy_from_slice(&feature.to_be_bytes());
    cdb[7..9].copy_from_slice(&(allocation as u16).to_be_bytes());
    let result = dvd
        .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
        .await;
    assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
    assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
    assert!(result.tx <= allocation);
    let mut actual = [0; 512];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(&actual[..16], &[0xa5; 16]);
    assert!(actual[16 + result.tx..].iter().all(|byte| *byte == 0xa5));
    actual[16..16 + result.tx].to_vec()
}

// Test: Request individual profile/core/media/read/power/timeout/streaming features with and without media.
// Expected: Feature payloads, capability flags, current profile, and all truncation boundaries match configuration.
#[async_test]
async fn one_feature_requests_return_exact_capabilities_and_media_dependent_flags() {
    for present in [false, true] {
        let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
        if !present {
            dvd.change_media(None);
        }
        for (code, expected) in feature_pages(present) {
            for allocation in [8, 9, 8 + expected.len() - 1, 8 + expected.len(), 128] {
                let response = configuration(&dvd, 2, code, allocation).await;
                assert_eq!(&response[4..8], &[0, 0, 0, if present { 16 } else { 0 }]);
                assert_eq!(
                    &response[8..],
                    &expected[..(allocation - 8).min(expected.len())],
                    "feature {code:#x}"
                );
            }
        }
    }
}

// Test: Request ALL/CURRENT feature suffixes beginning at random-readable, DVD-read, power, or beyond the list.
// Expected: Features retain ordering, selection honors the starting code, and CURRENT omits inactive media features.
#[async_test]
async fn all_and_current_requests_filter_the_feature_suffix_by_media_state() {
    for present in [false, true] {
        let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
        if !present {
            dvd.change_media(None);
        }
        for request_type in [0, 1] {
            for starting in [0x10, 0x1f, 0x100, 0x108] {
                let expected: Vec<u8> = feature_pages(present)
                    .into_iter()
                    .filter(|(code, _)| *code >= starting)
                    .filter(|(code, _)| {
                        request_type == 0
                            || (*code != 0x1e && (present || ![0x10, 0x1f, 0x107].contains(code)))
                    })
                    .flat_map(|(_, data)| data)
                    .collect();
                let response = configuration(&dvd, request_type, starting, 256).await;
                assert_eq!(&response[4..8], &[0, 0, 0, if present { 16 } else { 0 }]);
                assert_eq!(&response[8..], expected);
            }
        }
    }
}

// Test: Request configuration with allocations shorter than its fixed header.
// Expected: The header truncates to the allocation and no descriptor or guard bytes are overwritten.
#[async_test]
async fn short_configuration_allocations_return_only_the_available_header_prefix() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for allocation in 0..8 {
        let response = configuration(&dvd, 2, 0x100, allocation).await;
        assert_eq!(response.len(), allocation);
        if allocation > 4 {
            assert_eq!(&response[4..], &[0, 0, 0, 16][..allocation - 4]);
        }
    }
}

// Test: Known product bug: inspect the configuration header's data length for one power-management feature.
// Expected: The reported available length excludes the four-byte data-length field itself.
#[async_test]
#[ignore = "known product bug: GET CONFIGURATION data length includes its own four-byte field"]
async fn known_bug_configuration_data_length_excludes_its_own_field() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let response = configuration(&dvd, 2, 0x100, 128).await;
    assert_eq!(response.len(), 12);
    assert_eq!(u32::from_be_bytes(response[..4].try_into().unwrap()), 8);
}

// Test: Request a reserved configuration request type or allocation larger than the supplied guest buffer.
// Expected: Invalid requests fail with zero transfer and do not write any response or guard bytes.
#[async_test]
async fn invalid_configuration_type_and_oversized_allocation_preserve_memory() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    for (request_type, allocation) in [(3, 32u16), (0, 129)] {
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 128, true);
        let mut cdb = [0; 16];
        cdb[0] = 0x46;
        cdb[1] = request_type;
        cdb[7..9].copy_from_slice(&allocation.to_be_bytes());
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 256]);
    }
}

// Test: Supply a reserved feature code in a one-feature GET CONFIGURATION request.
// Expected: An unsupported guest feature code returns a successful header-only reply without panicking.
#[async_test]
async fn unknown_one_feature_code_does_not_panic() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let response = configuration(&dvd, 2, 0xfe, 128).await;
    assert_eq!(response.len(), 8);
    assert_eq!(&response[4..], &[0, 0, 0, 16]);
}
