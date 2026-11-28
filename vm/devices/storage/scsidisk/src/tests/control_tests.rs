// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{TestDisk, check_response};
use crate::{SimpleScsiDisk, scsi};
use disk_backend::Disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request, ScsiResult};
use scsidisk_resources::DiskParameters;

fn configured_disk(sectors: u64, read_only: bool, parameters: DiskParameters) -> SimpleScsiDisk {
    let (backing, _) = TestDisk::new(512, 4096, sectors, read_only, /* storage: */ false);
    SimpleScsiDisk::new(Disk::new(backing).unwrap(), parameters)
}

// Test: Read capacity using 10/16-byte commands across the 32-bit LBA boundary and provisioning modes.
// Expected: Capacity-10 saturates, capacity-16 is exact, geometry is 512/4096, and only LBPME follows UNMAP.
#[async_test]
async fn capacity_wire_images_preserve_geometry_large_sizes_and_provisioning() {
    for sectors in [1, 1024, u64::from(u32::MAX), u64::from(u32::MAX) + 10] {
        for unmap in [false, true] {
            let disk = configured_disk(
                sectors,
                false,
                DiskParameters {
                    unmap: Some(unmap),
                    ..Default::default()
                },
            );
            let mut cdb = [0; 16];
            cdb[0] = 0x25;
            let mut expected = [0; 8];
            expected[..4]
                .copy_from_slice(&((sectors - 1).min(u64::from(u32::MAX)) as u32).to_be_bytes());
            expected[4..].copy_from_slice(&512u32.to_be_bytes());
            check_response(&disk, cdb, 128, &expected).await;
            cdb[..2].copy_from_slice(&[0x9e, 0x10]);
            cdb[10..14].copy_from_slice(&32u32.to_be_bytes());
            let mut expected = [0; 32];
            expected[..8].copy_from_slice(&(sectors - 1).to_be_bytes());
            expected[8..12].copy_from_slice(&512u32.to_be_bytes());
            expected[13] = 3;
            expected[14] = if unmap { 0x80 } else { 0 };
            for length in [12, 16, 31, 32, 128] {
                check_response(&disk, cdb, length, &expected[..length.min(32)]).await;
            }
        }
    }
}

// Test: Query caching/all-pages MODE SENSE(6/10) using current/changeable/default controls and truncation.
// Expected: Literal headers encode protection/FUA, caching reflects configuration, and guard bytes survive.
#[async_test]
async fn mode_sense_wire_images_follow_cache_fua_protection_and_page_control() {
    for read_only in [false, true] {
        for fua in [false, true] {
            for write_cache in [false, true] {
                let disk = configured_disk(
                    1024,
                    read_only,
                    DiskParameters {
                        fua: Some(fua),
                        write_cache: Some(write_cache),
                        ..Default::default()
                    },
                );
                let dsp = if read_only { 0x80 } else { 0 } | if fua { 0x10 } else { 0 };
                for ten in [false, true] {
                    let header = if ten {
                        vec![0, 18, 0, dsp, 0, 0, 0, 0]
                    } else {
                        vec![15, 0, dsp, 0]
                    };
                    for control in [0, 1, 2] {
                        for page in [8, 0x3f] {
                            let mut expected = header.clone();
                            expected.extend_from_slice(&[
                                8,
                                10,
                                if write_cache && control != 1 { 4 } else { 0 },
                            ]);
                            expected.resize(header.len() + 12, 0);
                            for allocation in [
                                header.len(),
                                header.len() + 1,
                                header.len() + 2,
                                header.len() + 3,
                                expected.len(),
                                expected.len() + 8,
                            ] {
                                let mut cdb = [0; 16];
                                cdb[0] = if ten { 0x5a } else { 0x1a };
                                cdb[2] = page | control << 6;
                                if ten {
                                    cdb[7..9].copy_from_slice(&(allocation as u16).to_be_bytes());
                                } else {
                                    cdb[4] = allocation as u8;
                                }
                                check_response(
                                    &disk,
                                    cdb,
                                    128,
                                    &expected[..allocation.min(expected.len())],
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }
}

// Test: Cause an illegal command, request its sense data at different allocations, and request it again.
// Expected: The first response reports the original error and truncates correctly; the second is NO SENSE.
#[async_test]
async fn request_sense_reports_and_consumes_the_previous_command_error() {
    for allocation in [8, 17, 18, 32] {
        let disk = configured_disk(1024, false, Default::default());
        let memory = GuestMemory::allocate(4096);
        let buffers = OwnedRequestBuffers::linear(0, 0, true);
        let mut cdb = [0; 16];
        cdb[0] = 0xff;
        let error = disk
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(error.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        cdb[0] = 3;
        cdb[4] = allocation;
        let mut expected = [0; 18];
        expected[0] = 0x70;
        expected[2] = 5;
        expected[7] = 10;
        expected[12] = 0x20;
        let transferred = usize::from(allocation).min(expected.len());
        check_response(&disk, cdb, 128, &expected[..transferred]).await;
        expected[2] = 0;
        expected[12] = 0;
        check_response(&disk, cdb, 128, &expected[..transferred]).await;
    }
}

// Test: Send supported no-data control commands and MODE SENSE/SELECT zero allocations.
// Expected: Commands complete successfully with no transfer or writes to the guarded destination.
#[async_test]
async fn no_data_control_commands_complete_without_touching_guest_memory() {
    let disk = configured_disk(1024, false, Default::default());
    for operation in [0x00, 0x04, 0x16, 0x17, 0x1e, 0x1a, 0x5a, 0x15, 0x55] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        check_response(&disk, cdb, 0, &[]).await;
    }
    for operation in [0x1a, 0x5a] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        check_response(&disk, cdb, 128, &[]).await;
    }
}

// Test: VERIFY(10/12/16) the first, interior, and final disk sectors.
// Expected: Valid verification ranges succeed without returning data or modifying guest memory.
#[async_test]
async fn verify_command_variants_accept_valid_capacity_boundaries() {
    let disk = configured_disk(1024, false, Default::default());
    for operation in [0x2f, 0xaf, 0x8f] {
        for (start, count) in [(0u64, 1u32), (3, 5), (1023, 1)] {
            let mut cdb = [0; 16];
            cdb[0] = operation;
            if operation == 0x8f {
                cdb[2..10].copy_from_slice(&start.to_be_bytes());
                cdb[10..14].copy_from_slice(&count.to_be_bytes());
            } else {
                cdb[2..6].copy_from_slice(&(start as u32).to_be_bytes());
                if operation == 0x2f {
                    cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
                } else {
                    cdb[6..10].copy_from_slice(&count.to_be_bytes());
                }
            }
            check_response(&disk, cdb, 128, &[]).await;
        }
    }
}

async fn check_invalid(
    disk: &SimpleScsiDisk,
    cdb: [u8; 16],
    buffer_len: usize,
    srb: scsi::srb::SrbStatus,
    additional: scsi::AdditionalSenseCode,
) {
    let memory = GuestMemory::allocate(4096);
    memory.write_at(0, &[0xa5; 256]).unwrap();
    let buffers = OwnedRequestBuffers::linear(16, buffer_len, true);
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
        .await;
    assert_eq!(
        result.scsi_status,
        scsi::ScsiStatus::CHECK_CONDITION,
        "{cdb:?}"
    );
    assert_eq!(result.srb_status, srb);
    assert_eq!(result.tx, 0);
    let sense = result.sense_data.unwrap();
    assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
    assert_eq!(sense.additional_sense_code, additional);
    let mut actual = [0; 256];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, [0xa5; 256]);
}

// Test: Use short/oversized control allocations, saved/unknown mode pages, and unsupported service actions.
// Expected: Defined invalid-request or data-overrun status is returned without any guest-buffer write.
#[async_test]
async fn invalid_control_allocations_and_pages_preserve_guest_buffers() {
    let disk = configured_disk(1024, false, Default::default());
    for (operation, flags, page, allocation, buffer_len, overrun) in [
        (0x03, 0, 0, 7, 128, false),
        (0x03, 0, 0, 129, 128, false),
        (0x1a, 0, 8, 3, 128, false),
        (0x5a, 0, 8, 7, 128, false),
        (0x1a, 0, 8, 129, 128, false),
        (0x5a, 0, 8, 129, 128, false),
        (0x1a, 0, 0xc8, 32, 128, false),
        (0x5a, 0, 0x3e, 32, 128, false),
        (0x25, 0, 0, 0, 7, true),
        (0x9e, 0x10, 0, 32, 11, true),
        (0x9e, 0x1f, 0, 32, 32, false),
    ] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        cdb[1] = flags;
        cdb[2] = page;
        if operation == 0x5a {
            cdb[7..9].copy_from_slice(&(allocation as u16).to_be_bytes());
        } else {
            cdb[4] = allocation as u8;
        }
        check_invalid(
            &disk,
            cdb,
            buffer_len,
            if overrun {
                scsi::srb::SrbStatus::DATA_OVERRUN
            } else {
                scsi::srb::SrbStatus::INVALID_REQUEST
            },
            scsi::AdditionalSenseCode::INVALID_CDB,
        )
        .await;
    }
}

// Test: Verify ranges beyond capacity and relative-address VERIFY(10/12) requests.
// Expected: Out-of-range work reports ILLEGAL BLOCK and relative addressing reports INVALID CDB.
#[async_test]
async fn invalid_verify_ranges_and_relative_addresses_are_rejected() {
    let disk = configured_disk(1024, false, Default::default());
    for operation in [0x2f, 0xaf, 0x8f] {
        let mut cdb = [0; 16];
        cdb[0] = operation;
        if operation == 0x8f {
            cdb[2..10].copy_from_slice(&1023u64.to_be_bytes());
            cdb[10..14].copy_from_slice(&2u32.to_be_bytes());
        } else {
            cdb[2..6].copy_from_slice(&1023u32.to_be_bytes());
            if operation == 0x2f {
                cdb[7..9].copy_from_slice(&2u16.to_be_bytes());
            } else {
                cdb[6..10].copy_from_slice(&2u32.to_be_bytes());
            }
        }
        check_invalid(
            &disk,
            cdb,
            128,
            scsi::srb::SrbStatus::INVALID_REQUEST,
            scsi::AdditionalSenseCode::ILLEGAL_BLOCK,
        )
        .await;
        if operation != 0x8f {
            cdb[1] = 1;
            check_invalid(
                &disk,
                cdb,
                128,
                scsi::srb::SrbStatus::INVALID_REQUEST,
                scsi::AdditionalSenseCode::INVALID_CDB,
            )
            .await;
        }
    }
}

// Test: Send default/self-test diagnostics and diagnostics with unsupported codes or parameter data.
// Expected: Supported forms succeed with no transfer; unsupported diagnostic forms return INVALID CDB.
#[async_test]
async fn send_diagnostic_validates_flags_and_parameter_length() {
    let disk = configured_disk(1024, false, Default::default());
    for flags in [0, 4] {
        let mut cdb = [0; 16];
        cdb[0] = 0x1d;
        cdb[1] = flags;
        check_response(&disk, cdb, 0, &[]).await;
    }
    for (flags, length) in [(0x10, 0u16), (0x20, 0), (0, 1)] {
        let mut cdb = [0; 16];
        cdb[0] = 0x1d;
        cdb[1] = flags;
        cdb[3..5].copy_from_slice(&length.to_be_bytes());
        check_invalid(
            &disk,
            cdb,
            128,
            scsi::srb::SrbStatus::INVALID_REQUEST,
            scsi::AdditionalSenseCode::INVALID_CDB,
        )
        .await;
    }
}

fn caching_parameters(ten: bool, descriptor: bool, cache: bool, page_size: usize) -> Vec<u8> {
    let header = if ten { 8 } else { 4 };
    let descriptor_length: usize = if descriptor { 8 } else { 0 };
    let mut parameters = vec![0; header + descriptor_length + page_size];
    if ten {
        parameters[6..8].copy_from_slice(&(descriptor_length as u16).to_be_bytes());
    } else {
        parameters[3] = descriptor_length as u8;
    }
    if descriptor {
        parameters[header + 6] = 2;
    }
    let page = header + descriptor_length;
    parameters[page] = 8;
    parameters[page + 1] = (page_size - 2) as u8;
    parameters[page + 2] = if cache { 4 } else { 0 };
    parameters
}

async fn select_mode(
    disk: &SimpleScsiDisk,
    parameters: &[u8],
    ten: bool,
    save: bool,
) -> ScsiResult {
    let memory = GuestMemory::allocate(4096);
    memory.write_at(0, parameters).unwrap();
    let buffers = OwnedRequestBuffers::linear(0, parameters.len(), false);
    let mut cdb = [0; 16];
    cdb[0] = if ten { 0x55 } else { 0x15 };
    cdb[1] = 0x10 | u8::from(save);
    if ten {
        cdb[7..9].copy_from_slice(&(parameters.len() as u16).to_be_bytes());
    } else {
        cdb[4] = parameters.len() as u8;
    }
    let result = disk
        .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
        .await;
    let mut actual = vec![0; parameters.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, parameters);
    result
}

// Test: Select a standard 20-byte caching page with/without a block descriptor through both CDB forms.
// Expected: Unchanged cache policy succeeds, attempted changes fail, and MODE SENSE still reports the policy.
#[async_test]
async fn mode_select_accepts_unchanged_cache_policy_and_rejects_changes() {
    for cache in [false, true] {
        let disk = configured_disk(
            1024,
            false,
            DiskParameters {
                write_cache: Some(cache),
                ..Default::default()
            },
        );
        for ten in [false, true] {
            for descriptor in [false, true] {
                let parameters = caching_parameters(ten, descriptor, cache, 20);
                let result = select_mode(&disk, &parameters, ten, false).await;
                assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
                assert_eq!(result.tx, parameters.len());
                let changed = caching_parameters(ten, descriptor, !cache, 20);
                let result = select_mode(&disk, &changed, ten, false).await;
                assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
                assert_eq!(
                    result.sense_data.unwrap().additional_sense_code,
                    scsi::AdditionalSenseCode::INVALID_FIELD_PARAMETER_LIST
                );
                assert_eq!(result.tx, 0);
            }
        }
        let mut cdb = [0; 16];
        cdb[0] = 0x1a;
        cdb[2] = 8;
        cdb[4] = 16;
        let mut expected = vec![15, 0, 0, 0, 8, 10, if cache { 4 } else { 0 }];
        expected.resize(16, 0);
        check_response(&disk, cdb, 128, &expected).await;
    }
}

// Test: Select saved pages, truncated parameter lists, oversized block descriptors, or invalid page headers.
// Expected: Invalid selection is rejected without changing policy or mutating the caller's parameter list.
#[async_test]
async fn mode_select_rejects_invalid_headers_descriptors_and_saved_pages() {
    let disk = configured_disk(1024, false, Default::default());
    for ten in [false, true] {
        let valid = caching_parameters(ten, false, true, 20);
        let result = select_mode(&disk, &valid, ten, true).await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(
            result.sense_data.unwrap().additional_sense_code,
            scsi::AdditionalSenseCode::INVALID_CDB
        );
        let header = if ten { 8 } else { 4 };
        let mut wrong_descriptor = valid.clone();
        if ten {
            wrong_descriptor[6..8].copy_from_slice(&64u16.to_be_bytes());
        } else {
            wrong_descriptor[3] = 64;
        }
        let mut wrong_page = valid.clone();
        wrong_page[header] = 7;
        let mut wrong_page_length = valid.clone();
        wrong_page_length[header + 1] = 1;
        for (parameters, additional) in [
            (
                vec![0; header],
                scsi::AdditionalSenseCode::PARAMETER_LIST_LENGTH,
            ),
            (
                wrong_descriptor,
                scsi::AdditionalSenseCode::PARAMETER_LIST_LENGTH,
            ),
            (
                wrong_page,
                scsi::AdditionalSenseCode::INVALID_FIELD_PARAMETER_LIST,
            ),
            (
                wrong_page_length,
                scsi::AdditionalSenseCode::INVALID_FIELD_PARAMETER_LIST,
            ),
        ] {
            let result = select_mode(&disk, &parameters, ten, false).await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
            assert_eq!(result.sense_data.unwrap().additional_sense_code, additional);
            assert_eq!(result.tx, 0);
        }
    }
}

// IGNORED: MODE SELECT currently rejects the short caching page advertised by MODE SENSE.
//       Keep this regression pending a separate production fix.
//
// Test: Select the short caching-page format advertised by this device's MODE SENSE.
// Expected: Both MODE SELECT forms accept unchanged policy with the advertised page length of ten.
#[async_test]
#[ignore = "known product bug: MODE SELECT compares payload page length to the full caching-page size"]
async fn known_bug_mode_select_accepts_the_short_caching_page_advertised_by_mode_sense() {
    let disk = configured_disk(1024, false, Default::default());
    let mut results = Vec::new();
    for ten in [false, true] {
        let parameters = caching_parameters(ten, false, true, 12);
        let result = select_mode(&disk, &parameters, ten, false).await;
        results.push((result.scsi_status, result.tx));
    }
    assert_eq!(
        results,
        [(scsi::ScsiStatus::GOOD, 16), (scsi::ScsiStatus::GOOD, 20)]
    );
}
