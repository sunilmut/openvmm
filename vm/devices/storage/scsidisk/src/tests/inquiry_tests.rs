// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::TestDisk;
use super::test_helpers::{check_execute_scsi_pass_with_tx, new_scsi_disk};
use crate::{SimpleScsiDisk, scsi};
use disk_backend::Disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};
use scsidisk_resources::DiskParameters;

fn inquiry_request(flags: u8, page: u8, allocation: u16) -> Request {
    let mut cdb = [0; 16];
    cdb[..6].copy_from_slice(&[
        0x12,
        flags,
        page,
        (allocation >> 8) as u8,
        allocation as u8,
        0,
    ]);
    Request { cdb, srb_flags: 0 }
}

fn configured_disk(parameters: DiskParameters) -> SimpleScsiDisk {
    let (disk, _) = TestDisk::new(512, 4096, 1024, false, false);
    SimpleScsiDisk::new(Disk::new(disk).unwrap(), parameters)
}

async fn check_vpd_page(disk: &SimpleScsiDisk, page: u8, body: &[u8]) {
    let mut expected = vec![0, page, 0, body.len() as u8];
    expected.extend_from_slice(body);
    for allocation in [4, 5, expected.len() - 1, expected.len(), expected.len() + 8] {
        let memory = GuestMemory::allocate(512);
        memory.write_at(0, &[0xa5; 512]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 480, true);
        let transferred = allocation.min(expected.len());
        check_execute_scsi_pass_with_tx(
            disk,
            &buffers.buffer(&memory),
            &inquiry_request(1, page, allocation as u16),
            transferred,
        )
        .await;
        let mut actual = [0; 512];
        memory.read_at(0, &mut actual).unwrap();
        let mut guarded_expected = [0xa5; 512];
        guarded_expected[16..16 + transferred].copy_from_slice(&expected[..transferred]);
        assert_eq!(
            actual, guarded_expected,
            "page {page:#x}, allocation {allocation}"
        );
    }
}

// Test: Toggle UNMAP, ODX, and serial-number configuration independently.
// Expected: Supported-pages VPD advertises exactly the available pages, sorted by page code.
#[async_test]
async fn supported_pages_follow_each_configured_capability() {
    for unmap in [false, true] {
        for odx in [false, true] {
            for serial in [false, true] {
                let disk = configured_disk(DiskParameters {
                    unmap: Some(unmap),
                    odx: Some(odx),
                    serial_number: if serial {
                        b"serial-42".to_vec()
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                });
                let mut expected = vec![
                    0,
                    scsi::VPD_DEVICE_IDENTIFIERS,
                    scsi::VPD_MSFT_PAGING_EXTENT_PROPERTIES,
                    scsi::VPD_MSFT_VIRTUAL_DEVICE_PROPERTIES,
                ];
                if unmap {
                    expected.extend([
                        scsi::VPD_BLOCK_LIMITS,
                        scsi::VPD_BLOCK_DEVICE_CHARACTERISTICS,
                        scsi::VPD_LOGICAL_BLOCK_PROVISIONING,
                    ]);
                }
                if odx {
                    expected.push(scsi::VPD_THIRD_PARTY_COPY);
                }
                if serial {
                    expected.push(scsi::VPD_SERIAL_NUMBER);
                }
                expected.sort_unstable();
                check_vpd_page(&disk, 0, &expected).await;
                if serial {
                    check_vpd_page(&disk, scsi::VPD_SERIAL_NUMBER, b"serial-42").await;
                }
            }
        }
    }
}

// Test: Request binary T10/NAA identifiers with a configured, nonzero disk ID.
// Expected: Descriptor lengths, Microsoft OUI, and stable ID bytes have the exact on-wire encoding.
#[async_test]
async fn device_identifiers_encode_the_configured_disk_id() {
    let id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let disk = configured_disk(DiskParameters {
        disk_id: Some(id),
        ..Default::default()
    });
    let mut body = vec![1, 1, 0, 24];
    body.extend_from_slice(b"Msft    ");
    body.extend_from_slice(&id);
    body.extend_from_slice(&[1, 3, 0, 16, 0x60, 2, 0x24, 0x80]);
    body.extend_from_slice(&[1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16]);
    check_vpd_page(&disk, scsi::VPD_DEVICE_IDENTIFIERS, &body).await;
}

// Test: Query UNMAP limits with zero or explicit granularity and a configured transfer ceiling.
// Expected: Big-endian limits advertise 4096 descriptors, nonzero granularity, and 16-sector WRITE SAME.
#[async_test]
async fn block_limits_encode_configured_transfer_and_unmap_granularity() {
    for (granularity, expected_granularity) in [(0, 1u32), (32, 32)] {
        let disk = configured_disk(DiskParameters {
            unmap: Some(true),
            max_transfer_length: Some(8192),
            optimal_unmap_sectors: Some(granularity),
            ..Default::default()
        });
        let mut body = [0; 60];
        body[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        body[20..24].copy_from_slice(&4096u32.to_be_bytes());
        body[24..28].copy_from_slice(&expected_granularity.to_be_bytes());
        body[28..32].copy_from_slice(&0x80000000u32.to_be_bytes());
        body[32..40].copy_from_slice(&16u64.to_be_bytes());
        check_vpd_page(&disk, scsi::VPD_BLOCK_LIMITS, &body).await;
    }
}

// Test: Query configured medium characteristics and logical provisioning capability.
// Expected: Rotation rate is big-endian and thin provisioning advertises UNMAP and its minimum exponent.
#[async_test]
async fn medium_characteristics_and_thin_provisioning_have_stable_wire_fields() {
    let disk = configured_disk(DiskParameters {
        unmap: Some(true),
        medium_rotation_rate: Some(7200),
        ..Default::default()
    });
    let mut body = [0; 60];
    body[..2].copy_from_slice(&7200u16.to_be_bytes());
    check_vpd_page(&disk, scsi::VPD_BLOCK_DEVICE_CHARACTERISTICS, &body).await;
    check_vpd_page(
        &disk,
        scsi::VPD_LOGICAL_BLOCK_PROVISIONING,
        &[1, 0x80, 2, 0],
    )
    .await;
}

// Test: Request Microsoft paging, virtual-device, and enabled ODX capability pages.
// Expected: Published version/signature bytes and 64-MiB ODX limits retain their compatible wire format.
#[async_test]
async fn microsoft_and_odx_pages_preserve_the_published_wire_contracts() {
    let disk = configured_disk(DiskParameters {
        odx: Some(true),
        ..Default::default()
    });
    check_vpd_page(
        &disk,
        scsi::VPD_MSFT_PAGING_EXTENT_PROPERTIES,
        &[1, 1, 0, 0],
    )
    .await;
    check_vpd_page(
        &disk,
        scsi::VPD_MSFT_VIRTUAL_DEVICE_PROPERTIES,
        &[
            1, 0, 0, 0, 0x15, 0x8f, 0xa9, 0x89, 0x28, 0xc9, 0x8b, 0x4d, 0x94, 0xcd, 0xef, 0x51,
            0xfa, 0xa9, 0x9d, 0x33,
        ],
    )
    .await;
    let mut body = [0; 36];
    body[2..4].copy_from_slice(&32u16.to_be_bytes());
    body[4..8].copy_from_slice(&[0x4d, 0x1f, 0x83, 0x84]);
    body[10..12].copy_from_slice(&8u16.to_be_bytes());
    body[20..28].copy_from_slice(&131072u64.to_be_bytes());
    body[28..36].copy_from_slice(&131072u64.to_be_bytes());
    check_vpd_page(&disk, scsi::VPD_THIRD_PARTY_COPY, &body).await;
}

// Test: Request standard INQUIRY with allocations shorter than, equal to, and longer than its data.
// Expected: The literal disk identity and SPC-3 wire header are truncated correctly without overwrites.
#[async_test]
async fn standard_inquiry_wire_image_and_allocation_boundaries() {
    let (disk, _) = new_scsi_disk(512, 4096, 1024, false, false, false);
    let mut expected = [0; 104];
    expected[..8].copy_from_slice(&[0, 0, 5, 2, 99, 0, 0, 2]);
    expected[8..16].copy_from_slice(b"Msft    ");
    expected[16..32].copy_from_slice(b"Virtual Disk    ");
    expected[32..36].copy_from_slice(b"1.0 ");
    for allocation in [5, 8, 35, 36, 103, 104, 120] {
        let memory = GuestMemory::allocate(192);
        memory.write_at(0, &[0xa5; 192]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 160, true);
        let transferred = usize::from(allocation).min(expected.len());
        check_execute_scsi_pass_with_tx(
            &disk,
            &buffers.buffer(&memory),
            &inquiry_request(0, 0, allocation),
            transferred,
        )
        .await;
        let mut actual = [0; 192];
        memory.read_at(0, &mut actual).unwrap();
        let mut guarded_expected = [0xa5; 192];
        guarded_expected[16..16 + transferred].copy_from_slice(&expected[..transferred]);
        assert_eq!(actual, guarded_expected, "allocation {allocation}");
    }
}

// Test: Request invalid INQUIRY flags/pages, undersized headers, and allocations beyond the buffer.
// Expected: Invalid requests report ILLEGAL REQUEST/INVALID CDB, transfer nothing, and preserve output.
#[async_test]
async fn invalid_inquiry_requests_preserve_guest_memory_and_report_sense() {
    let disk = configured_disk(Default::default());
    for (flags, page, allocation) in [
        (0, 0, 4),
        (1, 0, 3),
        (0, 0, 129),
        (2, 0, 128),
        (0, 0x80, 128),
        (1, 0xfe, 128),
        (1, scsi::VPD_SERIAL_NUMBER, 128),
        (1, scsi::VPD_BLOCK_LIMITS, 128),
        (1, scsi::VPD_BLOCK_DEVICE_CHARACTERISTICS, 128),
        (1, scsi::VPD_LOGICAL_BLOCK_PROVISIONING, 128),
        (1, scsi::VPD_THIRD_PARTY_COPY, 128),
    ] {
        let memory = GuestMemory::allocate(128);
        memory.write_at(0, &[0xa5; 128]).unwrap();
        let buffers = OwnedRequestBuffers::linear(0, 128, true);
        let result = disk
            .execute_scsi(
                &buffers.buffer(&memory),
                &inquiry_request(flags, page, allocation),
            )
            .await;
        assert_eq!(
            result.scsi_status,
            scsi::ScsiStatus::CHECK_CONDITION,
            "{flags}/{page:#x}/{allocation}"
        );
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
        assert_eq!(
            sense.additional_sense_code,
            scsi::AdditionalSenseCode::INVALID_CDB
        );
        let mut actual = [0; 128];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 128]);
    }
}

// Test: Place standard and supported VPD responses in partly or wholly inaccessible guest memory.
// Expected: Memory failures become typed SCSI errors with zero transfer rather than panics or success.
#[async_test]
async fn inquiry_response_memory_faults_are_reported_for_headers_and_payloads() {
    let disk = configured_disk(DiskParameters {
        unmap: Some(true),
        odx: Some(true),
        serial_number: b"serial-42".to_vec(),
        ..Default::default()
    });
    let requests = [
        (0, 0),
        (1, 0),
        (1, scsi::VPD_SERIAL_NUMBER),
        (1, scsi::VPD_DEVICE_IDENTIFIERS),
        (1, scsi::VPD_BLOCK_LIMITS),
        (1, scsi::VPD_BLOCK_DEVICE_CHARACTERISTICS),
        (1, scsi::VPD_LOGICAL_BLOCK_PROVISIONING),
        (1, scsi::VPD_MSFT_PAGING_EXTENT_PROPERTIES),
        (1, scsi::VPD_MSFT_VIRTUAL_DEVICE_PROPERTIES),
        (1, scsi::VPD_THIRD_PARTY_COPY),
    ];
    for (flags, page) in requests {
        for gpa in [4092, 8192] {
            let memory = GuestMemory::allocate(4096);
            memory.write_at(0, &[0xa5; 16]).unwrap();
            let buffers = if gpa == 4092 {
                OwnedRequestBuffers::new_unaligned(&[0, 1], 4092, 128)
            } else {
                OwnedRequestBuffers::new_unaligned(&[2], 0, 128)
            };
            let result = disk
                .execute_scsi(&buffers.buffer(&memory), &inquiry_request(flags, page, 128))
                .await;
            assert_eq!(
                result.scsi_status,
                scsi::ScsiStatus::CHECK_CONDITION,
                "page {page:#x}, GPA {gpa}"
            );
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::INVALID_REQUEST);
            assert_eq!(result.tx, 0);
            let sense = result.sense_data.unwrap();
            assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
            assert_eq!(
                sense.additional_sense_code,
                scsi::AdditionalSenseCode::INVALID_CDB
            );
            let mut prefix = [0; 12];
            memory.read_at(0, &mut prefix).unwrap();
            assert_eq!(prefix, [0xa5; 12]);
        }
    }
}
