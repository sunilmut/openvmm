// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ScsiDisk basic tests.

use super::test_helpers::TestDisk;
use super::test_helpers::check_execute_scsi_failed_with_result;
use super::test_helpers::check_execute_scsi_pass_with_tx;
use super::test_helpers::check_guest_memory;
use super::test_helpers::check_response;
use super::test_helpers::make_cdb10_request;
use super::test_helpers::make_cdb16_request;
use super::test_helpers::make_guest_memory;
use super::test_helpers::make_repeat_data_buffer;
use super::test_helpers::new_atapi_disk;
use super::test_helpers::new_scsi_disk;
use super::test_helpers::new_scsi_dvd;
use crate::SimpleScsiDisk;
use crate::scsi;
use disk_backend::Disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi::AdditionalSenseCode;
use scsi::ScsiOp;
use scsi::ScsiStatus;
use scsi::SenseKey;
use scsi::srb::SrbStatus;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::AsyncScsiDisk;
use scsi_core::Request;
use scsi_core::ScsiResult;
use scsi_core::ScsiSaveRestore;
use scsi_core::save_restore::SavedSenseData;
use scsi_core::save_restore::ScsiDiskSavedState;
use scsi_core::save_restore::ScsiSavedState;
use scsidisk_resources::DiskParameters;
use std::mem::size_of;
use std::sync::Arc;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// Test: Query provisioning at disk-size boundaries through the guest INQUIRY interface.
// Expected: The exponent changes at the declared thresholds and represents every sector count.
#[async_test]
async fn logical_block_provisioning_threshold_boundaries() {
    let response_len =
        size_of::<scsi::VpdPageHeader>() + size_of::<scsi::VpdLogicalBlockProvisioningPage>();
    let inquiry = scsi::CdbInquiry {
        operation_code: ScsiOp::INQUIRY.0,
        flags: scsi::InquiryFlags::new().with_vpd(true),
        page_code: scsi::VPD_LOGICAL_BLOCK_PROVISIONING,
        allocation_length: (response_len as u16).into(),
        control: 0,
    };
    let mut cdb = [0; 16];
    cdb[..size_of_val(&inquiry)].copy_from_slice(inquiry.as_bytes());
    let request = Request { cdb, srb_flags: 0 };

    for (sector_count, expected) in [
        (0, 1),
        (1, 1),
        ((1 << 32) - 1, 1),
        (1 << 32, 1),
        ((2 << 32) - 1, 1),
        (2 << 32, 2),
        ((2 << 32) + 1, 2),
        (3 << 32, 2),
        ((4 << 32) - 1, 2),
        (4 << 32, 3),
        ((4 << 32) + 1, 3),
        (5 << 32, 3),
        (u64::MAX, 32),
    ] {
        let (backing, _) = TestDisk::new(
            512,
            512,
            sector_count,
            /* read_only: */ false,
            /* storage: */ false,
        );
        let disk = SimpleScsiDisk::new(
            Disk::new(backing).unwrap(),
            DiskParameters {
                unmap: Some(true),
                ..Default::default()
            },
        );
        let memory = GuestMemory::allocate(response_len);
        let buffers = OwnedRequestBuffers::linear(0, response_len, true);
        check_execute_scsi_pass_with_tx(&disk, &buffers.buffer(&memory), &request, response_len)
            .await;

        let mut response = vec![0; response_len];
        memory.read_at(0, &mut response).unwrap();
        let page = scsi::VpdLogicalBlockProvisioningPage::read_from_prefix(
            &response[size_of::<scsi::VpdPageHeader>()..],
        )
        .unwrap()
        .0;
        assert_eq!(page.threshold_exponent, expected, "{sector_count}");
        assert!(
            u128::from(sector_count) < (1u128 << (32 + page.threshold_exponent)),
            "{sector_count}"
        );
    }
}

fn save_scsi_disk(scsi_disk: &SimpleScsiDisk) -> ScsiDiskSavedState {
    match scsi_disk.save().unwrap() {
        Some(ScsiSavedState::ScsiDisk(saved_state)) => saved_state,
        _ => panic!("expected a disk checkpoint"),
    }
}

fn restore_scsi_disk(scsi_disk: &SimpleScsiDisk, saved_state: ScsiDiskSavedState) {
    scsi_disk
        .restore(&ScsiSavedState::ScsiDisk(saved_state))
        .unwrap();
    let restored = save_scsi_disk(scsi_disk);
    assert_eq!(restored.sector_count, saved_state.sector_count);
    assert_eq!(restored.sense_data, saved_state.sense_data);
}

async fn check_report_pending_unit_attention(scsi_disk: &SimpleScsiDisk, report: bool) {
    let external_data = OwnedRequestBuffers::new(&[0]);
    let guest_mem = GuestMemory::allocate(4096);
    guest_mem.fill_at(0, 0xa5, 4096).unwrap();
    let result = scsi_disk
        .execute_scsi(
            &external_data.buffer(&guest_mem),
            &Request {
                cdb: scsi::Cdb16 {
                    operation_code: ScsiOp::READ16,
                    flags: scsi::Cdb16Flags::new(),
                    logical_block: 0.into(),
                    transfer_blocks: 1.into(),
                    reserved2: 0,
                    control: 0,
                }
                .as_bytes()
                .try_into()
                .unwrap(),
                srb_flags: 0,
            },
        )
        .await;
    if report {
        assert_eq!(result.scsi_status, ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, SrbStatus::ERROR);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(
            (
                sense.header.sense_key,
                sense.additional_sense_code,
                sense.additional_sense_code_qualifier,
            ),
            (
                SenseKey::UNIT_ATTENTION,
                AdditionalSenseCode::PARAMETERS_CHANGED,
                scsi::SCSI_SENSEQ_CAPACITY_DATA_CHANGED,
            )
        );
    } else {
        assert_eq!(result.scsi_status, ScsiStatus::GOOD);
        assert_eq!(result.srb_status, SrbStatus::SUCCESS);
        assert_eq!(result.tx, 512);
        assert!(result.sense_data.is_none());
    }
    let mut actual = [0; 4096];
    guest_mem.read_at(0, &mut actual).unwrap();
    let mut expected = [0xa5; 4096];
    if !report {
        expected[..512].fill(0);
    }
    assert_eq!(actual, expected);
}

async fn write_same(
    logical_sector_size: u32,
    physical_sector_size: u32,
    sector_count: u64,
    read_only: bool,
    fua: bool,
) {
    println!(
        "write_same test - read_only: {:?} fua: {:?}",
        read_only, fua
    );
    let (scsi_disk, state) = new_scsi_disk(
        logical_sector_size,
        physical_sector_size,
        sector_count,
        read_only,
        /* storage: */ true,
        /* pr: */ false,
    );
    let sector_size = logical_sector_size as usize;
    let transfer_len = sector_size * 4;

    let data = make_repeat_data_buffer(
        transfer_len.div_ceil(hvdef::HV_PAGE_SIZE as usize),
        sector_size,
    );
    let guest_mem = make_guest_memory(&data);
    let external_data = OwnedRequestBuffers::linear(0, data.len(), true);
    println!("validate guest_mem and data ...");
    check_guest_memory(&guest_mem, 0, &data);

    let request = make_cdb16_request(ScsiOp::WRITE_SAME16, fua, 0, 4);
    println!("write same guest_mem to disk...");
    check_execute_scsi_pass_with_tx(
        &scsi_disk,
        &external_data.buffer(&guest_mem),
        &request,
        transfer_len,
    )
    .await;
    assert_eq!(state.lock().is_fua_set, fua);
    check_guest_memory(&guest_mem, 0, &data);

    let guest_mem2 = GuestMemory::allocate(transfer_len + hvdef::HV_PAGE_SIZE as usize);
    guest_mem2
        .fill_at(0, 0xa5, transfer_len + hvdef::HV_PAGE_SIZE as usize)
        .unwrap();
    let read_buffers = OwnedRequestBuffers::linear(0, transfer_len, true);
    let request = make_cdb16_request(ScsiOp::READ16, fua, 0, 4);
    println!("read disk to guest_mem2 ...");
    check_execute_scsi_pass_with_tx(
        &scsi_disk,
        &read_buffers.buffer(&guest_mem2),
        &request,
        transfer_len,
    )
    .await;
    assert_eq!(state.lock().is_fua_set, false);

    println!("validate guest_mem2 ...");
    let mut actual = vec![0; transfer_len + hvdef::HV_PAGE_SIZE as usize];
    guest_mem2.read_at(0, &mut actual).unwrap();
    let mut expected = vec![0xa5; actual.len()];
    expected[..transfer_len].copy_from_slice(&data[..transfer_len]);
    assert_eq!(actual, expected);
}

async fn resize(new_sector_count: Option<u64>) {
    let (disk, state) = new_scsi_disk(
        512, 4096, 512, /* read_only: */ false, /* storage: */ true, /* pr: */ false,
    );
    check_report_pending_unit_attention(&disk, false).await;
    if let Some(new_sector_count) = new_sector_count {
        state.lock().sector_count = new_sector_count;
    }
    check_report_pending_unit_attention(&disk, new_sector_count.is_some()).await;
    check_report_pending_unit_attention(&disk, false).await;
    let mut expected = [0; 8];
    expected[..4].copy_from_slice(&((new_sector_count.unwrap_or(512) - 1) as u32).to_be_bytes());
    expected[4..].copy_from_slice(&512u32.to_be_bytes());
    let mut cdb = [0; 16];
    cdb[0] = ScsiOp::READ_CAPACITY.0;
    check_response(&disk, cdb, 128, &expected).await;
}

// Test: Construct protected/unprotected disks with both geometries and reservation modes.
// Expected: Guest capacity and mode replies preserve sector size, physical geometry and protection.
#[async_test]
async fn validate_new_scsi_disk() {
    for (physical_sector_size, read_only, pr) in [
        (4096, false, false),
        (512, true, false),
        (4096, false, true),
        (512, true, true),
    ] {
        let (disk, _) = new_scsi_disk(
            512,
            physical_sector_size,
            1024,
            read_only,
            /* storage: */ false,
            pr,
        );
        let mut cdb = [0; 16];
        cdb[0] = 0x25;
        check_response(&disk, cdb, 128, &[0, 0, 3, 0xff, 0, 0, 2, 0]).await;
        cdb[..2].copy_from_slice(&[0x9e, 0x10]);
        cdb[10..14].copy_from_slice(&32u32.to_be_bytes());
        let mut capacity = [0; 32];
        capacity[6..12].copy_from_slice(&[3, 0xff, 0, 0, 2, 0]);
        capacity[13] = if physical_sector_size == 4096 { 3 } else { 0 };
        check_response(&disk, cdb, 128, &capacity).await;
        cdb = [0; 16];
        cdb[..5].copy_from_slice(&[0x1a, 0, 8, 0, 16]);
        let mut mode = [0; 16];
        mode[..7].copy_from_slice(&[15, 0, if read_only { 0x80 } else { 0 }, 0, 8, 10, 4]);
        check_response(&disk, cdb, 128, &mode).await;
    }
}

// Test: Save and restore an unchanged disk through its public checkpoint interface.
// Expected: The restored checkpoint retains its sector count and empty sense data.
#[test]
fn validate_save_restore_scsi_disk_no_change() {
    let (scsi_disk, _state) = new_scsi_disk(
        512, 4096, 1024, /* read_only: */ false, /* storage: */ false,
        /* pr: */ false,
    );
    let saved_state = save_scsi_disk(&scsi_disk);
    restore_scsi_disk(&scsi_disk, saved_state);
}

// Test: Restore an old capacity checkpoint after the backing disk grows.
// Expected: A guest read reports capacity-change attention once, then succeeds without buffer damage.
#[async_test]
async fn validate_save_restore_scsi_disk_with_change() {
    let (disk, state) = new_scsi_disk(
        512, 4096, 1024, /* read_only: */ false, /* storage: */ true,
        /* pr: */ false,
    );
    let saved_state = save_scsi_disk(&disk);
    restore_scsi_disk(&disk, saved_state);
    check_report_pending_unit_attention(&disk, false).await;
    state.lock().sector_count = saved_state.sector_count + 1;
    restore_scsi_disk(&disk, saved_state);
    check_report_pending_unit_attention(&disk, true).await;
    check_report_pending_unit_attention(&disk, false).await;
}

// Test: Restore a checkpoint containing nonzero sense fields.
// Expected: Saving the restored disk reproduces those serialized sense fields exactly.
#[test]
fn validate_save_restore_scsi_disk_with_sense_data() {
    let (disk, _state) = new_scsi_disk(
        512, 4096, 1024, /* read_only: */ false, /* storage: */ false,
        /* pr: */ false,
    );
    let mut saved_state = save_scsi_disk(&disk);
    saved_state.sense_data = Some(SavedSenseData {
        sense_key: SenseKey::UNIT_ATTENTION.0,
        additional_sense_code: AdditionalSenseCode::OPERATING_CONDITIONS_CHANGED.0,
        additional_sense_code_qualifier: scsi::SCSI_SENSEQ_OPERATING_DEFINITION_CHANGED,
    });
    restore_scsi_disk(&disk, saved_state);
}

// Test: Grow a backing disk between guest reads.
// Expected: Capacity-change attention is delivered once and its failed read writes no guest bytes.
#[async_test]
async fn validate_report_pending_unit_attention() {
    let (disk, state) = new_scsi_disk(
        512, 4096, 1024, /* read_only: */ false, /* storage: */ true,
        /* pr: */ false,
    );
    check_report_pending_unit_attention(&disk, false).await;
    state.lock().sector_count = 4096;
    check_report_pending_unit_attention(&disk, true).await;
    check_report_pending_unit_attention(&disk, false).await;
}

// Test: Issue WRITE SAME on 512-byte and 4 KiB disks, with and without FUA.
// Expected: Four sectors repeat exactly; FUA reaches the backend, input and read guards stay intact.
#[async_test]
async fn validate_async_write_same() {
    write_same(
        512, 4096, 512, /* read_only: */ false, /* fua: */ false,
    )
    .await;
    write_same(
        512, 4096, 512, /* read_only: */ false, /* fua: */ true,
    )
    .await;
    write_same(
        4096, 4096, 16, /* read_only: */ false, /* fua: */ false,
    )
    .await;
    write_same(
        4096, 4096, 16, /* read_only: */ false, /* fua: */ true,
    )
    .await;
}

// Test: Submit the same UNMAP list to writable and read-only disks.
// Expected: Writable discard succeeds; protected media reports WRITE PROTECT without altering input.
#[async_test]
async fn unmap_read_only_disk() {
    let descriptor = scsi::UnmapBlockDescriptor {
        start_lba: 0.into(),
        lba_count: 8.into(),
        reserved: [0; 4],
    };
    let header = scsi::UnmapListHeader {
        data_length: ((size_of::<scsi::UnmapListHeader>() + size_of_val(&descriptor) - 2) as u16)
            .into(),
        block_descriptor_data_length: (size_of_val(&descriptor) as u16).into(),
        reserved: [0; 4],
    };
    let mut data = header.as_bytes().to_vec();
    data.extend_from_slice(descriptor.as_bytes());

    let cdb = scsi::Unmap {
        operation_code: ScsiOp::UNMAP,
        anchor: 0,
        reserved2: [0; 4],
        group_number: 0,
        allocation_length: (data.len() as u16).into(),
        control: 0,
    };
    let mut request = Request {
        cdb: [0; 16],
        srb_flags: 0,
    };
    request.cdb[..size_of_val(&cdb)].copy_from_slice(cdb.as_bytes());

    let guest_mem = make_guest_memory(&data);
    let external_data = OwnedRequestBuffers::linear(0, data.len(), false);

    for read_only in [false, true] {
        let (backing, _) = TestDisk::new(512, 512, 1024, read_only, /* storage: */ false);
        let disk = SimpleScsiDisk::new(
            Disk::new(backing).unwrap(),
            DiskParameters {
                unmap: Some(true),
                ..Default::default()
            },
        );
        if read_only {
            check_execute_scsi_failed_with_result(
                &disk,
                &external_data.buffer(&guest_mem),
                &request,
                &ScsiResult {
                    scsi_status: ScsiStatus::CHECK_CONDITION,
                    srb_status: SrbStatus::ERROR,
                    tx: 0,
                    sense_data: Some(scsi::SenseData::new(
                        SenseKey::DATA_PROTECT,
                        AdditionalSenseCode::WRITE_PROTECT,
                        0,
                    )),
                },
            )
            .await;
        } else {
            check_execute_scsi_pass_with_tx(&disk, &external_data.buffer(&guest_mem), &request, 0)
                .await;
        }
        check_guest_memory(&guest_mem, 0, &data);
    }
}

// Test: Resize to two larger capacities and leave a third disk unchanged.
// Expected: Only resized disks raise attention, and guest capacity reports the current backing size.
#[async_test]
async fn validate_resize() {
    resize(Some(1024)).await;
    resize(Some(4096)).await;
    resize(None).await;
}

// Test: Read two distinct nonzero ISO blocks through an ATAPI wrapper over 512-byte backing sectors.
// Expected: The wrapper transfers exactly 4096 bytes at the requested LBA and preserves all guest guards.
#[async_test]
async fn validate_atapi_disk_read() {
    let iso_sector_size = 2048;
    let (disk, state) = new_scsi_dvd(512, 4096, 1024, true);
    state.lock().storage.fill(0x5c);
    state.lock().storage[3 * iso_sector_size..4 * iso_sector_size].fill(0x33);
    state.lock().storage[4 * iso_sector_size..5 * iso_sector_size].fill(0x44);
    let original_storage = state.lock().storage.clone();
    let atapi_disk = new_atapi_disk(Arc::new(disk));
    let external_data = OwnedRequestBuffers::linear(64, iso_sector_size * 2 + 128, true);
    let guest_mem = GuestMemory::allocate(8192);
    guest_mem.fill_at(0, 0xa5, 8192).unwrap();
    let request = make_cdb10_request(ScsiOp::READ, false, 3, 2);
    check_execute_scsi_pass_with_tx(
        &atapi_disk,
        &external_data.buffer(&guest_mem),
        &request,
        iso_sector_size * 2,
    )
    .await;
    let mut actual = [0; 8192];
    guest_mem.read_at(0, &mut actual).unwrap();
    let mut expected = [0xa5; 8192];
    expected[64..64 + iso_sector_size].fill(0x33);
    expected[64 + iso_sector_size..64 + iso_sector_size * 2].fill(0x44);
    assert_eq!(actual, expected);
    assert_eq!(state.lock().storage, original_storage);
}

fn make_read_track_information_request(
    number_type: u8,
    logical_track_number: u32,
    allocation_length: u16,
) -> Request {
    let mut cdb = [0u8; 16];
    cdb[0] = ScsiOp::READ_TRACK_INFORMATION.0;
    cdb[1] = number_type & 0x3; // number_type in bits [1:0]
    cdb[2..6].copy_from_slice(&logical_track_number.to_be_bytes());
    cdb[7..9].copy_from_slice(&allocation_length.to_be_bytes());
    Request { cdb, srb_flags: 0 }
}

// Test: Request full and truncated track information using track and session addressing.
// Expected: Transfer length follows allocation and full replies identify track/session one.
#[async_test]
async fn validate_read_track_information_returns_correct_tx() {
    let sector_count = 1024u64;
    let (dvd, _state) = new_scsi_dvd(2048, 2048, sector_count, false);
    let track_info_size = size_of::<scsi::TrackInformation3>();

    // Test with allocation_length == full struct size (number_type=1, track 1).
    {
        let alloc_len = track_info_size as u16;
        let guest_mem = GuestMemory::allocate(track_info_size);
        let external_data = OwnedRequestBuffers::linear(0, track_info_size, true);
        let request = make_read_track_information_request(1, 1, alloc_len);
        check_execute_scsi_pass_with_tx(
            &dvd,
            &external_data.buffer(&guest_mem),
            &request,
            track_info_size,
        )
        .await;

        // Verify the returned TrackInformation3 header bytes.
        let mut buf = vec![0u8; track_info_size];
        guest_mem.read_at(0, &mut buf).unwrap();
        let info = scsi::TrackInformation3::read_from_prefix(&buf).unwrap().0;
        assert_eq!(info.length.get(), 0x002e);
        assert_eq!(info.track_number_lsb, 0x01);
        assert_eq!(info.session_number_lsb, 0x01);
    }

    // Test with allocation_length < struct size — tx should be clamped.
    {
        let alloc_len = 8u16;
        let guest_mem = GuestMemory::allocate(track_info_size);
        let external_data = OwnedRequestBuffers::linear(0, alloc_len as usize, true);
        let request = make_read_track_information_request(1, 1, alloc_len);
        check_execute_scsi_pass_with_tx(
            &dvd,
            &external_data.buffer(&guest_mem),
            &request,
            alloc_len as usize,
        )
        .await;
    }

    // Test with number_type=2 (session), session 1.
    {
        let alloc_len = track_info_size as u16;
        let guest_mem = GuestMemory::allocate(track_info_size);
        let external_data = OwnedRequestBuffers::linear(0, track_info_size, true);
        let request = make_read_track_information_request(2, 1, alloc_len);
        check_execute_scsi_pass_with_tx(
            &dvd,
            &external_data.buffer(&guest_mem),
            &request,
            track_info_size,
        )
        .await;
    }
}
