// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::{scsi, scsidvd::SimpleScsiDvd};
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request, ScsiSaveRestore};

fn event_request(mask: u8, allocation: u16) -> [u8; 16] {
    let mut cdb = [0; 16];
    cdb[0] = 0x4a;
    cdb[1] = 1;
    cdb[4] = mask;
    cdb[7..9].copy_from_slice(&allocation.to_be_bytes());
    cdb
}

async fn media_event(dvd: &SimpleScsiDvd, event: u8, status: u8) {
    check_response(
        dvd,
        event_request(0x10, 8),
        128,
        &[0, 6, 4, 0x7e, event, status, 0, 0],
    )
    .await;
}

async fn control(dvd: &SimpleScsiDvd, operation: u8, flags: u8) {
    let mut cdb = [0; 16];
    cdb[0] = operation;
    cdb[4] = flags;
    check_response(dvd, cdb, 0, &[]).await;
}

// Test: Poll the initial loaded medium, remove it externally, and poll an initially empty drive.
// Expected: Removal and arrival events are delivered once, followed by accurate no-change media/tray state.
#[async_test]
async fn dvd_media_events_deliver_each_transition_once() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    media_event(&dvd, 3, 1).await;
    media_event(&dvd, 2, 2).await;
    media_event(&dvd, 0, 2).await;
    dvd.change_media(None);
    media_event(&dvd, 3, 1).await;
    media_event(&dvd, 0, 1).await;
    let empty = SimpleScsiDvd::new(None);
    media_event(&empty, 3, 0).await;
    media_event(&empty, 0, 0).await;
}

// Test: Query each notification class with persistent prevention enabled/disabled and truncated allocations.
// Expected: Wire class IDs, active/ready/media flags, priority, and guarded truncation remain consistent.
#[async_test]
async fn dvd_notification_classes_report_persistent_policy_and_exact_prefixes() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    dvd.clear_nexus_state();
    for persistent in [false, true] {
        control(&dvd, 0x1e, if persistent { 3 } else { 0 }).await;
        for (mask, class, status) in [
            (2, 1, if persistent { 0x80 } else { 0 }),
            (4, 2, 1),
            (8, 3, if persistent { 0x80 } else { 0 }),
            (16, 4, 2),
            (32, 5, if persistent { 0x80 } else { 0 }),
            (64, 6, 0),
            (0x7e, 1, if persistent { 0x80 } else { 0 }),
        ] {
            let expected = [0, 6, class, 0x7e, 0, status, 0, 0];
            for allocation in 0..=8 {
                check_response(
                    &dvd,
                    event_request(mask, allocation),
                    128,
                    &expected[..usize::from(allocation)],
                )
                .await;
            }
        }
    }
}

// Test: Save after the removal phase of a loaded-media transition, consume arrival, restore, and poll again.
// Expected: Restore replays exactly the pending arrival and nexus clearing discards subsequent pending events.
#[async_test]
async fn dvd_checkpoint_preserves_pending_arrival_and_nexus_clear_discards_events() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    media_event(&dvd, 3, 1).await;
    let saved = dvd.save().unwrap().unwrap();
    media_event(&dvd, 2, 2).await;
    media_event(&dvd, 0, 2).await;
    dvd.restore(&saved).unwrap();
    media_event(&dvd, 2, 2).await;
    media_event(&dvd, 0, 2).await;
    dvd.change_media(None);
    dvd.clear_nexus_state();
    media_event(&dvd, 0, 1).await;
}

// Test: Start/stop the medium, eject it, close the empty tray, and eject the empty drive again.
// Expected: Motor commands preserve media; eject removes it once; tray closure never reloads an ejected medium.
#[async_test]
async fn dvd_guest_eject_and_load_preserve_tray_and_media_semantics() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
    dvd.clear_nexus_state();
    control(&dvd, 0x1b, 0).await;
    control(&dvd, 0x1b, 1).await;
    media_event(&dvd, 0, 2).await;
    control(&dvd, 0x1b, 2).await;
    media_event(&dvd, 3, 1).await;
    media_event(&dvd, 0, 1).await;
    control(&dvd, 0x1b, 3).await;
    media_event(&dvd, 0, 0).await;
    control(&dvd, 0x1b, 2).await;
    media_event(&dvd, 0, 1).await;
}

// Test: Prevent ejection with and without media, then clear the nexus and retry.
// Expected: Prevention returns the medium-removal-prevented sense without state mutation, and nexus clearing allows eject.
#[async_test]
async fn dvd_prevent_removal_blocks_ejection_until_nexus_reset() {
    for present in [false, true] {
        let (loaded, _) = new_scsi_dvd(2048, 2048, 1024, false);
        let dvd = if present {
            loaded
        } else {
            SimpleScsiDvd::new(None)
        };
        dvd.clear_nexus_state();
        control(&dvd, 0x1e, 3).await;
        let memory = GuestMemory::allocate(4096);
        let buffers = OwnedRequestBuffers::linear(0, 0, false);
        let mut cdb = [0; 16];
        cdb[0] = 0x1b;
        cdb[4] = 2;
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(result.srb_status, scsi::srb::SrbStatus::ERROR);
        assert_eq!(result.tx, 0);
        let sense = result.sense_data.unwrap();
        assert_eq!(
            sense.header.sense_key,
            if present {
                scsi::SenseKey::ILLEGAL_REQUEST
            } else {
                scsi::SenseKey::NOT_READY
            }
        );
        assert_eq!(
            sense.additional_sense_code,
            scsi::AdditionalSenseCode::MEDIUM_REMOVAL_PREVENTED
        );
        assert_eq!(sense.additional_sense_code_qualifier, 2);
        media_event(&dvd, 0, if present { 2 } else { 0 }).await;
        dvd.clear_nexus_state();
        control(&dvd, 0x1b, 2).await;
        media_event(&dvd, if present { 3 } else { 0 }, 1).await;
    }
}

// Test: Request asynchronous event notification or an event allocation larger than the response buffer.
// Expected: Invalid CDB and overrun errors transfer nothing, preserve memory, and leave the initial media event pending.
#[async_test]
async fn invalid_dvd_event_requests_preserve_memory_and_pending_transition() {
    for oversized in [false, true] {
        let (dvd, _) = new_scsi_dvd(2048, 2048, 1024, false);
        let memory = GuestMemory::allocate(4096);
        memory.write_at(0, &[0xa5; 256]).unwrap();
        let buffers = OwnedRequestBuffers::linear(16, 128, true);
        let mut cdb = event_request(16, if oversized { 129 } else { 8 });
        if !oversized {
            cdb[1] = 0;
        }
        let result = dvd
            .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
            .await;
        assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
        assert_eq!(
            result.srb_status,
            if oversized {
                scsi::srb::SrbStatus::DATA_OVERRUN
            } else {
                scsi::srb::SrbStatus::ERROR
            }
        );
        assert_eq!(result.tx, 0);
        let mut actual = [0; 256];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa5; 256]);
        media_event(&dvd, 3, 1).await;
    }
}

// Test: Poll readiness and media-dependent information with the medium present and an empty tray closed/open/closed.
// Expected: Loaded media is ready; absent media reports NOT READY/NO MEDIA with the precise tray qualifier and no output writes.
#[async_test]
async fn dvd_absent_media_reports_readiness_and_tray_specific_sense() {
    let (loaded, _) = new_scsi_dvd(2048, 2048, 1024, false);
    let mut ready = [0; 16];
    ready[0] = 0;
    check_response(&loaded, ready, 0, &[]).await;
    let dvd = SimpleScsiDvd::new(None);
    dvd.clear_nexus_state();
    for (movement, qualifier) in [(None, 1), (Some(2), 2), (Some(3), 1)] {
        if let Some(flags) = movement {
            control(&dvd, 0x1b, flags).await;
        }
        for operation in [0, 0x51, 0xad] {
            let memory = GuestMemory::allocate(4096);
            memory.write_at(0, &[0xa5; 256]).unwrap();
            let buffers = OwnedRequestBuffers::linear(16, 128, true);
            let mut cdb = [0; 16];
            cdb[0] = operation;
            if operation == 0x51 {
                cdb[8] = 32;
            }
            if operation == 0xad {
                cdb[9] = 16;
            }
            let result = dvd
                .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
                .await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::ERROR);
            assert_eq!(result.tx, 0);
            let sense = result.sense_data.unwrap();
            assert_eq!(sense.header.sense_key, scsi::SenseKey::NOT_READY);
            assert_eq!(
                sense.additional_sense_code,
                scsi::AdditionalSenseCode::NO_MEDIA_IN_DEVICE
            );
            assert_eq!(sense.additional_sense_code_qualifier, qualifier);
            let mut actual = [0; 256];
            memory.read_at(0, &mut actual).unwrap();
            assert_eq!(actual, [0xa5; 256]);
        }
    }
}
