// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::save_restore::DriveState;
use crate::save_restore::IsoMediumEvent;
use crate::save_restore::SavedSenseData;
use crate::save_restore::ScsiDiskSavedState;
use crate::save_restore::ScsiDvdSavedState;
use crate::save_restore::ScsiSavedState;
use mesh::OwnedMessage;
use test_with_tracing::test;

fn transfer(state: ScsiSavedState) -> ScsiSavedState {
    OwnedMessage::serialized(OwnedMessage::new(state).serialize())
        .parse()
        .unwrap()
}

// Test: Transfer DVD migration messages for all tray/media combinations,
//       varying removal flags, pending media events, and absent-media sense.
// Expected: The DVD variant retains each field, and consumers observe the
//       original tray/media condition without losing the sense qualifier.
#[test]
fn dvd_messages_preserve_media_condition_and_independent_flags() {
    for (index, (drive_state, event, tray_open, medium_present)) in [
        (
            DriveState::MediumPresentTrayClosed,
            IsoMediumEvent::None,
            false,
            true,
        ),
        (
            DriveState::MediumPresentTrayOpen,
            IsoMediumEvent::NoMediaToMedia,
            true,
            true,
        ),
        (
            DriveState::MediumNotPresentTrayOpen,
            IsoMediumEvent::MediaToNoMedia,
            true,
            false,
        ),
        (
            DriveState::MediumNotPresentTrayClosed,
            IsoMediumEvent::MediaToMedia,
            false,
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let sense = (!medium_present).then_some(SavedSenseData {
            sense_key: 2,
            additional_sense_code: 0x3a,
            additional_sense_code_qualifier: if tray_open { 2 } else { 1 },
        });
        let persistent = index & 1 != 0;
        let prevent = index & 2 != 0;
        let ScsiSavedState::ScsiDvd(received) =
            transfer(ScsiSavedState::ScsiDvd(ScsiDvdSavedState {
                sense_data: sense,
                persistent,
                prevent,
                drive_state,
                pending_medium_event: event,
            }))
        else {
            panic!("DVD migration message changed device type");
        };
        assert_eq!(received.drive_state, drive_state);
        assert_eq!(received.drive_state.tray_open(), tray_open);
        assert_eq!(received.drive_state.medium_present(), medium_present);
        assert_eq!(received.sense_data, sense);
        assert_eq!(received.persistent, persistent);
        assert_eq!(received.prevent, prevent);
        assert_eq!(received.pending_medium_event, event);
    }
}

// Test: Transfer disk migration messages with empty, small, and large capacities
//       and both absent and present NOT READY sense information.
// Expected: The disk variant retains all 64 capacity bits and the independent
//       sense key, additional code, and qualifier rather than inheriting stale sense.
#[test]
fn disk_messages_preserve_capacity_and_optional_sense() {
    let sense = SavedSenseData {
        sense_key: 2,
        additional_sense_code: 4,
        additional_sense_code_qualifier: 1,
    };
    for sector_count in [0, 1, 1 << 40, u64::MAX] {
        for sense_data in [None, Some(sense)] {
            let ScsiSavedState::ScsiDisk(received) =
                transfer(ScsiSavedState::ScsiDisk(ScsiDiskSavedState {
                    sector_count,
                    sense_data,
                }))
            else {
                panic!("disk migration message changed device type");
            };
            assert_eq!(received.sector_count, sector_count);
            assert_eq!(received.sense_data, sense_data);
        }
    }
}
