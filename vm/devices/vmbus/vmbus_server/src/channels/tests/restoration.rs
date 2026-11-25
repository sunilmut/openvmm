// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn saved_mapping() -> SavedStateData {
    let mut env = TestEnv::new();
    let id = env.offer_with_mnf(1);
    env.connect(Version::Copper, FeatureFlags::new());
    env.c().handle_request_offers().unwrap();
    env.gpadl(1, 42);
    env.c().gpadl_create_complete(id, GpadlId(42), 0);
    env.server.save().into()
}

fn connected(data: &mut SavedStateData) -> &mut saved_state::ConnectedState {
    let saved_state::SavedConnectionState::Connected(state) = &mut data.state else {
        panic!("expected connected snapshot");
    };
    state
}

fn restore(data: SavedStateData) -> Result<(), RestoreError> {
    let mut env = TestEnv::new();
    env.c().restore(data.into())
}

// Test: Save while a new contact is queued behind disconnect, including invalid monitor-page pairs.
// Expected: Restore replays the requested VP, version, and monitor settings, or reports the invalid pair.
#[test]
fn pending_reconnect_survives_restore_with_its_original_contact_parameters() {
    for (child, parent) in [(0, 0), (0x123000, 0x321000), (0x123000, 0)] {
        let mut env = TestEnv::new();
        env.connect(Version::Win10, FeatureFlags::new());
        env.send_message(in_msg(
            protocol::MessageType::INITIATE_CONTACT,
            protocol::InitiateContact2 {
                initiate_contact: protocol::InitiateContact {
                    version_requested: Version::Copper as u32,
                    target_message_vp: 7,
                    interrupt_page_or_target_info: TargetInfo::new()
                        .with_sint(VMBUS_SINT)
                        .with_vtl(0)
                        .into(),
                    child_to_parent_monitor_page_gpa: child,
                    parent_to_child_monitor_page_gpa: parent,
                },
                client_id: Guid::ZERO,
            },
        ));
        let saved = env.server.save();
        let mut restored = TestEnv::new();
        restored.c().restore(saved).unwrap();
        restored.c().revoke_unclaimed_channels();
        let request = restored.next_action();
        assert!(request.version.is_none());
        assert_eq!(request.monitor_page, Update::Reset);
        restored.c().complete_disconnect();
        if parent == 0 && child != 0 {
            let response: protocol::VersionResponse2 = restored.notifier.get_message();
            assert_eq!(response.version_response.version_supported, 1);
            assert_eq!(
                response.version_response.connection_state,
                protocol::ConnectionState::FAILED_UNKNOWN_FAILURE
            );
            assert!(restored.notifier.modify_requests.is_empty());
        } else {
            let request = restored.next_action();
            assert_eq!(request.version.unwrap().version, Version::Copper);
            assert_eq!(request.target_message_vp, Some(7));
            assert_eq!(
                request.monitor_page,
                if child == 0 {
                    Update::Reset
                } else {
                    Update::Set(MonitorPageGpas {
                        child_to_parent: child,
                        parent_to_child: parent,
                    })
                }
            );
            restored
                .c()
                .complete_initiate_contact(ModifyConnectionResponse::Supported(
                    protocol::ConnectionState::SUCCESSFUL,
                    SUPPORTED_FEATURE_FLAGS,
                    None,
                ));
            let response: protocol::VersionResponse2 = restored.notifier.get_message();
            assert_eq!(response.version_response.version_supported, 1);
            assert_eq!(
                response.version_response.connection_state,
                protocol::ConnectionState::SUCCESSFUL
            );
            restored.c().handle_request_offers().unwrap();
            restored
                .notifier
                .check_message(OutgoingMessage::new(&protocol::AllOffersDelivered {}));
        }
    }
}

// Test: Restore snapshots containing a repeated channel or GPADL identity.
// Expected: Duplicate records are rejected with the relevant typed restore error.
#[test]
fn duplicate_saved_channel_and_gpadl_records_are_rejected() {
    let mut channels = saved_mapping();
    let state = connected(&mut channels);
    state.channels.push(state.channels[0].clone());
    assert!(matches!(
        restore(channels),
        Err(RestoreError::AlreadyRestored(_))
    ));

    let mut mappings = saved_mapping();
    let state = connected(&mut mappings);
    state.gpadls.push(state.gpadls[0].clone());
    assert!(matches!(
        restore(mappings),
        Err(RestoreError::GpadlIdInUse(GpadlId(42), ChannelId(1)))
    ));
}

// Test: Restore a GPADL without its channel or with a malformed range buffer.
// Expected: The missing association and invalid range produce distinct, explicit restore errors.
#[test]
fn saved_gpadls_require_an_existing_channel_and_a_valid_range() {
    let mut missing = saved_mapping();
    connected(&mut missing).channels.clear();
    assert!(matches!(
        restore(missing),
        Err(RestoreError::MissingGpadlChannel(GpadlId(42), ChannelId(1)))
    ));
    let mut malformed = saved_mapping();
    connected(&mut malformed).gpadls[0].buf.clear();
    assert!(matches!(
        restore(malformed),
        Err(RestoreError::InvalidGpadl(_))
    ));
}

// Test: Restore channel IDs that are outside the protocol namespace or collide across channel keys.
// Expected: Neither invalid assignment can overwrite a channel's existing routing identity.
#[test]
fn saved_channel_ids_must_be_valid_and_unique() {
    let mut invalid = saved_mapping();
    connected(&mut invalid).channels[0].channel_id = 0;
    assert!(matches!(
        restore(invalid),
        Err(RestoreError::Offer(OfferError::InvalidChannelId(
            ChannelId(0)
        )))
    ));

    let mut duplicate = saved_mapping();
    let state = connected(&mut duplicate);
    let mut channel = state.channels[0].clone();
    channel.key.instance_id = guid_from_id(2);
    state.channels.push(channel);
    assert!(matches!(
        restore(duplicate),
        Err(RestoreError::Offer(OfferError::ChannelIdInUse(ChannelId(
            1
        ))))
    ));
}

// Test: Restore an unaccepted GPADL associated with a revoked channel.
// Expected: Restore rejects work that cannot be offered to the revoked device.
#[test]
fn revoked_channels_cannot_restore_an_unaccepted_gpadl() {
    let mut data = saved_mapping();
    let state = connected(&mut data);
    state.channels[0].state = saved_state::ChannelState::Revoked;
    state.gpadls[0].state = saved_state::GpadlState::Offered;
    assert!(matches!(
        restore(data),
        Err(RestoreError::GpadlForRevokedChannel(
            GpadlId(42),
            ChannelId(1)
        ))
    ));
}

// Test: Match a relay offer whose fixed monitor ID differs from the snapshot's monitor.
// Expected: Restore and late reoffer both reject the mismatch rather than changing interrupt routing.
#[test]
fn relay_monitor_identity_must_match_before_and_after_snapshot_restore() {
    let saved = saved_mapping();
    let mut early = TestEnv::new();
    early.offer_with_preset_mnf(1, 7);
    assert!(matches!(
        early.c().restore(saved.clone().into()),
        Err(RestoreError::MismatchedMonitorId(7, Some(0)))
    ));

    let mut late = TestEnv::new();
    late.c().restore(saved.into()).unwrap();
    let result = late.c().offer_channel(OfferParamsInternal {
        interface_id: guid_from_id(1),
        instance_id: guid_from_id(1),
        use_mnf: MnfUsage::Relayed { monitor_id: 7 },
        ..Default::default()
    });
    assert!(matches!(
        result,
        Err(OfferError::MismatchedMonitorId(
            Some(MonitorId(0)),
            MonitorId(7)
        ))
    ));
}

// Test: Save after the guest requests unload while initial connection negotiation is outstanding.
// Expected: Restore finishes negotiation, disconnects, and sends the pending unload acknowledgement.
#[test]
fn unload_queued_during_negotiation_is_completed_after_restore() {
    let mut env = TestEnv::new();
    env.start_connect(Version::Copper, FeatureFlags::new(), false, false);
    env.c().handle_unload();
    let mut restored = TestEnv::new();
    restored.c().restore(env.server.save()).unwrap();
    assert_eq!(
        restored.next_action().version.unwrap().version,
        Version::Copper
    );
    restored
        .c()
        .complete_initiate_contact(ModifyConnectionResponse::Supported(
            protocol::ConnectionState::SUCCESSFUL,
            SUPPORTED_FEATURE_FLAGS,
            None,
        ));
    let response: protocol::VersionResponse2 = restored.notifier.get_message();
    assert_eq!(response.version_response.version_supported, 1);
    let disconnect = restored.next_action();
    assert!(disconnect.version.is_none());
    assert_eq!(disconnect.monitor_page, Update::Reset);
    restored.c().complete_disconnect();
    restored
        .notifier
        .check_message(OutgoingMessage::new(&protocol::UnloadComplete {}));
    restored.connect(Version::Copper, FeatureFlags::new());
}

// Test: Restore two monitored channels that incorrectly claim the same monitor ID.
// Expected: The second device restore reports a duplicate instead of sharing the first channel's interrupt bit.
#[test]
fn restored_monitored_channels_cannot_claim_the_same_interrupt_bit() {
    let mut env = TestEnv::new();
    env.offer_with_mnf(1);
    env.offer_with_mnf(2);
    env.connect(Version::Copper, FeatureFlags::new());
    env.c().handle_request_offers().unwrap();
    let mut data = SavedStateData::from(env.server.save());
    let state = connected(&mut data);
    state.channels[1].monitor_id = state.channels[0].monitor_id;
    let mut restored = TestEnv::new();
    let first = restored.offer_with_mnf(1);
    let second = restored.offer_with_mnf(2);
    restored.c().restore(data.into()).unwrap();
    restored.c().restore_channel(first, false).unwrap();
    assert!(matches!(
        restored.c().restore_channel(second, false),
        Err(RestoreError::DuplicateMonitorId(0))
    ));
}
