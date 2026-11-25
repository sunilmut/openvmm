// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn opened_channel(version: Version) -> (TestEnv, OfferId) {
    let mut env = TestEnv::new();
    let id = env.offer(1);
    env.connect(version, FeatureFlags::new());
    env.c().handle_request_offers().unwrap();
    env.open(1);
    assert!(matches!(env.recv.try_recv().unwrap(), (offer, Action::Open(..)) if offer == id));
    env.c().open_complete(id, 0);
    env.notifier.messages.clear();
    (env, id)
}

fn retarget(env: &mut TestEnv, vp: u32) {
    env.send_message(in_msg(
        protocol::MessageType::MODIFY_CHANNEL,
        protocol::ModifyChannel {
            channel_id: ChannelId(1),
            target_vp: vp,
        },
    ));
}

// Test: Retarget an Iron channel while a previous retarget is still outstanding.
// Expected: The overlapping request is ignored, completion status is preserved, and later requests work.
#[test]
fn modern_retarget_waits_for_completion_before_accepting_another_request() {
    let (mut env, id) = opened_channel(Version::Iron);
    retarget(&mut env, 7);
    assert!(
        matches!(env.recv.try_recv().unwrap(), (offer, Action::Modify { target_vp: 7 }) if offer == id)
    );
    retarget(&mut env, 9);
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    env.c().modify_channel_complete(id, -42);
    let response: protocol::ModifyChannelResponse = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.status, -42);
    retarget(&mut env, 11);
    assert!(
        matches!(env.recv.try_recv().unwrap(), (offer, Action::Modify { target_vp: 11 }) if offer == id)
    );
    env.c().modify_channel_complete(id, 0);
    let response: protocol::ModifyChannelResponse = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.status, 0);
}

// Test: Save an older channel with several retarget requests outstanding, then restore it.
// Expected: Restore retains the active target and completion delivers only the latest queued target.
#[test]
fn legacy_retarget_coalesces_pending_targets_across_restore() {
    let (mut env, id) = opened_channel(Version::Win10Rs5);
    retarget(&mut env, 7);
    assert!(
        matches!(env.recv.try_recv().unwrap(), (offer, Action::Modify { target_vp: 7 }) if offer == id)
    );
    retarget(&mut env, 9);
    retarget(&mut env, 11);
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let state = env.server.save();

    let mut restored = TestEnv::new();
    let id = restored.offer(1);
    restored.c().restore(state).unwrap();
    assert_eq!(
        restored
            .server
            .get_restore_open_params(id)
            .unwrap()
            .open_data
            .target_vp,
        Some(7)
    );
    restored.c().restore_channel(id, true).unwrap();
    restored.c().modify_channel_complete(id, 0);
    assert!(
        matches!(restored.recv.try_recv().unwrap(), (offer, Action::Modify { target_vp: 11 }) if offer == id)
    );
    restored.c().modify_channel_complete(id, 0);
    assert!(restored.notifier.messages.is_empty());
    assert!(matches!(
        restored.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    let mut again = TestEnv::new();
    let id = again.offer(1);
    again.c().restore(restored.server.save()).unwrap();
    assert_eq!(
        again
            .server
            .get_restore_open_params(id)
            .unwrap()
            .open_data
            .target_vp,
        Some(11)
    );
}

// Test: Try to disable interrupts through ModifyChannel or retarget a closed channel.
// Expected: Both requests report failure without asking the device to change its target.
#[test]
fn invalid_retargets_report_failure_without_device_work() {
    let (mut env, id) = opened_channel(Version::Iron);
    let error = env
        .try_send_message(in_msg(
            protocol::MessageType::MODIFY_CHANNEL,
            protocol::ModifyChannel {
                channel_id: ChannelId(1),
                target_vp: protocol::VP_INDEX_DISABLE_INTERRUPT,
            },
        ))
        .unwrap_err();
    assert!(matches!(error, ChannelError::InvalidTargetVp));
    let response: protocol::ModifyChannelResponse = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.status, protocol::STATUS_UNSUCCESSFUL);
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    env.close(1).unwrap();
    assert!(matches!(env.recv.try_recv().unwrap(), (offer, Action::Close) if offer == id));
    env.c().close_complete(id);
    let error = env
        .try_send_message(in_msg(
            protocol::MessageType::MODIFY_CHANNEL,
            protocol::ModifyChannel {
                channel_id: ChannelId(1),
                target_vp: 3,
            },
        ))
        .unwrap_err();
    assert!(matches!(error, ChannelError::InvalidChannelState));
    let response: protocol::ModifyChannelResponse = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.status, protocol::STATUS_UNSUCCESSFUL);
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

// Test: Restore an opening or already-open channel with nonzero ring and user parameters.
// Expected: Device restore parameters retain every supplied value and opening gets one success reply.
#[test]
fn restore_preserves_open_parameters_and_completes_pending_opens() {
    for completed in [false, true] {
        let mut env = TestEnv::new();
        let id = env.offer(1);
        env.connect(Version::Copper, FeatureFlags::new());
        env.c().handle_request_offers().unwrap();
        env.c()
            .handle_open_channel(&protocol::OpenChannel2 {
                open_channel: protocol::OpenChannel {
                    channel_id: ChannelId(1),
                    open_id: 17,
                    ring_buffer_gpadl_id: GpadlId(42),
                    target_vp: 3,
                    downstream_ring_buffer_page_offset: 2,
                    user_data: [0x5a; 120].into(),
                },
                ..FromZeros::new_zeroed()
            })
            .unwrap();
        if completed {
            env.c().open_complete(id, 0);
        }
        let mut restored = TestEnv::new();
        let id = restored.offer(1);
        restored.c().restore(env.server.save()).unwrap();
        let params = restored.server.get_restore_open_params(id).unwrap();
        assert_eq!(params.channel_id, ChannelId(1));
        assert_eq!(params.open_data.ring_gpadl_id, GpadlId(42));
        assert_eq!(params.open_data.ring_offset, 2);
        assert_eq!(params.open_data.target_vp, Some(3));
        assert_eq!(params.open_data.user_data, [0x5a; 120].into());
        restored.c().restore_channel(id, true).unwrap();
        if completed {
            assert!(restored.notifier.messages.is_empty());
        } else {
            let response: protocol::OpenResult = restored.notifier.get_message();
            assert_eq!(response.channel_id, ChannelId(1));
            assert_eq!(response.open_id, 17);
            assert_eq!(response.status, 0);
        }
        restored.close(1).unwrap();
        assert!(matches!(restored.recv.try_recv().unwrap(), (offer, Action::Close) if offer == id));
    }
}

// Test: Restore a closing channel after the guest queued a new open.
// Expected: A closed device is reopened with the new request rather than the old open parameters.
#[test]
fn restore_reopens_a_closed_device_with_the_queued_request() {
    let (mut env, _) = opened_channel(Version::Copper);
    env.close(1).unwrap();
    env.c()
        .handle_open_channel(&protocol::OpenChannel2 {
            open_channel: protocol::OpenChannel {
                channel_id: ChannelId(1),
                target_vp: 9,
                open_id: 23,
                ring_buffer_gpadl_id: GpadlId(77),
                ..FromZeros::new_zeroed()
            },
            ..FromZeros::new_zeroed()
        })
        .unwrap();
    let mut restored = TestEnv::new();
    let id = restored.offer(1);
    restored.c().restore(env.server.save()).unwrap();
    assert_eq!(
        restored
            .server
            .get_restore_open_params(id)
            .unwrap()
            .open_data
            .target_vp,
        Some(0)
    );
    restored.c().restore_channel(id, false).unwrap();
    let (offer, action) = restored.recv.try_recv().unwrap();
    assert_eq!(offer, id);
    let Action::Open(params, _) = action else {
        panic!("expected reopen");
    };
    assert_eq!(params.open_data.target_vp, Some(9));
    assert_eq!(params.open_data.ring_gpadl_id, GpadlId(77));
    restored.c().open_complete(id, 0);
    let response: protocol::OpenResult = restored.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.open_id, 23);
    assert_eq!(response.status, 0);
}

// Test: Restore missing, closed, and already-restored channels with incompatible device state.
// Expected: Typed errors reject mismatches, while restoring a genuinely closed channel succeeds once.
#[test]
fn restore_rejects_missing_mismatched_and_duplicate_device_state() {
    let mut fresh = TestEnv::new();
    let id = fresh.offer(1);
    assert!(matches!(
        fresh.server.get_restore_open_params(id),
        Err(RestoreError::MissingChannel(_))
    ));
    assert!(matches!(
        fresh.c().restore_channel(id, true),
        Err(RestoreError::MissingChannel(_))
    ));
    fresh.c().restore_channel(id, false).unwrap();
    fresh.connect(Version::Copper, FeatureFlags::new());
    fresh.c().handle_request_offers().unwrap();
    let mut restored = TestEnv::new();
    let id = restored.offer(1);
    restored.c().restore(fresh.server.save()).unwrap();
    assert!(matches!(
        restored.server.get_restore_open_params(id),
        Err(RestoreError::MismatchedOpenState(_))
    ));
    assert!(matches!(
        restored.c().restore_channel(id, true),
        Err(RestoreError::MismatchedOpenState(_))
    ));
    restored.c().restore_channel(id, false).unwrap();
    assert!(matches!(
        restored.server.get_restore_open_params(id),
        Err(RestoreError::AlreadyRestored(_))
    ));
    assert!(matches!(
        restored.c().restore_channel(id, false),
        Err(RestoreError::AlreadyRestored(_))
    ));
}

// Test: Ask for a channel's restorable GPADLs at different creation and teardown stages.
// Expected: Accepted and offered mappings retain their data; incomplete, tearing-down, and other-channel mappings are omitted.
#[test]
fn device_restore_gpadls_preserve_acceptance_and_filter_unavailable_mappings() {
    let mut env = TestEnv::new();
    let id = env.offer(1);
    let other = env.offer(2);
    env.connect(Version::Copper, FeatureFlags::new());
    env.c().handle_request_offers().unwrap();
    for (channel, gpadl, offer) in [(1, 10, id), (2, 11, other), (1, 14, id)] {
        env.gpadl(channel, gpadl);
        env.c().gpadl_create_complete(offer, GpadlId(gpadl), 0);
    }
    env.gpadl(1, 12);
    env.c().handle_gpadl_header(
        &protocol::GpadlHeader {
            channel_id: ChannelId(1),
            gpadl_id: GpadlId(13),
            count: 1,
            len: 24,
        },
        [8192u64, 0].as_bytes(),
    );
    env.teardown_gpadl(1, 14);
    let mut mappings = env.server.channel_gpadls(id);
    mappings.sort_by_key(|mapping| mapping.request.id.0);
    assert_eq!(mappings.len(), 2);
    for (mapping, (expected, accepted)) in mappings.iter().zip([(10, true), (12, false)]) {
        assert_eq!(mapping.request.id, GpadlId(expected));
        assert_eq!(mapping.accepted, accepted);
        assert_eq!(mapping.request.count, 1);
        assert_eq!(mapping.request.buf, [1, 0]);
    }
}

// Test: Restore guest-selected interrupt IDs and interrupt-redirection flags.
// Expected: Device restore parameters preserve the negotiated IDs and flags rather than using defaults.
#[test]
fn restore_preserves_guest_selected_interrupt_routing() {
    let mut env = TestEnv::new();
    let id = env.offer(1);
    env.connect(
        Version::Copper,
        FeatureFlags::new()
            .with_guest_specified_signal_parameters(true)
            .with_channel_interrupt_redirection(true),
    );
    env.c().handle_request_offers().unwrap();
    env.c()
        .handle_open_channel(&protocol::OpenChannel2 {
            open_channel: protocol::OpenChannel {
                channel_id: ChannelId(1),
                target_vp: 7,
                ring_buffer_gpadl_id: GpadlId(42),
                ..FromZeros::new_zeroed()
            },
            event_flag: 91,
            connection_id: 0x1234,
            flags: protocol::OpenChannelFlags::new().with_redirect_interrupt(true),
        })
        .unwrap();
    env.c().open_complete(id, 0);
    let mut restored = TestEnv::new();
    let id = restored.offer(1);
    restored.c().restore(env.server.save()).unwrap();
    let params = restored.server.get_restore_open_params(id).unwrap();
    assert_eq!(params.open_data.target_vp, Some(7));
    assert_eq!(params.open_data.event_flag, 91);
    assert_eq!(params.open_data.connection_id, 0x1234);
    assert_eq!(params.event_flag, 91);
    assert_eq!(params.connection_id, 0x1234);
    assert!(params.flags.redirect_interrupt());
}

// Test: Reuse an incomplete GPADL ID on another channel, then finish the original mapping.
// Expected: The collision is rejected without mixing ranges; the other channel can reuse the ID once complete.
#[test]
fn incomplete_gpadl_ids_cannot_mix_ranges_from_different_channels() {
    let mut env = TestEnv::new();
    let first = env.offer(1);
    let second = env.offer(2);
    env.connect(Version::Copper, FeatureFlags::new());
    env.c().handle_request_offers().unwrap();
    env.notifier.messages.clear();
    for channel in [1, 2] {
        env.c().handle_gpadl_header(
            &protocol::GpadlHeader {
                channel_id: ChannelId(channel),
                gpadl_id: GpadlId(42),
                count: 1,
                len: 24,
            },
            [8192u64, 0].as_bytes(),
        );
    }
    let response: protocol::GpadlCreated = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(2));
    assert_eq!(response.gpadl_id, GpadlId(42));
    assert_eq!(response.status, protocol::STATUS_UNSUCCESSFUL);
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    env.c()
        .handle_gpadl_body(
            &protocol::GpadlBody {
                rsvd: 0,
                gpadl_id: GpadlId(42),
            },
            [1u64].as_bytes(),
        )
        .unwrap();
    let (id, action) = env.recv.try_recv().unwrap();
    assert_eq!(id, first);
    let Action::Gpadl(id, count, pages) = action else {
        panic!("expected complete mapping");
    };
    assert_eq!(id, GpadlId(42));
    assert_eq!(count, 1);
    assert_eq!(pages, [8192, 0, 1]);
    env.c().gpadl_create_complete(first, GpadlId(42), 0);
    let response: protocol::GpadlCreated = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.status, 0);
    env.gpadl(2, 42);
    assert!(
        matches!(env.recv.try_recv().unwrap(), (id, Action::Gpadl(GpadlId(42), 1, _)) if id == second)
    );
    env.c().gpadl_create_complete(second, GpadlId(42), 0);
    let response: protocol::GpadlCreated = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(2));
    assert_eq!(response.status, 0);
}

// Test: Send untrusted requests to a trusted connection and disallowed traffic while paused.
// Expected: Neither rejection changes state or starts device work; trusted resume restores normal operation.
#[test]
fn trust_and_pause_rejections_preserve_the_connection_until_valid_resume() {
    let mut env = TestEnv::new();
    let id = env.offer(1);
    env.connect_trusted(Version::Copper, FeatureFlags::new().with_pause_resume(true));
    assert!(matches!(
        env.try_send_message(in_msg(
            protocol::MessageType::REQUEST_OFFERS,
            protocol::RequestOffers {}
        )),
        Err(ChannelError::UntrustedMessage)
    ));
    assert!(env.notifier.messages.is_empty());
    env.send_message(in_msg_ex(
        protocol::MessageType::REQUEST_OFFERS,
        protocol::RequestOffers {},
        false,
        true,
    ));
    env.notifier.messages.clear();
    env.send_message(in_msg_ex(
        protocol::MessageType::PAUSE,
        protocol::Pause,
        false,
        true,
    ));
    let _: protocol::PauseResponse = env.notifier.get_message();
    assert!(matches!(
        env.try_send_message(in_msg_ex(
            protocol::MessageType::CLOSE_CHANNEL,
            protocol::CloseChannel {
                channel_id: ChannelId(1)
            },
            false,
            true
        )),
        Err(ChannelError::Paused)
    ));
    assert!(env.notifier.messages.is_empty());
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    env.send_message(in_msg_ex(
        protocol::MessageType::RESUME,
        protocol::Resume,
        false,
        true,
    ));
    env.send_message(in_msg_ex(
        protocol::MessageType::OPEN_CHANNEL,
        protocol::OpenChannel {
            channel_id: ChannelId(1),
            ..FromZeros::new_zeroed()
        },
        false,
        true,
    ));
    assert!(matches!(env.recv.try_recv().unwrap(), (offer, Action::Open(..)) if offer == id));
    env.c().open_complete(id, 0);
    let response: protocol::OpenResult = env.notifier.get_message();
    assert_eq!(response.status, 0);
}

// IGNORED: Validation rejects the page pair before marking the connection as
//          modifying. The failure handler then panics instead of replying.
//
// Test: Send ModifyConnection with only one monitor-page address.
// Expected: The guest receives failure rather than a panic, and no backend mapping request is sent.
#[test]
#[ignore = "one-sided monitor-page update panics in complete_modify_connection"]
fn malformed_monitor_page_update_reports_failure_without_panicking() {
    let mut env = TestEnv::new();
    env.connect(
        Version::Copper,
        FeatureFlags::new().with_modify_connection(true),
    );
    env.send_message(in_msg(
        protocol::MessageType::MODIFY_CONNECTION,
        protocol::ModifyConnection {
            child_to_parent_monitor_page_gpa: 0x5000,
            parent_to_child_monitor_page_gpa: 0,
        },
    ));
    let response: protocol::ModifyConnectionResponse = env.notifier.get_message();
    assert_eq!(
        response.connection_state,
        protocol::ConnectionState::FAILED_UNKNOWN_FAILURE
    );
    assert!(env.notifier.modify_requests.is_empty());
}

// Test: Queue a new channel open while the device is still completing the previous close.
// Expected: Reopen waits for close completion and uses the new request's target, ring, and open ID.
#[test]
fn queued_reopen_waits_for_the_previous_device_close() {
    let (mut env, id) = opened_channel(Version::Copper);
    env.close(1).unwrap();
    assert!(matches!(env.recv.try_recv().unwrap(), (offer, Action::Close) if offer == id));
    env.c()
        .handle_open_channel(&protocol::OpenChannel2 {
            open_channel: protocol::OpenChannel {
                channel_id: ChannelId(1),
                open_id: 23,
                target_vp: 9,
                ring_buffer_gpadl_id: GpadlId(77),
                ..FromZeros::new_zeroed()
            },
            ..FromZeros::new_zeroed()
        })
        .unwrap();
    assert!(matches!(
        env.recv.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    env.c().close_complete(id);
    let (offer, action) = env.recv.try_recv().unwrap();
    assert_eq!(offer, id);
    let Action::Open(params, _) = action else {
        panic!("expected reopen");
    };
    assert_eq!(params.open_data.target_vp, Some(9));
    assert_eq!(params.open_data.ring_gpadl_id, GpadlId(77));
    env.c().open_complete(id, 0);
    let response: protocol::OpenResult = env.notifier.get_message();
    assert_eq!(response.channel_id, ChannelId(1));
    assert_eq!(response.open_id, 23);
    assert_eq!(response.status, 0);
}
