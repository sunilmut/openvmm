// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::CancelContext;
use test_with_tracing::test;

pub(super) async fn bounded<F: Future>(future: F) -> F::Output {
    CancelContext::new()
        .with_timeout(Duration::from_secs(5))
        .until_cancelled(future)
        .await
        .expect("server control test timed out")
}

async fn open_ring(env: &mut TestEnv, channel: &mut TestChannel) {
    env.synic.send_message_core(
        OutgoingMessage::with_data(
            &protocol::GpadlHeader {
                channel_id: ChannelId(1),
                gpadl_id: GpadlId(42),
                count: 1,
                len: 40,
            },
            [4 * 4096u64, 0, 1, 2, 3].as_bytes(),
        ),
        false,
    );
    channel.handle_gpadl().await;
    env.expect_response(protocol::MessageType::GPADL_CREATED)
        .await;
    env.synic.send_message(protocol::OpenChannel {
        channel_id: ChannelId(1),
        open_id: 17,
        ring_buffer_gpadl_id: GpadlId(42),
        target_vp: 0,
        downstream_ring_buffer_page_offset: 2,
        user_data: Default::default(),
    });
    channel.handle_open(|_| {}).await;
    let response: protocol::OpenResult = env.get_response().await;
    assert_eq!(response.open_id, 17);
    assert_eq!(response.status, 0);
}

fn pending_ring_notifications(gm: &GuestMemory) {
    // Both rings have unread bytes and enough free space for a blocked writer.
    for offset in [0, 8192] {
        gm.write_at(offset, [16u32, 0, 0, 1].as_bytes()).unwrap();
    }
}

async fn wait_for_guest_interrupts(synic: &MockSynic, driver: &DefaultDriver, expected: usize) {
    let mut notify = vmcore::notify::Notify::from_event(synic.guest_interrupt_event.clone())
        .pollable(driver)
        .unwrap();
    while synic.guest_interrupts.load(Ordering::SeqCst) < expected {
        notify.wait().await;
    }
    assert_eq!(synic.guest_interrupts.load(Ordering::SeqCst), expected);
}

// Test: Reject one device open while another channel opens, then retry the rejected channel.
// Expected: Wire replies retain distinct channel/open IDs and status; the peer and retry succeed.
#[async_test]
async fn rejected_device_open_preserves_peer_and_retry_correlation(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver)
            .without_message_delays()
            .build_with(GuestMemory::empty(), |builder| {
                builder.channel_unstick_delay(None)
            });
        let mut first = env.offer(1, false).await;
        let mut peer = env.offer(2, false).await;
        env.vmbus.start();
        env.connect(2, protocol::FeatureFlags::new(), false).await;
        env.gpadl(1, 41, &mut first).await;
        env.gpadl(2, 42, &mut peer).await;
        for (channel_id, open_id, ring, target) in [(1, 17, 41, 3), (2, 23, 42, 7)] {
            env.synic.send_message(protocol::OpenChannel {
                channel_id: ChannelId(channel_id),
                open_id,
                ring_buffer_gpadl_id: GpadlId(ring),
                target_vp: target,
                downstream_ring_buffer_page_offset: 0,
                user_data: [target as u8; 120].into(),
            });
        }
        let ChannelRequest::Open(failed) = first.next_request().await else {
            panic!("expected first open");
        };
        let ChannelRequest::Open(accepted) = peer.next_request().await else {
            panic!("expected peer open");
        };
        assert_eq!(failed.input().open_data.target_vp, Some(3));
        assert_eq!(accepted.input().open_data.target_vp, Some(7));
        assert_eq!(accepted.input().open_data.user_data, [7; 120].into());
        accepted.complete(true);
        let response: protocol::OpenResult = env.get_response().await;
        assert_eq!(
            (response.channel_id, response.open_id, response.status),
            (ChannelId(2), 23, protocol::STATUS_SUCCESS as u32)
        );
        failed.complete(false);
        let response: protocol::OpenResult = env.get_response().await;
        assert_eq!(
            (response.channel_id, response.open_id, response.status),
            (ChannelId(1), 17, protocol::STATUS_UNSUCCESSFUL as u32)
        );
        env.synic.send_message(protocol::OpenChannel {
            channel_id: ChannelId(1),
            open_id: 29,
            ring_buffer_gpadl_id: GpadlId(41),
            target_vp: 9,
            downstream_ring_buffer_page_offset: 0,
            user_data: Default::default(),
        });
        first
            .handle_open(|request| assert_eq!(request.open_data.target_vp, Some(9)))
            .await;
        let response: protocol::OpenResult = env.get_response().await;
        assert_eq!(
            (response.channel_id, response.open_id, response.status),
            (ChannelId(1), 29, protocol::STATUS_SUCCESS as u32)
        );
        assert!(matches!(poll!(peer.request_recv.next()), Poll::Pending));
        assert!(matches!(poll!(env.message_recv.next()), Poll::Pending));
    })
    .await;
}
// Test: Open rings with pending notifications while the guest misses initial channel interrupts.
// Expected: Delayed recovery wakes both guest ring endpoints without spuriously waking the host.
#[async_test]
async fn delayed_channel_recovery_signals_pending_guest_ring_work(driver: DefaultDriver) {
    bounded(async {
        let gm = GuestMemory::allocate(4 * 4096);
        pending_ring_notifications(&gm);
        let mut env = TestEnvBuilder::new(driver.clone()).build_with(gm, |builder| {
            builder.channel_unstick_delay(Some(Duration::from_millis(10)))
        });
        let host_interrupts = Arc::new(AtomicUsize::new(0));
        let count = host_interrupts.clone();
        let mut channel = env
            .offer_with_event(
                1,
                false,
                Interrupt::from_fn(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        open_ring(&mut env, &mut channel).await;
        wait_for_guest_interrupts(&env.synic, &driver, 2).await;
        assert_eq!(host_interrupts.load(Ordering::SeqCst), 0);
    })
    .await;
}

// Test: Restore an open channel saved before the lost-SynIC compatibility fix.
// Expected: Restored GPADLs and open parameters are usable, and startup wakes both sides of both rings.
#[async_test]
async fn legacy_restore_recovers_pending_host_and_guest_ring_notifications(driver: DefaultDriver) {
    bounded(async {
        let gm = GuestMemory::allocate(4 * 4096);
        pending_ring_notifications(&gm);
        let mut env = TestEnvBuilder::new(driver.clone())
            .build_with(gm.clone(), |builder| builder.channel_unstick_delay(None));
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        open_ring(&mut env, &mut channel).await;
        env.vmbus.stop().await;
        let mut state = env.vmbus.save().await;
        state.lost_synic_bug_fixed = false;

        let restored = TestEnvBuilder::new(driver.clone())
            .build_with(gm, |builder| builder.channel_unstick_delay(None));
        let host_interrupts = Arc::new(AtomicUsize::new(0));
        let count = host_interrupts.clone();
        let channel = restored
            .offer_with_event(
                1,
                false,
                Interrupt::from_fn(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await;
        restored.vmbus.restore(state).await.unwrap();
        let result = channel
            .server_request_send
            .call(ChannelServerRequest::Restore, true)
            .await
            .unwrap()
            .unwrap();
        let open = result.open_request.unwrap();
        assert_eq!(open.open_data.ring_gpadl_id, GpadlId(42));
        assert_eq!(open.open_data.ring_offset, 2);
        assert_eq!(result.gpadls.len(), 1);
        assert!(result.gpadls[0].accepted);
        assert_eq!(result.gpadls[0].request.buf, [4 * 4096, 0, 1, 2, 3]);
        restored.vmbus.start();
        wait_for_guest_interrupts(&restored.synic, &driver, 2).await;
        assert_eq!(host_interrupts.load(Ordering::SeqCst), 2);
    })
    .await;
}

// Test: Forward hvsocket requests through a configured relay or the default rejection handler.
// Expected: Failure replies retain both IDs, and a configured relay receives the full guest request.
#[async_test]
async fn hvsocket_requests_reach_the_relay_and_return_correlated_failures(driver: DefaultDriver) {
    bounded(async {
        for configured in [false, true] {
            let relay = HvsockRelayChannel::new();
            let mut receiver = relay.relay_half;
            let mut env = TestEnvBuilder::new(driver.clone())
                .build_with(GuestMemory::empty(), |builder| {
                    builder.hvsock_notify(configured.then_some(relay.server_half))
                });
            env.vmbus.start();
            env.connect(0, protocol::FeatureFlags::new(), false).await;
            // A rejected duplicate must not block later socket traffic.
            env.synic.send_message(protocol::RequestOffers {});
            let service = Guid::new_random();
            let endpoint = Guid::new_random();
            let silo = Guid::new_random();
            env.synic.send_message(protocol::TlConnectRequest2 {
                base: protocol::TlConnectRequest {
                    service_id: service,
                    endpoint_id: endpoint,
                },
                silo_id: silo,
            });
            if configured {
                let request = receiver.request_receive.next().await.unwrap();
                assert_eq!(request.service_id, service);
                assert_eq!(request.endpoint_id, endpoint);
                assert_eq!(request.silo_id, silo);
                receiver
                    .response_send
                    .send(HvsockConnectResult::from_request(&request, false));
            }
            let result: protocol::TlConnectResult = env.get_response().await;
            assert_eq!(result.service_id, service);
            assert_eq!(result.endpoint_id, endpoint);
            assert_eq!(result.status, protocol::STATUS_CONNECTION_REFUSED);
        }
    })
    .await;
}

// Test: Have the relay reject a version, fail a supported connection, and then accept a retry.
// Expected: The guest sees each relay result accurately and can reconnect after either failure.
#[async_test]
async fn relay_negotiation_failures_allow_a_successful_retry(driver: DefaultDriver) {
    bounded(async {
        let relay = VmbusRelayChannel::new();
        let mut receiver = relay.relay_half;
        let mut env =
            TestEnvBuilder::new(driver.clone()).build_with(GuestMemory::empty(), |builder| {
                builder
                    .enable_mnf(false)
                    .server_relay(Some(relay.server_half))
            });
        env.vmbus.start();
        for (reply, supported, state) in [
            (
                ModifyRelayResponse::Unsupported,
                0,
                protocol::ConnectionState::SUCCESSFUL,
            ),
            (
                ModifyRelayResponse::Supported(
                    protocol::ConnectionState::FAILED_UNKNOWN_FAILURE,
                    protocol::FeatureFlags::new(),
                ),
                1,
                protocol::ConnectionState::FAILED_UNKNOWN_FAILURE,
            ),
            (
                ModifyRelayResponse::Supported(
                    protocol::ConnectionState::SUCCESSFUL,
                    protocol::FeatureFlags::new(),
                ),
                1,
                protocol::ConnectionState::SUCCESSFUL,
            ),
        ] {
            env.initiate_contact(
                protocol::Version::Win10Rs5,
                protocol::FeatureFlags::new(),
                false,
                false,
            );
            let request = receiver.request_receive.next().await.unwrap();
            assert_eq!(request.version, Some(protocol::Version::Win10Rs5 as u32));
            assert!(matches!(request.monitor_page, Update::Reset));
            assert_eq!(request.use_interrupt_page, Some(false));
            receiver.response_send.send(reply);
            let response: protocol::VersionResponse = env.get_response().await;
            assert_eq!(response.version_supported, supported);
            assert_eq!(response.connection_state, state);
        }
        env.synic.send_message(protocol::RequestOffers {});
        env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
    })
    .await;
}

// Test: Limit live negotiation immediately or only after the boot client's first unload.
// Expected: The delayed cap permits the first modern client; afterward only the configured version works.
#[async_test]
async fn version_cap_takes_effect_at_the_configured_connection_boundary(driver: DefaultDriver) {
    bounded(async {
        for delayed in [false, true] {
            let mut env =
                TestEnvBuilder::new(driver.clone()).build_with(GuestMemory::empty(), |builder| {
                    builder
                        .max_version(Some(MaxVersionInfo::new(
                            protocol::Version::Win10Rs5 as u32,
                        )))
                        .delay_max_version(delayed)
                });
            env.vmbus.start();
            env.initiate_contact(
                protocol::Version::Copper,
                protocol::FeatureFlags::new(),
                false,
                false,
            );
            if delayed {
                let response: protocol::VersionResponse2 = env.get_response().await;
                assert_eq!(response.version_response.version_supported, 1);
                env.synic.send_message(protocol::Unload {});
                env.expect_response(protocol::MessageType::UNLOAD_COMPLETE)
                    .await;
                env.initiate_contact(
                    protocol::Version::Copper,
                    protocol::FeatureFlags::new(),
                    false,
                    false,
                );
            }
            let response: protocol::VersionResponse = env.get_response().await;
            assert_eq!(response.version_supported, 0);
            env.initiate_contact(
                protocol::Version::Win10Rs5,
                protocol::FeatureFlags::new(),
                false,
                false,
            );
            let response: protocol::VersionResponse = env.get_response().await;
            assert_eq!(response.version_supported, 1);
            assert_eq!(
                response.connection_state,
                protocol::ConnectionState::SUCCESSFUL
            );
        }
    })
    .await;
}

// Test: Force confidential, pinned external memory on a redirected paravisor server.
// Expected: Wire offers and device opens carry the requirements, and device resources select private memory.
#[async_test]
async fn forced_confidential_pinned_channels_use_the_private_memory_view(driver: DefaultDriver) {
    bounded(async {
        let gm = GuestMemory::allocate(4096);
        gm.write_at(0, &[0x11]).unwrap();
        let private = GuestMemory::allocate(4096);
        private.write_at(0, &[0x22]).unwrap();
        let mut env = TestEnvBuilder::new(driver).build_with(gm, |builder| {
            builder
                .private_gm(Some(private))
                .use_message_redirect(true)
                .force_confidential_external_memory(true)
                .support_gpa_pinning(true)
                .force_gpa_pinning(true)
                .channel_unstick_delay(None)
        });
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.initiate_contact(
            protocol::Version::Copper,
            protocol::FeatureFlags::new()
                .with_confidential_channels(true)
                .with_gpa_pinning(true),
            true,
            false,
        );
        let version: protocol::VersionResponse2 = env.get_response().await;
        assert!(protocol::FeatureFlags::from_bits(version.supported_features).gpa_pinning());
        env.synic.send_message_trusted(protocol::RequestOffers {});
        let offer: protocol::OfferChannel = env.get_response().await;
        assert!(offer.flags.confidential_external_memory());
        assert!(offer.flags.require_pinned_external_memory());
        env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
        env.gpadl(1, 42, &mut channel).await;
        env.synic.send_message_trusted(protocol::OpenChannel {
            channel_id: ChannelId(1),
            open_id: 0,
            ring_buffer_gpadl_id: GpadlId(42),
            target_vp: 0,
            downstream_ring_buffer_page_offset: 0,
            user_data: Default::default(),
        });
        let ChannelRequest::Open(rpc) = channel.next_request().await else {
            panic!("expected open");
        };
        assert!(rpc.input().use_confidential_ring);
        assert!(rpc.input().use_confidential_external_memory);
        assert!(rpc.input().is_external_memory_pinned);
        let mut value = [0];
        channel
            ._resources
            .guest_memory(rpc.input())
            .read_at(0, &mut value)
            .unwrap();
        assert_eq!(value, [0x22]);
        rpc.complete(true);
        let response: protocol::OpenResult = env.get_response().await;
        assert_eq!(response.status, 0);
    })
    .await;
}

// Test: Send a VTL2 contact to the primary server and forward it to a separate VTL2 server.
// Expected: The secondary negotiates its own message port and offers channels from its offset namespace.
#[async_test]
async fn multiclient_contact_is_forwarded_to_the_requested_vtl(driver: DefaultDriver) {
    bounded(async {
        let (send, receive) = mesh::channel();
        let primary = TestEnvBuilder::new(driver.clone())
            .build_with(GuestMemory::empty(), |builder| {
                builder.external_server(Some(send))
            });
        let mut secondary =
            TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| {
                builder
                    .vtl(Vtl::Vtl2)
                    .enable_mnf(false)
                    .external_requests(Some(receive))
                    .enable_channel_id_offset(true)
            });
        let _channel = secondary.offer(1, false).await;
        primary.vmbus.start();
        secondary.vmbus.start();
        primary.synic.send_message(protocol::InitiateContact {
            version_requested: protocol::Version::Copper as u32,
            target_message_vp: 0,
            interrupt_page_or_target_info: protocol::TargetInfo::new()
                .with_sint(2)
                .with_vtl(2)
                .into(),
            child_to_parent_monitor_page_gpa: 0,
            parent_to_child_monitor_page_gpa: 0,
        });
        let response: protocol::VersionResponse2 = secondary.get_response().await;
        assert_eq!(response.version_response.version_supported, 1);
        assert_eq!(
            response.version_response.selected_version_or_connection_id,
            0x0080_0024
        );
        secondary.synic.send_message(protocol::RequestOffers {});
        let offer: protocol::OfferChannel = secondary.get_response().await;
        assert_eq!(offer.channel_id, ChannelId(1025));
        secondary
            .expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
    })
    .await;
}

// Test: Offer while stopped with compatibility delivery and a ready port, force-reset, and shut down.
// Expected: The stopped offer is delivered, reset allows a new connection, and shutdown makes control fail.
#[async_test]
async fn stopped_delivery_force_reset_and_shutdown_obey_the_control_contract(
    driver: DefaultDriver,
) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver)
            .without_message_delays()
            .build_with(GuestMemory::empty(), |builder| {
                builder.send_messages_while_stopped(true)
            });
        env.vmbus.start();
        env.connect(0, protocol::FeatureFlags::new(), false).await;
        env.vmbus.stop().await;
        let _channel = env.offer(1, false).await;
        let offer: protocol::OfferChannel = env.get_response().await;
        assert_eq!(offer.channel_id, ChannelId(1));
        let control = env.vmbus.control();
        control.force_reset().await.unwrap();
        env.vmbus.start();
        env.initiate_contact(
            protocol::Version::Copper,
            protocol::FeatureFlags::new(),
            false,
            false,
        );
        let response: protocol::VersionResponse2 = env.get_response().await;
        assert_eq!(response.version_response.version_supported, 1);
        env.vmbus.shutdown().await;
        let error = control.force_reset().await.unwrap_err();
        assert_eq!(error.to_string(), "vmbus server is gone");
    })
    .await;
}

// Test: Open a pre-Win8 channel using the shared interrupt page, signal both directions, and close it.
// Expected: Guest bits and host callbacks are delivered and cleared; closing unregisters the host callback.
#[async_test]
async fn legacy_interrupt_page_routes_and_unregisters_channel_signals(driver: DefaultDriver) {
    bounded(async {
        let gm = GuestMemory::allocate(8192);
        let mut env = TestEnvBuilder::new(driver)
            .build_with(gm.clone(), |builder| builder.channel_unstick_delay(None));
        let host_interrupts = Arc::new(AtomicUsize::new(0));
        let count = host_interrupts.clone();
        let mut channel = env
            .offer_with_event(
                1,
                false,
                Interrupt::from_fn(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await;
        env.vmbus.start();
        env.synic.send_message(protocol::InitiateContact {
            version_requested: protocol::Version::Win7 as u32,
            target_message_vp: 0,
            interrupt_page_or_target_info: 4096,
            child_to_parent_monitor_page_gpa: 0,
            parent_to_child_monitor_page_gpa: 0,
        });
        let response: protocol::VersionResponse = env.get_response().await;
        assert_eq!(response.version_supported, 1);
        env.synic.send_message(protocol::RequestOffers {});
        env.expect_response(protocol::MessageType::OFFER_CHANNEL)
            .await;
        env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
        env.gpadl(1, 42, &mut channel).await;
        env.synic.send_message(protocol::OpenChannel {
            channel_id: ChannelId(1),
            open_id: 0,
            ring_buffer_gpadl_id: GpadlId(42),
            target_vp: 7,
            downstream_ring_buffer_page_offset: 0,
            user_data: Default::default(),
        });
        let ChannelRequest::Open(rpc) = channel.next_request().await else {
            panic!("expected open");
        };
        rpc.input().interrupt.deliver();
        rpc.complete(true);
        env.expect_response(protocol::MessageType::OPEN_CHANNEL_RESULT)
            .await;
        let mut bits = [0; 8];
        gm.read_at(4096, &mut bits).unwrap();
        assert_eq!(u64::from_le_bytes(bits), 2);
        assert_eq!(env.synic.guest_interrupts.load(Ordering::SeqCst), 1);

        let shared = env
            .synic
            .inner
            .lock()
            .event_ports
            .iter()
            .find(|(id, _)| *id == SHARED_EVENT_CONNECTION_ID)
            .unwrap()
            .1
            .clone();
        gm.write_at(4096 + 2048, &2u64.to_le_bytes()).unwrap();
        shared.handle_event(0);
        assert_eq!(host_interrupts.load(Ordering::SeqCst), 1);
        gm.read_at(4096 + 2048, &mut bits).unwrap();
        assert_eq!(bits, [0; 8]);
        env.synic.send_message(protocol::CloseChannel {
            channel_id: ChannelId(1),
        });
        let ChannelRequest::Close(rpc) = channel.next_request().await else {
            panic!("expected close");
        };
        rpc.complete(());
        gm.write_at(4096 + 2048, &2u64.to_le_bytes()).unwrap();
        shared.handle_event(0);
        assert_eq!(host_interrupts.load(Ordering::SeqCst), 1);
        gm.read_at(4096 + 2048, &mut bits).unwrap();
        assert_eq!(bits, [0; 8]);
    })
    .await;
}

// Test: Negotiate a legacy interrupt page that is misaligned or outside guest memory.
// Expected: Legacy negotiation reports unsupported instead of accepting an unusable mapping.
#[async_test]
async fn invalid_legacy_interrupt_pages_fail_negotiation(driver: DefaultDriver) {
    bounded(async {
        for address in [1, 8192] {
            let mut env = TestEnvBuilder::new(driver.clone())
                .build_with(GuestMemory::allocate(4096), std::convert::identity);
            env.vmbus.start();
            env.synic.send_message(protocol::InitiateContact {
                version_requested: protocol::Version::Win7 as u32,
                target_message_vp: 0,
                interrupt_page_or_target_info: address,
                child_to_parent_monitor_page_gpa: 0,
                parent_to_child_monitor_page_gpa: 0,
            });
            let response: protocol::VersionResponse = env.get_response().await;
            assert_eq!(response.version_supported, 0);
            assert_eq!(response.selected_version_or_connection_id, 0);
        }
    })
    .await;
}

// Test: Restore an open channel with a proxy that either accepts or rejects its saved state.
// Expected: The proxy gets the channel and GPADL data; only an accepted restore reaches startup and cache clear.
#[async_test]
async fn proxy_acknowledgement_controls_restore_and_startup_cache_clear(driver: DefaultDriver) {
    bounded(async {
        let gm = GuestMemory::allocate(4 * 4096);
        let mut env = TestEnvBuilder::new(driver.clone())
            .build_with(gm.clone(), |builder| builder.channel_unstick_delay(None));
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        open_ring(&mut env, &mut channel).await;
        env.vmbus.stop().await;
        let saved = env.vmbus.save().await;
        for rejected in [false, true] {
            let (send, mut receive) = mesh::channel();
            let restored = TestEnvBuilder::new(driver.clone()).build_with(gm.clone(), |builder| {
                builder
                    .saved_state_notify(Some(send))
                    .channel_unstick_delay(None)
            });
            let channel = restored.offer(1, false).await;
            let proxy = async {
                let SavedStateRequest::Set(rpc) = receive.next().await.unwrap() else {
                    panic!("expected saved state");
                };
                let data = channels::SavedStateData::from((**rpc.input()).clone());
                let guid = Guid {
                    data1: 1,
                    ..Guid::ZERO
                };
                let key = OfferKey {
                    interface_id: guid,
                    instance_id: guid,
                    subchannel_index: 0,
                };
                let channel = data.find_channel(key).unwrap();
                assert_eq!(channel.channel_id(), 1);
                assert_eq!(channel.key(), key);
                let open = channel.open_request().unwrap();
                assert_eq!(open.ring_buffer_gpadl_id, GpadlId(42));
                assert_eq!(open.downstream_ring_buffer_page_offset, 2);
                let (channels, gpadls) = data.channels_and_gpadls();
                assert_eq!(channels.len(), 1);
                assert_eq!(gpadls.len(), 1);
                assert_eq!(gpadls[0].buf, [4 * 4096, 0, 1, 2, 3]);
                if rejected {
                    rpc.handle_failable_sync(|_| anyhow::bail!("injected proxy failure"));
                } else {
                    rpc.complete(Ok(()));
                }
            };
            let snapshot = SavedState {
                server: saved.server.clone(),
                lost_synic_bug_fixed: saved.lost_synic_bug_fixed,
            };
            let (result, ()) = futures::join!(restored.vmbus.restore(snapshot), proxy);
            if rejected {
                assert!(matches!(result, Err(RestoreError::ServerError(_))));
                assert!(matches!(poll!(receive.next()), Poll::Pending));
            } else {
                result.unwrap();
                channel
                    .server_request_send
                    .call(ChannelServerRequest::Restore, true)
                    .await
                    .unwrap()
                    .unwrap();
                restored.vmbus.start();
                let SavedStateRequest::Clear(rpc) = receive.next().await.unwrap() else {
                    panic!("expected cache clear");
                };
                rpc.complete(());
                restored.vmbus.stop().await;
                assert!(matches!(poll!(receive.next()), Poll::Pending));
            }
        }
    })
    .await;
}

// Test: Restore a modern live connection into a server with a stricter rollback version limit.
// Expected: The independent restore limit rejects the snapshot with its unsupported protocol version.
#[async_test]
async fn restore_version_limit_is_independent_of_live_negotiation(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnv::new(driver.clone());
        env.vmbus.start();
        env.connect(0, protocol::FeatureFlags::new(), false).await;
        env.vmbus.stop().await;
        let saved = env.vmbus.save().await;
        let restored = TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| builder.max_restore_version(Some(MaxVersionInfo::new(protocol::Version::Win10Rs5 as u32))));
        assert!(matches!(restored.vmbus.restore(saved).await, Err(RestoreError::UnsupportedVersion(version)) if version == protocol::Version::Copper as u32));
    }).await;
}

// Test: Retarget an open channel and have the device reject the change.
// Expected: The interrupt target is updated before device work, and the guest receives the device's status.
#[async_test]
async fn channel_retarget_updates_the_interrupt_before_notifying_the_device(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| {
            builder.channel_unstick_delay(None)
        });
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        env.open_channel(1, 42, &mut channel, |_| {}).await;
        env.synic.send_message(protocol::ModifyChannel {
            channel_id: ChannelId(1),
            target_vp: 7,
        });
        let ChannelRequest::Modify(rpc) = channel.next_request().await else {
            panic!("expected retarget");
        };
        assert!(matches!(
            rpc.input(),
            ModifyRequest::TargetVp { target_vp: 7 }
        ));
        assert_eq!(env.synic.guest_target_vps.lock().as_slice(), [0, 7]);
        rpc.complete(-42);
        let response: protocol::ModifyChannelResponse = env.get_response().await;
        assert_eq!(response.channel_id, ChannelId(1));
        assert_eq!(response.status, -42);
    })
    .await;
}

// Test: Close reserved channels with a changed VP or a changed SINT.
// Expected: Open replies use the reserved target and close acknowledgements reach the new requested target.
#[async_test]
async fn reserved_channel_responses_follow_changed_message_targets(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver)
            .without_message_delays()
            .build_with(GuestMemory::empty(), |builder| {
                builder.channel_unstick_delay(None)
            });
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        env.gpadl(1, 42, &mut channel).await;
        for (open_vp, open_sint, close_vp, close_sint) in [(1, 3, 2, 3), (3, 4, 4, 5)] {
            env.synic.send_message(protocol::OpenReservedChannel {
                channel_id: ChannelId(1),
                target_vp: open_vp,
                target_sint: open_sint,
                ring_buffer_gpadl: GpadlId(42),
                downstream_page_offset: 0,
            });
            channel
                .handle_open(|request| assert_eq!(request.open_data.target_vp, None))
                .await;
            let response: protocol::OpenResult = env.get_response().await;
            assert_eq!(response.status, 0);
            assert_eq!(
                env.synic.message_targets.lock().last(),
                Some(&(Vtl::Vtl0, open_vp, open_sint as u8))
            );
            env.synic.send_message(protocol::CloseReservedChannel {
                channel_id: ChannelId(1),
                target_vp: close_vp,
                target_sint: close_sint,
            });
            let ChannelRequest::Close(rpc) = channel.next_request().await else {
                panic!("expected close");
            };
            rpc.complete(());
            let response: protocol::CloseReservedChannelResponse = env.get_response().await;
            assert_eq!(response.channel_id, ChannelId(1));
            assert_eq!(
                env.synic.message_targets.lock().last(),
                Some(&(Vtl::Vtl0, close_vp, close_sint as u8))
            );
        }
    })
    .await;
}

// Test: Offer several public channel kinds with an explicit order that reverses interface order.
// Expected: Wire offers follow the configured order and preserve interface, pipe, and socket metadata.
#[async_test]
async fn ordered_public_offers_preserve_channel_type_wire_metadata(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| {
            builder.use_absolute_channel_order(true)
        });
        let silo = Guid::new_random();
        let mut channels = Vec::new();
        for (index, channel_type) in [
            vmbus_channel::bus::ChannelType::Device { pipe_packets: true },
            vmbus_channel::bus::ChannelType::Interface {
                user_defined: [0x5a; 120].into(),
            },
            vmbus_channel::bus::ChannelType::HvSocket {
                is_connect: true,
                is_for_container: true,
                silo_id: silo,
            },
            vmbus_channel::bus::ChannelType::Pipe {
                message_mode: false,
                user_defined: [0xa5; 112].into(),
                pipe_flags: protocol::PipeFlags::new().with_gpa_direct(true),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let id = index as u32 + 1;
            let guid = Guid {
                data1: id,
                ..Guid::ZERO
            };
            channels.push(
                env.offer_params(
                    OfferParams {
                        interface_name: format!("kind-{id}"),
                        interface_id: guid,
                        instance_id: guid,
                        channel_type,
                        offer_order: Some(5 - u64::from(id)),
                        ..Default::default()
                    },
                    Interrupt::null(),
                )
                .await,
            );
        }
        env.vmbus.start();
        env.initiate_contact(
            protocol::Version::Copper,
            protocol::FeatureFlags::new(),
            false,
            false,
        );
        env.expect_response(protocol::MessageType::VERSION_RESPONSE)
            .await;
        env.synic.send_message(protocol::RequestOffers {});
        for expected in [4, 3, 2, 1] {
            let offer: protocol::OfferChannel = env.get_response().await;
            assert_eq!(offer.instance_id.data1, expected);
            match expected {
                1 => {
                    assert!(offer.flags.named_pipe_mode());
                    assert_eq!(
                        offer.user_defined.as_pipe_params().pipe_type,
                        protocol::PipeType::MESSAGE
                    );
                }
                2 => {
                    assert!(offer.flags.enumerate_device_interface());
                    assert_eq!(offer.user_defined.as_bytes(), [0x5a; 120]);
                }
                3 => {
                    assert!(offer.flags.tlnpi_provider());
                    let params = offer.user_defined.as_hvsock_params();
                    assert_eq!(params.pipe_type, protocol::PipeType::BYTE);
                    assert_eq!(params.is_for_guest_accept, 1);
                    assert_eq!(params.is_for_guest_container, 1);
                    assert_eq!(params.silo_id.get(), silo);
                }
                4 => {
                    let params = offer.user_defined.as_pipe_params();
                    assert_eq!(params.pipe_type, protocol::PipeType::BYTE);
                    assert!(params.flags.gpa_direct());
                    assert_eq!(params.user_defined.as_bytes(), [0xa5; 112]);
                }
                _ => unreachable!(),
            }
        }
        env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
    })
    .await;
}

// Test: Ask to change monitor pages while a live channel is using monitored notifications.
// Expected: The guest receives failure and the SynIC retains the original monitor-page mapping.
#[async_test]
async fn active_monitored_channels_prevent_monitor_page_replacement(driver: DefaultDriver) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| {
            builder.channel_unstick_delay(None)
        });
        let mut channel = env
            .offer_params(
                OfferParams {
                    interface_name: "monitored".into(),
                    interface_id: Guid::new_random(),
                    instance_id: Guid::new_random(),
                    mnf_interrupt_latency: Some(Duration::from_micros(100)),
                    ..Default::default()
                },
                Interrupt::null(),
            )
            .await;
        env.vmbus.start();
        env.initiate_contact(
            protocol::Version::Copper,
            protocol::FeatureFlags::new().with_modify_connection(true),
            false,
            true,
        );
        env.expect_response(protocol::MessageType::VERSION_RESPONSE)
            .await;
        env.synic.send_message(protocol::RequestOffers {});
        let offer: protocol::OfferChannel = env.get_response().await;
        assert_eq!(offer.monitor_allocated, 1);
        env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
            .await;
        env.open_channel(1, 42, &mut channel, |_| {}).await;
        env.synic.send_message(protocol::ModifyConnection {
            child_to_parent_monitor_page_gpa: 0x5000,
            parent_to_child_monitor_page_gpa: 0x6000,
        });
        let response: protocol::ModifyConnectionResponse = env.get_response().await;
        assert_eq!(
            response.connection_state,
            protocol::ConnectionState::FAILED_UNKNOWN_FAILURE
        );
        assert_eq!(
            env.synic.inner.lock().monitor_page,
            Some(MonitorPageGpas {
                child_to_parent: 0x123f000,
                parent_to_child: 0x321f000
            })
        );
    })
    .await;
}

// Test: Contact a nonstandard SINT, including failure to create its reply port.
// Expected: Rejection is sent to the requested target when possible; either outcome permits a normal retry.
#[async_test]
async fn unsupported_multiclient_target_replies_do_not_poison_negotiation(driver: DefaultDriver) {
    bounded(async {
        for port_fails in [false, true] {
            let mut env = TestEnvBuilder::new(driver.clone())
                .without_message_delays()
                .build();
            env.vmbus.start();
            if port_fails {
                env.synic.fail_next_guest_message_port(5, 3);
            }
            env.synic.send_message(protocol::InitiateContact {
                version_requested: protocol::Version::Copper as u32,
                target_message_vp: 5,
                interrupt_page_or_target_info: protocol::TargetInfo::new()
                    .with_sint(3)
                    .with_vtl(0)
                    .into(),
                child_to_parent_monitor_page_gpa: 0,
                parent_to_child_monitor_page_gpa: 0,
            });
            if !port_fails {
                let response: protocol::VersionResponse = env.get_response().await;
                assert_eq!(response.version_supported, 0);
                assert_eq!(
                    env.synic.message_targets.lock().last(),
                    Some(&(Vtl::Vtl0, 5, 3))
                );
            }
            env.initiate_contact(
                protocol::Version::Copper,
                protocol::FeatureFlags::new(),
                false,
                false,
            );
            let response: protocol::VersionResponse2 = env.get_response().await;
            assert_eq!(response.version_response.version_supported, 1);
            env.synic.send_message(protocol::RequestOffers {});
            env.expect_response(protocol::MessageType::ALL_OFFERS_DELIVERED)
                .await;
        }
    })
    .await;
}

// Test: Fail an interrupt-port retarget before the device is notified, then retry.
// Expected: Failure preserves the old target, skips device work, and permits a later successful retarget.
#[async_test]
async fn failed_interrupt_retarget_does_not_notify_the_device_or_block_retry(
    driver: DefaultDriver,
) {
    bounded(async {
        let mut env = TestEnvBuilder::new(driver).build_with(GuestMemory::empty(), |builder| {
            builder.channel_unstick_delay(None)
        });
        let mut channel = env.offer(1, false).await;
        env.vmbus.start();
        env.connect(1, protocol::FeatureFlags::new(), false).await;
        env.open_channel(1, 42, &mut channel, |_| {}).await;
        env.synic
            .fail_next_event_retarget
            .store(true, Ordering::SeqCst);
        env.synic.send_message(protocol::ModifyChannel {
            channel_id: ChannelId(1),
            target_vp: 7,
        });
        let response: protocol::ModifyChannelResponse = env.get_response().await;
        assert_eq!(response.channel_id, ChannelId(1));
        assert_eq!(response.status, protocol::STATUS_UNSUCCESSFUL);
        assert_eq!(env.synic.guest_target_vps.lock().as_slice(), [0]);
        assert!(matches!(poll!(channel.request_recv.next()), Poll::Pending));
        env.synic.send_message(protocol::ModifyChannel {
            channel_id: ChannelId(1),
            target_vp: 9,
        });
        let ChannelRequest::Modify(rpc) = channel.next_request().await else {
            panic!("expected retry");
        };
        assert!(matches!(
            rpc.input(),
            ModifyRequest::TargetVp { target_vp: 9 }
        ));
        assert_eq!(env.synic.guest_target_vps.lock().as_slice(), [0, 9]);
        rpc.complete(0);
        let response: protocol::ModifyChannelResponse = env.get_response().await;
        assert_eq!(response.status, 0);
    })
    .await;
}
