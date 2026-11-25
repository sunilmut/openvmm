// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Modify through the public access handle, then unload the connection.
// Expected: Default monitor GPAs are zero on the wire, the host's status is
//       preserved, and unload completes only after its protocol response.
#[async_test]
async fn public_modify_and_unload_use_the_negotiated_connection(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    server.connect(&mut client).await;
    let modify = client.access().modify(ModifyConnectionRequest::default());
    let host = async {
        check_message(
            server.next().await.unwrap(),
            protocol::ModifyConnection {
                child_to_parent_monitor_page_gpa: 0,
                parent_to_child_monitor_page_gpa: 0,
            },
        );
        server.send(in_msg(
            MessageType::MODIFY_CONNECTION_RESPONSE,
            protocol::ModifyConnectionResponse {
                connection_state: ConnectionState::FAILED_LOW_RESOURCES,
            },
        ));
    };
    assert_eq!(
        (modify, host).join().await.0,
        ConnectionState::FAILED_LOW_RESOURCES
    );
    let host = async {
        check_message(server.next().await.unwrap(), protocol::Unload {});
        server.send(in_msg(
            MessageType::UNLOAD_COMPLETE,
            protocol::UnloadComplete {},
        ));
    };
    (client.unload(), host).join().await;
}

fn saved_channel(id: u32, state: saved_state::ChannelState) -> saved_state::Channel {
    saved_state::Channel {
        id,
        state,
        offer: protocol::OfferChannel {
            channel_id: ChannelId(id),
            interface_id: Guid::new_random(),
            instance_id: Guid::new_random(),
            ..FromZeros::new_zeroed()
        }
        .into(),
    }
}

fn snapshot(channels: Vec<saved_state::Channel>, gpadls: Vec<saved_state::Gpadl>) -> SavedState {
    SavedState {
        client_state: saved_state::ClientState::Connected {
            version: Version::Copper as u32,
            feature_flags: SUPPORTED_FEATURE_FLAGS.into(),
        },
        channels,
        gpadls,
        pending_messages: Vec::new(),
    }
}

// Test: Restore malformed public snapshots with unsupported negotiation or GPADLs.
// Expected: Restore rejects unsupported versions/features, unknown channels,
//       duplicate GPADLs, and oversized queued messages with typed errors.
#[async_test]
async fn restore_rejects_malformed_snapshot_inputs(driver: DefaultDriver) {
    for case in 0..5 {
        let (_server, mut client) = test_init(&driver);
        client.stop().await;
        let mut saved = snapshot(Vec::new(), Vec::new());
        match case {
            0 => {
                saved.client_state = saved_state::ClientState::Connected {
                    version: 0xdead,
                    feature_flags: 0,
                }
            }
            1 => {
                saved.client_state = saved_state::ClientState::Connected {
                    version: Version::Copper as u32,
                    feature_flags: u32::MAX,
                }
            }
            2 => saved.gpadls.push(saved_state::Gpadl {
                gpadl_id: 1,
                channel_id: 99,
                state: saved_state::GpadlState::Created,
            }),
            3 => {
                saved
                    .channels
                    .push(saved_channel(7, saved_state::ChannelState::Offered));
                saved.gpadls = vec![
                    saved_state::Gpadl {
                        gpadl_id: 1,
                        channel_id: 7,
                        state: saved_state::GpadlState::Created,
                    };
                    2
                ];
            }
            4 => saved.pending_messages.push(saved_state::PendingMessage {
                data: vec![0; protocol::MAX_MESSAGE_SIZE + 1],
            }),
            _ => unreachable!(),
        }
        let error = client.restore(saved).await.unwrap_err();
        match (case, error) {
            (0, RestoreError::UnsupportedVersion(0xdead))
            | (1, RestoreError::UnsupportedFeatureFlags(u32::MAX))
            | (2, RestoreError::GpadlForUnknownChannelId(99))
            | (3, RestoreError::DuplicateGpadlId(1))
            | (4, RestoreError::InvalidPendingMessage(_)) => {}
            (_, error) => panic!("unexpected restore failure: {error}"),
        }
    }
}

// Test: Leave a restored opened channel unclaimed with created and tearing-down GPADLs.
// Expected: Post-restore queues Close and the necessary teardown, replays a
//       pending message, and accepts completions for both saved GPADLs.
#[async_test]
async fn post_restore_closes_unclaimed_channels_and_drains_saved_gpadls(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    client.stop().await;
    let mut saved = snapshot(
        vec![saved_channel(7, saved_state::ChannelState::Opened)],
        vec![
            saved_state::Gpadl {
                gpadl_id: 11,
                channel_id: 7,
                state: saved_state::GpadlState::Created,
            },
            saved_state::Gpadl {
                gpadl_id: 12,
                channel_id: 7,
                state: saved_state::GpadlState::TearingDown,
            },
        ],
    );
    saved.pending_messages.push(saved_state::PendingMessage {
        data: OutgoingMessage::new(&protocol::GpadlTeardown {
            channel_id: ChannelId(7),
            gpadl_id: GpadlId(12),
        })
        .data()
        .to_vec(),
    });
    let connection = client.restore(saved).await.unwrap().unwrap();
    assert_eq!(connection.offers.len(), 1);
    client.post_restore().await;
    client.start();
    check_message(
        server.next().await.unwrap(),
        protocol::GpadlTeardown {
            channel_id: ChannelId(7),
            gpadl_id: GpadlId(12),
        },
    );
    check_message(
        server.next().await.unwrap(),
        protocol::CloseChannel {
            channel_id: ChannelId(7),
        },
    );
    check_message(
        server.next().await.unwrap(),
        protocol::GpadlTeardown {
            channel_id: ChannelId(7),
            gpadl_id: GpadlId(11),
        },
    );
    for id in [11, 12] {
        server.send(in_msg(
            MessageType::GPADL_TORNDOWN,
            protocol::GpadlTorndown {
                gpadl_id: GpadlId(id),
            },
        ));
    }
    server.stop_client(&mut client).await;
}

// Test: Claim restored channels with invalid, conflicting, and valid event flags.
// Expected: Invalid requests fail without consuming the channel; valid claims
//       retain their flags, and already claimed channels reject another claim.
#[async_test]
async fn restored_channel_claims_validate_event_flags_and_allow_retry(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    client.stop().await;
    let connection = client
        .restore(snapshot(
            vec![
                saved_channel(7, saved_state::ChannelState::Opened),
                saved_channel(8, saved_state::ChannelState::Opened),
            ],
            Vec::new(),
        ))
        .await
        .unwrap()
        .unwrap();
    client.start();
    let first = &connection.offers[0];
    let second = &connection.offers[1];
    for (incoming_event, redirected_event_flag) in [
        (Some(Event::new()), None),
        (None, Some(1)),
        (Some(Event::new()), Some(0)),
        (Some(Event::new()), Some(2048)),
    ] {
        assert!(
            first
                .request_send
                .call_failable(
                    ChannelRequest::Restore,
                    RestoreRequest {
                        incoming_event,
                        redirected_event_flag,
                        connection_id: 5,
                    }
                )
                .await
                .is_err()
        );
    }
    let claim = || RestoreRequest {
        incoming_event: Some(Event::new()),
        redirected_event_flag: Some(1),
        connection_id: 5,
    };
    let result = first
        .request_send
        .call_failable(ChannelRequest::Restore, claim())
        .await
        .unwrap();
    assert_eq!(result.redirected_event_flag, Some(1));
    assert!(
        second
            .request_send
            .call_failable(ChannelRequest::Restore, claim())
            .await
            .is_err()
    );
    assert!(
        first
            .request_send
            .call_failable(ChannelRequest::Restore, claim())
            .await
            .is_err()
    );
    let result = second
        .request_send
        .call_failable(
            ChannelRequest::Restore,
            RestoreRequest {
                incoming_event: None,
                redirected_event_flag: None,
                connection_id: 6,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.redirected_event_flag, None);
    server.stop_client(&mut client).await;
    client.post_restore().await;
}

// Test: Request a connection modification while another modification is pending.
// Expected: The duplicate fails locally, while the first caller receives its
//       host response and no second ModifyConnection is sent.
#[async_test]
async fn concurrent_connection_modification_rejects_only_the_duplicate(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    server.connect(&mut client).await;
    let access = client.access();
    let mut first = pin!(access.modify(ModifyConnectionRequest::default()));
    assert!(first.as_mut().now_or_never().is_none());
    check_message(
        server.next().await.unwrap(),
        protocol::ModifyConnection {
            child_to_parent_monitor_page_gpa: 0,
            parent_to_child_monitor_page_gpa: 0,
        },
    );
    assert_eq!(
        access.modify(ModifyConnectionRequest::default()).await,
        ConnectionState::FAILED_UNKNOWN_FAILURE,
    );
    server.send(in_msg(
        MessageType::MODIFY_CONNECTION_RESPONSE,
        protocol::ModifyConnectionResponse {
            connection_state: ConnectionState::SUCCESSFUL,
        },
    ));
    assert_eq!(first.await, ConnectionState::SUCCESSFUL);
    assert!(server.next().now_or_never().is_none());
}

async fn connect_without_features(
    server: &mut TestServer,
    client: &mut VmbusClient,
) -> ConnectResult {
    let peer = async {
        let contact = server.next().await.unwrap();
        assert!(matches!(
            Message::parse(contact.data(), None).unwrap(),
            Message::InitiateContact2(..)
        ));
        server.send(in_msg(
            MessageType::VERSION_RESPONSE,
            protocol::VersionResponse2 {
                version_response: protocol::VersionResponse {
                    version_supported: 1,
                    connection_state: ConnectionState::SUCCESSFUL,
                    ..FromZeros::new_zeroed()
                },
                supported_features: 0,
            },
        ));
        check_message(server.next().await.unwrap(), protocol::RequestOffers {});
        server.send(in_msg(
            MessageType::OFFER_CHANNEL,
            protocol::OfferChannel {
                channel_id: ChannelId(7),
                interface_id: Guid::new_random(),
                instance_id: Guid::new_random(),
                ..FromZeros::new_zeroed()
            },
        ));
        server.send(in_msg(MessageType::ALL_OFFERS_DELIVERED, [0]));
    };
    (client.connect(0, None, Guid::ZERO), peer)
        .join()
        .await
        .0
        .unwrap()
}

fn legacy_open() -> OpenRequest {
    OpenRequest {
        open_data: OpenData {
            ring_gpadl_id: GpadlId(17),
            ring_offset: 2,
            target_vp: Some(3),
            event_flag: 7,
            connection_id: 19,
            user_data: UserDefinedData::default(),
        },
        incoming_event: None,
        use_vtl2_connection_id: false,
    }
}

// Test: Have the host reject a supported connection, then retry with a good host.
// Expected: The caller receives the host's exact failure status, and a later
//       connection succeeds rather than being left in an invalid state.
#[async_test]
async fn rejected_connection_preserves_host_status_and_allows_retry(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let peer = async {
        let contact = server.next().await.unwrap();
        assert!(matches!(
            Message::parse(contact.data(), None).unwrap(),
            Message::InitiateContact2(..)
        ));
        server.send(in_msg(
            MessageType::VERSION_RESPONSE,
            protocol::VersionResponse2 {
                version_response: protocol::VersionResponse {
                    version_supported: 1,
                    connection_state: ConnectionState::FAILED_LOW_RESOURCES,
                    ..FromZeros::new_zeroed()
                },
                supported_features: 0,
            },
        ));
    };
    let (result, ()) = (client.connect(0, None, Guid::ZERO), peer).join().await;
    assert!(matches!(
        result,
        Err(ConnectError::FailedToConnect(
            ConnectionState::FAILED_LOW_RESOURCES
        ))
    ));
    let connection = server.connect(&mut client).await;
    assert_eq!(connection.version.version, Version::Copper);
}

// Test: Have the host reject both supported protocol versions.
// Expected: Negotiation falls back from Copper to Iron and returns
//       NoSupportedVersions instead of retrying forever.
#[async_test]
async fn unsupported_host_versions_terminate_negotiation(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let peer = async {
        for expected in [Version::Copper, Version::Iron] {
            let contact = server.next().await.unwrap();
            let version = match Message::parse(contact.data(), None).unwrap() {
                Message::InitiateContact2(msg, _) => msg.initiate_contact.version_requested,
                Message::InitiateContact(msg, _) => msg.version_requested,
                other => panic!("expected contact, got {other:?}"),
            };
            assert_eq!(version, expected as u32);
            server.send(in_msg(
                MessageType::VERSION_RESPONSE,
                protocol::VersionResponse {
                    version_supported: 0,
                    connection_state: ConnectionState::SUCCESSFUL,
                    ..FromZeros::new_zeroed()
                },
            ));
        }
    };
    let (result, ()) = (client.connect(0, None, Guid::ZERO), peer).join().await;
    assert!(matches!(result, Err(ConnectError::NoSupportedVersions)));
}

// Test: Open a channel on a host without optional connection or interrupt features.
// Expected: Unsupported options fail without host messages; a compatible retry
//       opens using the legacy format, and duplicate open and restore fail.
#[async_test]
async fn legacy_host_rejects_unsupported_options_and_accepts_compatible_retry(
    driver: DefaultDriver,
) {
    let (mut server, mut client) = test_init(&driver);
    let connection = connect_without_features(&mut server, &mut client).await;
    let offer = &connection.offers[0];
    assert_eq!(
        client
            .access()
            .modify(ModifyConnectionRequest::default())
            .await,
        ConnectionState::FAILED_UNKNOWN_FAILURE
    );
    let mut request = legacy_open();
    request.open_data.event_flag = 8;
    assert!(
        offer
            .request_send
            .call_failable(ChannelRequest::Open, request)
            .await
            .is_err()
    );
    let mut request = legacy_open();
    request.use_vtl2_connection_id = true;
    assert!(
        offer
            .request_send
            .call_failable(ChannelRequest::Open, request)
            .await
            .is_err()
    );
    let mut request = legacy_open();
    request.incoming_event = Some(Event::new());
    assert!(
        offer
            .request_send
            .call_failable(ChannelRequest::Open, request)
            .await
            .is_err()
    );
    let open = offer
        .request_send
        .call_failable(ChannelRequest::Open, legacy_open());
    check_message(
        server.next().await.unwrap(),
        protocol::OpenChannel {
            channel_id: ChannelId(7),
            open_id: 0,
            ring_buffer_gpadl_id: GpadlId(17),
            target_vp: 3,
            downstream_ring_buffer_page_offset: 2,
            user_data: UserDefinedData::default(),
        },
    );
    server.send(in_msg(
        MessageType::OPEN_CHANNEL_RESULT,
        protocol::OpenResult {
            channel_id: ChannelId(7),
            open_id: 0,
            status: 0,
        },
    ));
    assert_eq!(open.await.unwrap().redirected_event_flag, None);
    assert!(
        offer
            .request_send
            .call_failable(ChannelRequest::Open, legacy_open())
            .await
            .is_err()
    );
    assert!(
        offer
            .request_send
            .call_failable(
                ChannelRequest::Restore,
                RestoreRequest {
                    incoming_event: None,
                    redirected_event_flag: None,
                    connection_id: 19,
                }
            )
            .await
            .is_err()
    );
    offer
        .request_send
        .call(ChannelRequest::Close, ())
        .await
        .unwrap();
    check_message(
        server.next().await.unwrap(),
        protocol::CloseChannel {
            channel_id: ChannelId(7),
        },
    );
    offer
        .request_send
        .call(ChannelRequest::Close, ())
        .await
        .unwrap();
    client.stop().await;
    assert!(server.next().now_or_never().is_none());
}

// Test: Send a multi-message GPADL and request its teardown twice before completion.
// Expected: Every GPA is preserved across wire fragments; both teardown callers
//       complete after a single host teardown and a single completion message.
#[async_test]
async fn large_gpadl_preserves_fragments_and_coalesces_teardown_waiters(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let connection = server.get_channels(&mut client, 1).await;
    let offer = &connection.offers[0];
    assert!(
        offer
            .request_send
            .call(ChannelRequest::TeardownGpadl, GpadlId(999))
            .await
            .is_err()
    );
    let mut buf = vec![100 * vmbus_ring::PAGE_SIZE as u64];
    buf.extend(1..=100);
    let create = offer.request_send.call_failable(
        ChannelRequest::Gpadl,
        GpadlRequest {
            id: GpadlId(17),
            count: 1,
            buf: buf.clone(),
        },
    );
    let header_values = protocol::GpadlHeader::MAX_DATA_VALUES;
    check_message_with_data(
        server.next().await.unwrap(),
        protocol::GpadlHeader {
            channel_id: ChannelId(0),
            gpadl_id: GpadlId(17),
            len: (buf.len() * 8) as u16,
            count: 1,
        },
        buf[..header_values].as_bytes(),
    );
    for chunk in buf[header_values..].chunks(protocol::GpadlBody::MAX_DATA_VALUES) {
        check_message_with_data(
            server.next().await.unwrap(),
            protocol::GpadlBody {
                rsvd: 0,
                gpadl_id: GpadlId(17),
            },
            chunk.as_bytes(),
        );
    }
    server.send(in_msg(
        MessageType::GPADL_CREATED,
        protocol::GpadlCreated {
            channel_id: ChannelId(0),
            gpadl_id: GpadlId(17),
            status: 0,
        },
    ));
    create.await.unwrap();
    let first = offer
        .request_send
        .call(ChannelRequest::TeardownGpadl, GpadlId(17));
    check_message(
        server.next().await.unwrap(),
        protocol::GpadlTeardown {
            channel_id: ChannelId(0),
            gpadl_id: GpadlId(17),
        },
    );
    let second = offer
        .request_send
        .call(ChannelRequest::TeardownGpadl, GpadlId(17));
    // A close RPC on the same stream is a barrier for the second teardown.
    offer
        .request_send
        .call(ChannelRequest::Close, ())
        .await
        .unwrap();
    assert!(server.next().now_or_never().is_none());
    server.send(in_msg(
        MessageType::GPADL_TORNDOWN,
        protocol::GpadlTorndown {
            gpadl_id: GpadlId(17),
        },
    ));
    first.await.unwrap();
    second.await.unwrap();
}

// Test: Create GPADLs on two channels and return their host results in reverse order.
// Expected: Failure completes only its matching request; the other stays pending
//       until its own successful response arrives.
#[async_test]
async fn concurrent_gpadl_results_remain_bound_to_their_channel_and_handle(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let connection = server.get_channels(&mut client, 2).await;
    let request = |id| GpadlRequest {
        id: GpadlId(id),
        count: 1,
        buf: vec![vmbus_ring::PAGE_SIZE as u64, 42],
    };
    let mut first = pin!(
        connection.offers[0]
            .request_send
            .call_failable(ChannelRequest::Gpadl, request(17))
    );
    check_message_with_data(
        server.next().await.unwrap(),
        protocol::GpadlHeader {
            channel_id: ChannelId(0),
            gpadl_id: GpadlId(17),
            len: 16,
            count: 1,
        },
        request(17).buf.as_bytes(),
    );
    let second = connection.offers[1]
        .request_send
        .call_failable(ChannelRequest::Gpadl, request(18));
    check_message_with_data(
        server.next().await.unwrap(),
        protocol::GpadlHeader {
            channel_id: ChannelId(1),
            gpadl_id: GpadlId(18),
            len: 16,
            count: 1,
        },
        request(18).buf.as_bytes(),
    );
    server.send(in_msg(
        MessageType::GPADL_CREATED,
        protocol::GpadlCreated {
            channel_id: ChannelId(1),
            gpadl_id: GpadlId(18),
            status: protocol::STATUS_UNSUCCESSFUL,
        },
    ));
    assert!(second.await.is_err());
    assert!(first.as_mut().now_or_never().is_none());
    server.send(in_msg(
        MessageType::GPADL_CREATED,
        protocol::GpadlCreated {
            channel_id: ChannelId(0),
            gpadl_id: GpadlId(17),
            status: 0,
        },
    ));
    first.await.unwrap();
}
