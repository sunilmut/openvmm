// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use protocol::*;
use test_with_tracing::test;
use zerocopy::FromBytes;

fn version(version: Version, feature_flags: FeatureFlags) -> Option<VersionInfo> {
    Some(VersionInfo {
        version,
        feature_flags,
    })
}

// Test: Parse version constraints, including numeric boundaries and malformed input.
// Expected: Valid components retain all 16 bits; invalid text returns an error
//       identifying the original input instead of silently choosing a version.
#[test]
fn version_constraints_validate_both_components() {
    for (text, expected) in [
        ("0.13", 13),
        ("5.3", 0x0005_0003),
        ("65535.65535", u32::MAX),
        ("0.0", 0),
    ] {
        assert_eq!(parse_vmbus_version(text).unwrap(), expected);
    }
    for text in [
        "", "5", ".3", "5.", "5.3.1", "-1.0", "0.-1", "65536.0", "0.65536", " 5.3", "5.3 ",
    ] {
        assert_eq!(
            parse_vmbus_version(text).unwrap_err(),
            format!("invalid vmbus version '{text}'")
        );
    }
}

// Test: Intersect peer feature capabilities and carry a negotiated version forward.
// Expected: Only common features survive, union preserves advertised bits, and
//       a version-only limit does not enable features that were never negotiated.
#[test]
fn negotiated_feature_constraints_preserve_capability_sets() {
    let advertised = FeatureFlags::from(0x8000_0055);
    let requested = FeatureFlags::from(0x8000_0066);
    let negotiated = advertised & requested;
    assert_eq!(negotiated.into_bits(), 0x8000_0044);
    assert!(!advertised.contains(requested));
    assert!(advertised.contains(negotiated));
    assert!(advertised.contains(FeatureFlags::new()));
    assert_eq!((advertised | requested).into_bits(), 0x8000_0077);
    let mut limited = requested;
    limited &= advertised;
    let max = MaxVersionInfo::from(VersionInfo {
        version: Version::Copper,
        feature_flags: limited,
    });
    assert_eq!(max.version, 0x0006_0000);
    assert_eq!(max.feature_flags, negotiated);
    let version_only = MaxVersionInfo::new(max.version);
    assert_eq!(version_only.version, max.version);
    assert_eq!(version_only.feature_flags.into_bits(), 0);
}

// Test: Import opaque outgoing messages at the SynIC payload-size boundary.
// Expected: Valid bytes are preserved exactly, oversized input fails, and
//       equality distinguishes payload differences as well as message length.
#[test]
fn outgoing_message_import_enforces_capacity_and_wire_equality() {
    for length in [0, HEADER_SIZE, MAX_MESSAGE_SIZE] {
        let bytes: Vec<_> = (0..length).map(|i| i as u8).collect();
        let message = OutgoingMessage::from_message(&bytes).unwrap();
        assert_eq!(message.data(), bytes);
        assert_eq!(message, OutgoingMessage::from_message(&bytes).unwrap());
        let mut changed = bytes.clone();
        if let Some(first) = changed.first_mut() {
            *first ^= 0xff;
            assert_ne!(message, OutgoingMessage::from_message(&changed).unwrap());
        }
        if length < MAX_MESSAGE_SIZE {
            changed.push(0);
            assert_ne!(message, OutgoingMessage::from_message(&changed).unwrap());
        }
    }
    let error = OutgoingMessage::from_message(&[0; MAX_MESSAGE_SIZE + 1]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "a synic message exceeds the maximum length"
    );
}

// Test: Parse channel-close packets, truncated messages and unknown message types.
// Expected: Valid payloads round-trip, truncated inputs identify the missing
//       header/body, and unsupported or disconnected messages are rejected.
#[test]
fn message_parser_distinguishes_truncation_from_unsupported_messages() {
    let message = OutgoingMessage::new(&CloseChannel {
        channel_id: ChannelId(42),
    });
    let connected = version(Version::V1, FeatureFlags::new());
    let header = MessageHeader::read_from_prefix(message.data()).unwrap().0;
    assert_eq!(header.message_type(), MessageType::CLOSE_CHANNEL);
    match Message::parse(message.data(), connected).unwrap() {
        Message::CloseChannel(close, trailing) => {
            assert_eq!(close.channel_id, ChannelId(42));
            assert!(trailing.is_empty());
        }
        other => panic!("unexpected message: {other:?}"),
    }
    for length in 0..message.data().len() {
        let expected = (length >= HEADER_SIZE).then_some(MessageType::CLOSE_CHANNEL);
        assert!(
            matches!(Message::parse(&message.data()[..length], connected), Err(ParseError::MessageTooSmall(kind)) if kind == expected)
        );
    }
    assert!(matches!(
        Message::parse(message.data(), None),
        Err(ParseError::InvalidMessageType(MessageType::CLOSE_CHANNEL))
    ));
    let unknown = MessageHeader::new(MessageType(0xffff));
    assert!(matches!(
        Message::parse(unknown.as_bytes(), connected),
        Err(ParseError::InvalidMessageType(MessageType(0xffff)))
    ));
}

// Test: Upgrade legacy contact and response packets before connection negotiation.
// Expected: Existing wire fields survive, new fields initialize to zero, and
//       packet size selects the correct response variant without a known version.
#[test]
fn negotiation_upgrades_preserve_legacy_fields_and_zero_extensions() {
    let base = InitiateContact {
        version_requested: 0x60000,
        target_message_vp: 7,
        interrupt_page_or_target_info: 0x1234,
        parent_to_child_monitor_page_gpa: 0x5000,
        child_to_parent_monitor_page_gpa: 0x6000,
    };
    let extended = InitiateContact2::from(base);
    assert_eq!(extended.initiate_contact, base);
    assert_eq!(extended.client_id, Guid::ZERO);
    for (message, is_extended) in [
        (OutgoingMessage::new(&base), false),
        (OutgoingMessage::new(&extended), true),
    ] {
        match Message::parse(message.data(), None).unwrap() {
            Message::InitiateContact2(value, rest) if is_extended => {
                assert_eq!(value, extended);
                assert!(rest.is_empty());
            }
            Message::InitiateContact(value, rest) if !is_extended => {
                assert_eq!(value, base);
                assert!(rest.is_empty());
            }
            other => panic!("unexpected contact variant: {other:?}"),
        }
    }
    let response = VersionResponse {
        version_supported: 1,
        connection_state: ConnectionState::SUCCESSFUL,
        padding: 0,
        selected_version_or_connection_id: 0x123456,
    };
    let response2 = VersionResponse2::from(response);
    let response3 = VersionResponse3::from(response2);
    assert_eq!(response3, VersionResponse3::from(response));
    assert_eq!(response2.version_response, response);
    assert_eq!(response2.supported_features, 0);
    assert_eq!(response3.parent_to_child_monitor_page_gpa, 0);
    assert_eq!(response3.child_to_parent_monitor_page_gpa, 0);
    for (message, expected_size) in [
        (
            OutgoingMessage::new(&response),
            size_of::<VersionResponse>(),
        ),
        (
            OutgoingMessage::new(&response2),
            size_of::<VersionResponse2>(),
        ),
        (
            OutgoingMessage::new(&response3),
            size_of::<VersionResponse3>(),
        ),
    ] {
        let parsed_size = match Message::parse(message.data(), None).unwrap() {
            Message::VersionResponse(_, rest) => {
                assert!(rest.is_empty());
                size_of::<VersionResponse>()
            }
            Message::VersionResponse2(_, rest) => {
                assert!(rest.is_empty());
                size_of::<VersionResponse2>()
            }
            Message::VersionResponse3(_, rest) => {
                assert!(rest.is_empty());
                size_of::<VersionResponse3>()
            }
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(parsed_size, expected_size);
    }
}

// Test: Open a channel using legacy and feature-gated signal-routing parameters.
// Expected: Extensions default to zero, negotiated features select OpenChannel2,
//       and disabling interrupts is distinct from targeting VP zero.
#[test]
fn channel_open_routing_and_parser_follow_negotiated_features() {
    let base = OpenChannel {
        channel_id: ChannelId(5),
        open_id: 17,
        ring_buffer_gpadl_id: GpadlId(9),
        target_vp: 0,
        downstream_ring_buffer_page_offset: 2,
        user_data: UserDefinedData::default(),
    };
    let mut extended = OpenChannel2::from(base);
    assert_eq!(extended.open_channel, base);
    assert_eq!(extended.connection_id, 0);
    assert_eq!(extended.event_flag, 0);
    assert_eq!(extended.flags.into_bits(), 0);
    for (vtl, expected) in [
        (hvdef::Vtl::Vtl0, 0x2005),
        (hvdef::Vtl::Vtl1, 0x12005),
        (hvdef::Vtl::Vtl2, 0x22005),
    ] {
        extended.connection_id = ConnectionId::new(5, vtl, 2).0;
        assert_eq!(extended.connection_id, expected);
    }
    assert_eq!(vp_index_if_enabled(0), Some(0));
    assert_eq!(vp_index_if_enabled(u32::MAX - 1), Some(u32::MAX - 1));
    assert_eq!(vp_index_if_enabled(VP_INDEX_DISABLE_INTERRUPT), None);
    extended.event_flag = 123;
    extended.flags = OpenChannelFlags::new().with_redirect_interrupt(true);
    let packet = OutgoingMessage::new(&extended);
    for features in [
        FeatureFlags::new().with_guest_specified_signal_parameters(true),
        FeatureFlags::new().with_channel_interrupt_redirection(true),
    ] {
        match Message::parse(packet.data(), version(Version::Copper, features)).unwrap() {
            Message::OpenChannel2(value, rest) => {
                assert_eq!(value, extended);
                assert!(rest.is_empty());
            }
            other => panic!("unexpected extended open: {other:?}"),
        }
    }
    assert!(
        matches!(Message::parse(packet.data(), version(Version::Copper, FeatureFlags::new())).unwrap(),
        Message::OpenChannel(value, rest) if value == base && rest.len() == 8)
    );
}

// Test: Access named-pipe offer parameters through the shared user-defined buffer.
// Expected: Typed changes appear at their wire offsets, payload bytes round-trip,
//       and diagnostic output distinguishes zero from nonzero buffers.
#[test]
fn pipe_offer_views_preserve_wire_layout_and_diagnostics() {
    let mut data = UserDefinedData::default();
    assert_eq!(format!("{data:?}"), "UserDefinedData([<all-zeroes>])");
    let payload: [u8; 112] = std::array::from_fn(|i| i as u8);
    {
        let pipe = data.as_pipe_params_mut();
        pipe.user_defined = PipeUserDefinedData::from(payload);
        pipe.flags = PipeFlags::new().with_gpa_direct(true);
    }
    assert_eq!(
        <[u8; 112]>::from(data.as_pipe_params().user_defined),
        payload
    );
    assert_eq!(data.as_pipe_params().flags.into_bits(), 1);
    assert_eq!(&data[4..116], &payload);
    assert_eq!(&data[116..], &1u32.to_le_bytes());
    data[4] = 0xfe;
    assert_eq!(
        <[u8; 112]>::from(data.as_pipe_params().user_defined)[0],
        0xfe
    );
    let raw: [u8; 120] = data.into();
    assert_eq!(&UserDefinedData::from(raw)[..], &raw);
    assert_eq!(<[u8; 112]>::from(PipeUserDefinedData::default()), [0; 112]);
    let diagnostic = format!("{:?}", UserDefinedData::from([0xab; 120]));
    assert_eq!(
        diagnostic,
        format!("UserDefinedData([{}])", "AB".repeat(120))
    );
}

// Test: Populate the unaligned hvsocket offer fields inside user-defined data.
// Expected: Booleans, version and silo GUID round-trip at their protocol offsets,
//       without overwriting bytes outside the hvsocket parameter structure.
#[test]
fn hvsock_offer_views_preserve_unaligned_fields_and_tail() {
    let silo = guid::guid!("01234567-89ab-cdef-0123-456789abcdef");
    for accept in [false, true] {
        for container in [false, true] {
            let mut data = UserDefinedData::from([0xa5; 120]);
            *data.as_hvsock_params_mut() =
                HvsockUserDefinedParameters::new(accept, container, silo);
            let parsed = data.as_hvsock_params();
            assert_eq!(parsed.pipe_type, PipeType::BYTE);
            assert_eq!(parsed.is_for_guest_accept, u8::from(accept));
            assert_eq!(parsed.is_for_guest_container, u8::from(container));
            assert_eq!(parsed.version.get(), HvsockParametersVersion::RS5);
            assert_eq!(parsed.silo_id.get(), silo);
            assert_eq!(&data[6..10], &1u32.to_le_bytes());
            assert!(
                data[size_of::<HvsockUserDefinedParameters>()..]
                    .iter()
                    .all(|b| *b == 0xa5)
            );
        }
    }
}

// Test: Translate hvsocket requests and connection outcomes across public APIs.
// Expected: Endpoint/service/silo identities survive conversion and only a
//       successful protocol status is treated as a successful connection.
#[test]
fn hvsock_connection_conversions_preserve_identity_and_failure_status() {
    let base = TlConnectRequest {
        endpoint_id: guid::guid!("11111111-2222-3333-4444-555555555555"),
        service_id: guid::guid!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
    };
    let mut wire = TlConnectRequest2::from(base);
    assert_eq!(wire.silo_id, Guid::ZERO);
    wire.silo_id = guid::guid!("12345678-1234-5678-90ab-cdef12345678");
    for unaware in [false, true] {
        let request = HvsockConnectRequest::from_message(wire, unaware);
        assert_eq!(request.endpoint_id, base.endpoint_id);
        assert_eq!(request.service_id, base.service_id);
        assert_eq!(request.silo_id, wire.silo_id);
        assert_eq!(request.hosted_silo_unaware, unaware);
        assert_eq!(TlConnectRequest2::from(request).as_bytes(), wire.as_bytes());
        for success in [false, true] {
            let result = HvsockConnectResult::from_request(&request, success);
            assert_eq!(result.endpoint_id, base.endpoint_id);
            assert_eq!(result.service_id, base.service_id);
            assert_eq!(result.success, success);
        }
    }

    for status in [
        STATUS_SUCCESS,
        STATUS_CONNECTION_REFUSED,
        STATUS_UNSUCCESSFUL,
        1,
    ] {
        let result = HvsockConnectResult::from(TlConnectResult {
            endpoint_id: base.endpoint_id,
            service_id: base.service_id,
            status,
        });
        assert_eq!(result.endpoint_id, base.endpoint_id);
        assert_eq!(result.service_id, base.service_id);
        assert_eq!(result.success, status == STATUS_SUCCESS);
    }
}

// Test: Encode a GPADL whose page list fills a header and a continuation message.
// Expected: Parsing preserves both IDs and every high-address PFN in order,
//       including the last PFN in a full-size continuation payload.
#[test]
fn multipart_gpadl_messages_preserve_full_page_lists() {
    let header_pfns = GpadlHeader::MAX_DATA_VALUES - 1;
    let page_count = header_pfns + GpadlBody::MAX_DATA_VALUES;
    let pfns: Vec<u64> = (0..page_count)
        .map(|index| 0x1_0000_0000 + index as u64 * 3)
        .collect();
    let mut ranges = Vec::new();
    ranges.extend_from_slice(&(page_count as u32 * 4096).to_le_bytes());
    ranges.extend_from_slice(&0u32.to_le_bytes());
    for pfn in &pfns {
        ranges.extend_from_slice(&pfn.to_le_bytes());
    }
    let split = (header_pfns + 1) * size_of::<u64>();
    let header = OutgoingMessage::with_data(
        &GpadlHeader {
            channel_id: ChannelId(37),
            gpadl_id: GpadlId(0x8765_4321),
            len: ranges.len().try_into().unwrap(),
            count: 1,
        },
        &ranges[..split],
    );
    let body = OutgoingMessage::with_data(
        &GpadlBody {
            rsvd: 0,
            gpadl_id: GpadlId(0x8765_4321),
        },
        &ranges[split..],
    );
    assert!(header.data().len() <= MAX_MESSAGE_SIZE);
    assert_eq!(body.data().len(), MAX_MESSAGE_SIZE);

    for negotiated in [Version::V1, Version::Copper] {
        let connected = version(negotiated, FeatureFlags::new());
        let mut received = Vec::new();
        match Message::parse(header.data(), connected).unwrap() {
            Message::GpadlHeader(value, data) => {
                assert_eq!(value.channel_id, ChannelId(37));
                assert_eq!(value.gpadl_id, GpadlId(0x8765_4321));
                assert_eq!(usize::from(value.len), ranges.len());
                assert_eq!(value.count, 1);
                received.extend_from_slice(data);
            }
            other => panic!("unexpected GPADL header: {other:?}"),
        }
        match Message::parse(body.data(), connected).unwrap() {
            Message::GpadlBody(value, data) => {
                assert_eq!(value.gpadl_id, GpadlId(0x8765_4321));
                assert_eq!(value.rsvd, 0);
                received.extend_from_slice(data);
            }
            other => panic!("unexpected GPADL body: {other:?}"),
        }
        assert_eq!(received, ranges);
    }
}

// Test: Parse monitor-page changes and pause/resume packets across negotiations.
// Expected: Copper and the specific capability are both required; accepted
//       packets retain complete payloads and tails, and short bodies fail.
#[test]
fn connection_control_packets_require_their_own_negotiated_capability() {
    let modify = OutgoingMessage::with_data(
        &ModifyConnection {
            parent_to_child_monitor_page_gpa: 0x1234_5678_9abc_d000,
            child_to_parent_monitor_page_gpa: 0xfedc_ba98_7654_3000,
        },
        &[0xde, 0xad],
    );
    assert_eq!(
        modify.data(),
        &[
            25, 0, 0, 0, 0, 0, 0, 0, 0, 0xd0, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0, 0x30, 0x54,
            0x76, 0x98, 0xba, 0xdc, 0xfe, 0xde, 0xad,
        ]
    );
    let packets = [
        (modify, MessageType::MODIFY_CONNECTION, false),
        (
            OutgoingMessage::with_data(
                &ModifyConnectionResponse {
                    connection_state: ConnectionState::FAILED_LOW_RESOURCES,
                },
                &[0xde, 0xad],
            ),
            MessageType::MODIFY_CONNECTION_RESPONSE,
            false,
        ),
        (
            OutgoingMessage::with_data(&Pause, &[0xde, 0xad]),
            MessageType::PAUSE,
            true,
        ),
        (
            OutgoingMessage::with_data(&PauseResponse, &[0xde, 0xad]),
            MessageType::PAUSE_RESPONSE,
            true,
        ),
        (
            OutgoingMessage::with_data(&Resume, &[0xde, 0xad]),
            MessageType::RESUME,
            true,
        ),
    ];
    let modify_only = FeatureFlags::new().with_modify_connection(true);
    let pause_only = FeatureFlags::new().with_pause_resume(true);
    for (packet, kind, needs_pause) in packets {
        for negotiated in [None, Some(Version::Iron), Some(Version::Copper)] {
            for (features, modify_enabled, pause_enabled) in [
                (FeatureFlags::new(), false, false),
                (modify_only, true, false),
                (pause_only, false, true),
                (modify_only | pause_only, true, true),
            ] {
                let connected = negotiated.and_then(|value| version(value, features));
                let accepted = negotiated == Some(Version::Copper)
                    && if needs_pause {
                        pause_enabled
                    } else {
                        modify_enabled
                    };
                let parsed = Message::parse(packet.data(), connected);
                if !accepted {
                    assert!(matches!(
                        parsed,
                        Err(ParseError::InvalidMessageType(actual)) if actual == kind
                    ));
                    continue;
                }
                let tail = match parsed.unwrap() {
                    Message::ModifyConnection(value, tail) => {
                        assert_eq!(kind, MessageType::MODIFY_CONNECTION);
                        assert_eq!(
                            value.parent_to_child_monitor_page_gpa,
                            0x1234_5678_9abc_d000
                        );
                        assert_eq!(
                            value.child_to_parent_monitor_page_gpa,
                            0xfedc_ba98_7654_3000
                        );
                        tail
                    }
                    Message::ModifyConnectionResponse(value, tail) => {
                        assert_eq!(kind, MessageType::MODIFY_CONNECTION_RESPONSE);
                        assert_eq!(
                            value.connection_state,
                            ConnectionState::FAILED_LOW_RESOURCES
                        );
                        tail
                    }
                    Message::Pause(_, tail) => {
                        assert_eq!(kind, MessageType::PAUSE);
                        tail
                    }
                    Message::PauseResponse(_, tail) => {
                        assert_eq!(kind, MessageType::PAUSE_RESPONSE);
                        tail
                    }
                    Message::Resume(_, tail) => {
                        assert_eq!(kind, MessageType::RESUME);
                        tail
                    }
                    other => panic!("unexpected control packet: {other:?}"),
                };
                assert_eq!(tail, &[0xde, 0xad]);
                let body_size = if needs_pause {
                    0
                } else if kind == MessageType::MODIFY_CONNECTION {
                    16
                } else {
                    1
                };
                for length in 8..8 + body_size {
                    assert!(matches!(
                        Message::parse(&packet.data()[..length], connected),
                        Err(ParseError::MessageTooSmall(Some(actual))) if actual == kind
                    ));
                }
            }
        }
    }
}

// Test: Decode legacy and silo-aware socket requests from independent wire bytes.
// Expected: RS5 selects the extension only when complete; earlier versions and
//       short extensions preserve legacy identities and every unconsumed byte.
#[test]
fn socket_request_size_fallback_preserves_wire_identities_and_tails() {
    let wire = [
        21, 0, 0, 0, 0, 0, 0, 0, 0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x98, 0xba, 0xdc, 0xfe, 0x54, 0x76, 0x10, 0x32, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ];
    let endpoint = guid::guid!("01234567-89ab-cdef-0123-456789abcdef");
    let service = guid::guid!("fedcba98-7654-3210-fedc-ba9876543210");
    let silo = guid::guid!("11223344-5566-7788-99aa-bbccddeeff00");
    let request = TlConnectRequest2 {
        base: TlConnectRequest {
            endpoint_id: endpoint,
            service_id: service,
        },
        silo_id: silo,
    };
    assert_eq!(OutgoingMessage::new(&request).data(), &wire);
    assert_eq!(OutgoingMessage::new(&request.base).data(), &wire[..40]);
    let mut extended = wire.to_vec();
    extended.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    for negotiated in [Version::Win10, Version::Win10Rs5, Version::Copper] {
        let connected = version(negotiated, FeatureFlags::new());
        for length in 8..40 {
            assert!(matches!(
                Message::parse(&wire[..length], connected),
                Err(ParseError::MessageTooSmall(Some(
                    MessageType::TL_CONNECT_REQUEST
                )))
            ));
        }
        for length in 40..=extended.len() {
            match Message::parse(&extended[..length], connected).unwrap() {
                Message::TlConnectRequest(value, tail) => {
                    assert!(negotiated == Version::Win10 || length < 56);
                    assert_eq!(value.endpoint_id, endpoint);
                    assert_eq!(value.service_id, service);
                    assert_eq!(tail, &extended[40..length]);
                }
                Message::TlConnectRequest2(value, tail) => {
                    assert!(negotiated != Version::Win10 && length >= 56);
                    assert_eq!(value.base.endpoint_id, endpoint);
                    assert_eq!(value.base.service_id, service);
                    assert_eq!(value.silo_id, silo);
                    assert_eq!(tail, &extended[56..length]);
                }
                other => panic!("unexpected socket request: {other:?}"),
            }
        }
    }
    for connected in [None, version(Version::Win8_1, FeatureFlags::new())] {
        assert!(matches!(
            Message::parse(&wire, connected),
            Err(ParseError::InvalidMessageType(
                MessageType::TL_CONNECT_REQUEST
            ))
        ));
    }
}
