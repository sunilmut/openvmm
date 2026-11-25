// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use rndisprot::Oid;
use test_with_tracing::test;

#[path = "snapshot_behavior.rs"]
mod snapshot_behavior;

fn network_device(driver: &DefaultDriver) -> Nic {
    Nic::builder().build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(TestNicEndpoint::new(Some(TestNicEndpointState::new()))),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    )
}

async fn nic(driver: &DefaultDriver) -> TestNicDevice {
    TestNicDevice::new_with_nic(driver, network_device(driver)).await
}

async fn control<T: IntoBytes + Immutable + KnownLayout>(
    channel: &mut TestNicChannel<'_>,
    message_type: u32,
    request: T,
    extra: &[u8],
    reply_type: u32,
) -> Vec<u8> {
    // Reuse the send buffer only after the previous request was acknowledged.
    channel.send_offset = 0;
    channel
        .send_rndis_control_message_no_completion(message_type, request, extra)
        .await;
    let parser = channel.rndis_message_parser();
    let mut acknowledged = false;
    let mut reply = None;
    while !acknowledged || reply.is_none() {
        let received = channel
            .read_with(|packet| match packet {
                IncomingPacket::Completion(completion) => {
                    let mut reader = completion.reader();
                    let header: protocol::MessageHeader = reader.read_plain().unwrap();
                    assert_eq!(
                        header.message_type,
                        protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE
                    );
                    let result: protocol::Message1SendRndisPacketComplete =
                        reader.read_plain().unwrap();
                    assert_eq!(result.status, protocol::Status::SUCCESS);
                    None
                }
                IncomingPacket::Data(data) => {
                    let (header, ranges) = parser.parse_control_message(data);
                    let mut reader = PagedRanges::new(ranges.iter()).reader(&parser.mem);
                    reader.skip(size_of::<rndisprot::MessageHeader>()).unwrap();
                    let mut body = vec![
                        0;
                        header.message_length as usize
                            - size_of::<rndisprot::MessageHeader>()
                    ];
                    reader.read(&mut body).unwrap();
                    Some((data.transaction_id(), header.message_type, body))
                }
            })
            .await
            .expect("control response timed out");
        if let Some((transaction_id, message_type, body)) = received {
            channel
                .write(OutgoingPacket {
                    transaction_id: transaction_id.expect("control buffer requires completion"),
                    packet_type: OutgoingPacketType::Completion,
                    payload: &NvspMessage {
                        header: protocol::MessageHeader {
                            message_type: protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE,
                        },
                        data: protocol::Message1SendRndisPacketComplete {
                            status: protocol::Status::SUCCESS,
                        },
                        padding: &[],
                    }
                    .payload(),
                })
                .await;
            if message_type == reply_type {
                assert!(reply.replace(body).is_none());
            } else {
                assert_eq!(message_type, rndisprot::MESSAGE_TYPE_INDICATE_STATUS_MSG);
                let indication = rndisprot::IndicateStatus::read_from_prefix(&body)
                    .unwrap()
                    .0;
                assert_eq!(
                    indication.status,
                    rndisprot::STATUS_TASK_OFFLOAD_CURRENT_CONFIG
                );
            }
        } else {
            assert!(!acknowledged);
            acknowledged = true;
        }
    }
    reply.unwrap()
}

async fn query(channel: &mut TestNicChannel<'_>, oid: Oid) -> (u32, Vec<u8>) {
    let body = control(
        channel,
        rndisprot::MESSAGE_TYPE_QUERY_MSG,
        rndisprot::QueryRequest {
            request_id: 0x1234,
            oid,
            information_buffer_length: 0,
            information_buffer_offset: 0,
            device_vc_handle: 0,
        },
        &[],
        rndisprot::MESSAGE_TYPE_QUERY_CMPLT,
    )
    .await;
    let response = rndisprot::QueryComplete::read_from_prefix(&body).unwrap().0;
    assert_eq!(response.request_id, 0x1234);
    let start = response.information_buffer_offset as usize;
    let end = start + response.information_buffer_length as usize;
    assert_eq!(end, body.len());
    (response.status, body[start..end].to_vec())
}

async fn value(channel: &mut TestNicChannel<'_>, oid: Oid) -> Vec<u8> {
    let (status, data) = query(channel, oid).await;
    assert_eq!(status, rndisprot::STATUS_SUCCESS, "{oid:?}");
    data
}

async fn set(channel: &mut TestNicChannel<'_>, oid: Oid, data: &[u8]) -> u32 {
    let body = control(
        channel,
        rndisprot::MESSAGE_TYPE_SET_MSG,
        rndisprot::SetRequest {
            request_id: 0x5678,
            oid,
            information_buffer_length: data.len() as u32,
            information_buffer_offset: size_of::<rndisprot::SetRequest>() as u32,
            device_vc_handle: 0,
        },
        data,
        rndisprot::MESSAGE_TYPE_SET_CMPLT,
    )
    .await;
    let response = rndisprot::SetComplete::read_from_bytes(&body).unwrap();
    assert_eq!(response.request_id, 0x5678);
    response.status
}

async fn offload(channel: &mut TestNicChannel<'_>, oid: Oid) -> rndisprot::NdisOffload {
    let data = value(channel, oid).await;
    let mut result = rndisprot::NdisOffload::new_zeroed();
    result.as_mut_bytes()[..data.len()].copy_from_slice(&data);
    assert_eq!(result.header.size as usize, data.len());
    assert_eq!(
        result.header.object_type,
        rndisprot::NdisObjectType::OFFLOAD
    );
    result
}

// Test: Query adapter identity, frame sizes, media and operational limits over RNDIS.
// Expected: Replies preserve request IDs and return consistent Ethernet geometry,
//       identity and link information in the documented wire formats.
#[async_test]
async fn queries_report_adapter_identity_and_geometry(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for (oid, expected) in [
        (Oid::OID_GEN_HARDWARE_STATUS, 0),
        (Oid::OID_GEN_MEDIA_SUPPORTED, rndisprot::MEDIUM_802_3),
        (Oid::OID_GEN_MEDIA_IN_USE, rndisprot::MEDIUM_802_3),
        (Oid::OID_GEN_MAXIMUM_LOOKAHEAD, 1500),
        (Oid::OID_GEN_CURRENT_LOOKAHEAD, 1500),
        (Oid::OID_GEN_MAXIMUM_FRAME_SIZE, 1500),
        (Oid::OID_GEN_MAXIMUM_TOTAL_SIZE, 1514),
        (Oid::OID_GEN_TRANSMIT_BLOCK_SIZE, 1514),
        (Oid::OID_GEN_RECEIVE_BLOCK_SIZE, 1514),
        (Oid::OID_GEN_TRANSMIT_BUFFER_SPACE, 262144),
        (Oid::OID_GEN_RECEIVE_BUFFER_SPACE, 262144),
        (Oid::OID_GEN_VENDOR_ID, 0x155d),
        (Oid::OID_GEN_CURRENT_PACKET_FILTER, 0),
        (
            Oid::OID_GEN_MAC_OPTIONS,
            rndisprot::MAC_OPTION_COPY_LOOKAHEAD_DATA
                | rndisprot::MAC_OPTION_TRANSFERS_NOT_PEND
                | rndisprot::MAC_OPTION_NO_LOOPBACK
                | rndisprot::MAC_OPTION_8021P_PRIORITY
                | rndisprot::MAC_OPTION_8021Q_VLAN,
        ),
        (
            Oid::OID_GEN_MEDIA_CONNECT_STATUS,
            rndisprot::MEDIA_STATE_CONNECTED,
        ),
        (Oid::OID_GEN_MAXIMUM_SEND_PACKETS, u32::MAX),
        (Oid::OID_802_3_MAXIMUM_LIST_SIZE, 0),
        (Oid::OID_802_3_RCV_ERROR_ALIGNMENT, 0),
        (Oid::OID_802_3_XMIT_ONE_COLLISION, 0),
        (Oid::OID_802_3_XMIT_MORE_COLLISIONS, 0),
    ] {
        assert_eq!(
            u32::read_from_bytes(&value(&mut channel, oid).await).unwrap(),
            expected,
            "{oid:?}"
        );
    }
    for oid in [
        Oid::OID_802_3_PERMANENT_ADDRESS,
        Oid::OID_802_3_CURRENT_ADDRESS,
    ] {
        assert_eq!(value(&mut channel, oid).await, [1, 2, 3, 4, 5, 6]);
    }
    assert_eq!(
        value(&mut channel, Oid::OID_GEN_VENDOR_DESCRIPTION).await,
        b"Microsoft Corporation"
    );
    for oid in [
        Oid::OID_GEN_DRIVER_VERSION,
        Oid::OID_GEN_VENDOR_DRIVER_VERSION,
    ] {
        assert_eq!(value(&mut channel, oid).await, 0x100u16.to_le_bytes());
    }
    let name = value(&mut channel, Oid::OID_GEN_FRIENDLY_NAME).await;
    let name: Vec<_> = name
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|c| *c != 0)
        .collect();
    assert_eq!(String::from_utf16(&name).unwrap(), "Network Device");
    let speed = rndisprot::LinkSpeed::read_from_bytes(
        &value(&mut channel, Oid::OID_GEN_MAX_LINK_SPEED).await,
    )
    .unwrap();
    assert!(speed.xmit > 0);
    assert_eq!(speed.xmit, speed.rcv);
    let current =
        u32::read_from_bytes(&value(&mut channel, Oid::OID_GEN_LINK_SPEED).await).unwrap();
    assert_eq!(u64::from(current) * 100, speed.xmit);
    let link =
        rndisprot::LinkState::read_from_bytes(&value(&mut channel, Oid::OID_GEN_LINK_STATE).await)
            .unwrap();
    assert_eq!(link.media_connect_state, 1);
    assert_eq!(link.xmit_link_speed, speed.xmit);
    assert_eq!(link.rcv_link_speed, speed.rcv);
}

// Test: Negotiate legacy, modern and unsupported NDIS versions and query OID lists.
// Expected: NDIS 5 omits offloads, NDIS 6 advertises them, RSS starts at 6.30,
//       and unsupported major versions return BAD_VERSION without a payload.
#[async_test]
async fn supported_oid_lists_follow_negotiated_ndis_version(driver: DefaultDriver) {
    for (major, minor) in [(5, 0), (6, 20), (6, 30), (7, 0)] {
        let mut device = nic(&driver).await;
        let mut channel = device.connect_vmbus_channel().await;
        channel.send_initialize_message().await;
        channel.send_ndis_config_message(Default::default()).await;
        let message = NvspMessage {
            header: protocol::MessageHeader {
                message_type: protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
            },
            data: protocol::Message1SendNdisVersion {
                ndis_major_version: major,
                ndis_minor_version: minor,
            },
            padding: &[],
        };
        channel
            .write(OutgoingPacket {
                transaction_id: 99,
                packet_type: OutgoingPacketType::InBandWithCompletion,
                payload: &message.payload(),
            })
            .await;
        channel
            .read_with(|packet| assert!(matches!(packet, IncomingPacket::Completion(_))))
            .await
            .unwrap();
        channel.send_receive_buffer_message(0).await;
        channel.send_send_buffer_message().await;
        initialize_rndis_control(&mut channel).await;
        let (status, bytes) = query(&mut channel, Oid::OID_GEN_SUPPORTED_LIST).await;
        if major == 7 {
            assert_eq!(status, rndisprot::STATUS_BAD_VERSION);
            assert!(bytes.is_empty());
        } else {
            assert_eq!(status, rndisprot::STATUS_SUCCESS);
            let oids: Vec<_> = bytes
                .chunks_exact(4)
                .map(|b| Oid(u32::from_le_bytes(b.try_into().unwrap())))
                .collect();
            assert!(oids.contains(&Oid::OID_802_3_CURRENT_ADDRESS));
            assert_eq!(
                oids.contains(&Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG),
                major == 6
            );
            assert_eq!(
                oids.contains(&Oid::OID_GEN_RECEIVE_SCALE_CAPABILITIES),
                major == 6 && minor >= 30
            );
            let mut unique = oids.iter().map(|oid| oid.0).collect::<Vec<_>>();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), oids.len());
        }
    }
}

// Test: Query hardware/current offloads, encapsulation and RSS capabilities.
// Expected: Hardware and initial settings agree, Ethernet encapsulation is
//       reported and RSS exposes usable queue and indirection-table limits.
#[async_test]
async fn capability_queries_report_backend_offloads(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    let hardware = offload(&mut channel, Oid::OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES).await;
    let current = offload(&mut channel, Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG).await;
    assert_eq!(hardware.as_bytes(), current.as_bytes());
    assert_eq!(
        hardware.checksum.ipv4_tx_flags.tcp_checksum(),
        rndisprot::NDIS_OFFLOAD_SUPPORTED
    );
    assert_eq!(
        hardware.checksum.ipv6_rx_flags.udp_checksum(),
        rndisprot::NDIS_OFFLOAD_SUPPORTED
    );
    assert!(hardware.lso_v2.ipv4_max_offload_size > 1514);
    assert!(hardware.lso_v2.ipv6_max_offload_size > 1514);
    let encap = rndisprot::NdisOffloadEncapsulation::read_from_bytes(
        &value(&mut channel, Oid::OID_OFFLOAD_ENCAPSULATION).await,
    )
    .unwrap();
    assert_eq!(encap.ipv4_header_size, 14);
    assert_eq!(encap.ipv6_header_size, 14);
    assert_eq!(
        encap.ipv4_encapsulation_type,
        rndisprot::NDIS_ENCAPSULATION_IEEE_802_3
    );
    let data = value(&mut channel, Oid::OID_GEN_RECEIVE_SCALE_CAPABILITIES).await;
    let mut rss = rndisprot::NdisReceiveScaleCapabilities::new_zeroed();
    rss.as_mut_bytes()[..data.len()].copy_from_slice(&data);
    assert!(rss.number_of_receive_queues > 0);
    assert!(rss.number_of_indirection_table_entries > 0);
}

fn parameters() -> rndisprot::NdisOffloadParameters {
    let mut value = rndisprot::NdisOffloadParameters::new_zeroed();
    value.header = rndisprot::NdisObjectHeader {
        object_type: rndisprot::NdisObjectType::DEFAULT,
        revision: 1,
        size: rndisprot::NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1 as u16,
    };
    value
}

// Test: Change checksum/segmentation offloads and query the resulting configuration.
// Expected: Disabled and directional settings are visible in guest replies;
//       enabling unsupported LSOv1 fails without changing those settings.
#[async_test]
async fn offload_settings_round_trip_through_guest_queries(driver: DefaultDriver) {
    use rndisprot::{OffloadParametersChecksum as Checksum, OffloadParametersSimple as Simple};
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for (checksum, lso, tx, rx, segmentation) in [
        (Checksum::TX_RX_DISABLED, Simple::DISABLED, 0, 0, false),
        (
            Checksum::TX_ENABLED_RX_DISABLED,
            Simple::ENABLED,
            1,
            0,
            true,
        ),
        (
            Checksum::RX_ENABLED_TX_DISABLED,
            Simple::DISABLED,
            0,
            1,
            false,
        ),
        (Checksum::TX_RX_ENABLED, Simple::ENABLED, 1, 1, true),
    ] {
        let mut params = parameters();
        params.ipv4_checksum = checksum;
        params.tcp4_checksum = checksum;
        params.udp4_checksum = checksum;
        params.tcp6_checksum = checksum;
        params.udp6_checksum = checksum;
        params.lsov2_ipv4 = lso;
        params.lsov2_ipv6 = lso;
        assert_eq!(
            set(
                &mut channel,
                Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes()
            )
            .await,
            rndisprot::STATUS_SUCCESS
        );
        let current = offload(&mut channel, Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG).await;
        assert_eq!(current.checksum.ipv4_tx_flags.ip_checksum(), tx);
        assert_eq!(current.checksum.ipv4_rx_flags.ip_checksum(), rx);
        assert_eq!(current.checksum.ipv4_tx_flags.tcp_checksum(), tx);
        assert_eq!(current.checksum.ipv4_rx_flags.udp_checksum(), rx);
        assert_eq!(current.checksum.ipv6_tx_flags.udp_checksum(), tx);
        assert_eq!(current.checksum.ipv6_rx_flags.tcp_checksum(), rx);
        assert_eq!(current.lso_v2.ipv4_max_offload_size != 0, segmentation);
        assert_eq!(current.lso_v2.ipv6_max_offload_size != 0, segmentation);
    }
    let mut params = parameters();
    params.lsov1 = Simple::ENABLED;
    assert_eq!(
        set(
            &mut channel,
            Oid::OID_TCP_OFFLOAD_PARAMETERS,
            params.as_bytes()
        )
        .await,
        rndisprot::STATUS_NOT_SUPPORTED
    );
    assert_eq!(
        offload(&mut channel, Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG)
            .await
            .checksum
            .ipv4_tx_flags
            .tcp_checksum(),
        1
    );
}

// Test: Send malformed NDIS headers and unsupported or truncated OID requests.
// Expected: Invalid headers fail with INVALID_DATA, short fields fail explicitly,
//       unknown OIDs fail as unsupported and the channel remains usable.
#[async_test]
async fn invalid_oid_requests_fail_without_breaking_control_channel(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for case in 0..4 {
        let mut params = parameters();
        match case {
            0 => params.header.object_type = rndisprot::NdisObjectType::OFFLOAD,
            1 => params.header.revision = 0,
            2 => params.header.size = 4,
            3 => params.header.size = 200,
            _ => unreachable!(),
        }
        assert_eq!(
            set(
                &mut channel,
                Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes()
            )
            .await,
            rndisprot::STATUS_INVALID_DATA
        );
    }
    assert_eq!(
        set(&mut channel, Oid::OID_GEN_CURRENT_LOOKAHEAD, &[]).await,
        rndisprot::STATUS_FAILURE
    );
    assert_eq!(
        set(
            &mut channel,
            Oid::OID_GEN_CURRENT_LOOKAHEAD,
            &64u32.to_le_bytes()
        )
        .await,
        rndisprot::STATUS_SUCCESS
    );
    assert_eq!(
        set(&mut channel, Oid::OID_GEN_NETWORK_LAYER_ADDRESSES, &[]).await,
        rndisprot::STATUS_SUCCESS
    );
    assert_eq!(
        set(&mut channel, Oid(0xffffeeee), &[]).await,
        rndisprot::STATUS_NOT_SUPPORTED
    );
    let (status, data) = query(&mut channel, Oid(0xffffeeee)).await;
    assert_eq!(status, rndisprot::STATUS_NOT_SUPPORTED);
    assert!(data.is_empty());
    let response = control(
        &mut channel,
        rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG,
        rndisprot::KeepaliveRequest { request_id: 99 },
        &[],
        rndisprot::MESSAGE_TYPE_KEEPALIVE_CMPLT,
    )
    .await;
    let response = rndisprot::KeepaliveComplete::read_from_bytes(&response).unwrap();
    assert_eq!(response.request_id, 99);
    assert_eq!(response.status, rndisprot::STATUS_SUCCESS);
}

fn config(name: &[u16], value: &[u16]) -> Vec<u8> {
    let header = rndisprot::RndisConfigParameterInfo {
        name_offset: size_of::<rndisprot::RndisConfigParameterInfo>() as u32,
        name_length: size_of_val(name) as u32,
        parameter_type: rndisprot::NdisParameterType::STRING,
        value_offset: (size_of::<rndisprot::RndisConfigParameterInfo>() + size_of_val(name)) as u32,
        value_length: size_of_val(value) as u32,
    };
    [header.as_bytes(), name.as_bytes(), value.as_bytes()].concat()
}

// Test: Set each supported legacy string offload option and query current offloads.
// Expected: Disabling and enabling affects the corresponding advertised setting;
//       accepted unknown/integer options leave the adapter operational.
#[async_test]
async fn legacy_config_parameters_update_advertised_offloads(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for (index, name) in [
        "*IPChecksumOffloadIPv4",
        "*TCPChecksumOffloadIPv4",
        "*TCPChecksumOffloadIPv6",
        "*UDPChecksumOffloadIPv4",
        "*UDPChecksumOffloadIPv6",
        "*LsoV2IPv4",
        "*LsoV2IPv6",
    ]
    .into_iter()
    .enumerate()
    {
        let name: Vec<_> = name.encode_utf16().collect();
        for enabled in [false, true] {
            let data = config(&name, &[if enabled { b'3' } else { b'0' } as u16]);
            assert_eq!(
                set(&mut channel, Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &data).await,
                rndisprot::STATUS_SUCCESS
            );
            let current = offload(&mut channel, Oid::OID_TCP_OFFLOAD_CURRENT_CONFIG).await;
            let (tx, rx) = match index {
                0 => (
                    current.checksum.ipv4_tx_flags.ip_checksum(),
                    current.checksum.ipv4_rx_flags.ip_checksum(),
                ),
                1 => (
                    current.checksum.ipv4_tx_flags.tcp_checksum(),
                    current.checksum.ipv4_rx_flags.tcp_checksum(),
                ),
                2 => (
                    current.checksum.ipv6_tx_flags.tcp_checksum(),
                    current.checksum.ipv6_rx_flags.tcp_checksum(),
                ),
                3 => (
                    current.checksum.ipv4_tx_flags.udp_checksum(),
                    current.checksum.ipv4_rx_flags.udp_checksum(),
                ),
                4 => (
                    current.checksum.ipv6_tx_flags.udp_checksum(),
                    current.checksum.ipv6_rx_flags.udp_checksum(),
                ),
                5 => (
                    u32::from(current.lso_v2.ipv4_max_offload_size != 0),
                    u32::from(current.lso_v2.ipv4_max_offload_size != 0),
                ),
                6 => (
                    u32::from(current.lso_v2.ipv6_max_offload_size != 0),
                    u32::from(current.lso_v2.ipv6_max_offload_size != 0),
                ),
                _ => unreachable!(),
            };
            assert_eq!((tx, rx), (u32::from(enabled), u32::from(enabled)));
        }
    }
    let unknown: Vec<_> = "UnrecognizedOption".encode_utf16().collect();
    assert_eq!(
        set(
            &mut channel,
            Oid::OID_GEN_RNDIS_CONFIG_PARAMETER,
            &config(&unknown, &[b'1' as u16])
        )
        .await,
        rndisprot::STATUS_SUCCESS
    );
    for parameter_type in [
        rndisprot::NdisParameterType::INTEGER,
        rndisprot::NdisParameterType::HEX_INTEGER,
    ] {
        let mut data = config(&unknown, &[0, 0]);
        let mut header = rndisprot::RndisConfigParameterInfo::read_from_prefix(&data)
            .unwrap()
            .0;
        header.parameter_type = parameter_type;
        data[..size_of_val(&header)].copy_from_slice(header.as_bytes());
        assert_eq!(
            set(&mut channel, Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &data).await,
            rndisprot::STATUS_SUCCESS
        );
    }
}

// Test: Send malformed legacy configuration strings, lengths and offsets.
// Expected: Invalid UTF-16, oversized names/values, missing digits and inaccessible
//       buffers produce explicit failure replies without terminating the channel.
#[async_test]
async fn malformed_legacy_parameters_return_precise_failures(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for data in [
        config(&vec![b'a' as u16; 128], &[b'0' as u16]),
        config(&[b'a' as u16], &vec![b'0' as u16; 128]),
        config(&[0xd800], &[b'0' as u16]),
        config(&[b'a' as u16], &[0xd800]),
        config(&[b'a' as u16], &[b'x' as u16]),
        config(&[b'a' as u16], &[]),
    ] {
        assert_eq!(
            set(&mut channel, Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &data).await,
            rndisprot::STATUS_INVALID_DATA
        );
    }
    for corrupt_name in [true, false] {
        let mut header = rndisprot::RndisConfigParameterInfo::new_zeroed();
        if corrupt_name {
            header.name_offset = u32::MAX;
            header.name_length = 2;
        } else {
            header.value_offset = u32::MAX;
            header.value_length = 4;
        }
        assert_eq!(
            set(
                &mut channel,
                Oid::OID_GEN_RNDIS_CONFIG_PARAMETER,
                header.as_bytes()
            )
            .await,
            rndisprot::STATUS_FAILURE
        );
    }
}

// Test: Set Ethernet offload encapsulation, then change each enabled IP format.
// Expected: Supported Ethernet layouts succeed; incorrect IPv4/IPv6 types and
//       header sizes are rejected, while disabled formats need no valid layout.
#[async_test]
async fn encapsulation_requests_validate_enabled_ip_layouts(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    let valid = rndisprot::NdisOffloadEncapsulation {
        header: rndisprot::NdisObjectHeader {
            object_type: rndisprot::NdisObjectType::OFFLOAD_ENCAPSULATION,
            revision: 1,
            size: rndisprot::NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1 as u16,
        },
        ipv4_enabled: rndisprot::NDIS_OFFLOAD_SET_ON,
        ipv4_encapsulation_type: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
        ipv4_header_size: 14,
        ipv6_enabled: rndisprot::NDIS_OFFLOAD_SET_ON,
        ipv6_encapsulation_type: rndisprot::NDIS_ENCAPSULATION_IEEE_802_3,
        ipv6_header_size: 14,
    };
    for case in 0..6 {
        let mut request = valid;
        match case {
            0 => {}
            1 => request.ipv4_encapsulation_type = 0,
            2 => request.ipv4_header_size = 13,
            3 => request.ipv6_encapsulation_type = 0,
            4 => request.ipv6_header_size = 13,
            5 => {
                request.ipv4_enabled = rndisprot::NDIS_OFFLOAD_SET_OFF;
                request.ipv6_enabled = rndisprot::NDIS_OFFLOAD_SET_OFF;
                request.ipv4_header_size = 0;
                request.ipv6_header_size = 0;
            }
            _ => unreachable!(),
        }
        let expected = if matches!(case, 0 | 5) {
            rndisprot::STATUS_SUCCESS
        } else {
            rndisprot::STATUS_NOT_SUPPORTED
        };
        assert_eq!(
            set(
                &mut channel,
                Oid::OID_OFFLOAD_ENCAPSULATION,
                request.as_bytes()
            )
            .await,
            expected
        );
    }
}

// Test: Supply RSS parameters with invalid key/table lengths and out-of-range data.
// Expected: Invalid lengths return INVALID_DATA and inaccessible buffers fail,
//       with a subsequent query still completing successfully.
#[async_test]
async fn malformed_rss_parameters_do_not_disable_control_queries(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for case in 0..5 {
        let mut data = build_rss_enable_params();
        let mut params = rndisprot::NdisReceiveScaleParameters::read_from_prefix(&data)
            .unwrap()
            .0;
        match case {
            0 => params.hash_secret_key_size = 39,
            1 => params.indirection_table_size = 0,
            2 => params.indirection_table_size = 2,
            3 => params.hash_secret_key_offset = u32::MAX,
            4 => params.indirection_table_offset = u32::MAX,
            _ => unreachable!(),
        }
        data[..size_of_val(&params)].copy_from_slice(params.as_bytes());
        let expected = if case < 3 {
            rndisprot::STATUS_INVALID_DATA
        } else {
            rndisprot::STATUS_FAILURE
        };
        assert_eq!(
            set(&mut channel, Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS, &data).await,
            expected
        );
    }

    assert_eq!(
        value(&mut channel, Oid::OID_802_3_CURRENT_ADDRESS).await,
        [1, 2, 3, 4, 5, 6]
    );
}

// Test: Write a segmented receive packet across noncontiguous guest pages.
// Expected: Backend-visible scatter/gather addresses describe the complete MTU,
//       and guest memory contains an intact RNDIS packet and payload.
#[test]
fn receive_buffer_segments_preserve_guest_packet_bytes() {
    let memory = GuestMemory::allocate(12288);
    let map = GpadlMap::new();
    map.add(
        GpadlId(1),
        MultiPagedRangeBuf::from_range_buffer(1, vec![12288, 2, 0, 1]).unwrap(),
    );
    let gpadl = map.view().map(GpadlId(1)).unwrap();
    let buffers = GuestBuffers::new(memory.clone(), gpadl.clone(), 9292, 9000).unwrap();
    let mut pool = BufferPool::new(Arc::new(buffers));
    let mut addresses = Vec::new();
    pool.push_guest_addresses(RxId(0), &mut addresses);
    assert_eq!(
        addresses.iter().map(|s| (s.gpa, s.len)).collect::<Vec<_>>(),
        [(8448, 3840), (0, 5160)]
    );
    assert_eq!(pool.capacity(RxId(0)), 9000);
    let data: Vec<_> = (0..5000).map(|i| (i % 251) as u8).collect();
    pool.write_packet_segments(
        RxId(0),
        &RxMetadata {
            len: data.len(),
            ..Default::default()
        },
        &[&data[..17], &[], &data[17..3000], &data[3000..]],
    );
    let mut reader = PagedRanges::new(gpadl.iter()).reader(pool.guest_memory());
    let header: rndisprot::MessageHeader = reader.read_plain().unwrap();
    assert_eq!(header.message_type, rndisprot::MESSAGE_TYPE_PACKET_MSG);
    let packet: rndisprot::Packet = reader.read_plain().unwrap();
    assert_eq!(packet.data_length as usize, data.len());
    let range = gpadl.first().unwrap().subrange(
        size_of::<rndisprot::MessageHeader>() + packet.data_offset as usize,
        packet.data_length as usize,
    );
    let mut received = vec![0; data.len()];
    range.reader(&memory).read(&mut received).unwrap();
    assert_eq!(received, data);
}

// Test: Query an OID through NVSP's extended-query interface after initialization.
// Expected: The matching transaction completes with an explicit unsupported
//       status and no returned data; ordinary RNDIS queries still work.
#[async_test]
async fn extended_oid_queries_fail_explicitly_without_terminating_channel(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    let mut data = protocol::Message5OidQueryEx::new_zeroed();
    data.oid = Oid::OID_802_3_CURRENT_ADDRESS;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE5_TYPE_OID_QUERY_EX,
        },
        data,
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 0xabcdef,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| {
            let IncomingPacket::Completion(completion) = packet else {
                panic!("expected completion")
            };
            assert_eq!(completion.transaction_id(), 0xabcdef);
            let mut reader = completion.reader();
            let header: protocol::MessageHeader = reader.read_plain().unwrap();
            assert_eq!(
                header.message_type,
                protocol::MESSAGE5_TYPE_OID_QUERY_EX_COMPLETE
            );
            let reply: protocol::Message5OidQueryExComplete = reader.read_plain().unwrap();
            assert_eq!(reply.status, rndisprot::STATUS_NOT_SUPPORTED);
            assert_eq!(reply.bytes, 0);
        })
        .await
        .unwrap();
    assert_eq!(
        value(&mut channel, Oid::OID_802_3_CURRENT_ADDRESS).await,
        [1, 2, 3, 4, 5, 6]
    );
}

// Test: Retry unsupported NVSP negotiation with version 1 and omit NDIS config.
// Expected: Unsupported versions are declined, the legacy retry succeeds and
//       the adapter supplies default Ethernet MTU without a config message.
#[async_test]
async fn legacy_negotiation_recovers_after_unsupported_version(driver: DefaultDriver) {
    let mut device = nic(&driver).await;
    let mut channel = device.connect_vmbus_channel().await;
    let message = NvspMessage {
        header: protocol::MessageHeader {
            message_type: protocol::MESSAGE_TYPE_INIT,
        },
        data: protocol::MessageInit {
            protocol_version: u32::MAX,
            protocol_version2: u32::MAX,
        },
        padding: &[],
    };
    channel
        .write(OutgoingPacket {
            transaction_id: 99,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &message.payload(),
        })
        .await;
    channel
        .read_with(|packet| {
            let IncomingPacket::Completion(completion) = packet else {
                panic!("expected completion")
            };
            let mut reader = completion.reader();
            let _: protocol::MessageHeader = reader.read_plain().unwrap();
            let reply: protocol::MessageInitComplete = reader.read_plain().unwrap();
            assert_eq!(reply.status, protocol::Status::NONE);
        })
        .await
        .unwrap();
    channel
        .send_initialize_message_with_version(Version::V1)
        .await;
    channel.send_ndis_version_message().await;
    channel.send_receive_buffer_message(0).await;
    channel.send_send_buffer_message().await;
    initialize_rndis_control(&mut channel).await;
    assert_eq!(
        value(&mut channel, Oid::OID_GEN_MAXIMUM_TOTAL_SIZE).await,
        1514u32.to_le_bytes()
    );
}

// Test: Submit packets to an asynchronously completing endpoint without a restart.
// Expected: Each guest transaction receives its own successful completion and
//       subsequent submissions can reuse the released transmit capacity.
#[async_test]
async fn asynchronous_transmit_completions_release_guest_requests(driver: DefaultDriver) {
    let state = TestNicEndpointState::new();
    {
        let mut endpoint = state.lock();
        endpoint.sync_tx = false;
        endpoint.complete_async_tx = true;
    }
    let nic = Nic::builder().build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(TestNicEndpoint::new(Some(state))),
        [1, 2, 3, 4, 5, 6].into(),
        0,
    );
    let mut device = TestNicDevice::new_with_nic(&driver, nic).await;
    let mut channel = device.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    for length in [60, 1500] {
        let mut data = build_ipv4_tcp_packet();
        data.resize(length, 0xab);
        let transaction_id = channel.transaction_id;
        channel
            .send_rndis_packet_offload(&data, true, false, false)
            .await;
        channel
            .read_with(|packet| {
                let IncomingPacket::Completion(completion) = packet else {
                    panic!("expected completion")
                };
                assert_eq!(completion.transaction_id(), transaction_id);
                let mut reader = completion.reader();
                let header: protocol::MessageHeader = reader.read_plain().unwrap();
                assert_eq!(
                    header.message_type,
                    protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE
                );
                let reply: protocol::Message1SendRndisPacketComplete = reader.read_plain().unwrap();
                assert_eq!(reply.status, protocol::Status::SUCCESS);
            })
            .await
            .unwrap();
    }
}

// Test: Initialize ring-limited adapters for old/new Linux, FreeBSD and other guests.
// Expected: Guest-specific ring optimization decisions preserve successful
//       negotiation and control responses on both sides of version cutoffs.
#[async_test]
async fn ring_limited_adapters_support_legacy_and_modern_guest_ids(driver: DefaultDriver) {
    use hvdef::hypercall::{HvGuestOsOpenSource, HvGuestOsOpenSourceType as Os};
    for (os_type, version) in [
        (Os::LINUX, 199423),
        (Os::LINUX, 199424),
        (Os::FREEBSD, 1400096),
        (Os::FREEBSD, 1400097),
        (Os::XEN, 1),
    ] {
        let id = HvGuestOsId::from(u64::from(
            HvGuestOsOpenSource::new()
                .with_is_open_source(true)
                .with_os_type(os_type.0)
                .with_version(version),
        ));
        let nic = Nic::builder()
            .limit_ring_buffer(true)
            .get_guest_os_id(Box::new(move || id))
            .build(
                &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
                Guid::new_random(),
                Box::new(NullEndpoint::new()),
                [1, 2, 3, 4, 5, 6].into(),
                0,
            );
        let mut device = TestNicDevice::new_with_nic(&driver, nic).await;
        let mut channel = device.connect_vmbus_channel().await;
        channel.initialize(0, Default::default()).await;
        initialize_rndis_control(&mut channel).await;
        assert_eq!(
            value(&mut channel, Oid::OID_802_3_CURRENT_ADDRESS).await,
            [1, 2, 3, 4, 5, 6]
        );
    }
}

// Test: Negotiate MTUs below and above the supported Ethernet range.
// Expected: The guest-facing maximum frame size uses the default MTU and
//       subsequent RNDIS requests remain operational.
#[async_test]
async fn invalid_mtus_use_default_guest_frame_size(driver: DefaultDriver) {
    for mtu in [0, 9217] {
        let mut device = nic(&driver).await;
        let mut channel = device.connect_vmbus_channel().await;
        channel.mtu = mtu;
        channel.initialize(0, Default::default()).await;
        initialize_rndis_control(&mut channel).await;
        assert_eq!(
            value(&mut channel, Oid::OID_GEN_MAXIMUM_TOTAL_SIZE).await,
            1514u32.to_le_bytes()
        );
    }
}
