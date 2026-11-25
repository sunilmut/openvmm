// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

async fn step(channel: &mut TestNicChannel<'_>, phase: usize) {
    match phase {
        0 => channel.send_initialize_message().await,
        1 => channel.send_ndis_config_message(Default::default()).await,
        2 => channel.send_ndis_version_message().await,
        3 => channel.send_receive_buffer_message(0).await,
        4 => channel.send_send_buffer_message().await,
        5 => initialize_rndis_control(channel).await,
        _ => panic!("invalid initialization phase"),
    }
}

// Test: Snapshot each negotiation boundary and resume on a fresh NIC.
// Expected: Initialization continues from every saved phase and guest queries
//       return the original adapter identity after restoration.
#[async_test]
async fn snapshots_resume_every_initialization_boundary(driver: DefaultDriver) {
    for phase in 0..=6 {
        let mut original = nic(&driver).await;
        let bus = original.mock_vmbus.clone();
        let mut channel = original.connect_vmbus_channel().await;
        for before in 0..phase {
            step(&mut channel, before).await;
        }
        channel.stop().await;
        let saved = channel.save().await.unwrap().unwrap();
        let ids = (channel.recv_buf_id, channel.send_buf_id);
        let mut restored =
            TestNicDevice::new_with_nic_and_vmbus(&driver, bus, network_device(&driver)).await;
        let mut channel = channel.restore(&mut restored, saved).await.unwrap();
        channel.recv_buf_id = ids.0;
        channel.send_buf_id = ids.1;
        channel.start();
        for after in phase..6 {
            step(&mut channel, after).await;
        }
        assert_eq!(
            value(&mut channel, Oid::OID_802_3_CURRENT_ADDRESS).await,
            [1, 2, 3, 4, 5, 6]
        );
    }
}

// Test: Restore partial-initialization snapshots with invalid versions or buffers.
// Expected: Unsupported protocol versions, missing GPADLs and unusable receive
//       suballocations fail through the public restore operation.
#[async_test]
async fn partial_snapshots_reject_invalid_versions_and_buffers(driver: DefaultDriver) {
    for case in 0..5 {
        let mut original = nic(&driver).await;
        let bus = original.mock_vmbus.clone();
        let mut channel = original.connect_vmbus_channel().await;
        for phase in 0..4 {
            step(&mut channel, phase).await;
        }
        channel.stop().await;
        let mut state = channel
            .save()
            .await
            .unwrap()
            .unwrap()
            .parse::<saved_state::SavedState>()
            .unwrap();
        let saved_state::Primary::Init(init) = &mut state.open.as_mut().unwrap().primary else {
            panic!("expected partially initialized snapshot");
        };
        match case {
            0 => init.version = u32::MAX,
            1 => init.receive_buffer.as_mut().unwrap().gpadl_id = GpadlId(u32::MAX),
            2 => init.receive_buffer.as_mut().unwrap().sub_allocation_size = 0,
            3 => init.receive_buffer.as_mut().unwrap().sub_allocation_size = u32::MAX,
            4 => {
                init.send_buffer = Some(saved_state::SendBuffer {
                    gpadl_id: GpadlId(u32::MAX),
                })
            }
            _ => unreachable!(),
        }
        let mut restored =
            TestNicDevice::new_with_nic_and_vmbus(&driver, bus, network_device(&driver)).await;
        assert!(
            channel
                .restore(&mut restored, SavedStateBlob::new(state))
                .await
                .is_err()
        );
    }
}

async fn reject_ready_snapshots(driver: DefaultDriver, cases: Range<usize>) {
    for case in cases {
        let mut original = nic(&driver).await;
        let bus = original.mock_vmbus.clone();
        let mut channel = original.connect_vmbus_channel().await;
        channel.initialize(0, Default::default()).await;
        initialize_rndis_control(&mut channel).await;
        channel.stop().await;
        let mut state = channel
            .save()
            .await
            .unwrap()
            .unwrap()
            .parse::<saved_state::SavedState>()
            .unwrap();
        let saved_state::Primary::Ready(ready) = &mut state.open.as_mut().unwrap().primary else {
            panic!("expected operational snapshot");
        };
        match case {
            0 => {
                ready.rss_state = Some(saved_state::RssState {
                    key: vec![0; 39],
                    indirection_table: vec![0; 128],
                })
            }
            1 => {
                ready.channels[0].as_mut().unwrap().in_use_rx = vec![
                    saved_state::Rx { buffers: vec![0] },
                    saved_state::Rx { buffers: vec![0] },
                ]
            }
            2 => {
                ready.channels[0].as_mut().unwrap().in_use_rx = vec![saved_state::Rx {
                    buffers: vec![u32::MAX],
                }]
            }
            _ => unreachable!(),
        }
        let mut restored =
            TestNicDevice::new_with_nic_and_vmbus(&driver, bus, network_device(&driver)).await;
        assert!(
            channel
                .restore(&mut restored, SavedStateBlob::new(state))
                .await
                .is_err()
        );
    }
}

// Test: Restore operational snapshots with malformed RSS keys or receive ownership.
// Expected: Invalid RSS key lengths and duplicate receive buffers are rejected
//       rather than exposing a partially restored adapter.
#[async_test]
async fn ready_snapshots_reject_invalid_rss_and_receive_ownership(driver: DefaultDriver) {
    reject_ready_snapshots(driver, 0..2).await;
}

// IGNORED: An out-of-range saved receive-buffer ID panics in RxBuffers::allocate.
//       Production validation is intentionally not changed by this test campaign.
//
// Test: Restore an operational snapshot containing receive-buffer ID u32::MAX.
// Expected: Restore returns an invalid-saved-state error instead of panicking.
#[async_test]
#[ignore = "product bug: out-of-range saved receive buffer panics during restore"]
async fn out_of_range_saved_receive_buffer_returns_an_error(driver: DefaultDriver) {
    reject_ready_snapshots(driver, 2..3).await;
}

// Test: Restore an operational snapshot with queued transmit completions.
// Expected: Every saved transaction receives a successful guest completion,
//       and subsequent control requests are processed normally.
#[async_test]
async fn restored_transmit_completions_preserve_guest_transactions(driver: DefaultDriver) {
    let mut original = nic(&driver).await;
    let bus = original.mock_vmbus.clone();
    let mut channel = original.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    channel.stop().await;
    let ids = (channel.recv_buf_id, channel.send_buf_id);
    let mut state = channel
        .save()
        .await
        .unwrap()
        .unwrap()
        .parse::<saved_state::SavedState>()
        .unwrap();
    let saved_state::Primary::Ready(ready) = &mut state.open.as_mut().unwrap().primary else {
        panic!("expected operational snapshot");
    };
    ready.channels[0].as_mut().unwrap().pending_tx_completions = vec![0x400, 0x401, 0x402];
    let mut restored =
        TestNicDevice::new_with_nic_and_vmbus(&driver, bus, network_device(&driver)).await;
    let mut channel = channel
        .restore(&mut restored, SavedStateBlob::new(state))
        .await
        .unwrap();
    channel.recv_buf_id = ids.0;
    channel.send_buf_id = ids.1;
    channel.start();
    for transaction in [0x400, 0x401, 0x402] {
        channel
            .read_with(|packet| {
                let IncomingPacket::Completion(completion) = packet else {
                    panic!("expected completion")
                };
                assert_eq!(completion.transaction_id(), transaction);
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
    assert_eq!(
        value(&mut channel, Oid::OID_802_3_CURRENT_ADDRESS).await,
        [1, 2, 3, 4, 5, 6]
    );
}

// Test: Restore queued guest control requests, save again before starting and
//       restore that snapshot into a third adapter.
// Expected: Each queued keepalive is preserved through both migrations and
//       completes with its original request ID when the adapter starts.
#[async_test]
async fn queued_guest_control_requests_survive_repeated_snapshots(driver: DefaultDriver) {
    let mut original = nic(&driver).await;
    let bus = original.mock_vmbus.clone();
    let mut channel = original.connect_vmbus_channel().await;
    channel.initialize(0, Default::default()).await;
    initialize_rndis_control(&mut channel).await;
    channel.stop().await;
    let ids = (channel.recv_buf_id, channel.send_buf_id);
    let mut state = channel
        .save()
        .await
        .unwrap()
        .unwrap()
        .parse::<saved_state::SavedState>()
        .unwrap();
    let saved_state::Primary::Ready(ready) = &mut state.open.as_mut().unwrap().primary else {
        panic!("expected operational snapshot");
    };
    ready.control_messages = [70, 71, 72]
        .map(|request_id| saved_state::IncomingControlMessage {
            message_type: rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG,
            data: rndisprot::KeepaliveRequest { request_id }
                .as_bytes()
                .to_vec(),
        })
        .into();
    let mut middle =
        TestNicDevice::new_with_nic_and_vmbus(&driver, bus.clone(), network_device(&driver)).await;
    let mut channel = channel
        .restore(&mut middle, SavedStateBlob::new(state))
        .await
        .unwrap();
    let state = channel.save().await.unwrap().unwrap();
    let mut final_device =
        TestNicDevice::new_with_nic_and_vmbus(&driver, bus, network_device(&driver)).await;
    let mut channel = channel.restore(&mut final_device, state).await.unwrap();
    channel.recv_buf_id = ids.0;
    channel.send_buf_id = ids.1;
    channel.start();
    for request_id in [70, 71, 72] {
        let reply: rndisprot::KeepaliveComplete = channel
            .read_rndis_control_message(rndisprot::MESSAGE_TYPE_KEEPALIVE_CMPLT)
            .await
            .unwrap();
        assert_eq!(reply.request_id, request_id);
        assert_eq!(reply.status, rndisprot::STATUS_SUCCESS);
    }
}

// Test: Repeat negotiation fields, send receive buffers before MTU negotiation,
//       and reference an unknown receive GPADL.
// Expected: Invalid sequences receive no successful completion and the device
//       remains stoppable through its public lifecycle interface.
#[async_test]
async fn invalid_initialization_sequences_are_not_acknowledged(driver: DefaultDriver) {
    for case in 0..6 {
        let mut device = nic(&driver).await;
        let mut channel = device.connect_vmbus_channel().await;
        let steps = match case {
            0 => 2,
            1 => 3,
            2 => 4,
            3 => 3,
            4 => 1,
            5 => 2,
            _ => unreachable!(),
        };
        for phase in 0..steps {
            step(&mut channel, phase).await;
        }
        let (message_type, payload) = match case {
            0 => (
                protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
                protocol::Message2SendNdisConfig {
                    mtu: 1514,
                    reserved: 0,
                    capabilities: Default::default(),
                }
                .as_bytes()
                .to_vec(),
            ),
            1 => (
                protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
                protocol::Message1SendNdisVersion {
                    ndis_major_version: 6,
                    ndis_minor_version: 30,
                }
                .as_bytes()
                .to_vec(),
            ),
            2 | 4 | 5 => (
                protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
                protocol::Message1SendReceiveBuffer {
                    gpadl_handle: if case == 2 {
                        channel.recv_buf_id
                    } else {
                        GpadlId(u32::MAX)
                    },
                    id: 0,
                    reserved: 0,
                }
                .as_bytes()
                .to_vec(),
            ),
            3 => {
                channel.send_send_buffer_message().await;
                (
                    protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
                    protocol::Message1SendSendBuffer {
                        gpadl_handle: channel.send_buf_id,
                        id: 0,
                        reserved: 0,
                    }
                    .as_bytes()
                    .to_vec(),
                )
            }
            _ => unreachable!(),
        };
        let header = protocol::MessageHeader { message_type };
        channel
            .write(OutgoingPacket {
                transaction_id: 0xeeee,
                packet_type: OutgoingPacketType::InBandWithCompletion,
                payload: &[header.as_bytes(), &payload],
            })
            .await;
        assert!(
            channel.read_with(|_| ()).await.is_err(),
            "invalid initialization case {case} was acknowledged"
        );
        channel.stop().await;
    }
}
