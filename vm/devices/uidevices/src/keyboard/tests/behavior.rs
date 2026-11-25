// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_helpers::connected_gpadl_channels;
use test_with_tracing::test;

// Test: Run the public keyboard device on guest-backed rings, then save and restore it.
// Expected: Negotiated input resumes without another handshake, preserving E0/E1 and break flags.
#[async_test]
async fn saved_keyboard_resumes_extended_keystrokes_without_renegotiation() {
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new_raw(guest).unwrap();
    let (source, mut sink) = input_pair();
    let mut keyboard = Keyboard::new(Box::new(source));
    let mut channel = keyboard.open(host, memory).unwrap();
    assert!(!sink.is_active());
    {
        let mut run = pin!(StopTask::run_unstoppable(async |stop| keyboard
            .run(stop, &mut channel)
            .await));
        send_packet(
            &mut guest,
            protocol::MESSAGE_PROTOCOL_REQUEST,
            &protocol::MessageProtocolRequest {
                version: protocol::VERSION_WIN8,
            },
        )
        .await
        .unwrap();
        assert!(run.as_mut().now_or_never().is_none());
        assert!(matches!(
            recv_packet(&mut guest).await,
            Some(Packet::ProtocolResponse(
                protocol::MessageProtocolResponse { accepted: 1 }
            ))
        ));
        assert!(sink.is_active());
        sink.send(KeyboardData {
            code: 0xe01d,
            make: true,
        });
        assert!(run.as_mut().now_or_never().is_none());
        assert_keystroke(&mut guest, 0x1d, protocol::KEYSTROKE_IS_E0).await;
    }
    let saved = keyboard
        .supports_save_restore()
        .unwrap()
        .save_open(&channel);
    let saved = mesh::payload::decode(&mesh::payload::encode(saved)).unwrap();
    drop(channel);
    let (host, guest_channel, _memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new_raw(guest_channel).unwrap();
    let mut channel = keyboard.restore_open(saved, host).unwrap();
    {
        let mut run = pin!(StopTask::run_unstoppable(async |stop| keyboard
            .run(stop, &mut channel)
            .await));
        sink.send(KeyboardData {
            code: 0xe19d,
            make: false,
        });
        assert!(run.as_mut().now_or_never().is_none());
        assert_keystroke(
            &mut guest,
            0x1d,
            protocol::KEYSTROKE_IS_E1 | protocol::KEYSTROKE_IS_BREAK,
        )
        .await;
    }
    keyboard.close().await;
    assert!(!sink.is_active());
    let mut source = keyboard.into_source();
    sink.send(KeyboardData {
        code: 0x20,
        make: true,
    });
    let input = source.next().await.unwrap();
    assert_eq!((input.code, input.make), (0x20, true));
}

// Check the received event rather than the worker's saved/private state.
async fn assert_keystroke(guest: &mut MessagePipe<GpadlRingMem>, code: u16, expected_flags: u32) {
    let Some(Packet::Event(event)) = recv_packet(guest).await else {
        panic!("expected keystroke");
    };
    assert_eq!(
        (event.make_code, event.padding, event.flags),
        (code, 0, expected_flags)
    );
}

// Test: Send an LED update before negotiation, then renegotiate an active keyboard.
// Expected: Both out-of-order requests return the typed protocol-order error.
#[async_test]
async fn keyboard_rejects_out_of_order_requests(driver: DefaultDriver) {
    for active in [false, true] {
        let (host, mut guest) = connected_raw_message_pipes(16384);
        let (source, _sink) = input_pair();
        let worker = start_worker(&driver, Keyboard::new(Box::new(source)), host);
        if active {
            send_packet(
                &mut guest,
                protocol::MESSAGE_PROTOCOL_REQUEST,
                &protocol::MessageProtocolRequest {
                    version: protocol::VERSION_WIN8,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                recv_packet(&mut guest).await,
                Some(Packet::ProtocolResponse(_))
            ));
            send_packet(
                &mut guest,
                protocol::MESSAGE_PROTOCOL_REQUEST,
                &protocol::MessageProtocolRequest {
                    version: protocol::VERSION_WIN8,
                },
            )
            .await
            .unwrap();
        } else {
            send_packet(
                &mut guest,
                protocol::MESSAGE_SET_LED_INDICATORS,
                &protocol::MessageLedIndicatorsState {
                    led_flags: 7,
                    padding: 0,
                },
            )
            .await
            .unwrap();
        }
        assert!(matches!(worker.await, Err(Error::UnexpectedPacketOrder)));
    }
}

// Test: Send an unrecognized message type to the keyboard.
// Expected: The parser reports the exact unknown type, without accepting it as negotiation.
#[async_test]
async fn keyboard_reports_unknown_message_type() {
    let (mut host, mut guest) = connected_raw_message_pipes(16384);
    guest.send(&0xdeadbeefu32.to_le_bytes()).await.unwrap();
    assert!(matches!(
        super::super::recv_packet(&mut host).await,
        Err(Error::UnknownMessageType(0xdeadbeef))
    ));
}

// Test: Stop the public keyboard runner during accepted input, then restart it.
// Expected: The accepted key is delivered once, and cancellation does not finish the device.
#[async_test]
async fn public_keyboard_runner_remains_restartable_after_cancellation(driver: DefaultDriver) {
    let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("keyboard-lifecycle");
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new_raw(guest).unwrap();
    let (source, gate) = gated_input(Some(KeyboardData {
        code: 0x1e,
        make: true,
    }));
    let mut device = Keyboard::new(Box::new(source));
    let channel = device.open(host, memory).unwrap();
    send_packet(
        &mut guest,
        protocol::MESSAGE_PROTOCOL_REQUEST,
        &protocol::MessageProtocolRequest {
            version: protocol::VERSION_WIN8,
        },
    )
    .await
    .unwrap();
    let mut task =
        task_control::TaskControl::new(crate::test_helpers::DeviceWorker { device, channel });
    task.insert(&worker_driver, "keyboard", ());
    assert!(task.start());
    gate.stop(&mut task, &driver).await;
    assert!(matches!(
        recv_packet(&mut guest).await,
        Some(Packet::ProtocolResponse(_))
    ));
    assert_keystroke(&mut guest, 0x1e, 0).await;
    assert!(task.start());
    vmbus_channel::test_helpers::with_timeout(&driver, assert_keystroke(&mut guest, 0x1e, 0)).await;
    vmbus_channel::test_helpers::stop_with_timeout(&mut task, &driver).await;
}

// Test: Close keyboard input after negotiation, then send LED and repeated-version requests.
// Expected: Input EOF preserves LED handling; the protocol violation terminates the runner.
#[async_test]
async fn keyboard_input_eof_preserves_guest_request_handling() {
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new_raw(guest).unwrap();
    let (source, sink) = input_pair();
    let mut keyboard = Keyboard::new(Box::new(source));
    let mut channel = keyboard.open(host, memory).unwrap();
    let mut run = pin!(StopTask::run_unstoppable(async |stop| keyboard
        .run(stop, &mut channel)
        .await));
    send_packet(
        &mut guest,
        protocol::MESSAGE_PROTOCOL_REQUEST,
        &protocol::MessageProtocolRequest {
            version: protocol::VERSION_WIN8,
        },
    )
    .await
    .unwrap();
    assert!(run.as_mut().now_or_never().is_none());
    assert!(matches!(
        recv_packet(&mut guest).await,
        Some(Packet::ProtocolResponse(
            protocol::MessageProtocolResponse { accepted: 1 }
        ))
    ));
    drop(sink);
    assert!(run.as_mut().now_or_never().is_none());
    send_packet(
        &mut guest,
        protocol::MESSAGE_SET_LED_INDICATORS,
        &protocol::MessageLedIndicatorsState {
            led_flags: 0,
            padding: 0,
        },
    )
    .await
    .unwrap();
    assert!(run.as_mut().now_or_never().is_none());
    send_packet(
        &mut guest,
        protocol::MESSAGE_PROTOCOL_REQUEST,
        &protocol::MessageProtocolRequest {
            version: protocol::VERSION_WIN8,
        },
    )
    .await
    .unwrap();
    run.as_mut()
        .now_or_never()
        .expect("repeated negotiation must terminate the public runner")
        .expect("protocol failure is not task cancellation");
}
