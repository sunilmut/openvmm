// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_helpers::connected_gpadl_channels;
use futures::FutureExt;
use test_with_tracing::test;

// Negotiate the mouse over its guest pipe, leaving HID acknowledgement to the caller.
async fn request_protocol(guest: &mut MessagePipe<GpadlRingMem>) {
    send_packet(
        guest,
        protocol::SYNTHHID_PROTOCOL_REQUEST,
        size_of::<protocol::MessageProtocolRequest>() as u32,
        &protocol::MessageProtocolRequest {
            version: protocol::SYNTHHID_INPUT_VERSION,
        },
    )
    .await
    .unwrap();
}

// Read a complete input report and compare its independent HID field values.
async fn assert_report(guest: &mut MessagePipe<GpadlRingMem>, buttons: u8, wheel: i16) {
    let mut bytes = [0; 256];
    let length = guest.recv(&mut bytes).await.unwrap();
    let (header, payload) = protocol::MessageHeader::read_from_prefix(&bytes[..length]).unwrap();
    assert_eq!(
        header.message_type,
        protocol::SYNTHHID_PROTOCOL_INPUT_REPORT
    );
    assert_eq!(header.message_size, 7);
    let packet = protocol::MousePacket::read_from_bytes(payload).unwrap();
    assert_eq!(
        (packet.button_data, packet.x, packet.y, packet.z),
        (buttons, 123, 32767, wheel)
    );
}

// Test: Queue mouse input before HID acknowledgement, then acknowledge its descriptor.
// Expected: Input stays inactive until acknowledgement; coordinates and all button/wheel
//       mappings are transmitted with exact report lengths.
#[async_test]
async fn mouse_hid_ack_gates_input_and_preserves_reports() {
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest).unwrap();
    let (source, mut sink) = input_pair();
    let mut mouse = Mouse::new(Box::new(source));
    let mut channel = mouse.open(host, memory).unwrap();
    {
        let mut run = pin!(StopTask::run_unstoppable(async |stop| mouse
            .run(stop, &mut channel)
            .await));
        request_protocol(&mut guest).await;
        sink.send(MouseData {
            button_mask: 1,
            x: 123,
            y: 32767,
        });
        assert!(run.as_mut().now_or_never().is_none());
        assert!(matches!(
            recv_packet(&mut guest).await,
            Some(Packet::ProtocolResponse(_))
        ));
        let Some(Packet::DeviceInfo(info)) = recv_packet(&mut guest).await else {
            panic!("expected HID descriptor");
        };
        let (vendor, product, report_length) = (
            info.device_attributes.vendor_id,
            info.device_attributes.product_id,
            info.descriptor_info.descriptor_list.report_length,
        );
        assert_eq!((vendor, product, report_length), (0x045e, 0x0621, 67));
        assert_eq!(&info.report_descriptor[..67], &protocol::REPORT_DESCRIPTOR);
        assert!(!sink.is_active());
        let mut buffer = [0; 256];
        assert!(guest.recv(&mut buffer).now_or_never().is_none());
        send_packet(
            &mut guest,
            protocol::SYNTHHID_INIT_DEVICE_INFO_ACK,
            1,
            &protocol::MessageDeviceInfoAck { acknowledged: 1 },
        )
        .await
        .unwrap();
        assert!(run.as_mut().now_or_never().is_none());
        assert!(sink.is_active());
        assert_report(&mut guest, 1, 0).await;
        for (mask, buttons, wheel) in [
            (0, 0, 0),
            (2, 4, 0),
            (4, 2, 0),
            (7, 7, 0),
            (8, 0, 1),
            (16, 0, -1),
        ] {
            sink.send(MouseData {
                button_mask: mask,
                x: 123,
                y: 32767,
            });
            assert!(run.as_mut().now_or_never().is_none());
            assert_report(&mut guest, buttons, wheel).await;
        }
    }
    mouse.close().await;
    assert!(!sink.is_active());
    let mut source = mouse.into_source();
    sink.send(MouseData {
        button_mask: 0,
        x: 5,
        y: 6,
    });
    let input = source.next().await.unwrap();
    assert_eq!((input.x, input.y), (5, 6));
}

// Test: Save after sending HID information but before the guest acknowledges it.
// Expected: Restore waits for that acknowledgement, without repeating protocol negotiation.
#[async_test]
async fn mouse_restore_resumes_pending_hid_ack() {
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest).unwrap();
    let (source, mut sink) = input_pair();
    let mut mouse = Mouse::new(Box::new(source));
    let mut channel = mouse.open(host, memory).unwrap();
    {
        let mut run = pin!(StopTask::run_unstoppable(async |stop| mouse
            .run(stop, &mut channel)
            .await));
        request_protocol(&mut guest).await;
        assert!(run.as_mut().now_or_never().is_none());
        recv_packet(&mut guest).await.unwrap();
        recv_packet(&mut guest).await.unwrap();
    }
    let saved = mouse.supports_save_restore().unwrap().save_open(&channel);
    let saved = mesh::payload::decode(&mesh::payload::encode(saved)).unwrap();
    drop(channel);
    let (host, guest_channel, _memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest_channel).unwrap();
    let mut channel = mouse.restore_open(saved, host).unwrap();
    {
        let mut run = pin!(StopTask::run_unstoppable(async |stop| mouse
            .run(stop, &mut channel)
            .await));
        assert!(run.as_mut().now_or_never().is_none());
        let mut bytes = [0; 256];
        assert!(guest.recv(&mut bytes).now_or_never().is_none());
        assert!(!sink.is_active());
        send_packet(
            &mut guest,
            protocol::SYNTHHID_INIT_DEVICE_INFO_ACK,
            1,
            &protocol::MessageDeviceInfoAck { acknowledged: 1 },
        )
        .await
        .unwrap();
        sink.send(MouseData {
            button_mask: 4,
            x: 123,
            y: 32767,
        });
        assert!(run.as_mut().now_or_never().is_none());
        assert_report(&mut guest, 2, 0).await;
    }
}

// Test: Negotiate the mouse, then send another protocol request instead of a HID ack.
// Expected: The channel rejects the out-of-order request with the typed order error.
#[async_test]
async fn mouse_rejects_protocol_request_when_awaiting_hid_ack(driver: DefaultDriver) {
    let (host, mut guest) = connected_message_pipes(16384);
    let (source, _sink) = input_pair();
    let worker = start_worker(&driver, Mouse::new(Box::new(source)), host);
    for _ in 0..2 {
        send_packet(
            &mut guest,
            protocol::SYNTHHID_PROTOCOL_REQUEST,
            4,
            &protocol::MessageProtocolRequest {
                version: protocol::SYNTHHID_INPUT_VERSION,
            },
        )
        .await
        .unwrap();
    }

    assert!(matches!(worker.await, Err(Error::UnexpectedPacketOrder)));
}

// Test: Stop the public mouse runner during accepted input, then restart it.
// Expected: The accepted report is retained and cancellation leaves the device restartable.
#[async_test]
async fn public_mouse_runner_remains_restartable_after_cancellation(driver: DefaultDriver) {
    let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("mouse-lifecycle");
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest).unwrap();
    let (source, gate) = gated_input(Some(MouseData {
        button_mask: 1,
        x: 123,
        y: 32767,
    }));
    let mut device = Mouse::new(Box::new(source));
    let channel = device.open(host, memory).unwrap();
    request_protocol(&mut guest).await;
    send_packet(
        &mut guest,
        protocol::SYNTHHID_INIT_DEVICE_INFO_ACK,
        1,
        &protocol::MessageDeviceInfoAck { acknowledged: 1 },
    )
    .await
    .unwrap();
    let mut task =
        task_control::TaskControl::new(crate::test_helpers::DeviceWorker { device, channel });
    task.insert(&worker_driver, "mouse", ());
    assert!(task.start());
    gate.stop(&mut task, &driver).await;
    recv_packet(&mut guest).await.unwrap();
    recv_packet(&mut guest).await.unwrap();
    assert_report(&mut guest, 1, 0).await;
    assert!(task.start());
    vmbus_channel::test_helpers::with_timeout(&driver, assert_report(&mut guest, 1, 0)).await;
    vmbus_channel::test_helpers::stop_with_timeout(&mut task, &driver).await;
}

// Test: Close mouse input after HID activation, then send another protocol request.
// Expected: Input EOF keeps the channel open; the unexpected request terminates the runner.
#[async_test]
async fn mouse_input_eof_preserves_guest_request_handling() {
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest).unwrap();
    let (source, sink) = input_pair();
    let mut mouse = Mouse::new(Box::new(source));
    let mut channel = mouse.open(host, memory).unwrap();
    request_protocol(&mut guest).await;
    send_packet(
        &mut guest,
        protocol::SYNTHHID_INIT_DEVICE_INFO_ACK,
        1,
        &protocol::MessageDeviceInfoAck { acknowledged: 1 },
    )
    .await
    .unwrap();
    let mut run = pin!(StopTask::run_unstoppable(async |stop| mouse
        .run(stop, &mut channel)
        .await));
    assert!(run.as_mut().now_or_never().is_none());
    recv_packet(&mut guest).await.unwrap();
    recv_packet(&mut guest).await.unwrap();
    drop(sink);
    assert!(run.as_mut().now_or_never().is_none());
    request_protocol(&mut guest).await;
    run.as_mut()
        .now_or_never()
        .expect("unexpected active-state request must terminate the public runner")
        .expect("protocol failure is not task cancellation");
}
