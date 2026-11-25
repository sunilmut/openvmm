// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Negotiate with the wrong first packet or an unsupported protocol version.
// Expected: Invalid order and unsupported version return distinct typed errors and publish no successful negotiation response.
#[test]
fn invalid_negotiation_is_rejected_without_a_success_response() {
    for (header, version, bad_order) in [
        (
            protocol::Header::new_host_request(HostRequests::GET_RX_DATA),
            protocol::ProtocolVersions::MANGANESE,
            true,
        ),
        (
            protocol::Header::new_host_request(HostRequests::VERSION),
            protocol::ProtocolVersions(0),
            false,
        ),
        (
            protocol::Header::new_host_request(HostRequests::VERSION),
            protocol::ProtocolVersions(u32::MAX),
            false,
        ),
    ] {
        let (_, mut channel, mut guest, _) = fixture();
        guest
            .try_send(
                protocol::VersionRequestMessage {
                    header,
                    requested_version: version,
                }
                .as_bytes(),
            )
            .unwrap();
        let error = channel.process_init().now_or_never().unwrap().unwrap_err();
        assert!(if bad_order {
            matches!(error, Error::UnexpectedPacketOrder)
        } else {
            matches!(error, Error::InvalidVersionNegotiation)
        });
        let mut bytes = [0; 512];
        assert!(guest.recv(&mut bytes).now_or_never().is_none());
    }
}

// Test: Decode truncated headers/TX messages, invalid versions/types, unknown request/notification IDs, and oversized TX lengths.
// Expected: Every malformed packet returns its specific typed protocol error rather than panicking, produces no response, and never writes bytes to the serial backend.
#[test]
fn malformed_wire_packets_return_typed_errors_without_backend_output() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    for len in 0..size_of::<protocol::Header>() {
        assert!(
            matches!(channel.process_header(&mut serial, &vec![0; len]), Err(Error::MessageSizeHeader(size)) if size == len)
        );
    }
    let mut header = protocol::Header::new_host_request(HostRequests::GET_RX_DATA);
    header.message_version = protocol::MessageVersions(0xff);
    assert!(matches!(
        channel.process_header(&mut serial, header.as_bytes()),
        Err(Error::InvalidMessageHeaderVersion)
    ));
    header.message_version = protocol::MessageVersions::HEADER_VERSION_1;
    for kind in [0, 3, 4, 0xff] {
        header.message_type = protocol::MessageTypes(kind);
        assert!(
            matches!(channel.process_header(&mut serial, header.as_bytes()), Err(Error::BadMessageType(value)) if value == kind)
        );
    }
    for request in [
        HostRequests::VERSION,
        HostRequests::INVALID,
        HostRequests(u16::MAX),
    ] {
        assert!(
            matches!(channel.process_header(&mut serial, protocol::Header::new_host_request(request).as_bytes()), Err(Error::UnknownHostRequest { request: actual }) if actual == request)
        );
    }
    for notification in [HostNotifications::INVALID, HostNotifications(0xff)] {
        assert!(
            matches!(channel.process_header(&mut serial, protocol::Header::new_host_notification(notification).as_bytes()), Err(Error::UnknownHostNotification { notification: actual }) if actual == notification)
        );
    }
    let message = tx_message(b"not-transmitted");
    for len in size_of::<protocol::Header>()..size_of::<protocol::TxDataAvailableMessage>() {
        assert!(
            matches!(channel.process_header(&mut serial, &message.as_bytes()[..len]), Err(Error::MessageSizeHostNotification { len: actual, notification: HostNotifications::TX_DATA_AVAILABLE }) if actual == len)
        );
    }
    for len in [65, 255] {
        let (mut serial, mut channel, _, backend) = fixture();
        let mut message = tx_message(&[]);
        message.buffer_length = len;
        assert!(
            matches!(channel.process_header(&mut serial, message.as_bytes()), Err(Error::TxDataLength(actual)) if actual == len)
        );
        assert!(backend.lock().output.is_empty());
    }
    assert!(backend.lock().output.is_empty());
    let mut bytes = [0; 512];
    assert!(guest.recv(&mut bytes).now_or_never().is_none());
}

// Test: Hold the serial backend pending while a TX is accepted, then submit another TX before completion and finally release the backend.
// Expected: The overlapping batch is rejected as in flight, accepted bytes survive backpressure exactly once, and the next legal TX is accepted after the completion notification.
#[test]
fn overlapping_tx_is_rejected_without_losing_the_accepted_batch() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    receive(&mut guest);
    backend.lock().write_pending = true;
    guest.try_send(tx_message(b"accepted").as_bytes()).unwrap();
    step(&mut channel, &mut serial);
    guest.try_send(tx_message(b"rejected").as_bytes()).unwrap();
    assert!(matches!(
        channel.process_ready(&mut serial).now_or_never().unwrap(),
        Err(Error::TxInFlight)
    ));
    assert!(backend.lock().output.is_empty());
    backend.lock().write_pending = false;
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::Header::new_guest_notification(protocol::GuestNotifications::TX_COMPLETED)
            .as_bytes()
    );
    guest.try_send(tx_message(b"later").as_bytes()).unwrap();
    step(&mut channel, &mut serial);
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::Header::new_guest_notification(protocol::GuestNotifications::TX_COMPLETED)
            .as_bytes()
    );
    assert_eq!(backend.lock().output, b"acceptedlater");
}

// Test: Read host input into the RX cache, clear it over the ring, query the empty cache, then provide new input.
// Expected: Cleared bytes are not returned, the empty response is fully zero padded, and new input triggers a fresh availability notification with only the new bytes.
#[test]
fn rx_clear_discards_old_bytes_and_new_input_rearms_notification() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    receive(&mut guest);
    backend.lock().input.extend(b"old-input");
    step(&mut channel, &mut serial);
    receive(&mut guest);
    guest
        .try_send(
            protocol::Header::new_host_notification(HostNotifications::RX_CLEAR_BUFFER).as_bytes(),
        )
        .unwrap();
    step(&mut channel, &mut serial);
    guest
        .try_send(protocol::Header::new_host_request(HostRequests::GET_RX_DATA).as_bytes())
        .unwrap();
    step(&mut channel, &mut serial);
    let response = protocol::RxDataResponse::read_from_bytes(&receive(&mut guest)).unwrap();
    assert_eq!(response.buffer_length, 0);
    assert_eq!(response.more_data_available, 0);
    assert_eq!(response.buffer, [0; 64]);
    backend.lock().input.extend(b"new");
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::Header::new_guest_notification(protocol::GuestNotifications::RX_DATA_AVAILABLE)
            .as_bytes()
    );
    guest
        .try_send(protocol::Header::new_host_request(HostRequests::GET_RX_DATA).as_bytes())
        .unwrap();
    step(&mut channel, &mut serial);
    let response = protocol::RxDataResponse::read_from_bytes(&receive(&mut guest)).unwrap();
    assert_eq!(response.buffer_length, 3);
    assert_eq!(&response.buffer[..3], b"new");
    assert_eq!(&response.buffer[3..], &[0; 61]);
}
