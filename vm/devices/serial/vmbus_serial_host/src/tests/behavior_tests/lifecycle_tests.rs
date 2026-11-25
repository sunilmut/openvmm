// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn modem(guest: &mut MessagePipe<FlatRingMem>, connected: bool) {
    assert_eq!(
        receive(guest),
        protocol::SetModumStatusMessage {
            header: protocol::Header::new_guest_notification(
                protocol::GuestNotifications::SET_MODEM_STATUS
            ),
            modem_status: if connected { 0xbb } else { 0x0b },
            is_connected: connected.into(),
        }
        .as_bytes()
    );
}

// Test: Offer COM1 and COM2 and query their migration capability.
// Expected: Each port advertises its distinct protocol instance/name and common message-pipe interface, and unsupported save/restore is reported as unavailable.
#[test]
fn serial_ports_advertise_distinct_message_pipe_offers_without_migration() {
    for (port, name, instance) in [
        (
            Port::Com1,
            "serial_com1",
            protocol::UART_INTERFACE_INSTANCE_COM1,
        ),
        (
            Port::Com2,
            "serial_com2",
            protocol::UART_INTERFACE_INSTANCE_COM2,
        ),
    ] {
        let mut serial = Serial::new(port, Box::new(Disconnected));
        let offer = serial.offer();
        assert_eq!(offer.interface_name, name);
        assert_eq!(offer.interface_id, protocol::UART_INTERFACE_TYPE);
        assert_eq!(offer.instance_id, instance);
        assert!(matches!(
            offer.channel_type,
            ChannelType::Pipe {
                message_mode: true,
                ..
            }
        ));
        assert!(serial.supports_save_restore().is_none());
    }
}

// Test: Report EOF after negotiation, fail a reconnect once, then reconnect and deliver binary input after a transient read error.
// Expected: The guest observes exact disconnected/connected modem transitions, backend errors produce no false data notification, and subsequent real input is delivered intact.
#[test]
fn eof_reconnect_and_read_errors_preserve_modem_and_input_contracts() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    modem(&mut guest, true);
    backend.lock().eof = true;
    step(&mut channel, &mut serial);
    modem(&mut guest, false);
    backend.lock().fail_connect = true;
    assert!(channel.process_ready(&mut serial).now_or_never().is_none());
    {
        let mut backend = backend.lock();
        backend.connect = true;
        backend.fail_read = true;
    }
    step(&mut channel, &mut serial);
    modem(&mut guest, true);
    let mut buffer = [0; 512];
    assert!(guest.recv(&mut buffer).now_or_never().is_none());
    backend.lock().input.extend([0, 0x81, 0xff]);
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
    assert_eq!(&response.buffer[..3], &[0, 0x81, 0xff]);
}

// Test: Fill the 1024-byte RX cache, leave extra input pending, encounter a disconnect-poll error, and disconnect/reconnect before draining it.
// Expected: Full-cache polling neither overreads nor loses input, actual disconnect/reconnect produces exact modem packets, and all 1100 original bytes are eventually returned once in order.
#[test]
fn full_rx_cache_preserves_pending_input_across_disconnect_and_reconnect() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    modem(&mut guest, true);
    let input: Vec<_> = (0..1100).map(|value| (value % 251) as u8).collect();
    backend.lock().input.extend(&input);
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::Header::new_guest_notification(protocol::GuestNotifications::RX_DATA_AVAILABLE)
            .as_bytes()
    );
    assert_eq!(backend.lock().input.len(), 76);
    backend.lock().fail_disconnect = true;
    assert!(channel.process_ready(&mut serial).now_or_never().is_none());
    backend.lock().disconnect = true;
    step(&mut channel, &mut serial);
    modem(&mut guest, false);
    backend.lock().connect = true;
    step(&mut channel, &mut serial);
    modem(&mut guest, true);
    let mut output = Vec::new();
    while output.len() < input.len() {
        guest
            .try_send(protocol::Header::new_host_request(HostRequests::GET_RX_DATA).as_bytes())
            .unwrap();
        step(&mut channel, &mut serial);
        let response = protocol::RxDataResponse::read_from_bytes(&receive(&mut guest)).unwrap();
        assert!(response.buffer_length > 0);
        output.extend_from_slice(&response.buffer[..response.buffer_length as usize]);
        assert_eq!(
            response.more_data_available,
            u8::from(output.len() < input.len())
        );
    }
    assert_eq!(output, input);
    assert!(backend.lock().input.is_empty());
}

// Test: Drive the public test protocol runner concurrently with a guest that negotiates, observes modem status, and closes its real ring endpoint.
// Expected: The full ready-state processing loop sends exact responses and returns cleanly when the guest closes, without requiring cancellation or panicking.
#[async_test]
async fn full_protocol_runner_finishes_cleanly_after_guest_channel_closes(driver: DefaultDriver) {
    let (mut serial, mut channel, mut guest, _) = fixture();
    let server = channel.test_process(&mut serial);
    let client = async {
        guest
            .try_send(
                protocol::VersionRequestMessage {
                    header: protocol::Header::new_host_request(HostRequests::VERSION),
                    requested_version: protocol::ProtocolVersions::MANGANESE,
                }
                .as_bytes(),
            )
            .unwrap();
        let mut bytes = [0; 512];
        let len = with_timeout(&driver, guest.recv(&mut bytes)).await.unwrap();
        assert_eq!(
            &bytes[..len],
            protocol::VersionRequestResponse {
                header: protocol::Header::new_host_response(HostRequests::VERSION),
                version_accepted: 1,
                pad: 0
            }
            .as_bytes()
        );
        let len = with_timeout(&driver, guest.recv(&mut bytes)).await.unwrap();
        assert_eq!(
            &bytes[..len],
            protocol::SetModumStatusMessage {
                header: protocol::Header::new_guest_notification(
                    protocol::GuestNotifications::SET_MODEM_STATUS
                ),
                modem_status: 0xbb,
                is_connected: 1
            }
            .as_bytes()
        );
        drop(guest);
    };
    with_timeout(&driver, async {
        futures::join!(server, client);
    })
    .await;
}
