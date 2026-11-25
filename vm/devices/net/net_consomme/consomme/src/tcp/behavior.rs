// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{ConsommeParams, DefaultDriver, TcpControl, TcpTestHarness, parse_tcp_packet};
use crate::TcpBufferBounds;
use std::task::Poll;
use std::time::Duration;

// Test: Fill and drain a guest-to-host receive window near its capacity twice.
// Expected: Host bytes are unchanged and advertised windows grow from 16 KiB
//       to 32 KiB and then the configured 64 KiB ceiling.
#[pal_async::async_test]
async fn receive_autotuning_grows_the_advertised_window_without_losing_bytes(
    driver: DefaultDriver,
) {
    let mut params = ConsommeParams::new().unwrap();
    params.tcp_rx_buffer = TcpBufferBounds {
        initial: 16 * 1024,
        max: 64 * 1024,
    };
    let mut harness = TcpTestHarness::connect_with_params(driver, params).await;
    let scale = harness
        .client
        .received_packets
        .lock()
        .iter()
        .filter_map(|bytes| TcpTestHarness::is_tcp_packet(bytes))
        .find(|tcp| tcp.control == TcpControl::Syn)
        .unwrap()
        .window_scale
        .unwrap();
    harness.buf.resize(65536, 0);
    for (length, expected_window) in [(13_000, 32 * 1024), (26_000, 64 * 1024)] {
        harness.clear_guest_packets();
        let payload = vec![0x5a; length];
        harness.send_data_next(&payload);
        let mut received = Vec::new();
        harness
            .poll_until_host_read(&mut received, payload.len())
            .await;
        assert_eq!(received, payload);
        let expected_ack = harness.guest_seq;
        let packet = harness
            .poll_until_guest_packet(|tcp| tcp.ack_number == Some(expected_ack))
            .await;
        let (_, _, ack) = parse_tcp_packet(&packet);
        assert_eq!(usize::from(ack.window_len) << scale, expected_window);
    }
}

// Test: Abort host TCP sockets both during normal traffic and after host FIN.
// Expected: The guest receives a reset acknowledging its current sequence;
//       neither host abort is mistaken for a successful graceful close.
#[pal_async::async_test]
async fn host_socket_aborts_reset_open_and_half_closed_guest_flows(driver: DefaultDriver) {
    for half_closed in [false, true] {
        let mut harness = TcpTestHarness::connect(driver.clone()).await;
        if half_closed {
            harness.host_shutdown_write();
            harness
                .poll_until_guest_packet(|tcp| tcp.control == TcpControl::Fin)
                .await;
        }
        harness.clear_guest_packets();
        let expected_ack = harness.guest_seq;
        let TcpTestHarness {
            mut consomme,
            mut client,
            host_stream,
            ..
        } = harness;
        socket2::SockRef::from(host_stream.get())
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(host_stream);
        let packet = std::future::poll_fn(|cx| {
            consomme.access(&mut client).poll(cx);
            client
                .received_packets
                .lock()
                .iter()
                .find(|bytes| {
                    TcpTestHarness::is_tcp_packet(bytes)
                        .is_some_and(|tcp| tcp.control == TcpControl::Rst)
                })
                .cloned()
                .map_or(Poll::Pending, Poll::Ready)
        })
        .await;
        let (_, _, reset) = parse_tcp_packet(&packet);
        assert_eq!(reset.ack_number, Some(expected_ack));
        assert!(reset.payload.is_empty());
    }
}
