// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vmbus_channel::connected_async_channels;
use vmbus_ring::FlatRingMem;

#[cfg(target_os = "linux")]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;

fn pair() -> (ShutdownGuestChannel<FlatRingMem>, MessagePipe<FlatRingMem>) {
    let (guest, host) = connected_async_channels(16384);
    (
        ShutdownGuestChannel::new(MessagePipe::new(guest).unwrap()),
        MessagePipe::new(host).unwrap(),
    )
}

fn negotiation(
    framework: &[hyperv_ic_protocol::Version],
    message: &[hyperv_ic_protocol::Version],
    transaction: bool,
) -> Vec<u8> {
    let body = hyperv_ic_protocol::NegotiateMessage {
        framework_version_count: framework.len() as u16,
        message_version_count: message.len() as u16,
        ..FromZeros::new_zeroed()
    };
    let header = hyperv_ic_protocol::Header {
        message_type: hyperv_ic_protocol::MessageType::VERSION_NEGOTIATION,
        message_size: (size_of_val(&body) + size_of_val(framework) + size_of_val(message)) as u16,
        transaction_id: 0x51,
        flags: hyperv_ic_protocol::HeaderFlags::new()
            .with_request(true)
            .with_transaction(transaction),
        ..FromZeros::new_zeroed()
    };
    [
        header.as_bytes(),
        body.as_bytes(),
        framework.as_bytes(),
        message.as_bytes(),
    ]
    .concat()
}

async fn receive<M: RingMem + Unpin>(driver: &DefaultDriver, host: &mut MessagePipe<M>) -> Vec<u8> {
    let mut buffer = vec![0; hyperv_ic_protocol::MAX_MESSAGE_SIZE];
    let length = with_timeout(driver, host.recv(&mut buffer)).await.unwrap();
    buffer.truncate(length);
    buffer
}

async fn negotiate(
    driver: &DefaultDriver,
    channel: &mut ShutdownGuestChannel<FlatRingMem>,
    host: &mut MessagePipe<FlatRingMem>,
    ic: &ShutdownGuestIc,
    framework: &[hyperv_ic_protocol::Version],
    message: &[hyperv_ic_protocol::Version],
    expected: [hyperv_ic_protocol::Version; 2],
    transaction: bool,
) {
    channel
        .handle_host_message(&negotiation(framework, message, transaction), ic)
        .await;
    let body = hyperv_ic_protocol::NegotiateMessage {
        framework_version_count: 1,
        message_version_count: 1,
        ..FromZeros::new_zeroed()
    };
    let header = hyperv_ic_protocol::Header {
        message_type: hyperv_ic_protocol::MessageType::VERSION_NEGOTIATION,
        message_size: (size_of_val(&body) + size_of_val(&expected)) as u16,
        transaction_id: 0x51,
        status: Status::SUCCESS,
        flags: hyperv_ic_protocol::HeaderFlags::new()
            .with_transaction(transaction)
            .with_response(true),
        ..FromZeros::new_zeroed()
    };
    assert_eq!(
        receive(driver, host).await,
        [header.as_bytes(), body.as_bytes(), expected.as_bytes()].concat()
    );
}

// Test: Negotiate shuffled/duplicate supported versions, then renegotiate an older version on the same live channel.
// Expected: The exact response selects the newest offered supported versions independently, preserves transaction ID/transaction flag, marks response rather than request, and subsequent negotiation replaces the selected versions.
#[async_test]
async fn version_negotiation_selects_latest_and_supports_renegotiation(driver: DefaultDriver) {
    let (mut channel, mut host) = pair();
    let ic = ShutdownGuestIc::new();
    negotiate(
        &driver,
        &mut channel,
        &mut host,
        &ic,
        &[
            FRAMEWORK_VERSION_1,
            FRAMEWORK_VERSION_3,
            FRAMEWORK_VERSION_1,
        ],
        &[
            SHUTDOWN_VERSION_3_1,
            SHUTDOWN_VERSION_1,
            SHUTDOWN_VERSION_3_2,
            SHUTDOWN_VERSION_3,
            SHUTDOWN_VERSION_3_2,
        ],
        [FRAMEWORK_VERSION_3, SHUTDOWN_VERSION_3_2],
        true,
    )
    .await;
    negotiate(
        &driver,
        &mut channel,
        &mut host,
        &ic,
        &[FRAMEWORK_VERSION_1],
        &[SHUTDOWN_VERSION_1],
        [FRAMEWORK_VERSION_1, SHUTDOWN_VERSION_1],
        false,
    )
    .await;
}

fn shutdown_packet(restart: bool, hibernate: bool, force: bool) -> Vec<u8> {
    let body = hyperv_ic_protocol::shutdown::ShutdownMessage {
        reason_code: 0x80000000,
        timeout_secs: 7,
        flags: hyperv_ic_protocol::shutdown::ShutdownFlags::new()
            .with_restart(restart)
            .with_hibernate(hibernate)
            .with_force(force),
        message: [0; 2048],
    };
    let header = hyperv_ic_protocol::Header {
        message_type: hyperv_ic_protocol::MessageType::SHUTDOWN,
        message_size: size_of_val(&body) as u16,
        transaction_id: 0x2a,
        flags: hyperv_ic_protocol::HeaderFlags::new()
            .with_request(true)
            .with_transaction(true),
        ..FromZeros::new_zeroed()
    };
    [header.as_bytes(), body.as_bytes()].concat()
}

fn shutdown_response(status: Status) -> Vec<u8> {
    hyperv_ic_protocol::Header {
        framework_version: FRAMEWORK_VERSION_1,
        message_version: SHUTDOWN_VERSION_3_1,
        message_type: hyperv_ic_protocol::MessageType::SHUTDOWN,
        transaction_id: 0x2a,
        status,
        flags: hyperv_ic_protocol::HeaderFlags::new()
            .with_response(true)
            .with_transaction(true),
        ..FromZeros::new_zeroed()
    }
    .as_bytes()
    .to_vec()
}

// Test: Forward shutdown flags/results, drop an individual notifier RPC and recover on the same connection, then close the listener.
// Expected: Flags, statuses and negotiated response headers remain exact; no reply precedes RPC resolution, dropping a request yields FAIL without hanging, and a live listener can subsequently return SUCCESS.
#[async_test]
async fn shutdown_rpc_flags_results_and_disconnection_map_to_exact_replies(driver: DefaultDriver) {
    let (mut channel, mut host) = pair();
    let mut ic = ShutdownGuestIc::new();
    let mut notifier = ic.get_shutdown_notifier();
    negotiate(
        &driver,
        &mut channel,
        &mut host,
        &ic,
        &[FRAMEWORK_VERSION_1],
        &[SHUTDOWN_VERSION_3_1],
        [FRAMEWORK_VERSION_1, SHUTDOWN_VERSION_3_1],
        true,
    )
    .await;
    for (restart, hibernate, force, expected_type, result, status) in [
        (
            false,
            false,
            false,
            ShutdownType::PowerOff,
            ShutdownResult::Ok,
            Status::SUCCESS,
        ),
        (
            true,
            false,
            true,
            ShutdownType::Reboot,
            ShutdownResult::Failed(0x80070005),
            Status(0x80070005),
        ),
        (
            false,
            true,
            false,
            ShutdownType::Hibernate,
            ShutdownResult::NotReady,
            Status::FAIL,
        ),
        (
            true,
            true,
            true,
            ShutdownType::Reboot,
            ShutdownResult::AlreadyInProgress,
            Status::FAIL,
        ),
    ] {
        let packet = shutdown_packet(restart, hibernate, force);
        with_timeout(&driver, async {
            futures::join!(channel.handle_host_message(&packet, &ic), async {
                notifier.recv().await.unwrap().handle_sync(|params| {
                    assert_eq!(
                        std::mem::discriminant(&params.shutdown_type),
                        std::mem::discriminant(&expected_type)
                    );
                    assert_eq!(params.force, force);
                    result
                });
            });
        })
        .await;
        assert_eq!(receive(&driver, &mut host).await, shutdown_response(status));
        assert!(notifier.recv().now_or_never().is_none());
    }
    for cancel in [true, false] {
        let packet = shutdown_packet(false, false, false);
        with_timeout(&driver, async {
            futures::join!(channel.handle_host_message(&packet, &ic), async {
                let request = notifier.recv().await.unwrap();
                assert!(host.recv(&mut [0; 4096]).now_or_never().is_none());
                if cancel {
                    drop(request);
                } else {
                    request.handle_sync(|_| ShutdownResult::Ok);
                }
            });
        })
        .await;
        assert_eq!(
            receive(&driver, &mut host).await,
            shutdown_response(if cancel {
                Status::FAIL
            } else {
                Status::SUCCESS
            })
        );
        assert_no_output(&mut host, &mut notifier);
    }
    drop(notifier);
    with_timeout(
        &driver,
        channel.handle_host_message(&shutdown_packet(false, false, true), &ic),
    )
    .await;
    assert_eq!(
        receive(&driver, &mut host).await,
        shutdown_response(Status::FAIL)
    );
}

fn assert_no_output(
    host: &mut MessagePipe<FlatRingMem>,
    notifier: &mut mesh::Receiver<Rpc<ShutdownParams, ShutdownResult>>,
) {
    assert!(host.recv(&mut [0; 4096]).now_or_never().is_none());
    assert!(notifier.recv().now_or_never().is_none());
}

// Test: Send shutdown before negotiation, every truncated IC header/negotiation prefix, an unknown message type, and truncated shutdown bodies; follow them with valid negotiation and shutdown.
// Expected: Invalid/unnegotiated traffic produces no reply or notification and never panics; a later valid request still delivers exactly one shutdown and its successful negotiated response.
#[async_test]
async fn malformed_and_unnegotiated_packets_do_not_notify_and_recover(driver: DefaultDriver) {
    let (mut channel, mut host) = pair();
    let mut ic = ShutdownGuestIc::new();
    let mut notifier = ic.get_shutdown_notifier();
    channel
        .handle_host_message(&shutdown_packet(false, false, false), &ic)
        .await;
    assert_no_output(&mut host, &mut notifier);
    for length in 0..size_of::<hyperv_ic_protocol::Header>() {
        channel.handle_host_message(&vec![0; length], &ic).await;
        assert_no_output(&mut host, &mut notifier);
    }
    let packet = negotiation(&[FRAMEWORK_VERSION_1], &[SHUTDOWN_VERSION_3_1], true);
    for length in 0..size_of::<hyperv_ic_protocol::NegotiateMessage>() {
        channel
            .handle_host_message(
                &packet[..size_of::<hyperv_ic_protocol::Header>() + length],
                &ic,
            )
            .await;
        assert_no_output(&mut host, &mut notifier);
    }
    let header = hyperv_ic_protocol::Header {
        message_type: hyperv_ic_protocol::MessageType(0xffff),
        ..FromZeros::new_zeroed()
    };
    channel.handle_host_message(header.as_bytes(), &ic).await;
    assert_no_output(&mut host, &mut notifier);
    negotiate(
        &driver,
        &mut channel,
        &mut host,
        &ic,
        &[FRAMEWORK_VERSION_1],
        &[SHUTDOWN_VERSION_3_1],
        [FRAMEWORK_VERSION_1, SHUTDOWN_VERSION_3_1],
        true,
    )
    .await;
    let packet = shutdown_packet(false, false, false);
    for length in [
        0,
        1,
        size_of::<hyperv_ic_protocol::shutdown::ShutdownMessage>() - 1,
    ] {
        channel
            .handle_host_message(
                &packet[..size_of::<hyperv_ic_protocol::Header>() + length],
                &ic,
            )
            .await;
        assert_no_output(&mut host, &mut notifier);
    }
    with_timeout(&driver, async {
        futures::join!(channel.handle_host_message(&packet, &ic), async {
            notifier.recv().await.unwrap().handle_sync(|params| {
                assert!(matches!(params.shutdown_type, ShutdownType::PowerOff));
                assert!(!params.force);
                ShutdownResult::Ok
            });
        });
    })
    .await;
    assert_eq!(
        receive(&driver, &mut host).await,
        shutdown_response(Status::SUCCESS)
    );
    assert_no_output(&mut host, &mut notifier);
}
