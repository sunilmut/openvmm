// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::GUEST_CID;
use super::HDR_SIZE;
use super::QUEUE_SIZE;
use super::RX_AVAIL_ADDR;
use super::RX_DESC_ADDR;
use super::RX_USED_ADDR;
use super::TestHarness;
use crate::spec::*;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use virtio::QueueResources;
use virtio::VirtioDevice;
use virtio::queue::QueueParams;
use virtio::spec::VirtioDeviceFeatures;
use vmcore::interrupt::Interrupt;

async fn expect_reset(harness: &mut TestHarness, header: &VsockHeader, data: &[u8]) {
    let (_, address) = harness.post_rx_buffer(HDR_SIZE + 64);
    harness.post_tx_packet(header, data);
    harness.wait_for_tx_used().await;
    let (_, length) = harness.wait_for_rx_used().await;
    assert_eq!(length, HDR_SIZE);
    let reply = harness.read_header(address);
    assert_eq!(
        (reply.src_cid, reply.dst_cid, reply.src_port, reply.dst_port),
        (VSOCK_CID_HOST, GUEST_CID, header.dst_port, header.src_port)
    );
    assert_eq!((reply.operation(), reply.len), (Operation::RST, 0));
}

fn rx_resources(harness: &TestHarness) -> QueueResources {
    QueueResources {
        params: QueueParams {
            size: QUEUE_SIZE,
            enable: true,
            desc_addr: RX_DESC_ADDR,
            avail_addr: RX_AVAIL_ADDR,
            used_addr: RX_USED_ADDR,
        },
        notify: Interrupt::from_event(harness.rx_interrupt_event.clone()),
        event: harness.rx_queue_event.clone(),
        guest_memory: harness.mem.clone(),
    }
}

// Test: Send invalid addresses/types/operations and control packets for absent peers.
// Expected: Each packet receives a correctly addressed, header-only RST; the worker survives.
#[async_test]
async fn malformed_and_unconnected_packets_get_canonical_resets(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver, tempfile::tempdir().unwrap());
    harness.enable().await;
    let header = harness.guest_header(1024, 65000, Operation::REQUEST, 0, 0);
    let mut malformed = [header; 4];
    malformed[0].src_cid = 17;
    malformed[1].dst_cid = 18;
    malformed[2].socket_type = u16::MAX;
    malformed[3].op = u16::MAX;
    for (index, mut header) in malformed.into_iter().enumerate() {
        header.src_port += index as u32;
        expect_reset(&mut harness, &header, &[]).await;
    }
    for (index, operation) in [
        Operation::RESPONSE,
        Operation::SHUTDOWN,
        Operation::RW,
        Operation::CREDIT_UPDATE,
        Operation::CREDIT_REQUEST,
    ]
    .into_iter()
    .enumerate()
    {
        let header = harness.guest_header(2000 + index as u32, 65000, operation, 0, 0);
        expect_reset(&mut harness, &header, &[]).await;
    }
}

// Test: Send a duplicate connection request for an already established port pair.
// Expected: The old connection is reset, and later data cannot use that connection.
#[async_test]
async fn duplicate_request_removes_the_existing_connection(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver, tempfile::tempdir().unwrap());
    let mut listener = harness.create_port_listener(1234);
    harness.enable().await;
    let _host = harness
        .connect_guest_to_host(&mut listener, 1024, 1234)
        .await;
    let duplicate = harness.guest_header(1024, 1234, Operation::REQUEST, 0, 0);
    expect_reset(&mut harness, &duplicate, &[]).await;
    let data = harness.guest_header(1024, 1234, Operation::RW, 3, 0);
    expect_reset(&mut harness, &data, b"old").await;
}

// Test: Request flow-control credit after a guest-initiated handshake.
// Expected: The reply advertises usable receive capacity and no unreceived bytes.
#[async_test]
async fn credit_request_returns_current_receive_window(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver, tempfile::tempdir().unwrap());
    let mut listener = harness.create_port_listener(1234);
    harness.enable().await;
    let _host = harness
        .connect_guest_to_host(&mut listener, 1024, 1234)
        .await;
    let (_, address) = harness.post_rx_buffer(HDR_SIZE + 64);
    let header = harness.guest_header(1024, 1234, Operation::CREDIT_REQUEST, 0, 0);
    harness.post_tx_packet(&header, &[]);
    harness.wait_for_tx_used().await;
    let (_, length) = harness.wait_for_rx_used().await;
    assert_eq!(length, HDR_SIZE);
    let reply = harness.read_header(address);
    assert_eq!(reply.operation(), Operation::CREDIT_UPDATE);
    assert_eq!(
        (reply.src_cid, reply.dst_cid, reply.src_port, reply.dst_port),
        (VSOCK_CID_HOST, GUEST_CID, 1234, 1024)
    );
    let (capacity, forwarded) = (reply.buf_alloc, reply.fwd_cnt);
    assert!(capacity > 0);
    assert_eq!(forwarded, 0);
}

// Test: Send payload after the guest has shut down its send half.
// Expected: The protocol violation resets the connection rather than forwarding data.
#[async_test]
async fn data_after_send_shutdown_resets_the_connection(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver, tempfile::tempdir().unwrap());
    let mut listener = harness.create_port_listener(1234);
    harness.enable().await;
    let _host = harness
        .connect_guest_to_host(&mut listener, 1024, 1234)
        .await;
    let shutdown = harness.guest_header(
        1024,
        1234,
        Operation::SHUTDOWN,
        0,
        ShutdownFlags::new().with_send(true).into_bits(),
    );
    harness.post_tx_packet(&shutdown, &[]);
    harness.wait_for_tx_used().await;
    let data = harness.guest_header(1024, 1234, Operation::RW, 4, 0);
    expect_reset(&mut harness, &data, b"late").await;
    let credit = harness.guest_header(1024, 1234, Operation::CREDIT_REQUEST, 0, 0);
    expect_reset(&mut harness, &credit, &[]).await;
}

// Test: Reject invalid queue setup, then stop and resume the running receive queue.
// Expected: Errors do not poison setup; saved ring indices resume without replay or loss.
#[async_test]
async fn queue_validation_and_restart_preserve_ring_progress(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver, tempfile::tempdir().unwrap());
    let features = VirtioDeviceFeatures::new();
    let resources = rx_resources(&harness);
    let err = harness
        .device
        .start_queue(3, resources, &features, None)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("invalid queue index"));
    let unsupported = VirtioDeviceFeatures::new().with_device_specific_low(
        VsockFeaturesBank0::new()
            .with_no_implied_stream(true)
            .into_bits(),
    );
    let resources = rx_resources(&harness);
    let err = harness
        .device
        .start_queue(0, resources, &unsupported, None)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("guest does not support stream sockets"));
    let resources = rx_resources(&harness);
    harness
        .device
        .start_queue(0, resources, &features, None)
        .await
        .unwrap();
    let resources = rx_resources(&harness);
    let err = harness
        .device
        .start_queue(0, resources, &features, None)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("already started"));
    assert!(harness.device.stop_queue(0).await.is_some());
    assert!(harness.device.stop_queue(0).await.is_none());

    harness.enable().await;
    let header = harness.guest_header(1024, 65000, Operation::CREDIT_REQUEST, 0, 0);
    expect_reset(&mut harness, &header, &[]).await;
    let state = harness.device.stop_queue(0).await.unwrap();
    assert_eq!((state.avail_index, state.used_index), (1, 1));
    let resources = rx_resources(&harness);
    harness
        .device
        .start_queue(0, resources, &features, Some(state))
        .await
        .unwrap();
    let header = harness.guest_header(1025, 65000, Operation::CREDIT_REQUEST, 0, 0);
    expect_reset(&mut harness, &header, &[]).await;
    let state = harness.device.stop_queue(0).await.unwrap();
    assert_eq!((state.avail_index, state.used_index), (2, 2));
    for index in [1, 2] {
        assert!(harness.device.stop_queue(index).await.is_some());
        assert!(harness.device.stop_queue(index).await.is_none());
    }
}
