// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::driver::OpenParams;
use crate::driver::open_channel;
use std::sync::atomic::AtomicUsize;
use test_with_tracing::test;
use user_driver::DmaClient;
use user_driver_emulated_mock::DeviceTestMemory;

fn offer() -> (
    OfferInfo,
    mesh::Receiver<ChannelRequest>,
    mesh::OneshotSender<()>,
    Arc<AtomicUsize>,
) {
    let (request_send, request_recv) = mesh::channel();
    let (revoke_send, revoke_recv) = mesh::oneshot();
    let signals = Arc::new(AtomicUsize::new(0));
    let signal = signals.clone();
    (
        OfferInfo {
            offer: protocol::OfferChannel {
                channel_id: ChannelId(7),
                ..FromZeros::new_zeroed()
            },
            guest_to_host_interrupt: Interrupt::from_fn(move || {
                signal.fetch_add(1, Ordering::SeqCst);
            }),
            request_send,
            revoke_recv,
        },
        request_recv,
        revoke_send,
        signals,
    )
}

fn params() -> OpenParams {
    OpenParams {
        ring_pages: 4,
        ring_offset_in_pages: 2,
    }
}

fn gpadl(request: ChannelRequest) -> (FailableRpc<GpadlRequest, ()>, u64) {
    let ChannelRequest::Gpadl(rpc) = request else {
        panic!("expected GPADL creation")
    };
    assert_eq!(rpc.input().id.0, (1 << 31) | 7);
    assert_eq!(rpc.input().count, 1);
    assert_eq!(rpc.input().buf.len(), 5);
    assert_eq!(rpc.input().buf[0], 4 * vmbus_ring::PAGE_SIZE as u64);
    let gpa = rpc.input().buf[1] * vmbus_ring::PAGE_SIZE as u64;
    (rpc, gpa)
}

async fn finish_close(receiver: &mut mesh::Receiver<ChannelRequest>, close: bool) {
    if close {
        let ChannelRequest::Close(rpc) = receiver.next().await.unwrap() else {
            panic!("expected Close")
        };
        rpc.complete(());
    }
    let ChannelRequest::TeardownGpadl(rpc) = receiver.next().await.unwrap() else {
        panic!("expected GPADL teardown");
    };
    assert_eq!(rpc.input().0, (1 << 31) | 7);
    rpc.complete(());
    assert!(receiver.next().await.is_none());
}

// Test: Open a DMA-backed channel, exchange ring data and signals, then close it.
// Expected: GPADL and open metadata agree, payload bytes reach host-visible
//       memory, notifications work both ways, and close releases the DMA buffer.
#[async_test]
async fn driver_opens_shared_rings_signals_and_releases_memory_on_close(driver: DefaultDriver) {
    let memory = DeviceTestMemory::new(8, true, "vmbus-channel");
    let dma = memory.dma_client();
    let (offer, mut requests, _revoke, signals) = offer();
    let peer = async {
        let (rpc, gpa) = gpadl(requests.next().await.unwrap());
        rpc.complete(Ok(()));
        let ChannelRequest::Open(rpc) = requests.next().await.unwrap() else {
            panic!("expected Open")
        };
        assert_eq!(rpc.input().open_data.ring_gpadl_id.0, (1 << 31) | 7);
        assert_eq!(rpc.input().open_data.ring_offset, 2);
        assert_eq!(rpc.input().open_data.target_vp, Some(0));
        assert!(rpc.input().use_vtl2_connection_id);
        let event = rpc.input().incoming_event.clone().unwrap();
        rpc.complete(Ok(OpenOutput {
            redirected_event_flag: Some(1),
        }));
        (gpa, event)
    };
    let (channel, (gpa, event)) = (open_channel(driver, offer, params(), dma.as_ref()), peer)
        .join()
        .await;
    let channel = channel.unwrap();
    assert!(dma.allocate_dma_buffer(4 * vmbus_ring::PAGE_SIZE).is_err());
    let mut outgoing = channel.out_ring.outgoing().unwrap();
    let range = channel
        .out_ring
        .write(
            &mut outgoing,
            &vmbus_ring::OutgoingPacket {
                transaction_id: 123,
                size: 8,
                typ: vmbus_ring::OutgoingPacketType::InBandNoCompletion,
            },
        )
        .unwrap();
    range.write_aligned_full(&channel.out_ring, &[u64::from_ne_bytes(*b"payload!")]);
    channel.out_ring.commit_write(&mut outgoing);
    let mut bytes = [0; 8];
    // VMBus in-band packets have a 16-byte wire descriptor.
    memory
        .guest_memory()
        .read_at(gpa + vmbus_ring::PAGE_SIZE as u64 + 16, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"payload!");
    channel.signal.signal_remote();
    assert_eq!(signals.load(Ordering::SeqCst), 1);
    assert!(
        poll_fn(|cx| channel.signal.poll_for_signal(cx))
            .now_or_never()
            .is_none()
    );
    event.signal();
    assert!(
        poll_fn(|cx| channel.signal.poll_for_signal(cx))
            .await
            .is_ok()
    );
    drop(channel);
    finish_close(&mut requests, true).await;
    assert!(dma.allocate_dma_buffer(4 * vmbus_ring::PAGE_SIZE).is_ok());
}

// Test: Revoke an open channel while its consumer waits for a signal.
// Expected: The consumer is woken with ChannelClosed; teardown runs without
//       sending a redundant Close for the already revoked channel.
#[async_test]
async fn driver_revocation_wakes_waiters_and_tears_down_without_close(driver: DefaultDriver) {
    let memory = DeviceTestMemory::new(8, true, "vmbus-revoke");
    let dma = memory.dma_client();
    let (offer, mut requests, revoke, _) = offer();
    let peer = async {
        let (rpc, _) = gpadl(requests.next().await.unwrap());
        rpc.complete(Ok(()));
        let ChannelRequest::Open(rpc) = requests.next().await.unwrap() else {
            panic!("expected Open")
        };
        rpc.complete(Ok(OpenOutput {
            redirected_event_flag: Some(1),
        }));
    };
    let (channel, ()) = (open_channel(driver, offer, params(), dma.as_ref()), peer)
        .join()
        .await;
    let channel = channel.unwrap();
    assert!(
        poll_fn(|cx| channel.signal.poll_for_signal(cx))
            .now_or_never()
            .is_none()
    );
    revoke.send(());
    assert!(
        poll_fn(|cx| channel.signal.poll_for_signal(cx))
            .await
            .is_err()
    );
    finish_close(&mut requests, false).await;
    drop(channel);
    assert!(dma.allocate_dma_buffer(4 * vmbus_ring::PAGE_SIZE).is_ok());
}

// Test: Fail GPADL creation or channel open after allocating ring memory.
// Expected: Opening returns an error, created GPADLs are torn down exactly
//       when needed, and the DMA pool can allocate the buffer again.
#[async_test]
async fn driver_open_failures_release_dma_and_teardown_only_created_gpadls(driver: DefaultDriver) {
    for fail_gpadl in [true, false] {
        let memory = DeviceTestMemory::new(8, true, "vmbus-open-failure");
        let dma = memory.dma_client();
        let (offer, mut requests, _revoke, _) = offer();
        let peer = async {
            let (rpc, _) = gpadl(requests.next().await.unwrap());
            if fail_gpadl {
                rpc.fail(anyhow::anyhow!("injected GPADL failure"));
            } else {
                rpc.complete(Ok(()));
                let ChannelRequest::Open(rpc) = requests.next().await.unwrap() else {
                    panic!("expected Open")
                };
                rpc.fail(anyhow::anyhow!("injected open failure"));
                finish_close(&mut requests, false).await;
            }
        };
        let (result, ()) = (
            open_channel(driver.clone(), offer, params(), dma.as_ref()),
            peer,
        )
            .join()
            .await;
        assert!(result.is_err());
        if fail_gpadl {
            assert!(requests.next().await.is_none());
        }
        assert!(dma.allocate_dma_buffer(4 * vmbus_ring::PAGE_SIZE).is_ok());
    }
}

// Test: Open a channel when the DMA pool cannot hold its requested ring pages.
// Expected: Allocation fails before any GPADL or channel request is sent.
#[async_test]
async fn driver_allocation_failure_does_not_send_host_requests(driver: DefaultDriver) {
    let memory = DeviceTestMemory::new(4, true, "vmbus-small-pool");
    let (offer, mut requests, _revoke, _) = offer();
    let result = open_channel(driver, offer, params(), memory.dma_client().as_ref()).await;
    assert!(result.is_err());
    assert!(requests.next().await.is_none());
}
