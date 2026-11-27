// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::future::Either;
use futures::future::select;
use mesh::payload::Protobuf;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use pal_async::task::Spawn;
use pal_async::timer::PolledTimer;
use std::future::poll_fn;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;
use test_with_tracing::test;
use user_driver_emulated_mock::DeviceTestMemory;
use vmbus_ring::RingMem;

#[derive(Debug, PartialEq)]
enum Event {
    Registered,
    HostOpened,
    DeviceOpened(u16),
    Running(u64),
    HostClosed,
    TornDown,
    Saved(u64),
    RunnerDropped,
    DeviceClosed(u16),
    Restored(u64),
    DeviceDropped,
}

#[derive(Protobuf, SavedStateRoot)]
#[mesh(package = "test.vmbus_relay_intercept_device")]
struct TestSavedState {
    #[mesh(1)]
    progress: u64,
}

struct TestRunner {
    _channel: RawAsyncChannel<MemoryBlockRingBuffer>,
    progress: u64,
    events: mesh::Sender<Event>,
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        self.events.send(Event::RunnerDropped);
    }
}

struct TestDevice {
    instance_id: Guid,
    response: OfferResponse,
    events: mesh::Sender<Event>,
}

impl Drop for TestDevice {
    fn drop(&mut self) {
        self.events.send(Event::DeviceDropped);
    }
}

impl SimpleVmbusClientDevice for TestDevice {
    type SavedState = TestSavedState;
    type Runner = TestRunner;

    fn inspect(&mut self, req: inspect::Request<'_>, _: Option<&mut Self::Runner>) {
        req.ignore();
    }

    fn instance_id(&self) -> Guid {
        self.instance_id
    }

    fn offer(&self, _: &vmbus_core::protocol::OfferChannel) -> OfferResponse {
        match self.response {
            OfferResponse::Ignore => OfferResponse::Ignore,
            OfferResponse::Open => OfferResponse::Open,
        }
    }

    fn open(
        &mut self,
        channel_idx: u16,
        channel: RawAsyncChannel<MemoryBlockRingBuffer>,
    ) -> Result<Self::Runner> {
        self.events.send(Event::DeviceOpened(channel_idx));
        Ok(TestRunner {
            _channel: channel,
            progress: 0x1_0000_00a5,
            events: self.events.clone(),
        })
    }

    fn close(&mut self, channel_idx: u16) {
        self.events.send(Event::DeviceClosed(channel_idx));
    }

    fn supports_save_restore(
        &mut self,
    ) -> Option<
        &mut dyn SaveRestoreSimpleVmbusClientDevice<
            SavedState = Self::SavedState,
            Runner = Self::Runner,
        >,
    > {
        Some(self)
    }
}

impl SimpleVmbusClientDeviceAsync for TestDevice {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        runner: &mut Self::Runner,
    ) -> Result<(), Cancelled> {
        runner.progress += 1;
        self.events.send(Event::Running(runner.progress));
        stop.until_stopped(pending::<()>()).await
    }
}

impl SaveRestoreSimpleVmbusClientDevice for TestDevice {
    fn save_open(&mut self, runner: &Self::Runner) -> Self::SavedState {
        self.events.send(Event::Saved(runner.progress));
        TestSavedState {
            progress: runner.progress,
        }
    }

    fn restore_open(
        &mut self,
        state: Self::SavedState,
        channel: RawAsyncChannel<MemoryBlockRingBuffer>,
    ) -> Result<Self::Runner> {
        self.events.send(Event::Restored(state.progress));
        Ok(TestRunner {
            _channel: channel,
            progress: state.progress,
            events: self.events.clone(),
        })
    }
}

fn run_bounded(test: impl AsyncFnOnce(DefaultDriver)) {
    DefaultPool::run_with(async |driver| {
        let mut timer = PolledTimer::new(&driver);
        match select(
            pin!(test(driver)),
            pin!(timer.sleep(Duration::from_secs(5))),
        )
        .await
        {
            Either::Left(((), _)) => {}
            Either::Right(_) => panic!("intercepted-device test timed out"),
        }
    });
}

fn offer(
    instance_id: Guid,
) -> (
    OfferInfo,
    mesh::Receiver<ChannelRequest>,
    mesh::OneshotSender<()>,
) {
    let (request_send, requests) = mesh::channel();
    let (revoke, revoke_recv) = mesh::oneshot();
    let mut offer = vmbus_core::protocol::OfferChannel::new_zeroed();
    offer.instance_id = instance_id;
    offer.subchannel_index = 7;
    offer.is_dedicated = 1;
    (
        OfferInfo {
            offer,
            guest_to_host_interrupt: Interrupt::null(),
            request_send,
            revoke_recv,
        },
        requests,
        revoke,
    )
}

fn empty_state() -> SimpleVmbusClientDeviceTaskState {
    let (_, recv_relay) = mesh::channel();
    let (send_disconnected, _) = mesh::oneshot();
    SimpleVmbusClientDeviceTaskState {
        offer: None,
        recv_relay,
        send_disconnected: Some(send_disconnected),
        vtl_pages: None,
    }
}

async fn expect_events(events: &mut mesh::Receiver<Event>, expected: &[Event]) {
    for event in expected {
        assert_eq!(events.next().await.as_ref(), Some(event));
    }
}

// Test: Read and write wrapped data through a DMA-backed ring with a control-page guard.
// Expected: Logical addresses wrap within data pages; backing bytes match exactly
//       and neither direction changes the control page.
#[test]
fn dma_ring_wrap_preserves_control_page() {
    let memory = DeviceTestMemory::new(4, true, "relay-ring");
    let block = memory
        .dma_client()
        .allocate_dma_buffer(2 * PAGE_SIZE)
        .expect("test ring allocation");
    let ring = MemoryBlockRingBuffer::new(block.clone());
    ring.control()[0].store(0xaabbccdd, Ordering::SeqCst);
    let payload: Vec<_> = (0..32).collect();
    let logical = 4 * PAGE_SIZE - 7;
    ring.write_at(logical, &payload);

    let mut backing = vec![0; PAGE_SIZE];
    block.read_at(PAGE_SIZE, &mut backing);
    let mut expected = vec![0; PAGE_SIZE];
    expected[..25].copy_from_slice(&payload[7..]);
    expected[PAGE_SIZE - 7..].copy_from_slice(&payload[..7]);
    assert_eq!(backing, expected);

    let mut received = vec![0; payload.len()];
    ring.read_at(logical, &mut received);
    assert_eq!(received, payload);
    let mut header = vec![0; PAGE_SIZE];
    block.read_at(0, &mut header);
    let mut expected = vec![0; PAGE_SIZE];
    expected[..4].copy_from_slice(&0xaabbccddu32.to_ne_bytes());
    assert_eq!(header, expected);
}

// Test: Repeat start/offer requests, stop, save twice, restart and revoke via relay RPCs.
// Expected: Host-owned pages remain reserved until teardown, saved progress survives
//       both saves/restart, and runner drop precedes close on both stop and revoke.
#[test]
fn relay_stop_save_restart_and_revoke_preserve_ownership() {
    run_bounded(async |driver| {
        let memory = DeviceTestMemory::new(8, true, "relay-lifecycle");
        let allocator: Arc<dyn DmaClient> = memory.dma_client();
        let (send_events, mut events) = mesh::channel();
        let instance_id = Guid::new_random();
        let device = TestDevice {
            instance_id,
            response: OfferResponse::Open,
            events: send_events.clone(),
        };
        let (send_relay, recv_relay) = mesh::channel();
        SimpleVmbusClientDeviceWrapper::new(driver.clone(), allocator.clone(), device)
            .expect("wrapper creation")
            .detach(driver.clone(), recv_relay)
            .expect("wrapper detachment");
        let (offered, mut requests, revoke) = offer(instance_id);
        let host_allocator = allocator.clone();
        let host = driver.spawn("relay-test-host", async move {
            let mut registered = None;
            while let Some(request) = requests.next().await {
                match request {
                    ChannelRequest::Gpadl(rpc) => {
                        assert!(registered.is_none());
                        assert_eq!(rpc.input().count, 1);
                        assert_eq!(rpc.input().buf, vec![16384, 0, 1, 2, 3]);
                        registered = Some(rpc.input().id);
                        send_events.send(Event::Registered);
                        rpc.complete(Ok(()));
                    }
                    ChannelRequest::Open(rpc) => {
                        let request = rpc.input();
                        assert_eq!(Some(request.open_data.ring_gpadl_id), registered);
                        assert_eq!(request.open_data.ring_offset, 2);
                        assert_eq!(request.open_data.target_vp, Some(0));
                        assert_eq!(request.open_data.event_flag, !0);
                        assert_eq!(request.open_data.connection_id, !0);
                        assert!(request.incoming_event.is_some());
                        assert!(request.use_vtl2_connection_id);
                        send_events.send(Event::HostOpened);
                        rpc.complete(Ok(OpenOutput {
                            redirected_event_flag: None,
                        }));
                    }
                    ChannelRequest::Close(rpc) => {
                        assert!(host_allocator.allocate_dma_buffer(4 * PAGE_SIZE).is_err());
                        send_events.send(Event::HostClosed);
                        rpc.complete(());
                    }
                    ChannelRequest::TeardownGpadl(rpc) => {
                        assert_eq!(Some(*rpc.input()), registered.take());
                        assert!(host_allocator.allocate_dma_buffer(4 * PAGE_SIZE).is_err());
                        send_events.send(Event::TornDown);
                        rpc.complete(());
                    }
                    other => panic!("unexpected host request: {other}"),
                }
            }
            assert!(registered.is_none(), "all host mappings were torn down");
        });

        send_relay.send(InterceptChannelRequest::Start);
        send_relay
            .call(InterceptChannelRequest::Stop, ())
            .await
            .expect("idle stop response");
        let empty = send_relay
            .call(InterceptChannelRequest::Save, ())
            .await
            .expect("initial save response");
        empty
            .parse::<NoSavedState>()
            .expect("initially no saved state");
        send_relay.send(InterceptChannelRequest::Offer(offered));
        expect_events(
            &mut events,
            &[
                Event::Registered,
                Event::HostOpened,
                Event::DeviceOpened(7),
                Event::Running(0x1_0000_00a6),
            ],
        )
        .await;
        send_relay.send(InterceptChannelRequest::Start);
        let (duplicate, mut duplicate_requests, _duplicate_revoke) = offer(instance_id);
        send_relay.send(InterceptChannelRequest::Offer(duplicate));
        assert!(
            duplicate_requests.next().await.is_none(),
            "active channel ignores duplicate offer without another host request"
        );
        send_relay
            .call(InterceptChannelRequest::Stop, ())
            .await
            .expect("stop response");
        expect_events(
            &mut events,
            &[
                Event::HostClosed,
                Event::TornDown,
                Event::Saved(0x1_0000_00a6),
                Event::RunnerDropped,
                Event::DeviceClosed(7),
            ],
        )
        .await;
        drop(
            allocator
                .allocate_dma_buffer(4 * PAGE_SIZE)
                .expect("pages reusable after stop"),
        );
        for _ in 0..2 {
            let saved = send_relay
                .call(InterceptChannelRequest::Save, ())
                .await
                .expect("save response");
            assert_eq!(
                saved
                    .parse::<TestSavedState>()
                    .expect("saved progress")
                    .progress,
                0x1_0000_00a6
            );
        }
        send_relay.send(InterceptChannelRequest::Start);
        expect_events(
            &mut events,
            &[
                Event::Registered,
                Event::HostOpened,
                Event::Restored(0x1_0000_00a6),
                Event::Running(0x1_0000_00a7),
            ],
        )
        .await;
        revoke.send(());
        expect_events(
            &mut events,
            &[
                Event::RunnerDropped,
                Event::DeviceClosed(7),
                Event::TornDown,
            ],
        )
        .await;
        drop(send_relay);
        expect_events(&mut events, &[Event::DeviceDropped]).await;
        host.await;
        drop(
            allocator
                .allocate_dma_buffer(4 * PAGE_SIZE)
                .expect("pages reusable after revoke"),
        );
    });
}

// Test: Offer a device that declines the channel while every DMA page is occupied.
// Expected: Ignoring the offer succeeds without attempting allocation or host RPCs.
#[test]
fn ignored_offer_does_not_allocate_or_contact_host() {
    run_bounded(async |driver| {
        let memory = DeviceTestMemory::new(8, true, "relay-ignored");
        let allocator = memory.dma_client();
        let _occupied = allocator
            .allocate_dma_buffer(4 * PAGE_SIZE)
            .expect("occupy test pool");
        let (events, _received) = mesh::channel();
        let instance_id = Guid::new_random();
        let device = TestDevice {
            instance_id,
            response: OfferResponse::Ignore,
            events,
        };
        let mut task = SimpleVmbusClientDeviceTask::new(device, Arc::new(driver), allocator);
        let (offer, mut requests, _revoke) = offer(instance_id);
        task.handle_offer(offer, &mut empty_state())
            .await
            .expect("ignored offer succeeds");
        assert!(requests.next().await.is_none(), "no host request was sent");
    });
}

// Test: Open an accepted offer with an exhausted DMA pool.
// Expected: Allocation failure keeps reserve-memory context and sends no host RPC.
#[test]
fn allocation_failure_preserves_context_without_host_registration() {
    run_bounded(async |driver| {
        let memory = DeviceTestMemory::new(8, true, "relay-exhausted");
        let allocator = memory.dma_client();
        let _occupied = allocator
            .allocate_dma_buffer(4 * PAGE_SIZE)
            .expect("occupy test pool");
        let (events, _received) = mesh::channel();
        let instance_id = Guid::new_random();
        let device = TestDevice {
            instance_id,
            response: OfferResponse::Open,
            events,
        };
        let mut task = SimpleVmbusClientDeviceTask::new(device, Arc::new(driver), allocator);
        let (offer, mut requests, _revoke) = offer(instance_id);
        let error = task
            .handle_offer(offer, &mut empty_state())
            .await
            .expect_err("pool exhausted");
        let message = format!("{error:#}");
        assert!(message.contains("reserve memory"), "{message}");
        assert!(
            message.contains("allocating memory for vmbus rings"),
            "{message}"
        );
        assert!(
            requests.next().await.is_none(),
            "no host registration on allocation failure"
        );
    });
}

// Test: Deliver each direction of an intercepted channel's event signaling.
// Expected: Outgoing notification reaches the interrupt target; incoming signaling
//       wakes the channel exactly once and leaves the wait pending after consumption.
#[test]
fn channel_signals_deliver_and_consume_notifications() {
    run_bounded(async |driver| {
        let (send, mut received) = mesh::channel();
        let event = pal_event::Event::new();
        let signal = MemoryBlockChannelSignal {
            event: Notify::from_event(event.clone())
                .pollable(&driver)
                .expect("event polling"),
            interrupt: Interrupt::from_fn(move || send.send(())),
        };
        assert!(
            poll_fn(|cx| Poll::Ready(signal.poll_for_signal(cx)))
                .await
                .is_pending()
        );
        signal.signal_remote();
        received.next().await.expect("interrupt delivered");
        event.signal();
        assert!(
            poll_fn(|cx| signal.poll_for_signal(cx)).await.is_ok(),
            "channel remains open"
        );
        assert!(
            poll_fn(|cx| Poll::Ready(signal.poll_for_signal(cx)))
                .await
                .is_pending()
        );
    });
}

// Test: Restore an incompatible state after a valid snapshot, then restore valid state.
// Expected: The incompatible type clears the old snapshot without opening a channel;
//       a later valid restore is accepted and returned intact by Save.
#[test]
fn incompatible_restore_discards_stale_state_and_recovers() {
    run_bounded(async |driver| {
        let memory = DeviceTestMemory::new(8, true, "relay-restore");
        let (events, mut received) = mesh::channel();
        let device = TestDevice {
            instance_id: Guid::new_random(),
            response: OfferResponse::Open,
            events,
        };
        let (send, recv) = mesh::channel();
        SimpleVmbusClientDeviceWrapper::new(driver.clone(), memory.dma_client(), device)
            .expect("wrapper creation")
            .detach(driver, recv)
            .expect("wrapper detachment");

        send.send(InterceptChannelRequest::Restore(SavedStateBlob::new(
            TestSavedState {
                progress: 0x1_0000_00a5,
            },
        )));
        let saved = send
            .call(InterceptChannelRequest::Save, ())
            .await
            .expect("save response");
        assert_eq!(
            saved
                .parse::<TestSavedState>()
                .expect("initial snapshot")
                .progress,
            0x1_0000_00a5
        );

        send.send(InterceptChannelRequest::Restore(SavedStateBlob::new(
            NoSavedState,
        )));
        let saved = send
            .call(InterceptChannelRequest::Save, ())
            .await
            .expect("save response");
        saved
            .parse::<NoSavedState>()
            .expect("incompatible restore cleared stale snapshot");

        send.send(InterceptChannelRequest::Restore(SavedStateBlob::new(
            TestSavedState {
                progress: 0x2_0000_00b6,
            },
        )));
        let saved = send
            .call(InterceptChannelRequest::Save, ())
            .await
            .expect("save response");
        assert_eq!(
            saved
                .parse::<TestSavedState>()
                .expect("recovered snapshot")
                .progress,
            0x2_0000_00b6
        );
        drop(send);
        expect_events(&mut received, &[Event::DeviceDropped]).await;
    });
}
