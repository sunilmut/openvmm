// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::loopback::LoopbackEndpoint;
use crate::tests::Bufs;
use net_backend_resources::mac_address::MacAddress;
use net_backend_resources::null::NullHandle;
use pal_async::DefaultDriver;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use test_with_tracing::test;
use vm_resource::ResolveResource;

fn pool() -> Bufs {
    Bufs::new(GuestMemory::allocate(256 * 1024))
}

fn configs(driver: &DefaultDriver, count: usize) -> Vec<QueueConfig> {
    (0..count)
        .map(|_| QueueConfig {
            driver: Box::new(driver.clone()),
            enabled_rx_offloads: RxOffloadSupport::default(),
        })
        .collect()
}

fn packet(gpa: u64, len: u32) -> TxSegment {
    TxSegment {
        gpa,
        len,
        ty: TxSegmentType::Head(TxMetadata {
            id: TxId(7),
            segment_count: 1,
            len,
            ..Default::default()
        }),
    }
}

fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

fn received(pool: &Bufs, id: RxId, expected: &[u8]) {
    let mut addresses = Vec::new();
    pool.push_guest_addresses(id, &mut addresses);
    assert!(pool.capacity(id) as usize >= expected.len());
    let mut actual = vec![0; expected.len()];
    pool.guest_memory()
        .read_at(addresses[0].gpa, &mut actual)
        .unwrap();
    assert_eq!(actual, expected);
    let metadata = pool.rx_metadata(id).unwrap();
    assert_eq!(metadata.len, expected.len());
    assert_eq!(metadata.offset, 0);
}

// Test: Resolve a null endpoint, allocate multiple queues and post TX/RX work.
// Expected: Transmits complete synchronously without reading packet memory,
//       receives stay pending, and a guest-VF switch is explicitly rejected.
#[pal_async::async_test]
async fn null_endpoint_drops_transmits_and_never_completes_receives(driver: DefaultDriver) {
    let mut endpoint = null::NullResolver
        .resolve(
            NullHandle,
            resolve::ResolveEndpointParams {
                mac_address: MacAddress::new([2, 0, 0, 0, 0, 1]),
            },
        )
        .unwrap()
        .0;
    assert_eq!(endpoint.endpoint_type(), "null");
    assert!(endpoint.is_ordered());
    let offloads = endpoint.tx_offload_support();
    assert!(offloads.ipv4_header && offloads.tcp && offloads.udp && offloads.tso && offloads.uso);
    assert!(endpoint.multiqueue_support().max_queues >= 2);
    assert_eq!(endpoint.multiqueue_support().indirection_table_size, 128);
    assert!(!endpoint.tx_fast_completions());
    assert_eq!(endpoint.link_speed(), 10_000_000_000);
    assert!(endpoint.set_data_path_to_guest_vf(true).await.is_err());
    endpoint.set_data_path_to_guest_vf(false).await.unwrap();
    assert!(endpoint.get_data_path_to_guest_vf().await.is_err());
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 2), None, &mut queues)
        .await
        .unwrap();
    assert_eq!(queues.len(), 2);
    let mut pool = pool();
    for queue in &mut queues {
        queue.update_target_vp(1).await;
        assert!(queue.queue_stats().is_none());
        queue.rx_avail(&mut pool, &[RxId(1)]);
        assert!(queue.poll_ready(&mut context(), &mut pool).is_pending());
        let mut done = [RxId(99)];
        assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 0);
        assert_eq!(done[0].0, 99);
        assert_eq!(
            queue.tx_avail(&mut pool, &[packet(u64::MAX, 1)]).unwrap(),
            (true, 1)
        );
        assert_eq!(queue.tx_poll(&mut pool, &mut [TxId(99)]).unwrap(), 0);
        assert!(pool.rx_metadata(RxId(1)).is_none());
    }
    drop(queues);
    endpoint.stop().await;
}

// Test: Loop back a two-segment VLAN packet while another queue has RX credit.
// Expected: Payload and VLAN metadata reach only the originating queue, receive
//       completion is FIFO ordered, and an empty poll cannot consume a packet.
#[pal_async::async_test]
async fn loopback_preserves_segment_data_vlan_and_queue_isolation(driver: DefaultDriver) {
    let mut endpoint = LoopbackEndpoint::new();
    assert_eq!(endpoint.endpoint_type(), "loopback");
    assert!(endpoint.is_ordered());
    assert!(endpoint.multiqueue_support().max_queues >= 2);
    assert_eq!(endpoint.multiqueue_support().indirection_table_size, 64);
    assert!(!endpoint.tx_offload_support().tcp);
    assert!(endpoint.set_data_path_to_guest_vf(false).await.is_err());
    let mut queues = Vec::new();
    let rss = RssConfig {
        key: &[1; 40],
        indirection_table: &[0, 1],
        flags: 0,
    };
    endpoint
        .get_queues(configs(&driver, 2), Some(&rss), &mut queues)
        .await
        .unwrap();
    let mut pool = pool();
    pool.guest_memory().write_at(0x20000, b"head").unwrap();
    pool.guest_memory().write_at(0x21000, b"tail").unwrap();
    let vlan = VlanMetadata::new().with_vlan_id(55).with_priority(3);
    let segments = [
        TxSegment {
            gpa: 0x20000,
            len: 4,
            ty: TxSegmentType::Head(TxMetadata {
                id: TxId(5),
                segment_count: 2,
                len: 8,
                vlan: Some(vlan),
                ..Default::default()
            }),
        },
        TxSegment {
            gpa: 0x21000,
            len: 4,
            ty: TxSegmentType::Tail,
        },
    ];
    queues[0].rx_avail(&mut pool, &[RxId(3), RxId(5)]);
    queues[1].rx_avail(&mut pool, &[RxId(4)]);
    assert_eq!(queues[0].tx_avail(&mut pool, &segments).unwrap(), (true, 2));
    assert!(queues[0].poll_ready(&mut context(), &mut pool).is_ready());
    assert!(queues[1].poll_ready(&mut context(), &mut pool).is_pending());
    assert_eq!(queues[0].rx_poll(&mut pool, &mut []).unwrap(), 0);
    let mut done = [RxId(99)];
    assert_eq!(queues[0].rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, 3);
    received(&pool, done[0], b"headtail");
    let received_vlan = pool.rx_metadata(done[0]).unwrap().vlan.unwrap();
    assert_eq!(received_vlan.vlan_id(), 55);
    assert_eq!(received_vlan.priority(), 3);
    assert!(pool.rx_metadata(RxId(4)).is_none());
    assert_eq!(queues[0].tx_avail(&mut pool, &segments).unwrap(), (true, 2));
    assert_eq!(queues[0].rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, 5);
    assert_eq!(queues[0].tx_avail(&mut pool, &segments).unwrap(), (true, 0));
    assert_eq!(queues[0].tx_poll(&mut pool, &mut [TxId(99)]).unwrap(), 0);
    assert_eq!(queues[1].rx_poll(&mut pool, &mut done).unwrap(), 0);
    drop(queues);
    endpoint.stop().await;
}

// Test: Fail loopback's packet read and retry using the same posted RX buffer.
// Expected: The memory error is explicit, no receive is completed for it, and
//       the valid retry consumes the original RX credit and returns correct data.
#[pal_async::async_test]
async fn loopback_guest_memory_failure_preserves_receive_credit(driver: DefaultDriver) {
    let mut endpoint = LoopbackEndpoint::new();
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 1), None, &mut queues)
        .await
        .unwrap();
    let queue = &mut queues[0];
    let mut pool = pool();
    queue.rx_avail(&mut pool, &[RxId(1)]);
    assert!(queue.tx_avail(&mut pool, &[packet(0x100000, 4)]).is_err());
    assert!(queue.poll_ready(&mut context(), &mut pool).is_pending());
    assert_eq!(queue.rx_poll(&mut pool, &mut [RxId(0)]).unwrap(), 0);
    pool.guest_memory().write_at(0x20000, b"good").unwrap();
    assert_eq!(
        queue.tx_avail(&mut pool, &[packet(0x20000, 4)]).unwrap(),
        (true, 1)
    );
    let mut done = [RxId(0)];
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, 1);
    received(&pool, done[0], b"good");
}

// Test: Write receive packets from zero, one and several discontiguous slices.
// Expected: The public buffer interface writes concatenated payload bytes and
//       matching metadata without disturbing bytes beyond the packet.
#[test]
fn receive_packet_segments_write_exact_payload_and_metadata() {
    let mut pool = pool();
    pool.set_capacity(RxId(2), 32);
    for (segments, expected) in [
        (&[][..], &b""[..]),
        (&[&b"single"[..]][..], &b"single"[..]),
        (
            &[&b"head"[..], &b""[..], &b"tail"[..]][..],
            &b"headtail"[..],
        ),
    ] {
        let mut addresses = Vec::new();
        pool.push_guest_addresses(RxId(2), &mut addresses);
        pool.guest_memory()
            .write_at(addresses[0].gpa, &[0xa5; 32])
            .unwrap();
        let metadata = RxMetadata {
            len: expected.len(),
            ..Default::default()
        };
        pool.write_packet_segments(RxId(2), &metadata, segments);
        received(&pool, RxId(2), expected);
        let mut sentinel = vec![0; 32 - expected.len()];
        pool.guest_memory()
            .read_at(addresses[0].gpa + expected.len() as u64, &mut sentinel)
            .unwrap();
        assert_eq!(sentinel, vec![0xa5; 32 - expected.len()]);
    }
}

#[derive(InspectMut)]
#[inspect(skip)]
struct ScriptedEndpoint {
    ordered: bool,
    inner: NullEndpoint,
    events: mesh::Receiver<EndpointAction>,
    stops: Arc<AtomicUsize>,
    vf: AtomicBool,
}

#[async_trait]
impl Endpoint for ScriptedEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "scripted"
    }
    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        self.inner.get_queues(config, rss, queues).await
    }
    async fn stop(&mut self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
    }
    fn is_ordered(&self) -> bool {
        self.ordered
    }
    fn tx_fast_completions(&self) -> bool {
        true
    }
    fn link_speed(&self) -> u64 {
        123_000_000
    }
    async fn set_data_path_to_guest_vf(&self, use_vf: bool) -> anyhow::Result<()> {
        self.vf.store(use_vf, Ordering::SeqCst);
        Ok(())
    }
    async fn get_data_path_to_guest_vf(&self) -> anyhow::Result<bool> {
        Ok(self.vf.load(Ordering::SeqCst))
    }
    async fn wait_for_endpoint_action(&mut self) -> EndpointAction {
        match self.events.next().await {
            Some(action) => action,
            None => pending().await,
        }
    }
}

fn scripted(
    ordered: bool,
) -> (
    ScriptedEndpoint,
    mesh::Sender<EndpointAction>,
    Arc<AtomicUsize>,
) {
    let (send, events) = mesh::channel();
    let stops = Arc::new(AtomicUsize::new(0));
    (
        ScriptedEndpoint {
            ordered,
            inner: NullEndpoint::new(),
            events,
            stops: stops.clone(),
            vf: AtomicBool::new(false),
        },
        send,
        stops,
    )
}

async fn disconnect(
    endpoint: &mut DisconnectableEndpoint,
    control: &mut DisconnectableEndpointControl,
) -> Option<Box<dyn Endpoint>> {
    let mut disconnect = std::pin::pin!(control.disconnect());
    assert!(futures::poll!(disconnect.as_mut()).is_pending());
    assert_eq!(
        endpoint.wait_for_endpoint_action().await,
        EndpointAction::RestartRequired
    );
    // The documented acknowledgement is deferred until the next action request.
    let mut next_action = std::pin::pin!(endpoint.wait_for_endpoint_action());
    assert!(futures::poll!(next_action.as_mut()).is_pending());
    disconnect.await.unwrap()
}

// Test: Connect, deliver a link event, switch VF paths, disconnect and reconnect.
// Expected: Public methods reach the active backend, disconnect returns ownership
//       after restart acknowledgement, and reconnect preserves advertised ordering.
#[pal_async::async_test]
async fn disconnectable_endpoint_forwards_lifecycle_and_preserves_capabilities(
    driver: DefaultDriver,
) {
    let (mut endpoint, mut control) = DisconnectableEndpoint::new();
    assert_eq!(endpoint.endpoint_type(), "null");
    let (backend, events, stops) = scripted(false);
    control.connect(Box::new(backend)).unwrap();
    assert_eq!(
        endpoint.wait_for_endpoint_action().await,
        EndpointAction::RestartRequired
    );
    assert_eq!(endpoint.endpoint_type(), "scripted");
    assert!(!endpoint.is_ordered());
    assert!(endpoint.tx_fast_completions());
    assert_eq!(endpoint.link_speed(), 123_000_000);
    assert!(!endpoint.tx_offload_support().tcp);
    assert_eq!(endpoint.multiqueue_support().max_queues, 1);
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 1), None, &mut queues)
        .await
        .unwrap();
    assert_eq!(queues.len(), 1);
    endpoint.set_data_path_to_guest_vf(true).await.unwrap();
    assert!(endpoint.get_data_path_to_guest_vf().await.unwrap());
    events.send(EndpointAction::LinkStatusNotify(true));
    assert_eq!(
        endpoint.wait_for_endpoint_action().await,
        EndpointAction::LinkStatusNotify(true)
    );
    drop(queues);
    endpoint.stop().await;
    assert_eq!(stops.load(Ordering::SeqCst), 1);
    let old = disconnect(&mut endpoint, &mut control).await.unwrap();
    assert_eq!(old.endpoint_type(), "scripted");
    assert_eq!(endpoint.endpoint_type(), "null");
    assert!(endpoint.tx_fast_completions());
    assert_eq!(endpoint.link_speed(), 123_000_000);
    endpoint
        .get_queues(configs(&driver, 1), None, &mut Vec::new())
        .await
        .unwrap();
    endpoint.stop().await;
    assert!(endpoint.set_data_path_to_guest_vf(true).await.is_err());
    assert!(endpoint.get_data_path_to_guest_vf().await.is_err());
    let (backend, _events, _) = scripted(true);
    control.connect(Box::new(backend)).unwrap();
    assert_eq!(
        endpoint.wait_for_endpoint_action().await,
        EndpointAction::RestartRequired
    );
    assert!(!endpoint.is_ordered());
}

// Test: Disconnect before any connection and drop the controlling sender.
// Expected: An empty disconnect returns no endpoint, and closing control does
//       not manufacture a restart or link notification.
#[test]
fn empty_disconnect_and_closed_control_do_not_create_spurious_actions() {
    futures::executor::block_on(async {
        let (mut endpoint, mut control) = DisconnectableEndpoint::new();
        assert!(disconnect(&mut endpoint, &mut control).await.is_none());
        drop(control);
        let mut action = std::pin::pin!(endpoint.wait_for_endpoint_action());
        assert!(futures::poll!(action.as_mut()).is_pending());
    });
}

// Test: Submit two packets with receive credit for only the first packet.
// Expected: The accepted segment count ends at a packet boundary; retrying the
//       remaining packet after replenishment delivers both exactly once in order.
#[pal_async::async_test]
async fn loopback_backpressure_preserves_the_unaccepted_packet(driver: DefaultDriver) {
    let mut endpoint = LoopbackEndpoint::new();
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 1), None, &mut queues)
        .await
        .unwrap();
    let queue = &mut queues[0];
    let mut pool = pool();
    pool.guest_memory().write_at(0x20000, b"head").unwrap();
    pool.guest_memory().write_at(0x21000, b"tail").unwrap();
    pool.guest_memory().write_at(0x22000, b"next").unwrap();
    let segments = [
        TxSegment {
            gpa: 0x20000,
            len: 4,
            ty: TxSegmentType::Head(TxMetadata {
                id: TxId(1),
                segment_count: 2,
                len: 8,
                ..Default::default()
            }),
        },
        TxSegment {
            gpa: 0x21000,
            len: 4,
            ty: TxSegmentType::Tail,
        },
        packet(0x22000, 4),
    ];
    assert_eq!(queue.tx_avail(&mut pool, &segments).unwrap(), (true, 0));
    queue.rx_avail(&mut pool, &[RxId(1)]);
    let (synchronous, accepted) = queue.tx_avail(&mut pool, &segments).unwrap();
    assert!(synchronous);
    assert_eq!(accepted, 2);
    let remaining = &segments[accepted..];
    assert_eq!(queue.tx_avail(&mut pool, remaining).unwrap(), (true, 0));
    queue.rx_avail(&mut pool, &[RxId(2)]);
    assert_eq!(queue.tx_avail(&mut pool, remaining).unwrap(), (true, 1));
    let mut done = [RxId(99); 3];
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 2);
    assert_eq!(done.map(|id| id.0), [1, 2, 99]);
    received(&pool, done[0], b"headtail");
    received(&pool, done[1], b"next");
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 0);
    assert!(queue.poll_ready(&mut context(), &mut pool).is_pending());
}

// Test: Read a scattered packet whose second segment initially has no memory.
// Expected: Failure leaves the packet cursor intact; repairing the address reads
//       the entire packet, advances exactly one packet, and preserves its suffix.
#[test]
fn linearize_failed_tail_preserves_packet_and_retry_suffix() {
    let pool = pool();
    pool.guest_memory().write_at(0x20000, b"head").unwrap();
    pool.guest_memory().write_at(0x21000, b"tail").unwrap();
    pool.guest_memory().write_at(0x22000, b"next").unwrap();
    let mut segments = [
        TxSegment {
            gpa: 0x20000,
            len: 4,
            ty: TxSegmentType::Head(TxMetadata {
                segment_count: 2,
                len: 8,
                ..Default::default()
            }),
        },
        TxSegment {
            gpa: 0x100000,
            len: 4,
            ty: TxSegmentType::Tail,
        },
        packet(0x22000, 4),
    ];
    let mut remaining = &segments[..];
    assert!(linearize(&pool, &mut remaining).is_err());
    assert!(std::ptr::eq(remaining, &segments[..]));
    segments[1].gpa = 0x21000;
    let mut remaining = &segments[..];
    assert_eq!(linearize(&pool, &mut remaining).unwrap(), b"headtail");
    assert!(std::ptr::eq(remaining, &segments[2..]));
    assert_eq!(linearize(&pool, &mut remaining).unwrap(), b"next");
    assert!(remaining.is_empty());
}

// Test: Cancel pending action waits before a link event and after disconnect's
//       restart acknowledgement, then reconnect a different backend.
// Expected: Cancellation does not lose events or lock out later waits;
//       disconnect returns the original live backend only after acknowledgement,
//       and the replacement advertises its own capabilities.
#[test]
fn cancelled_action_waits_preserve_events_and_disconnect_ownership() {
    futures::executor::block_on(async {
        let (mut endpoint, mut control) = DisconnectableEndpoint::new();
        let (backend, events, stops) = scripted(true);
        control.connect(Box::new(backend)).unwrap();
        assert_eq!(
            endpoint.wait_for_endpoint_action().await,
            EndpointAction::RestartRequired
        );
        endpoint.set_data_path_to_guest_vf(true).await.unwrap();
        {
            let mut action = std::pin::pin!(endpoint.wait_for_endpoint_action());
            assert!(futures::poll!(action.as_mut()).is_pending());
        }
        events.send(EndpointAction::LinkStatusNotify(false));
        assert_eq!(
            endpoint.wait_for_endpoint_action().await,
            EndpointAction::LinkStatusNotify(false)
        );
        let mut old = {
            let mut disconnect = std::pin::pin!(control.disconnect());
            assert!(futures::poll!(disconnect.as_mut()).is_pending());
            assert_eq!(
                endpoint.wait_for_endpoint_action().await,
                EndpointAction::RestartRequired
            );
            assert!(futures::poll!(disconnect.as_mut()).is_pending());
            {
                let mut action = std::pin::pin!(endpoint.wait_for_endpoint_action());
                assert!(futures::poll!(action.as_mut()).is_pending());
            }
            disconnect.await.unwrap().unwrap()
        };
        assert_eq!(old.endpoint_type(), "scripted");
        assert!(old.get_data_path_to_guest_vf().await.unwrap());
        old.stop().await;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert_eq!(endpoint.endpoint_type(), "null");
        assert!(endpoint.set_data_path_to_guest_vf(true).await.is_err());
        control.connect(Box::new(LoopbackEndpoint::new())).unwrap();
        assert_eq!(
            endpoint.wait_for_endpoint_action().await,
            EndpointAction::RestartRequired
        );
        assert_eq!(endpoint.endpoint_type(), "loopback");
        assert!(endpoint.is_ordered());
        assert!(!endpoint.tx_fast_completions());
        assert_eq!(endpoint.link_speed(), 10_000_000_000);
        assert_eq!(endpoint.multiqueue_support().indirection_table_size, 64);
        let mut action = std::pin::pin!(endpoint.wait_for_endpoint_action());
        assert!(futures::poll!(action.as_mut()).is_pending());
    });
}

// Test: Recreate loopback queues after dropping outstanding RX credit and a
//       completed packet, then send a fresh packet with fresh receive credit.
// Expected: Old completions and credits are not restored into the new queue;
//       only the new buffer receives data, and old guest payload stays intact.
#[pal_async::async_test]
async fn loopback_recreated_queue_requires_fresh_receive_credit(driver: DefaultDriver) {
    let mut endpoint = LoopbackEndpoint::new();
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 1), None, &mut queues)
        .await
        .unwrap();
    let mut pool = pool();
    pool.guest_memory().write_at(0x20000, b"old!").unwrap();
    pool.guest_memory().write_at(0x21000, b"new!").unwrap();
    queues[0].rx_avail(&mut pool, &[RxId(1), RxId(2)]);
    assert_eq!(
        queues[0]
            .tx_avail(&mut pool, &[packet(0x20000, 4)])
            .unwrap(),
        (true, 1)
    );
    assert!(queues[0].poll_ready(&mut context(), &mut pool).is_ready());
    drop(queues);
    endpoint.stop().await;
    let mut queues = Vec::new();
    endpoint
        .get_queues(configs(&driver, 1), None, &mut queues)
        .await
        .unwrap();
    let queue = &mut queues[0];
    let mut done = [RxId(99); 2];
    assert!(queue.poll_ready(&mut context(), &mut pool).is_pending());
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 0);
    assert_eq!(done.map(|id| id.0), [99, 99]);
    assert_eq!(
        queue.tx_avail(&mut pool, &[packet(0x21000, 4)]).unwrap(),
        (true, 0)
    );
    queue.rx_avail(&mut pool, &[RxId(3)]);
    assert_eq!(
        queue.tx_avail(&mut pool, &[packet(0x21000, 4)]).unwrap(),
        (true, 1)
    );
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done.map(|id| id.0), [3, 99]);
    received(&pool, RxId(3), b"new!");
    received(&pool, RxId(1), b"old!");
    assert!(pool.rx_metadata(RxId(2)).is_none());
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 0);
    assert!(queue.poll_ready(&mut context(), &mut pool).is_pending());
    drop(queues);
    endpoint.stop().await;
}
