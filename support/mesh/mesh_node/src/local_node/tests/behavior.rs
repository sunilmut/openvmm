// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use test_with_tracing::test;

async fn within<T>(driver: &DefaultDriver, future: impl Future<Output = T>) -> T {
    let mut timer = pal_async::timer::PolledTimer::new(driver);
    match futures::future::select(
        pin!(future),
        pin!(timer.sleep(std::time::Duration::from_secs(5))),
    )
    .await
    {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right(_) => panic!("mesh operation timed out"),
    }
}

// Test: Send borrowed protobuf values and close with a final protobuf message.
// Expected: Receivers observe both complete values before closure, even after rebind.
#[test]
fn protobuf_send_and_close_preserve_values_across_handler_replacement() {
    let (sender, receiver) = Port::new_pair();
    let receiver: PortWithHandler<Queue> = receiver.into();
    let value = String::from("borrowed value");
    sender.send_protobuf((value.as_str(),));
    drop(value);
    sender.send_protobuf_and_close(("final value",));
    assert!(receiver.is_closed().unwrap());
    let receiver: Port = receiver.into();
    let mut receiver = Channel::<(), String>::from(receiver);
    assert_eq!(receiver.try_recv().unwrap(), "borrowed value");
    assert_eq!(receiver.try_recv().unwrap(), "final value");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Closed)));
}

// Test: Send a port capability through a stack-backed message to a closed peer.
// Expected: Discarding the message drops its capability exactly as ordinary ownership.
#[test]
fn discarded_stack_messages_release_their_port_capabilities() {
    let (sender, receiver) = Port::new_pair();
    drop(receiver);
    let (capability, observer) = Port::new_pair();
    sender.send_protobuf((capability,));
    assert!(observer.is_closed().unwrap());
}

// Test: Wait for migrating ports separately from all active node ports.
// Expected: Stable ports do not block migration waits; all-port waits end on close.
#[async_test]
async fn node_drain_distinguishes_stable_ports_from_pending_migrations(driver: DefaultDriver) {
    within(&driver, async {
        let (first, second, _handles) = new_two_node_mesh(&driver);
        let (sender, mut receiver) = new_remote_port_pair(&first.node, &second.node);
        assert!(first.node.wait_for_ports(false).now_or_never().is_some());
        let mut draining = pin!(first.node.wait_for_ports(true));
        assert!(draining.as_mut().now_or_never().is_none());
        drop(sender);
        draining.await;
        assert!(matches!(receiver.recv().await, Err(RecvError::Closed)));
    })
    .await;
}

// Test: Retain cloned remote-node handles, then explicitly disconnect or fail one.
// Expected: Clones keep traffic alive; either terminal operation fails affected ports.
#[async_test]
async fn remote_handle_clones_keep_connections_alive_until_explicit_failure(driver: DefaultDriver) {
    within(&driver, async {
        for disconnect in [true, false] {
            let (first, second, mut handles) = new_two_node_mesh(&driver);
            let (sender, mut receiver) = new_remote_port_pair(&first.node, &second.node);
            let handle = second.node.get_remote_handle(first.node.id());
            let retained = handle.clone();
            drop(handle);
            handles.remove(1);
            assert!(!retained.connect(EventsFrom {
                node_id: second.node.id(),
                send: first.send.clone()
            }));
            sender.send(bmsg(b"retained"));
            assert_eq!(receiver.recv().await.unwrap().data, b"retained");
            if disconnect {
                retained.disconnect();
            } else {
                retained.fail(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            assert!(matches!(receiver.recv().await, Err(RecvError::Failed)));
            assert!(receiver.port.is_closed().is_err());
        }
    })
    .await;
}

// Test: Shut down connections, import a new port, and drop the local node.
// Expected: New connections fail immediately; node destruction fails surviving ports.
#[test]
fn node_shutdown_prevents_reconnection_and_drop_fails_surviving_ports() {
    let node = LocalNode::with_id(NodeId::new(), Box::new(NullConnect));
    let remote_id = NodeId::new();
    let _remote = node.add_remote(remote_id);
    let port = node.add_port(PortId::new(), Address::new(remote_id, PortId::new()));
    let mut existing = Channel::<(), ()>::from(port);
    assert!(matches!(existing.try_recv(), Err(TryRecvError::Empty)));
    node.fail_all_nodes();
    let port = node.add_port(PortId::new(), Address::new(NodeId::new(), PortId::new()));
    assert!(port.is_closed().is_err());
    let mut rejected = Channel::<(), ()>::from(port);
    assert!(matches!(rejected.try_recv(), Err(TryRecvError::Failed)));
    drop(node);
    assert!(matches!(existing.try_recv(), Err(TryRecvError::Failed)));
}

#[derive(Default)]
struct RejectMessages {
    failed: bool,
}

impl HandlePortEvent for RejectMessages {
    fn message<'a>(
        &mut self,
        _control: &mut PortControl<'_, 'a>,
        _message: Message<'a>,
    ) -> Result<(), HandleMessageError> {
        Err(HandleMessageError::new(std::io::Error::other(
            "invalid payload",
        )))
    }

    fn close(&mut self, _control: &mut PortControl<'_, '_>) {}

    fn fail(&mut self, _control: &mut PortControl<'_, '_>, _err: NodeError) {
        self.failed = true;
    }

    fn drain(&mut self) -> Vec<OwnedMessage> {
        Vec::new()
    }
}

// Test: Reject a message either on arrival or while installing a new handler.
// Expected: Both endpoints fail, the handler is notified, and the cause is retained.
#[test]
fn rejected_live_and_queued_messages_fail_both_endpoints_with_the_original_cause() {
    for queued in [false, true] {
        let (sender, receiver) = Port::new_pair();
        let sender: PortWithHandler<Queue> = sender.into();
        if queued {
            sender.send(Message::new((17u32,)));
        }
        let receiver = receiver.set_handler(RejectMessages::default());
        if !queued {
            sender.send(Message::new((17u32,)));
        }
        let err = receiver.is_closed().unwrap_err();
        let mut cause: &dyn std::error::Error = &err;
        while let Some(source) = cause.source() {
            cause = source;
        }
        assert_eq!(cause.to_string(), "invalid payload");
        assert!(receiver.with_handler(|handler| handler.failed));
        assert!(sender.is_closed().is_err());
        assert!(
            sender.with_handler(|handler| matches!(handler.try_recv(), Err(TryRecvError::Failed)))
        );
    }
}

struct CapturedEvents {
    node_id: NodeId,
    events: Arc<Mutex<VecDeque<RemoteEvent>>>,
}

impl SendEvent for CapturedEvents {
    fn event(&self, event: OutgoingEvent<'_>) {
        let mut data = Vec::with_capacity(event.len());
        let mut resources = Vec::new();
        event.write_to(&mut data, &mut resources);
        self.events.lock().push_back(RemoteEvent {
            node_id: self.node_id,
            data,
            resources,
        });
    }
}

struct WirePair {
    source: LocalNode,
    destination: LocalNode,
    sender: Port,
    receiver: Channel<(), String>,
    _handles: [RemoteNodeHandle; 2],
    events: Arc<Mutex<VecDeque<RemoteEvent>>>,
}

impl WirePair {
    fn new() -> Self {
        let source = LocalNode::with_id(NodeId::new(), Box::new(NullConnect));
        let destination = LocalNode::with_id(NodeId::new(), Box::new(NullConnect));
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let source_handle = source.add_remote(destination.id());
        assert!(source_handle.connect(CapturedEvents {
            node_id: source.id(),
            events: events.clone(),
        }));
        let destination_handle = destination.add_remote(source.id());
        let sender_id = PortId::new();
        let receiver_id = PortId::new();
        let sender = source.add_port(sender_id, Address::new(destination.id(), receiver_id));
        let receiver = destination
            .add_port(receiver_id, Address::new(source.id(), sender_id))
            .into();
        Self {
            source,
            destination,
            sender,
            receiver,
            _handles: [source_handle, destination_handle],
            events,
        }
    }
}

fn deliver(destination: &LocalNode, mut event: RemoteEvent) {
    destination.event(&event.node_id, &event.data, &mut event.resources);
}

// Test: Deliver captured wire messages and their final close event out of order.
// Expected: No later event overtakes missing data; full values precede closure.
#[test]
fn out_of_order_wire_messages_and_close_preserve_delivery_order() {
    let WirePair {
        source: _source,
        destination,
        sender,
        mut receiver,
        _handles,
        events,
    } = WirePair::new();
    sender.send_protobuf(("first\0payload",));
    sender.send_protobuf(("second",));
    sender.send_protobuf_and_close(("final",));
    let first = events.lock().pop_front().unwrap();
    let second = events.lock().pop_front().unwrap();
    let close = events.lock().pop_front().unwrap();
    deliver(&destination, close);
    deliver(&destination, second);
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    deliver(&destination, first);
    for expected in ["first\0payload", "second", "final"] {
        assert_eq!(receiver.try_recv().unwrap(), expected);
    }
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Closed)));
}

// Test: Deliver every incomplete prefix of a valid captured wire message.
// Expected: Truncation delivers nothing and does not consume the valid sequence.
#[test]
fn truncated_wire_messages_leave_the_valid_message_deliverable() {
    let mut pair = WirePair::new();
    pair.sender.send_protobuf(("complete\0payload",));
    let event = pair.events.lock().pop_front().unwrap();
    for len in 0..event.data.len() {
        pair.destination
            .event(&event.node_id, &event.data[..len], &mut Vec::new());
        assert!(matches!(pair.receiver.try_recv(), Err(TryRecvError::Empty)));
    }
    deliver(&pair.destination, event);
    assert_eq!(pair.receiver.try_recv().unwrap(), "complete\0payload");
    assert!(matches!(pair.receiver.try_recv(), Err(TryRecvError::Empty)));
}

// Test: Replay a delivered wire event while another port uses the same connection.
// Expected: Only the replayed destination fails; unrelated traffic remains usable.
#[test]
fn duplicate_wire_events_fail_only_the_affected_port() {
    let mut pair = WirePair::new();
    let sender_id = PortId::new();
    let receiver_id = PortId::new();
    let other_sender = pair
        .source
        .add_port(sender_id, Address::new(pair.destination.id(), receiver_id));
    let mut other_receiver = Channel::<(), String>::from(
        pair.destination
            .add_port(receiver_id, Address::new(pair.source.id(), sender_id)),
    );
    pair.sender.send_protobuf(("once",));
    let mut event = pair.events.lock().pop_front().unwrap();
    pair.destination
        .event(&event.node_id, &event.data, &mut event.resources);
    assert_eq!(pair.receiver.try_recv().unwrap(), "once");
    deliver(&pair.destination, event);
    assert!(matches!(
        pair.receiver.try_recv(),
        Err(TryRecvError::Failed)
    ));
    other_sender.send_protobuf(("unaffected",));
    deliver(&pair.destination, pair.events.lock().pop_front().unwrap());
    assert_eq!(other_receiver.try_recv().unwrap(), "unaffected");
    assert!(matches!(
        other_receiver.try_recv(),
        Err(TryRecvError::Empty)
    ));
}
