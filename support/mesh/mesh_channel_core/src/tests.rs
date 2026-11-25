// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{Receiver, RecvError, Sender, TryRecvError, channel, oneshot};
use futures::StreamExt;
use futures::executor::block_on;
use mesh_node::local_node::Port;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// Test: Bridge two channels with messages already queued on both sides.
// Expected: Existing and future messages arrive in order, and dropping the last
//       upstream sender closes the downstream stream.
#[test]
fn bridges_preserve_queued_messages_and_propagate_closure() {
    block_on(async {
        let (upstream, relay_in) = channel::<u32>();
        let (relay_out, mut downstream) = channel::<u32>();
        relay_out.send(1);
        upstream.send(2);
        relay_in.bridge(relay_out);
        upstream.send(3);
        for expected in [1, 2, 3] {
            assert_eq!(downstream.recv().await.unwrap(), expected);
        }
        drop(upstream);
        assert!(matches!(downstream.recv().await, Err(RecvError::Closed)));

        let (upstream, relay_in) = channel::<u32>();
        let (relay_out, mut downstream) = channel::<u32>();
        relay_out.bridge(relay_in);
        upstream.send(4);
        assert_eq!(downstream.recv().await.unwrap(), 4);
        drop(upstream);
        assert_eq!(downstream.next().await, None);
    });
}

// Test: Reopen a receiver that initially has no senders, then repeat after closure.
// Expected: Each new sender restores delivery, and the final close is visible to
//       both nonblocking receives and the stream interface.
#[test]
fn default_receiver_can_be_reopened_after_closure() {
    block_on(async {
        let mut receiver = Receiver::<u32>::default();
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Closed)));
        for value in [7, 9] {
            let sender = receiver.sender();
            assert!(!sender.is_closed());
            assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            sender.send(value);
            assert_eq!(receiver.recv().await.unwrap(), value);
            drop(sender);
            assert_eq!(receiver.next().await, None);
        }
    });
}

// Test: Convert a polled receiver back through a port and close its peer.
// Expected: Port conversion preserves pending reception and later sender closure.
#[test]
fn polled_remote_receiver_roundtrips_without_losing_delivery() {
    block_on(async {
        let (send_port, recv_port) = Port::new_pair();
        let mut receiver = Receiver::<u32>::from(recv_port);
        assert!(futures::poll!(receiver.next()).is_pending());
        let mut receiver = Receiver::<u32>::from(Port::from(receiver));
        let sender = Sender::<u32>::from(send_port);
        assert!(!sender.is_closed());
        sender.send(42);
        assert_eq!(receiver.recv().await.unwrap(), 42);
        drop(receiver);
        assert!(sender.is_closed());
        let closed_port = Port::from(sender);
        assert!(Sender::<u32>::from(closed_port).is_closed());
    });
}

struct DropNotice(Arc<AtomicUsize>);

impl Drop for DropNotice {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Test: Send owned values after a receiver closes and abandon queued values.
// Expected: Rejected and unread values are each dropped exactly once.
#[test]
fn abandoned_values_are_released_by_both_channel_types() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = channel();
    sender.send(DropNotice(drops.clone()));
    drop(receiver);
    assert!(sender.is_closed());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    sender.send(DropNotice(drops.clone()));
    assert_eq!(drops.load(Ordering::SeqCst), 2);

    let (sender, receiver) = oneshot();
    assert!(!sender.is_closed());
    drop(receiver);
    assert!(sender.is_closed());
    sender.send(DropNotice(drops.clone()));
    assert_eq!(drops.load(Ordering::SeqCst), 3);

    let (sender, receiver) = oneshot();
    sender.send(DropNotice(drops.clone()));
    drop(receiver);
    assert_eq!(drops.load(Ordering::SeqCst), 4);
}

// Test: Convert oneshot senders with open and already-closed receivers through ports.
// Expected: Delivery works before closure, and later conversions retain closure.
#[test]
fn oneshot_port_conversions_preserve_delivery_and_closed_status() {
    block_on(async {
        let (sender, receiver) = oneshot::<String>();
        let sender = crate::OneshotSender::<String>::from(Port::from(sender));
        assert!(!sender.is_closed());
        sender.send("delivered".into());
        assert_eq!(receiver.await.unwrap(), "delivered");

        let (sender, receiver) = oneshot::<u32>();
        drop(receiver);
        let sender = crate::OneshotSender::<u32>::from(Port::from(sender));
        assert!(sender.is_closed());
        drop(sender);

        let (sender, receiver) = oneshot::<u32>();
        let receiver = crate::OneshotReceiver::<u32>::from(Port::from(receiver));
        assert!(!sender.is_closed());
        drop(receiver);
        assert!(sender.is_closed());
    });
}

// Test: Receive an incompatible encoded payload through each receive interface.
// Expected: Corruption is reported as a typed channel error or stream termination,
//       rather than returning an invalid value.
#[test]
fn malformed_payloads_fail_nonblocking_and_stream_receivers() {
    let (sender, receiver) = channel::<String>();
    let mut receiver = Receiver::<u32>::from(Port::from(receiver));
    sender.send("not an integer".into());
    let error = match receiver.try_recv() {
        Err(TryRecvError::Error(error)) => error,
        _ => panic!("expected channel error"),
    };
    assert!(matches!(error.kind(), crate::ChannelErrorKind::NodeFailure));
    assert!(std::error::Error::source(&error).is_some());

    block_on(async {
        let (sender, receiver) = channel::<String>();
        let mut receiver = Receiver::<u32>::from(Port::from(receiver));
        sender.send("not an integer".into());
        assert_eq!(receiver.next().await, None);
    });
}
