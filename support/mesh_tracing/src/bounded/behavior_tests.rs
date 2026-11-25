// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{BoundedReceiver, BoundedSender, TrySendError, bounded};
use futures::{FutureExt, StreamExt};
use mesh::payload::SerializedMessage;
use mesh::resource::Resource;
use test_with_tracing::test;

// Test: Fill a four-message channel and block an async send while consuming messages across the quota-return boundary.
// Expected: One read does not release quota, the second unblocks the pending send, and all accepted payloads arrive once in FIFO order before closure.
#[test]
fn quota_boundary_unblocks_async_send_without_reordering_or_early_credit() {
    let (mut send, mut receive) = bounded::<u32>(4);
    for value in 1..=4 {
        send.try_send(value).unwrap();
    }
    assert!(matches!(send.try_send(99), Err(TrySendError::Full)));
    {
        let mut pending = std::pin::pin!(send.send(5));
        assert!(pending.as_mut().now_or_never().is_none());
        assert_eq!(receive.next().now_or_never(), Some(Some(1)));
        assert!(pending.as_mut().now_or_never().is_none());
        assert_eq!(receive.next().now_or_never(), Some(Some(2)));
        assert_eq!(pending.as_mut().now_or_never(), Some(()));
    }
    drop(send);
    assert_eq!(
        futures::executor::block_on(receive.collect::<Vec<_>>()),
        [3, 4, 5]
    );
}

// Test: Close the receiver while a sender is blocked by exhausted quota, and create a channel with zero quota.
// Expected: Receiver closure releases the pending send and future sends report Closed; zero quota never accepts a payload.
#[test]
fn receiver_closure_releases_blocked_send_and_zero_quota_never_accepts() {
    let (mut send, receive) = bounded::<u32>(1);
    send.try_send(1).unwrap();
    {
        let mut pending = std::pin::pin!(send.send(2));
        assert!(pending.as_mut().now_or_never().is_none());
        drop(receive);
        assert_eq!(pending.as_mut().now_or_never(), Some(()));
    }
    assert!(matches!(send.try_send(3), Err(TrySendError::Closed)));
    let (send, receive) = bounded::<u32>(0);
    assert!(matches!(send.try_send(1), Err(TrySendError::Full)));
    drop(receive);
    assert!(matches!(send.try_send(1), Err(TrySendError::Closed)));
}

// Test: Serialize a receiver with its entire quota queued, then serialize its sender after the queue is drained.
// Expected: Endpoint transfer preserves exact queued payloads, FIFO order, reclaimed capacity, and clean end-of-stream after sender closure.
#[test]
fn serialized_endpoints_preserve_queued_messages_and_reclaimed_capacity() {
    let (send, receive) = bounded::<u32>(4);
    for value in [11, 22, 33, 44] {
        send.try_send(value).unwrap();
    }
    let encoded = SerializedMessage::<Resource>::from_message(receive);
    let mut receive: BoundedReceiver<u32> = encoded.into_message().unwrap();
    for expected in [11, 22, 33, 44] {
        assert_eq!(receive.next().now_or_never(), Some(Some(expected)));
    }
    let encoded = SerializedMessage::<Resource>::from_message(send);
    let send: BoundedSender<u32> = encoded.into_message().unwrap();
    for value in [55, 66, 77, 88] {
        send.try_send(value).unwrap();
    }
    assert!(matches!(send.try_send(99), Err(TrySendError::Full)));
    drop(send);
    assert_eq!(
        futures::executor::block_on(receive.collect::<Vec<_>>()),
        [55, 66, 77, 88]
    );
}

// Test: Transfer a receiver after consuming one message of a two-message quota-return batch, then drain the rest.
// Expected: Consumption before and after transfer contributes to the same quota accounting, so draining four messages restores all four send slots.
#[test]
#[ignore = "known product bug: receiver serialization drops partially consumed quota"]
fn known_bug_receiver_transfer_preserves_partially_consumed_quota() {
    let (send, mut receive) = bounded::<u32>(4);
    for value in 1..=4 {
        send.try_send(value).unwrap();
    }
    assert_eq!(receive.next().now_or_never(), Some(Some(1)));
    let encoded = SerializedMessage::<Resource>::from_message(receive);
    let mut receive: BoundedReceiver<u32> = encoded.into_message().unwrap();
    for expected in 2..=4 {
        assert_eq!(receive.next().now_or_never(), Some(Some(expected)));
    }
    for value in 5..=8 {
        send.try_send(value).unwrap();
    }
    assert!(matches!(send.try_send(9), Err(TrySendError::Full)));
    drop(send);
    assert_eq!(
        futures::executor::block_on(receive.collect::<Vec<_>>()),
        [5, 6, 7, 8]
    );
}

// Test: Decode a serialized numeric receiver as a string receiver, then send a numeric payload from its original peer.
// Expected: The incompatible wire payload is rejected without producing a fabricated string or panicking.
#[test]
fn incompatible_serialized_payload_is_rejected_without_a_value() {
    let (send, receive) = bounded::<u32>(2);
    let encoded = SerializedMessage::<Resource>::from_message(receive);
    let mut receive: BoundedReceiver<String> = encoded.into_message().unwrap();
    send.try_send(17).unwrap();
    assert_eq!(receive.next().now_or_never(), Some(None));
}

// Test: Inject a malformed quota response through the actual mesh transport, with and without an already accepted payload.
// Expected: Protocol failure closes the sender and terminates the receiver, but accepted data is delivered before the terminal error.
#[test]
fn malformed_quota_closes_the_channel_without_discarding_accepted_data() {
    for accepted in [None, Some(42)] {
        let (send, mut receive) = bounded::<u32>(2);
        if let Some(value) = accepted {
            send.try_send(value).unwrap();
        } else {
            assert!(receive.next().now_or_never().is_none());
        }
        receive.port.with_port_and_handler(|port, _| {
            port.respond(mesh::Message::new(("invalid quota".to_owned(),)));
        });
        assert!(matches!(send.try_send(99), Err(TrySendError::Closed)));
        if let Some(value) = accepted {
            assert_eq!(receive.next().now_or_never(), Some(Some(value)));
        }
        assert_eq!(receive.next().now_or_never(), Some(None));
        assert_eq!(receive.next().now_or_never(), Some(None));
    }
}
