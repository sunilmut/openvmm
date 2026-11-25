// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::{FutureExt, StreamExt};
use pal_async::{DefaultDriver, async_test};

// Test: Poll and await notifications backed by an OS event and by a slim event, then convert the pollable handle back.
// Expected: Cloned interrupts signal the same object before/after round-trip conversion, consumed signals do not repeat, and event availability reflects the backing type.
#[async_test]
async fn notification_backings_preserve_signal_identity_across_pollable_round_trips(
    driver: DefaultDriver,
) {
    for os_event in [false, true] {
        let notify = if os_event {
            Notify::from_event(Event::new())
        } else {
            Notify::from_slim_event(Arc::new(SlimEvent::new()))
        };
        assert_eq!(notify.event().is_some(), os_event);
        let interrupt = notify.clone().interrupt();
        let mut polled = notify.pollable(&driver).unwrap();
        assert!(poll_fn(|cx| polled.poll_wait(cx)).now_or_never().is_none());
        interrupt.deliver();
        polled.wait().await;
        assert!(poll_fn(|cx| polled.poll_wait(cx)).now_or_never().is_none());
        let notify = polled.into_inner();
        assert_eq!(notify.event().is_some(), os_event);
        let mut restored = notify.pollable(&driver).unwrap();
        interrupt.deliver();
        poll_fn(|cx| restored.poll_wait(cx)).await;
        assert!(restored.wait().now_or_never().is_none());
        interrupt.deliver();
        restored.wait().await;
    }
}

// Test: Signal a slim event repeatedly before and after consuming a stream item.
// Expected: Multiple outstanding signals coalesce into one item, each item consumes its signal, and future signals remain observable through either stream or wait APIs.
#[async_test]
async fn slim_event_stream_coalesces_signals_and_consumes_each_notification(
    _driver: DefaultDriver,
) {
    let event = SlimEvent::new();
    {
        let mut stream = event.as_stream();
        assert!(stream.next().now_or_never().is_none());
        event.signal();
        event.signal();
        assert_eq!(stream.next().await, Some(()));
        assert!(stream.next().now_or_never().is_none());
        event.signal();
        assert_eq!(stream.next().await, Some(()));
    }
    assert!(event.wait().now_or_never().is_none());
    event.signal();
    event.wait().await;
    assert!(event.wait().now_or_never().is_none());
}
