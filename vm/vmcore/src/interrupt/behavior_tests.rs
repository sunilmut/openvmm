// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{EventProxy, Interrupt, InterruptTarget};
use mesh::payload::SerializedMessage;
use mesh::resource::Resource;
use pal_event::Event;
use test_with_tracing::test;

// Test: Serialize event-backed and callback-backed interrupts and decode a message with no interrupt event.
// Expected: Decoded event handles retain the original signal identity, while local callbacks and absent events cannot cross the serialized boundary.
#[test]
fn serialized_interrupts_preserve_event_identity_and_reject_missing_events() {
    let event = Event::new();
    let encoded = SerializedMessage::<Resource>::from_message(Interrupt::from_event(event.clone()));
    let decoded: Interrupt = encoded.into_message().unwrap();
    decoded.deliver();
    assert!(event.try_wait());
    assert!(!event.try_wait());
    decoded.clone().deliver();
    assert!(event.try_wait());
    for encoded in [
        SerializedMessage::<Resource>::from_message(Interrupt::from_fn(|| {})),
        SerializedMessage::default(),
    ] {
        let result: Result<Interrupt, _> = encoded.into_message();
        assert!(
            result.is_err(),
            "interrupt without an event must not decode"
        );
    }
}

struct Callback {
    delivered: mesh::Sender<()>,
    released: Option<mesh::OneshotSender<()>>,
}

impl InterruptTarget for Callback {
    fn deliver(&self) {
        self.delivered.send(());
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.released.take().unwrap().send(());
    }
}

// Test: Deliver twice through a callback proxy, then drop its owner before signaling its event again.
// Expected: Each acknowledged signal reaches the target once, dropping the proxy releases the target, and no later callback remains possible.
#[pal_async::async_test]
async fn proxy_cancellation_releases_its_target_and_prevents_later_delivery(
    driver: pal_async::DefaultDriver,
) {
    let (delivered, mut deliveries) = mesh::channel();
    let (released, release) = mesh::oneshot();
    let interrupt = Interrupt::from_target(Callback {
        delivered,
        released: Some(released),
    });
    let (proxy, event) = EventProxy::new(&driver, interrupt).unwrap();
    for _ in 0..2 {
        event.signal();
        deliveries.recv().await.unwrap();
    }
    drop(proxy);
    release.await.unwrap();
    event.signal();
    assert!(deliveries.recv().await.is_err());
}
