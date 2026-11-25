// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::multi_waker::MultiWaker;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use test_with_tracing::test;

#[derive(Default)]
struct Notification(AtomicBool);

impl Wake for Notification {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn register(mux: &MultiWaker<2>, index: usize, waker: &Waker) -> Waker {
    let Poll::Ready(registered) = mux.poll_wrapped(&mut Context::from_waker(waker), index, |cx| {
        Poll::Ready(cx.waker().clone())
    }) else {
        panic!("registration must complete synchronously")
    };
    registered
}

// Test: Replace one registered waiter and retain cloned multiplexed wake handles.
// Expected: Only current waiters wake, even after the multiplexer itself is dropped.
#[test]
fn cloned_wakers_preserve_current_waiters_without_retaining_stale_registrations() {
    let mux = MultiWaker::new();
    let old = Arc::new(Notification::default());
    let current = Arc::new(Notification::default());
    let peer = Arc::new(Notification::default());
    let retained = register(&mux, 0, &Waker::from(old.clone()));
    drop(register(&mux, 0, &Waker::from(current.clone())));
    drop(register(&mux, 1, &Waker::from(peer.clone())));
    let cloned = retained.clone();
    drop(mux);
    cloned.wake_by_ref();
    assert!(!old.0.load(Ordering::SeqCst));
    assert!(current.0.swap(false, Ordering::SeqCst));
    assert!(peer.0.swap(false, Ordering::SeqCst));
    retained.wake();
    assert!(!current.0.load(Ordering::SeqCst));
    assert!(!peer.0.load(Ordering::SeqCst));
}

// Test: Wake the temporary context directly while another index has a saved waiter.
// Expected: Both the current caller and the other registered caller are notified.
#[test]
fn waking_a_temporary_context_notifies_other_registered_waiters() {
    let mux = MultiWaker::new();
    let current = Arc::new(Notification::default());
    let peer = Arc::new(Notification::default());
    drop(register(&mux, 1, &Waker::from(peer.clone())));
    let waker = Waker::from(current.clone());
    assert!(
        mux.poll_wrapped(&mut Context::from_waker(&waker), 0, |cx| {
            cx.waker().wake_by_ref();
            Poll::Ready(())
        })
        .is_ready()
    );
    assert!(current.0.load(Ordering::SeqCst));
    assert!(peer.0.load(Ordering::SeqCst));
}
