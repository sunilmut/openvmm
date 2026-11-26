// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public interrupt recipient lifetime and wake registration.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::task::Context;
use std::task::Wake;
use std::task::Waker;
use test_with_tracing::test;
use user_driver::interrupt::DeviceInterruptSource;

#[derive(Default)]
struct WakeFlag(AtomicBool);

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, SeqCst);
    }
}

// Test: Clone a signaled recipient, then alternate cached and uncached signals
//       across independently consumed and newly registered recipients.
// Expected: New clones inherit no old notification; each live recipient gets
//       future notifications independently, with signaled state consumed once.
#[test]
fn clone_registration_and_broadcast_do_not_replay_old_notifications() {
    let mut source = DeviceInterruptSource::new();
    let mut original = source.new_target();
    source.signal();
    let mut clone = original.clone();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(clone.poll(&mut cx).is_pending());
    assert!(original.poll(&mut cx).is_ready());
    assert!(original.poll(&mut cx).is_pending());
    source.signal_uncached();
    assert!(original.poll(&mut cx).is_ready());
    assert!(clone.poll(&mut cx).is_ready());
    assert!(clone.poll(&mut cx).is_pending());
    let mut late = source.new_target();
    assert!(late.poll(&mut cx).is_pending());
    source.signal();
    source.signal();
    assert!(original.poll(&mut cx).is_ready());
    assert!(clone.poll(&mut cx).is_ready());
    assert!(late.poll(&mut cx).is_ready());
    assert!(original.poll(&mut cx).is_pending());
    assert!(clone.poll(&mut cx).is_pending());
    assert!(late.poll(&mut cx).is_pending());
}

// Test: Replace a recipient's waiting task, then remove a different recipient
//       after the source has cached it.
// Expected: Only the current waiting task is awakened, and neither cached nor
//       uncached broadcasts awaken a dropped recipient.
#[test]
fn current_waker_replaces_old_and_dropped_recipient_is_not_awakened() {
    let mut source = DeviceInterruptSource::new();
    let mut live = source.new_target();
    let old = Arc::new(WakeFlag::default());
    let current = Arc::new(WakeFlag::default());
    let old_waker = Waker::from(old.clone());
    let current_waker = Waker::from(current.clone());
    assert!(live.poll(&mut Context::from_waker(&old_waker)).is_pending());
    assert!(
        live.poll(&mut Context::from_waker(&current_waker))
            .is_pending()
    );
    source.signal();
    assert!(!old.0.load(SeqCst));
    assert!(current.0.load(SeqCst));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(live.poll(&mut cx).is_ready());
    let mut doomed = live.clone();
    source.signal();
    assert!(doomed.poll(&mut cx).is_ready());
    let dropped = Arc::new(WakeFlag::default());
    let dropped_waker = Waker::from(dropped.clone());
    assert!(
        doomed
            .poll(&mut Context::from_waker(&dropped_waker))
            .is_pending()
    );
    drop(doomed);
    source.signal_uncached();
    source.signal();
    assert!(!dropped.0.load(SeqCst));
    assert!(live.poll(&mut cx).is_ready());
}
