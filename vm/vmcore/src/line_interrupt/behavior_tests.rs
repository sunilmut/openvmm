// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::TestLineInterruptTarget;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use test_with_tracing::test;

// Test: Attach overlapping source ranges after lines at both inclusive endpoints and just outside them already exist.
// Expected: Asserted lines propagate immediately only to matching target vectors, and later transitions preserve range offsets independently.
#[test]
fn late_target_attachment_respects_inclusive_range_boundaries_and_offsets() {
    let set = LineSet::new();
    let below = set.new_line(9, "below").unwrap();
    let first = set.new_line(10, "first").unwrap();
    let last = set.new_line(12, "last").unwrap();
    let above = set.new_line(13, "above").unwrap();
    below.set_level(true);
    first.set_level(true);
    let left = TestLineInterruptTarget::new_arc();
    let right = TestLineInterruptTarget::new_arc();
    set.add_target(10..=12, 40, "left", left.clone());
    set.add_target(12..=14, 80, "right", right.clone());
    assert!(left.is_high(40));
    assert!(!left.is_high(39));
    assert!(!left.is_high(42));
    assert!(!right.is_high(80));
    last.set_level(true);
    above.set_level(true);
    assert!(left.is_high(42));
    assert!(right.is_high(80));
    assert!(right.is_high(81));
    assert!(!left.is_high(43));
    first.set_level(false);
    assert!(!left.is_high(40));
    assert!(left.is_high(42));
    drop(last);
    assert!(!left.is_high(42));
    assert!(!right.is_high(80));
    assert!(right.is_high(81));
}

// Test: Share a source IRQ up to its 16-handle limit through the direct sharing API, then free and reuse one slot.
// Expected: Both allocation APIs report the source IRQ at capacity, freeing one slot permits reuse, and shared assertions remain OR-combined.
#[test]
fn shared_handle_limit_reports_source_irq_and_freed_slots_are_reusable() {
    let set = LineSet::new();
    let target = TestLineInterruptTarget::new_arc();
    set.add_target(37..=37, 77, "target", target.clone());
    let root = set.new_line(37, "root").unwrap();
    let mut shared: Vec<_> = (0..15)
        .map(|index| root.new_shared(format!("shared-{index}")).unwrap())
        .collect();
    assert!(matches!(
        root.new_shared("overflow"),
        Err(NewLineError::TooMany(37))
    ));
    assert!(matches!(
        set.new_line(37, "overflow"),
        Err(NewLineError::TooMany(37))
    ));
    root.set_level(true);
    shared[0].set_level(true);
    drop(shared.pop());
    let reused = root.new_shared("reused").unwrap();
    assert!(target.is_high(77));
    drop(root);
    assert!(target.is_high(77));
    shared[0].set_level(false);
    assert!(!target.is_high(77));
    reused.set_level(true);
    assert!(target.is_high(77));
    drop(reused);
    assert!(!target.is_high(77));
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Test: Register two successive waiters on a low line and then assert it.
// Expected: Only the latest waiter wakes, polling a high line is ready immediately, and repeated assertions do not re-wake a consumed waiter.
#[test]
fn line_waiter_replacement_and_high_polling_have_exact_wake_semantics() {
    let target = TestLineInterruptTarget::new_arc();
    let line = LineInterrupt::new_with_target("line", target.clone(), 42);
    let first = Arc::new(CountWake::default());
    let second = Arc::new(CountWake::default());
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    assert_eq!(
        target.poll_high(&mut Context::from_waker(&first_waker), 42),
        Poll::Pending
    );
    assert_eq!(
        target.poll_high(&mut Context::from_waker(&second_waker), 42),
        Poll::Pending
    );
    line.set_level(true);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        target.poll_high(&mut Context::from_waker(&first_waker), 42),
        Poll::Ready(())
    );
    line.set_level(true);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
}
