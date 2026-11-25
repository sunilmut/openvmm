// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use pal_async::{DefaultDriver, async_test};
use test_with_tracing::test;

// Test: Compare VM times on either side of zero and of the 64-bit wrap boundary, including sub-100-ns duration truncation.
// Expected: Ordering/min/max/subtraction use relative modular time and duration addition retains only complete 100-ns ticks.
#[test]
fn modular_time_arithmetic_preserves_wrap_order_and_tick_resolution() {
    for (earlier, later, ticks) in [(0, 7, 7), (u64::MAX - 3, 3, 7)] {
        let earlier = VmTime::from_100ns(earlier);
        let later = VmTime::from_100ns(later);
        assert!(earlier.is_before(later));
        assert!(later.is_after(earlier));
        assert_eq!(earlier.min(later), earlier);
        assert_eq!(later.min(earlier), earlier);
        assert_eq!(earlier.max(later), later);
        assert_eq!(later.max(earlier), later);
        assert_eq!(
            later.checked_sub(earlier),
            Some(Duration::from_nanos(ticks * 100))
        );
        assert_eq!(earlier.checked_sub(later), None);
        assert_eq!(
            earlier.wrapping_add(Duration::from_nanos(ticks * 100)),
            later
        );
        assert!(!earlier.is_before(earlier));
        assert!(!earlier.is_after(earlier));
    }
    assert_eq!(
        VmTime::from_100ns(50)
            .wrapping_add(Duration::from_nanos(199))
            .as_100ns(),
        51
    );
}

// Test: Restore a stopped keeper shared by two time sources, then start and stop it.
// Expected: Save/restore is exact for every source, stopped time has no host mapping, and running timestamps map earlier guest times to the resume point.
#[async_test]
async fn keeper_restore_and_host_mapping_are_consistent_across_sources(driver: DefaultDriver) {
    let mut keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(123));
    let first = keeper.builder().build(&driver).await.unwrap();
    let second = first.builder().build(&driver).await.unwrap();
    let first = first.access("first");
    let second = second.access("second");
    assert_eq!(keeper.save().vmtime.as_100ns(), 123);
    assert_eq!(first.now().as_100ns(), 123);
    assert!(first.host_time(VmTime::from_100ns(123)).is_none());
    keeper
        .restore(SavedState::from_vmtime(VmTime::from_100ns(900)))
        .await;
    assert_eq!(keeper.save().vmtime.as_100ns(), 900);
    assert_eq!(first.now().as_100ns(), 900);
    assert_eq!(second.now().as_100ns(), 900);
    keeper.start().await;
    let resume = first.host_time(VmTime::from_100ns(900)).unwrap();
    assert_eq!(first.host_time(VmTime::from_100ns(800)), Some(resume));
    assert_eq!(
        first.host_time(VmTime::from_100ns(901)).unwrap().as_nanos() - resume.as_nanos(),
        100
    );
    keeper.stop().await;
    assert_eq!(first.now(), second.now());
    assert!(!first.now().is_before(VmTime::from_100ns(900)));
    assert!(second.host_time(second.now()).is_none());
}

// Test: Sample a started clock with host timestamps before and after its recorded start, including a large backward jump.
// Expected: Earlier samples clamp to the start timestamp instead of underflowing VM time; later samples advance by complete 100-ns ticks.
#[test]
fn host_samples_before_start_clamp_without_wrapping_the_guest_clock() {
    let start = Timestamp::new(VmTime::from_100ns(900), Instant::from_nanos(5_000_000_000));
    let state = TimeState::Started(start);
    for now in [4_999_999_900, 3_000_000_000] {
        let timestamp = state.now(Instant::from_nanos(now));
        assert_eq!(timestamp.vmtime, start.vmtime);
        assert_eq!(timestamp.os_time(), start.os_time());
    }
    let later = state.now(Instant::from_nanos(5_000_001_299));
    assert_eq!(later.vmtime.as_100ns(), 912);
    assert_eq!(later.os_time(), Instant::from_nanos(5_000_001_299));
}

// Test: Register two stopped-clock waiters with different deadlines, then start the shared clock and await both.
// Expected: The timer rearms across pending deadlines, neither completion precedes its VM deadline, and both one-shot timeouts are consumed.
#[async_test]
async fn running_clock_rearms_and_completes_each_registered_timeout(driver: DefaultDriver) {
    let mut keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let source = keeper.builder().build(&driver).await.unwrap();
    let mut early = source.access("early");
    let mut late = source.access("late");
    let early_deadline = VmTime::from_100ns(100_000);
    let late_deadline = VmTime::from_100ns(300_000);
    early.set_timeout(early_deadline);
    late.set_timeout(late_deadline);
    assert!(
        poll_fn(|cx| early.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    assert!(poll_fn(|cx| late.poll_timeout(cx)).now_or_never().is_none());
    keeper.start().await;
    let (early_now, late_now) = futures::join!(
        poll_fn(|cx| early.poll_timeout(cx)),
        poll_fn(|cx| late.poll_timeout(cx)),
    );
    assert!(early_now.is_after(early_deadline));
    assert!(late_now.is_after(late_deadline));
    assert_eq!(early.get_timeout(), None);
    assert_eq!(late.get_timeout(), None);
    keeper.stop().await;
}

// Test: Shorten but never extend an existing timeout, cancel it while waiting, and then request an already-due timeout.
// Expected: The earliest deadline wins, cancellation removes pending delivery, and immediate completion consumes its timeout.
#[async_test]
async fn timeout_shortening_cancellation_and_immediate_completion(driver: DefaultDriver) {
    let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(1000));
    let source = keeper.builder().build(&driver).await.unwrap();
    let mut access = source.access("timeout");
    access.set_timeout_if_before(VmTime::from_100ns(1200));
    access.set_timeout_if_before(VmTime::from_100ns(1300));
    assert_eq!(access.get_timeout(), Some(VmTime::from_100ns(1200)));
    access.set_timeout_if_before(VmTime::from_100ns(1100));
    assert_eq!(access.get_timeout(), Some(VmTime::from_100ns(1100)));
    assert!(
        poll_fn(|cx| access.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    access.cancel_timeout();
    access.cancel_timeout();
    assert_eq!(access.get_timeout(), None);
    assert!(
        poll_fn(|cx| access.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    access.set_timeout(VmTime::from_100ns(900));
    assert_eq!(
        poll_fn(|cx| access.poll_timeout(cx)).now_or_never(),
        Some(VmTime::from_100ns(1000))
    );
    assert_eq!(access.get_timeout(), None);
}

// Test: Start a periodic timer on a stopped clock, restore beyond several periods, and then cancel/restart it.
// Expected: One poll reports the current due time and catches up to a future deadline, repeated polling does not redeliver, and cancellation prevents further expiration.
#[async_test]
async fn periodic_timer_catches_up_and_cancel_restart_preserves_state(driver: DefaultDriver) {
    let mut keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(100));
    let source = keeper.builder().build(&driver).await.unwrap();
    let mut timer = VmTimerPeriodic::new(source.access("periodic"));
    assert!(!timer.is_running());
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    timer.start(Duration::from_nanos(1000));
    assert!(timer.is_running());
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    keeper
        .restore(SavedState {
            vmtime: VmTime::from_100ns(145),
        })
        .await;
    assert_eq!(
        poll_fn(|cx| timer.poll_timeout(cx)).now_or_never(),
        Some(VmTime::from_100ns(145))
    );
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    timer.cancel();
    assert!(!timer.is_running());
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    timer.start(Duration::from_nanos(2000));
    keeper
        .restore(SavedState {
            vmtime: VmTime::from_100ns(164),
        })
        .await;
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    keeper
        .restore(SavedState {
            vmtime: VmTime::from_100ns(165),
        })
        .await;
    assert!(
        poll_fn(|cx| timer.poll_timeout(cx))
            .now_or_never()
            .is_none()
    );
    keeper
        .restore(SavedState {
            vmtime: VmTime::from_100ns(166),
        })
        .await;
    assert_eq!(
        poll_fn(|cx| timer.poll_timeout(cx)).now_or_never(),
        Some(VmTime::from_100ns(166))
    );
    timer.cancel();
}

// Test: Retain a time-source builder after its owning keeper has been dropped.
// Expected: Building a new source returns TimeKeeperIsGone rather than hanging or constructing a disconnected clock.
#[async_test]
async fn building_after_keeper_drop_returns_the_public_lifetime_error(driver: DefaultDriver) {
    let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let builder = keeper.builder().clone();
    drop(keeper);
    assert!(matches!(
        builder.build(&driver).await,
        Err(TimeKeeperIsGone)
    ));
}
