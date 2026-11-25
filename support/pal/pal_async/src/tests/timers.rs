// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::timer::Instant;
use pal_async_test::async_test;
use test_with_tracing::test;

// Test: Compute timer deadlines at the clock's lower and upper boundaries.
// Expected: Saturating operations clamp, while ordinary arithmetic retains nanoseconds.
#[test]
fn deadline_arithmetic_handles_saturation_and_precise_durations() {
    let start = Instant::from_nanos(10);
    assert_eq!((start + Duration::from_nanos(7)).as_nanos(), 17);
    assert_eq!((start - Duration::from_nanos(7)).as_nanos(), 3);
    assert_eq!(
        start.saturating_sub(Instant::from_nanos(11)),
        Duration::ZERO
    );
    assert_eq!(
        start.saturating_sub(Instant::from_nanos(3)),
        Duration::from_nanos(7)
    );
    assert_eq!(start.saturating_add(Duration::MAX).as_nanos(), u64::MAX);
    assert_eq!(
        Instant::from_nanos(u64::MAX - 2)
            .saturating_add(Duration::from_nanos(3))
            .as_nanos(),
        u64::MAX
    );
}

// Test: Replace a pending timer deadline with an already expired deadline.
// Expected: The cancelled long wait does not delay the replacement timer.
#[async_test]
async fn replacing_a_timer_deadline_wakes_at_the_new_deadline(driver: DefaultDriver) {
    within(&driver, async {
        let mut timer = PolledTimer::new(&driver);
        assert!(
            timer
                .sleep(Duration::from_secs(60))
                .now_or_never()
                .is_none()
        );
        let deadline = Instant::now();
        let now = std::future::poll_fn(|cx| timer.poll_until(cx, deadline)).await;
        assert!(now >= deadline);
        let deadline = Instant::now() + Duration::from_millis(2);
        assert!(timer.sleep_until(deadline).await >= deadline);
    })
    .await;
}
