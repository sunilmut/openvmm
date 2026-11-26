// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::RateLimiter;
use super::disable_rate_limiting;
use parking_lot::Mutex;
use std::time::Duration;
use std::time::Instant;
use test_with_tracing::test;

static TEST_SERIAL: Mutex<()> = Mutex::new(());

struct RestoreRateLimiting;

impl Drop for RestoreRateLimiting {
    fn drop(&mut self) {
        disable_rate_limiting(false);
    }
}

// Test: Consume the default quota and submit further events within the same period.
// Expected: Ten events are admitted, the tenth reports zero prior drops, and subsequent events are suppressed.
#[test]
fn default_quota_reports_the_last_admitted_event() {
    let _serial = TEST_SERIAL.lock();
    let limiter = RateLimiter::new_default();
    for _ in 0..9 {
        assert!(matches!(limiter.event(), Ok(None)));
    }
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
    assert!(limiter.event().is_err());
}

// Test: Suppress three events, expire the period without sleeping, and consume the next period's quota.
// Expected: The first resumed event reports exactly three drops once, and the next quota boundary reports zero new drops.
#[test]
fn expired_period_reports_missed_events_exactly_once() {
    let _serial = TEST_SERIAL.lock();
    let limiter = RateLimiter::new(60_000, 2);
    assert!(matches!(limiter.event(), Ok(None)));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    for _ in 0..3 {
        assert!(limiter.event().is_err());
    }
    limiter.state.lock().start = Some(
        Instant::now()
            .checked_sub(Duration::from_secs(61))
            .expect("representable expired period"),
    );
    assert!(matches!(limiter.event(), Ok(Some(3))));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
}

// Test: Resubmit unchanged configuration while exhausted, then independently change quota and period.
// Expected: Unchanged settings do not evade suppression; a real change starts a clean budget with no stale missed-event report.
#[test]
fn reconfiguration_resets_only_when_parameters_change() {
    let _serial = TEST_SERIAL.lock();
    let limiter = RateLimiter::new(60_000, 2);
    assert!(matches!(limiter.event(), Ok(None)));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
    assert!(limiter.event_with_config(Some(60_000), Some(2)).is_err());
    assert!(matches!(limiter.event_with_config(None, Some(3)), Ok(None)));
    assert!(matches!(limiter.event(), Ok(None)));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
    assert!(matches!(
        limiter.event_with_config(Some(120_000), None),
        Ok(None)
    ));
    assert!(matches!(limiter.event(), Ok(None)));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
}

// Test: Submit an event while the limiter state is locked, then release it and exercise a zero quota.
// Expected: Contention suppresses without blocking or spending the budget, and a zero quota admits no events.
#[test]
fn contention_and_zero_quota_never_grant_extra_budget() {
    let _serial = TEST_SERIAL.lock();
    let limiter = RateLimiter::new(60_000, 2);
    let held = limiter.state.lock();
    assert!(limiter.event().is_err());
    drop(held);
    assert!(matches!(limiter.event(), Ok(None)));
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
    let zero = RateLimiter::new(60_000, 0);
    assert!(zero.event().is_err());
    assert!(zero.event().is_err());
}

// Test: Bypass an exhausted limiter and a contended limiter, then reenable it after a configuration request during bypass.
// Expected: Bypass admits events without spending or reconfiguring state; reenabling restores the original exhausted budget.
#[test]
fn global_bypass_does_not_spend_or_reconfigure_budget() {
    let _serial = TEST_SERIAL.lock();
    let _restore = RestoreRateLimiting;
    let limiter = RateLimiter::new(60_000, 1);
    assert!(matches!(limiter.event(), Ok(Some(0))));
    assert!(limiter.event().is_err());
    disable_rate_limiting(true);
    let held = limiter.state.lock();
    for _ in 0..3 {
        assert!(matches!(
            limiter.event_with_config(Some(120_000), Some(4)),
            Ok(None)
        ));
    }
    drop(held);
    disable_rate_limiting(false);
    assert!(limiter.event().is_err());
}
