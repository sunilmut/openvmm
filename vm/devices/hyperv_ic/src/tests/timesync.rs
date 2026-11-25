// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::test_helpers::restore;
use crate::test_helpers::start;
use crate::timesync::TimesyncIc;
use hyperv_ic_protocol::MessageType;
use hyperv_ic_protocol::Status;
use hyperv_ic_protocol::timesync as proto;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::timer::PolledTimer;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use test_with_tracing::test;
use vmbus_channel::test_helpers::stop_with_timeout;
use vmcore::reference_time::GetReferenceTime;
use vmcore::reference_time::ReferenceTimeResult;
use vmcore::reference_time::ReferenceTimeSource;
use zerocopy::FromBytes;

pub(super) struct TimeSource {
    pub snapshot: Option<jiff::Timestamp>,
    pub counter: AtomicU64,
}

impl GetReferenceTime for TimeSource {
    fn now(&self) -> ReferenceTimeResult {
        ReferenceTimeResult {
            ref_time: self.counter.fetch_add(1, Ordering::SeqCst),
            system_time: self.snapshot,
        }
    }
}

// Test: Negotiate time synchronization, acknowledge the initial sync, wait for
//       a periodic sample, then save and restore the device.
// Expected: Wire timestamps preserve 100ns precision, samples use fresh reference
//       times, and restore renegotiates and sends a new sync rather than a sample.
#[async_test]
async fn sync_sample_and_restore_preserve_timestamp_and_flags(driver: DefaultDriver) {
    let source = ReferenceTimeSource::new(TimeSource {
        snapshot: Some(jiff::Timestamp::new(1_700_000_000, 123_456_700).unwrap()),
        counter: AtomicU64::new(42),
    });
    let (mut task, mut guest) = start(&driver, TimesyncIc::new(&driver, source));
    guest.negotiate(proto::TIMESYNC_VERSION_4).await;
    let frame = guest.receive(MessageType::TIME_SYNC).await;
    let message = proto::TimesyncMessageV4::read_from_bytes(&frame.body).unwrap();
    assert_eq!(message.parent_time.get(), 133_444_736_001_234_567);
    assert_eq!(message.vm_reference_time, 42);
    assert!(message.flags.sync());
    assert!(!message.flags.sample());
    guest.respond(&frame, Status::SUCCESS, &[]).await;
    // Samples are deliberately periodic. Wait outside the shared five-second
    // response deadline, then use that deadline to bound receiving the sample.
    PolledTimer::new(&driver)
        .sleep(Duration::from_secs(5))
        .await;
    let frame = guest.receive(MessageType::TIME_SYNC).await;
    let message = proto::TimesyncMessageV4::read_from_bytes(&frame.body).unwrap();
    assert_eq!(message.parent_time.get(), 133_444_736_001_234_567);
    assert_eq!(message.vm_reference_time, 43);
    assert!(!message.flags.sync());
    assert!(message.flags.sample());
    stop_with_timeout(&mut task, &driver).await;
    let mut guest = restore(&driver, &mut task);
    assert!(task.start());
    guest.negotiate(proto::TIMESYNC_VERSION_4).await;
    let frame = guest.receive(MessageType::TIME_SYNC).await;
    let message = proto::TimesyncMessageV4::read_from_bytes(&frame.body).unwrap();
    assert_eq!(message.vm_reference_time, 44);
    assert!(message.flags.sync());
    assert!(!message.flags.sample());
    stop_with_timeout(&mut task, &driver).await;
}

// Test: Synchronize time using a reference source without a system-time snapshot.
// Expected: The reference time is preserved and wall-clock time is sampled
//       between the caller's before/after bounds, expressed in the guest epoch.
#[async_test]
async fn missing_snapshot_uses_current_system_time(driver: DefaultDriver) {
    let source = ReferenceTimeSource::new(TimeSource {
        snapshot: None,
        counter: AtomicU64::new(0x12345678),
    });
    let before = jiff::Timestamp::now();
    let (mut task, mut guest) = start(&driver, TimesyncIc::new(&driver, source));
    guest.negotiate(proto::TIMESYNC_VERSION_4).await;
    let frame = guest.receive(MessageType::TIME_SYNC).await;
    let after = jiff::Timestamp::now();
    let message = proto::TimesyncMessageV4::read_from_bytes(&frame.body).unwrap();
    let ticks = message.parent_time.get();
    let unix_ticks = ticks - 116_444_736_000_000_000;
    let actual = jiff::Timestamp::new(
        (unix_ticks / 10_000_000) as i64,
        ((unix_ticks % 10_000_000) * 100) as i32,
    )
    .unwrap();
    // Wire conversion rounds down to the nearest 100ns.
    assert!(actual >= before - jiff::SignedDuration::from_nanos(99));
    assert!(actual <= after);
    assert_eq!(message.vm_reference_time, 0x12345678);
    stop_with_timeout(&mut task, &driver).await;
}
