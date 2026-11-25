// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use test_with_tracing::test;

#[derive(Default)]
struct Recorded {
    builds: Vec<(String, Option<u32>, bool)>,
    current: usize,
    retargets: Vec<u32>,
    waits: usize,
}

struct RecordingBackend {
    driver: DefaultDriver,
    recorded: Arc<Mutex<Recorded>>,
    ready: Arc<AtomicBool>,
}

struct RecordingDriver {
    driver: DefaultDriver,
    recorded: Arc<Mutex<Recorded>>,
    ready: Arc<AtomicBool>,
}

impl Inspect for RecordingDriver {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.ignore();
    }
}

impl BuildVmTaskDriver for RecordingBackend {
    type Driver = RecordingDriver;
    type CurrentDriver = RecordingDriver;

    fn build(&self, name: String, target_vp: Option<u32>, run_on_target: bool) -> Self::Driver {
        self.recorded
            .lock()
            .builds
            .push((name, target_vp, run_on_target));
        RecordingDriver {
            driver: self.driver.clone(),
            recorded: self.recorded.clone(),
            ready: self.ready.clone(),
        }
    }

    fn build_current(&self) -> Self::CurrentDriver {
        self.recorded.lock().current += 1;
        RecordingDriver {
            driver: self.driver.clone(),
            recorded: self.recorded.clone(),
            ready: self.ready.clone(),
        }
    }
}

impl TargetedDriver for RecordingDriver {
    fn spawner(&self) -> &dyn Spawn {
        &self.driver
    }
    fn driver(&self) -> &dyn Driver {
        &self.driver
    }
    fn retarget_vp(&self, target_vp: u32) {
        self.recorded.lock().retargets.push(target_vp);
    }
    fn is_target_vp_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
    async fn wait_target_vp_ready(&self) {
        self.recorded.lock().waits += 1;
        self.ready.store(true, Ordering::SeqCst);
    }
}

// Test: Build default, custom-targeted, and current drivers, then retarget/wait through cloned public handles.
// Expected: Names and scheduling hints reach the backend unchanged, current dispatch uses its own constructor, and readiness/retarget operations reach the shared driver.
#[test]
fn builder_policy_and_cloned_driver_controls_reach_the_recording_backend() {
    let mut pool = DefaultPool::new();
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let source = VmTaskDriverSource::new(RecordingBackend {
        driver: pool.driver(),
        recorded: recorded.clone(),
        ready: Arc::new(AtomicBool::new(false)),
    });
    let simple = source.simple();
    let driver = source
        .builder()
        .target_vp(7)
        .run_on_target(true)
        .build("device-queue");
    let current = source.current();
    let cloned = driver.clone();
    assert!(!driver.is_target_vp_ready());
    cloned.retarget_vp(11);
    pool.run_until(cloned.wait_target_vp_ready());
    assert!(driver.is_target_vp_ready());
    assert_eq!(
        recorded.lock().builds,
        [
            ("".to_owned(), None, false),
            ("device-queue".to_owned(), Some(7), true)
        ]
    );
    assert_eq!(recorded.lock().current, 1);
    assert_eq!(recorded.lock().retargets, [11]);
    assert_eq!(recorded.lock().waits, 1);
    assert_eq!(
        pool.run_until(simple.spawn("simple-value", async { 41 })),
        41
    );
    assert_eq!(
        pool.run_until(current.spawn("current-value", async { 43 })),
        43
    );
    #[cfg(unix)]
    pool.run_until(exercise_io(driver));
}

// Test: Use a single-driver backend despite target/run-on-target hints, including its current-driver path.
// Expected: Tasks execute on the caller's pool, default readiness completes immediately, and retargeting does not move execution to another thread.
#[test]
fn single_driver_backend_keeps_tasks_on_the_supplied_executor() {
    let mut pool = DefaultPool::new();
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(pool.driver()));
    let driver = source
        .builder()
        .target_vp(9)
        .run_on_target(true)
        .build("ignored-name");
    driver.retarget_vp(12);
    assert!(driver.is_target_vp_ready());
    pool.run_until(driver.wait_target_vp_ready());
    let expected = std::thread::current().id();
    assert_eq!(
        pool.run_until(driver.spawn("thread-id", async { std::thread::current().id() })),
        expected
    );
    assert_eq!(
        pool.run_until(
            source
                .current()
                .spawn("current-thread-id", async { std::thread::current().id() })
        ),
        expected
    );
}

// Test: Spawn through current() first outside a dedicated pool and then from a task running on a targeted pool.
// Expected: Outside work falls back to the supplied executor, while nested work runs on the active dedicated pool rather than the fallback.
#[test]
fn current_driver_uses_active_dedicated_pool_and_default_fallback() {
    let mut pool = DefaultPool::new();
    let source = VmTaskDriverSource::new(thread::ThreadDriverBackend::new(pool.driver()));
    let current = source.current();
    let expected = std::thread::current().id();
    assert_eq!(
        pool.run_until(current.spawn("fallback-thread", async { std::thread::current().id() })),
        expected
    );
    let fixed = source.simple();
    assert_eq!(
        pool.run_until(fixed.spawn("fixed-default", async { std::thread::current().id() })),
        expected
    );
    let dedicated = source
        .builder()
        .target_vp(3)
        .build("vmcore-dedicated-probe");
    dedicated.retarget_vp(4);
    let observed = futures::executor::block_on(dedicated.spawn("outer", async move {
        current
            .spawn("inner", async {
                std::thread::current().name().map(str::to_owned)
            })
            .await
    }));
    assert_eq!(observed.as_deref(), Some("vmcore-dedicated-probe"));
}

#[cfg(unix)]
async fn exercise_io(driver: VmTaskDriver) {
    use futures::{AsyncReadExt, FutureExt};
    use pal_async::interest::{InterestSlot, PollEvents};
    use pal_async::socket::PolledSocket;
    use pal_async::timer::PolledTimer;
    use pal_async::wait::PolledWait;
    use std::future::poll_fn;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    let mut timer = PolledTimer::new(&driver);
    let start = Instant::now();
    timer.sleep(Duration::from_millis(1)).await;
    assert!(start.elapsed() >= Duration::from_millis(1));
    let event = pal_event::Event::new();
    let mut wait = PolledWait::new(&driver, event.clone()).unwrap();
    assert!(wait.wait().now_or_never().is_none());
    event.signal();
    wait.wait().await.unwrap();
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let mut socket = PolledSocket::new(&driver, reader).unwrap();
    writer.write_all(b"socket-payload").unwrap();
    let mut socket_bytes = [0; 14];
    AsyncReadExt::read_exact(&mut socket, &mut socket_bytes)
        .await
        .unwrap();
    assert_eq!(&socket_bytes, b"socket-payload");
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let mut ready = driver.new_dyn_fd_ready(reader.as_raw_fd()).unwrap();
    assert!(
        poll_fn(|cx| ready.poll_fd_ready(cx, InterestSlot::Read, PollEvents::IN))
            .now_or_never()
            .is_none()
    );
    writer.write_all(b"fd-payload").unwrap();
    let events = poll_fn(|cx| ready.poll_fd_ready(cx, InterestSlot::Read, PollEvents::IN)).await;
    assert!(events.has_in());
    let mut fd_bytes = [0; 10];
    Read::read_exact(&mut reader, &mut fd_bytes).unwrap();
    assert_eq!(&fd_bytes, b"fd-payload");
    #[cfg(target_os = "linux")]
    assert!(!driver.io_uring_probe(u8::MAX));
}

// Test: Run timers, event waits, socket reads, and fd-readiness operations through each native task-driver dispatch path.
// Expected: Exact payloads and readiness reach the supplied executor, timers do not fire early, and current() also drives IO on the active dedicated thread.
#[cfg(unix)]
#[test]
fn io_forwarding_works_for_fixed_single_current_and_dedicated_dispatch() {
    let mut pool = DefaultPool::new();
    let single = VmTaskDriverSource::new(SingleDriverBackend::new(pool.driver()));
    let threaded = VmTaskDriverSource::new(thread::ThreadDriverBackend::new(pool.driver()));
    for driver in [
        single.simple(),
        single.current(),
        threaded.simple(),
        threaded.current(),
    ] {
        pool.run_until(exercise_io(driver));
    }
    let current = threaded.current();
    let dedicated = threaded.builder().target_vp(5).build("vmcore-io-probe");
    futures::executor::block_on(dedicated.spawn("current-io", exercise_io(current)));
}
