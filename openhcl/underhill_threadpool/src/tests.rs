// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::local::block_on;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use pal_async::wait::PolledWait;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;
use test_with_tracing::test;

fn allowed_online_cpus() -> io::Result<Vec<u32>> {
    let mut affinity = CpuSet::new();
    pal::unix::affinity::get_current_thread_affinity(&mut affinity)?;
    let mut cpus = Vec::new();
    for cpu in 0..=pal::unix::affinity::max_present_cpu()? {
        if affinity.is_set(cpu) && is_cpu_online(cpu)? {
            cpus.push(cpu);
            if cpus.len() == 2 {
                break;
            }
        }
    }
    if cpus.is_empty() {
        return Err(io::Error::other("no allowed online CPU for the test"));
    }
    Ok(cpus)
}

// Test: Start a targeted worker and register notifications before and after startup.
// Expected: Work runs on the requested CPU with its initiating metadata; startup
//       notifies with true, and a late callback is returned uncalled to its owner.
#[test]
fn targeted_worker_preserves_context_and_notification_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let mut caller_affinity = CpuSet::new();
    pal::unix::affinity::get_current_thread_affinity(&mut caller_affinity)?;
    let cpu = pal::unix::affinity::get_cpu_number();
    let pool = AffinitizedThreadpool::new(16)?;
    let driver = pool.driver(cpu);
    let (notify, notified) = mpsc::channel();
    assert!(
        driver
            .set_spawn_notifier(move |cancel| {
                notify
                    .send(cancel)
                    .expect("test notification receiver lives");
            })
            .is_ok()
    );

    let (send, received) = mpsc::channel();
    let task = driver.spawn("targeted-worker-test", async move {
        let thread = Thread::current().expect("worker has its thread context");
        send.send((
            pal::unix::affinity::get_cpu_number(),
            thread.with_driver(|driver| driver.target_cpu()),
            thread.first_task().expect("initiating task metadata").name,
        ))
        .expect("test result receiver lives");
    });
    let result = received.recv_timeout(Duration::from_secs(5))?;
    block_on(task);

    assert_eq!(result.0, cpu);
    assert_eq!(result.1, cpu);
    assert_eq!(result.2.as_ref(), "targeted-worker-test");
    assert!(notified.recv_timeout(Duration::from_secs(5))?);

    let (notify, notified) = mpsc::channel();
    let returned = driver
        .set_spawn_notifier(move |cancel| {
            notify
                .send(cancel)
                .expect("test notification receiver lives");
        })
        .expect_err("worker already started");
    assert!(matches!(
        notified.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    returned(false);
    assert!(!notified.recv_timeout(Duration::from_secs(5))?);

    let mut after = CpuSet::new();
    pal::unix::affinity::get_current_thread_affinity(&mut after)?;
    assert_eq!(after, caller_affinity);
    assert!(Thread::current().is_none());
    Ok(())
}

// Test: Retarget a shared driver clone before submitting work through the original.
// Expected: Subsequent tasks run on the selected available CPU, not the original
//       target; routing is checked on up to two allowed, online CPUs.
#[test]
fn shared_retargeting_routes_subsequent_work() -> Result<(), Box<dyn std::error::Error>> {
    let cpus = allowed_online_cpus()?;
    let initial_cpu = cpus[0];
    let pool = AffinitizedThreadpool::new(16)?;
    let original = RetargetableDriver::new(pool.clone(), initial_cpu);
    let shared = original.clone();

    for &cpu in cpus.iter().rev() {
        shared.retarget(cpu);
        let (send, received) = mpsc::channel();
        let task = original.spawn("retarget-test", async move {
            let thread = Thread::current().expect("worker has its thread context");
            send.send((
                pal::unix::affinity::get_cpu_number(),
                thread.with_driver(|driver| driver.target_cpu()),
            ))
            .expect("test result receiver lives");
        });
        let result = received.recv_timeout(Duration::from_secs(5))?;
        block_on(task);
        assert_eq!(result, (cpu, cpu));
    }
    let mut active = pool
        .active_drivers()
        .map(|driver| driver.target_cpu())
        .collect::<Vec<_>>();
    active.sort_unstable();
    assert_eq!(active, cpus);
    Ok(())
}

// Test: Retarget a task after its wait is submitted, then signal the original FD.
// Expected: The accepted wait still consumes that signal, resumes on the new
//       target, and its worker timer does not complete before its deadline.
#[test]
fn retargeting_preserves_in_flight_wait_and_timer() -> Result<(), Box<dyn std::error::Error>> {
    let cpus = allowed_online_cpus()?;
    let pool = AffinitizedThreadpool::new(16)?;
    let original = RetargetableDriver::new(pool, cpus[0]);
    let moved_target = *cpus.last().expect("at least one allowed CPU");
    let (stream, mut peer) = UnixStream::pair()?;
    stream.set_nonblocking(true)?;
    let mut wait = PolledWait::new_with_size(&original, stream, 1)?;
    let (started, admitted) = mpsc::channel();
    let (send, received) = mpsc::channel();

    let task = original.spawn("retarget-wait-test", async move {
        poll_fn(|cx| {
            assert!(wait.poll_wait(cx).is_pending(), "wait has no signal yet");
            Poll::Ready(())
        })
        .await;
        started.send(()).expect("test admission receiver lives");
        wait.wait().await.expect("submitted wait completes");
        let mut stream = wait.into_inner();
        assert!(matches!(
            stream.read(&mut [0]),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock
        ));

        let driver = Thread::current()
            .expect("worker has its thread context")
            .with_driver(Clone::clone);
        driver.wait_for_affinity().await;
        let mut timer = PolledTimer::new(&driver);
        let deadline = Instant::now() + Duration::from_millis(1);
        let fired = timer.sleep_until(deadline).await;
        assert!(fired >= deadline);
        send.send(pal::unix::affinity::get_cpu_number())
            .expect("test result receiver lives");
    });

    admitted.recv_timeout(Duration::from_secs(5))?;
    original.retarget(moved_target);
    peer.write_all(b"X")?;
    let cpu = received.recv_timeout(Duration::from_secs(5))?;
    block_on(task);
    assert_eq!(cpu, moved_target);
    Ok(())
}
