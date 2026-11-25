// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::DefaultPool;
use crate::task::*;
use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Waker;
use test_with_tracing::test;

struct LocalSpawner(Arc<Scheduler>);

impl SpawnLocal for LocalSpawner {
    fn scheduler_local(&self, _metadata: &TaskMetadata) -> Arc<dyn Schedule> {
        self.0.clone()
    }
}

fn task_named(name: &str) -> Option<TaskData> {
    TaskList::global()
        .tasks()
        .into_iter()
        .find(|task| task.name() == name)
}

// Test: Drive a non-Send task from ready through waiting and completion.
// Expected: Local ownership is preserved and public task reports track its lifetime.
#[test]
fn local_tasks_preserve_non_send_ownership_and_report_lifecycle() {
    let (mut queue, scheduler) = task_queue("local-lifecycle");
    let spawner = Box::new(LocalSpawner(Arc::new(scheduler)));
    let value = Rc::new(Cell::new(0));
    let shared = value.clone();
    let event = async_channel::bounded::<()>(1);
    let receiver = event.1;
    let task = spawner.spawn_local("pal-async-local-lifecycle", async move {
        with_current_task_metadata(|metadata| {
            let metadata = metadata.unwrap();
            assert_eq!(metadata.name().as_ref(), "pal-async-local-lifecycle");
            assert!(metadata.location().file().ends_with("scheduling.rs"));
        });
        assert_eq!(
            task_named("pal-async-local-lifecycle")
                .unwrap()
                .state()
                .to_string(),
            "running"
        );
        receiver.recv().await.unwrap();
        shared.set(41);
        shared
    });
    let initial = task_named("pal-async-local-lifecycle").unwrap();
    let id = initial.id();
    assert_eq!(initial.executor(), Some("local-lifecycle"));
    assert!(initial.location().file().ends_with("scheduling.rs"));
    assert_eq!(initial.state().to_string(), "ready");
    assert!(queue.run().now_or_never().is_none());
    assert_eq!(
        task_named("pal-async-local-lifecycle")
            .unwrap()
            .state()
            .to_string(),
        "waiting"
    );
    event.0.try_send(()).unwrap();
    assert_eq!(
        task_named("pal-async-local-lifecycle")
            .unwrap()
            .state()
            .to_string(),
        "ready"
    );
    assert!(queue.run().now_or_never().is_none());
    let complete = task_named("pal-async-local-lifecycle").unwrap();
    assert_eq!(complete.id(), id);
    assert_eq!(complete.state().to_string(), "complete");
    assert!(Rc::ptr_eq(&crate::local::block_on(task), &value));
    assert_eq!(value.get(), 41);
    assert!(task_named("pal-async-local-lifecycle").is_none());
    assert!(with_current_task_metadata(|metadata| metadata.is_none()));
}

struct DropFlag(Rc<Cell<bool>>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

// Test: Cancel a waiting local task while retaining a clone of its wake handle.
// Expected: Cancellation drops the future and reports cancellation until the
//       last wake handle drops.
#[test]
fn cancelling_local_tasks_drops_the_future_even_with_retained_wakers() {
    let (mut queue, scheduler) = task_queue("local-cancel");
    let spawner = Arc::new(LocalSpawner(Arc::new(scheduler)));
    let dropped = Rc::new(Cell::new(false));
    let flag = DropFlag(dropped.clone());
    let waker = Rc::new(RefCell::new(None::<Waker>));
    let recorded = waker.clone();
    let task = spawner.spawn_local("pal-async-local-cancel", async move {
        let _flag = flag;
        std::future::poll_fn(|cx| {
            *recorded.borrow_mut() = Some(cx.waker().clone());
            std::task::Poll::<()>::Pending
        })
        .await;
    });
    assert!(queue.run().now_or_never().is_none());
    drop(task);
    assert!(queue.run().now_or_never().is_none());
    assert!(dropped.get());
    assert_eq!(
        task_named("pal-async-local-cancel")
            .unwrap()
            .state()
            .to_string(),
        "cancelled"
    );
    drop(waker.borrow_mut().take());
    assert!(task_named("pal-async-local-cancel").is_none());
}

// Test: Finish a run_with pool while retaining only cloned weak driver references.
// Expected: Tasks complete normally, but weak references cannot keep the pool alive.
#[test]
fn weak_drivers_do_not_prevent_run_with_pool_shutdown() {
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let weak = DefaultPool::run_with(async |driver| {
            let weak = driver.downgrade();
            let cloned = weak.clone();
            assert!(cloned.upgrade().is_some());
            assert_eq!(driver.spawn("weak-driver-result", async { 73 }).await, 73);
            cloned
        });
        send.send(weak).unwrap();
    });
    let weak = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    thread.join().unwrap();
    assert!(weak.upgrade().is_none());
}
