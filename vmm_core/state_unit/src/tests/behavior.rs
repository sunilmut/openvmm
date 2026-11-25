// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::SavedState;
use super::TestUnit;
use crate::SavedStateUnit;
use crate::StateRequest;
use crate::StateUnit;
use crate::StateUnits;
use crate::run_async_unit;
use crate::run_unit;
use futures::StreamExt;
use mesh::payload::Protobuf;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::task::Spawn;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use test_with_tracing::test;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SavedStateBlob;
use vmcore::save_restore::SavedStateRoot;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Operation {
    Start,
    Stop,
    Reset,
    Save,
    Restore,
}

#[derive(inspect::Inspect)]
struct RecordingUnit {
    #[inspect(skip)]
    name: &'static str,
    #[inspect(skip)]
    calls: Arc<Mutex<Vec<(&'static str, Operation)>>>,
    #[inspect(skip)]
    value: AtomicU32,
}

impl RecordingUnit {
    fn new(name: &'static str, calls: &Arc<Mutex<Vec<(&'static str, Operation)>>>) -> Self {
        Self {
            name,
            calls: calls.clone(),
            value: AtomicU32::new(0),
        }
    }

    fn record(&self, operation: Operation) {
        self.calls.lock().push((self.name, operation));
    }
}

#[derive(Protobuf, SavedStateRoot)]
#[mesh(package = "state_unit.behavior_test")]
struct Value(u32);

impl StateUnit for &RecordingUnit {
    async fn start(&mut self) {
        self.record(Operation::Start);
    }

    async fn stop(&mut self) {
        self.record(Operation::Stop);
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        self.record(Operation::Reset);
        self.value.store(0, Ordering::Relaxed);
        Ok(())
    }

    async fn save(&mut self) -> Result<Option<SavedStateBlob>, SaveError> {
        self.record(Operation::Save);
        Ok(Some(SavedStateBlob::new(Value(
            self.value.load(Ordering::Relaxed),
        ))))
    }

    async fn restore(&mut self, state: SavedStateBlob) -> Result<(), RestoreError> {
        self.record(Operation::Restore);
        self.value
            .store(state.parse::<Value>()?.0, Ordering::Relaxed);
        Ok(())
    }
}

// Test: Add a dependent while running, then start only newly stopped units.
// Expected: Existing units are not restarted, and a stopped VM stays stopped.
#[async_test]
async fn hot_add_starts_only_new_units(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let unit = RecordingUnit::new("base", &calls);
    let base = units
        .add("base")
        .spawn(&driver, |recv| run_async_unit(unit, recv))
        .unwrap();

    units.start_stopped_units().await;
    assert!(!units.is_running());
    assert!(calls.lock().is_empty());
    units.start().await;
    assert!(units.is_running());
    let unit = RecordingUnit::new("added", &calls);
    let added = units
        .add("added")
        .depends_on(base.handle())
        .spawn(&driver, |recv| run_async_unit(unit, recv))
        .unwrap();

    units.start_stopped_units().await;
    units.start().await;
    assert_eq!(
        *calls.lock(),
        [("base", Operation::Start), ("added", Operation::Start)]
    );
    units.stop().await;
    units.start_stopped_units().await;
    assert!(!units.is_running());
    assert_eq!(
        *calls.lock(),
        [
            ("base", Operation::Start),
            ("added", Operation::Start),
            ("added", Operation::Stop),
            ("base", Operation::Stop),
        ]
    );

    added.remove().await;
    base.remove().await;
}

// Test: Reset, restore and save a unit served by the shared-reference runner.
// Expected: Each operation is routed once, and saved values reflect restore/reset.
#[async_test]
async fn async_runner_routes_saved_state(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let unit = RecordingUnit::new("device", &calls);
    let worker = units
        .add("device")
        .spawn(&driver, |recv| run_async_unit(unit, recv))
        .unwrap();
    units
        .restore(vec![SavedStateUnit {
            name: "device".into(),
            state: SavedStateBlob::new(Value(41)),
        }])
        .await
        .unwrap();
    let saved = units.save().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "device");
    assert_eq!(saved[0].state.parse::<Value>().unwrap().0, 41);
    units.reset().await.unwrap();
    let saved = units.save().await.unwrap();
    assert_eq!(saved[0].state.parse::<Value>().unwrap().0, 0);
    assert_eq!(
        *calls.lock(),
        [
            ("device", Operation::Restore),
            ("device", Operation::Save),
            ("device", Operation::Reset),
            ("device", Operation::Save),
        ]
    );
    worker.remove().await;
}

// Test: Restore a list containing both duplicate and unknown unit names.
// Expected: Both errors identify their units, no state changes, and retry is allowed.
#[async_test]
async fn invalid_restore_names_do_not_dispatch_or_consume_eligibility(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let _worker = units
        .add("device")
        .spawn(&driver, |recv| {
            run_unit(
                TestUnit {
                    value: Arc::new(true.into()),
                    support_saved_state: true,
                    ..Default::default()
                },
                recv,
            )
        })
        .unwrap();
    let state = |name: &str| SavedStateUnit {
        name: name.into(),
        state: SavedStateBlob::new(SavedState(false)),
    };
    let err = units
        .restore(vec![state("device"), state("device"), state("missing")])
        .await
        .unwrap_err();
    let message = format!("{:#}", anyhow::Error::new(err));
    for expected in [
        "restore failed",
        "device",
        "duplicate unit name",
        "missing",
        "unknown unit name",
    ] {
        assert!(message.contains(expected), "{message}");
    }
    let saved = units.save().await.unwrap();
    assert!(saved[0].state.parse::<SavedState>().unwrap().0);
    units.restore(vec![state("device")]).await.unwrap();
    let saved = units.save().await.unwrap();
    assert!(!saved[0].state.parse::<SavedState>().unwrap().0);
}

// Test: Register the same name twice, remove the original, then reuse its name.
// Expected: The duplicate is rejected without replacing the original saved state.
#[async_test]
async fn duplicate_registration_preserves_original_and_allows_later_reuse(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let original = units
        .add("device")
        .spawn(&driver, |recv| {
            run_unit(
                TestUnit {
                    value: Arc::new(true.into()),
                    support_saved_state: true,
                    ..Default::default()
                },
                recv,
            )
        })
        .unwrap();
    let err = units.add("device").build(mesh::channel().0).unwrap_err();
    assert_eq!(err.to_string(), "state unit name device is in use");
    let saved = units.save().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "device");
    assert!(saved[0].state.parse::<SavedState>().unwrap().0);

    original.remove().await;
    let replacement = units
        .add("device")
        .spawn(&driver, |recv| {
            run_unit(
                TestUnit {
                    support_saved_state: true,
                    ..Default::default()
                },
                recv,
            )
        })
        .unwrap();
    let saved = units.save().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "device");
    assert!(!saved[0].state.parse::<SavedState>().unwrap().0);
    replacement.remove().await;
}

// Test: Detach a registration handle, then transition and save the unit.
// Expected: Detaching keeps the unit registered until the whole set is dropped.
#[async_test]
async fn detached_unit_still_receives_transitions(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let (send, recv) = mesh::channel();
    let handle = units.add("detached").build(send).unwrap();
    let task = driver.spawn("detached-state-unit", async move {
        run_unit(
            TestUnit {
                support_saved_state: true,
                ..Default::default()
            },
            recv,
        )
        .await
    });
    handle.detach();
    units.start().await;
    units.stop().await;
    let saved = units.save().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "detached");
    assert!(!saved[0].state.parse::<SavedState>().unwrap().0);
    assert!(units.add("detached").build(mesh::channel().0).is_err());
    drop(units);
    task.await;
}

// Test: Remove a dependency after it receives Start but before it replies.
// Expected: The canceled reply does not fail the transition or strand its dependent.
#[async_test]
async fn removal_during_transition_does_not_strand_dependents(driver: DefaultDriver) {
    let mut units = StateUnits::new();
    let (send, mut recv) = mesh::channel();
    let removed = units.add("removed").build(send).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let unit = RecordingUnit::new("survivor", &calls);
    let survivor = units
        .add("survivor")
        .depends_on(&removed)
        .spawn(&driver, |recv| run_async_unit(unit, recv))
        .unwrap();
    futures::join!(units.start(), async move {
        let Some(StateRequest::Start(rpc)) = recv.next().await else {
            panic!("expected start request");
        };
        removed.remove();
        drop(rpc);
    });
    assert!(units.is_running());
    assert_eq!(*calls.lock(), [("survivor", Operation::Start)]);
    units.stop().await;
    let saved = units.save().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "survivor");
    assert_eq!(saved[0].state.parse::<Value>().unwrap().0, 0);
    survivor.remove().await;
}
