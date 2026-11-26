// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Register;
use super::WatchdogServiceError;
use super::WatchdogServices;
use super::platform::BaseWatchdogPlatform;
use super::platform::WatchdogPlatform;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::non_volatile_store::NonVolatileStore;
use vmcore::non_volatile_store::NonVolatileStoreError;
use vmcore::save_restore::SaveRestore;
use vmcore::vmtime::SavedState as VmTimeSavedState;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;
use watchdog_vmgs_format::WatchdogVmgsFormatStoreError;

struct Store {
    data: Arc<Mutex<Option<Vec<u8>>>>,
    fail_restore: bool,
    fail_persist: bool,
}

#[async_trait::async_trait]
impl NonVolatileStore for Store {
    async fn restore(&mut self) -> Result<Option<Vec<u8>>, NonVolatileStoreError> {
        if self.fail_restore {
            return Err(NonVolatileStoreError::new(std::io::Error::other(
                "restore unavailable",
            )));
        }
        Ok(self.data.lock().clone())
    }

    async fn persist(&mut self, data: Vec<u8>) -> Result<(), NonVolatileStoreError> {
        if self.fail_persist {
            return Err(NonVolatileStoreError::new(std::io::Error::other(
                "persist unavailable",
            )));
        }
        *self.data.lock() = Some(data);
        Ok(())
    }
}

// Test: Cold boot consumes persisted failure once; restoration leaves it intact.
//       Guest status acknowledgement and rejected register writes are independent.
// Expected: Cold boot reports failure until W1C, restoration performs no clearing,
//       and invalid config or read-only writes preserve accepted register state.
#[test]
fn boot_status_and_register_rejection() {
    pal_async::DefaultPool::run_with(async |driver| {
        for restoring in [false, true] {
            let data = Arc::new(Mutex::new(Some(vec![1])));
            let platform = BaseWatchdogPlatform::new(Box::new(Store {
                data: data.clone(),
                fail_restore: false,
                fail_persist: false,
            }))
            .await
            .unwrap();
            let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
            let vmtime = keeper.builder().build(&driver).await.unwrap();
            let mut watchdog = WatchdogServices::new(
                "protocol",
                vmtime.access("protocol"),
                Box::new(platform),
                restoring,
            )
            .await;
            assert_eq!(
                watchdog.read(Register::Config).unwrap(),
                if restoring { 0 } else { 0x100 }
            );
            assert_eq!(*data.lock(), Some(vec![u8::from(restoring)]));
            watchdog.write(Register::Count, 9).unwrap();
            watchdog.write(Register::Config, 0x11).unwrap();
            let accepted = watchdog.read(Register::Config).unwrap();
            for bit in (2..32).filter(|bit| ![4, 8].contains(bit)) {
                let rejected = accepted | (1 << bit);
                assert!(matches!(
                    watchdog.write(Register::Config, rejected),
                    Err(WatchdogServiceError::InvalidConfigBits(value)) if value == rejected
                ));
                assert_eq!(watchdog.read(Register::Config).unwrap(), accepted);
                assert_eq!(watchdog.read(Register::Count).unwrap(), 9);
            }
            assert!(matches!(
                watchdog.write(Register::Resolution, u32::MAX),
                Err(WatchdogServiceError::WriteResolution)
            ));
            assert_eq!(watchdog.read(Register::Resolution).unwrap(), 1);
            watchdog.write(Register::Config, 0x111).unwrap();
            assert_eq!(watchdog.read(Register::Config).unwrap(), 0x11);
            assert_eq!(watchdog.read(Register::Count).unwrap(), 9);
        }
    });
}

// Test: A platform has multiple callbacks and a working nonvolatile store.
// Expected: Every callback runs in registration order, then a fresh platform
//       observes the durable failure and clears it exactly once.
#[test]
fn all_callbacks_and_durable_boot_status() {
    pal_async::DefaultPool::run_with(async |_driver| {
        let data = Arc::new(Mutex::new(None));
        let mut platform = BaseWatchdogPlatform::new(Box::new(Store {
            data: data.clone(),
            fail_restore: false,
            fail_persist: false,
        }))
        .await
        .unwrap();
        let callbacks = Arc::new(Mutex::new(Vec::new()));
        for name in ["first", "second"] {
            let callbacks = callbacks.clone();
            platform.add_callback(Box::new(move || callbacks.lock().push(name)));
        }
        platform.on_timeout().await;
        assert_eq!(*callbacks.lock(), ["first", "second"]);
        assert_eq!(*data.lock(), Some(vec![1]));
        let mut rebooted = BaseWatchdogPlatform::new(Box::new(Store {
            data: data.clone(),
            fail_restore: false,
            fail_persist: false,
        }))
        .await
        .unwrap();
        assert!(rebooted.read_and_clear_boot_status().await);
        assert!(!rebooted.read_and_clear_boot_status().await);
        assert_eq!(*data.lock(), Some(vec![0]));
    });
}

// Test: Restore fails, stored data is malformed, or clearing failure cannot persist.
// Expected: Construction returns typed storage/format errors, while the documented
//       boot-status read-error fallback reports no failure without overwriting data.
#[test]
fn platform_storage_errors_are_reported_or_degraded() {
    pal_async::DefaultPool::run_with(async |_driver| {
        assert!(matches!(
            BaseWatchdogPlatform::new(Box::new(Store {
                data: Arc::new(Mutex::new(None)),
                fail_restore: true,
                fail_persist: false,
            }))
            .await,
            Err(WatchdogVmgsFormatStoreError::NonVolatileStoreAccessError(_))
        ));
        assert!(matches!(
            BaseWatchdogPlatform::new(Box::new(Store {
                data: Arc::new(Mutex::new(Some(vec![2]))),
                fail_restore: false,
                fail_persist: false,
            }))
            .await,
            Err(WatchdogVmgsFormatStoreError::InvalidFormat(_))
        ));
        let data = Arc::new(Mutex::new(Some(vec![1])));
        let mut platform = BaseWatchdogPlatform::new(Box::new(Store {
            data: data.clone(),
            fail_restore: false,
            fail_persist: true,
        }))
        .await
        .unwrap();
        assert!(!platform.read_and_clear_boot_status().await);
        assert_eq!(*data.lock(), Some(vec![1]));
    });
}

// Test: A saved disabled configuration replaces subsequently modified registers.
//       Enabling the restored watchdog uses its saved count when past the deadline.
// Expected: Guest-visible state round-trips and no timeout occurs one second early;
//       expiration invokes the platform once and disables the restored watchdog.
#[test]
fn saved_registers_restore_the_guest_deadline() {
    pal_async::DefaultPool::run_with(async |driver| {
        let mut keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
        let vmtime = keeper.builder().build(&driver).await.unwrap();
        let mut platform = BaseWatchdogPlatform::new(
            vmcore::non_volatile_store::EphemeralNonVolatileStore::new_boxed(),
        )
        .await
        .unwrap();
        let expired = Arc::new(Mutex::new(Vec::new()));
        let callback = expired.clone();
        platform.add_callback(Box::new(move || callback.lock().push("expired")));
        let mut watchdog =
            WatchdogServices::new("saved", vmtime.access("saved"), Box::new(platform), true).await;
        watchdog.write(Register::Count, 9).unwrap();
        watchdog.write(Register::Config, 0x11).unwrap();
        let saved = watchdog.save().unwrap();
        watchdog.write(Register::Count, 2).unwrap();
        watchdog.write(Register::Config, 0).unwrap();
        watchdog.restore(saved).unwrap();
        assert_eq!(watchdog.read(Register::Config).unwrap(), 0x11);
        assert_eq!(watchdog.read(Register::Count).unwrap(), 9);
        assert_eq!(watchdog.read(Register::Resolution).unwrap(), 1);
        watchdog.write(Register::Config, 0x13).unwrap();
        for ticks in [80_000_000, 90_000_001, 100_000_000] {
            keeper
                .restore(VmTimeSavedState::from_vmtime(VmTime::from_100ns(ticks)))
                .await;
            watchdog.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
            if ticks == 80_000_000 {
                assert!(expired.lock().is_empty());
                assert_eq!(watchdog.read(Register::Config).unwrap(), 0x13);
            } else {
                assert_eq!(*expired.lock(), ["expired"]);
                assert_eq!(watchdog.read(Register::Config).unwrap(), 0x10);
            }
        }
    });
}
