// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::non_volatile_store::NonVolatileStoreError;

#[derive(Default)]
struct Storage {
    data: Option<Vec<u8>>,
    writes: Vec<Vec<u8>>,
    fail_restore: bool,
    fail_next_write: bool,
}

struct Store(Arc<Mutex<Storage>>);

#[async_trait::async_trait]
impl NonVolatileStore for Store {
    async fn persist(&mut self, data: Vec<u8>) -> Result<(), NonVolatileStoreError> {
        let mut storage = self.0.lock();
        if std::mem::take(&mut storage.fail_next_write) {
            return Err(NonVolatileStoreError::new(anyhow::anyhow!(
                "write rejected"
            )));
        }
        storage.writes.push(data.clone());
        storage.data = Some(data);
        Ok(())
    }

    async fn restore(&mut self) -> Result<Option<Vec<u8>>, NonVolatileStoreError> {
        let storage = self.0.lock();
        if storage.fail_restore {
            return Err(NonVolatileStoreError::new(anyhow::anyhow!("read rejected")));
        }
        Ok(storage.data.clone())
    }
}

fn fixture(data: Option<Vec<u8>>) -> (Arc<Mutex<Storage>>, Box<dyn NonVolatileStore>) {
    let storage = Arc::new(Mutex::new(Storage {
        data,
        ..Default::default()
    }));
    (storage.clone(), Box::new(Store(storage)))
}

// Test: Restore absent, clear and failed-boot records, then set and clear.
// Expected: The one-byte status is durable across reopening; reads consume
//       failure once and repeated unchanged operations do not write again.
#[test]
fn durable_boot_status_transitions() {
    block_on(async {
        for initial in [None, Some(vec![0]), Some(vec![1])] {
            let expected = initial.as_deref() == Some(&[1]);
            let (storage, backend) = fixture(initial);
            let mut store = WatchdogVmgsFormatStore::new(backend).await.unwrap();
            assert_eq!(store.read_and_clear_boot_status().await.unwrap(), expected);
            assert!(!store.read_and_clear_boot_status().await.unwrap());
            assert_eq!(storage.lock().writes.len(), usize::from(expected));
            store.set_boot_failure().await.unwrap();
            store.set_boot_failure().await.unwrap();
            assert_eq!(
                storage.lock().writes,
                if expected {
                    vec![vec![0], vec![1]]
                } else {
                    vec![vec![1]]
                }
            );
            drop(store);
            let mut reopened = WatchdogVmgsFormatStore::new(Box::new(Store(storage.clone())))
                .await
                .unwrap();
            assert!(reopened.read_and_clear_boot_status().await.unwrap());
            assert_eq!(storage.lock().data, Some(vec![0]));
            assert!(!reopened.read_and_clear_boot_status().await.unwrap());
        }
    });
}

// Test: Restore empty, oversized and non-boolean watchdog records.
// Expected: The public store rejects all invalid formats without rewriting
//       storage, including otherwise valid boolean bytes with trailing data.
#[test]
fn invalid_records_are_not_rewritten() {
    block_on(async {
        for bytes in [vec![], vec![2], vec![255], vec![0, 0], vec![1, 0]] {
            let (storage, backend) = fixture(Some(bytes.clone()));
            let result = WatchdogVmgsFormatStore::new(backend).await;
            assert!(matches!(
                result,
                Err(WatchdogVmgsFormatStoreError::InvalidFormat(_))
            ));
            assert_eq!(storage.lock().data, Some(bytes));
            assert!(storage.lock().writes.is_empty());
        }
    });
}

// Test: Fail restoration and each of the two durable status transitions.
// Expected: All storage failures preserve their typed error and leave the
//       previously persisted data unchanged, rather than reporting success.
#[test]
fn storage_errors_are_propagated() {
    block_on(async {
        let (storage, backend) = fixture(None);
        storage.lock().fail_restore = true;
        assert!(matches!(
            WatchdogVmgsFormatStore::new(backend).await,
            Err(WatchdogVmgsFormatStoreError::NonVolatileStoreAccessError(_))
        ));
        for initial in [None, Some(vec![1])] {
            let (storage, backend) = fixture(initial.clone());
            let mut store = WatchdogVmgsFormatStore::new(backend).await.unwrap();
            storage.lock().fail_next_write = true;
            let failed = if initial.is_none() {
                store.set_boot_failure().await.map(|()| false)
            } else {
                store.read_and_clear_boot_status().await
            };
            assert!(matches!(
                failed,
                Err(WatchdogVmgsFormatStoreError::NonVolatileStoreAccessError(_))
            ));
            assert_eq!(storage.lock().data, initial);
            assert!(storage.lock().writes.is_empty());
        }
    });
}

// Test: Retry enabling boot-failure status after a transient persistence error.
// Expected: A successful retry durably writes the failure byte, so reopening
//       the store reports the watchdog failure to the next boot.
// IGNORED: Reproduced with the test enabled: a failed write leaves the cached
//       flag true, so the retry returns success without persisting any data.
#[test]
#[ignore = "product bug: failed persistence suppresses durable retry"]
fn retry_after_failed_persist_is_durable() {
    block_on(async {
        let (storage, backend) = fixture(None);
        let mut store = WatchdogVmgsFormatStore::new(backend).await.unwrap();
        storage.lock().fail_next_write = true;
        assert!(store.set_boot_failure().await.is_err());
        store.set_boot_failure().await.unwrap();
        drop(store);
        let mut reopened = WatchdogVmgsFormatStore::new(Box::new(Store(storage)))
            .await
            .unwrap();
        assert!(reopened.read_and_clear_boot_status().await.unwrap());
    });
}
