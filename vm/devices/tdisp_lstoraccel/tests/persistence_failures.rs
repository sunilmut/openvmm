// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential updates across acknowledged and ambiguous persistence failures.

#![cfg(target_os = "linux")]

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tdisp_lstoraccel::credential_store::CredentialStoreError;
use tdisp_lstoraccel::credential_store::LstoraccelCredentialStore;
use tdisp_lstoraccel::credential_store::NamespaceCredentialKey;
use test_with_tracing::test;
use vmcore::non_volatile_store::NonVolatileStore;
use vmcore::non_volatile_store::NonVolatileStoreError;

#[derive(Clone, Copy)]
enum FailurePoint {
    BeforeCommit,
    AfterCommit,
}

#[derive(Clone)]
struct FaultStore {
    bytes: Arc<Mutex<Option<Vec<u8>>>>,
    fail_next: Arc<AtomicBool>,
    point: FailurePoint,
}

impl FaultStore {
    fn new(point: FailurePoint) -> Self {
        Self {
            bytes: Arc::default(),
            fail_next: Arc::default(),
            point,
        }
    }

    fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    async fn open(&self) -> LstoraccelCredentialStore {
        LstoraccelCredentialStore::open(Box::new(self.clone()))
            .await
            .unwrap()
    }
}

#[async_trait::async_trait]
impl NonVolatileStore for FaultStore {
    async fn persist(&mut self, data: Vec<u8>) -> Result<(), NonVolatileStoreError> {
        let fail = self.fail_next.swap(false, Ordering::SeqCst);
        if !fail || matches!(self.point, FailurePoint::AfterCommit) {
            *self.bytes.lock() = Some(data);
        }
        if fail {
            return Err(NonVolatileStoreError::new(std::io::Error::other(
                "injected persistence failure",
            )));
        }
        Ok(())
    }

    async fn restore(&mut self) -> Result<Option<Vec<u8>>, NonVolatileStoreError> {
        Ok(self.bytes.lock().clone())
    }
}

// Test: Fail namespace creation before and after the backend commits bytes,
//       then discard the failed wrapper and reopen it as required by its API.
// Expected: Failed updates never publish in-memory credentials; reopening
//       reflects actual persistence and permits recovery without losing peers.
#[pal_async::async_test]
async fn failed_put_preserves_acknowledged_view_until_reopen() {
    for point in [FailurePoint::BeforeCommit, FailurePoint::AfterCommit] {
        let backend = FaultStore::new(point);
        let mut store = backend.open().await;
        let peer = NamespaceCredentialKey {
            vsn: [1; 20],
            nsid: 7,
        };
        let target = NamespaceCredentialKey {
            vsn: [2; 20],
            nsid: 7,
        };
        store.put(&peer, &[0x31; 32]).await.unwrap();
        backend.fail_next();
        assert!(matches!(
            store.put(&target, &[0x42; 32]).await,
            Err(CredentialStoreError::Storage(_))
        ));
        assert_eq!(store.get(&peer), Some(&[0x31; 32]));
        assert!(store.get(&target).is_none());
        drop(store);

        let mut store = backend.open().await;
        let expected = match point {
            FailurePoint::BeforeCommit => None,
            FailurePoint::AfterCommit => Some(&[0x42; 32]),
        };
        assert_eq!(store.get(&target), expected);
        assert_eq!(store.get(&peer), Some(&[0x31; 32]));
        store.remove(&target).await.unwrap();
        store.put(&target, &[0x53; 32]).await.unwrap();
        drop(store);
        let store = backend.open().await;
        assert_eq!(store.get(&target), Some(&[0x53; 32]));
        assert_eq!(store.get(&peer), Some(&[0x31; 32]));
    }
}

// Test: Fail namespace deletion before and after its persisted commit and
//       reopen without reusing the failed wrapper for another update.
// Expected: The failed wrapper retains its acknowledged credential view;
//       reopening resolves the ambiguous deletion without affecting a peer.
#[pal_async::async_test]
async fn failed_remove_is_resolved_by_reopening() {
    for point in [FailurePoint::BeforeCommit, FailurePoint::AfterCommit] {
        let backend = FaultStore::new(point);
        let mut store = backend.open().await;
        let peer = NamespaceCredentialKey {
            vsn: [3; 20],
            nsid: 8,
        };
        let target = NamespaceCredentialKey {
            vsn: [3; 20],
            nsid: 9,
        };
        store.put(&peer, &[0x64; 32]).await.unwrap();
        store.put(&target, &[0x75; 32]).await.unwrap();
        backend.fail_next();
        assert!(matches!(
            store.remove(&target).await,
            Err(CredentialStoreError::Storage(_))
        ));
        assert_eq!(store.get(&target), Some(&[0x75; 32]));
        assert_eq!(store.get(&peer), Some(&[0x64; 32]));
        drop(store);

        let store = backend.open().await;
        let expected = match point {
            FailurePoint::BeforeCommit => Some(&[0x75; 32]),
            FailurePoint::AfterCommit => None,
        };
        assert_eq!(store.get(&target), expected);
        assert_eq!(store.get(&peer), Some(&[0x64; 32]));
    }
}
