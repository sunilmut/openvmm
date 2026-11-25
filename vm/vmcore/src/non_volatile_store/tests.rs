// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use test_with_tracing::test;

// Test: Persist/restore through a boxed ephemeral store and a mutable-reference forwarding wrapper.
// Expected: Absence differs from an empty blob, arbitrary bytes round-trip, restored buffers do not alias storage, and later writes replace earlier data.
#[test]
fn ephemeral_store_preserves_blob_identity_and_owned_restore_copies() {
    block_on(async {
        let mut store = EphemeralNonVolatileStore::new_boxed();
        assert_eq!(NonVolatileStore::restore(&mut store).await.unwrap(), None);
        NonVolatileStore::persist(&mut store, vec![0, 0xff, 0x81, 0])
            .await
            .unwrap();
        let mut restored = NonVolatileStore::restore(&mut store)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored, [0, 0xff, 0x81, 0]);
        restored.fill(0x55);
        assert_eq!(
            NonVolatileStore::restore(&mut store).await.unwrap(),
            Some(vec![0, 0xff, 0x81, 0])
        );
        let mut forwarded = &mut store;
        NonVolatileStore::persist(&mut forwarded, Vec::new())
            .await
            .unwrap();
        assert_eq!(
            NonVolatileStore::restore(&mut forwarded).await.unwrap(),
            Some(Vec::new())
        );
    });
}

#[derive(Default)]
struct FailingStore {
    persisted: Vec<Vec<u8>>,
    restores: usize,
}

#[async_trait::async_trait]
impl NonVolatileStore for FailingStore {
    async fn persist(&mut self, data: Vec<u8>) -> Result<(), NonVolatileStoreError> {
        self.persisted.push(data);
        Err(NonVolatileStoreError::new(anyhow::anyhow!(
            "persist sentinel"
        )))
    }

    async fn restore(&mut self) -> Result<Option<Vec<u8>>, NonVolatileStoreError> {
        self.restores += 1;
        Err(NonVolatileStoreError::new(anyhow::anyhow!(
            "restore sentinel"
        )))
    }
}

// Test: Forward persist and restore to a mutable store that records calls and fails each operation.
// Expected: The backend receives each operation exactly once with unchanged bytes, and typed errors retain their distinct underlying causes.
#[test]
fn forwarded_failures_preserve_backend_calls_and_error_causes() {
    block_on(async {
        let mut store = FailingStore::default();
        {
            let mut forwarded = &mut store;
            let error = NonVolatileStore::persist(&mut forwarded, vec![1, 0xff, 3])
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "error accessing non-volatile store");
            assert_eq!(
                std::error::Error::source(&error).unwrap().to_string(),
                "persist sentinel"
            );
            let error = NonVolatileStore::restore(&mut forwarded).await.unwrap_err();
            assert_eq!(
                std::error::Error::source(&error).unwrap().to_string(),
                "restore sentinel"
            );
        }
        assert_eq!(store.persisted, [vec![1, 0xff, 3]]);
        assert_eq!(store.restores, 1);
    });
}

// Test: Resolve the ephemeral store resource twice and persist data to just one result.
// Expected: Each resolution yields an independent empty store, not shared or prepopulated storage.
#[test]
fn ephemeral_resolver_creates_independent_empty_stores() {
    use vm_resource::ResolveResource;
    block_on(async {
        let resolver = resources::EphemeralNonVolatileStoreResolver;
        let mut first = resolver
            .resolve(resources::EphemeralNonVolatileStoreHandle, &())
            .unwrap()
            .0;
        let mut second = resolver
            .resolve(resources::EphemeralNonVolatileStoreHandle, &())
            .unwrap()
            .0;
        first.persist(vec![4, 5, 6]).await.unwrap();
        assert_eq!(first.restore().await.unwrap(), Some(vec![4, 5, 6]));
        assert_eq!(second.restore().await.unwrap(), None);
    });
}
