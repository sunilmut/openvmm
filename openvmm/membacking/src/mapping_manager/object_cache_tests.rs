// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::ObjectCache;
use super::ObjectId;
use futures::FutureExt;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Request the same object while its first construction is pending.
// Expected: Both callers receive the winning value; after all references are
//       released, a later caller can construct a fresh value for the same ID.
#[async_test]
async fn concurrent_builders_share_result_and_expired_values_can_be_rebuilt() {
    let cache = ObjectCache::new();
    let id = ObjectId::new();
    let (release, wait) = mesh::oneshot();
    let mut first = Box::pin(cache.get_or_insert_with(&id, async {
        wait.await.unwrap();
        Ok::<_, &str>(37)
    }));
    assert!(first.as_mut().now_or_never().is_none());
    let mut second = Box::pin(cache.get_or_insert_with(&id, async { Ok::<_, &str>(99) }));
    assert!(second.as_mut().now_or_never().is_none());
    release.send(());
    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert_eq!(*first, 37);
    assert_eq!(*second, 37);
    let cached = cache
        .get_or_insert_with(&id, async { Ok::<_, &str>(99) })
        .await
        .unwrap();
    assert_eq!(*cached, 37);
    drop((first, second, cached));
    let replacement = cache
        .get_or_insert_with(&id, async { Ok::<_, &str>(99) })
        .await
        .unwrap();
    assert_eq!(*replacement, 99);
}

// Test: Fail an in-flight construction while another caller waits for that ID.
// Expected: The first error is preserved; the waiting caller retries its own
//       factory and its successful result becomes reusable.
#[async_test]
async fn failed_builder_allows_a_waiter_to_retry() {
    let cache = ObjectCache::new();
    let id = ObjectId::new();
    let (release, wait) = mesh::oneshot();
    let mut first = Box::pin(cache.get_or_insert_with(&id, async {
        wait.await.unwrap();
        Err::<u32, _>("injected factory failure")
    }));
    assert!(first.as_mut().now_or_never().is_none());
    let mut waiter = Box::pin(cache.get_or_insert_with(&id, async { Ok::<_, &str>(99) }));
    assert!(waiter.as_mut().now_or_never().is_none());
    release.send(());
    assert_eq!(first.await.unwrap_err(), "injected factory failure");
    let result = waiter.await.unwrap();
    assert_eq!(*result, 99);
    assert_eq!(
        *cache
            .get_or_insert_with(&id, async { Ok::<_, &str>(1) })
            .await
            .unwrap(),
        99
    );
}

// IGNORED: Dropping the active factory leaves its cache entry in Building, so
// existing and future waiters for that object ID can never make progress.
//
// Test: Cancel the active builder while another caller waits for the same ID.
// Expected: The surviving caller can build its value instead of waiting forever
//       for a factory future that no longer exists.
#[async_test]
#[ignore = "product regression: cancelling a cache builder strands its waiters"]
async fn cancelled_builder_allows_a_waiter_to_retry() {
    let cache = ObjectCache::new();
    let id = ObjectId::new();
    let mut first =
        Box::pin(cache.get_or_insert_with(&id, std::future::pending::<Result<u32, &str>>()));
    assert!(first.as_mut().now_or_never().is_none());
    let mut waiter = Box::pin(cache.get_or_insert_with(&id, async { Ok::<_, &str>(99) }));
    assert!(waiter.as_mut().now_or_never().is_none());
    drop(first);
    let result = waiter
        .now_or_never()
        .expect("surviving factory remains blocked")
        .unwrap();
    assert_eq!(*result, 99);
}
