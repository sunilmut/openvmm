// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::auto_cache::AutoCacheSqliteDiskLayer;
use test_with_tracing::test;

// Test: Create identity-keyed and explicit-key caches, populate data/zero sectors without overwriting existing cache entries, and reopen them read-only.
// Expected: Cache geometry matches the source, first-written bytes including explicit zero sectors survive replacement attempts and reopen, and a read-only cache rejects further writes.
#[async_test]
async fn automatic_cache_creation_reopen_and_no_overwrite_preserve_first_data() {
    let dir = tempfile::tempdir().unwrap();
    for key in [None, Some("explicit-key".to_owned())] {
        let expected_key = key.clone().unwrap_or_else(|| "12".repeat(16));
        let cache = AutoCacheSqliteDiskLayer::new(dir.path().into(), key.clone(), false)
            .attach(Some(metadata()))
            .await
            .unwrap();
        assert_eq!(cache.layer_type(), "sqlite");
        assert_eq!(cache.sector_count(), 8);
        assert_eq!(cache.sector_size(), 512);
        assert_eq!(cache.physical_sector_size(), 512);
        assert!(cache.is_logically_read_only());
        assert!(!cache.is_fua_respected());
        assert_eq!(cache.disk_id(), None);
        assert_eq!(cache.unmap_behavior(), UnmapBehavior::Zeroes);
        assert_eq!(cache.optimal_unmap_sectors(), 1);
        cache_fill(&cache, 1, &vec![0xa1; 512]).await.unwrap();
        cache_fill(&cache, 2, &vec![0; 512]).await.unwrap();
        cache_fill(&cache, 1, &vec![0xb2; 2 * 512]).await.unwrap();
        cache.sync_cache().await.unwrap();
        drop(cache);
        let path = dir.path().join(expected_key).join("cache.dbhd");
        let mut expected = vec![0xa1; 512];
        expected.extend(vec![0; 512]);
        assert_eq!(read_layers(&[&path], 1, 2).await, expected);
        let reopened = AutoCacheSqliteDiskLayer::new(dir.path().into(), key, true)
            .attach(Some(metadata()))
            .await
            .unwrap();
        assert!(matches!(
            cache_fill(&reopened, 3, &vec![0xcc; 512]).await,
            Err(DiskError::Io(_))
        ));
        assert_eq!(read_layers(&[&path], 1, 2).await, expected);
    }
}

// Test: Attach caches without lower metadata or identity, with an empty key, in missing read-only storage, and against an existing cache of the wrong size.
// Expected: Each unsupported configuration reports its specific error rather than creating or silently reformatting a cache, and wrong-size rejection preserves the original cached bytes.
#[async_test]
async fn invalid_cache_configuration_is_rejected_without_destroying_existing_data() {
    let dir = tempfile::tempdir().unwrap();
    let error = AutoCacheSqliteDiskLayer::new(dir.path().into(), Some("key".into()), false)
        .attach(None)
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "no layer to cache");
    let mut no_id = metadata();
    no_id.disk_id = None;
    let error = AutoCacheSqliteDiskLayer::new(dir.path().into(), None, false)
        .attach(Some(no_id))
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "cannot cache without a disk ID to use as a key"
    );
    let error = AutoCacheSqliteDiskLayer::new(dir.path().into(), Some(String::new()), false)
        .attach(Some(metadata()))
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "empty cache key");
    let error = AutoCacheSqliteDiskLayer::new(dir.path().into(), Some("missing".into()), true)
        .attach(Some(metadata()))
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "cache file does not exist and cannot be created in read-only mode"
    );
    assert!(!dir.path().join("missing").exists());
    let cache = AutoCacheSqliteDiskLayer::new(dir.path().into(), Some("existing".into()), false)
        .attach(Some(metadata()))
        .await
        .unwrap();
    cache_fill(&cache, 0, &vec![0x81; 512]).await.unwrap();
    drop(cache);
    let mut changed = metadata();
    changed.sector_count = 16;
    let error = AutoCacheSqliteDiskLayer::new(dir.path().into(), Some("existing".into()), false)
        .attach(Some(changed))
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "cache layer has different sector count: 8 vs 16"
    );
    assert_eq!(
        read_layers(&[&dir.path().join("existing/cache.dbhd")], 0, 1).await,
        vec![0x81; 512]
    );
}
