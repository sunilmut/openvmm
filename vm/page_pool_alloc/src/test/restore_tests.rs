// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Restore one allocation, deliberately leak an unmatched allocation, and save/restore that resulting pool again.
// Expected: Leaking resolves restore validation without freeing the missing device's page; its ownership cannot be reclaimed, while surviving allocations and truly free capacity remain usable across the second restore.
#[test]
fn deliberately_leaked_pages_remain_unavailable_across_another_restore() {
    let ranges = [MemoryRange::from_4k_gpn_range(2..6)];
    let snapshot = {
        let mut pool = PagePool::new(&ranges, TestMapper::new(8).unwrap()).unwrap();
        let survivor = pool.allocator("survivor".into()).unwrap();
        let missing = pool.allocator("missing-device".into()).unwrap();
        let surviving = survivor
            .alloc(1.try_into().unwrap(), "live".into())
            .unwrap();
        let abandoned = missing
            .alloc(1.try_into().unwrap(), "abandoned".into())
            .unwrap();
        assert_eq!(surviving.base_pfn(), 2);
        assert_eq!(abandoned.base_pfn(), 3);
        pool.save().unwrap()
    };
    let snapshot_with_leak = {
        let mut pool = PagePool::new(&ranges, TestMapper::new(8).unwrap()).unwrap();
        pool.restore(snapshot).unwrap();
        let survivor = pool.allocator("survivor".into()).unwrap();
        let _surviving = survivor.restore_alloc(2, 1.try_into().unwrap()).unwrap();
        assert!(pool.validate_restore(false).is_err());
        pool.validate_restore(true).unwrap();
        pool.validate_restore(false).unwrap();
        let missing = pool.allocator("missing-device".into()).unwrap();
        assert!(matches!(
            missing.restore_alloc(3, 1.try_into().unwrap()),
            Err(crate::Error::NoMatchingAllocation)
        ));
        pool.save().unwrap()
    };
    let mut pool = PagePool::new(&ranges, TestMapper::new(8).unwrap()).unwrap();
    pool.restore(snapshot_with_leak).unwrap();
    let survivor = pool.allocator("survivor".into()).unwrap();
    let surviving = survivor.restore_alloc(2, 1.try_into().unwrap()).unwrap();
    assert_eq!(surviving.base_pfn(), 2);
    assert_eq!(surviving.size_pages(), 1);
    pool.validate_restore(false).unwrap();
    let missing = pool.allocator("missing-device".into()).unwrap();
    assert!(matches!(
        missing.restore_alloc(3, 1.try_into().unwrap()),
        Err(crate::Error::NoMatchingAllocation)
    ));
    let free = missing
        .alloc(2.try_into().unwrap(), "free-pages".into())
        .unwrap();
    assert_eq!(free.base_pfn(), 4);
    assert_eq!(free.size_pages(), 2);
    assert!(matches!(
        missing.alloc(1.try_into().unwrap(), "must-not-reuse-leaked".into()),
        Err(crate::Error::PagePoolOutOfMemory { size: 1, .. })
    ));
}
