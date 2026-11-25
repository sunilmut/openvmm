// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::sync::Arc;
use test_with_tracing::test;
use user_driver::DmaClient;

impl PoolSource for Arc<TestMapper> {
    fn address_bias(&self) -> u64 {
        self.as_ref().address_bias()
    }
    fn file_offset(&self, address: u64) -> u64 {
        self.as_ref().file_offset(address)
    }
    fn mappable(&self) -> MappableRef<'_> {
        self.as_ref().mappable()
    }
}

// Test: Save two devices' DMA allocations, restore the pool over the same backing, and attach pending buffers one device at a time.
// Expected: Each device receives only its own original PFNs and bytes without zeroing, repeated attachment is empty, and restore validation succeeds only after every device reattaches.
#[test]
fn attaching_pending_dma_buffers_preserves_contents_and_device_ownership() {
    let mapper = Arc::new(TestMapper::new(10).unwrap());
    let ranges = [MemoryRange::from_4k_gpn_range(2..8)];
    let snapshot = {
        let mut pool = PagePool::new(&ranges, mapper.clone()).unwrap();
        let first = pool.allocator("first-device".into()).unwrap();
        let second = pool.allocator("second-device".into()).unwrap();
        let first_block = first.allocate_dma_buffer(2 * PAGE_SIZE as usize).unwrap();
        let second_block = second.allocate_dma_buffer(PAGE_SIZE as usize).unwrap();
        let first_tail = first.allocate_dma_buffer(PAGE_SIZE as usize).unwrap();
        first_block.write_at(PAGE_SIZE as usize - 2, &[1, 0x81, 0xfe, 0xff]);
        second_block.write_at(0, b"second");
        first_tail.write_at(0, b"tail");
        pool.save().unwrap()
    };
    let mut pool = PagePool::new(&ranges, mapper).unwrap();
    pool.restore(snapshot).unwrap();
    let first = pool.allocator("first-device".into()).unwrap();
    let attached = first.attach_pending_buffers().unwrap();
    assert_eq!(attached.len(), 2);
    let first_block = attached
        .iter()
        .find(|block| block.pfns() == [2, 3])
        .unwrap();
    let mut bytes = [0; 4];
    first_block.read_at(PAGE_SIZE as usize - 2, &mut bytes);
    assert_eq!(bytes, [1, 0x81, 0xfe, 0xff]);
    let first_tail = attached.iter().find(|block| block.pfns() == [5]).unwrap();
    first_tail.read_at(0, &mut bytes);
    assert_eq!(&bytes, b"tail");
    assert!(first.attach_pending_buffers().unwrap().is_empty());
    assert!(pool.validate_restore(false).is_err());
    let second = pool.allocator("second-device".into()).unwrap();
    let second_attached = second.attach_pending_buffers().unwrap();
    assert_eq!(second_attached.len(), 1);
    assert_eq!(second_attached[0].pfns(), &[4]);
    let mut second_bytes = [0; 6];
    second_attached[0].read_at(0, &mut second_bytes);
    assert_eq!(&second_bytes, b"second");
    pool.validate_restore(false).unwrap();
}

// Test: Allocate DMA memory from pre-dirtied biased backing, modify bytes across a page boundary, then free and allocate again.
// Expected: Only allocated pages are zeroed, PFNs/size/bias describe the correct mapping, cross-page writes reach the backing exactly, and reused memory is sanitized again.
#[test]
fn dma_allocations_zero_reused_memory_and_preserve_biased_mapping() {
    let mapper = TestMapper::new(12).unwrap();
    let alias = mapper.sparse_mapping();
    alias
        .atomic_slice(0, 12 * PAGE_SIZE as usize)
        .atomic_fill(0xcc);
    let pool = PagePool::new(
        &[MemoryRange::from_4k_gpn_range(2..6)],
        BiasedMapper::new(mapper, 16 * PAGE_SIZE),
    )
    .unwrap();
    let allocator = pool.allocator("dma-device".into()).unwrap();
    let len = 2 * PAGE_SIZE as usize;
    let block = allocator.allocate_dma_buffer(len).unwrap();
    assert_eq!(block.len(), len);
    assert_eq!(block.pfns(), &[18, 19]);
    assert_eq!(block.pfn_bias(), 16);
    assert_eq!(block.base() as usize % PAGE_SIZE as usize, 0);
    let mut bytes = vec![0xa5; len];
    block.read_at(0, &mut bytes);
    assert_eq!(bytes, vec![0; len]);
    let mut untouched = [0; 8];
    alias
        .atomic_slice(PAGE_SIZE as usize, 8)
        .atomic_read(&mut untouched);
    assert_eq!(untouched, [0xcc; 8]);
    alias
        .atomic_slice(4 * PAGE_SIZE as usize, 8)
        .atomic_read(&mut untouched);
    assert_eq!(untouched, [0xcc; 8]);
    block.write_at(PAGE_SIZE as usize - 2, &[0x80, 0, 0xfe, 0xff]);
    let mut changed = [0; 4];
    alias
        .atomic_slice(3 * PAGE_SIZE as usize - 2, 4)
        .atomic_read(&mut changed);
    assert_eq!(changed, [0x80, 0, 0xfe, 0xff]);
    drop(block);
    let reused = allocator.allocate_dma_buffer(len).unwrap();
    assert_eq!(reused.pfns(), &[18, 19]);
    reused.read_at(0, &mut bytes);
    assert_eq!(bytes, vec![0; len]);
}

// Test: Keep an allocator spawner after dropping its pool, allocate DMA memory, and retain only a small MemoryBlock view.
// Expected: The spawner remains usable, the view retains the full allocation and its contents, capacity cannot be reused until the final view drops, and then all pages become available again.
#[test]
fn spawner_and_dma_subviews_retain_mapping_and_capacity_until_last_owner_drops() {
    let pool = PagePool::new(
        &[MemoryRange::from_4k_gpn_range(1..3)],
        TestMapper::new(4).unwrap(),
    )
    .unwrap();
    let spawner = pool.allocator_spawner();
    drop(pool);
    let allocator = spawner.allocator("retained-device".into()).unwrap();
    drop(spawner);
    let block = allocator
        .allocate_dma_buffer(2 * PAGE_SIZE as usize)
        .unwrap();
    let view = block.subblock(PAGE_SIZE as usize - 2, 4);
    view.write_at(0, &[1, 0x81, 0xfe, 0xff]);
    assert_eq!(view.pfns(), &[1, 2]);
    drop(block);
    let mut bytes = [0; 4];
    view.read_at(0, &mut bytes);
    assert_eq!(bytes, [1, 0x81, 0xfe, 0xff]);
    let error = allocator
        .allocate_dma_buffer(PAGE_SIZE as usize)
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::PagePoolOutOfMemory { size: 1, .. })
    ));
    drop(view);
    let replacement = allocator
        .allocate_dma_buffer(2 * PAGE_SIZE as usize)
        .unwrap();
    assert_eq!(replacement.pfns(), &[1, 2]);
    replacement.read_at(PAGE_SIZE as usize - 2, &mut bytes);
    assert_eq!(bytes, [0; 4]);
}

// Test: Request zero and non-page-multiple DMA lengths before a whole-pool allocation.
// Expected: Invalid lengths return their specific errors without consuming pages, and the next valid allocation still owns the entire pool.
#[test]
fn invalid_dma_lengths_do_not_consume_capacity() {
    let pool = PagePool::new(
        &[MemoryRange::from_4k_gpn_range(1..3)],
        TestMapper::new(4).unwrap(),
    )
    .unwrap();
    let allocator = pool.allocator("invalid-size-device".into()).unwrap();
    for len in [0, 1, PAGE_SIZE as usize - 1, PAGE_SIZE as usize + 1] {
        let error = allocator.allocate_dma_buffer(len).unwrap_err();
        assert_eq!(
            error.to_string(),
            if len == 0 {
                "allocation of size 0 not supported"
            } else {
                "not a page-size multiple"
            }
        );
    }
    let entire_pool = allocator
        .allocate_dma_buffer(2 * PAGE_SIZE as usize)
        .unwrap();
    assert_eq!(entire_pool.pfns(), &[1, 2]);
}
