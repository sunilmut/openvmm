// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe DMA buffer views and allocator ownership; no physical DMA is issued.

#![cfg(target_os = "linux")]

use guestmem::GuestMemory;
use guestmem::ranges::PagedRange;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::task::Context;
use std::task::Wake;
use std::task::Waker;
use test_with_tracing::test;
use user_driver::lockmem::LockedMemory;
use user_driver::memory::MemoryBlock;
use user_driver::memory::PAGE_SIZE;
use user_driver::page_allocator::PageAllocator;

fn memory(pages: usize) -> MemoryBlock {
    MemoryBlock::new(LockedMemory::new(pages * PAGE_SIZE).unwrap())
}

#[derive(Default)]
struct WakeFlag(AtomicBool);

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, SeqCst);
    }
}

// Test: Write through nested, unaligned DMA views spanning a page boundary,
//       clone one view and drop its originating owners.
// Expected: Only the requested byte interval changes, typed unaligned accesses
//       round-trip, zeroing stays within bounds and the clone keeps backing live.
#[test]
fn nested_views_preserve_byte_boundaries_and_backing_lifetime() {
    let root = memory(2);
    root.write_at(0, &vec![0xa5; PAGE_SIZE * 2]);
    let outer = root.subblock(PAGE_SIZE - 7, 40);
    let inner = outer.subblock(3, 29);
    inner.write_at(0, &[0x3c; 29]);
    inner.write_obj(1, &0x1234_5678u32);
    assert_eq!(inner.read_obj::<u32>(1), 0x1234_5678);
    inner.write_zeros(8, 7);
    let mut bytes = vec![0; PAGE_SIZE * 2];
    root.read_at(0, &mut bytes);
    let start = PAGE_SIZE - 4;
    let mut expected = vec![0xa5; PAGE_SIZE * 2];
    expected[start..start + 29].fill(0x3c);
    expected[start + 1..start + 5].copy_from_slice(&0x1234_5678u32.to_ne_bytes());
    expected[start + 8..start + 15].fill(0);
    assert_eq!(bytes, expected);
    let survivor = inner.clone();
    drop(inner);
    drop(outer);
    drop(root);
    survivor.write_at(28, &[0x7e]);
    let mut byte = [0];
    survivor.read_at(28, &mut byte);
    assert_eq!(byte, [0x7e]);
}

// Test: Exhaust a DMA page pool, register an allocation waiter and release an
//       existing allocation while keeping another allocation live.
// Expected: Oversized requests fail, release wakes the waiter, and recycled
//       pages never overwrite the still-live allocation.
#[test]
fn released_pages_wake_waiters_without_aliasing_live_storage() {
    let allocator = PageAllocator::new(memory(4));
    futures::executor::block_on(async {
        let error = allocator.alloc_pages(4).await.err().unwrap();
        assert_eq!((error.requested, error.max), (4, 3));
        let first = allocator.alloc_pages(3).await.unwrap();
        let live = allocator.alloc_pages(1).await.unwrap();
        live.write(&[0x5a; 32]);
        let mut waiting = std::pin::pin!(allocator.alloc_bytes(PAGE_SIZE + 17));
        let wake = Arc::new(WakeFlag::default());
        let waker = Waker::from(wake.clone());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(first);
        assert!(wake.0.load(SeqCst));
        let recycled = waiting.await.unwrap();
        let payload = vec![0x6b; PAGE_SIZE + 17];
        recycled.write(&payload);
        let mut result = vec![0; payload.len()];
        recycled.read(&mut result);
        assert_eq!(result, payload);
        let mut canary = [0; 32];
        live.read(&mut canary);
        assert_eq!(canary, [0x5a; 32]);
    });
}

// Test: Bounce an unaligned guest range across three noncontiguous guest pages
//       into two DMA pages and back; also use an unbacked guest range.
// Expected: Every payload byte reaches its exact guest address, all surrounding
//       bytes remain unchanged and inaccessible guest pages return errors.
#[test]
fn guest_bounce_copy_preserves_noncontiguous_ranges_and_canaries() {
    let allocator = PageAllocator::new(memory(3));
    let length = PAGE_SIZE + 13;
    let pages = futures::executor::block_on(allocator.alloc_bytes(length)).unwrap();
    let guest = GuestMemory::allocate(PAGE_SIZE * 8);
    guest.write_at(0, &vec![0xa7; PAGE_SIZE * 8]).unwrap();
    let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
    let addresses = [PAGE_SIZE * 2 - 5, PAGE_SIZE * 4, PAGE_SIZE * 6];
    guest.write_at(addresses[0] as u64, &payload[..5]).unwrap();
    guest
        .write_at(addresses[1] as u64, &payload[5..5 + PAGE_SIZE])
        .unwrap();
    guest
        .write_at(addresses[2] as u64, &payload[5 + PAGE_SIZE..])
        .unwrap();
    let range = PagedRange::new(PAGE_SIZE - 5, length, &[1, 4, 6]).unwrap();
    pages.copy_from_guest_memory(&guest, range).unwrap();
    let mut actual = vec![0; length];
    pages.read(&mut actual);
    assert_eq!(actual, payload);
    let reply: Vec<_> = payload.iter().map(|byte| !byte).collect();
    pages.write(&reply);
    pages.copy_to_guest_memory(&guest, range).unwrap();
    let mut expected = vec![0xa7; PAGE_SIZE * 8];
    expected[addresses[0]..addresses[0] + 5].copy_from_slice(&reply[..5]);
    expected[addresses[1]..addresses[1] + PAGE_SIZE].copy_from_slice(&reply[5..5 + PAGE_SIZE]);
    expected[addresses[2]..addresses[2] + 8].copy_from_slice(&reply[5 + PAGE_SIZE..]);
    let mut actual = vec![0; expected.len()];
    guest.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let inaccessible = PagedRange::new(0, length, &[20, 21]).unwrap();
    assert!(pages.copy_from_guest_memory(&guest, inaccessible).is_err());
    assert!(pages.copy_to_guest_memory(&guest, inaccessible).is_err());
}

// IGNORED: An enabled run accepted 24..40 within a 32-byte parent view because
//       nested bounds are checked against the root backing allocation instead.
//       This is a public view-isolation defect; no exploit chain is asserted.
//
// Test: Request a nested subview that exceeds its immediate parent's bounds
//       while remaining within the original allocation.
// Expected: The subset API rejects the range rather than exposing bytes outside
//       the parent view.
#[test]
#[ignore = "nested subviews check root capacity instead of parent bounds"]
fn nested_subviews_cannot_escape_their_parent() {
    let root = memory(1);
    let parent = root.subblock(64, 32);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parent.subblock(24, 16)));
    assert!(result.is_err(), "nested subview escaped its parent");
}

// IGNORED: An enabled run panicked in the n + 1 capacity check for usize::MAX
//       instead of returning PageAllocationError. The inspected NVMe caller
//       requests one PRP page or allocates by byte count; no exploit is claimed.
//
// Test: Request the largest representable number of pages from a small pool.
// Expected: A too-large allocation returns its ordinary bounds error without
//       overflowing or waiting for impossible capacity.
#[test]
#[ignore = "page request capacity check overflows before returning the error"]
fn largest_page_request_returns_the_capacity_error() {
    let allocator = PageAllocator::new(memory(2));
    let error = futures::executor::block_on(allocator.alloc_pages(usize::MAX))
        .err()
        .expect("oversized request must be rejected");
    assert_eq!((error.requested, error.max), (usize::MAX, 1));
}
