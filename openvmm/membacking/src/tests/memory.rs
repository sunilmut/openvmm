// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::PAGE;
use super::backing;
use super::manager;
use super::read_byte;
use crate::GuestMemoryBuilder;
use crate::MemoryBuildError;
use crate::RamBackingRequest;
use crate::SharedMemoryBacking;
use memory_range::MemoryRange;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Export shared RAM backing, transfer its owned file handle, and build
//       a replacement manager from it after dropping the original manager.
// Expected: Sparse guest ranges preserve their contents and holes through restart.
#[async_test]
async fn shared_backing_restart_preserves_sparse_ram() {
    let ranges = vec![
        MemoryRange::new(0..PAGE),
        MemoryRange::new(3 * PAGE..4 * PAGE),
    ];
    let original = manager(ranges.clone(), 5 * PAGE).await;
    let gm = original.client().guest_memory().await.unwrap();
    gm.write_at(0, &[0x17]).unwrap();
    gm.write_at(3 * PAGE, &[0xe2]).unwrap();
    let backing = original.shared_memory_backing().unwrap().into_mappable();
    let fd: std::os::fd::OwnedFd = backing.into();
    let transferred = SharedMemoryBacking::from_mappable(fd.into());
    drop(gm);
    drop(original);
    let restored = GuestMemoryBuilder::new()
        .add_backing(RamBackingRequest::new(ranges).existing_mappable(transferred.into_mappable()))
        .build(5 * PAGE)
        .await
        .unwrap();
    let gm = restored.client().guest_memory().await.unwrap();
    assert_eq!(read_byte(&gm, 0), 0x17);
    assert_eq!(read_byte(&gm, 3 * PAGE), 0xe2);
    assert!(gm.read_at(PAGE, &mut [0]).is_err());
    gm.write_at(3 * PAGE, &[0x5c]).unwrap();
    let second = restored.client().guest_memory().await.unwrap();
    assert_eq!(read_byte(&second, 3 * PAGE), 0x5c);
}

// Test: Build private, prefetched shared, and empty memory managers.
// Expected: Allocated RAM is zeroed and writable, holes reject access, and
//       private or absent RAM cannot be exported as a shared backing.
#[async_test]
async fn private_prefetched_and_empty_ram_have_consistent_access() {
    for private in [false, true] {
        let manager = GuestMemoryBuilder::new()
            .supports_memory_fault_resolution(true)
            .add_backing(
                RamBackingRequest::new(vec![MemoryRange::new(PAGE..3 * PAGE)])
                    .private_memory(private)
                    .prefetch(true)
                    .transparent_hugepages(true),
            )
            .build(4 * PAGE)
            .await
            .unwrap();
        let gm = manager.client().guest_memory().await.unwrap();
        assert_eq!(read_byte(&gm, PAGE), 0);
        gm.write_at(2 * PAGE + 7, &[0xad]).unwrap();
        assert_eq!(read_byte(&gm, 2 * PAGE + 7), 0xad);
        assert!(gm.read_at(0, &mut [0]).is_err());
        assert_eq!(manager.shared_memory_backing().is_none(), private);
        assert_eq!(gm.sharing().is_none(), private);
    }
    let manager = GuestMemoryBuilder::new().build(PAGE).await.unwrap();
    assert!(manager.shared_memory_backing().is_none());
    assert!(
        manager
            .client()
            .guest_memory()
            .await
            .unwrap()
            .read_at(0, &mut [0])
            .is_err()
    );
}

// Test: Resolve valid, unmapped, out-of-range and cross-backing memory faults.
// Expected: A valid fault returns exactly its uniform range on Linux; invalid
//       ranges are rejected instead of borrowing backing from a neighbor.
#[async_test]
async fn fault_resolution_obeys_ram_boundaries() {
    let manager = GuestMemoryBuilder::new()
        .supports_memory_fault_resolution(true)
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..PAGE)]))
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(
            PAGE..2 * PAGE,
        )]))
        .build(4 * PAGE)
        .await
        .unwrap();
    assert!(manager.shared_memory_backing().is_none());
    let resolver = manager.memory_fault_resolver();
    for write in [false, true] {
        let page = MemoryRange::new(0..PAGE);
        assert_eq!(resolver.resolve(page, write).unwrap(), page);
        for invalid in [
            MemoryRange::new(2 * PAGE..3 * PAGE),
            MemoryRange::new(4 * PAGE..5 * PAGE),
            MemoryRange::new(0..2 * PAGE),
        ] {
            assert!(resolver.resolve(invalid, write).is_err());
        }
    }
}

// Test: Reject incompatible RAM options and invalid legacy or alias layouts.
// Expected: Public construction returns the corresponding validation error
//       before attempting a hugepage allocation or publishing any RAM.
#[async_test]
async fn incompatible_backing_options_report_specific_errors() {
    let range = || vec![MemoryRange::new(0..0x100000)];
    let fd = backing(&vec![0; PAGE as usize]);
    let result = GuestMemoryBuilder::new()
        .x86_legacy_support(true)
        .add_backing(RamBackingRequest::new(range()).private_memory(true))
        .build(0x100000)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::PrivateMemoryWithLegacy)
    ));
    let result = GuestMemoryBuilder::new()
        .add_backing(
            RamBackingRequest::new(range())
                .private_memory(true)
                .existing_mappable(fd),
        )
        .build(0x100000)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::PrivateMemoryWithExistingBacking)
    ));
    let result = GuestMemoryBuilder::new()
        .add_backing(
            RamBackingRequest::new(range())
                .private_memory(true)
                .hugepages(None),
        )
        .build(0x100000)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::HugepagesWithPrivateMemory)
    ));
    let result = GuestMemoryBuilder::new()
        .x86_legacy_support(true)
        .add_backing(RamBackingRequest::new(range()).hugepages(None))
        .build(0x100000)
        .await;
    assert!(matches!(result, Err(MemoryBuildError::HugepagesWithLegacy)));
    let result = GuestMemoryBuilder::new()
        .x86_legacy_support(true)
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(
            PAGE..2 * PAGE,
        )]))
        .build(2 * PAGE)
        .await;
    assert!(matches!(result, Err(MemoryBuildError::InvalidRamForX86)));
    let result = GuestMemoryBuilder::new()
        .vtl0_alias_map(Some(PAGE))
        .build(2 * PAGE)
        .await;
    assert!(matches!(result, Err(MemoryBuildError::AliasMapWontFit)));
}

// Test: Request invalid hugepage sizes and unaligned RAM layouts through the
//       public builder without reserving any host hugepages.
// Expected: Invalid size, total size, and range alignment have distinct errors.
#[async_test]
async fn hugepage_validation_rejects_bad_layouts_before_allocation() {
    let result = GuestMemoryBuilder::new()
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..PAGE)]).hugepages(Some(3)))
        .build(PAGE)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::InvalidHugepageSize(_))
    ));
    let result = GuestMemoryBuilder::new()
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..PAGE)]).hugepages(None))
        .build(PAGE)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::HugepageRamSizeUnaligned { .. })
    ));
    let result = GuestMemoryBuilder::new()
        .add_backing(
            RamBackingRequest::new(vec![
                MemoryRange::new(0..PAGE),
                MemoryRange::new(0x200000 + PAGE..0x400000),
            ])
            .hugepages(Some(0x200000)),
        )
        .build(0x400000)
        .await;
    assert!(matches!(
        result,
        Err(MemoryBuildError::HugepageRamRangeUnaligned { .. })
    ));
}

// Test: Request a virtual address reservation larger than the Linux user space
//       while providing no RAM backing to allocate or commit.
// Expected: Construction reports a VA reservation error rather than panicking
//       or allocating guest RAM.
#[async_test]
async fn impossible_address_space_reports_reservation_error() {
    let result = GuestMemoryBuilder::new().build(1 << 63).await;
    assert!(matches!(result, Err(MemoryBuildError::VaMapper(_))));
}
