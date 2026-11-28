// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AccessType;
use crate::GuestMemory;
use crate::GuestMemoryAccess;
use crate::GuestMemoryBackingError;
use crate::GuestMemoryError;
use crate::PAGE_SIZE64;
use crate::PageFaultAction;
use crate::PageFaultError;

use parking_lot::Mutex;
use sparse_mmap::SparseMapping;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use test_with_tracing::test;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq)]
enum LockOperation {
    Lock(Vec<u64>),
    Unlock(Vec<u64>),
}

struct LockMapping {
    mapping: SparseMapping,
    lockable: bool,
    unlock_required: bool,
    operations: Mutex<Vec<LockOperation>>,
}

impl LockMapping {
    /// Allocates a backing whose locking behavior is selected by named fields.
    fn new(size: usize) -> Self {
        let mapping = SparseMapping::new(size).unwrap();
        mapping.alloc(0, size).unwrap();
        Self {
            mapping,
            lockable: false,
            unlock_required: false,
            operations: Mutex::new(Vec::new()),
        }
    }

    fn take_operations(&self) -> Vec<LockOperation> {
        std::mem::take(&mut *self.operations.lock())
    }
}

// SAFETY: the mapping remains allocated for the full reported range.
unsafe impl GuestMemoryAccess for LockMapping {
    fn mapping(&self) -> Option<NonNull<u8>> {
        NonNull::new(self.mapping.as_ptr().cast())
    }

    fn max_address(&self) -> u64 {
        self.mapping.len() as u64
    }

    fn supports_kernel_lock(&self) -> bool {
        self.lockable
    }

    fn supports_user_lock(&self) -> bool {
        self.lockable
    }

    fn lock_kernel_gpns(&self, gpns: &[u64]) -> Result<bool, GuestMemoryBackingError> {
        self.operations
            .lock()
            .push(LockOperation::Lock(gpns.to_vec()));
        Ok(self.unlock_required)
    }

    fn lock_user_gpns(&self, gpns: &[u64]) -> Result<bool, GuestMemoryBackingError> {
        GuestMemoryAccess::lock_kernel_gpns(self, gpns)
    }

    fn unlock_gpns(&self, gpns: &[u64]) {
        self.operations
            .lock()
            .push(LockOperation::Unlock(gpns.to_vec()));
    }
}

fn lock_pages(
    memory: &GuestMemory,
    access: AccessType,
    kernel: bool,
    gpns: &[u64],
) -> Result<(), GuestMemoryError> {
    if kernel {
        memory.lock_kernel_gpns(access, gpns).map(drop)
    } else {
        memory.lock_user_gpns(access, gpns).map(drop)
    }
}

fn check_locks(memory: &GuestMemory, backing: &LockMapping, gpns: &[u64], expected: &[u64]) {
    for access in [AccessType::Read, AccessType::Write] {
        for kernel in [false, true] {
            lock_pages(memory, access, kernel, gpns).unwrap();
            let mut operations = vec![LockOperation::Lock(expected.to_vec())];
            if backing.unlock_required {
                operations.push(LockOperation::Unlock(expected.to_vec()));
            }
            assert_eq!(backing.take_operations(), operations);
        }
    }
}

// Test: Lock Arc-backed memory with supported and unsupported locking.
// Expected: Capabilities, ordered lock hooks and required unlocks are
//       preserved.
#[test]
fn arc_preserves_locking_support_and_hooks() {
    for lockable in [false, true] {
        let backing = Arc::new(LockMapping {
            lockable,
            unlock_required: true,
            ..LockMapping::new(PAGE_SIZE * 2)
        });
        let memory = GuestMemory::new("arc-locking", backing.clone());
        assert_eq!(memory.supports_kernel_lock(), lockable);
        assert_eq!(memory.supports_user_lock(), lockable);
        if lockable {
            check_locks(&memory, &backing, &[1, 0], &[1, 0]);
        } else {
            for access in [AccessType::Read, AccessType::Write] {
                for kernel in [false, true] {
                    assert!(lock_pages(&memory, access, kernel, &[0]).is_err());
                }
            }
            assert!(backing.take_operations().is_empty());
        }
    }
}

// Test: Lock aligned and nested views over both backing capability settings.
// Expected: Each view retains its parent's support and accepts only valid
//       locks.
#[test]
fn subranges_preserve_locking_support() {
    for lockable in [false, true] {
        let backing = Arc::new(LockMapping {
            lockable,
            unlock_required: true,
            ..LockMapping::new(PAGE_SIZE * 4)
        });
        let memory = GuestMemory::new("subrange-locking", backing.clone());
        let range = memory
            .subrange(PAGE_SIZE64, PAGE_SIZE64 * 2, false)
            .unwrap();
        let nested = range.subrange(PAGE_SIZE64, PAGE_SIZE64, false).unwrap();
        for view in [&range, &nested] {
            assert_eq!(view.supports_kernel_lock(), lockable);
            assert_eq!(view.supports_user_lock(), lockable);
            for access in [AccessType::Read, AccessType::Write] {
                for kernel in [false, true] {
                    assert_eq!(lock_pages(view, access, kernel, &[0]).is_ok(), lockable);
                }
            }
        }
        if !lockable {
            assert!(backing.take_operations().is_empty());
        }
    }
}

// Test: Lock reordered pages through nested views with both unlock policies.
// Expected: Hooks receive translated pages in order and unlock only when
//       needed.
#[test]
fn subranges_forward_lock_hooks_with_offsets() {
    for unlock_required in [false, true] {
        let backing = Arc::new(LockMapping {
            lockable: true,
            unlock_required,
            ..LockMapping::new(PAGE_SIZE * 5)
        });
        let memory = GuestMemory::new("subrange-hooks", backing.clone());
        let range = memory
            .subrange(PAGE_SIZE64, PAGE_SIZE64 * 3, false)
            .unwrap();
        check_locks(&range, &backing, &[2, 0], &[3, 1]);
        let nested = range.subrange(PAGE_SIZE64, PAGE_SIZE64 * 2, false).unwrap();
        check_locks(&nested, &backing, &[1, 0], &[3, 2]);
    }
}

// Test: Lock a view of the second region under all backing support
//       combinations.
// Expected: Support reflects all regions; only the selected backing is locked.
#[test]
fn multi_region_subranges_preserve_parent_support_and_translate_gpns() {
    for first in [false, true] {
        for second in [false, true] {
            let backings = [
                Arc::new(LockMapping {
                    lockable: first,
                    unlock_required: true,
                    ..LockMapping::new(PAGE_SIZE)
                }),
                Arc::new(LockMapping {
                    lockable: second,
                    unlock_required: true,
                    ..LockMapping::new(PAGE_SIZE)
                }),
            ];
            let memory = GuestMemory::new_multi_region(
                "multi-subrange",
                PAGE_SIZE64 * 2,
                backings.iter().cloned().map(Some).collect(),
            )
            .unwrap();
            let range = memory
                .subrange(PAGE_SIZE64 * 2, PAGE_SIZE64, false)
                .unwrap();
            assert_eq!(range.supports_kernel_lock(), first && second);
            assert_eq!(range.supports_user_lock(), first && second);
            if first && second {
                check_locks(&range, &backings[1], &[0], &[0]);
            } else {
                for access in [AccessType::Read, AccessType::Write] {
                    for kernel in [false, true] {
                        assert!(lock_pages(&range, access, kernel, &[0]).is_err());
                    }
                }
                assert!(backings[1].take_operations().is_empty());
            }
            assert!(backings[0].take_operations().is_empty());
        }
    }
}

// Test: Copy bytes and request page locks through unaligned and nested views.
// Expected: Copies succeed; both lock APIs fail without calling backing hooks.
#[test]
fn unaligned_subranges_allow_copies_but_not_page_locks() {
    let backing = Arc::new(LockMapping {
        lockable: true,
        unlock_required: true,
        ..LockMapping::new(PAGE_SIZE * 4)
    });
    let memory = GuestMemory::new("unaligned-subrange", backing.clone());
    let range = memory.subrange(1, PAGE_SIZE64 * 2, false).unwrap();
    let nested = range.subrange(PAGE_SIZE64 - 1, PAGE_SIZE64, false).unwrap();
    for view in [&range, &nested] {
        view.write_at(0, &[0x5a]).unwrap();
        let mut value = [0];
        view.read_at(0, &mut value).unwrap();
        assert_eq!(value, [0x5a]);
        assert!(!view.supports_kernel_lock());
        assert!(!view.supports_user_lock());
        for access in [AccessType::Read, AccessType::Write] {
            for kernel in [false, true] {
                assert!(lock_pages(view, access, kernel, &[0]).is_err());
            }
        }
    }
    assert!(backing.take_operations().is_empty());
}

// Test: Lock partial, absent and overflowing pages through a bounded view.
// Expected: Invalid page lists fail before any backing lock or unlock hook.
#[test]
fn subrange_locks_reject_partial_pages_and_invalid_gpns() {
    let backing = Arc::new(LockMapping {
        lockable: true,
        unlock_required: true,
        ..LockMapping::new(PAGE_SIZE * 4)
    });
    let memory = GuestMemory::new("subrange-bounds", backing.clone());
    let range = memory
        .subrange(PAGE_SIZE64, PAGE_SIZE64 + 1, false)
        .unwrap();
    for access in [AccessType::Read, AccessType::Write] {
        for kernel in [false, true] {
            for gpns in [&[1][..], &[2], &[0, u64::MAX]] {
                assert!(lock_pages(&range, access, kernel, gpns).is_err());
                assert!(backing.take_operations().is_empty());
            }
        }
    }
}
/// An implementation of a GuestMemoryAccess trait that expects all of
/// guest memory to be mapped at a given base, with mmap or the Windows
/// equivalent. Pages that are not backed by RAM will return failure
/// when attempting to access them.
pub struct GuestMemoryMapping {
    mapping: SparseMapping,
    #[cfg(feature = "bitmap")]
    bitmap: Option<Vec<u8>>,
}

unsafe impl GuestMemoryAccess for GuestMemoryMapping {
    fn mapping(&self) -> Option<NonNull<u8>> {
        NonNull::new(self.mapping.as_ptr().cast())
    }

    fn max_address(&self) -> u64 {
        self.mapping.len() as u64
    }

    #[cfg(feature = "bitmap")]
    fn access_bitmap(&self) -> Option<crate::BitmapInfo> {
        self.bitmap.as_ref().map(|bm| crate::BitmapInfo {
            read_bitmap: NonNull::new(bm.as_ptr().cast_mut()).unwrap(),
            write_bitmap: NonNull::new(bm.as_ptr().cast_mut()).unwrap(),
            bit_offset: 0,
        })
    }
}

const PAGE_SIZE: usize = 4096;
const SIZE_1MB: usize = 1048576;

/// Create a test guest layout:
/// 0           -> 1MB          RAM
/// 1MB         -> 2MB          empty
/// 2MB         -> 3MB          RAM
/// 3MB         -> 3MB + 4K     empty
/// 3MB + 4K    -> 4MB          RAM
fn create_test_mapping() -> GuestMemoryMapping {
    let mapping = SparseMapping::new(SIZE_1MB * 4).unwrap();
    mapping.alloc(0, SIZE_1MB).unwrap();
    mapping.alloc(2 * SIZE_1MB, SIZE_1MB).unwrap();
    mapping
        .alloc(3 * SIZE_1MB + PAGE_SIZE, SIZE_1MB - PAGE_SIZE)
        .unwrap();

    GuestMemoryMapping {
        mapping,
        #[cfg(feature = "bitmap")]
        bitmap: None,
    }
}

// Test: Read and write plain, page-sized and large buffers in RAM and a hole.
// Expected: RAM starts zeroed and preserves copied bytes; the hole rejects
//       reads.
#[test]
fn test_basic_read_write() {
    let mapping = create_test_mapping();
    let gm = GuestMemory::new("test", mapping);

    // Test reading at 0.
    let addr = 0;
    let result = gm.read_plain::<u8>(addr);
    assert_eq!(result.unwrap(), 0);

    // Test read/write to first page
    let write_buffer = [1, 2, 3, 4, 5];
    let mut read_buffer = [0; 5];
    gm.write_at(0, &write_buffer).unwrap();
    gm.read_at(0, &mut read_buffer).unwrap();
    assert_eq!(write_buffer, read_buffer);
    assert_eq!(gm.read_plain::<u8>(0).unwrap(), 1);
    assert_eq!(gm.read_plain::<u8>(1).unwrap(), 2);
    assert_eq!(gm.read_plain::<u8>(2).unwrap(), 3);
    assert_eq!(gm.read_plain::<u8>(3).unwrap(), 4);
    assert_eq!(gm.read_plain::<u8>(4).unwrap(), 5);

    // Test read/write to page at 2MB
    let addr = 2 * SIZE_1MB as u64;
    let write_buffer: Vec<u8> = (0..PAGE_SIZE).map(|x| x as u8).collect();
    let mut read_buffer: Vec<u8> = (0..PAGE_SIZE).map(|_| 0).collect();
    gm.write_at(addr, write_buffer.as_slice()).unwrap();
    gm.read_at(addr, read_buffer.as_mut_slice()).unwrap();
    assert_eq!(write_buffer, read_buffer);

    // Copy a full megabyte through the second RAM region.
    let write_buffer: Vec<u8> = (0..SIZE_1MB).map(|x| x as u8).collect();
    let mut read_buffer: Vec<u8> = (0..SIZE_1MB).map(|_| 0).collect();
    gm.write_at(addr, write_buffer.as_slice()).unwrap();
    gm.read_at(addr, read_buffer.as_mut_slice()).unwrap();
    assert_eq!(write_buffer, read_buffer);

    // Test bad read at 1MB
    let addr = SIZE_1MB as u64;
    let result = gm.read_plain::<u8>(addr);
    assert!(result.is_err());
}

// Test: Compare-exchange both halves of a 128-bit word, including mismatches.
// Expected: Updates preserve guards; unsupported hosts fail without writing.
#[test]
fn test_compare_exchange_u128() {
    const OLD: u128 = 0x0123456789abcdef_fedcba9876543210;
    const NEW: u128 = 0x1122334455667788_99aabbccddeeff00;
    let gm = GuestMemory::new("test", create_test_mapping());
    let addr = PAGE_SIZE64 - 16;
    gm.write_plain(addr - 16, &OLD).unwrap();
    gm.write_plain(addr, &OLD).unwrap();
    gm.write_plain(addr + 16, &OLD).unwrap();

    let result = gm.compare_exchange(addr, OLD, NEW);
    // xtask-fmt allow-target-arch cpu-intrinsic
    #[cfg(target_arch = "x86_64")]
    if !std::is_x86_feature_detected!("cmpxchg16b") {
        let error = result.unwrap_err();
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<trycopy::MemoryError>()
            .unwrap();
        assert_eq!(
            source.kind(),
            trycopy::MemoryErrorKind::UnsupportedAtomicAccess
        );
        assert_eq!(gm.read_plain::<u128>(addr).unwrap(), OLD);
        return;
    }
    assert_eq!(result.unwrap(), Ok(NEW));
    for current in [NEW ^ 1, NEW ^ (1 << 64)] {
        assert_eq!(gm.compare_exchange(addr, current, OLD).unwrap(), Err(NEW));
        assert_eq!(gm.read_plain::<u128>(addr).unwrap(), NEW);
    }
    assert_eq!(gm.read_plain::<u128>(addr - 16).unwrap(), OLD);
    assert_eq!(gm.read_plain::<u128>(addr + 16).unwrap(), OLD);
    gm.compare_exchange(SIZE_1MB as u64, OLD, NEW).unwrap_err();
    gm.compare_exchange(4 * SIZE_1MB as u64, OLD, NEW)
        .unwrap_err();
}

// Test: Have four threads repeatedly compare-exchange paired 128-bit
//       increments.
// Expected: The joined total has no lost increments and neither half is torn.
#[test]
fn test_compare_exchange_u128_concurrent() {
    // test_compare_exchange_u128 covers the unsupported result.
    // xtask-fmt allow-target-arch cpu-intrinsic
    #[cfg(target_arch = "x86_64")]
    if !std::is_x86_feature_detected!("cmpxchg16b") {
        return;
    }
    let gm = GuestMemory::allocate(PAGE_SIZE);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let gm = &gm;
            scope.spawn(move || {
                let mut current = 0u128;
                for _ in 0..1000 {
                    loop {
                        let new = current + (1 << 64) + 1;
                        match gm.compare_exchange(0, current, new).unwrap() {
                            Ok(_) => {
                                current = new;
                                break;
                            }
                            Err(actual) => {
                                assert_eq!(actual as u64, (actual >> 64) as u64);
                                current = actual;
                            }
                        }
                    }
                }
            });
        }
    });
    assert_eq!(gm.read_plain::<u128>(0).unwrap(), (4000 << 64) | 4000);
}

// Test: Read present regions, an absent region and each backing/address limit.
// Expected: Only addresses inside present backings can be read.
#[test]
fn test_multi() {
    let len = SIZE_1MB * 4;
    let mapping = SparseMapping::new(len).unwrap();
    mapping.alloc(0, len).unwrap();
    let mapping = Arc::new(GuestMemoryMapping {
        mapping,
        #[cfg(feature = "bitmap")]
        bitmap: None,
    });
    let region_len = 1 << 30;
    let gm = GuestMemory::new_multi_region(
        "test",
        region_len,
        vec![Some(mapping.clone()), None, Some(mapping.clone())],
    )
    .unwrap();

    let mut b = [0];
    let len = len as u64;
    gm.read_at(0, &mut b).unwrap();
    gm.read_at(len, &mut b).unwrap_err();
    gm.read_at(region_len, &mut b).unwrap_err();
    gm.read_at(2 * region_len, &mut b).unwrap();
    gm.read_at(2 * region_len + len, &mut b).unwrap_err();
    gm.read_at(3 * region_len, &mut b).unwrap_err();
}

// Test: Read allowed, denied and page-crossing ranges under a permission
//       bitmap.
// Expected: Every touched page must be permitted, including the trailing page.
#[cfg(feature = "bitmap")]
#[test]
fn test_bitmap() {
    let len = PAGE_SIZE * 4;
    let mapping = SparseMapping::new(len).unwrap();
    mapping.alloc(0, len).unwrap();
    let bitmap = vec![0b0101];
    let mapping = Arc::new(GuestMemoryMapping {
        mapping,
        bitmap: Some(bitmap),
    });
    let gm = GuestMemory::new("test", mapping);

    gm.read_plain::<[u8; 1]>(0).unwrap();
    gm.read_plain::<[u8; 1]>(PAGE_SIZE64 - 1).unwrap();
    gm.read_plain::<[u8; 2]>(PAGE_SIZE64 - 1).unwrap_err();
    gm.read_plain::<[u8; 1]>(PAGE_SIZE64).unwrap_err();
    gm.read_plain::<[u8; 1]>(PAGE_SIZE64 * 2).unwrap();
    gm.read_plain::<[u8; PAGE_SIZE * 2]>(0).unwrap_err();
}

struct FaultingMapping {
    mapping: SparseMapping,
}

#[derive(Debug, Error)]
#[error("fault")]
struct Fault;

unsafe impl GuestMemoryAccess for FaultingMapping {
    fn mapping(&self) -> Option<NonNull<u8>> {
        NonNull::new(self.mapping.as_ptr().cast())
    }

    fn max_address(&self) -> u64 {
        self.mapping.len() as u64
    }

    fn page_fault(
        &self,
        address: u64,
        _len: usize,
        write: bool,
        bitmap_failure: bool,
    ) -> PageFaultAction {
        assert!(!bitmap_failure);
        let qlen = self.mapping.len() as u64 / 4;
        if address < qlen || address >= 3 * qlen {
            return PageFaultAction::Fail(PageFaultError::other(Fault));
        }
        let page_address = (address as usize) & !(PAGE_SIZE - 1);
        if address >= 2 * qlen {
            if write {
                return PageFaultAction::Fail(PageFaultError::other(Fault));
            }
            self.mapping.map_zero(page_address, PAGE_SIZE).unwrap();
        } else {
            self.mapping.alloc(page_address, PAGE_SIZE).unwrap();
        }
        PageFaultAction::Retry
    }
}

impl FaultingMapping {
    fn new(len: usize) -> Self {
        let mapping = SparseMapping::new(len).unwrap();
        FaultingMapping { mapping }
    }
}

// Test: Retry faults into writable or read-only pages and access denied pages.
// Expected: Valid retries succeed; denied and read-only writes return errors.
#[test]
fn test_fault() {
    let len = PAGE_SIZE * 4;
    let mapping = FaultingMapping::new(len);
    let gm = GuestMemory::new("test", mapping);

    gm.write_plain::<u8>(0, &0).unwrap_err();
    gm.read_plain::<u8>(PAGE_SIZE64 - 1).unwrap_err();
    gm.read_plain::<u8>(PAGE_SIZE64).unwrap();
    gm.write_plain::<u8>(PAGE_SIZE64, &0).unwrap();
    gm.write_plain::<u16>(PAGE_SIZE64 * 3 - 1, &0).unwrap_err();
    gm.read_plain::<u16>(PAGE_SIZE64 * 3 - 1).unwrap_err();
    gm.read_plain::<u8>(PAGE_SIZE64 * 3 - 1).unwrap();
    gm.write_plain::<u8>(PAGE_SIZE64 * 3 - 1, &0).unwrap_err();
}

// Test: Compare-exchange at aligned and unaligned composed view addresses.
// Expected: Supported accesses change only the word; unsupported ones fail.
#[test]
fn test_compare_exchange_alignment() {
    trycopy::initialize_try_copy();
    let mapping = FaultingMapping::new(PAGE_SIZE * 4);
    mapping.mapping.alloc(0, PAGE_SIZE).unwrap();
    let gm = GuestMemory::new("atomic-alignment", mapping);
    const NEW: u64 = 0x123456789abcdef0;
    for (offset, gpa) in [(0, 1), (1, 0), (1, 7), (0, 8)] {
        let view = gm.subrange(offset, 16, false).unwrap();
        let mut expected = [0xa5; 32];
        gm.write_at(0, &expected).unwrap();

        let result = view.compare_exchange(gpa, u64::from_ne_bytes([0xa5; 8]), NEW);
        // Test expectations depend on host support for unaligned atomic accesses.
        // xtask-fmt allow-target-arch cpu-intrinsic
        if !cfg!(target_arch = "x86_64") && !(offset + gpa).is_multiple_of(8) {
            let error = result.unwrap_err();
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<trycopy::MemoryError>()
                .unwrap();
            assert_eq!(
                source.kind(),
                trycopy::MemoryErrorKind::UnalignedAtomicAccess
            );
        } else {
            assert_eq!(result.unwrap(), Ok(NEW));
            let start = (offset + gpa) as usize;
            expected[start..start + 8].copy_from_slice(&NEW.to_ne_bytes());
        }

        let mut actual = [0; 32];
        gm.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

// Regression: Computing offset + len - 1 underflowed for an empty access.
// Test: Read and write zero-sized values at zero with every bitmap page denied.
// Expected: Both succeed without touching a page or computing a last-page
//       index.
#[cfg(feature = "bitmap")]
#[test]
fn test_zero_length_access_at_offset_zero() {
    let len = PAGE_SIZE * 4;
    let mapping = SparseMapping::new(len).unwrap();
    mapping.alloc(0, len).unwrap();
    let bitmap = vec![0b0000]; // every page marked inaccessible
    let mapping = Arc::new(GuestMemoryMapping {
        mapping,
        bitmap: Some(bitmap),
    });
    let gm = GuestMemory::new("test", mapping);

    gm.read_plain::<()>(0).unwrap();
    gm.write_plain::<()>(0, &()).unwrap();
}

// Test: Fill an allocated heap and borrow or recover it while clones exist.
// Expected: Bytes survive; mutable access and recovery require unique
//       ownership.
#[test]
fn test_allocated() {
    let mut gm = GuestMemory::allocate(0x10000);
    let pattern = [0x42; 0x10000];
    gm.write_at(0, &pattern).unwrap();
    assert_eq!(gm.inner_buf_mut().unwrap(), &pattern);
    gm.inner_buf().unwrap();
    let gm2 = gm.clone();
    assert!(gm.inner_buf_mut().is_none());
    gm.inner_buf().unwrap();
    let mut gm = gm.into_inner_buf().unwrap_err();
    drop(gm2);
    assert_eq!(gm.inner_buf_mut().unwrap(), &pattern);
    gm.into_inner_buf().unwrap();
}

/// A backing whose locking support can be toggled, used to exercise
/// [`GuestMemory::supports_kernel_lock`] aggregation. Backed by a real mapping
/// so it can participate in single- and multi-region construction.
struct ToggleLockMapping {
    mapping: SparseMapping,
    lockable: bool,
    locks: AtomicUsize,
    unlocks: AtomicUsize,
    exposures: AtomicUsize,
}

impl ToggleLockMapping {
    fn new(size: usize, lockable: bool) -> Self {
        let mapping = SparseMapping::new(size).unwrap();
        mapping.alloc(0, size).unwrap();
        Self {
            mapping,
            lockable,
            locks: AtomicUsize::new(0),
            unlocks: AtomicUsize::new(0),
            exposures: AtomicUsize::new(0),
        }
    }
}

// SAFETY: the mapping is valid for the full range reported by `max_address`.
unsafe impl GuestMemoryAccess for ToggleLockMapping {
    fn mapping(&self) -> Option<NonNull<u8>> {
        NonNull::new(self.mapping.as_ptr().cast())
    }

    fn max_address(&self) -> u64 {
        self.mapping.len() as u64
    }

    fn supports_kernel_lock(&self) -> bool {
        self.lockable
    }

    fn supports_user_lock(&self) -> bool {
        self.lockable
    }

    fn lock_kernel_gpns(&self, _gpns: &[u64]) -> Result<bool, GuestMemoryBackingError> {
        self.locks.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    fn unlock_gpns(&self, _gpns: &[u64]) {
        self.unlocks.fetch_add(1, Ordering::Relaxed);
    }

    fn expose_va(&self, _address: u64, _len: u64) -> Result<(), GuestMemoryBackingError> {
        self.exposures.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

// Test: Lock the same backing for user and kernel access, then drop the guards.
// Expected: Only kernel locks expose memory; every successful lock is released.
#[test]
fn usermode_locks_do_not_prepare_kernel_io() {
    let backing = Arc::new(ToggleLockMapping::new(PAGE_SIZE, true));
    let gm = GuestMemory::new("lock-access", backing.clone());
    let pages = gm.lock_user_gpns(AccessType::Write, &[0]).unwrap();
    assert_eq!(backing.exposures.load(Ordering::Relaxed), 0);
    assert_eq!(backing.locks.load(Ordering::Relaxed), 1);
    drop(pages);
    assert_eq!(backing.unlocks.load(Ordering::Relaxed), 1);

    let pages = gm.lock_kernel_gpns(AccessType::Write, &[0]).unwrap();
    assert_eq!(backing.exposures.load(Ordering::Relaxed), 1);
    assert_eq!(backing.locks.load(Ordering::Relaxed), 2);
    drop(pages);
    assert_eq!(backing.unlocks.load(Ordering::Relaxed), 2);
}

// Test: Request kernel locks through supported and unsupported Arc backings.
// Expected: Arc forwards required hooks and never locks an unsupported backing.
#[test]
fn test_arc_lock_forwarding() {
    let backing = Arc::new(ToggleLockMapping::new(PAGE_SIZE, true));
    let gm = GuestMemory::new("arc-lock", backing.clone());
    let pages = gm.lock_kernel_gpns(AccessType::Read, &[0]).unwrap();
    assert_eq!(backing.locks.load(Ordering::Relaxed), 1);
    assert_eq!(backing.exposures.load(Ordering::Relaxed), 1);
    drop(pages);
    assert_eq!(backing.unlocks.load(Ordering::Relaxed), 1);
    let backing = Arc::new(ToggleLockMapping::new(PAGE_SIZE, false));
    let gm = GuestMemory::new("arc-no-lock", backing.clone());
    assert!(!gm.supports_kernel_lock());
    assert!(gm.lock_kernel_gpns(AccessType::Read, &[0]).is_err());
    assert_eq!(backing.locks.load(Ordering::Relaxed), 0);
}

// Test: Query heap and homogeneous or mixed-region locking support.
// Expected: Present backings must all support locking; unsupported locks fail.
#[test]
fn test_supports_kernel_lock() {
    // A mapping-backed backing supports locking by default.
    let gm = GuestMemory::allocate(0x10000);
    assert!(gm.supports_kernel_lock());

    // A backing that reports no locking support (e.g. on-demand
    // translation behind an emulated IOMMU) does not support locking, and
    // `supports_kernel_lock` is authoritative: locking fails without touching
    // the backing's `lock_kernel_gpns`.
    let gm = GuestMemory::new("nolock", ToggleLockMapping::new(SIZE_1MB, false));
    assert!(!gm.supports_kernel_lock());
    assert!(gm.lock_user_gpns(AccessType::Write, &[0]).is_err());

    // Multi-region: locking is supported only when every present backing
    // supports it.
    let gm = GuestMemory::new_multi_region(
        "multi-lockable",
        SIZE_1MB as u64,
        vec![
            Some(ToggleLockMapping::new(SIZE_1MB / 2, true)),
            Some(ToggleLockMapping::new(SIZE_1MB / 2, true)),
        ],
    )
    .unwrap();
    assert!(gm.supports_kernel_lock());

    let gm = GuestMemory::new_multi_region(
        "multi-mixed",
        SIZE_1MB as u64,
        vec![
            Some(ToggleLockMapping::new(SIZE_1MB / 2, true)),
            Some(ToggleLockMapping::new(SIZE_1MB / 2, false)),
        ],
    )
    .unwrap();
    assert!(!gm.supports_kernel_lock());
}

// Test: Copy a range with out-of-order pages and partial head and tail pages.
// Expected: The declared page order determines the bytes; guards are untouched.
#[test]
fn scattered_range_preserves_page_order_and_guards() {
    let memory = GuestMemory::allocate(PAGE_SIZE * 4);
    memory.fill_at(0, 0xa5, PAGE_SIZE * 4).unwrap();
    let pages = [2, 0, 3];
    let range = crate::PagedRange::new(PAGE_SIZE - 3, PAGE_SIZE + 8, &pages).unwrap();
    let payload: Vec<_> = (0..PAGE_SIZE + 8).map(|index| index as u8).collect();
    memory.write_range(&range, &payload).unwrap();
    let mut expected = vec![0xa5; PAGE_SIZE * 4];
    expected[PAGE_SIZE * 3 - 3..PAGE_SIZE * 3].copy_from_slice(&payload[..3]);
    expected[..PAGE_SIZE].copy_from_slice(&payload[3..PAGE_SIZE + 3]);
    expected[PAGE_SIZE * 3..PAGE_SIZE * 3 + 5].copy_from_slice(&payload[PAGE_SIZE + 3..]);
    let mut actual = vec![0; expected.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let mut gathered = vec![0; payload.len()];
    memory.read_range(&range, &mut gathered).unwrap();
    assert_eq!(gathered, payload);
    for value in [0x6b, 0] {
        if value == 0 {
            memory.zero_range(&range).unwrap();
        } else {
            memory.fill_range(&range, value).unwrap();
        }
        expected[PAGE_SIZE * 3 - 3..PAGE_SIZE * 3].fill(value);
        expected[..PAGE_SIZE].fill(value);
        expected[PAGE_SIZE * 3..PAGE_SIZE * 3 + 5].fill(value);
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

// Test: Copy atomic buffers through scattered and contiguous memory APIs.
// Expected: Atomic copies preserve page order and leave surrounding bytes
//       intact.
#[test]
fn atomic_copies_preserve_scattered_order_and_guards() {
    use std::sync::atomic::AtomicU8;
    let memory = GuestMemory::allocate(PAGE_SIZE * 3);
    memory.fill_at(0, 0xa5, PAGE_SIZE * 3).unwrap();
    let pages = [2, 0];
    let range = crate::PagedRange::new(PAGE_SIZE - 2, 5, &pages).unwrap();
    let source = [0xcc, 1, 2, 3, 4, 5, 0xdd].map(AtomicU8::new);
    memory
        .write_range_from_atomic(&range, &source[1..6])
        .unwrap();
    let destination = [0xa5; 7].map(AtomicU8::new);
    memory
        .read_range_to_atomic(&range, &destination[1..6])
        .unwrap();
    assert_eq!(
        destination.map(|byte| byte.into_inner()),
        [0xa5, 1, 2, 3, 4, 5, 0xa5]
    );
    let mut expected = vec![0xa5; PAGE_SIZE * 3];
    expected[PAGE_SIZE * 3 - 2..].copy_from_slice(&[1, 2]);
    expected[..3].copy_from_slice(&[3, 4, 5]);
    let mut actual = vec![0; expected.len()];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    memory
        .write_from_atomic(PAGE_SIZE64 - 2, &source[1..6])
        .unwrap();
    let destination = [0xa5; 7].map(AtomicU8::new);
    memory
        .read_to_atomic(PAGE_SIZE64 - 2, &destination[1..6])
        .unwrap();
    assert_eq!(
        destination.map(|byte| byte.into_inner()),
        [0xa5, 1, 2, 3, 4, 5, 0xa5]
    );
    assert_eq!(
        memory.read_plain::<[u8; 7]>(PAGE_SIZE64 - 3).unwrap(),
        [0xa5, 1, 2, 3, 4, 5, 0xa5]
    );
    expected[PAGE_SIZE - 2..PAGE_SIZE + 3].copy_from_slice(&[1, 2, 3, 4, 5]);
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        source.map(|byte| byte.into_inner()),
        [0xcc, 1, 2, 3, 4, 5, 0xdd]
    );
}

// Test: Borrow and recover heap memory while clones exist and after they drop.
// Expected: Mutable ownership requires uniqueness, and recovered data survives.
#[test]
fn allocated_memory_respects_shared_ownership() {
    let mut memory = GuestMemory::allocate(1);
    memory.inner_buf_mut().unwrap()[0] = 0x5a;
    assert!(memory.inner_buf().unwrap().len() >= PAGE_SIZE);
    let clone = memory.clone();
    assert!(memory.inner_buf_mut().is_none());
    let mut memory = memory.into_inner_buf().unwrap_err();
    assert_eq!(clone.read_plain::<u8>(0).unwrap(), 0x5a);
    drop(clone);
    memory.inner_buf_mut().unwrap()[1] = 0x6b;
    let heap = memory.into_inner_buf().unwrap();
    assert_eq!(heap[0].load(Ordering::Relaxed), 0x5a);
    assert_eq!(heap[1].load(Ordering::Relaxed), 0x6b);
    let mut external = GuestMemory::new("external", heap);
    assert!(external.inner_buf().is_none());
    assert!(external.inner_buf_mut().is_none());
    let external = external.into_inner_buf().unwrap_err();
    assert_eq!(
        external.read_plain::<u16>(0).unwrap(),
        u16::from_ne_bytes([0x5a, 0x6b])
    );
}

// Test: Write through nested views and attempt accesses outside their bounds.
// Expected: Offsets compose, out-of-bounds operations fail, and guards survive.
#[test]
fn nested_subranges_constrain_visible_memory() {
    let memory = GuestMemory::allocate(PAGE_SIZE * 3);
    memory.fill_at(0, 0xa5, PAGE_SIZE * 3).unwrap();
    let outer = memory
        .subrange(PAGE_SIZE64 - 1, PAGE_SIZE64 + 2, false)
        .unwrap();
    let inner = outer.lockable_subrange(1, PAGE_SIZE64).unwrap();
    inner.fill_at(0, 0x7b, PAGE_SIZE).unwrap();
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 - 1).unwrap(), 0xa5);
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64).unwrap(), 0x7b);
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 * 2 - 1).unwrap(), 0x7b);
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 * 2).unwrap(), 0xa5);
    for address in [PAGE_SIZE64, u64::MAX] {
        assert!(inner.read_plain::<u8>(address).is_err());
        assert!(inner.write_plain(address, &0u8).is_err());
        assert!(inner.fill_at(address, 0, 1).is_err());
    }
    assert!(inner.subrange(PAGE_SIZE64, 1, false).is_err());
    assert!(inner.subrange(u64::MAX, 2, false).is_err());
}

// Test: Submit layouts whose granularity, backing size, or address space is
//       invalid.
// Expected: Each invalid layout returns its corresponding error category.
#[test]
fn invalid_multi_region_layouts_return_errors() {
    use crate::AlignedHeapMemory;
    use crate::MultiRegionError;
    let empty = || Vec::<Option<AlignedHeapMemory>>::new();
    assert!(matches!(
        GuestMemory::new_multi_region("layout", 3, empty()),
        Err(MultiRegionError::NotPowerOfTwo(3))
    ));
    assert!(matches!(
        GuestMemory::new_multi_region("layout", 1, empty()),
        Err(MultiRegionError::RegionSizeTooSmall(1))
    ));
    assert!(matches!(
        GuestMemory::new_multi_region(
            "layout",
            PAGE_SIZE64,
            vec![Some(AlignedHeapMemory::new(PAGE_SIZE * 2))]
        ),
        Err(MultiRegionError::BackingTooLarge { .. })
    ));
    assert!(matches!(
        GuestMemory::new_multi_region(
            "layout",
            1 << 62,
            vec![None::<AlignedHeapMemory>, None, None]
        ),
        Err(MultiRegionError::TooManyRegions { .. })
    ));
}

fn check_stream_cursors(mut reader: impl crate::MemoryRead, mut writer: impl crate::MemoryWrite) {
    assert_eq!(writer.len(), 12);
    assert!(matches!(
        writer.write(&[0; 13]),
        Err(crate::AccessError::OutOfRange(12, 13))
    ));
    assert_eq!(writer.len(), 12);
    writer.write(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(writer.len(), 4);
    assert!(matches!(
        writer.fill(0, 5),
        Err(crate::AccessError::OutOfRange(4, 5))
    ));
    assert_eq!(writer.len(), 4);
    writer.fill(0x6b, 4).unwrap();
    assert_eq!(writer.len(), 0);
    writer.write(&[]).unwrap();
    writer.fill(0, 0).unwrap();
    assert!(matches!(
        reader.read(&mut [0; 13]),
        Err(crate::AccessError::OutOfRange(12, 13))
    ));
    assert!(matches!(
        reader.skip(13),
        Err(crate::AccessError::OutOfRange(12, 13))
    ));
    assert_eq!(reader.len(), 12);
    let mut prefix = [0; 4];
    reader.read(&mut prefix).unwrap();
    assert_eq!(prefix, [1, 2, 3, 4]);
    reader.skip(2).unwrap();
    assert_eq!(reader.len(), 6);
    let mut suffix = [0; 6];
    reader.read(&mut suffix).unwrap();
    assert_eq!(suffix, [7, 8, 0x6b, 0x6b, 0x6b, 0x6b]);
    assert_eq!(reader.len(), 0);
    reader.read(&mut []).unwrap();
    reader.skip(0).unwrap();
}

// Test: Stream data across a scattered page boundary and reject overlong
//       accesses.
// Expected: Only successful operations advance the cursor and data stays
//       ordered.
#[test]
fn single_range_streams_preserve_cursor_and_data() {
    use crate::ranges::GuestMemoryView;
    let memory = GuestMemory::allocate(PAGE_SIZE * 3);
    memory.fill_at(0, 0xa5, PAGE_SIZE * 3).unwrap();
    let pages = [0, 2];
    let range = crate::PagedRange::new(PAGE_SIZE - 3, 12, &pages).unwrap();
    check_stream_cursors(range.reader(&memory), range.writer(&memory));
    assert_eq!(
        memory.read_plain::<[u8; 3]>(PAGE_SIZE64 - 3).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(
        memory.read_plain::<[u8; 9]>(PAGE_SIZE64 * 2).unwrap(),
        [4, 5, 6, 7, 8, 0x6b, 0x6b, 0x6b, 0x6b]
    );
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 - 4).unwrap(), 0xa5);
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 * 2 + 9).unwrap(), 0xa5);
}

// Test: Stream through several disjoint ranges, including an empty middle
//       range.
// Expected: Range boundaries do not introduce bytes or reset stream cursors.
#[test]
fn multiple_range_streams_preserve_cursor_and_data() {
    use crate::MemoryRead;
    use crate::ranges::GuestMemoryView;
    let memory = GuestMemory::allocate(PAGE_SIZE * 3);
    let pages = [2, 0];
    let first = crate::PagedRange::new(1, 6, &pages[..1]).unwrap();
    let empty = crate::PagedRange::new(0, 0, &[]).unwrap();
    let second = crate::PagedRange::new(2, 6, &pages[1..]).unwrap();
    let ranges = || crate::ranges::PagedRanges::new([first, empty, second]);
    check_stream_cursors(ranges().reader(&memory), ranges().writer(&memory));
    assert_eq!(
        memory.read_plain::<[u8; 6]>(PAGE_SIZE64 * 2 + 1).unwrap(),
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        memory.read_plain::<[u8; 6]>(2).unwrap(),
        [7, 8, 0x6b, 0x6b, 0x6b, 0x6b]
    );
    let mut reader = ranges().reader(&memory);
    reader.skip(7).unwrap();
    assert_eq!(reader.into_inner().len(), 5);
    assert_eq!(ranges().writer(&memory).into_inner().len(), 12);
}

fn check_stream_memory_errors(
    mut reader: impl crate::MemoryRead,
    mut writer: impl crate::MemoryWrite,
) {
    assert!(matches!(
        reader.read(&mut [0; 1]),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(reader.len(), 4);
    assert!(matches!(
        writer.write(&[1]),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(writer.len(), 4);
    assert!(matches!(
        writer.fill(1, 1),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(writer.len(), 4);
}

// Test: Stream from and to an inaccessible guest range through both adapters.
// Expected: Errors retain their memory classification and do not consume bytes.
#[test]
fn range_stream_memory_errors_preserve_cursor() {
    use crate::ranges::GuestMemoryView;
    let memory = GuestMemory::empty();
    let range = crate::PagedRange::new(0, 4, &[0]).unwrap();
    check_stream_memory_errors(range.reader(&memory), range.writer(&memory));
    check_stream_memory_errors(
        crate::ranges::PagedRanges::new([range]).reader(&memory),
        crate::ranges::PagedRanges::new([range]).writer(&memory),
    );
}

struct FallbackMemory(Mutex<Vec<u8>>);

impl FallbackMemory {
    fn new() -> Self {
        Self(Mutex::new(vec![0xa5; PAGE_SIZE * 2]))
    }
}

// No mapping escapes, and the mutex serializes all access to the backing bytes.
unsafe impl GuestMemoryAccess for FallbackMemory {
    fn mapping(&self) -> Option<NonNull<u8>> {
        None
    }

    fn max_address(&self) -> u64 {
        (PAGE_SIZE * 2) as u64
    }

    unsafe fn read_fallback(
        &self,
        address: u64,
        dest: *mut u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        let bytes = self.0.lock();
        let source = &bytes[address as usize..address as usize + len];
        // SAFETY: the slice bounds the source; the caller provides a valid dest.
        unsafe { trycopy::try_copy(source.as_ptr(), dest, len) }
            .map_err(|error| GuestMemoryBackingError::other(address, error))
    }

    unsafe fn write_fallback(
        &self,
        address: u64,
        source: *const u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        let mut bytes = self.0.lock();
        let destination = &mut bytes[address as usize..address as usize + len];
        // SAFETY: the slice bounds dest; the caller provides a valid source.
        unsafe { trycopy::try_copy(source, destination.as_mut_ptr(), len) }
            .map_err(|error| GuestMemoryBackingError::other(address, error))
    }

    fn fill_fallback(
        &self,
        address: u64,
        value: u8,
        len: usize,
    ) -> Result<(), GuestMemoryBackingError> {
        self.0.lock()[address as usize..address as usize + len].fill(value);
        Ok(())
    }

    fn compare_exchange_fallback(
        &self,
        address: u64,
        current: &mut [u8],
        new: &[u8],
    ) -> Result<bool, GuestMemoryBackingError> {
        let mut bytes = self.0.lock();
        let destination = &mut bytes[address as usize..address as usize + new.len()];
        if destination == current {
            destination.copy_from_slice(new);
            Ok(true)
        } else {
            current.copy_from_slice(destination);
            Ok(false)
        }
    }

    fn base_iova(&self) -> Option<u64> {
        Some(0x100000)
    }
}

fn check_fallback_access(memory: &GuestMemory, address: u64) {
    memory.write_at(address, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    memory.fill_at(address + 1, 0x7b, 2).unwrap();
    assert_eq!(
        memory.read_plain::<[u8; 4]>(address).unwrap(),
        [1, 0x7b, 0x7b, 4]
    );
    memory.write_plain(address + 4, &0x44332211u32).unwrap();
    assert_eq!(
        memory.compare_exchange(address + 4, 0u32, 99).unwrap(),
        Err(0x44332211)
    );
    assert_eq!(memory.read_plain::<u32>(address + 4).unwrap(), 0x44332211);
    assert_eq!(
        memory
            .compare_exchange(address + 4, 0x44332211u32, 0x88776655)
            .unwrap(),
        Ok(0x88776655)
    );
    assert_eq!(memory.read_plain::<u32>(address + 4).unwrap(), 0x88776655);
    assert_eq!(memory.read_plain::<u8>(address - 1).unwrap(), 0xa5);
    assert_eq!(memory.read_plain::<u8>(address + 8).unwrap(), 0xa5);
}

// Test: Perform data and atomic operations on an unmapped backing and nested
//       view.
// Expected: Fallback operations preserve values, offsets, guards, and DMA
//       addresses.
#[test]
fn fallback_access_survives_nested_views() {
    let memory = GuestMemory::new("fallback", Arc::new(FallbackMemory::new()));
    assert!(memory.full_mapping().is_none());
    assert_eq!(memory.iova(8), Some(0x100008));
    assert_eq!(memory.iova(PAGE_SIZE64 * 2), None);
    check_fallback_access(&memory, 8);
    let view = memory
        .subrange(PAGE_SIZE64 - 4, PAGE_SIZE64, false)
        .unwrap();
    let nested = view.subrange(4, PAGE_SIZE64 - 4, false).unwrap();
    assert_eq!(nested.iova(8), Some(0x100008 + PAGE_SIZE64));
    check_fallback_access(&nested, 8);
    assert_eq!(
        memory.read_plain::<u32>(PAGE_SIZE64 + 12).unwrap(),
        0x88776655
    );
}

// Test: Access the second of two independent unmapped guest-memory regions.
// Expected: All fallback operations target that region without modifying the
//       first.
#[test]
fn multi_region_fallback_access_is_isolated() {
    let first = Arc::new(FallbackMemory::new());
    let second = Arc::new(FallbackMemory::new());
    let memory = GuestMemory::new_multi_region(
        "fallback-regions",
        PAGE_SIZE64 * 4,
        vec![Some(first.clone()), Some(second)],
    )
    .unwrap();
    check_fallback_access(&memory, PAGE_SIZE64 * 4 + 8);
    let view = memory
        .subrange(PAGE_SIZE64 * 4, PAGE_SIZE64, false)
        .unwrap();
    check_fallback_access(&view, 32);
    assert_eq!(view.iova(32), Some(0x100020));
    assert!(first.0.lock().iter().all(|&byte| byte == 0xa5));
    assert!(memory.read_plain::<u8>(PAGE_SIZE64 * 3).is_err());
}

#[derive(Default)]
struct LockedSegments<'a>(Vec<&'a [std::sync::atomic::AtomicU8]>);

impl<'a> crate::LockedRange<'a> for LockedSegments<'a> {
    fn push_sub_range(&mut self, segment: &'a [std::sync::atomic::AtomicU8]) {
        self.0.push(segment);
    }
}

// Test: Lock a partial scattered range and write through its exposed segments.
// Expected: Data follows page order and dropping the range releases the same
//       pages.
#[test]
fn locked_range_exposes_selected_bytes_and_releases_pages() {
    let backing = Arc::new(LockMapping {
        lockable: true,
        unlock_required: true,
        ..LockMapping::new(PAGE_SIZE * 4)
    });
    let memory = GuestMemory::new("locked-range", backing.clone());
    memory.fill_at(0, 0xa5, PAGE_SIZE * 4).unwrap();
    let pages = [2, 0, 1];
    let range = crate::PagedRange::new(PAGE_SIZE - 2, PAGE_SIZE + 4, &pages).unwrap();
    {
        let mut locked = memory
            .lock_range(AccessType::Write, range, LockedSegments::default())
            .unwrap();
        assert_eq!(
            backing.take_operations(),
            [LockOperation::Lock(pages.to_vec())]
        );
        let actual: Vec<_> = locked
            .get()
            .0
            .iter()
            .flat_map(|segment| segment.iter())
            .map(|byte| byte.load(Ordering::Relaxed))
            .collect();
        assert_eq!(actual, vec![0xa5; PAGE_SIZE + 4]);
        for byte in locked.get_mut().0.iter().flat_map(|segment| segment.iter()) {
            byte.store(0x6b, Ordering::Relaxed);
        }
    }
    assert_eq!(
        backing.take_operations(),
        [LockOperation::Unlock(pages.to_vec())]
    );
    let mut actual = vec![0; PAGE_SIZE * 4];
    memory.read_at(0, &mut actual).unwrap();
    let mut expected = vec![0xa5; PAGE_SIZE * 4];
    expected[..PAGE_SIZE + 2].fill(0x6b);
    expected[PAGE_SIZE * 3 - 2..PAGE_SIZE * 3].fill(0x6b);
    assert_eq!(actual, expected);
}

// Test: Probe mapped, absent, out-of-bounds, and overflowing guest addresses.
// Expected: Invalid probes fail and neither successful nor failed probes alter
//       data.
#[test]
fn probes_validate_access_without_changing_data() {
    let memory = GuestMemory::new("probe", create_test_mapping());
    memory.fill_at(0, 0x7b, PAGE_SIZE).unwrap();
    memory.probe_gpns(&[0, 512, 1023]).unwrap();
    memory.probe_gpns(&[]).unwrap();
    memory.probe_gpa_readable(0).unwrap();
    memory.probe_gpa_writable(0).unwrap();
    for gpn in [256, 1024, u64::MAX] {
        assert!(memory.probe_gpns(&[gpn]).is_err());
    }
    for address in [SIZE_1MB as u64, SIZE_1MB as u64 * 4, u64::MAX] {
        assert!(memory.probe_gpa_readable(address).is_err());
        assert!(memory.probe_gpa_writable(address).is_err());
    }
    let mut actual = vec![0; PAGE_SIZE];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, vec![0x7b; PAGE_SIZE]);
}

// Test: Lock repeated, reordered pages and retain them after dropping the view.
// Expected: Handles retain data, repeated pages alias, and each lock is
//       released.
#[test]
fn locked_page_handles_preserve_order_aliases_and_lifetime() {
    let backing = Arc::new(LockMapping {
        lockable: true,
        unlock_required: true,
        ..LockMapping::new(PAGE_SIZE * 3)
    });
    let memory = GuestMemory::new("page-handles", backing.clone());
    memory.fill_at(0, 0x1a, PAGE_SIZE).unwrap();
    memory.fill_at(PAGE_SIZE64, 0x2a, PAGE_SIZE).unwrap();
    memory.fill_at(PAGE_SIZE64 * 2, 0x3a, PAGE_SIZE).unwrap();
    let kernel = memory
        .lock_kernel_gpns(AccessType::Write, &[2, 0, 2])
        .unwrap();
    let user = memory.lock_user_gpns(AccessType::Read, &[1]).unwrap();
    assert_eq!(
        backing.take_operations(),
        [
            LockOperation::Lock(vec![2, 0, 2]),
            LockOperation::Lock(vec![1])
        ]
    );
    drop(memory);
    let handle = &kernel;
    let pages: &[&crate::Page] = handle.as_ref();
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[0][0].load(Ordering::Relaxed), 0x3a);
    assert_eq!(pages[1][0].load(Ordering::Relaxed), 0x1a);
    pages[0][0].store(0x6b, Ordering::Relaxed);
    assert_eq!(pages[2][0].load(Ordering::Relaxed), 0x6b);
    assert_eq!(user.pages().len(), 1);
    assert_eq!(user.pages()[0][0].load(Ordering::Relaxed), 0x2a);
    drop(kernel);
    drop(user);
    assert_eq!(
        backing.take_operations(),
        [
            LockOperation::Unlock(vec![2, 0, 2]),
            LockOperation::Unlock(vec![1])
        ]
    );
}

// Test: Allocate a non-page-sized heap and edit it through its byte and atomic
//       APIs.
// Expected: Allocation rounds up, starts zeroed, and every access sees the
//       same bytes.
#[test]
fn heap_memory_byte_and_atomic_views_share_aligned_storage() {
    use std::sync::atomic::AtomicU8;
    let mut heap = crate::AlignedHeapMemory::new(PAGE_SIZE + 1);
    assert_eq!(heap.len(), PAGE_SIZE * 2);
    assert!(heap.as_bytes().iter().all(|&byte| byte == 0));
    heap.as_mut_bytes()[PAGE_SIZE] = 0x6b;
    let atomic: &mut [AtomicU8] = heap.as_mut();
    atomic[0].store(0x5a, Ordering::Relaxed);
    heap[1] = AtomicU8::new(0x7c);
    let atomic: &[AtomicU8] = heap.as_ref();
    assert_eq!(atomic[PAGE_SIZE].load(Ordering::Relaxed), 0x6b);
    let memory = GuestMemory::new("heap-views", heap);
    let (pointer, length) = memory.full_mapping().unwrap();
    assert_eq!(pointer as usize % PAGE_SIZE, 0);
    assert_eq!(length, PAGE_SIZE * 2);
    assert_eq!(memory.read_plain::<[u8; 2]>(0).unwrap(), [0x5a, 0x7c]);
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64).unwrap(), 0x6b);
}

// Test: Read and write the same shared allocation through guest and host views.
// Expected: Both views observe each other's writes and report the full mapping.
#[test]
fn shared_allocation_observes_bidirectional_writes() {
    let shared = Arc::new(sparse_mmap::alloc::SharedMem::new(
        sparse_mmap::alloc::Allocation::new(PAGE_SIZE).unwrap(),
    ));
    shared[0].store(0x5a, Ordering::Relaxed);
    let memory = GuestMemory::new("shared-allocation", shared.clone());
    assert_eq!(memory.full_mapping().unwrap().1, PAGE_SIZE);
    assert_eq!(memory.read_plain::<u8>(0).unwrap(), 0x5a);
    memory.write_plain(1, &0x6bu8).unwrap();
    assert_eq!(shared[1].load(Ordering::Relaxed), 0x6b);
}

// Test: Nest aligned views across permitted and denied bitmap pages.
// Expected: Views retain page permissions and do not expose a bypassing
//       mapping.
#[cfg(feature = "bitmap")]
#[test]
fn bitmap_permissions_survive_aligned_nested_views() {
    let mapping = SparseMapping::new(PAGE_SIZE * 4).unwrap();
    mapping.alloc(0, PAGE_SIZE * 4).unwrap();
    let memory = GuestMemory::new(
        "bitmap-views",
        GuestMemoryMapping {
            mapping,
            bitmap: Some(vec![0b0101]),
        },
    );
    assert!(memory.full_mapping().is_none());
    let view = memory
        .subrange(PAGE_SIZE64, PAGE_SIZE64 * 2, false)
        .unwrap();
    assert!(view.full_mapping().is_none());
    for address in [0, PAGE_SIZE64 - 1] {
        assert!(memory.read_plain::<u8>(PAGE_SIZE64 + address).is_err());
        assert!(view.read_plain::<u8>(address).is_err());
        assert!(view.write_plain(address, &0x5au8).is_err());
    }
    view.write_plain(PAGE_SIZE64, &0x6bu8).unwrap();
    assert_eq!(memory.read_plain::<u8>(PAGE_SIZE64 * 2).unwrap(), 0x6b);
    let nested = view.subrange(PAGE_SIZE64, PAGE_SIZE64, false).unwrap();
    nested.fill_at(0, 0x7c, PAGE_SIZE).unwrap();
    let mut actual = vec![0; PAGE_SIZE];
    memory.read_at(PAGE_SIZE64 * 2, &mut actual).unwrap();
    assert_eq!(actual, vec![0x7c; PAGE_SIZE]);
    assert!(nested.read_plain::<u8>(PAGE_SIZE64).is_err());
}

// IGNORED: A known product bug drops the byte offset in unaligned bitmap views.
//       Keep this regression ignored until a separate production fix.
//
// Test: Access a denied parent page through an unaligned bitmap-backed view.
// Expected: The view rejects the same byte as its parent (known product bug).
#[cfg(feature = "bitmap")]
#[test]
#[ignore = "known product bug: unaligned subrange bitmap checks lose the byte offset"]
fn known_bug_unaligned_bitmap_view_must_not_allow_denied_parent_byte() {
    let mapping = SparseMapping::new(PAGE_SIZE * 4).unwrap();
    mapping.alloc(0, PAGE_SIZE * 4).unwrap();
    let memory = GuestMemory::new(
        "bitmap-unaligned",
        GuestMemoryMapping {
            mapping,
            bitmap: Some(vec![0b0101]),
        },
    );
    assert!(memory.read_plain::<u8>(PAGE_SIZE64 * 3).is_err());
    let view = memory
        .subrange(PAGE_SIZE64 + 1, PAGE_SIZE64 * 2, false)
        .unwrap();
    assert!(view.read_plain::<u8>(PAGE_SIZE64 * 2 - 1).is_err());
}

mod reference_tests;
