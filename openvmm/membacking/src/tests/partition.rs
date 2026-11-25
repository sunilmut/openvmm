// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: Implementing the partition's unsafe mapping API as a recording
// fixture. The fixture never dereferences or retains the supplied VA pointer.
#![expect(unsafe_code)]

use super::PAGE;
use super::manager;
use crate::GuestMemoryBuilder;
use crate::PartitionAttachError;
use crate::RamBackingRequest;
use crate::RamVisibility;
use hvdef::Vtl;
use memory_range::MemoryRange;
use pal_async::async_test;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use test_with_tracing::test;
use virt::PartitionHostAccess;
use virt::PartitionMemoryMap;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Map(u64, usize, bool, bool),
    Unmap(u64, u64),
    Prefetch(u64, u64),
    Pin(u64, u64),
}

#[derive(Default)]
struct Partition {
    events: Mutex<Vec<Event>>,
    fail_map: AtomicBool,
    fail_pin: AtomicBool,
    fail_prefetch: AtomicBool,
}

impl PartitionMemoryMap for Partition {
    unsafe fn map_range(
        &self,
        _data: *mut u8,
        size: usize,
        addr: u64,
        writable: bool,
        exec: bool,
    ) -> anyhow::Result<()> {
        self.events
            .lock()
            .push(Event::Map(addr, size, writable, exec));
        anyhow::ensure!(
            !self.fail_map.load(Ordering::SeqCst),
            "injected map failure"
        );
        Ok(())
    }

    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        self.events.lock().push(Event::Unmap(addr, size));
        Ok(())
    }

    fn prefetch_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        self.events.lock().push(Event::Prefetch(addr, size));
        anyhow::ensure!(
            !self.fail_prefetch.load(Ordering::SeqCst),
            "injected prefetch failure"
        );
        Ok(())
    }

    fn pin_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        self.events.lock().push(Event::Pin(addr, size));
        anyhow::ensure!(
            !self.fail_pin.load(Ordering::SeqCst),
            "injected pin failure"
        );
        Ok(())
    }
}

// Test: Attach a pinned, prefetched VTL2 partition with a VTL0 alias map.
// Expected: Both guest address views map with correct permissions, prefetch and
//       pin requests; a RAM protection change reaches both views.
#[async_test]
async fn alias_partition_receives_mapping_policy_and_visibility_changes() {
    let mut manager = GuestMemoryBuilder::new()
        .vtl0_alias_map(Some(0x100000))
        .pin_mappings(true)
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..2 * PAGE)]).prefetch(true))
        .build(4 * PAGE)
        .await
        .unwrap();
    let target = Arc::new(Partition::default());
    let partition: Arc<dyn PartitionMemoryMap> = target.clone();
    manager
        .attach_partition(Vtl::Vtl2, &partition, None, None)
        .await
        .unwrap();
    assert_eq!(
        *target.events.lock(),
        [
            Event::Map(0x100000, 8192, true, true),
            Event::Prefetch(0x100000, 8192),
            Event::Pin(0x100000, 8192),
            Event::Map(0, 8192, true, true),
            Event::Prefetch(0, 8192),
            Event::Pin(0, 8192),
        ]
    );
    target.events.lock().clear();
    manager
        .ram_visibility_control()
        .set_ram_visibility(MemoryRange::new(0..2 * PAGE), RamVisibility::ReadOnly)
        .await
        .unwrap();
    let events = target.events.lock();
    assert!(events.contains(&Event::Unmap(0x100000, 8192)));
    assert!(events.contains(&Event::Unmap(0, 8192)));
    assert!(events.contains(&Event::Map(0x100000, 8192, false, true)));
    assert!(events.contains(&Event::Map(0, 8192, false, true)));
}

// Test: Inject partition mapping, pinning and prefetch failures during attachment.
// Expected: Map and pin failures are explicit and rolled back; prefetch failure
//       is advisory, and a later attachment succeeds after errors are cleared.
#[async_test]
async fn partition_failures_roll_back_and_allow_retry() {
    for pin_failure in [false, true] {
        let mut manager = GuestMemoryBuilder::new()
            .pin_mappings(true)
            .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..PAGE)]).prefetch(true))
            .build(2 * PAGE)
            .await
            .unwrap();
        let target = Arc::new(Partition::default());
        target.fail_map.store(!pin_failure, Ordering::SeqCst);
        target.fail_pin.store(pin_failure, Ordering::SeqCst);
        let partition: Arc<dyn PartitionMemoryMap> = target.clone();
        assert!(matches!(
            manager
                .attach_partition(Vtl::Vtl0, &partition, None, None)
                .await,
            Err(PartitionAttachError::PartitionMapper(_))
        ));
        assert!(target.events.lock().contains(&Event::Unmap(0, 2 * PAGE)));
        if pin_failure {
            assert!(target.events.lock().contains(&Event::Unmap(0, PAGE)));
        }
        target.fail_map.store(false, Ordering::SeqCst);
        target.fail_pin.store(false, Ordering::SeqCst);
        target.fail_prefetch.store(true, Ordering::SeqCst);
        target.events.lock().clear();
        manager
            .attach_partition(Vtl::Vtl0, &partition, None, None)
            .await
            .unwrap();
        assert_eq!(
            *target.events.lock(),
            [
                Event::Map(0, PAGE as usize, true, true),
                Event::Prefetch(0, PAGE),
                Event::Pin(0, PAGE),
            ]
        );
        drop(partition);
        drop(target);
        manager
            .ram_visibility_control()
            .set_ram_visibility(MemoryRange::new(0..PAGE), RamVisibility::Unmapped)
            .await
            .unwrap();
        manager
            .ram_visibility_control()
            .set_ram_visibility(MemoryRange::new(0..PAGE), RamVisibility::ReadWrite)
            .await
            .unwrap();
    }
}

#[derive(Default)]
struct DeniedHostAccess(Mutex<Vec<(u64, u64, bool)>>);

impl PartitionHostAccess for DeniedHostAccess {
    fn acquire_host_access(&self, addr: u64, size: u64, write: bool) -> anyhow::Result<()> {
        self.0.lock().push((addr, size, write));
        anyhow::bail!("injected host-access denial")
    }
}

// Test: Attach a host-access provider, access an unbacked guest page, then drop
//       the provider and repeat the access.
// Expected: Requests are page-aligned with correct permissions, denials reach
//       the caller, and dropping the provider does not leave a dangling callback.
#[async_test]
async fn host_access_denials_are_aligned_and_do_not_affect_valid_ram() {
    let mut manager = manager(vec![MemoryRange::new(0..PAGE)], 3 * PAGE).await;
    let target: Arc<dyn PartitionMemoryMap> = Arc::new(Partition::default());
    let access = Arc::new(DeniedHostAccess::default());
    manager
        .attach_partition(Vtl::Vtl0, &target, None, Some(access.clone()))
        .await
        .unwrap();
    let gm = manager.client().guest_memory().await.unwrap();
    for write in [false, true] {
        if write {
            assert!(gm.write_at(PAGE + 7, &[0x11]).is_err());
        } else {
            assert!(gm.read_at(PAGE + 7, &mut [0]).is_err());
        }
    }
    assert_eq!(*access.0.lock(), [(PAGE, PAGE, false), (PAGE, PAGE, true)]);
    gm.write_at(0, &[0x58]).unwrap();
    assert_eq!(super::read_byte(&gm, 0), 0x58);
    drop(access);
    assert!(gm.read_at(PAGE + 7, &mut [0]).is_err());
}

struct GrantHostAccess {
    control: Mutex<Box<dyn guestmem::MappableGuestMemory>>,
    requests: Mutex<Vec<(u64, u64, bool)>>,
}

impl PartitionHostAccess for GrantHostAccess {
    fn acquire_host_access(&self, addr: u64, size: u64, write: bool) -> anyhow::Result<()> {
        self.requests.lock().push((addr, size, write));
        self.control.lock().map_to_guest(addr, true)?;
        Ok(())
    }
}

// Test: Grant access to an initially absent page in the host-access callback by
//       installing its prepared file mapping through the public device mapper.
// Expected: The faulting read retries successfully and later reads/writes use
//       the granted mapping without requesting access again.
#[async_test]
async fn host_access_grant_retries_the_original_read() {
    use guestmem::MemoryMapper;

    let mut manager = manager(vec![MemoryRange::new(0..PAGE)], 3 * PAGE).await;
    let mapper = manager.device_memory_mapper();
    let (control, region) = mapper
        .new_region(PAGE as usize, "on-demand".into())
        .unwrap();
    let backing = super::backing(&vec![0x63; PAGE as usize]);
    region.map(0, &backing, 0, PAGE as usize, true).unwrap();
    let access = Arc::new(GrantHostAccess {
        control: Mutex::new(control),
        requests: Mutex::new(Vec::new()),
    });
    let partition: Arc<dyn PartitionMemoryMap> = Arc::new(Partition::default());
    manager
        .attach_partition(Vtl::Vtl0, &partition, None, Some(access.clone()))
        .await
        .unwrap();
    let gm = manager.client().guest_memory().await.unwrap();
    assert_eq!(super::read_byte(&gm, PAGE + 7), 0x63);
    gm.write_at(PAGE + 7, &[0x25]).unwrap();
    assert_eq!(super::read_byte(&gm, PAGE + 7), 0x25);
    assert_eq!(*access.requests.lock(), [(PAGE, PAGE, false)]);
}
