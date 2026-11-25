// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: Implementing the DMA callback as a recorder; no supplied VA pointer
// is dereferenced, retained, or used to program hardware.
#![expect(unsafe_code)]

use super::PAGE;
use super::backing;
use super::manager;
use super::read_byte;
use crate::DmaMapRequest;
use crate::DmaTarget;
use crate::GuestMemoryBuilder;
use crate::MappingType;
use crate::RamBackingRequest;
use crate::RamVisibility;
use guestmem::MemoryMapper;
use memory_range::MemoryRange;
use pal_async::async_test;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Map(MemoryRange, u64, bool, MappingType, bool),
    Unmap(MemoryRange),
}

#[derive(Default)]
struct Target {
    events: Mutex<Vec<Event>>,
    fail_device_map: AtomicBool,
    fail_unmap: AtomicBool,
}

impl DmaTarget for Target {
    unsafe fn map_dma(&self, request: DmaMapRequest<'_>) -> anyhow::Result<()> {
        self.events.lock().push(Event::Map(
            request.range,
            request.file_offset,
            request.writable,
            request.mapping_type,
            request.mappable.is_some(),
        ));
        anyhow::ensure!(
            request.mapping_type != MappingType::Device
                || !self.fail_device_map.load(Ordering::SeqCst),
            "injected device DMA mapping failure"
        );
        Ok(())
    }

    fn unmap_dma(&self, range: MemoryRange) -> anyhow::Result<()> {
        self.events.lock().push(Event::Unmap(range));
        anyhow::ensure!(
            !self.fail_unmap.load(Ordering::SeqCst),
            "injected DMA unmap failure"
        );
        Ok(())
    }
}

// Test: Register a DMA consumer through the public client, fail device-memory
//       DMA unmapping, and then unregister the consumer.
// Expected: RAM is replayed with backing metadata, unmap failures do not prevent
//       CPU-side teardown, and unregister removes the remaining mappings.
#[async_test]
async fn public_dma_client_replays_ram_and_cleans_up_mappings() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 6 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let client = manager.dma_mapper_client();
    let target = Arc::new(Target::default());
    let handle = client.add_dma_mapper(target.clone(), true).await.unwrap();
    assert_eq!(
        *target.events.lock(),
        [Event::Map(
            MemoryRange::new(0..PAGE),
            0,
            true,
            MappingType::Ram,
            true
        ),]
    );
    target.events.lock().clear();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(PAGE as usize, "dma-device".into())
        .unwrap();
    let backing = backing(&vec![0x6d; 2 * PAGE as usize]);
    region.map(0, &backing, PAGE, PAGE as usize, true).unwrap();
    control.map_to_guest(3 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 3 * PAGE), 0x6d);
    assert!(target.events.lock().contains(&Event::Map(
        MemoryRange::new(3 * PAGE..4 * PAGE),
        PAGE,
        true,
        MappingType::Device,
        true,
    )));
    target.fail_unmap.store(true, Ordering::SeqCst);
    control.unmap_from_guest();
    assert!(gm.read_at(3 * PAGE, &mut [0]).is_err());
    assert!(
        target
            .events
            .lock()
            .contains(&Event::Unmap(MemoryRange::new(3 * PAGE..4 * PAGE)))
    );
    target.fail_unmap.store(false, Ordering::SeqCst);
    target.events.lock().clear();
    drop(handle);
    // This roundtrip is also a barrier for the preceding unregister request.
    manager
        .ram_visibility_control()
        .set_ram_visibility(MemoryRange::new(0..PAGE), RamVisibility::ReadOnly)
        .await
        .unwrap();
    assert_eq!(
        *target.events.lock(),
        [Event::Unmap(MemoryRange::new(0..PAGE))]
    );
    assert_eq!(read_byte(&gm, 0), 0);
}

// IGNORED: MappingType::Device documents DMA mapping failures as non-fatal, but
// enabling a device region propagates the DMA error and rolls back CPU mapping.
//
// Test: Fail an optional peer-to-peer DMA mapping while enabling a device region.
// Expected: CPU access remains available despite the device DMA failure.
#[async_test]
#[ignore = "product regression: device DMA failure prevents CPU region mapping"]
async fn optional_device_dma_failure_does_not_prevent_cpu_mapping() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 4 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let target = Arc::new(Target::default());
    let _handle = manager
        .dma_mapper_client()
        .add_dma_mapper(target.clone(), true)
        .await
        .unwrap();
    target.fail_device_map.store(true, Ordering::SeqCst);
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(PAGE as usize, "optional-dma".into())
        .unwrap();
    let backing = backing(&vec![0x6d; PAGE as usize]);
    region.map(0, &backing, 0, PAGE as usize, true).unwrap();
    control.map_to_guest(2 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x6d);
    control.unmap_from_guest();
}

// Test: Register file-dependent and VA-only DMA consumers against private RAM.
// Expected: File-dependent registration fails without callbacks, while a VA-only
//       consumer receives a backing-less RAM mapping and can be unregistered.
#[async_test]
async fn private_ram_rejects_file_only_dma_consumers() {
    let manager = GuestMemoryBuilder::new()
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..PAGE)]).private_memory(true))
        .build(2 * PAGE)
        .await
        .unwrap();
    let client = manager.dma_mapper_client();
    let target = Arc::new(Target::default());
    assert!(client.add_dma_mapper(target.clone(), true).await.is_err());
    assert!(target.events.lock().is_empty());
    let handle = client.add_dma_mapper(target.clone(), false).await.unwrap();
    assert_eq!(
        *target.events.lock(),
        [Event::Map(
            MemoryRange::new(0..PAGE),
            0,
            true,
            MappingType::Ram,
            false
        ),]
    );
    drop(handle);
    manager
        .ram_visibility_control()
        .set_ram_visibility(MemoryRange::new(0..PAGE), RamVisibility::Unmapped)
        .await
        .unwrap();
    assert_eq!(
        target.events.lock().last(),
        Some(&Event::Unmap(MemoryRange::new(0..PAGE)))
    );
}
