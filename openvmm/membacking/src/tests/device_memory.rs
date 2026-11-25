// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::PAGE;
use super::backing;
use super::manager;
use super::read_byte;
use crate::GuestMemoryBuilder;
use crate::RamBackingRequest;
use crate::RamVisibility;
use guestmem::MemoryMapper;
use memory_range::MemoryRange;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Map device-file pages before and after guest placement, then relocate,
//       protect, and remove the device region.
// Expected: File offsets and per-page permissions are honored, guest writes
//       persist across relocation, and old or removed GPAs are inaccessible.
#[async_test]
async fn device_mappings_preserve_offsets_permissions_and_relocation() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 16 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let data: Vec<_> = [0x11, 0x22, 0x33]
        .into_iter()
        .flat_map(|byte| std::iter::repeat_n(byte, PAGE as usize))
        .collect();
    let backing = backing(&data);
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(3 * PAGE as usize, "device".into())
        .unwrap();
    region.map(0, &backing, PAGE, PAGE as usize, true).unwrap();
    region
        .map(PAGE as usize, &backing, 0, PAGE as usize, false)
        .unwrap();
    control.map_to_guest(2 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x22);
    assert_eq!(read_byte(&gm, 3 * PAGE), 0x11);
    assert!(gm.write_at(3 * PAGE, &[0xff]).is_err());
    gm.write_at(2 * PAGE, &[0x77]).unwrap();
    assert!(gm.read_at(4 * PAGE, &mut [0]).is_err());
    region
        .map(2 * PAGE as usize, &backing, 2 * PAGE, PAGE as usize, true)
        .unwrap();
    assert_eq!(read_byte(&gm, 4 * PAGE), 0x33);

    control.map_to_guest(6 * PAGE, false).unwrap();
    assert!(gm.read_at(2 * PAGE, &mut [0]).is_err());
    assert_eq!(read_byte(&gm, 6 * PAGE), 0x77);
    assert_eq!(read_byte(&gm, 7 * PAGE), 0x11);
    assert_eq!(read_byte(&gm, 8 * PAGE), 0x33);
    assert!(gm.write_at(6 * PAGE, &[0xff]).is_err());
    control.unmap_from_guest();
    assert!(gm.read_at(6 * PAGE, &mut [0]).is_err());
    control.map_to_guest(9 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 9 * PAGE), 0x77);
    gm.write_at(9 * PAGE, &[0x88]).unwrap();
    let file = std::fs::File::from(std::os::fd::OwnedFd::from(backing));
    let mut byte = [0];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut byte, PAGE).unwrap();
    assert_eq!(byte, [0x88]);
    region.unmap(0, 3 * PAGE as usize).unwrap();
    for page in 9..12 {
        assert!(gm.read_at(page * PAGE, &mut [0]).is_err());
    }
    control.unmap_from_guest();
}

// Test: Overlay a legacy VGA RAM region with device memory and change RAM
//       visibility through the public controller.
// Expected: RAM has priority; unmapping reveals device data, read-only RAM
//       rejects writes, and restoring writable RAM preserves its own data.
#[async_test]
async fn legacy_ram_visibility_controls_device_overlay() {
    let manager = GuestMemoryBuilder::new()
        .x86_legacy_support(true)
        .add_backing(RamBackingRequest::new(vec![MemoryRange::new(0..0x100000)]))
        .build(0x100000)
        .await
        .unwrap();
    let gm = manager.client().guest_memory().await.unwrap();
    gm.write_at(0xa0000, &[0x37]).unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper.new_region(0x20000, "vga".into()).unwrap();
    let backing = backing(&vec![0x42; 0x20000]);
    region.map(0, &backing, 0, 0x20000, true).unwrap();
    control.map_to_guest(0xa0000, true).unwrap();
    assert_eq!(read_byte(&gm, 0xa0000), 0x37);
    let visibility = manager.ram_visibility_control();
    let vga = MemoryRange::new(0xa0000..0xc0000);
    visibility
        .set_ram_visibility(vga, RamVisibility::Unmapped)
        .await
        .unwrap();
    assert_eq!(read_byte(&gm, 0xa0000), 0x42);
    gm.write_at(0xa0000, &[0x55]).unwrap();
    visibility
        .set_ram_visibility(vga, RamVisibility::ReadOnly)
        .await
        .unwrap();
    assert_eq!(read_byte(&gm, 0xa0000), 0x37);
    assert!(gm.write_at(0xa0000, &[0xff]).is_err());
    visibility
        .set_ram_visibility(vga, RamVisibility::ReadWrite)
        .await
        .unwrap();
    assert_eq!(read_byte(&gm, 0xa0000), 0x37);
    gm.write_at(0xa0000, &[0x99]).unwrap();
    assert_eq!(read_byte(&gm, 0xa0000), 0x99);
    assert!(
        visibility
            .set_ram_visibility(MemoryRange::new(0xa0000..0xa1000), RamVisibility::Unmapped,)
            .await
            .is_err()
    );
    control.unmap_from_guest();
}

// Test: Submit unaligned and overflowing device offsets and guest addresses.
// Expected: InvalidInput is returned without creating an accessible guest
//       mapping; the same control can still map valid input afterward.
#[async_test]
async fn invalid_device_ranges_do_not_prevent_later_mapping() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 4 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(PAGE as usize, "invalid-ranges".into())
        .unwrap();
    let backing = backing(&vec![0x68; PAGE as usize]);
    for (offset, len) in [(1, PAGE as usize), (0, 1), (usize::MAX, PAGE as usize)] {
        let error = region.map(offset, &backing, 0, len, true).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            region.unmap(offset, len).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    for gpa in [1, u64::MAX - PAGE + 1] {
        assert_eq!(
            control.map_to_guest(gpa, true).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    region.map(0, &backing, 0, PAGE as usize, true).unwrap();
    control.map_to_guest(2 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x68);
    control.unmap_from_guest();
}

// Test: Place two same-priority device regions at partially overlapping GPAs.
// Expected: The partial overlap fails without disturbing the first
//       device, and the rejected device can be mapped to a different address.
#[async_test]
async fn partial_device_overlap_preserves_existing_mapping() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 6 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut first, first_region) = mapper
        .new_region(2 * PAGE as usize, "first".into())
        .unwrap();
    let (mut second, second_region) = mapper
        .new_region(2 * PAGE as usize, "second".into())
        .unwrap();
    let first_backing = backing(&vec![0x31; 2 * PAGE as usize]);
    let second_backing = backing(&vec![0xa7; 2 * PAGE as usize]);
    first_region
        .map(0, &first_backing, 0, 2 * PAGE as usize, true)
        .unwrap();
    second_region
        .map(0, &second_backing, 0, 2 * PAGE as usize, true)
        .unwrap();
    first.map_to_guest(2 * PAGE, true).unwrap();
    assert!(second.map_to_guest(3 * PAGE, true).is_err());
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x31);
    second.map_to_guest(4 * PAGE, true).unwrap();
    assert_eq!(read_byte(&gm, 4 * PAGE), 0xa7);
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x31);
    first.unmap_from_guest();
    second.unmap_from_guest();
}

// Test: Add a writable mapping from a read-only file descriptor to a live
//       device region, then retry with a writable descriptor for that backing.
// Expected: The OS mapping error is returned, no partial mapping is exposed,
//       and the successful retry uses the original file data.
#[async_test]
async fn failed_live_file_mapping_can_be_retried() {
    use std::os::fd::{AsFd, AsRawFd};

    let manager = manager(vec![MemoryRange::new(0..PAGE)], 4 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(PAGE as usize, "retry-file".into())
        .unwrap();
    control.map_to_guest(2 * PAGE, true).unwrap();
    let backing = backing(&vec![0x4e; PAGE as usize]);
    let read_only =
        std::fs::File::open(format!("/proc/self/fd/{}", backing.as_fd().as_raw_fd())).unwrap();
    let read_only = crate::Mappable::from(std::os::fd::OwnedFd::from(read_only));
    assert!(region.map(0, &read_only, 0, PAGE as usize, true).is_err());
    assert!(gm.read_at(2 * PAGE, &mut [0]).is_err());
    region.map(0, &backing, 0, PAGE as usize, true).unwrap();
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x4e);
    control.unmap_from_guest();
}

// Test: Enable a two-page device region whose second backing cannot be mapped
//       writable, then retry with read-only permissions.
// Expected: Failure removes the first page too; the retry exposes both original
//       pages read-only without leaving a partial writable mapping.
#[async_test]
async fn failed_region_enable_rolls_back_all_pages_and_allows_retry() {
    use std::os::fd::{AsFd, AsRawFd};

    let manager = manager(vec![MemoryRange::new(0..PAGE)], 6 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(2 * PAGE as usize, "enable-retry".into())
        .unwrap();
    let first = backing(&vec![0x28; PAGE as usize]);
    let second = backing(&vec![0x9c; PAGE as usize]);
    let read_only =
        std::fs::File::open(format!("/proc/self/fd/{}", second.as_fd().as_raw_fd())).unwrap();
    let read_only = crate::Mappable::from(std::os::fd::OwnedFd::from(read_only));
    region.map(0, &first, 0, PAGE as usize, true).unwrap();
    region
        .map(PAGE as usize, &read_only, 0, PAGE as usize, true)
        .unwrap();
    assert!(control.map_to_guest(2 * PAGE, true).is_err());
    assert!(gm.read_at(2 * PAGE, &mut [0]).is_err());
    assert!(gm.read_at(3 * PAGE, &mut [0]).is_err());
    control.map_to_guest(2 * PAGE, false).unwrap();
    assert_eq!(read_byte(&gm, 2 * PAGE), 0x28);
    assert_eq!(read_byte(&gm, 3 * PAGE), 0x9c);
    assert!(gm.write_at(2 * PAGE, &[0]).is_err());
    assert!(gm.write_at(3 * PAGE, &[0]).is_err());
    control.unmap_from_guest();
}

// IGNORED: DeviceMemoryRegion::unmap retains mappings inside the removed range
// and discards unaffected mappings. Relocation resurrects the removed page.
//
// Test: Remove one complete device mapping and then relocate the device.
// Expected: The removed page stays inaccessible while the unaffected page
//       retains its backing and contents after relocation.
#[async_test]
#[ignore = "product regression: unmap retains removed backing across relocation"]
async fn removed_mapping_stays_removed_after_relocation() {
    let manager = manager(vec![MemoryRange::new(0..PAGE)], 8 * PAGE).await;
    let gm = manager.client().guest_memory().await.unwrap();
    let mapper = manager.device_memory_mapper();
    let (mut control, region) = mapper
        .new_region(2 * PAGE as usize, "unmap-cache".into())
        .unwrap();
    let backing = backing(&vec![0x49; 2 * PAGE as usize]);
    region.map(0, &backing, 0, PAGE as usize, true).unwrap();
    region
        .map(PAGE as usize, &backing, PAGE, PAGE as usize, true)
        .unwrap();
    control.map_to_guest(2 * PAGE, true).unwrap();
    region.unmap(0, PAGE as usize).unwrap();
    assert!(gm.read_at(2 * PAGE, &mut [0]).is_err());
    assert_eq!(read_byte(&gm, 3 * PAGE), 0x49);
    control.map_to_guest(5 * PAGE, true).unwrap();
    assert!(gm.read_at(5 * PAGE, &mut [0]).is_err());
    assert_eq!(read_byte(&gm, 6 * PAGE), 0x49);
    control.unmap_from_guest();
}
