// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use std::os::unix::fs::FileExt;
use test_with_tracing::test;

// Test: Open an existing backing file read-only, writable, and with direct I/O.
// Expected: Permissions are enforced, existing data survives, and direct I/O
//       operates correctly through the disk interface.
#[async_test]
async fn backing_file_open_modes_preserve_data() {
    let backing = tempfile::NamedTempFile::new().unwrap();
    backing.as_file().set_len(4096).unwrap();
    backing.as_file().write_all_at(&[0x39; 512], 0).unwrap();

    let read_only = open_file_for_block(backing.path(), true, false).unwrap();
    let mut bytes = [0; 512];
    read_only.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [0x39; 512]);
    assert_eq!(
        read_only
            .write_at(&[0xff; 512], 0)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBADF)
    );

    let writable = open_file_for_block(backing.path(), false, false).unwrap();
    writable.write_all_at(&[0xa6; 512], 512).unwrap();
    let direct = open_file_for_block(backing.path(), false, true).unwrap();
    let disk = new_block_device_from(direct).unwrap();
    let gm = GuestMemory::allocate(4096);
    let request = OwnedRequestBuffers::linear(0, 1024, true);
    disk.read_vectored(&request.buffer(&gm), 0).await.unwrap();
    let mut actual = [0; 1024];
    gm.read_at(0, &mut actual).unwrap();
    assert_eq!(&actual[..512], &[0x39; 512]);
    assert_eq!(&actual[512..], &[0xa6; 512]);

    let missing = backing.path().with_extension("missing");
    assert_eq!(
        open_file_for_block(&missing, true, false)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!missing.exists());
}

// Test: Construct devices from a mis-sized file and a non-storage character file.
// Expected: Construction reports the specific error instead of exposing an
//       unusable disk, without changing the backing file.
#[test]
fn construction_rejects_invalid_backing_files() {
    let file = tempfile::tempfile().unwrap();
    file.set_len(513).unwrap();
    let observer = file.try_clone().unwrap();
    let Err(NewDeviceError::DeviceMetadata(error)) = new_block_device_from(file) else {
        panic!("misaligned file was not rejected as invalid metadata");
    };
    assert!(error.to_string().contains("invalid disk size"));
    assert_eq!(observer.metadata().unwrap().len(), 513);

    assert!(matches!(
        new_block_device_from(fs::File::open("/dev/null").unwrap()),
        Err(NewDeviceError::InvalidFileType)
    ));
}

async fn bounce_roundtrip(tracked: bool, always_bounce: bool) {
    let file = tempfile::tempfile().unwrap();
    file.set_len(4096).unwrap();
    file.write_all_at(&[0x71; 4096], 0).unwrap();
    let observer = file.try_clone().unwrap();
    let pool = test_pool().unwrap();
    let tracker =
        tracked.then(|| Arc::new(BounceBufferTracker::new(1, affinity::max_procs() as usize)));
    let disk = BlockDevice::new(
        file,
        false,
        pool.initiator().clone(),
        None,
        tracker,
        always_bounce,
    )
    .await
    .unwrap();
    let gm = GuestMemory::allocate(8192);
    // A one-byte offset forces bouncing even when always_bounce is disabled.
    let offset = if always_bounce { 0 } else { 1 };
    let write = OwnedRequestBuffers::new_unaligned(&[0], offset, 512);
    let read = OwnedRequestBuffers::new_unaligned(&[1], offset, 512);
    for (sector, value) in [(1, 0x23), (2, 0xb4)] {
        gm.write_at(offset as u64, &[value; 512]).unwrap();
        disk.write_vectored(&write.buffer(&gm), sector, false)
            .await
            .unwrap();
        disk.read_vectored(&read.buffer(&gm), sector).await.unwrap();
        let mut actual = [0; 512];
        gm.read_at(4096 + offset as u64, &mut actual).unwrap();
        assert_eq!(actual, [value; 512]);
    }
    disk.sync_cache().await.unwrap();
    let mut actual = [0; 4096];
    observer.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(&actual[..512], &[0x71; 512]);
    assert_eq!(&actual[512..1024], &[0x23; 512]);
    assert_eq!(&actual[1024..1536], &[0xb4; 512]);
    assert_eq!(&actual[1536..], &[0x71; 2560]);
}

// Test: Read and write unaligned guest buffers without a shared buffer tracker.
// Expected: Each payload round-trips exactly and neighboring file sectors survive.
#[async_test]
async fn unaligned_buffers_roundtrip_without_tracker() {
    bounce_roundtrip(false, false).await;
}

// Test: Force bouncing with a tracker limited to one page per processor.
// Expected: Repeated reads and writes release their buffers and preserve all data.
#[async_test]
async fn forced_bounce_releases_tracked_buffers() {
    bounce_roundtrip(true, true).await;
}

// Test: Submit invalid guest memory and a read targeting read-only guest buffers.
// Expected: Both operations report errors, leave file contents intact, and do not
//       prevent a subsequent valid bounced read.
#[async_test]
async fn invalid_guest_buffers_do_not_damage_disk_or_poison_later_io() {
    let file = tempfile::tempfile().unwrap();
    file.set_len(4096).unwrap();
    file.write_all_at(&[0x4a; 4096], 0).unwrap();
    let observer = file.try_clone().unwrap();
    let pool = test_pool().unwrap();
    let disk = BlockDevice::new(file, false, pool.initiator().clone(), None, None, true)
        .await
        .unwrap();
    let gm = GuestMemory::allocate(4096);
    let missing = OwnedRequestBuffers::linear(8192, 512, true);
    assert!(
        disk.write_vectored(&missing.buffer(&gm), 0, false)
            .await
            .is_err()
    );
    assert!(disk.read_vectored(&missing.buffer(&gm), 0).await.is_err());
    let read_only = OwnedRequestBuffers::linear(0, 512, false);
    assert!(disk.read_vectored(&read_only.buffer(&gm), 0).await.is_err());
    let valid = OwnedRequestBuffers::linear(0, 512, true);
    disk.read_vectored(&valid.buffer(&gm), 0).await.unwrap();
    let mut actual = [0; 4096];
    observer.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, [0x4a; 4096]);
    let mut read_back = [0; 512];
    gm.read_at(0, &mut read_back).unwrap();
    assert_eq!(read_back, [0x4a; 512]);
}

// Test: Read, write, discard, and eject a disk opened read-only.
// Expected: Reads work, writes and eject fail, unsupported discard leaves data
//       unchanged, and an out-of-range discard is still rejected.
#[async_test]
async fn read_only_disk_preserves_backing_data() {
    let backing = tempfile::NamedTempFile::new().unwrap();
    backing.as_file().write_all_at(&[0xc7; 4096], 0).unwrap();
    let pool = test_pool().unwrap();
    let disk = BlockDevice::new(
        open_file_for_block(backing.path(), true, false).unwrap(),
        true,
        pool.initiator().clone(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    let gm = GuestMemory::allocate(4096);
    let request = OwnedRequestBuffers::linear(0, 4096, true);
    disk.read_vectored(&request.buffer(&gm), 0).await.unwrap();
    let mut actual = [0; 4096];
    gm.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, [0xc7; 4096]);
    gm.write_at(0, &[0; 4096]).unwrap();
    assert!(
        disk.write_vectored(&request.buffer(&gm), 0, false)
            .await
            .is_err()
    );
    assert_eq!(disk.unmap_behavior(), UnmapBehavior::Ignored);
    disk.unmap(0, 8, false).await.unwrap();
    assert!(matches!(
        disk.unmap(8, 1, false).await,
        Err(DiskError::IllegalBlock)
    ));
    assert!(disk.eject().await.is_err());
    backing.as_file().read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, [0xc7; 4096]);
}

// Test: Observe a file-backed disk through the resize-wait interface.
// Expected: A stale caller receives the capacity immediately; a current caller
//       waits rather than receiving a spurious resize notification.
#[async_test]
async fn resize_wait_distinguishes_stale_and_current_capacity() {
    let disk = new_block_device().unwrap();
    assert_eq!(disk.wait_resize(0).await, 128);
    assert!(disk.wait_resize(128).now_or_never().is_none());
}

// Test: Resolve file handles through the static and tracked-buffer resolvers.
// Expected: The resulting disks expose the file's data with the requested
//       permissions; invalid backing files retain a construction error.
#[async_test]
async fn resource_resolvers_preserve_data_permissions_and_errors() {
    use disk_backend::resolve::ResolveDiskParameters;
    use disk_backend_resources::BlockDeviceDiskHandle;
    use resolver::BlockDeviceResolver;
    use resolver::ResolveDiskError;
    use resolver::StaticBlockDeviceResolver;
    use vm_resource::AsyncResolveResource;
    use vm_resource::ResourceResolver;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    let pool = test_pool().unwrap();
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(pool.initiator().clone()));
    let resolver = ResourceResolver::new();
    let tracked = BlockDeviceResolver::new(
        None,
        Arc::new(BounceBufferTracker::new(1, affinity::max_procs() as usize)),
        true,
    );
    for read_only in [false, true] {
        let backing = tempfile::NamedTempFile::new().unwrap();
        backing.as_file().write_all_at(&[0x59; 4096], 0).unwrap();
        let parameters = ResolveDiskParameters {
            read_only,
            driver_source: &driver_source,
        };
        for use_tracked in [false, true] {
            let handle = BlockDeviceDiskHandle {
                file: open_file_for_block(backing.path(), read_only, false).unwrap(),
            };
            let disk = if use_tracked {
                tracked.resolve(&resolver, handle, parameters).await
            } else {
                StaticBlockDeviceResolver
                    .resolve(&resolver, handle, parameters)
                    .await
            }
            .unwrap()
            .0;
            assert_eq!(disk.sector_count(), 8);
            assert_eq!(disk.is_read_only(), read_only);
            assert!(disk.pr().is_none());
            let gm = GuestMemory::allocate(4096);
            let request = OwnedRequestBuffers::linear(0, 512, true);
            disk.read_vectored(&request.buffer(&gm), 0).await.unwrap();
            let mut bytes = [0; 512];
            gm.read_at(0, &mut bytes).unwrap();
            assert_eq!(bytes, [0x59; 512]);
        }

        backing.as_file().set_len(513).unwrap();
        for use_tracked in [false, true] {
            let handle = BlockDeviceDiskHandle {
                file: open_file_for_block(backing.path(), read_only, false).unwrap(),
            };
            let result = if use_tracked {
                tracked.resolve(&resolver, handle, parameters).await
            } else {
                StaticBlockDeviceResolver
                    .resolve(&resolver, handle, parameters)
                    .await
            };
            assert!(matches!(
                result,
                Err(ResolveDiskError::NewDevice(NewDeviceError::DeviceMetadata(
                    _
                )))
            ));
        }
    }
}

// Test: Run two disks concurrently through the same bounded bounce-buffer tracker.
// Expected: Both finish repeated I/O with their own payloads, intact guest-buffer
//       guards, and no data from the other disk.
#[async_test]
async fn shared_bounce_tracker_keeps_concurrent_disks_isolated() {
    let pool = test_pool().unwrap();
    let tracker = Arc::new(BounceBufferTracker::new(1, affinity::max_procs() as usize));
    let mut disks = Vec::new();
    let mut observers = Vec::new();
    for _ in 0..2 {
        let file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        observers.push(file.try_clone().unwrap());
        disks.push(
            BlockDevice::new(
                file,
                false,
                pool.initiator().clone(),
                None,
                Some(tracker.clone()),
                true,
            )
            .await
            .unwrap(),
        );
    }

    futures::future::join_all(disks.iter().enumerate().map(|(index, disk)| async move {
        let gm = GuestMemory::allocate(8192);
        gm.write_at(0, &[0xcc; 8192]).unwrap();
        let write = OwnedRequestBuffers::linear(1, 512, true);
        let read = OwnedRequestBuffers::linear(4097, 512, true);
        for sector in 0..8 {
            let value = 0x20 + index as u8 * 0x40 + sector as u8;
            gm.write_at(1, &[value; 512]).unwrap();
            disk.write_vectored(&write.buffer(&gm), sector, false)
                .await
                .unwrap();
            disk.read_vectored(&read.buffer(&gm), sector).await.unwrap();
            let mut actual = [0; 514];
            gm.read_at(4096, &mut actual).unwrap();
            assert_eq!(actual[0], 0xcc);
            assert_eq!(&actual[1..513], &[value; 512]);
            assert_eq!(actual[513], 0xcc);
        }
        disk.sync_cache().await.unwrap();
    }))
    .await;

    for (index, observer) in observers.iter().enumerate() {
        assert_eq!(observer.metadata().unwrap().len(), 4096);
        for sector in 0..8 {
            let mut actual = [0; 512];
            observer.read_exact_at(&mut actual, sector * 512).unwrap();
            assert_eq!(actual, [0x20 + index as u8 * 0x40 + sector as u8; 512]);
        }
    }
}
