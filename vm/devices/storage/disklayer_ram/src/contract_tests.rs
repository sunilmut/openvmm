// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use disk_backend::DiskIo;
use disk_backend_resources::layer::RamDiskLayerHandle;
use disk_layered::resolve::ResolveDiskLayerParameters;
use guestmem::GuestMemory;
use pal_async::DefaultDriver;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use test_with_tracing::test;
use vm_resource::ResolveResource;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

// Test: Attach a configured lazy RAM layer with no lower layer.
// Expected: Missing capacity and invalid geometry are rejected; an explicit
//       capacity uses the default sector size and reads as zero-filled storage.
#[async_test]
async fn standalone_lazy_geometry_and_zero_initialization() {
    assert!(matches!(
        LazyRamDiskLayer::new().attach(None).await,
        Err(Error::EmptyDisk)
    ));
    assert!(matches!(
        LazyRamDiskLayer::new().with_len(0).attach(None).await,
        Err(Error::EmptyDisk)
    ));
    assert!(matches!(
        LazyRamDiskLayer::new()
            .with_len(4096)
            .with_sector_size(768)
            .attach(None)
            .await,
        Err(Error::InvalidSectorSize(768))
    ));
    let layer = LazyRamDiskLayer::new()
        .with_len(1024)
        .attach(None)
        .await
        .unwrap();
    let disk = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            layer: DiskLayer::new(layer),
            write_through: false,
            read_cache: false,
        }],
    )
    .await
    .unwrap();
    let mem = GuestMemory::allocate(1024);
    mem.write_at(0, &[0xa5; 1024]).unwrap();
    disk.read_vectored(&OwnedRequestBuffers::linear(0, 1024, true).buffer(&mem), 0)
        .await
        .unwrap();
    let mut bytes = [0xff; 1024];
    mem.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 1024]);
}

// Test: Resolve RAM overlays with inherited or explicit geometry.
// Expected: Both modes retain the lower disk bytes outside an upper write;
//       a 4K-sector write modifies one logical sector, not eight misplaced sectors.
#[async_test]
async fn resolved_overlay_geometry_preserves_lower_data(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    for handle in [
        RamDiskLayerHandle {
            len: None,
            sector_size: None,
        },
        RamDiskLayerHandle {
            len: Some(4 * 4096),
            sector_size: Some(4096),
        },
    ] {
        let upper = resolver::RamDiskLayerResolver
            .resolve(
                handle,
                ResolveDiskLayerParameters {
                    read_only: false,
                    driver_source: &source,
                },
            )
            .unwrap()
            .0;
        let lower = RamDiskLayer::new_with_sector_size(4 * 4096, 4096).unwrap();
        let mem = GuestMemory::allocate(4 * 4096);
        mem.write_at(0, &[0x31; 4 * 4096]).unwrap();
        lower
            .write(
                &OwnedRequestBuffers::linear(0, 4 * 4096, false).buffer(&mem),
                0,
                false,
            )
            .await
            .unwrap();
        let disk = LayeredDisk::new(
            false,
            vec![
                LayerConfiguration {
                    layer: upper,
                    write_through: false,
                    read_cache: false,
                },
                LayerConfiguration {
                    layer: DiskLayer::new(lower),
                    write_through: false,
                    read_cache: false,
                },
            ],
        )
        .await
        .unwrap();
        assert_eq!(disk.sector_size(), 4096);
        mem.write_at(0, &[0x72; 4096]).unwrap();
        disk.write_vectored(
            &OwnedRequestBuffers::linear(0, 4096, false).buffer(&mem),
            1,
            false,
        )
        .await
        .unwrap();
        disk.read_vectored(
            &OwnedRequestBuffers::linear(0, 4 * 4096, true).buffer(&mem),
            0,
        )
        .await
        .unwrap();
        let mut bytes = vec![0; 4 * 4096];
        mem.read_at(0, &mut bytes).unwrap();
        let mut expected = vec![0x31; 4 * 4096];
        expected[4096..8192].fill(0x72);
        assert_eq!(bytes, expected);
    }
}
