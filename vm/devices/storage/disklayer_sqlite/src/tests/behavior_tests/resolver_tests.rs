// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::resolver::SqliteDiskLayerResolver;
use disk_backend_resources::layer::SqliteAutoCacheDiskLayerHandle;
use disk_backend_resources::layer::SqliteDiskLayerFormatParams;
use disk_backend_resources::layer::SqliteDiskLayerHandle;
use disk_layered::resolve::ResolveDiskLayerParameters;
use pal_async::DefaultDriver;
use test_with_tracing::test;
use vm_resource::ResolveResource;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

async fn read_disk(disk: &Disk) -> Vec<u8> {
    let memory = GuestMemory::allocate(512);
    disk.read_vectored(
        &OwnedRequestBuffers::linear(0, 512, true).buffer(&memory),
        0,
    )
    .await
    .unwrap();
    let mut bytes = vec![0; 512];
    memory.read_at(0, &mut bytes).unwrap();
    bytes
}

// Test: Resolve a lazy format resource, attach/write/sync it, then resolve the existing file read-only and attempt to resolve a missing file.
// Expected: Resolution preserves lazy creation until attachment, persistent data survives the existing-file route, read-only writes fail without corruption, and missing files are not implicitly created.
#[async_test]
async fn resolver_lazy_format_existing_file_and_read_only_io_round_trip(driver: DefaultDriver) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resolved.dbhd");
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let input = ResolveDiskLayerParameters {
        read_only: false,
        driver_source: &driver_source,
    };
    let resolved = SqliteDiskLayerResolver
        .resolve(
            SqliteDiskLayerHandle {
                dbhd_path: path.to_str().unwrap().into(),
                format_dbhd: Some(SqliteDiskLayerFormatParams {
                    logically_read_only: false,
                    len: Some(4096),
                }),
            },
            input,
        )
        .unwrap();
    assert!(!path.exists());
    let disk = Disk::new(
        LayeredDisk::new(
            false,
            vec![LayerConfiguration {
                layer: resolved.0,
                write_through: false,
                read_cache: false,
            }],
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let memory = GuestMemory::allocate(512);
    memory.write_at(0, &vec![0x81; 512]).unwrap();
    disk.write_vectored(
        &OwnedRequestBuffers::linear(0, 512, false).buffer(&memory),
        0,
        false,
    )
    .await
    .unwrap();
    disk.sync_cache().await.unwrap();
    drop(disk);
    let resolved = SqliteDiskLayerResolver
        .resolve(
            SqliteDiskLayerHandle {
                dbhd_path: path.to_str().unwrap().into(),
                format_dbhd: None,
            },
            ResolveDiskLayerParameters {
                read_only: true,
                ..input
            },
        )
        .unwrap();
    let disk = Disk::new(
        LayeredDisk::new(
            true,
            vec![LayerConfiguration {
                layer: resolved.0,
                write_through: false,
                read_cache: false,
            }],
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(read_disk(&disk).await, vec![0x81; 512]);
    memory.write_at(0, &vec![0xfe; 512]).unwrap();
    assert!(
        disk.write_vectored(
            &OwnedRequestBuffers::linear(0, 512, false).buffer(&memory),
            0,
            false
        )
        .await
        .is_err()
    );
    assert_eq!(read_disk(&disk).await, vec![0x81; 512]);
    let missing = dir.path().join("missing.dbhd");
    assert!(
        SqliteDiskLayerResolver
            .resolve(
                SqliteDiskLayerHandle {
                    dbhd_path: missing.to_str().unwrap().into(),
                    format_dbhd: None
                },
                input
            )
            .is_err()
    );
    assert!(!missing.exists());
}

// Test: Resolve and attach an automatic read cache over a real lower SQLite disk, read to populate it, change the lower bytes, and read again.
// Expected: The explicit-key cache route creates a working read cache whose first captured bytes remain authoritative after the lower backing changes.
#[async_test]
async fn resolver_auto_cache_populates_and_reuses_cached_bytes(driver: DefaultDriver) {
    let dir = tempfile::tempdir().unwrap();
    let lower_path = dir.path().join("lower.dbhd");
    let lower = format(&lower_path, false);
    write(&lower, 0, &vec![0x33; 512]).await;
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolved = SqliteDiskLayerResolver
        .resolve(
            SqliteAutoCacheDiskLayerHandle {
                cache_path: dir.path().join("cache-root").to_str().unwrap().into(),
                cache_key: Some("explicit".into()),
            },
            ResolveDiskLayerParameters {
                read_only: false,
                driver_source: &driver_source,
            },
        )
        .unwrap();
    let disk = Disk::new(
        LayeredDisk::new(
            true,
            vec![
                LayerConfiguration {
                    layer: resolved.0,
                    write_through: false,
                    read_cache: true,
                },
                LayerConfiguration {
                    layer: DiskLayer::new(SqliteDiskLayer::new(&lower_path, true, None).unwrap()),
                    write_through: false,
                    read_cache: false,
                },
            ],
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(read_disk(&disk).await, vec![0x33; 512]);
    write(&lower, 0, &vec![0x44; 512]).await;
    assert_eq!(read_disk(&disk).await, vec![0x33; 512]);
    assert_eq!(read_layers(&[&lower_path], 0, 1).await, vec![0x44; 512]);
}
