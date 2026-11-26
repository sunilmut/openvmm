// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use disk_backend::resolve::ResolveDiskParameters;
use guestmem::GuestMemory;
use pal_async::DefaultDriver;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use test_with_tracing::test;
use vm_resource::ResourceResolver;
use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

// Test: Resolve a differencing chain, overwrite a middle sector and trim its block.
// Expected: Unmapped sectors read from the parent, sparse writes preserve both
//       neighbors, trim reveals parent data, and the parent file never changes.
#[async_test]
async fn resolved_differencing_reads_writes_and_trim_preserve_parent(driver: DefaultDriver) {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let parent_path = dir.path().join("parent.vhdx");
    let child_path = dir.path().join("child.vhdx");
    let file = BlockingFile::open(&parent_path, false).unwrap();
    let mut params = vhdx::CreateParams {
        disk_size: 2 * 1024 * 1024,
        ..Default::default()
    };
    vhdx::create(&file, &mut params).await.unwrap();
    let mem = GuestMemory::allocate(4096);
    let mut expected = [0; 1536];
    expected[..512].fill(0x12);
    expected[512..1024].fill(0x34);
    expected[1024..].fill(0x56);
    mem.write_at(0, &expected).unwrap();
    {
        let opened = VhdxFile::open(file.clone())
            .writable(&driver)
            .await
            .unwrap();
        let mut ranges = Vec::new();
        let guard = opened
            .resolve_write(7 * 512, 1536, &mut ranges)
            .await
            .unwrap();
        for range in ranges {
            match range {
                WriteRange::Data {
                    guest_offset,
                    length,
                    file_offset,
                } => {
                    let start = (guest_offset - 7 * 512) as usize;
                    file.write_from(
                        file_offset,
                        expected[start..start + length as usize].to_vec(),
                    )
                    .await
                    .unwrap();
                }
                WriteRange::Zero {
                    file_offset,
                    length,
                } => {
                    file.zero_range(file_offset, u64::from(length))
                        .await
                        .unwrap();
                }
            }
        }
        guard.complete().await.unwrap();
        opened.close().await.unwrap();
    }
    let opened = VhdxFile::open(file).read_only().await.unwrap();
    let parent = vhdx::VhdxParent::new(opened.data_write_guid())
        .with_relative_path(r".\parent.vhdx")
        .unwrap();
    drop(opened);
    let parent_before = std::fs::read(&parent_path).unwrap();
    let file = BlockingFile::open(&child_path, false).unwrap();
    let mut params = vhdx::CreateParams {
        disk_size: 2 * 1024 * 1024,
        disk_type: vhdx::DiskType::Differencing(parent),
        ..Default::default()
    };
    vhdx::create(&file, &mut params).await.unwrap();
    drop(file);
    let mut resolver = ResourceResolver::new();
    resolver.add_async_resolver::<vm_resource::kind::DiskHandleKind, _, _, _>(
        disk_layered::resolver::LayeredDiskResolver,
    );
    resolver.add_async_resolver(resolver::VhdxDiskLayerResolver);
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resource = chain::open_vhdx_chain(&child_path, false).await.unwrap();
    let disk = resolver
        .resolve(
            resource,
            ResolveDiskParameters {
                read_only: false,
                driver_source: &source,
            },
        )
        .await
        .unwrap()
        .0;
    let read = OwnedRequestBuffers::linear(0, 1536, true);
    disk.read_vectored(&read.buffer(&mem), 7).await.unwrap();
    let mut actual = [0; 1536];
    mem.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    mem.write_at(0, &[0xa9; 512]).unwrap();
    disk.write_vectored(
        &OwnedRequestBuffers::linear(0, 512, false).buffer(&mem),
        8,
        true,
    )
    .await
    .unwrap();
    disk.read_vectored(&read.buffer(&mem), 7).await.unwrap();
    mem.read_at(0, &mut actual).unwrap();
    let mut overlaid = expected;
    overlaid[512..1024].fill(0xa9);
    assert_eq!(actual, overlaid);
    disk.unmap(0, disk.sector_count(), false).await.unwrap();
    disk.read_vectored(&read.buffer(&mem), 7).await.unwrap();
    mem.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    disk.sync_cache().await.unwrap();
    drop(disk);
    assert_eq!(std::fs::read(&parent_path).unwrap(), parent_before);
    let resource = chain::open_vhdx_single(&parent_path, true).unwrap();
    let disk = resolver
        .resolve(
            resource,
            ResolveDiskParameters {
                read_only: true,
                driver_source: &source,
            },
        )
        .await
        .unwrap()
        .0;
    assert!(matches!(
        disk.write_vectored(
            &OwnedRequestBuffers::linear(0, 512, false).buffer(&mem),
            8,
            false
        )
        .await,
        Err(DiskError::ReadOnly)
    ));
}

// Test: Read beyond EOF and attempt writes through a read-only cloned file.
// Expected: Errors retain their I/O meaning, failed writes preserve all bytes,
//       and cloning does not make access depend on seek position.
#[async_test]
async fn blocking_file_clones_preserve_position_and_error_semantics() {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = dir.path().join("io.bin");
    std::fs::write(&path, [0x14, 0x25, 0x36, 0x47]).unwrap();
    let file = BlockingFile::open(&path, true).unwrap();
    let clone = file.clone();
    assert_eq!(clone.read_into(1, vec![0; 2]).await.unwrap(), [0x25, 0x36]);
    assert_eq!(file.read_into(0, vec![0; 1]).await.unwrap(), [0x14]);
    assert_eq!(
        clone.read_into(3, vec![0; 2]).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert!(file.write_from(0, vec![0xee; 4]).await.is_err());
    assert!(clone.set_file_size(32).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), [0x14, 0x25, 0x36, 0x47]);
}
