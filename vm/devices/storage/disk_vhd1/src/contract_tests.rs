// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use guestmem::GuestMemory;
use pal_async::DefaultDriver;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use test_with_tracing::test;
use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

fn checksum(footer: &mut [u8; 512]) {
    footer[64..68].fill(0);
    let sum = footer.iter().map(|&byte| u32::from(byte)).sum::<u32>();
    footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
}

fn footer() -> [u8; 512] {
    let mut bytes = [0; 512];
    bytes[..8].copy_from_slice(b"conectix");
    bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
    bytes[12..16].copy_from_slice(&0x10000_u32.to_be_bytes());
    bytes[16..24].fill(0xff);
    bytes[40..48].copy_from_slice(&1024_u64.to_be_bytes());
    bytes[48..56].copy_from_slice(&1024_u64.to_be_bytes());
    bytes[60..64].copy_from_slice(&2_u32.to_be_bytes());
    bytes[68..84].copy_from_slice(&[
        0x91, 0x02, 0x83, 0x74, 0x65, 0x56, 0x47, 0x38, 0x29, 0x1a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0,
    ]);
    checksum(&mut bytes);
    bytes
}

fn write_image(file: &mut File, footer: &[u8; 512]) {
    file.write_all(&[0x61; 1024]).unwrap();
    file.write_all(footer).unwrap();
}

// Test: Open an independently encoded fixed VHD through the disk and resolver.
// Expected: The payload and UUID survive I/O/flush without modifying its footer,
//       and the resolved read-only view returns the same updated sectors.
#[async_test]
async fn fixed_image_io_preserves_footer_and_resolved_identity(driver: DefaultDriver) {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = dir.path().join("fixed.vhd");
    let mut file = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let footer = footer();
    write_image(&mut file, &footer);
    let disk = Vhd1Disk::open_fixed(file, false).unwrap();
    let id: [u8; 16] = footer[68..84].try_into().unwrap();
    assert_eq!(disk.disk_id(), Some(id));
    let mem = GuestMemory::allocate(4096);
    mem.write_at(0, &[0x29; 512]).unwrap();
    let buffers = OwnedRequestBuffers::linear(0, 512, false);
    disk.write_vectored(&buffers.buffer(&mem), 1, true)
        .await
        .unwrap();
    disk.sync_cache().await.unwrap();
    disk.unmap(0, 2, false).await.unwrap();
    let mut file = disk.into_inner();
    file.rewind().unwrap();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    assert_eq!(&actual[..512], &[0x61; 512]);
    assert_eq!(&actual[512..1024], &[0x29; 512]);
    assert_eq!(&actual[1024..], &footer);

    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolved = Vhd1Resolver
        .resolve(
            FixedVhd1DiskHandle(File::open(&path).unwrap()),
            ResolveDiskParameters {
                read_only: true,
                driver_source: &source,
            },
        )
        .unwrap()
        .0;
    assert_eq!(resolved.disk_id(), Some(id));
    assert!(resolved.is_read_only());
    let buffers = OwnedRequestBuffers::linear(0, 1024, true);
    resolved
        .read_vectored(&buffers.buffer(&mem), 0)
        .await
        .unwrap();
    let mut readback = [0; 1024];
    mem.read_at(0, &mut readback).unwrap();
    assert_eq!(&readback, &actual[..1024]);
}

// Test: Feed independently encoded fixed-VHD footer and file-size violations.
// Expected: Each structural/format violation is rejected with its typed error,
//       and conversion of an unaligned raw disk leaves its bytes unchanged.
#[test]
fn malformed_fixed_images_are_rejected_without_raw_conversion_side_effects() {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = dir.path().join("candidate.vhd");
    for (offset, value, kind) in [
        (0, 0, 0),
        (12, 0xff, 1),
        (60, 0xff, 2),
        (55, 1, 3),
        (54, 0x10, 3),
        (100, 1, 4),
    ] {
        let mut bytes = footer();
        bytes[offset] = value;
        if kind != 4 {
            checksum(&mut bytes);
        }
        let mut file = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        write_image(&mut file, &bytes);
        let error = Vhd1Disk::open_fixed(file, false).unwrap_err();
        assert!(matches!(
            (kind, error),
            (0, OpenError::InvalidFooterCookie)
                | (1, OpenError::UnsupportedVersion(_))
                | (2, OpenError::NotFixed)
                | (3, OpenError::InvalidDiskSize(_))
                | (4, OpenError::InvalidFooterChecksum)
        ));
    }
    for length in [0, 511, 513] {
        let file = File::options().read(true).write(true).open(&path).unwrap();
        file.set_len(length).unwrap();
        assert!(
            matches!(Vhd1Disk::open_fixed(file, false), Err(OpenError::InvalidFileSize(size)) if size == length)
        );
    }
    let file = File::options().read(true).write(true).open(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Vhd1Disk::make_fixed(&file),
        Err(OpenError::InvalidDiskSize(513))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
