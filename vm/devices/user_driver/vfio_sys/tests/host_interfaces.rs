// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public host interfaces exercised without an assigned PCI device.

#![cfg(target_os = "linux")]

use nix::errno::Errno;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::symlink;
use test_with_tracing::test;
use vfio_sys::Group;
use vfio_sys::cdev::CdevDevice;
use vfio_sys::fd_identity;
use vfio_sys::iommufd::IommufdCtx;

// Test: Discover a device's group through relative sysfs-style links, including
//       missing, nonnumeric, overflowing, non-UTF8 and nameless targets.
// Expected: The numeric final component identifies the group without requiring
//       the target to exist; malformed links remain errors.
#[test]
fn group_discovery_validates_the_link_component() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let link = directory.path().join("iommu_group");
    let error = Group::find_group_for_device(directory.path()).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        ErrorKind::NotFound
    );
    for (target, expected) in [
        ("../../../kernel/iommu_groups/73", 73),
        ("../groups/18446744073709551615", u64::MAX),
    ] {
        symlink(target, &link).unwrap();
        assert_eq!(
            Group::find_group_for_device(directory.path()).unwrap(),
            expected
        );
        fs::remove_file(&link).unwrap();
    }
    for target in [
        OsStr::new("not-a-group"),
        OsStr::new("18446744073709551616"),
        OsStr::from_bytes(b"bad-\xff"),
        OsStr::new("/"),
    ] {
        symlink(target, &link).unwrap();
        assert!(Group::find_group_for_device(directory.path()).is_err());
        fs::remove_file(&link).unwrap();
    }
}

// Test: Duplicate, hard-link and rename an open backing file, then replace its
//       original pathname while the old inode remains live.
// Expected: DMA lookup identity follows the backing object, not its fd number
//       or pathname, and never aliases the replacement object.
#[test]
fn backing_identity_survives_aliases_but_not_path_replacement() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("backing");
    let alias = directory.path().join("alias");
    let original = File::create(&path).unwrap();
    let duplicate = original.try_clone().unwrap();
    let identity = fd_identity(original.as_fd()).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    fs::rename(&path, directory.path().join("moved")).unwrap();
    let replacement = File::create(&path).unwrap();
    drop(original);
    assert_eq!(fd_identity(duplicate.as_fd()).unwrap(), identity);
    assert_eq!(
        fd_identity(File::open(alias).unwrap().as_fd()).unwrap(),
        identity
    );
    assert_ne!(fd_identity(replacement.as_fd()).unwrap(), identity);
}

// Test: Map a nonzero file offset through the public device wrapper, create
//       read-only/shared writable views and close the originating device;
//       also try empty and unaligned mapping requests.
// Expected: Native-width volatile accesses address the requested page, preserve
//       its boundaries, remain coherent between mappings and persist to backing;
//       invalid requests retain the native InvalidInput error.
#[test]
fn shared_mapping_preserves_offsets_widths_and_owner_lifetime() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("bar");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let page = vfio_sys::host_page_size();
    let length = usize::try_from(page).unwrap();
    file.set_len(page * 2).unwrap();
    file.write_all_at(&0x1122_3344u32.to_ne_bytes(), page)
        .unwrap();
    file.write_all_at(&0x5566_7788_99aa_bbccu64.to_ne_bytes(), page + 8)
        .unwrap();
    let device = CdevDevice::from_file(file).into_device();
    for (offset, size) in [(0, 0), (page + 1, length)] {
        let error = device.map(offset, size, false).err().unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::InvalidInput
        );
    }
    let read = device.map(page, length, false).unwrap();
    let write = device.map(page, length, true).unwrap();
    assert_eq!(read.read_u32(0), 0x1122_3344);
    assert_eq!(write.read_u64(8), 0x5566_7788_99aa_bbcc);
    drop(device);
    write.write_u32(0, 0xa1b2_c3d4);
    write.write_u64(length - 8, 0x0123_4567_89ab_cdef);
    assert_eq!(read.read_u32(0), 0xa1b2_c3d4);
    assert_eq!(read.read_u64(length - 8), 0x0123_4567_89ab_cdef);
    drop(write);
    assert_eq!(read.read_u64(8), 0x5566_7788_99aa_bbcc);
    let backing = File::open(path).unwrap();
    let mut first_page = [1; 16];
    backing.read_exact_at(&mut first_page, 0).unwrap();
    assert_eq!(first_page, [0; 16]);
    let mut bytes = [0; 8];
    backing.read_exact_at(&mut bytes, page).unwrap();
    assert_eq!(&bytes[..4], &0xa1b2_c3d4u32.to_ne_bytes());
    backing.read_exact_at(&mut bytes, page * 2 - 8).unwrap();
    assert_eq!(bytes, 0x0123_4567_89ab_cdefu64.to_ne_bytes());
}

// Test: Use a real ordinary file as an unsupported ioctl endpoint.
// Expected: Device/group/IOMMU operations retain ENOTTY instead of returning
//       fabricated IDs or regions, while optional dmabuf probing falls back;
//       embedded NUL identifiers are rejected before reaching the kernel.
#[test]
fn unsupported_endpoint_distinguishes_fallback_from_operation_failure() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let file = File::create(directory.path().join("ordinary")).unwrap();
    let group = Group::from_file(file.try_clone().unwrap());
    assert!(
        group
            .open_device("bad\0device")
            .err()
            .unwrap()
            .downcast_ref::<std::ffi::NulError>()
            .is_some()
    );
    let cdev = CdevDevice::from_file(file.try_clone().unwrap());
    let bind_error = cdev.bind_iommufd(file.as_raw_fd()).unwrap_err();
    let attach_error = cdev.attach_ioas(7).unwrap_err();
    let detach_error = cdev.detach_ioas().unwrap_err();
    let device = cdev.into_device();
    assert!(!device.supports_dma_buf().unwrap());
    let iommu = IommufdCtx::from_file(file);
    for error in [
        group.status().err().unwrap(),
        group.open_device("0000:01:00.0").err().unwrap(),
        bind_error,
        attach_error,
        detach_error,
        device.info().err().unwrap(),
        device.region_mmap_areas(0).unwrap_err(),
        device
            .export_dma_buf(0, 0, vfio_sys::host_page_size())
            .unwrap_err(),
        iommu.ioas_alloc().unwrap_err(),
    ] {
        assert_eq!(error.downcast_ref::<Errno>(), Some(&Errno::ENOTTY));
    }
}
