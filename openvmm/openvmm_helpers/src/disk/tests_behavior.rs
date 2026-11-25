// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Create a raw disk over an existing file, then reopen it for guest use.
// Expected: Creation resets its size/content; opening preserves later guest writes.
#[async_test]
async fn raw_creation_truncates_but_open_preserves_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.raw");
    std::fs::write(&path, [0x55; 12288]).unwrap();
    let resource = create_disk_type(
        &path,
        8192,
        OpenDiskOptions {
            read_only: false,
            direct: false,
        },
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(resource.id(), "block");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(resource.id(), "file");
    assert_eq!(std::fs::read(&path).unwrap(), vec![0; 8192]);
    drop(resource);
    std::fs::write(&path, [0x71; 8192]).unwrap();
    for read_only in [false, true] {
        let resource = open_disk_type(
            &path,
            OpenDiskOptions {
                read_only,
                direct: false,
            },
        )
        .await
        .unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(resource.id(), "block");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(resource.id(), "file");
        assert_eq!(std::fs::read(&path).unwrap(), vec![0x71; 8192]);
    }
}

// Test: Create VHD and VMGS files, then validate them with the fixed-VHD parser.
// Expected: Each has a valid footer and retains its zero-filled guest payload on reopen.
#[async_test]
async fn fixed_disk_creation_produces_valid_reopenable_images() {
    let directory = tempfile::tempdir().unwrap();
    for extension in ["vhd", "vmgs"] {
        let path = directory.path().join(format!("disk.{extension}"));
        let resource = create_disk_type(
            &path,
            8192,
            OpenDiskOptions {
                read_only: false,
                direct: false,
            },
        )
        .unwrap();
        assert_eq!(resource.id(), "fixed_vhd1");
        drop(resource);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 8192 + 512);
        assert_eq!(&bytes[..8192], vec![0; 8192]);
        disk_vhd1::Vhd1Disk::open_fixed(std::fs::File::open(&path).unwrap(), true).unwrap();
        for read_only in [false, true] {
            let resource = open_disk_type(
                &path,
                OpenDiskOptions {
                    read_only,
                    direct: false,
                },
            )
            .await
            .unwrap();
            assert_eq!(resource.id(), "fixed_vhd1");
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        if extension == "vhd" {
            let error = open_disk_type(
                &path,
                OpenDiskOptions {
                    read_only: true,
                    direct: true,
                },
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "direct I/O is not supported for fixed .vhd files"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }
}

// Test: Open a VMGS file whose footer has not yet been initialized.
// Expected: The helper passes it to the fixed-VHD resource resolver without modifying it.
#[async_test]
async fn vmgs_footer_validation_is_deferred_to_the_resolver() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.vmgs");
    std::fs::write(&path, b"uninitialized VMGS").unwrap();
    let resource = open_disk_type(
        &path,
        OpenDiskOptions {
            read_only: false,
            direct: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(resource.id(), "fixed_vhd1");
    assert_eq!(std::fs::read(&path).unwrap(), b"uninitialized VMGS");
}

// Test: Create a disk in an unsupported format or with unsupported direct I/O.
// Expected: Exact actionable errors are returned before any destination file is created.
#[test]
fn unsupported_disk_creation_does_not_create_files() {
    let directory = tempfile::tempdir().unwrap();
    for (extension, expected) in [
        ("vhd", "direct I/O is not supported for VHD files"),
        ("vmgs", "direct I/O is not supported for VHD files"),
        ("vhdx", "creating vhdx not supported"),
        ("iso", "creating iso not supported"),
    ] {
        let path = directory.path().join(format!("disk.{extension}"));
        let error = create_disk_type(
            &path,
            8192,
            OpenDiskOptions {
                read_only: false,
                direct: true,
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert!(!path.exists());
    }
}

// Test: Open wrapped disks with direct I/O, or request a writable ISO.
// Expected: Unsupported modes fail before opening or creating any disk file.
#[async_test]
async fn unsupported_disk_open_modes_do_not_create_files() {
    let directory = tempfile::tempdir().unwrap();
    let direct_formats: &[&str] = if cfg!(windows) {
        &["vmgs"]
    } else {
        &["vmgs", "vhdx"]
    };
    for extension in direct_formats {
        let path = directory.path().join(format!("disk.{extension}"));
        let error = open_disk_type(
            &path,
            OpenDiskOptions {
                read_only: true,
                direct: true,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("direct I/O is not supported for .{extension} files")
        );
        assert!(!path.exists());
    }
    let error = open_disk_type(
        &directory.path().join("disk.iso"),
        OpenDiskOptions {
            read_only: false,
            direct: false,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "iso file cannot be opened as read/write");
}

// Test: Open missing raw, VHD, VMGS and VMDK disk files.
// Expected: Original NotFound errors and the failing path survive contextual wrapping.
#[async_test]
async fn disk_open_errors_retain_path_and_original_cause() {
    let directory = tempfile::tempdir().unwrap();
    for extension in ["raw", "vhd", "vmgs", "vmdk"] {
        let path = directory.path().join(format!("missing.{extension}"));
        let error = open_disk_type(
            &path,
            OpenDiskOptions {
                read_only: true,
                direct: false,
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with(&format!("failed to open '{}'", path.display()))
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }
}

// Test: Create raw or fixed-VHD disks below a nonexistent directory.
// Expected: Original NotFound errors and the failing path survive contextual wrapping.
#[test]
fn disk_creation_errors_retain_path_and_original_cause() {
    let directory = tempfile::tempdir().unwrap();
    for extension in ["raw", "vhd"] {
        let path = directory
            .path()
            .join("missing")
            .join(format!("disk.{extension}"));
        let error = create_disk_type(
            &path,
            8192,
            OpenDiskOptions {
                read_only: false,
                direct: false,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with(&format!("failed to create '{}'", path.display()))
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }
}

// Test: Open a truncated VHD rather than a valid fixed image.
// Expected: The typed invalid-file-size error survives disk format dispatch.
#[async_test]
async fn malformed_vhd_preserves_typed_parser_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.vhd");
    std::fs::write(&path, [0; 17]).unwrap();
    let error = open_disk_type(
        &path,
        OpenDiskOptions {
            read_only: true,
            direct: false,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<disk_vhd1::OpenError>(),
        Some(disk_vhd1::OpenError::InvalidFileSize(17))
    ));
}
