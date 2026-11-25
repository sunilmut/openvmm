// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Encode empty, error, raw-data and symlink-string replies through the vectored sender.
// Expected: Correlation IDs, signed errors, frame lengths, payloads and string terminators are exact.
#[test]
fn reply_encodings_preserve_data_and_include_string_terminators() {
    let mut capture = Capture::default();
    capture.send_empty(0x1234).unwrap();
    assert!(capture.check(0).is_empty());
    capture
        .send_error(0x1234, lx::Error::EACCES.value())
        .unwrap();
    assert!(capture.check(lx::Error::EACCES.value()).is_empty());
    capture.send_data(0x1234, b"\0\xffdata").unwrap();
    assert_eq!(capture.check(0), b"\0\xffdata");
    capture
        .send_string(0x1234, LxString::from("target/path"))
        .unwrap();
    assert_eq!(capture.check(0), b"target/path\0");
}

// Test: Pack consecutive directory entries, then reject an entry that exceeds the remaining capacity.
// Expected: Entries are eight-byte aligned, names are not NUL-terminated, padding is zero and rejection writes nothing.
#[test]
fn directory_entries_respect_capacity_alignment_and_atomic_rejection() {
    let mut bytes = Vec::with_capacity(64);
    assert!(bytes.dir_entry("hello", 29, 71, lx::DT_REG as u32));
    assert!(bytes.dir_entry("sub", 31, 73, lx::DT_DIR as u32));
    assert_eq!(bytes.len(), 64);
    for (offset, ino, next, name, kind) in [
        (0, 29, 71, b"hello".as_slice(), lx::DT_REG as u32),
        (32, 31, 73, b"sub".as_slice(), lx::DT_DIR as u32),
    ] {
        let (entry, rest) = fuse_dirent::read_from_prefix(&bytes[offset..]).unwrap();
        assert_eq!(
            (entry.ino, entry.off, entry.namelen, entry.file_type),
            (ino, next, name.len() as u32, kind)
        );
        assert_eq!(&rest[..name.len()], name);
        assert!(
            rest[name.len()..32 - size_of::<fuse_dirent>()]
                .iter()
                .all(|&b| b == 0)
        );
    }
    let original = bytes.clone();
    assert!(!bytes.dir_entry("x", 99, 99, 0));
    assert_eq!(bytes, original);
}

// Test: Pack a readdirplus entry with subsecond validity, then check exact-fit and no-space cases.
// Expected: The embedded lookup and directory metadata agree, and capacity checks have no side effects.
#[test]
fn directory_plus_preserves_attributes_timeouts_and_capacity() {
    let attr = fuse_attr {
        ino: 29,
        mode: lx::S_IFDIR | 0o750,
        size: 4096,
        ..FromZeros::new_zeroed()
    };
    let entry = fuse_entry_out::new(41, Duration::new(3, 17), Duration::new(5, 23), attr);
    let size = (size_of::<fuse_direntplus>() + 3 + 7) & !7;
    let mut bytes = Vec::with_capacity(size);
    assert!(bytes.check_dir_entry_plus("dir"));
    assert!(bytes.is_empty());
    assert!(bytes.dir_entry_plus("dir", 73, entry));
    assert_eq!(bytes.len(), size);
    let (entry, tail) = fuse_direntplus::read_from_prefix(&bytes).unwrap();
    assert_eq!(
        (entry.dirent.ino, entry.dirent.off, entry.dirent.file_type),
        (29, 73, lx::DT_DIR as u32)
    );
    assert_eq!((entry.entry_out.nodeid, entry.entry_out.attr.ino), (41, 29));
    assert_eq!(
        (
            entry.entry_out.entry_valid,
            entry.entry_out.entry_valid_nsec
        ),
        (3, 17)
    );
    assert_eq!(
        (entry.entry_out.attr_valid, entry.entry_out.attr_valid_nsec),
        (5, 23)
    );
    assert_eq!(&tail[..3], b"dir");
    assert!(tail[3..].iter().all(|&b| b == 0));
    let original = bytes.clone();
    assert!(!bytes.check_dir_entry_plus("x"));
    assert!(!bytes.dir_entry_plus("x", 99, fuse_entry_out::new_dot(99, lx::S_IFREG)));
    assert_eq!(bytes, original);
}
