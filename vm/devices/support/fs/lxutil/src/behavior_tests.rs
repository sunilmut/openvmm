// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{LxVolume, LxVolumeOptions, SetTime};
use std::time::Duration;
use test_with_tracing::test;

// Test: Parse malformed and unknown mount options alone and on either side of a valid read-only flag.
// Expected: Invalid input never enables read-only mode, clears an existing flag, or prevents later valid options from being applied.
#[test]
fn malformed_mount_options_do_not_change_or_hide_the_readonly_policy() {
    for token in [
        "metadata=yes",
        "case",
        "case=unknown",
        "uid",
        "uid=-1",
        "uid=4294967296",
        "gid",
        "gid=invalid",
        "mode",
        "mode=invalid",
        "mode=512",
        "default_uid",
        "default_uid=-1",
        "default_gid",
        "default_gid=4294967296",
        "umask",
        "umask=888",
        "umask=1000",
        "dmask",
        "dmask=888",
        "dmask=1000",
        "fmask",
        "fmask=888",
        "fmask=1000",
        "symlinkroot",
        "xattr",
        "sandbox=yes",
        "sandbox_disallowed_extensions",
        "ro=yes",
        "unknown=option",
    ] {
        assert!(
            !LxVolumeOptions::from_option_string(token).is_readonly(),
            "{token}"
        );
        for options in [format!("ro;{token}"), format!("{token};ro")] {
            assert!(
                LxVolumeOptions::from_option_string(&options).is_readonly(),
                "{options}"
            );
        }
    }
}

// Test: Set file timestamps through the path and handle convenience APIs while omitting one timestamp at a time.
// Expected: Explicit timestamps remain exact, Omit preserves the other field, and neither metadata update changes file contents.
#[test]
fn timestamp_convenience_apis_preserve_omitted_values_and_file_contents() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"unchanged").unwrap();
    let volume = LxVolume::new(root.path()).unwrap();
    volume
        .set_times(
            "file",
            SetTime::Set(Duration::new(111_111, 200_000)),
            SetTime::Set(Duration::new(222_222, 400_000)),
        )
        .unwrap();
    let file = volume.open("file", lx::O_RDWR, None).unwrap();
    file.set_times(SetTime::Omit, SetTime::Set(Duration::new(333_333, 600_000)))
        .unwrap();
    let stat = file.fstat().unwrap();
    assert_eq!(
        (stat.access_time.seconds, stat.access_time.nanoseconds),
        (111_111, 200_000)
    );
    assert_eq!(
        (stat.write_time.seconds, stat.write_time.nanoseconds),
        (333_333, 600_000)
    );
    volume
        .set_times(
            "file",
            SetTime::Set(Duration::new(444_444, 800_000)),
            SetTime::Omit,
        )
        .unwrap();
    let stat = volume.lstat("file").unwrap();
    assert_eq!(
        (stat.access_time.seconds, stat.access_time.nanoseconds),
        (444_444, 800_000)
    );
    assert_eq!(
        (stat.write_time.seconds, stat.write_time.nanoseconds),
        (333_333, 600_000)
    );
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"unchanged"
    );
}

// Test: Change only the owner and only the group to the file's existing values using path and handle APIs without elevated privileges.
// Expected: An omitted identity remains unchanged, the existing owner/group are retained, and file contents survive both operations.
#[cfg(unix)]
#[test]
fn same_owner_chown_preserves_the_omitted_identity_and_contents() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), b"unchanged").unwrap();
    let volume = LxVolume::new(root.path()).unwrap();
    let original = volume.lstat("file").unwrap();
    volume.chown("file", Some(original.uid), None).unwrap();
    let stat = volume.lstat("file").unwrap();
    assert_eq!((stat.uid, stat.gid), (original.uid, original.gid));
    let file = volume.open("file", lx::O_RDONLY, None).unwrap();
    file.chown(None, Some(original.gid)).unwrap();
    let stat = file.fstat().unwrap();
    assert_eq!((stat.uid, stat.gid), (original.uid, original.gid));
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"unchanged"
    );
}

// Test: Rename an open file on a Unix volume configured with the Windows-only sandbox option.
// Expected: Unix reports its documented native capabilities, and path/handle identities remain unchanged across the rename.
#[cfg(unix)]
#[test]
fn native_volume_capabilities_match_stable_identity_across_rename() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("before"), b"unchanged").unwrap();
    let volume = LxVolumeOptions::new()
        .sandbox(true)
        .new_volume(root.path())
        .unwrap();
    assert!(volume.supports_stable_file_id());
    assert!(!volume.is_sandbox());
    let original = volume.lstat("before").unwrap();
    let file = volume.open("before", lx::O_RDONLY, None).unwrap();
    std::fs::rename(root.path().join("before"), root.path().join("after")).unwrap();
    assert_eq!(volume.lstat("before").unwrap_err(), lx::Error::ENOENT);
    let renamed = volume.lstat("after").unwrap();
    let opened: lx::Stat = file.fstat().unwrap().into();
    assert_eq!(renamed.inode_nr, original.inode_nr);
    assert_eq!(opened.inode_nr, original.inode_nr);
    assert_eq!(renamed.file_size, 9);
    assert_eq!(opened.file_size, 9);
    assert_eq!(
        std::fs::read(root.path().join("after")).unwrap(),
        b"unchanged"
    );
}
