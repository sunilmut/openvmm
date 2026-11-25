// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Check a snapshot destination that is a dangling symlink.
// Expected: It is rejected as existing, without following or replacing the link.
#[test]
fn dangling_destination_link_is_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("snapshot");
    let target = directory.path().join("absent-target");
    std::os::unix::fs::symlink(&target, &destination).unwrap();
    let error = check_snapshot_destination(&destination).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "snapshot destination {} already exists",
            destination.display()
        )
    );
    assert_eq!(std::fs::read_link(&destination).unwrap(), target);
    assert!(!target.exists());
}

// Test: Publish a snapshot with a directory supplied as its memory backing file.
// Expected: The hard-link failure removes partial snapshot files but preserves the source.
#[test]
fn memory_link_failure_rolls_back_partial_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("memory");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("sentinel"), b"keep source").unwrap();
    let destination = directory.path().join("nested").join("snapshot");
    let error = write_snapshot(&destination, &test_manifest(), b"state", &source).unwrap_err();
    let canonical_source = fs_err::canonicalize(&source).unwrap();
    assert_eq!(
        error.to_string(),
        format!(
            "failed to hard-link {} -> {}",
            canonical_source.display(),
            destination.join("memory.bin").display()
        )
    );
    assert!(!destination.exists());
    assert_eq!(
        std::fs::read(source.join("sentinel")).unwrap(),
        b"keep source"
    );
    assert!(destination.parent().unwrap().is_dir());
}

// Test: Publish guest RAM, unlink its original name and reuse that name for a new file.
// Expected: The snapshot retains the original RAM, including writes through its open
//       backing handle; the replacement file and saved device state stay unchanged.
#[test]
fn published_memory_survives_backing_path_reuse() {
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("memory");
    let mut memory =
        std::fs::File::from(crate::shared_memory::open_memory_backing_file(&source, 8192).unwrap());
    let mut expected: Vec<u8> = (0..8192).map(|i| i as u8).collect();
    memory.write_all(&expected).unwrap();
    let destination = directory.path().join("snapshot");
    let mut manifest = test_manifest();
    manifest.memory_size_bytes = 8192;
    let state = b"device state\0\xff";
    write_snapshot(&destination, &manifest, state, &source).unwrap();

    // Reusing the name must not retarget the published memory link.
    std::fs::remove_file(&source).unwrap();
    std::fs::write(&source, b"replacement RAM").unwrap();
    memory.seek(SeekFrom::Start(4093)).unwrap();
    memory.write_all(b"\0\xffupdated").unwrap();
    expected[4093..4102].copy_from_slice(b"\0\xffupdated");
    drop(memory);

    assert_eq!(
        std::fs::read(destination.join("memory.bin")).unwrap(),
        expected
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"replacement RAM");
    let (restored, restored_state) = read_snapshot(&destination).unwrap();
    assert_eq!(restored.snapshot_id, manifest.snapshot_id);
    assert_eq!(restored.memory_size_bytes, 8192);
    assert_eq!(restored_state, state);
}
