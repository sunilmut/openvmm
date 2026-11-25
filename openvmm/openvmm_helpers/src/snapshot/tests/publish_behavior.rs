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
