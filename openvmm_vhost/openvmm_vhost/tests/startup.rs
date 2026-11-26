// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public Linux backend process startup and failure isolation.

#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;
use test_with_tracing::test;

// Test: Start the backend with a missing disk in writable and read-only modes.
// Expected: Disk-open failure exits unsuccessfully before touching the supplied
//       socket path or creating the missing disk.
#[test]
fn missing_disk_does_not_touch_socket_path() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let disk = directory.path().join("missing.img");
    let socket = directory.path().join("socket");
    fs::write(&socket, b"existing path must survive disk-open failure").unwrap();
    for mode in [None, Some("--read-only")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openvmm_vhost"));
        command
            .arg("--socket")
            .arg(&socket)
            .arg("blk")
            .arg("--disk")
            .arg(&disk);
        command.args(mode);
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("failed to open disk:"),
            "{output:?}"
        );
        assert!(!disk.exists());
        assert_eq!(
            fs::read(&socket).unwrap(),
            b"existing path must survive disk-open failure"
        );
    }
}

// Test: Resolve a valid disk but bind the backend socket over a directory.
// Expected: Bind failure propagates as a process error without modifying the
//       disk or deleting the directory and its existing contents.
#[test]
fn socket_bind_failure_preserves_disk_and_directory() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let disk = directory.path().join("disk.img");
    let socket = directory.path().join("socket");
    let contents = vec![0xa5; 4096];
    fs::write(&disk, &contents).unwrap();
    fs::create_dir(&socket).unwrap();
    fs::write(socket.join("keep"), b"unrelated data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_openvmm_vhost"))
        .arg("--socket")
        .arg(&socket)
        .arg("blk")
        .arg("--disk")
        .arg(&disk)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("vhost-user server failed"),
        "{output:?}"
    );
    assert_eq!(fs::read(&disk).unwrap(), contents);
    assert_eq!(fs::read(socket.join("keep")).unwrap(), b"unrelated data");
}
