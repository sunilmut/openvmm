// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public Linux pipe and process I/O contracts.

#![cfg(target_os = "linux")]

use pal::unix::pipe::set_nonblocking;
use pal::unix::process::Builder;
use pal::unix::process::Stdio;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use test_with_tracing::test;

fn descriptor_flags(file: &File) -> u32 {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .unwrap();
    u32::from_str_radix(flags.trim(), 8).unwrap()
}

// Test: Toggle a pipe's nonblocking mode, transfer bytes, then close its writer.
// Expected: Empty/live means WouldBlock, buffered bytes survive mode changes,
//       and EOF follows draining; close-on-exec remains set throughout.
#[test]
fn nonblocking_pipe_distinguishes_empty_buffered_and_closed() {
    let (mut read, mut write) = pal::pipe_pair().unwrap();
    assert_ne!(descriptor_flags(&read) & libc::O_CLOEXEC as u32, 0);
    set_nonblocking(&read, true).unwrap();
    assert_ne!(descriptor_flags(&read) & libc::O_NONBLOCK as u32, 0);
    assert_eq!(
        read.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    write.write_all(b"buffered pipe bytes").unwrap();
    set_nonblocking(&read, false).unwrap();
    let flags = descriptor_flags(&read);
    assert_eq!(flags & libc::O_NONBLOCK as u32, 0);
    assert_ne!(flags & libc::O_CLOEXEC as u32, 0);
    drop(write);
    let mut data = Vec::new();
    read.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"buffered pipe bytes");
    assert_eq!(read.read(&mut [0]).unwrap(), 0);
}

// Test: Clear staged/inherited environment and apply replacements/removals
//       while launching through both fork and vfork.
// Expected: The child's actual environment contains only the final requested
//       entry, including its non-UTF-8 bytes.
#[test]
fn child_environment_clear_replace_remove_preserves_raw_bytes() {
    for vfork in [false, true] {
        let (mut read, write) = pal::pipe_pair().unwrap();
        let mut command = Builder::new("/usr/bin/env");
        command
            .args(["-0"])
            .env("PAL_DISCARD", "stale")
            .env_clear()
            .env("PAL_VALUE", "replaced")
            .env("PAL_VALUE", OsString::from_vec(b"value-\xff".to_vec()))
            .env("PAL_REMOVE", "removed")
            .env_remove("PAL_REMOVE")
            .stdin(Stdio::Null)
            .stdout(Stdio::Fd(write.as_fd()))
            .stderr(Stdio::Null)
            .set_vfork(vfork);
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(write);
        let mut data = Vec::new();
        read.read_to_end(&mut data).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(data, b"PAL_VALUE=value-\xff\0");
    }
}

// Test: Supply a raw-byte argv0 and route child output through an explicit fd
//       instead of stdout, then use the original writer in the parent.
// Expected: Both exact child output and parent output arrive; child remapping
//       neither loses the exported descriptor at exec nor consumes its source.
#[test]
fn explicit_fd_and_raw_argv0_survive_exec_without_consuming_parent_source() {
    let (mut read, mut write) = pal::pipe_pair().unwrap();
    let mut command = Builder::new("/bin/sh");
    command
        .arg0(OsString::from_vec(b"worker-\xfe".to_vec()))
        .args(["-c", r#"printf '%s:child' "$0" >&9"#])
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .dup_fd(write.as_fd(), 9);
    let mut child = command.spawn().unwrap();
    assert!(child.wait().unwrap().success());
    drop(command);
    write.write_all(b":parent").unwrap();
    drop(write);
    let mut data = Vec::new();
    read.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"worker-\xfe:child:parent");
}

// Test: Explicitly close a standard descriptor only in the launched child.
// Expected: The child observes stdout absent, not an inherited open handle.
#[test]
fn child_close_fd_is_observable_after_exec() {
    let mut command = Builder::new("/bin/sh");
    command
        .args(["-c", "[ ! -e /proc/self/fd/1 ]"])
        .stdin(Stdio::Null)
        .stderr(Stdio::Null)
        .close_fd(1);
    assert!(command.spawn().unwrap().wait().unwrap().success());
}

// Test: Reject embedded NUL in executable, argument and either environment
//       component, and report a genuinely missing executable separately.
// Expected: NUL inputs fail with InvalidInput rather than truncated execution;
//       the native missing-file error remains NotFound.
#[test]
fn spawn_rejects_nul_without_hiding_native_exec_errors() {
    let nul = OsString::from_vec(b"invalid\0suffix".to_vec());
    let program = Builder::new(nul.clone());
    let mut argument = Builder::new("/usr/bin/true");
    argument.arg(nul.clone());
    let mut key = Builder::new("/usr/bin/true");
    key.env(nul.clone(), "value");
    let mut value = Builder::new("/usr/bin/true");
    value.env("PAL_NUL", nul);
    for command in [program, argument, key, value] {
        assert_eq!(
            command.spawn().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    let directory = tempfile::tempdir_in(".").unwrap();
    assert_eq!(
        Builder::new(directory.path().join("missing"))
            .spawn()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}
