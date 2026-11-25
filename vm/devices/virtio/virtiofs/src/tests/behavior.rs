// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::LxVolumeOptions;
use crate::VirtioFs;
use crate::test_helpers::decode_dir_entries;
use fuse::CreateOut;
use fuse::Fuse;
use fuse::Request;
use fuse::protocol::*;
use pal_async::DefaultDriver;
use pal_async::async_test;
use std::os::unix::fs::MetadataExt;
use test_with_tracing::test;
use virtio::VirtioDevice;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

fn request(node_id: u64) -> Request {
    let header = fuse_in_header {
        len: (size_of::<fuse_in_header>() + 6) as u32,
        opcode: FUSE_LOOKUP,
        unique: 1,
        nodeid: node_id,
        ..fuse_in_header::new_zeroed()
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(b"entry\0");
    Request::new(bytes.as_slice()).unwrap()
}

fn create(fs: &VirtioFs, parent: u64, name: &str) -> CreateOut {
    fs.create(
        &request(parent),
        name.as_ref(),
        &fuse_create_in {
            flags: (lx::O_CREAT | lx::O_EXCL | lx::O_RDWR) as u32,
            mode: 0o600,
            ..fuse_create_in::new_zeroed()
        },
    )
    .unwrap()
}

fn release(fs: &VirtioFs, node: u64, fh: u64) {
    fs.release(
        &request(node),
        &fuse_release_in {
            fh,
            ..fuse_release_in::new_zeroed()
        },
    )
    .unwrap();
}

// Test: Create a file, write at an offset, read through EOF, sync and release it.
// Expected: Guest and host see the same bytes; releasing invalidates only that handle.
#[test]
fn file_io_preserves_offsets_and_released_handles_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let created = create(&fs, FUSE_ROOT_ID, "data");
    let req = request(created.entry.nodeid);
    let fh = created.open.fh;
    assert_eq!(
        fs.write(
            &req,
            &fuse_write_in {
                fh,
                offset: 3,
                size: 4,
                ..fuse_write_in::new_zeroed()
            },
            b"data",
        )
        .unwrap(),
        4
    );
    let arg = fuse_read_in {
        fh,
        size: 30,
        ..fuse_read_in::new_zeroed()
    };
    assert_eq!(fs.read(&req, &arg).unwrap(), b"\0\0\0data");
    assert_eq!(
        std::fs::read(root.path().join("data")).unwrap(),
        b"\0\0\0data"
    );
    assert!(
        fs.read(&req, &fuse_read_in { offset: 100, ..arg })
            .unwrap()
            .is_empty()
    );
    for flags in [0, FUSE_FSYNC_FDATASYNC] {
        fs.fsync(&req, fh, flags).unwrap();
    }
    release(&fs, created.entry.nodeid, fh);
    assert_eq!(fs.read(&req, &arg).unwrap_err(), lx::Error::EBADF);
    assert_eq!(fs.fsync(&req, fh, 0).unwrap_err(), lx::Error::EBADF);
}

// Test: Change inode metadata, unlink the file, then use its live handle.
// Expected: Mode/times/size match the host; handle metadata survives unlink and truncation.
#[test]
fn metadata_routes_by_inode_or_live_handle_after_unlink() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let created = create(&fs, FUSE_ROOT_ID, "data");
    let req = request(created.entry.nodeid);
    let host = std::fs::metadata(root.path().join("data")).unwrap();
    let attr = fs
        .set_attr(
            &req,
            &fuse_setattr_in {
                valid: FATTR_MODE | FATTR_SIZE | FATTR_UID | FATTR_GID | FATTR_ATIME | FATTR_MTIME,
                mode: 0o640,
                size: 9,
                uid: host.uid(),
                gid: host.gid(),
                atime: 1_600_000_000,
                atimensec: 123_456_789,
                mtime: 1_600_000_001,
                mtimensec: 234_567_890,
                ..fuse_setattr_in::new_zeroed()
            },
        )
        .unwrap()
        .attr;
    assert_eq!(attr.mode & 0o777, 0o640);
    assert_eq!(attr.size, 9);
    assert_eq!((attr.atime, attr.atimensec), (1_600_000_000, 123_456_789));
    assert_eq!((attr.mtime, attr.mtimensec), (1_600_000_001, 234_567_890));
    let sx = fs
        .get_statx(&req, 0, 0, StatxFlags::new(), lx::StatExMask::new())
        .unwrap()
        .statx;
    assert_eq!(sx.ino, attr.ino);
    assert_eq!(sx.size, 9);
    assert_eq!(sx.mode as u32 & 0o777, 0o640);
    let host = std::fs::metadata(root.path().join("data")).unwrap();
    assert_eq!(host.len(), 9);
    assert_eq!(host.mtime(), 1_600_000_001);
    assert_eq!(host.mtime_nsec(), 234_567_890);

    fs.unlink(&request(FUSE_ROOT_ID), "data".as_ref()).unwrap();
    assert_eq!(fs.get_attr(&req, 0, 0).unwrap_err(), lx::Error::ENOENT);
    let attr = fs
        .get_attr(&req, FUSE_GETATTR_FH, created.open.fh)
        .unwrap()
        .attr;
    assert_eq!(attr.size, 9);
    let attr = fs
        .set_attr(
            &req,
            &fuse_setattr_in {
                valid: FATTR_FH | FATTR_SIZE,
                fh: created.open.fh,
                size: 2,
                ..fuse_setattr_in::new_zeroed()
            },
        )
        .unwrap()
        .attr;
    assert_eq!(attr.size, 2);
    assert_eq!(
        fs.get_statx(
            &req,
            created.open.fh,
            FUSE_GETATTR_FH,
            StatxFlags::new(),
            lx::StatExMask::new(),
        )
        .unwrap()
        .statx
        .size,
        2
    );
    release(&fs, created.entry.nodeid, created.open.fh);
}

// Test: Create and rename a directory, enumerate it through FUSE, then remove it.
// Expected: Host paths and guest names agree; removed directories and handles disappear.
#[test]
fn directory_mutations_and_enumeration_follow_host_namespace() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let req = request(FUSE_ROOT_ID);
    let dir = fs
        .mkdir(
            &req,
            "before".as_ref(),
            &fuse_mkdir_in {
                mode: 0o700,
                ..fuse_mkdir_in::new_zeroed()
            },
        )
        .unwrap();
    let file = create(&fs, dir.nodeid, "child");
    release(&fs, file.entry.nodeid, file.open.fh);
    fs.rename(&req, "before".as_ref(), FUSE_ROOT_ID, "after".as_ref(), 0)
        .unwrap();
    assert!(!root.path().join("before").exists());
    assert!(root.path().join("after").join("child").exists());
    let dir = fs.lookup(&req, "after".as_ref()).unwrap();
    let dir_req = request(dir.nodeid);
    let opened = fs.open_dir(&dir_req, lx::O_RDONLY as u32).unwrap();
    let read = fuse_read_in {
        fh: opened.fh,
        size: 4096,
        ..fuse_read_in::new_zeroed()
    };
    let entries = decode_dir_entries(&fs.read_dir_plus(&dir_req, &read).unwrap());
    assert!(
        entries
            .iter()
            .any(|entry| entry.name == "child" && entry.node_id == file.entry.nodeid)
    );
    assert!(!fs.read_dir(&dir_req, &read).unwrap().is_empty());
    fs.fsync_dir(&dir_req, opened.fh, 0).unwrap();
    fs.release_dir(
        &dir_req,
        &fuse_release_in {
            fh: opened.fh,
            ..fuse_release_in::new_zeroed()
        },
    )
    .unwrap();
    assert_eq!(fs.read_dir(&dir_req, &read).unwrap_err(), lx::Error::EBADF);
    assert_eq!(
        fs.rmdir(&req, "after".as_ref()).unwrap_err(),
        lx::Error::ENOTEMPTY
    );
    fs.unlink(&dir_req, "child".as_ref()).unwrap();
    fs.rmdir(&req, "after".as_ref()).unwrap();
    assert!(!root.path().join("after").exists());
}

// Test: Create hard links, symbolic links and an unprivileged FIFO through FUSE.
// Expected: Hard links share identity, symlink targets stay verbatim, FIFO type survives.
#[test]
fn links_and_fifo_nodes_preserve_identity_and_type() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let req = request(FUSE_ROOT_ID);
    let original = create(&fs, FUSE_ROOT_ID, "original");
    let hard = fs
        .link(&req, "hard".as_ref(), original.entry.nodeid)
        .unwrap();
    assert_eq!(hard.nodeid, original.entry.nodeid);
    assert_eq!(hard.attr.ino, original.entry.attr.ino);
    assert_eq!(hard.attr.nlink, 2);
    assert_eq!(
        std::fs::metadata(root.path().join("hard")).unwrap().ino(),
        std::fs::metadata(root.path().join("original"))
            .unwrap()
            .ino()
    );
    let symbolic = fs
        .symlink(&req, "symbolic".as_ref(), "../outside".as_ref())
        .unwrap();
    assert_eq!(
        fs.read_link(&request(symbolic.nodeid)).unwrap(),
        "../outside"
    );
    assert_eq!(
        std::fs::read_link(root.path().join("symbolic")).unwrap(),
        std::path::Path::new("../outside")
    );
    let fifo = fs
        .mknod(
            &req,
            "fifo".as_ref(),
            &fuse_mknod_in {
                mode: lx::S_IFIFO | 0o600,
                ..fuse_mknod_in::new_zeroed()
            },
        )
        .unwrap();
    assert_eq!(fifo.attr.mode & lx::S_IFMT, lx::S_IFIFO);
    assert_eq!(
        std::fs::symlink_metadata(root.path().join("fifo"))
            .unwrap()
            .mode()
            & lx::S_IFMT,
        lx::S_IFIFO
    );
    release(&fs, original.entry.nodeid, original.open.fh);
}

// Test: Set, size, list, replace and remove user xattrs, including short buffers.
// Expected: Binary values round-trip, lists are NUL-delimited and errno is preserved.
#[test]
fn xattr_round_trips_and_size_errors_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let created = create(&fs, FUSE_ROOT_ID, "data");
    let req = request(created.entry.nodeid);
    let name = "user.binary".as_ref();
    fs.set_xattr(&req, name, b"a\0b\xff", 1).unwrap();
    assert_eq!(fs.get_xattr_size(&req, name).unwrap(), 4);
    assert_eq!(fs.get_xattr(&req, name, 32).unwrap(), b"a\0b\xff");
    assert_eq!(fs.get_xattr(&req, name, 2).unwrap_err(), lx::Error::ERANGE);
    assert_eq!(
        fs.set_xattr(&req, name, b"no", 1).unwrap_err(),
        lx::Error::EEXIST
    );
    let size = fs.list_xattr_size(&req).unwrap();
    let names = fs.list_xattr(&req, size).unwrap();
    assert_eq!(names.len(), size as usize);
    assert_eq!(names.last(), Some(&0));
    assert!(
        names
            .split(|&byte| byte == 0)
            .any(|name| name == b"user.binary")
    );
    assert_eq!(fs.list_xattr(&req, 1).unwrap_err(), lx::Error::ERANGE);
    fs.set_xattr(&req, name, b"replacement", 2).unwrap();
    assert_eq!(fs.get_xattr(&req, name, 32).unwrap(), b"replacement");
    fs.remove_xattr(&req, name).unwrap();
    assert_eq!(
        fs.get_xattr_size(&req, name).unwrap_err(),
        lx::Error::ENODATA
    );
    assert_eq!(fs.remove_xattr(&req, name).unwrap_err(), lx::Error::ENODATA);
    release(&fs, created.entry.nodeid, created.open.fh);
}

// Test: Open a read-only share for reading, then attempt file and namespace writes.
// Expected: Reads succeed; mutations return EROFS and leave the host file unchanged.
#[test]
fn readonly_share_rejects_mutations_but_allows_reads() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("data"), b"original").unwrap();
    let mut options = LxVolumeOptions::default();
    options.readonly(true);
    let fs = VirtioFs::new(root.path(), Some(&options)).unwrap();
    let req = request(FUSE_ROOT_ID);
    let entry = fs.lookup(&req, "data".as_ref()).unwrap();
    let file_req = request(entry.nodeid);
    let opened = fs.open(&file_req, lx::O_RDONLY as u32).unwrap();
    let read = fuse_read_in {
        fh: opened.fh,
        size: 32,
        ..fuse_read_in::new_zeroed()
    };
    assert_eq!(fs.read(&file_req, &read).unwrap(), b"original");
    for flags in [lx::O_WRONLY, lx::O_RDWR, lx::O_RDONLY | lx::O_TRUNC] {
        assert_eq!(
            fs.open(&file_req, flags as u32).unwrap_err(),
            lx::Error::EROFS
        );
    }
    assert_eq!(
        fs.write(
            &file_req,
            &fuse_write_in {
                fh: opened.fh,
                ..fuse_write_in::new_zeroed()
            },
            b"changed",
        )
        .unwrap_err(),
        lx::Error::EROFS
    );
    for valid in [FATTR_SIZE, FATTR_SIZE | FATTR_FH] {
        assert_eq!(
            fs.set_attr(
                &file_req,
                &fuse_setattr_in {
                    valid,
                    fh: opened.fh,
                    size: 0,
                    ..fuse_setattr_in::new_zeroed()
                },
            )
            .unwrap_err(),
            lx::Error::EROFS
        );
    }
    for error in [
        fs.unlink(&req, "data".as_ref()).err(),
        fs.rename(&req, "data".as_ref(), FUSE_ROOT_ID, "renamed".as_ref(), 0)
            .err(),
        fs.link(&req, "linked".as_ref(), entry.nodeid).err(),
        fs.symlink(&req, "sym".as_ref(), "data".as_ref()).err(),
        fs.set_xattr(&file_req, "user.a".as_ref(), b"value", 0)
            .err(),
        fs.remove_xattr(&file_req, "user.a".as_ref()).err(),
    ] {
        assert_eq!(error, Some(lx::Error::EROFS));
    }
    assert_eq!(
        std::fs::read(root.path().join("data")).unwrap(),
        b"original"
    );
    assert!(!root.path().join("renamed").exists());
    release(&fs, entry.nodeid, opened.fh);
}

// Test: Exercise the synthetic aggregate root through the public FUSE callbacks.
// Expected: It is a read-only directory with dot entries, stable metadata and no xattrs.
#[test]
fn synthetic_root_public_callbacks_preserve_readonly_directory_contract() {
    let fs = VirtioFs::new_aggregate();
    let req = request(FUSE_ROOT_ID);
    let opened = fs.open_dir(&req, lx::O_RDONLY as u32).unwrap();
    let attr = fs.get_attr(&req, FUSE_GETATTR_FH, opened.fh).unwrap().attr;
    assert_eq!(attr.ino, FUSE_ROOT_ID);
    assert_eq!(attr.mode & lx::S_IFMT, lx::S_IFDIR);
    let sx = fs
        .get_statx(
            &req,
            opened.fh,
            FUSE_GETATTR_FH,
            StatxFlags::new(),
            lx::StatExMask::new(),
        )
        .unwrap()
        .statx;
    assert_eq!(sx.ino, FUSE_ROOT_ID);
    let read = fuse_read_in {
        fh: opened.fh,
        size: 4096,
        ..fuse_read_in::new_zeroed()
    };
    let entries = decode_dir_entries(&fs.read_dir_plus(&req, &read).unwrap());
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        [".", ".."]
    );
    assert!(!fs.read_dir(&req, &read).unwrap().is_empty());
    assert_eq!(fs.list_xattr_size(&req).unwrap(), 0);
    assert!(fs.list_xattr(&req, 16).unwrap().is_empty());
    assert_eq!(
        fs.get_xattr_size(&req, "user.a".as_ref()).unwrap_err(),
        lx::Error::ENODATA
    );
    assert_eq!(
        fs.get_xattr(&req, "user.a".as_ref(), 16).unwrap_err(),
        lx::Error::ENODATA
    );
    let stats = fs.statfs(&req).unwrap();
    assert_eq!(stats.namelen, 255);
    for error in [
        fs.set_attr(&req, &fuse_setattr_in::new_zeroed()).err(),
        fs.unlink(&req, "a".as_ref()).err(),
        fs.rmdir(&req, "a".as_ref()).err(),
        fs.rename(&req, "a".as_ref(), FUSE_ROOT_ID, "b".as_ref(), 0)
            .err(),
        fs.link(&req, "a".as_ref(), FUSE_ROOT_ID).err(),
        fs.symlink(&req, "a".as_ref(), "b".as_ref()).err(),
        fs.mkdir(&req, "a".as_ref(), &fuse_mkdir_in::new_zeroed())
            .err(),
        fs.mknod(&req, "a".as_ref(), &fuse_mknod_in::new_zeroed())
            .err(),
        fs.create(&req, "a".as_ref(), &fuse_create_in::new_zeroed())
            .err(),
        fs.set_xattr(&req, "user.a".as_ref(), b"value", 0).err(),
        fs.remove_xattr(&req, "user.a".as_ref()).err(),
    ] {
        assert_eq!(error, Some(lx::Error::EROFS));
    }
    fs.release_dir(
        &req,
        &fuse_release_in {
            fh: opened.fh,
            ..fuse_release_in::new_zeroed()
        },
    )
    .unwrap();
}

// Test: Query host filesystem capacity through the direct-share FUSE callback.
// Expected: Block geometry is nonzero and free/available space cannot exceed capacity.
#[test]
fn statfs_reports_consistent_host_capacity() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let stats = fs.statfs(&request(FUSE_ROOT_ID)).unwrap();
    assert!(stats.blocks > 0);
    assert!(stats.bsize > 0);
    assert!(stats.frsize > 0);
    assert!(stats.bfree <= stats.blocks);
    assert!(stats.bavail <= stats.bfree);
    assert!(stats.namelen >= 255);
}

// Test: Read a truncated mount tag and queue count through guest config registers.
// Expected: Byte order and layout are exact; unknown writes cannot change read-only config.
#[async_test]
async fn config_registers_expose_exact_tag_and_queue_layout(driver: DefaultDriver) {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut device = crate::virtio::VirtioFsDevice::new(
        &source,
        "abcdefghijklmnopqrstuvwxyz0123456789extra",
        fs,
        crate::virtio::VirtioFsDeviceOptions {
            num_request_queues: Some(3),
            ..Default::default()
        },
    );
    let mut expected = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
    expected.extend_from_slice(&3u32.to_le_bytes());
    for (index, word) in expected.chunks_exact(4).enumerate() {
        let value = device.read_registers_u32((index * 4) as u16).await;
        assert_eq!(value.to_le_bytes(), word);
    }
    assert_eq!(
        device.traits().device_register_length,
        expected.len() as u32
    );
    assert_eq!(device.traits().max_queues, 4);
    assert_eq!(device.read_registers_u32(40).await, 0);
    assert_eq!(device.read_registers_u32(u16::MAX - 3).await, 0);
    device.write_registers_u32(0, !0).await;
    device.write_registers_u32(36, 0).await;
    assert_eq!(device.read_registers_u32(0).await.to_le_bytes(), *b"abcd");
    assert_eq!(device.read_registers_u32(36).await, 3);
}

// IGNORED: Guest timestamp overflow currently panics in Duration::new.
//
// Test: Set an access timestamp whose nanosecond carry overflows its seconds.
// Expected: The unrepresentable guest timestamp returns an error, never a panic.
#[test]
#[ignore = "product bug: overflowing guest timestamps panic in Duration::new"]
fn overflowing_guest_timestamp_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let fs = VirtioFs::new(root.path(), None).unwrap();
    let created = create(&fs, FUSE_ROOT_ID, "data");
    let result = fs.set_attr(
        &request(created.entry.nodeid),
        &fuse_setattr_in {
            valid: FATTR_ATIME,
            atime: u64::MAX,
            atimensec: 1_000_000_000,
            ..fuse_setattr_in::new_zeroed()
        },
    );
    assert!(
        result.is_err(),
        "unrepresentable timestamps must be rejected"
    );
}
