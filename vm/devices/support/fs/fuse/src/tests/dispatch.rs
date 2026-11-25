// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;

#[derive(Default)]
struct EchoFs {
    calls: Arc<Mutex<Vec<(u32, Vec<u8>)>>>,
}

impl EchoFs {
    // Observe filesystem API calls, not private session state.
    fn record(&self, opcode: u32, request: &Request, payload: Vec<u8>) {
        assert_eq!(
            (
                request.opcode(),
                request.node_id(),
                request.uid(),
                request.gid(),
                request.pid()
            ),
            (opcode, 27, 101, 202, 303)
        );
        self.calls.lock().push((opcode, payload));
    }
}

fn name_bytes(name: &LxStr) -> Vec<u8> {
    [name.as_bytes(), &[0]].concat()
}

fn entry() -> fuse_entry_out {
    fuse_entry_out::new(
        41,
        Duration::new(3, 17),
        Duration::new(5, 23),
        fuse_attr {
            ino: 41,
            mode: lx::S_IFREG | 0o640,
            size: 8192,
            ..FromZeros::new_zeroed()
        },
    )
}

impl Fuse for EchoFs {
    fn lookup(&self, request: &Request, name: &LxStr) -> lx::Result<fuse_entry_out> {
        self.record(FUSE_LOOKUP, request, name_bytes(name));
        Ok(entry())
    }
    fn get_attr(&self, request: &Request, flags: u32, fh: u64) -> lx::Result<fuse_attr_out> {
        self.record(
            FUSE_GETATTR,
            request,
            args(
                fuse_getattr_in {
                    getattr_flags: flags,
                    dummy: 0,
                    fh,
                },
                b"",
            ),
        );
        Ok(fuse_attr_out::new(Duration::new(5, 23), entry().attr))
    }
    fn set_attr(&self, request: &Request, arg: &fuse_setattr_in) -> lx::Result<fuse_attr_out> {
        self.record(FUSE_SETATTR, request, arg.as_bytes().to_vec());
        Ok(fuse_attr_out::new(Duration::new(5, 23), entry().attr))
    }
    fn read_link(&self, request: &Request) -> lx::Result<LxString> {
        self.record(FUSE_READLINK, request, vec![]);
        Ok("target/path".into())
    }
    fn symlink(
        &self,
        request: &Request,
        name: &LxStr,
        target: &LxStr,
    ) -> lx::Result<fuse_entry_out> {
        self.record(
            FUSE_SYMLINK,
            request,
            [name_bytes(name), name_bytes(target)].concat(),
        );
        Ok(entry())
    }
    fn mknod(
        &self,
        request: &Request,
        name: &LxStr,
        arg: &fuse_mknod_in,
    ) -> lx::Result<fuse_entry_out> {
        self.record(
            FUSE_MKNOD,
            request,
            [arg.as_bytes(), &name_bytes(name)].concat(),
        );
        Ok(entry())
    }
    fn mkdir(
        &self,
        request: &Request,
        name: &LxStr,
        arg: &fuse_mkdir_in,
    ) -> lx::Result<fuse_entry_out> {
        self.record(
            FUSE_MKDIR,
            request,
            [arg.as_bytes(), &name_bytes(name)].concat(),
        );
        Ok(entry())
    }
    fn unlink(&self, request: &Request, name: &LxStr) -> lx::Result<()> {
        self.record(FUSE_UNLINK, request, name_bytes(name));
        Ok(())
    }
    fn rmdir(&self, request: &Request, name: &LxStr) -> lx::Result<()> {
        self.record(FUSE_RMDIR, request, name_bytes(name));
        Ok(())
    }
    fn rename(
        &self,
        request: &Request,
        name: &LxStr,
        new_dir: u64,
        new_name: &LxStr,
        flags: u32,
    ) -> lx::Result<()> {
        let names = [name_bytes(name), name_bytes(new_name)].concat();
        let payload = if request.opcode() == FUSE_RENAME2 {
            args(
                fuse_rename2_in {
                    newdir: new_dir,
                    flags,
                    padding: 0,
                },
                &names,
            )
        } else {
            assert_eq!(flags, 0);
            args(fuse_rename_in { newdir: new_dir }, &names)
        };
        self.record(request.opcode(), request, payload);
        Ok(())
    }
    fn link(&self, request: &Request, name: &LxStr, target: u64) -> lx::Result<fuse_entry_out> {
        self.record(
            FUSE_LINK,
            request,
            args(fuse_link_in { oldnodeid: target }, &name_bytes(name)),
        );
        Ok(entry())
    }
    fn open(&self, request: &Request, flags: u32) -> lx::Result<fuse_open_out> {
        self.record(
            FUSE_OPEN,
            request,
            args(fuse_open_in { flags, unused: 0 }, b""),
        );
        Ok(fuse_open_out::new(42, FOPEN_KEEP_CACHE))
    }
    fn read(&self, request: &Request, arg: &fuse_read_in) -> lx::Result<Vec<u8>> {
        self.record(FUSE_READ, request, arg.as_bytes().to_vec());
        Ok(b"data".to_vec())
    }
    fn write(&self, request: &Request, arg: &fuse_write_in, data: &[u8]) -> lx::Result<usize> {
        self.record(FUSE_WRITE, request, [arg.as_bytes(), data].concat());
        Ok(data.len())
    }
    fn statfs(&self, request: &Request) -> lx::Result<fuse_kstatfs> {
        self.record(FUSE_STATFS, request, vec![]);
        Ok(fuse_kstatfs::new(101, 73, 71, 29, 17, 4096, 255, 512))
    }
    fn release(&self, request: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        self.record(FUSE_RELEASE, request, arg.as_bytes().to_vec());
        Ok(())
    }
    fn fsync(&self, request: &Request, fh: u64, flags: u32) -> lx::Result<()> {
        self.record(
            FUSE_FSYNC,
            request,
            args(
                fuse_fsync_in {
                    fh,
                    fsync_flags: flags,
                    padding: 0,
                },
                b"",
            ),
        );
        Ok(())
    }
    fn set_xattr(
        &self,
        request: &Request,
        name: &LxStr,
        value: &[u8],
        flags: u32,
    ) -> lx::Result<()> {
        self.record(
            FUSE_SETXATTR,
            request,
            args(
                fuse_setxattr_in {
                    size: value.len().try_into().unwrap(),
                    flags,
                },
                &[name_bytes(name), value.to_vec()].concat(),
            ),
        );
        Ok(())
    }
    fn get_xattr(&self, request: &Request, name: &LxStr, size: u32) -> lx::Result<Vec<u8>> {
        self.record(
            FUSE_GETXATTR,
            request,
            args(fuse_getxattr_in { size, padding: 0 }, &name_bytes(name)),
        );
        Ok(b"data".to_vec())
    }
    fn get_xattr_size(&self, request: &Request, name: &LxStr) -> lx::Result<u32> {
        self.record(
            FUSE_GETXATTR,
            request,
            args(
                fuse_getxattr_in {
                    size: 0,
                    padding: 0,
                },
                &name_bytes(name),
            ),
        );
        Ok(4)
    }
    fn list_xattr(&self, request: &Request, size: u32) -> lx::Result<Vec<u8>> {
        self.record(
            FUSE_LISTXATTR,
            request,
            args(fuse_getxattr_in { size, padding: 0 }, b""),
        );
        Ok(b"a\0b\0".to_vec())
    }
    fn list_xattr_size(&self, request: &Request) -> lx::Result<u32> {
        self.record(
            FUSE_LISTXATTR,
            request,
            args(fuse_getxattr_in::new_zeroed(), b""),
        );
        Ok(4)
    }
    fn remove_xattr(&self, request: &Request, name: &LxStr) -> lx::Result<()> {
        self.record(FUSE_REMOVEXATTR, request, name_bytes(name));
        Ok(())
    }
    fn flush(&self, request: &Request, arg: &fuse_flush_in) -> lx::Result<()> {
        self.record(FUSE_FLUSH, request, arg.as_bytes().to_vec());
        Ok(())
    }
    fn open_dir(&self, request: &Request, flags: u32) -> lx::Result<fuse_open_out> {
        self.record(
            FUSE_OPENDIR,
            request,
            args(fuse_open_in { flags, unused: 0 }, b""),
        );
        Ok(fuse_open_out::new(42, FOPEN_KEEP_CACHE))
    }
    fn read_dir(&self, request: &Request, arg: &fuse_read_in) -> lx::Result<Vec<u8>> {
        self.record(FUSE_READDIR, request, arg.as_bytes().to_vec());
        Ok(b"data".to_vec())
    }
    fn release_dir(&self, request: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        self.record(FUSE_RELEASEDIR, request, arg.as_bytes().to_vec());
        Ok(())
    }
    fn fsync_dir(&self, request: &Request, fh: u64, flags: u32) -> lx::Result<()> {
        self.record(
            FUSE_FSYNCDIR,
            request,
            args(
                fuse_fsync_in {
                    fh,
                    fsync_flags: flags,
                    padding: 0,
                },
                b"",
            ),
        );
        Ok(())
    }
    fn get_lock(&self, request: &Request, arg: &fuse_lk_in) -> lx::Result<fuse_file_lock> {
        self.record(FUSE_GETLK, request, arg.as_bytes().to_vec());
        Ok(fuse_file_lock {
            start: 17,
            end: 73,
            lock_type: 1,
            pid: 303,
        })
    }
    fn set_lock(&self, request: &Request, arg: &fuse_lk_in, sleep: bool) -> lx::Result<()> {
        self.record(
            if sleep { FUSE_SETLKW } else { FUSE_SETLK },
            request,
            arg.as_bytes().to_vec(),
        );
        Ok(())
    }
    fn access(&self, request: &Request, mask: u32) -> lx::Result<()> {
        self.record(
            FUSE_ACCESS,
            request,
            args(fuse_access_in { mask, padding: 0 }, b""),
        );
        Ok(())
    }
    fn create(
        &self,
        request: &Request,
        name: &LxStr,
        arg: &fuse_create_in,
    ) -> lx::Result<CreateOut> {
        self.record(
            FUSE_CREATE,
            request,
            [arg.as_bytes(), &name_bytes(name)].concat(),
        );
        Ok(CreateOut {
            entry: entry(),
            open: fuse_open_out::new(42, FOPEN_KEEP_CACHE),
        })
    }
    fn block_map(&self, request: &Request, block: u64, block_size: u32) -> lx::Result<u64> {
        self.record(
            FUSE_BMAP,
            request,
            args(
                fuse_bmap_in {
                    block,
                    blocksize: block_size,
                    padding: 0,
                },
                b"",
            ),
        );
        Ok(73)
    }
    fn ioctl(
        &self,
        request: &Request,
        arg: &fuse_ioctl_in,
        data: &[u8],
    ) -> lx::Result<(i32, Vec<u8>)> {
        self.record(FUSE_IOCTL, request, [arg.as_bytes(), data].concat());
        Ok((17, vec![]))
    }
    fn fallocate(&self, request: &Request, arg: &fuse_fallocate_in) -> lx::Result<()> {
        self.record(FUSE_FALLOCATE, request, arg.as_bytes().to_vec());
        Ok(())
    }
    fn read_dir_plus(&self, request: &Request, arg: &fuse_read_in) -> lx::Result<Vec<u8>> {
        self.record(FUSE_READDIRPLUS, request, arg.as_bytes().to_vec());
        Ok(b"data".to_vec())
    }
    fn lseek(&self, request: &Request, fh: u64, offset: u64, whence: u32) -> lx::Result<u64> {
        self.record(
            FUSE_LSEEK,
            request,
            args(
                fuse_lseek_in {
                    fh,
                    offset,
                    whence,
                    padding: 0,
                },
                b"",
            ),
        );
        Ok(8192)
    }
    fn copy_file_range(
        &self,
        request: &Request,
        arg: &fuse_copy_file_range_in,
    ) -> lx::Result<usize> {
        self.record(FUSE_COPY_FILE_RANGE, request, arg.as_bytes().to_vec());
        Ok(3072)
    }
    fn setup_mapping(
        &self,
        request: &Request,
        _: &dyn Mapper,
        arg: &fuse_setupmapping_in,
    ) -> lx::Result<()> {
        self.record(FUSE_SETUPMAPPING, request, arg.as_bytes().to_vec());
        Ok(())
    }
    fn remove_mapping(
        &self,
        request: &Request,
        _: &dyn Mapper,
        moffset: u64,
        len: u64,
    ) -> lx::Result<()> {
        self.record(
            FUSE_REMOVEMAPPING,
            request,
            args(
                fuse_removemapping_in { count: 1 },
                fuse_removemapping_one { moffset, len }.as_bytes(),
            ),
        );
        Ok(())
    }
    fn get_statx(
        &self,
        request: &Request,
        fh: u64,
        getattr_flags: u32,
        flags: StatxFlags,
        mask: lx::StatExMask,
    ) -> lx::Result<fuse_statx_out> {
        let mut arg = fuse_statx_in::new_zeroed();
        arg.fh = fh;
        arg.getattr_flags = getattr_flags;
        arg.flags = flags;
        arg.mask = mask.into();
        self.record(FUSE_STATX, request, args(arg, b""));
        Ok(fuse_statx_out::new(
            Duration::new(5, 23),
            StatxFlags::new(),
            fuse_statx::new_zeroed(),
        ))
    }
}

// Share the wire round-trip checks while keeping failures scoped to an operation family.
fn assert_dispatches(opcodes: &[u32]) {
    let fs = EchoFs::default();
    let calls = fs.calls.clone();
    let session = Session::new(fs);
    initialize(&session);
    for (opcode, payload) in operations()
        .into_iter()
        .filter(|(opcode, _)| opcodes.contains(opcode))
    {
        calls.lock().clear();
        let mut capture = Capture::default();
        session.dispatch(request(opcode, &payload), &mut capture, Some(&NoMapper));
        let reply = capture.check(0);
        if opcode == FUSE_SYNCFS {
            assert!(calls.lock().is_empty());
        } else {
            assert_eq!(calls.lock().as_slice(), &[(opcode, payload.clone())]);
        }
        match opcode {
            FUSE_LOOKUP | FUSE_SYMLINK | FUSE_MKNOD | FUSE_MKDIR | FUSE_LINK => {
                assert_eq!(reply, entry().as_bytes())
            }
            FUSE_GETATTR | FUSE_SETATTR => assert_eq!(
                reply,
                fuse_attr_out::new(Duration::new(5, 23), entry().attr).as_bytes()
            ),
            FUSE_READLINK => assert_eq!(reply, b"target/path\0"),
            FUSE_OPEN | FUSE_OPENDIR => {
                assert_eq!(reply, fuse_open_out::new(42, FOPEN_KEEP_CACHE).as_bytes())
            }
            FUSE_READ | FUSE_READDIR | FUSE_READDIRPLUS => assert_eq!(reply, b"data"),
            FUSE_WRITE => assert_eq!(
                reply,
                fuse_write_out {
                    size: 4,
                    padding: 0
                }
                .as_bytes()
            ),
            FUSE_COPY_FILE_RANGE => assert_eq!(
                reply,
                fuse_write_out {
                    size: 3072,
                    padding: 0
                }
                .as_bytes()
            ),
            FUSE_STATFS => assert_eq!(
                reply,
                fuse_kstatfs::new(101, 73, 71, 29, 17, 4096, 255, 512).as_bytes()
            ),
            FUSE_GETXATTR | FUSE_LISTXATTR => {
                let arg = fuse_getxattr_in::read_from_prefix(&payload).unwrap().0;
                if arg.size == 0 {
                    assert_eq!(
                        reply,
                        fuse_getxattr_out {
                            size: 4,
                            padding: 0
                        }
                        .as_bytes()
                    );
                } else {
                    assert_eq!(
                        reply,
                        if opcode == FUSE_GETXATTR {
                            b"data"
                        } else {
                            b"a\0b\0"
                        }
                    );
                }
            }
            FUSE_GETLK => assert_eq!(
                reply,
                fuse_file_lock {
                    start: 17,
                    end: 73,
                    lock_type: 1,
                    pid: 303
                }
                .as_bytes()
            ),
            FUSE_CREATE => assert_eq!(
                reply,
                CreateOut {
                    entry: entry(),
                    open: fuse_open_out::new(42, FOPEN_KEEP_CACHE)
                }
                .as_bytes()
            ),
            FUSE_BMAP => assert_eq!(reply, fuse_bmap_out { block: 73 }.as_bytes()),
            FUSE_IOCTL => assert_eq!(
                reply,
                fuse_ioctl_out {
                    result: 17,
                    ..FromZeros::new_zeroed()
                }
                .as_bytes()
            ),
            FUSE_LSEEK => assert_eq!(reply, fuse_lseek_out { offset: 8192 }.as_bytes()),
            FUSE_STATX => assert_eq!(
                reply,
                fuse_statx_out::new(
                    Duration::new(5, 23),
                    StatxFlags::new(),
                    fuse_statx::new_zeroed()
                )
                .as_bytes()
            ),
            _ => assert!(reply.is_empty(), "unexpected payload for opcode {opcode}"),
        }
        assert_eq!(capture.messages.len(), 1);
    }
}

// Test: Dispatch inode creation, names, attributes, links and filesystem statistics.
// Expected: Callbacks receive the original names and arguments, and metadata replies retain their wire layout.
#[test]
fn inode_and_metadata_requests_preserve_arguments_and_replies() {
    assert_dispatches(&[
        FUSE_LOOKUP,
        FUSE_GETATTR,
        FUSE_SETATTR,
        FUSE_READLINK,
        FUSE_SYMLINK,
        FUSE_MKNOD,
        FUSE_MKDIR,
        FUSE_UNLINK,
        FUSE_RMDIR,
        FUSE_RENAME,
        FUSE_LINK,
        FUSE_RENAME2,
        FUSE_STATFS,
        FUSE_STATX,
    ]);
}

// Test: Dispatch file I/O, handle, lock, allocation, seek and copy operations.
// Expected: Field values and blocking-lock mode reach the correct callbacks and results use the expected payloads.
#[test]
fn file_io_handles_and_locks_preserve_arguments_and_replies() {
    assert_dispatches(&[
        FUSE_OPEN,
        FUSE_READ,
        FUSE_WRITE,
        FUSE_RELEASE,
        FUSE_FSYNC,
        FUSE_FLUSH,
        FUSE_GETLK,
        FUSE_SETLK,
        FUSE_SETLKW,
        FUSE_ACCESS,
        FUSE_CREATE,
        FUSE_BMAP,
        FUSE_IOCTL,
        FUSE_FALLOCATE,
        FUSE_LSEEK,
        FUSE_COPY_FILE_RANGE,
    ]);
}

// Test: Dispatch directory open, read, close, synchronization and readdirplus requests.
// Expected: Directory callbacks, rather than file callbacks, receive the handles, offsets and flags.
#[test]
fn directory_operations_use_directory_callbacks_and_payloads() {
    assert_dispatches(&[
        FUSE_OPENDIR,
        FUSE_READDIR,
        FUSE_RELEASEDIR,
        FUSE_FSYNCDIR,
        FUSE_READDIRPLUS,
    ]);
}

// Test: Dispatch xattr size/data queries, changes and removal, plus DAX and sync requests.
// Expected: Size queries are distinct from data queries, values are preserved and successful mappings receive replies.
#[test]
fn xattr_and_mapping_requests_preserve_sizes_values_and_ranges() {
    assert_dispatches(&[
        FUSE_SETXATTR,
        FUSE_GETXATTR,
        FUSE_LISTXATTR,
        FUSE_REMOVEXATTR,
        FUSE_SETUPMAPPING,
        FUSE_REMOVEMAPPING,
        FUSE_SYNCFS,
    ]);
}
