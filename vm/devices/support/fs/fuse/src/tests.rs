// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::io;
use test_with_tracing::test;

mod dispatch;
mod lifecycle;
mod regressions;
mod reply;

#[derive(Default)]
struct Capture {
    messages: Vec<Vec<u8>>,
    error: Option<io::ErrorKind>,
}

impl ReplySender for Capture {
    // Capture the actual vectored wire reply, including failed delivery attempts.
    fn send(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<()> {
        self.messages.push(
            buffers
                .iter()
                .flat_map(|buffer| buffer.iter())
                .copied()
                .collect(),
        );
        match self.error {
            Some(error) => Err(io::Error::from(error)),
            None => Ok(()),
        }
    }
}

impl Capture {
    // Validate framing and correlation before returning the reply payload.
    fn check(&self, error: i32) -> &[u8] {
        let bytes = self.messages.last().expect("a reply must be sent");
        let (header, payload) = fuse_out_header::read_from_prefix(bytes).unwrap();
        assert_eq!(header.len as usize, bytes.len());
        assert_eq!(header.unique, 0x1234);
        assert_eq!(header.error, -error);
        payload
    }
}

struct EmptyFs;
impl Fuse for EmptyFs {}

struct NoMapper;
impl Mapper for NoMapper {
    fn map(&self, _: u64, _: FileRef<'_>, _: u64, _: u64, _: bool) -> lx::Result<()> {
        panic!("this filesystem must not create OS mappings")
    }
    fn unmap(&self, _: u64, _: u64) -> lx::Result<()> {
        panic!("this filesystem must not remove OS mappings")
    }
    fn clear(&self) {}
}

// Encode requests as the guest would, rather than constructing private Request fields.
fn wire(opcode: u32, payload: &[u8]) -> Vec<u8> {
    let header = fuse_in_header {
        len: (size_of::<fuse_in_header>() + payload.len())
            .try_into()
            .unwrap(),
        opcode,
        unique: 0x1234,
        nodeid: 27,
        uid: 101,
        gid: 202,
        pid: 303,
        padding: 0,
    };
    [header.as_bytes(), payload].concat()
}

// Serialize a fixed argument followed by strings or variable-length data.
fn args<T: IntoBytes + Immutable>(arg: T, extra: &[u8]) -> Vec<u8> {
    [arg.as_bytes(), extra].concat()
}

fn request(opcode: u32, payload: &[u8]) -> Request {
    Request::new(wire(opcode, payload).as_slice()).unwrap()
}

fn initialize(session: &Session) {
    let input = fuse_init_in {
        major: 7,
        minor: 39,
        flags: u32::MAX,
        flags2: u32::MAX,
        ..FromZeros::new_zeroed()
    };
    let mut capture = Capture::default();
    session.dispatch(request(FUSE_INIT, input.as_bytes()), &mut capture, None);
    capture.check(0);
    assert!(session.is_initialized());
}

// Nonzero argument values distinguish field swaps and accidental default arguments.
fn operations() -> Vec<(u32, Vec<u8>)> {
    let mut statx = fuse_statx_in::new_zeroed();
    statx.fh = 42;
    statx.getattr_flags = 1;
    statx.mask = 0x7ff;
    vec![
        (FUSE_LOOKUP, b"entry\0".to_vec()),
        (
            FUSE_GETATTR,
            args(
                fuse_getattr_in {
                    getattr_flags: 1,
                    dummy: 0,
                    fh: 42,
                },
                b"",
            ),
        ),
        (
            FUSE_SETATTR,
            args(
                fuse_setattr_in {
                    valid: FATTR_SIZE,
                    size: 8192,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (FUSE_READLINK, vec![]),
        (FUSE_SYMLINK, b"entry\0target/path\0".to_vec()),
        (
            FUSE_MKNOD,
            args(
                fuse_mknod_in {
                    mode: lx::S_IFREG | 0o640,
                    rdev: 17,
                    umask: 0o22,
                    padding: 0,
                },
                b"entry\0",
            ),
        ),
        (
            FUSE_MKDIR,
            args(
                fuse_mkdir_in {
                    mode: 0o750,
                    umask: 0o27,
                },
                b"entry\0",
            ),
        ),
        (FUSE_UNLINK, b"entry\0".to_vec()),
        (FUSE_RMDIR, b"entry\0".to_vec()),
        (
            FUSE_RENAME,
            args(fuse_rename_in { newdir: 73 }, b"entry\0new\0"),
        ),
        (FUSE_LINK, args(fuse_link_in { oldnodeid: 91 }, b"entry\0")),
        (
            FUSE_OPEN,
            args(
                fuse_open_in {
                    flags: lx::O_RDWR as u32,
                    unused: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_READ,
            args(
                fuse_read_in {
                    fh: 42,
                    offset: 19,
                    size: 4,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_WRITE,
            args(
                fuse_write_in {
                    fh: 42,
                    offset: 19,
                    size: 4,
                    ..FromZeros::new_zeroed()
                },
                b"data",
            ),
        ),
        (FUSE_STATFS, vec![]),
        (
            FUSE_RELEASE,
            args(
                fuse_release_in {
                    fh: 42,
                    flags: 2,
                    release_flags: 1,
                    lock_owner: 83,
                },
                b"",
            ),
        ),
        (
            FUSE_FSYNC,
            args(
                fuse_fsync_in {
                    fh: 42,
                    fsync_flags: 1,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_SETXATTR,
            args(fuse_setxattr_in { size: 4, flags: 2 }, b"user.attr\0data"),
        ),
        (
            FUSE_GETXATTR,
            args(
                fuse_getxattr_in {
                    size: 0,
                    padding: 0,
                },
                b"user.attr\0",
            ),
        ),
        (
            FUSE_GETXATTR,
            args(
                fuse_getxattr_in {
                    size: 4,
                    padding: 0,
                },
                b"user.attr\0",
            ),
        ),
        (
            FUSE_LISTXATTR,
            args(
                fuse_getxattr_in {
                    size: 0,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_LISTXATTR,
            args(
                fuse_getxattr_in {
                    size: 4,
                    padding: 0,
                },
                b"",
            ),
        ),
        (FUSE_REMOVEXATTR, b"user.attr\0".to_vec()),
        (
            FUSE_FLUSH,
            args(
                fuse_flush_in {
                    fh: 42,
                    lock_owner: 83,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_OPENDIR,
            args(
                fuse_open_in {
                    flags: lx::O_DIRECTORY as u32,
                    unused: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_READDIR,
            args(
                fuse_read_in {
                    fh: 42,
                    offset: 19,
                    size: 4,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_RELEASEDIR,
            args(
                fuse_release_in {
                    fh: 42,
                    flags: 2,
                    release_flags: 1,
                    lock_owner: 83,
                },
                b"",
            ),
        ),
        (
            FUSE_FSYNCDIR,
            args(
                fuse_fsync_in {
                    fh: 42,
                    fsync_flags: 1,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_GETLK,
            args(
                fuse_lk_in {
                    fh: 42,
                    owner: 83,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_SETLK,
            args(
                fuse_lk_in {
                    fh: 42,
                    owner: 83,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_SETLKW,
            args(
                fuse_lk_in {
                    fh: 42,
                    owner: 83,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_ACCESS,
            args(
                fuse_access_in {
                    mask: 6,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_CREATE,
            args(
                fuse_create_in {
                    flags: 2,
                    mode: 0o640,
                    umask: 0o27,
                    padding: 0,
                },
                b"entry\0",
            ),
        ),
        (FUSE_INTERRUPT, args(fuse_interrupt_in { unique: 97 }, b"")),
        (
            FUSE_BMAP,
            args(
                fuse_bmap_in {
                    block: 11,
                    blocksize: 4096,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_IOCTL,
            args(
                fuse_ioctl_in {
                    fh: 42,
                    cmd: 73,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (FUSE_POLL, args(fuse_poll_in::new_zeroed(), b"")),
        (
            FUSE_NOTIFY_REPLY,
            args(fuse_notify_retrieve_in::new_zeroed(), b""),
        ),
        (
            FUSE_FALLOCATE,
            args(
                fuse_fallocate_in {
                    fh: 42,
                    offset: 19,
                    length: 4096,
                    mode: 1,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_READDIRPLUS,
            args(
                fuse_read_in {
                    fh: 42,
                    offset: 19,
                    size: 4,
                    ..FromZeros::new_zeroed()
                },
                b"",
            ),
        ),
        (
            FUSE_RENAME2,
            args(
                fuse_rename2_in {
                    newdir: 73,
                    flags: 2,
                    padding: 0,
                },
                b"entry\0new\0",
            ),
        ),
        (
            FUSE_LSEEK,
            args(
                fuse_lseek_in {
                    fh: 42,
                    offset: 19,
                    whence: 3,
                    padding: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_COPY_FILE_RANGE,
            args(
                fuse_copy_file_range_in {
                    fh_in: 42,
                    off_in: 19,
                    nodeid_out: 73,
                    fh_out: 84,
                    off_out: 101,
                    len: 4096,
                    flags: 0,
                },
                b"",
            ),
        ),
        (
            FUSE_SETUPMAPPING,
            args(
                fuse_setupmapping_in {
                    fh: 42,
                    foffset: 19,
                    len: 4096,
                    flags: 1,
                    moffset: 8192,
                },
                b"",
            ),
        ),
        (
            FUSE_REMOVEMAPPING,
            args(
                fuse_removemapping_in { count: 1 },
                fuse_removemapping_one {
                    moffset: 8192,
                    len: 4096,
                }
                .as_bytes(),
            ),
        ),
        (FUSE_SYNCFS, args(fuse_syncfs_in::new_zeroed(), b"")),
        (FUSE_STATX, args(statx, b"")),
        (FUSE_CANONICAL_PATH, vec![]),
    ]
}

// Test: Dispatch implemented protocol operations to a filesystem that uses the default callbacks.
// Expected: Unsupported operations return ENOSYS; release and sync operations succeed with empty replies.
#[test]
fn default_filesystem_preserves_optional_operation_fallbacks() {
    let session = Session::new(EmptyFs);
    initialize(&session);
    for (opcode, payload) in operations() {
        let mut capture = Capture::default();
        session.dispatch(request(opcode, &payload), &mut capture, Some(&NoMapper));
        let expected = if [FUSE_RELEASE, FUSE_RELEASEDIR, FUSE_SYNCFS].contains(&opcode) {
            0
        } else {
            lx::Error::ENOSYS.value()
        };
        assert!(capture.check(expected).is_empty(), "opcode {opcode}");
        assert_eq!(capture.messages.len(), 1);
    }
}

// Test: Send an operation before INIT, malformed packets after INIT, and a duplicate INIT.
// Expected: The protocol errors are reported without losing the initialized session.
#[test]
fn malformed_and_out_of_sequence_messages_do_not_poison_session() {
    let session = Session::new(EmptyFs);
    let mut capture = Capture::default();
    session.dispatch(request(FUSE_READLINK, b""), &mut capture, None);
    capture.check(lx::Error::EIO.value());
    assert!(!session.is_initialized());
    initialize(&session);
    let mut bytes = wire(FUSE_LOOKUP, b"entry\0");
    bytes[..4].copy_from_slice(&4096u32.to_ne_bytes());
    session.dispatch(Request::new(bytes.as_slice()).unwrap(), &mut capture, None);
    capture.check(lx::Error::EIO.value());
    session.dispatch(request(FUSE_LOOKUP, b"bad/name\0"), &mut capture, None);
    capture.check(lx::Error::EINVAL.value());
    session.dispatch(request(FUSE_LOOKUP, b"unterminated"), &mut capture, None);
    capture.check(lx::Error::EINVAL.value());
    let init = fuse_init_in {
        major: 7,
        minor: 39,
        ..FromZeros::new_zeroed()
    };
    session.dispatch(request(FUSE_INIT, init.as_bytes()), &mut capture, None);
    capture.check(lx::Error::EIO.value());
    assert!(session.is_initialized());
    session.dispatch(
        request(FUSE_SYNCFS, fuse_syncfs_in::new_zeroed().as_bytes()),
        &mut capture,
        None,
    );
    capture.check(0);
}
