// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use test_with_tracing::test;

#[derive(Default)]
struct LifecycleFs(Arc<Mutex<Vec<(u32, u64, u64)>>>);

impl Fuse for LifecycleFs {
    fn init(&self, _: &mut SessionInfo) {
        self.0.lock().push((FUSE_INIT, 0, 0));
    }
    fn destroy(&self) {
        self.0.lock().push((FUSE_DESTROY, 0, 0));
    }
    fn forget(&self, node: u64, count: u64) {
        self.0.lock().push((FUSE_FORGET, node, count));
    }
    fn open(&self, _: &Request, _: u32) -> lx::Result<fuse_open_out> {
        Ok(fuse_open_out::new(42, 0))
    }
    fn open_dir(&self, _: &Request, _: u32) -> lx::Result<fuse_open_out> {
        Ok(fuse_open_out::new(43, 0))
    }
    fn create(&self, _: &Request, _: &LxStr, _: &fuse_create_in) -> lx::Result<CreateOut> {
        Ok(CreateOut {
            entry: fuse_entry_out::new_zeroed(),
            open: fuse_open_out::new(44, 0),
        })
    }
    fn release(&self, _: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        assert_eq!((arg.release_flags, arg.lock_owner), (0, 0));
        self.0.lock().push((FUSE_RELEASE, arg.fh, arg.flags.into()));
        Ok(())
    }
    fn release_dir(&self, _: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        assert_eq!((arg.release_flags, arg.lock_owner), (0, 0));
        self.0
            .lock()
            .push((FUSE_RELEASEDIR, arg.fh, arg.flags.into()));
        Ok(())
    }
    fn setup_mapping(
        &self,
        _: &Request,
        _: &dyn Mapper,
        _: &fuse_setupmapping_in,
    ) -> lx::Result<()> {
        panic!("DAX callback invoked without a mapper")
    }
    fn remove_mapping(&self, _: &Request, _: &dyn Mapper, _: u64, _: u64) -> lx::Result<()> {
        panic!("DAX callback invoked without a mapper")
    }
}

#[derive(Default)]
struct ClearMapper(AtomicUsize);
impl Mapper for ClearMapper {
    fn map(&self, _: u64, _: FileRef<'_>, _: u64, _: u64, _: bool) -> lx::Result<()> {
        panic!("unexpected map")
    }
    fn unmap(&self, _: u64, _: u64) -> lx::Result<()> {
        panic!("unexpected unmap")
    }
    fn clear(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Test: Destroy a session with mappings, destroy it again, and initialize it for a second mount.
// Expected: Mappings are cleared, destroy is called once per initialized lifetime, and remount succeeds.
#[test]
fn destroy_clears_mappings_and_allows_a_clean_remount() {
    let fs = LifecycleFs::default();
    let calls = fs.0.clone();
    let session = Session::new(fs);
    let mapper = ClearMapper::default();
    initialize(&session);
    let mut capture = Capture::default();
    session.dispatch(request(FUSE_DESTROY, b""), &mut capture, Some(&mapper));
    assert!(capture.check(0).is_empty());
    assert!(!session.is_initialized());
    assert_eq!(mapper.0.load(Ordering::SeqCst), 1);
    session.destroy();
    assert_eq!(
        calls.lock().as_slice(),
        &[(FUSE_INIT, 0, 0), (FUSE_DESTROY, 0, 0)]
    );
    initialize(&session);
    session.destroy();
    assert_eq!(
        calls.lock().as_slice(),
        &[
            (FUSE_INIT, 0, 0),
            (FUSE_DESTROY, 0, 0),
            (FUSE_INIT, 0, 0),
            (FUSE_DESTROY, 0, 0)
        ]
    );
}

// Test: Deliver ordinary forget and a batch whose advertised count exceeds its complete records.
// Expected: Complete records reach the filesystem in order and neither operation sends a reply.
#[test]
fn forget_messages_preserve_complete_records_without_sending_replies() {
    let fs = LifecycleFs::default();
    let calls = fs.0.clone();
    let session = Session::new(fs);
    initialize(&session);
    calls.lock().clear();
    let mut capture = Capture::default();
    session.dispatch(
        request(FUSE_FORGET, fuse_forget_in { nlookup: 5 }.as_bytes()),
        &mut capture,
        None,
    );
    let records = [
        fuse_forget_one {
            nodeid: 71,
            nlookup: 2,
        }
        .as_bytes(),
        fuse_forget_one {
            nodeid: 73,
            nlookup: 3,
        }
        .as_bytes(),
    ]
    .concat();
    let batch = args(fuse_batch_forget_in { count: 3, dummy: 0 }, &records);
    session.dispatch(request(FUSE_BATCH_FORGET, &batch), &mut capture, None);
    assert!(capture.messages.is_empty());
    assert_eq!(
        calls.lock().as_slice(),
        &[
            (FUSE_FORGET, 27, 5),
            (FUSE_FORGET, 71, 2),
            (FUSE_FORGET, 73, 3)
        ]
    );
}

// Test: Interrupt open, opendir and create while delivering their replies.
// Expected: Each acquired handle is released once with its original flags and no duplicate reply.
#[test]
fn interrupted_handle_replies_release_the_corresponding_file_or_directory() {
    let fs = LifecycleFs::default();
    let calls = fs.0.clone();
    let session = Session::new(fs);
    initialize(&session);
    calls.lock().clear();
    for (opcode, payload, expected) in [
        (
            FUSE_OPEN,
            args(
                fuse_open_in {
                    flags: 2,
                    unused: 0,
                },
                b"",
            ),
            (FUSE_RELEASE, 42, 2),
        ),
        (
            FUSE_OPENDIR,
            args(
                fuse_open_in {
                    flags: 0x10000,
                    unused: 0,
                },
                b"",
            ),
            (FUSE_RELEASEDIR, 43, 0x10000),
        ),
        (
            FUSE_CREATE,
            args(
                fuse_create_in {
                    flags: 2,
                    ..FromZeros::new_zeroed()
                },
                b"entry\0",
            ),
            (FUSE_RELEASE, 44, 2),
        ),
    ] {
        let mut capture = Capture {
            error: Some(io::ErrorKind::NotFound),
            ..Default::default()
        };
        session.dispatch(request(opcode, &payload), &mut capture, None);
        assert_eq!(capture.messages.len(), 1);
        assert_eq!(calls.lock().pop(), Some(expected));
        assert!(calls.lock().is_empty());
    }
}

// Test: Fail an ordinary reply, an error reply, and an open reply for reasons other than interruption.
// Expected: Ordinary/error sends are not retried, failed opens are not released, and later requests still work.
#[test]
fn transport_errors_do_not_retry_requests_or_release_noninterrupted_handles() {
    let fs = LifecycleFs::default();
    let calls = fs.0.clone();
    let session = Session::new(fs);
    initialize(&session);
    calls.lock().clear();
    for kind in [io::ErrorKind::NotFound, io::ErrorKind::BrokenPipe] {
        for (opcode, payload) in [
            (FUSE_SYNCFS, args(fuse_syncfs_in::new_zeroed(), b"")),
            (FUSE_LOOKUP, b"entry\0".to_vec()),
        ] {
            let mut capture = Capture {
                error: Some(kind),
                ..Default::default()
            };
            session.dispatch(request(opcode, &payload), &mut capture, None);
            assert_eq!(capture.messages.len(), 1);
        }
    }
    let mut failed = Capture {
        error: Some(io::ErrorKind::BrokenPipe),
        ..Default::default()
    };
    session.dispatch(
        request(FUSE_OPEN, fuse_open_in::new_zeroed().as_bytes()),
        &mut failed,
        None,
    );
    assert!(calls.lock().is_empty());
    let mut capture = Capture::default();
    session.dispatch(
        request(FUSE_SYNCFS, fuse_syncfs_in::new_zeroed().as_bytes()),
        &mut capture,
        None,
    );
    assert!(capture.check(0).is_empty());
}

// Test: Request DAX setup and removal without a mapper.
// Expected: Both operations return ENOSYS without invoking a filesystem mapping callback.
#[test]
fn dax_operations_require_a_mapper() {
    let session = Session::new(LifecycleFs::default());
    initialize(&session);
    for (opcode, payload) in operations()
        .into_iter()
        .filter(|(opcode, _)| [FUSE_SETUPMAPPING, FUSE_REMOVEMAPPING].contains(opcode))
    {
        let mut capture = Capture::default();
        session.dispatch(request(opcode, &payload), &mut capture, None);
        assert!(capture.check(lx::Error::ENOSYS.value()).is_empty());
    }
}
