// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::IoError;
use test_with_tracing::test;

#[derive(Clone, Copy)]
enum ReadAction {
    Ok(u32),
    Err(IoError),
    Defer,
}

#[derive(Clone, Copy)]
enum WriteAction {
    Ok,
    Err(IoError),
    Defer,
}

struct DeferredCallbacks {
    read_action: ReadAction,
    write_action: WriteAction,
    pending_read: Option<DeferredRead>,
    pending_write: Option<DeferredWrite>,
    reads: Vec<PciConfigAddress>,
    writes: Vec<(PciConfigAddress, u32)>,
}

impl DeferredCallbacks {
    fn new(read_action: ReadAction, write_action: WriteAction) -> Self {
        Self {
            read_action,
            write_action,
            pending_read: None,
            pending_write: None,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    fn complete_read(&mut self, value: u32) {
        self.pending_read
            .take()
            .unwrap()
            .complete(&value.as_bytes()[..4]);
    }

    fn complete_read_error(&mut self, error: IoError) {
        self.pending_read.take().unwrap().complete_error(error);
    }

    fn complete_write(&mut self) {
        self.pending_write.take().unwrap().complete();
    }

    fn complete_write_error(&mut self, error: IoError) {
        self.pending_write.take().unwrap().complete_error(error);
    }
}

impl PciBusCfgAccessCallbacks for DeferredCallbacks {
    fn read(&mut self, addr: PciConfigAddress, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
        self.reads.push(addr);
        match self.read_action {
            ReadAction::Ok(read_value) => {
                value.set(read_value);
                IoResult::Ok
            }
            ReadAction::Err(error) => IoResult::Err(error),
            ReadAction::Defer => {
                let (deferred, token) = defer_read();
                assert!(self.pending_read.replace(deferred).is_none());
                IoResult::Defer(token)
            }
        }
    }

    fn write(&mut self, addr: PciConfigAddress, value: ByteEnabledDwordWrite) -> IoResult {
        self.writes.push((addr, value.extract()));
        match self.write_action {
            WriteAction::Ok => IoResult::Ok,
            WriteAction::Err(error) => IoResult::Err(error),
            WriteAction::Defer => {
                let (deferred, token) = defer_write();
                assert!(self.pending_write.replace(deferred).is_none());
                IoResult::Defer(token)
            }
        }
    }
}

fn poll_once(handler: &mut PciBusCfgAccessHandler) {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    handler.poll(&mut cx);
}

fn poll_read_token(token: &mut DeferredToken, bytes: &mut [u8]) -> Poll<Result<(), IoError>> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    token.poll_read(&mut cx, bytes)
}

fn poll_write_token(token: &mut DeferredToken) -> Poll<Result<(), IoError>> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    token.poll_write(&mut cx)
}

#[test]
fn immediate_read_applies_byte_enable() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Ok(0x1122_3344), WriteAction::Ok);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let mut buffer = 0xffff_ffff;
    let value = ByteEnabledDwordRead::new(&mut buffer, PciConfigByteEnable::HIGH_WORD);

    assert!(matches!(
        handler.read(addr, value, &mut callbacks),
        IoResult::Ok
    ));
    assert_eq!(callbacks.reads, vec![addr]);
    assert_eq!(buffer, 0x1122_ffff);
}

#[test]
fn immediate_read_error_is_returned() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks =
        DeferredCallbacks::new(ReadAction::Err(IoError::InvalidRegister), WriteAction::Ok);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let mut buffer = 0;
    let value = ByteEnabledDwordRead::with_all_bytes_enabled(&mut buffer);

    assert!(matches!(
        handler.read(addr, value, &mut callbacks),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(callbacks.reads, vec![addr]);
}

#[test]
fn deferred_read_applies_byte_enable() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Defer, WriteAction::Ok);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let mut buffer = 0xffff_ffff;
    let value = ByteEnabledDwordRead::new(&mut buffer, PciConfigByteEnable::HIGH_WORD);

    let IoResult::Defer(mut bus_token) = handler.read(addr, value, &mut callbacks) else {
        panic!("read should defer");
    };

    callbacks.complete_read(0x1122_3344);
    poll_once(&mut handler);

    let mut read_data = [0; 2];
    assert!(matches!(
        poll_read_token(&mut bus_token, &mut read_data),
        Poll::Ready(Ok(()))
    ));

    assert_eq!(read_data, [0x22, 0x11]);
}

#[test]
fn deferred_read_error_completes_outer_read_with_error() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Defer, WriteAction::Ok);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let mut buffer = 0;
    let value = ByteEnabledDwordRead::with_all_bytes_enabled(&mut buffer);

    let IoResult::Defer(mut bus_token) = handler.read(addr, value, &mut callbacks) else {
        panic!("read should defer");
    };

    callbacks.complete_read_error(IoError::NoResponse);
    poll_once(&mut handler);

    let mut read_data = [0; 4];
    assert!(matches!(
        poll_read_token(&mut bus_token, &mut read_data),
        Poll::Ready(Err(IoError::NoResponse))
    ));
}

#[test]
fn partial_writes_do_not_read_for_write() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Ok(0x1122_3344), WriteAction::Ok);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let write_value = ByteEnabledDwordWrite::new(0xaa00, PciConfigByteEnable::BYTE1);

    assert!(matches!(
        handler.write(addr, write_value, &mut callbacks),
        IoResult::Ok
    ));
    assert_eq!(callbacks.reads, vec![]);
    assert_eq!(callbacks.writes, vec![(addr, 0x0000_aa00)]);
}

#[test]
fn immediate_write_error_is_returned() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(
        ReadAction::Ok(0x1122_3344),
        WriteAction::Err(IoError::InvalidRegister),
    );
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let write_value = ByteEnabledDwordWrite::new(0xaa00, PciConfigByteEnable::BYTE1);

    assert!(matches!(
        handler.write(addr, write_value, &mut callbacks),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(callbacks.writes, vec![(addr, 0x0000_aa00)]);
}

#[test]
fn deferred_writes_complete_outer_write() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Ok(0), WriteAction::Defer);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let write_value = ByteEnabledDwordWrite::with_all_bytes_enabled(0xaabb_ccdd);

    let IoResult::Defer(mut bus_token) = handler.write(addr, write_value, &mut callbacks) else {
        panic!("write should defer");
    };

    callbacks.complete_write();
    poll_once(&mut handler);

    assert!(matches!(
        poll_write_token(&mut bus_token),
        Poll::Ready(Ok(()))
    ));
}

#[test]
fn deferred_write_error_completes_outer_write_with_error() {
    let mut handler = PciBusCfgAccessHandler::new();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Ok(0), WriteAction::Defer);
    let addr = PciConfigAddress::new(0, 0, 1).unwrap();
    let write_value = ByteEnabledDwordWrite::with_all_bytes_enabled(0xaabb_ccdd);

    let IoResult::Defer(mut bus_token) = handler.write(addr, write_value, &mut callbacks) else {
        panic!("write should defer");
    };

    callbacks.complete_write_error(IoError::NoResponse);
    poll_once(&mut handler);

    assert!(matches!(
        poll_write_token(&mut bus_token),
        Poll::Ready(Err(IoError::NoResponse))
    ));
}

// Test: Poll mixed deferred reads/writes before completion, then finish the write first.
// Expected: Wakeups occur, pending work survives polls, masked data completes, and nothing redispatches.
#[test]
fn pending_accesses_wake_and_complete_independently_without_redispatch() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Wake, Waker};
    #[derive(Default)]
    struct WakeFlag(AtomicBool);
    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let flag = Arc::new(WakeFlag::default());
    let waker = Waker::from(flag.clone());
    let mut context = Context::from_waker(&waker);
    let mut handler = PciBusCfgAccessHandler::new();
    handler.poll(&mut context);
    assert!(handler.is_empty());
    let address = PciConfigAddress::new(1, 2, 3).unwrap();
    let mut callbacks = DeferredCallbacks::new(ReadAction::Defer, WriteAction::Defer);
    let mut inline = 0;
    let IoResult::Defer(mut read_token) = handler.read(
        address,
        ByteEnabledDwordRead::new(&mut inline, PciConfigByteEnable::HIGH_WORD),
        &mut callbacks,
    ) else {
        panic!("expected a deferred read")
    };
    assert!(flag.0.swap(false, Ordering::SeqCst));
    let IoResult::Defer(mut write_token) = handler.write(
        address,
        ByteEnabledDwordWrite::with_all_bytes_enabled(0x12345678),
        &mut callbacks,
    ) else {
        panic!("expected a deferred write")
    };
    handler.poll(&mut context);
    assert!(!handler.is_empty());
    let mut bytes = [0xa5; 2];
    assert!(poll_read_token(&mut read_token, &mut bytes).is_pending());
    assert!(poll_write_token(&mut write_token).is_pending());
    assert_eq!(bytes, [0xa5; 2]);
    callbacks.complete_write();
    assert!(flag.0.swap(false, Ordering::SeqCst));
    handler.poll(&mut context);
    assert!(matches!(
        poll_write_token(&mut write_token),
        Poll::Ready(Ok(()))
    ));
    assert!(!handler.is_empty());
    assert!(poll_read_token(&mut read_token, &mut bytes).is_pending());
    callbacks.complete_read(0x11223344);
    assert!(flag.0.swap(false, Ordering::SeqCst));
    handler.poll(&mut context);
    assert!(handler.is_empty());
    assert!(matches!(
        poll_read_token(&mut read_token, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [0x22, 0x11]);
    assert_eq!(callbacks.reads, [address]);
    assert_eq!(callbacks.writes, [(address, 0x12345678)]);
}
