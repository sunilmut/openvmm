// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::AsyncRead;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    blocked: bool,
    error: Option<ErrorKind>,
}

struct Backend(Arc<Mutex<Output>>);

impl InspectMut for Backend {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.ignore();
    }
}

impl AsyncRead for Backend {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        panic!("output-only device must not read its backend");
    }
}

impl AsyncWrite for Backend {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut output = self.0.lock();
        if output.blocked {
            return Poll::Pending;
        }
        if let Some(error) = output.error.take() {
            return Poll::Ready(Err(error.into()));
        }
        let n = buf.len().min(2);
        output.bytes.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl SerialIo for Backend {
    fn is_connected(&self) -> bool {
        true
    }

    fn poll_connect(&mut self, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_disconnect(&mut self, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

fn device() -> (SerialDebugcon, Arc<Mutex<Output>>) {
    let output = Arc::new(Mutex::new(Output::default()));
    (
        SerialDebugcon::new(0xe9, Box::new(Backend(output.clone()))),
        output,
    )
}

fn poll(device: &mut SerialDebugcon) {
    device
        .supports_poll_device()
        .unwrap()
        .poll_device(&mut Context::from_waker(Waker::noop()));
}

// Test: Queue byte writes across a pending backend and drain via short writes.
// Expected: Every accepted byte is delivered once, in order, with LF followed
//       by the raw-console CR adaptation and no invented input.
#[test]
fn pending_short_writes_preserve_output_order() {
    let (mut device, output) = device();
    output.lock().blocked = true;
    poll(&mut device);
    for byte in b"A\nB\0\xff" {
        assert!(matches!(device.io_write(0xe9, &[*byte]), IoResult::Ok));
    }
    poll(&mut device);
    assert!(output.lock().bytes.is_empty());
    output.lock().blocked = false;
    poll(&mut device);
    assert_eq!(output.lock().bytes, b"A\n\rB\0\xff");
    poll(&mut device);
    assert_eq!(output.lock().bytes, b"A\n\rB\0\xff");
}

// Test: Reject invalid guest ports and widths while retaining accepted output.
// Expected: Read buffers remain unchanged on error, rejected writes produce no
//       bytes, and a valid presence read never consumes queued output.
#[test]
fn invalid_accesses_have_no_output_side_effects() {
    let (mut device, output) = device();
    assert!(matches!(device.io_write(0xe9, b"X"), IoResult::Ok));
    let pio = device.supports_pio().unwrap();
    for port in [0xe8, 0xea] {
        let mut read = [0xa5];
        assert!(matches!(
            pio.io_read(port, &mut read),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert_eq!(read, [0xa5]);
        assert!(matches!(
            pio.io_write(port, b"Y"),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    for len in [0, 2, 4] {
        let mut read = vec![0xa5; len];
        assert!(matches!(
            pio.io_read(0xe9, &mut read),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(read, vec![0xa5; len]);
        assert!(matches!(
            pio.io_write(0xe9, &read),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    let mut signature = [0];
    assert!(matches!(pio.io_read(0xe9, &mut signature), IoResult::Ok));
    assert_eq!(signature, [0xe9]);
    poll(&mut device);
    assert_eq!(output.lock().bytes, b"X");
}

// Test: Reset while output is pending, then write a new diagnostic.
// Expected: Only pre-reset queued bytes are discarded; the new message drains.
#[test]
fn reset_discards_only_pending_output() {
    let (mut device, output) = device();
    output.lock().blocked = true;
    for byte in b"stale\n" {
        assert!(matches!(device.io_write(0xe9, &[*byte]), IoResult::Ok));
    }
    poll(&mut device);
    futures::executor::block_on(device.reset());
    output.lock().blocked = false;
    for byte in b"fresh\n" {
        assert!(matches!(device.io_write(0xe9, &[*byte]), IoResult::Ok));
    }
    poll(&mut device);
    assert_eq!(output.lock().bytes, b"fresh\n\r");
}

// Test: Encounter transient broken-pipe and non-retryable backend errors.
// Expected: Broken-pipe output is retried intact; other failed output is
//       discarded without poisoning subsequent diagnostics.
#[test]
fn backend_errors_preserve_retryable_output_only() {
    for (error, expected) in [
        (ErrorKind::BrokenPipe, b"old".as_slice()),
        (ErrorKind::Other, b"".as_slice()),
    ] {
        let (mut device, output) = device();
        output.lock().error = Some(error);
        for byte in b"old" {
            assert!(matches!(device.io_write(0xe9, &[*byte]), IoResult::Ok));
        }
        poll(&mut device);
        assert_eq!(output.lock().bytes, expected);
        assert!(matches!(device.io_write(0xe9, b"N"), IoResult::Ok));
        poll(&mut device);
        let mut complete = expected.to_vec();
        complete.push(b'N');
        assert_eq!(output.lock().bytes, complete);
    }
}
