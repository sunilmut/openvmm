// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::disconnected::Disconnected;
use crate::null::NullSerialBackend;
use crate::resources::ResolveSerialBackendParams;
use crate::resources::ResolvedSerialBackend;
use crate::serial_io::Connected;
use crate::serial_io::DetachableIo;
use crate::serial_io::detachable;
use futures::task::ArcWake;
use futures::task::waker;
use std::io;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Waker;
use test_with_tracing::test;
use vm_resource::ResourceResolver;
use vm_resource::kind::SerialBackendHandle;

#[derive(Clone, Copy)]
enum Response {
    Data,
    Pending,
    Error,
}

struct Backend {
    input: std::collections::VecDeque<u8>,
    output: Vec<u8>,
    flushes: usize,
    closes: usize,
    response: Response,
    read_waker: Option<Waker>,
}

impl Backend {
    fn new(response: Response) -> Self {
        Self {
            input: b"abcdefgh".iter().copied().collect(),
            output: Vec::new(),
            flushes: 0,
            closes: 0,
            response,
            read_waker: None,
        }
    }

    fn ready<T>(&self, value: T) -> Poll<io::Result<T>> {
        match self.response {
            Response::Data => Poll::Ready(Ok(value)),
            Response::Pending => Poll::Pending,
            Response::Error => Poll::Ready(Err(io::ErrorKind::PermissionDenied.into())),
        }
    }
}

impl InspectMut for Backend {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.ignore();
    }
}

impl SerialIo for Backend {
    fn is_connected(&self) -> bool {
        true
    }

    fn poll_connect(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ready(())
    }

    fn poll_disconnect(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncRead for Backend {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !matches!(self.response, Response::Data) {
            self.read_waker = Some(cx.waker().clone());
            return self.ready(0);
        }
        let len = buf.len().min(self.input.len());
        for byte in &mut buf[..len] {
            *byte = self.input.pop_front().unwrap();
        }
        Poll::Ready(Ok(len))
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        if !matches!(self.response, Response::Data) {
            self.read_waker = Some(cx.waker().clone());
            return self.ready(0);
        }
        let mut len = 0;
        for dst in bufs.iter_mut().flat_map(|buf| buf.iter_mut()) {
            let Some(byte) = self.input.pop_front() else {
                break;
            };
            *dst = byte;
            len += 1;
        }
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for Backend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !matches!(self.response, Response::Data) {
            return self.ready(0);
        }
        let len = buf.len().min(3);
        self.output.extend_from_slice(&buf[..len]);
        Poll::Ready(Ok(len))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if !matches!(self.response, Response::Data) {
            return self.ready(0);
        }
        let bytes: Vec<_> = bufs
            .iter()
            .flat_map(|buf| buf.iter().copied())
            .take(3)
            .collect();
        self.output.extend_from_slice(&bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        self.ready(())
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closes += 1;
        self.ready(())
    }
}

fn ready<T>(result: Poll<io::Result<T>>) -> T {
    match result {
        Poll::Ready(Ok(value)) => value,
        Poll::Ready(Err(error)) => panic!("unexpected backend error: {error}"),
        Poll::Pending => panic!("unexpected pending operation"),
    }
}

fn broken<T>(result: Poll<io::Result<T>>) {
    match result {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
        _ => panic!("expected a broken-pipe error"),
    }
}

fn disconnected(io: &mut impl SerialIo) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(!io.is_connected());
    assert!(io.poll_connect(&mut cx).is_pending());
    ready(io.poll_disconnect(&mut cx));
    let mut buf = [0xaa; 4];
    assert_eq!(ready(Pin::new(&mut *io).poll_read(&mut cx, &mut buf)), 0);
    assert_eq!(buf, [0xaa; 4]);
    assert_eq!(
        ready(Pin::new(&mut *io).poll_read_vectored(&mut cx, &mut [IoSliceMut::new(&mut buf)])),
        0
    );
    broken(Pin::new(&mut *io).poll_write(&mut cx, b"lost"));
    broken(Pin::new(&mut *io).poll_write_vectored(&mut cx, &[IoSlice::new(b"lost")]));
}

// Test: Forward scalar reads, partial writes, flush, and close through Connected.
// Expected: Payloads and backend completions are preserved, but backend EOF
//       does not disconnect this permanently connected adapter.
#[test]
fn connected_scalar_io_forwards_data_and_keeps_eof_pending() {
    let mut io = Connected::new(Backend::new(Response::Data));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(io.is_connected());
    ready(io.poll_connect(&mut cx));
    assert!(io.poll_disconnect(&mut cx).is_pending());
    let mut buf = [0; 8];
    assert_eq!(ready(Pin::new(&mut io).poll_read(&mut cx, &mut buf)), 8);
    assert_eq!(&buf, b"abcdefgh");
    assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
    assert_eq!(ready(Pin::new(&mut io).poll_write(&mut cx, b"12345")), 3);
    ready(Pin::new(&mut io).poll_flush(&mut cx));
    ready(Pin::new(&mut io).poll_close(&mut cx));
    let backend = io.into_inner();
    assert_eq!(backend.output, b"123");
    assert_eq!((backend.flushes, backend.closes), (1, 1));
}

// Test: Forward scatter/gather IO through Connected without flattening buffers.
// Expected: Reads fill both destinations, vectored writes preserve partial
//       completion, and vectored EOF remains pending.
#[test]
fn connected_vectored_io_preserves_buffer_order_and_partial_counts() {
    let mut io = Connected::new(Backend::new(Response::Data));
    let mut cx = Context::from_waker(Waker::noop());
    let (mut first, mut second) = ([0; 3], [0; 5]);
    assert_eq!(
        ready(Pin::new(&mut io).poll_read_vectored(
            &mut cx,
            &mut [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)]
        )),
        8
    );
    assert_eq!(&first, b"abc");
    assert_eq!(&second, b"defgh");
    assert!(
        Pin::new(&mut io)
            .poll_read_vectored(&mut cx, &mut [IoSliceMut::new(&mut first)])
            .is_pending()
    );
    assert_eq!(
        ready(
            Pin::new(&mut io)
                .poll_write_vectored(&mut cx, &[IoSlice::new(b"12"), IoSlice::new(b"345")])
        ),
        3
    );
    assert_eq!(io.into_inner().output, b"123");
}

// Test: Make backend read and write operations pending or fail through Connected.
// Expected: Every scalar, vectored, flush, and close operation preserves the
//       pending state or the original error kind.
#[test]
fn connected_io_preserves_pending_and_error_results() {
    for response in [Response::Pending, Response::Error] {
        let mut io = Connected::new(Backend::new(response));
        assert_outcomes(&mut io, response);
    }
}

fn assert_outcomes(io: &mut impl SerialIo, response: Response) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0xaa; 4];
    let operations = [
        Pin::new(&mut *io).poll_read(&mut cx, &mut buf),
        Pin::new(&mut *io).poll_read_vectored(&mut cx, &mut [IoSliceMut::new(&mut buf)]),
        Pin::new(&mut *io).poll_write(&mut cx, b"data"),
        Pin::new(&mut *io).poll_write_vectored(&mut cx, &[IoSlice::new(b"data")]),
        Pin::new(&mut *io).poll_flush(&mut cx).map_ok(|()| 0),
        Pin::new(&mut *io).poll_close(&mut cx).map_ok(|()| 0),
    ];
    for result in operations {
        match (response, result) {
            (Response::Pending, Poll::Pending) => {}
            (Response::Error, Poll::Ready(Err(error))) => {
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            _ => panic!("adapter changed the backend result"),
        }
    }
    assert_eq!(buf, [0xaa; 4]);
}

// Test: Detach a live backend after using scalar, vectored, and lifecycle IO.
// Expected: The returned backend retains forwarded output; the detached adapter
//       reports EOF and rejects writes, flush, and close with BrokenPipe.
#[test]
fn detachment_returns_the_backend_and_ends_the_original_io() {
    let (mut io, detacher) = detachable(Backend::new(Response::Data));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(io.is_connected());
    ready(io.poll_connect(&mut cx));
    assert!(io.poll_disconnect(&mut cx).is_pending());
    let (mut first, mut second) = ([0; 2], [0; 6]);
    assert_eq!(ready(Pin::new(&mut io).poll_read(&mut cx, &mut first)), 2);
    assert_eq!(&first, b"ab");
    assert_eq!(
        ready(Pin::new(&mut io).poll_read_vectored(&mut cx, &mut [IoSliceMut::new(&mut second)])),
        6
    );
    assert_eq!(&second, b"cdefgh");
    assert_eq!(ready(Pin::new(&mut io).poll_write(&mut cx, b"abc")), 3);
    assert_eq!(
        ready(
            Pin::new(&mut io)
                .poll_write_vectored(&mut cx, &[IoSlice::new(b"x"), IoSlice::new(b"yz")])
        ),
        3
    );
    ready(Pin::new(&mut io).poll_flush(&mut cx));
    ready(Pin::new(&mut io).poll_close(&mut cx));
    let backend = detacher.detach();
    assert_eq!(backend.output, b"abcxyz");
    assert_eq!((backend.flushes, backend.closes), (1, 1));
    disconnected(&mut io);
    broken(Pin::new(&mut io).poll_flush(&mut cx));
    broken(Pin::new(&mut io).poll_close(&mut cx));
}

// Test: Exercise error and pending replies before detaching, and start detached.
// Expected: Attached adapters preserve backend outcomes; an initially detached
//       adapter has the same EOF and broken-pipe behavior as one detached later.
#[test]
fn detachable_io_preserves_backend_outcomes_and_supports_initial_detachment() {
    for response in [Response::Pending, Response::Error] {
        let (mut io, _) = detachable(Backend::new(response));
        assert_outcomes(&mut io, response);
        let mut cx = Context::from_waker(Waker::noop());
        match (response, io.poll_connect(&mut cx)) {
            (Response::Pending, Poll::Pending) => {}
            (Response::Error, Poll::Ready(Err(error))) => {
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            _ => panic!("adapter changed the connection result"),
        }
    }
    let mut io = DetachableIo::<Backend>::detached();
    disconnected(&mut io);
    let mut cx = Context::from_waker(Waker::noop());
    broken(Pin::new(&mut io).poll_flush(&mut cx));
    broken(Pin::new(&mut io).poll_close(&mut cx));
}

// Test: Use a permanently disconnected backend directly and through an adapter.
// Expected: Neither connects or produces input; writes fail, but closing and
//       flushing the existing disconnected backend complete successfully.
#[test]
fn disconnected_backends_report_eof_and_reject_output() {
    let mut cx = Context::from_waker(Waker::noop());
    let mut direct = Disconnected;
    disconnected(&mut direct);
    ready(Pin::new(&mut direct).poll_flush(&mut cx));
    ready(Pin::new(&mut direct).poll_close(&mut cx));
    let (mut wrapped, _) = detachable(Disconnected);
    disconnected(&mut wrapped);
    ready(Pin::new(&mut wrapped).poll_flush(&mut cx));
    ready(Pin::new(&mut wrapped).poll_close(&mut cx));
}

// Test: Resolve null and disconnected resources and reclaim their handles.
// Expected: Round-tripped handles keep their identity and resolve to the same
//       externally observable connection and IO behavior.
#[pal_async::async_test]
async fn serial_resources_round_trip_without_changing_backend_behavior(
    driver: pal_async::DefaultDriver,
) {
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(null::resolver::NullSerialBackendResolver);
    resolver.add_resolver(disconnected::resolver::DisconnectedSerialBackendResolver);
    for (resource, connected) in [
        (NullSerialBackend.into(), true),
        (Disconnected.into(), false),
    ] {
        let resolve = || ResolveSerialBackendParams {
            driver: Box::new(driver.clone()),
            _async_trait_workaround: &(),
        };
        let ResolvedSerialBackend(mut backend) = resolver
            .resolve::<SerialBackendHandle, ResolvedSerialBackend>(resource, resolve())
            .await
            .unwrap();
        assert_eq!(backend.as_io().is_connected(), connected);
        let mut cx = Context::from_waker(Waker::noop());
        if connected {
            ready(backend.as_io_mut().poll_connect(&mut cx));
        } else {
            ready(backend.as_io_mut().poll_disconnect(&mut cx));
        }
        let resource = backend.into_resource();
        assert_eq!(
            resource.id(),
            if connected { "null" } else { "disconnected" }
        );
        let ResolvedSerialBackend(backend) = resolver
            .resolve::<SerialBackendHandle, ResolvedSerialBackend>(resource, resolve())
            .await
            .unwrap();
        let mut io = backend.into_io();
        if connected {
            assert_eq!(ready(Pin::new(&mut io).poll_write(&mut cx, b"discard")), 7);
        } else {
            broken(Pin::new(&mut io).poll_write(&mut cx, b"discard"));
        }
        ready(Pin::new(&mut io).poll_close(&mut cx));
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl ArcWake for WakeCount {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// IGNORED: Detaching removes the backend without waking its pending readers,
// so an executor may never poll the adapter again to observe EOF.
// Test: Register a pending read and detach while its backend remains alive.
// Expected: Detachment wakes the waiting reader so that it can receive EOF.
#[test]
#[ignore = "product bug: detachment does not wake a pending reader"]
fn detaching_wakes_readers_waiting_for_eof() {
    let (mut io, detacher) = detachable(Backend::new(Response::Pending));
    let count = Arc::new(WakeCount::default());
    let waker = waker(count.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut io).poll_read(&mut cx, &mut [0]).is_pending());
    let _backend = detacher.detach();
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(ready(Pin::new(&mut io).poll_read(&mut cx, &mut [0])), 0);
}

// Test: Transfer a serial backend after a short read and a partial write.
// Expected: The new adapter receives unread bytes and sends only the unwritten
//       suffix; the old adapter cannot consume or send any more data.
#[test]
fn backend_handoff_preserves_unread_input_and_partial_write_progress() {
    let (mut original, detacher) = detachable(Backend::new(Response::Data));
    let mut cx = Context::from_waker(Waker::noop());
    let mut prefix = [0xaa; 3];
    assert_eq!(
        ready(Pin::new(&mut original).poll_read(&mut cx, &mut prefix)),
        3
    );
    assert_eq!(&prefix, b"abc");
    let output = b"123456";
    let accepted = ready(Pin::new(&mut original).poll_write(&mut cx, output));
    assert_eq!(accepted, 3);

    let mut replacement = Connected::new(detacher.detach());
    disconnected(&mut original);
    let mut suffix = [0xaa; 8];
    assert_eq!(
        ready(Pin::new(&mut replacement).poll_read(&mut cx, &mut suffix)),
        5
    );
    assert_eq!(&suffix[..5], b"defgh");
    assert_eq!(&suffix[5..], &[0xaa; 3]);
    assert_eq!(
        ready(Pin::new(&mut replacement).poll_write(&mut cx, &output[accepted..])),
        3
    );
    ready(Pin::new(&mut replacement).poll_flush(&mut cx));
    assert_eq!(replacement.into_inner().output, output);
}
