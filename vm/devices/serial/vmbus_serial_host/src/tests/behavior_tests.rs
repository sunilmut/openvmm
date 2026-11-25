// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::io::AsyncRead;
use futures::io::AsyncWrite;
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;
use test_with_tracing::test;
use vmbus_ring::FlatRingMem;

mod error_tests;
mod lifecycle_tests;

#[derive(Default)]
struct Backend {
    input: VecDeque<u8>,
    output: Vec<u8>,
    max_write: Option<usize>,
    fail_write: bool,
    write_pending: bool,
    disconnected: bool,
    eof: bool,
    connect: bool,
    disconnect: bool,
    fail_read: bool,
    fail_connect: bool,
    fail_disconnect: bool,
}

#[derive(InspectMut)]
struct RecordingIo {
    #[inspect(skip)]
    backend: Arc<Mutex<Backend>>,
}

impl AsyncRead for RecordingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut backend = self.backend.lock();
        if backend.input.is_empty() {
            if std::mem::take(&mut backend.fail_read) {
                return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
            }
            if std::mem::take(&mut backend.eof) {
                backend.disconnected = true;
                return Poll::Ready(Ok(0));
            }
            return Poll::Pending;
        }
        let count = buf.len().min(backend.input.len());
        for byte in &mut buf[..count] {
            *byte = backend.input.pop_front().unwrap();
        }
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut backend = self.backend.lock();
        if backend.write_pending {
            return Poll::Pending;
        }
        if std::mem::take(&mut backend.fail_write) {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        let count = buf.len().min(backend.max_write.unwrap_or(buf.len()));
        backend.output.extend_from_slice(&buf[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl SerialIo for RecordingIo {
    fn is_connected(&self) -> bool {
        !self.backend.lock().disconnected
    }
    fn poll_connect(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut backend = self.backend.lock();
        if std::mem::take(&mut backend.fail_connect) {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        if !std::mem::take(&mut backend.connect) {
            return Poll::Pending;
        }
        backend.disconnected = false;
        Poll::Ready(Ok(()))
    }
    fn poll_disconnect(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut backend = self.backend.lock();
        if std::mem::take(&mut backend.fail_disconnect) {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        if !std::mem::take(&mut backend.disconnect) {
            return Poll::Pending;
        }
        backend.disconnected = true;
        Poll::Ready(Ok(()))
    }
}

fn fixture() -> (
    Serial,
    SerialChannel<FlatRingMem>,
    MessagePipe<FlatRingMem>,
    Arc<Mutex<Backend>>,
) {
    let (host, guest) = vmbus_channel::connected_async_channels(16384);
    let backend = Arc::new(Mutex::new(Backend::default()));
    let serial = Serial::new(
        Port::Com1,
        Box::new(RecordingIo {
            backend: backend.clone(),
        }),
    );
    (
        serial,
        SerialChannel::new(MessagePipe::new(host).unwrap()),
        MessagePipe::new(guest).unwrap(),
        backend,
    )
}

fn receive(guest: &mut MessagePipe<FlatRingMem>) -> Vec<u8> {
    let mut buffer = vec![0; protocol::MAX_MESSAGE_SIZE];
    let count = guest
        .recv(&mut buffer)
        .now_or_never()
        .expect("expected response without blocking")
        .unwrap();
    buffer.truncate(count);
    buffer
}

fn negotiate(channel: &mut SerialChannel<FlatRingMem>, guest: &mut MessagePipe<FlatRingMem>) {
    guest
        .try_send(
            protocol::VersionRequestMessage {
                header: protocol::Header::new_host_request(HostRequests::VERSION),
                requested_version: protocol::ProtocolVersions::MANGANESE,
            }
            .as_bytes(),
        )
        .unwrap();
    channel.process_init().now_or_never().unwrap().unwrap();
    assert_eq!(
        receive(guest),
        protocol::VersionRequestResponse {
            header: protocol::Header::new_host_response(HostRequests::VERSION),
            version_accepted: 1,
            pad: 0
        }
        .as_bytes()
    );
}

fn step(channel: &mut SerialChannel<FlatRingMem>, serial: &mut Serial) {
    assert!(
        channel
            .process_ready(serial)
            .now_or_never()
            .expect("expected one ready protocol event")
            .unwrap()
    );
}

fn tx_message(bytes: &[u8]) -> protocol::TxDataAvailableMessage {
    let mut message = protocol::TxDataAvailableMessage {
        header: protocol::Header::new_host_notification(HostNotifications::TX_DATA_AVAILABLE),
        buffer_length: bytes.len() as u8,
        ..Default::default()
    };
    message.buffer[..bytes.len()].copy_from_slice(bytes);
    message
}

// Test: Negotiate the actual ring protocol, observe the connected modem, receive 150 binary bytes through repeated GET_RX_DATA requests, then query the empty buffer.
// Expected: Exact version/modem headers and status are emitted, RX notification occurs once, chunks are ordered 64/64/22 with correct more-data flags and zero padding, and an empty response leaks no stale bytes.
#[test]
fn negotiated_rx_stream_has_exact_chunks_notifications_and_zero_padding() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::SetModumStatusMessage {
            header: protocol::Header::new_guest_notification(
                protocol::GuestNotifications::SET_MODEM_STATUS
            ),
            modem_status: 0xbb,
            is_connected: 1
        }
        .as_bytes()
    );
    let input: Vec<_> = (0..150).map(|value| value as u8 ^ 0x80).collect();
    backend.lock().input.extend(&input);
    step(&mut channel, &mut serial);
    assert_eq!(
        receive(&mut guest),
        protocol::Header::new_guest_notification(protocol::GuestNotifications::RX_DATA_AVAILABLE)
            .as_bytes()
    );
    for (index, expected) in input.chunks(64).chain(std::iter::once(&[][..])).enumerate() {
        guest
            .try_send(protocol::Header::new_host_request(HostRequests::GET_RX_DATA).as_bytes())
            .unwrap();
        step(&mut channel, &mut serial);
        let bytes = receive(&mut guest);
        let response = protocol::RxDataResponse::read_from_bytes(&bytes).unwrap();
        assert_eq!(
            response.header,
            protocol::Header::new_host_response(HostRequests::GET_RX_DATA)
        );
        assert_eq!(response.buffer_length as usize, expected.len());
        assert_eq!(response.more_data_available, u8::from(index < 2));
        assert_eq!(&response.buffer[..expected.len()], expected);
        assert!(
            response.buffer[expected.len()..]
                .iter()
                .all(|&byte| byte == 0)
        );
    }
    let mut buffer = [0; 512];
    assert!(guest.recv(&mut buffer).now_or_never().is_none());
}

// Test: Send two binary guest TX batches through the ring while the host backend accepts only two bytes per write, then fail one batch and submit a later batch.
// Expected: Every accepted byte is written exactly once in order, each batch gets one completion, failed bytes are dropped rather than replayed, and later TX still works.
#[test]
fn tx_partial_writes_complete_once_and_failed_batches_are_not_replayed() {
    let (mut serial, mut channel, mut guest, backend) = fixture();
    negotiate(&mut channel, &mut guest);
    step(&mut channel, &mut serial);
    receive(&mut guest);
    backend.lock().max_write = Some(2);
    for bytes in [&b"a\0\x81\xffz"[..], &b"second"[..]] {
        guest.try_send(tx_message(bytes).as_bytes()).unwrap();
        step(&mut channel, &mut serial);
        step(&mut channel, &mut serial);
        assert_eq!(
            receive(&mut guest),
            protocol::Header::new_guest_notification(protocol::GuestNotifications::TX_COMPLETED)
                .as_bytes()
        );
    }
    assert_eq!(backend.lock().output, b"a\0\x81\xffzsecond");
    backend.lock().fail_write = true;
    for bytes in [&b"drop-me"[..], &b"recovered"[..]] {
        guest.try_send(tx_message(bytes).as_bytes()).unwrap();
        step(&mut channel, &mut serial);
        step(&mut channel, &mut serial);
        assert_eq!(
            receive(&mut guest),
            protocol::Header::new_guest_notification(protocol::GuestNotifications::TX_COMPLETED)
                .as_bytes()
        );
    }
    assert_eq!(backend.lock().output, b"a\0\x81\xffzsecondrecovered");
    let mut buffer = [0; 512];
    assert!(guest.recv(&mut buffer).now_or_never().is_none());
}
