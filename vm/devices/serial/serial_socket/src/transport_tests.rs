// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::net::OpenSocketSerialConfig;
use crate::net::SocketSerialBackend;
use crate::net::SocketSerialResolver;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use futures::future::poll_fn;
use serial_core::SerialIo;
use serial_core::resources::ResolveSerialBackendParams;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpListener;
use std::net::TcpStream;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use test_with_tracing::test;
use vm_resource::ResolveResource;

// Test: No current socket or listener exists, so the serial transport is terminal.
// Expected: Connect stays pending, disconnect/flush/close complete, input is EOF,
//       and output is consumed without retaining bytes for a future connection.
#[test]
fn disconnected_transport_remains_terminal() {
    pal_async::DefaultPool::run_with(async |driver| {
        let mut backend = SocketSerialBackend::new(
            Box::new(driver),
            OpenSocketSerialConfig {
                current: None,
                listener: None,
            },
        )
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(!backend.is_connected());
        assert!(matches!(backend.poll_connect(&mut cx), Poll::Pending));
        assert!(matches!(
            backend.poll_disconnect(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(backend.read(&mut [0; 4]).await.unwrap(), 0);
        assert_eq!(backend.write(b"discarded").await.unwrap(), 9);
        backend.flush().await.unwrap();
        backend.close().await.unwrap();
        assert!(!backend.is_connected());
        assert!(matches!(backend.poll_connect(&mut cx), Poll::Pending));
    });
}

// Test: Current TCP connection and listener ownership move through resource config.
//       A queued replacement cannot displace the current peer until its half-close.
// Expected: Queued input and bidirectional output survive handoff, peer FIN clears
//       carrier without a read, and the listener accepts the replacement cleanly.
#[test]
fn tcp_handoff_and_half_close_reconnection() {
    pal_async::DefaultPool::run_with(async |driver| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut first = TcpStream::connect(address).unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (current, _) = listener.accept().unwrap();
        let mut config = OpenSocketSerialConfig::from(current);
        config.listener = Some(listener.into());
        let backend = SocketSerialBackend::new(Box::new(driver.clone()), config).unwrap();
        first.write_all(b"queued-before-handoff").unwrap();
        let mut next = TcpStream::connect(address).unwrap();
        next.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        next.write_all(b"replacement").unwrap();
        let config = backend.into_config();
        let mut backend = SocketSerialResolver
            .resolve(
                config,
                ResolveSerialBackendParams {
                    driver: Box::new(driver),
                    _async_trait_workaround: &(),
                },
            )
            .unwrap()
            .0
            .into_io();
        poll_fn(|cx| backend.poll_connect(cx)).await.unwrap();
        let mut input = [0; 21];
        backend.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"queued-before-handoff");
        backend.write_all(b"first-response").await.unwrap();
        backend.flush().await.unwrap();
        let mut response = [0; 14];
        first.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"first-response");
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(backend.poll_disconnect(&mut cx), Poll::Pending));
        first.shutdown(Shutdown::Write).unwrap();
        poll_fn(|cx| backend.poll_disconnect(cx)).await.unwrap();
        assert!(!backend.is_connected());
        backend.write_all(b"discard-between-peers").await.unwrap();
        poll_fn(|cx| backend.poll_connect(cx)).await.unwrap();
        let mut input = [0; 11];
        backend.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"replacement");
        backend.write_all(b"second-response").await.unwrap();
        backend.close().await.unwrap();
        let mut response = Vec::new();
        next.read_to_end(&mut response).unwrap();
        assert_eq!(&response, b"second-response");
    });
}

// Test: Unix streams and an abstract Unix listener are independently transferred.
// Expected: Binary serial bytes remain lossless across config handoff, and the
//       transferred listener still accepts a new peer without filesystem artifacts.
#[cfg(target_os = "linux")]
#[test]
fn unix_stream_and_listener_ownership() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;
    use unix_socket::UnixListener;
    use unix_socket::UnixStream;

    pal_async::DefaultPool::run_with(async |driver| {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let backend = SocketSerialBackend::new(Box::new(driver.clone()), stream.into()).unwrap();
        peer.write_all(&[0, 0xff, b'\r', b'\n']).unwrap();
        let mut backend =
            SocketSerialBackend::new(Box::new(driver.clone()), backend.into_config()).unwrap();
        let mut input = [0; 4];
        backend.read_exact(&mut input).await.unwrap();
        assert_eq!(input, [0, 0xff, b'\r', b'\n']);
        backend.write_all(&[0xfe, 0, 1]).await.unwrap();
        backend.close().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).unwrap();
        assert_eq!(response, [0xfe, 0, 1]);

        let mut name = [0; 16];
        getrandom::fill(&mut name).unwrap();
        let address = SocketAddr::from_abstract_name(name).unwrap();
        let listener = UnixListener::bind_addr(&address).unwrap();
        let backend = SocketSerialBackend::new(Box::new(driver.clone()), listener.into()).unwrap();
        let mut backend =
            SocketSerialBackend::new(Box::new(driver), backend.into_config()).unwrap();
        let mut peer = UnixStream::connect_addr(&address).unwrap();
        peer.write_all(b"accepted").unwrap();
        poll_fn(|cx| backend.poll_connect(cx)).await.unwrap();
        let mut input = [0; 8];
        backend.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"accepted");
        drop(peer);
        poll_fn(|cx| backend.poll_disconnect(cx)).await.unwrap();
        assert!(!backend.is_connected());
    });
}
