// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::driver::Driver;
use crate::interest::PollEvents;
use crate::socket::Listener;
use crate::socket::PollReadyExt;
use crate::socket::PolledSocket;
use crate::wait::PolledWait;
use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use pal_async_test::async_test;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::sync::Arc;
use test_with_tracing::test;
use unix_socket::UnixStream;

async fn transfer(mut reader: impl AsyncRead + Unpin, mut writer: impl AsyncWrite + Unpin) {
    let payload = b"abcdefgh";
    let sent = writer
        .write_vectored(&[IoSlice::new(&payload[..3]), IoSlice::new(&payload[3..])])
        .await
        .unwrap();
    writer.write_all(&payload[sent..]).await.unwrap();
    writer.flush().await.unwrap();
    let mut data = [0; 8];
    let (left, right) = data.split_at_mut(3);
    let received = reader
        .read_vectored(&mut [IoSliceMut::new(left), IoSliceMut::new(right)])
        .await
        .unwrap();
    reader.read_exact(&mut data[received..]).await.unwrap();
    assert_eq!(&data, payload);
    writer.close().await.unwrap();
    assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
}

// Test: Connect through a borrowed TCP listener and transfer vectored data.
// Expected: Endpoint addresses agree, bytes retain order, and write-close produces EOF.
#[async_test]
async fn tcp_connect_accept_and_vectored_io_preserve_stream_semantics(driver: DefaultDriver) {
    within(&driver, async {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut listener = PolledSocket::new(&driver, &listener).unwrap();
        assert_eq!(Listener::local_addr(listener.get()).unwrap(), address);
        assert!(listener.accept().now_or_never().is_none());
        let mut client = PolledSocket::connect_tcp(&driver, address).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        assert_eq!(client.get().local_addr().unwrap(), peer);
        client.get_mut().set_nodelay(true).unwrap();
        assert!(client.get().nodelay().unwrap());
        let mut server = PolledSocket::new(&driver, server).unwrap();
        assert!(server.wait_ready(PollEvents::IN).now_or_never().is_none());
        assert!(client.wait_ready(PollEvents::OUT).await.has_out());
        transfer(&mut server, &mut client).await;
        let server = server.into_inner();
        assert_eq!(server.peer_addr().unwrap(), peer);
    })
    .await;
}

// Test: Send vectored data through independently owned halves of Unix streams.
// Expected: Both directions preserve bytes and half-close without deadlocking.
#[async_test]
async fn split_socket_vectored_transfers_and_readiness_work_in_both_directions(
    driver: DefaultDriver,
) {
    within(&driver, async {
        let (left, right) = UnixStream::pair().unwrap();
        let (mut lr, mut lw) = PolledSocket::new(&driver, left).unwrap().split();
        let (mut rr, mut rw) = PolledSocket::new(&driver, right).unwrap().split();
        assert!(lr.wait_ready(PollEvents::IN).now_or_never().is_none());
        assert!(lw.wait_ready(PollEvents::OUT).await.has_out());
        transfer(&mut rr, &mut lw).await;
        transfer(&mut lr, &mut rw).await;
    })
    .await;
}

// Test: Listen on a socket2 Unix socket, connect by path, and use the accepted stream.
// Expected: Path-based connections exchange data; a missing path is an explicit error.
#[async_test]
async fn unix_path_connections_accept_and_report_missing_listeners(driver: DefaultDriver) {
    within(&driver, async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("listener");
        let socket =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(&socket2::SockAddr::unix(&path).unwrap())
            .unwrap();
        let mut listener = PolledSocket::new(&driver, socket).unwrap();
        listener.listen(1).unwrap();
        let mut client = PolledSocket::connect_unix(&driver, &path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut server = PolledSocket::new(&driver, server)
            .unwrap()
            .convert::<UnixStream>();
        transfer(&mut server, &mut client).await;
        let error = PolledSocket::connect_unix(&driver, directory.path().join("missing"))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    })
    .await;
}

async fn dynamic_driver_io(driver: &impl Driver) {
    let mut timer = PolledTimer::new(driver);
    timer.sleep(Duration::from_millis(1)).await;
    let mut wait = PolledWait::new(driver, pal_event::Event::new()).unwrap();
    assert!(wait.wait().now_or_never().is_none());
    wait.get().signal();
    wait.wait().await.unwrap();
    let event = wait.into_inner();
    let mut wait = PolledWait::new(driver, event).unwrap();
    wait.get().signal();
    wait.wait().await.unwrap();
    let (left, right) = UnixStream::pair().unwrap();
    let mut left = PolledSocket::new(driver, left).unwrap();
    let mut right = PolledSocket::new(driver, right).unwrap();
    transfer(&mut right, &mut left).await;
}

// Test: Create timers, event waits, and sockets through boxed and shared drivers.
// Expected: Dynamic driver forwarding preserves wakeups, event ownership, and I/O.
#[async_test]
async fn boxed_and_shared_drivers_support_real_io(driver: DefaultDriver) {
    within(&driver, async {
        let boxed: Box<dyn Driver> = Box::new(driver.clone());
        dynamic_driver_io(&boxed).await;
        let shared: Arc<dyn Driver> = Arc::new(driver.clone());
        dynamic_driver_io(&shared).await;
    })
    .await;
}

// Test: Peek and partially read a stream after the peer closes its write side.
// Expected: Buffered bytes precede EOF, peeking does not consume them, and
//       the half-closed peer can still receive a complete response.
#[async_test]
async fn half_closed_stream_peeks_preserve_buffered_data_and_the_reply_path(driver: DefaultDriver) {
    within(&driver, async {
        let (client, server) = UnixStream::pair().unwrap();
        let mut client = PolledSocket::new(&driver, client).unwrap();
        let mut server = PolledSocket::new(&driver, server).unwrap();
        client.write_all(b"request").await.unwrap();
        client.close().await.unwrap();

        let mut peeked = [0; 3];
        assert_eq!(server.peek(&mut peeked).await.unwrap(), 3);
        assert_eq!(&peeked, b"req");
        let mut prefix = [0; 2];
        server.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"re");
        assert_eq!(server.peek(&mut peeked).await.unwrap(), 3);
        assert_eq!(&peeked, b"que");
        let mut remainder = Vec::new();
        server.read_to_end(&mut remainder).await.unwrap();
        assert_eq!(remainder, b"quest");
        assert_eq!(server.peek(&mut peeked).await.unwrap(), 0);

        server.write_all(b"reply").await.unwrap();
        server.close().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"reply");
    })
    .await;
}
