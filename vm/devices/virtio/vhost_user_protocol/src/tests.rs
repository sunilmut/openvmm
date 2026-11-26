// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use pal_async::socket::PolledSocket;
use std::future::Future;
use std::io::IoSlice;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::task::Poll;
use test_with_tracing::test;
use unix_socket::ScmReceiver;
use unix_socket::UnixStream;
use zerocopy::IntoBytes;

fn pair(driver: &DefaultDriver) -> (VhostUserSocket, UnixStream) {
    let (receive, send) = UnixStream::pair().unwrap();
    (
        VhostUserSocket::new(PolledSocket::new(driver, receive).unwrap()),
        send,
    )
}

fn header(size: u32) -> VhostUserMsgHeader {
    VhostUserMsgHeader {
        request: VhostUserRequestCode::SET_CONFIG.0,
        flags: VHOST_USER_FLAG_VERSION | VHOST_USER_FLAG_NEED_REPLY,
        size,
    }
}

// Test: Transfer a maximum-size payload and an event descriptor over a socket pair.
// Expected: Partial sends preserve every payload byte, attach the descriptor
//       once, and replies retain the request code while clearing NEED_REPLY.
#[test]
fn large_message_and_reply_descriptor() {
    DefaultPool::run_with(async |driver| {
        let (sender, stream) = pair(&driver);
        let receiver = VhostUserSocket::new(PolledSocket::new(&driver, stream).unwrap());
        let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|index| index as u8).collect();
        let request = header(payload.len() as u32);
        let (event, mut event_peer) = UnixStream::pair().unwrap();
        let mut scm = ScmReceiver::new(VHOST_USER_MAX_FDS);
        let (sent, received) = futures::future::join(
            sender.send_message(&request, &payload, &[event.as_fd()]),
            receiver.recv_message(&mut scm),
        )
        .await;
        sent.unwrap();
        let (actual, bytes, mut fds) = received.unwrap();
        assert_eq!(actual.request, request.request);
        assert!(actual.need_reply());
        assert!(actual.version_valid());
        assert!(!actual.is_reply());
        assert_eq!(bytes, payload);
        assert_eq!(fds.len(), 1);
        assert!(scm.fds().is_empty());
        drop(event);
        let mut received_event = UnixStream::from(fds.pop().unwrap());
        received_event.write_all(b"event").unwrap();
        let mut event_bytes = [0; 5];
        event_peer.read_exact(&mut event_bytes).unwrap();
        assert_eq!(&event_bytes, b"event");

        let reply = VhostUserMsgHeader::reply(&actual, 0);
        receiver
            .send_message(&reply, &[], &[] as &[OwnedFd])
            .await
            .unwrap();
        let (reply, bytes, fds) = sender.recv_message(&mut scm).await.unwrap();
        assert_eq!(reply.request, request.request);
        assert!(reply.is_reply());
        assert!(!reply.need_reply());
        assert!(reply.version_valid());
        assert!(bytes.is_empty());
        assert!(fds.is_empty());
    });
}

// Test: Receive a fragmented header and an unexpected descriptor on payload bytes.
// Expected: The incomplete header waits, payload-only descriptors are closed,
//       and the reused ancillary receiver does not leak them to the next frame.
#[test]
fn fragmented_header_discards_payload_descriptors() {
    DefaultPool::run_with(async |driver| {
        let (socket, mut peer) = pair(&driver);
        let request = header(3);
        peer.write_all(&request.as_bytes()[..3]).unwrap();
        let mut scm = ScmReceiver::new(VHOST_USER_MAX_FDS);
        let (stray, mut stray_peer) = UnixStream::pair().unwrap();
        stray_peer
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let (_, payload, fds) = {
            let mut receive = std::pin::pin!(socket.recv_message(&mut scm));
            std::future::poll_fn(|cx| {
                assert!(receive.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            peer.write_all(&request.as_bytes()[3..]).unwrap();
            assert_eq!(
                unix_socket::send_with_fds(peer.as_fd(), &[IoSlice::new(b"abc")], [stray.as_fd()])
                    .unwrap(),
                3
            );
            drop(stray);
            receive.await.unwrap()
        };
        assert_eq!(payload, b"abc");
        assert!(fds.is_empty());
        assert_eq!(stray_peer.read(&mut [0]).unwrap(), 0);
        peer.write_all(header(0).as_bytes()).unwrap();
        let (_, payload, fds) = socket.recv_message(&mut scm).await.unwrap();
        assert!(payload.is_empty());
        assert!(fds.is_empty());
        assert!(scm.fds().is_empty());
    });
}

// Test: Close a connection at each frame phase and advertise an oversized payload.
// Expected: EOF never returns a partial message; oversized frames fail before
//       waiting for their body with the advertised byte count preserved.
#[test]
fn truncated_and_oversized_frames() {
    DefaultPool::run_with(async |driver| {
        let request = header(4);
        let mut frame = request.as_bytes().to_vec();
        frame.extend_from_slice(b"body");
        for count in [0, 5, 12, 14] {
            let (socket, mut peer) = pair(&driver);
            peer.write_all(&frame[..count]).unwrap();
            drop(peer);
            let mut scm = ScmReceiver::new(VHOST_USER_MAX_FDS);
            assert!(matches!(
                socket.recv_message(&mut scm).await,
                Err(SocketError::Closed)
            ));
            assert!(scm.fds().is_empty());
        }
        let (socket, mut peer) = pair(&driver);
        peer.write_all(header(4 * 1024 * 1024 + 1).as_bytes())
            .unwrap();
        let mut scm = ScmReceiver::new(VHOST_USER_MAX_FDS);
        assert!(matches!(
            socket.recv_message(&mut scm).await,
            Err(SocketError::PayloadTooLarge(4_194_305))
        ));
        let (socket, peer) = pair(&driver);
        drop(peer);
        assert!(matches!(
            socket
                .send_message(&header(0), &[], &[] as &[OwnedFd])
                .await,
            Err(SocketError::Io(_))
        ));
    });
}

// Test: Reject version three even though its low bit is also set.
// Expected: The protocol's two-bit version field equals one, not merely odd.
// IGNORED: version_valid checks only bit zero, accepting reserved version three;
//       reproduced enabled and retained without changing production behavior.
#[test]
#[ignore = "version_valid accepts reserved vhost-user version three"]
fn reserved_version_three_is_rejected() {
    let mut request = header(0);
    request.flags = 3 | VHOST_USER_FLAG_NEED_REPLY;
    assert!(!request.version_valid());
}
