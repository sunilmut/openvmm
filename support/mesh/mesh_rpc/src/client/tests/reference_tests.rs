// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::client::Client;
use crate::client::ExistingConnection;
use crate::message::MESSAGE_TYPE_RESPONSE;
use crate::message::Request;
use crate::message::Response;
use crate::message::read_message;
use crate::message::write_message;
use crate::service::Code;
use crate::service::Status;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::socket::PolledSocket;
use pal_async::task::Spawn;

// Test: Interleave replies to three live calls with a duplicate completed-call reply.
// Expected: Stream identity, not arrival order, selects each call's exact payload or status.
#[async_test]
async fn reordered_and_duplicate_responses_preserve_call_identity(driver: DefaultDriver) {
    let (client_socket, peer_socket) = unix_socket::UnixStream::pair().unwrap();
    let client = Client::new(
        &driver,
        ExistingConnection::new(PolledSocket::new(&driver, client_socket).unwrap()),
    );
    let mut peer_socket = PolledSocket::new(&driver, peer_socket).unwrap();
    let peer = driver.spawn("reordered-rpc-peer", async move {
        let mut streams = Vec::new();
        for expected in 1..=3 {
            let frame = read_message(&mut peer_socket).await.unwrap().unwrap();
            let request: Request = mesh::payload::decode(&frame.payload.unwrap()).unwrap();
            assert_eq!(request.service, "service");
            assert_eq!(request.method, format!("method{expected}"));
            assert_eq!(request.payload, [expected]);
            assert!(!streams.contains(&frame.stream_id));
            streams.push(frame.stream_id);
        }
        for (stream, response) in [
            (streams[1], Response::Payload(b"second answer".to_vec())),
            (
                streams[1],
                Response::Payload(b"duplicate must not escape".to_vec()),
            ),
            (
                streams[2],
                Response::Status(Status {
                    code: Code::PermissionDenied as i32,
                    message: "third denied".into(),
                    details: vec![],
                }),
            ),
            (streams[0], Response::Payload(b"first answer".to_vec())),
        ] {
            write_message(
                &mut peer_socket,
                stream,
                MESSAGE_TYPE_RESPONSE,
                &mesh::payload::encode(response),
            )
            .await
            .unwrap();
        }
    });
    let first = client.call().start_raw("service", "method1", vec![1]);
    let second = client.call().start_raw("service", "method2", vec![2]);
    let third = client.call().start_raw("service", "method3", vec![3]);
    let (first, second, third) = futures::join!(first, second, third);
    assert_eq!(first.unwrap(), b"first answer");
    assert_eq!(second.unwrap(), b"second answer");
    let third = third.unwrap_err();
    assert_eq!(third.code, Code::PermissionDenied as i32);
    assert_eq!(third.message, "third denied");
    assert!(third.details.is_empty());
    client.shutdown().await;
    peer.await;
}
