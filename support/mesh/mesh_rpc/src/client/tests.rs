// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Client;
use super::Dial;
use crate::service::Code;
use mesh::CancelContext;
use mesh::Deadline;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::socket::PolledSocket;
use std::future::pending;
use std::net::TcpStream;
use std::time::Duration;
use test_with_tracing::test;

struct NeverDial;

impl Dial for NeverDial {
    type Stream = PolledSocket<TcpStream>;

    async fn dial(&mut self) -> std::io::Result<Self::Stream> {
        pending().await
    }
}

struct FailDial;

impl Dial for FailDial {
    type Stream = PolledSocket<TcpStream>;

    async fn dial(&mut self) -> std::io::Result<Self::Stream> {
        Err(std::io::ErrorKind::NotConnected.into())
    }
}

#[async_test]
async fn test_failed_connect(driver: DefaultDriver) {
    let client = Client::new(&driver, FailDial);
    let err = client
        .call()
        .start_raw("service", "method", vec![])
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::Unavailable as i32);
    assert!(err.message.contains("not connected"));
}

#[async_test]
async fn test_delayed_connect_never(driver: DefaultDriver) {
    let client = Client::new(&driver, NeverDial);

    // The request should not fail within the cancel context timeout.
    CancelContext::new()
        .with_timeout(Duration::from_millis(250))
        .until_cancelled(
            client
                .call()
                .deadline(Some(Deadline::now() + Duration::from_mins(1)))
                .start_raw("service", "method", vec![]),
        )
        .await
        .unwrap_err();
}

#[async_test]
async fn test_delayed_connect(driver: DefaultDriver) {
    let client = Client::new(&driver, NeverDial);
    let err = client
        .call()
        .deadline(Some(Deadline::now() + Duration::from_millis(200)))
        .start_raw("service", "method", vec![])
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::DeadlineExceeded as i32);
}

// Test: Retry failed connections while waiting for readiness until the call expires.
// Expected: Wait-ready calls reach DeadlineExceeded rather than failing Unavailable.
#[async_test]
async fn wait_ready_retries_until_its_deadline(driver: DefaultDriver) {
    let client = super::ClientBuilder::new()
        .retry_timeout(Duration::from_millis(1))
        .build(&driver, FailDial);
    let error = client
        .call()
        .wait_ready(true)
        .timeout(Some(Duration::from_millis(20)))
        .start_raw("service", "method", vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code, Code::DeadlineExceeded as i32);
    client.shutdown().await;
}

// Test: Dial an existing connection twice and use the stream returned the first time.
// Expected: The first dial preserves the stream; the second reports AddrNotAvailable.
#[async_test]
async fn existing_connection_can_only_be_consumed_once() {
    use futures::AsyncReadExt;
    let mut dial = super::ExistingConnection::new(futures::io::Cursor::new(vec![7]));
    let mut stream = dial.dial().await.unwrap();
    let mut bytes = [0];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [7]);
    assert_eq!(
        dial.dial().await.unwrap_err().kind(),
        std::io::ErrorKind::AddrNotAvailable
    );
}

// Test: Receive malformed, wrong-type, explicit-error, oversized, and valid replies.
// Expected: Client status codes distinguish each failure, and unsolicited stream IDs
//           cannot consume the valid reply for an outstanding call.
#[async_test]
async fn wire_responses_preserve_error_classification_and_stream_routing(driver: DefaultDriver) {
    use crate::message::{MESSAGE_TYPE_RESPONSE, Request, Response, read_message, write_message};
    use pal_async::task::Spawn;
    let error_payload = mesh::payload::encode(Response::Status(crate::service::Status {
        code: Code::PermissionDenied as i32,
        message: "denied".into(),
        details: vec![],
    }));
    let cases = [
        (MESSAGE_TYPE_RESPONSE, vec![0xff], Some(Code::Unknown)),
        (0xff, vec![], Some(Code::Internal)),
        (
            MESSAGE_TYPE_RESPONSE,
            error_payload,
            Some(Code::PermissionDenied),
        ),
        (
            MESSAGE_TYPE_RESPONSE,
            vec![0; 1 << 24],
            Some(Code::ResourceExhausted),
        ),
        (
            MESSAGE_TYPE_RESPONSE,
            mesh::payload::encode(Response::Payload(b"answer".to_vec())),
            None,
        ),
    ];
    for (message_type, payload, expected_error) in cases {
        let (client_socket, peer_socket) = unix_socket::UnixStream::pair().unwrap();
        let client = Client::new(
            &driver,
            super::ExistingConnection::new(PolledSocket::new(&driver, client_socket).unwrap()),
        );
        let mut peer_socket = PolledSocket::new(&driver, peer_socket).unwrap();
        let peer = driver.spawn("raw-rpc-peer", async move {
            let frame = read_message(&mut peer_socket).await.unwrap().unwrap();
            let request: Request = mesh::payload::decode(&frame.payload.unwrap()).unwrap();
            assert_eq!(request.service, "service");
            assert_eq!(request.method, "method");
            assert_eq!(request.payload, [1, 2, 3]);
            write_message(
                &mut peer_socket,
                frame.stream_id.wrapping_add(2),
                MESSAGE_TYPE_RESPONSE,
                &[],
            )
            .await
            .unwrap();
            write_message(&mut peer_socket, frame.stream_id, message_type, &payload)
                .await
                .unwrap();
        });
        let result = client
            .call()
            .start_raw("service", "method", vec![1, 2, 3])
            .await;
        if let Some(expected) = expected_error {
            assert_eq!(result.unwrap_err().code, expected as i32);
        } else {
            assert_eq!(result.unwrap(), b"answer");
        }
        client.shutdown().await;
        peer.await;
    }
}
