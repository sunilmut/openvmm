// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::AsyncRead;
use futures::AsyncWrite;
use pal_async::DefaultDriver;
use pal_async::task::Spawn;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use test_with_tracing::test;

struct TokioSocket(PolledSocket<unix_socket::UnixStream>);

impl tokio::io::AsyncRead for TokioSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let length = std::task::ready!(
            Pin::new(&mut self.0).poll_read(context, buffer.initialize_unfilled())
        )?;
        buffer.advance(length);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TokioSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(context)
    }
}

struct Reply {
    status: http::StatusCode,
    body: Vec<u8>,
    trailers: Option<http::HeaderMap>,
}

type Request = (http::Request<()>, Vec<Vec<u8>>);

fn request(
    path: &str,
    content_type: Option<&str>,
    timeout: Option<&str>,
    chunks: Vec<Vec<u8>>,
) -> Request {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("http://localhost{path}"));
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    if let Some(timeout) = timeout {
        request = request.header("grpc-timeout", timeout);
    }
    (request.body(()).unwrap(), chunks)
}

async fn exchange(driver: &DefaultDriver, server: Server, requests: Vec<Request>) -> Vec<Reply> {
    let mut timeout = mesh::CancelContext::new().with_timeout(Duration::from_secs(5));
    timeout
        .until_cancelled(async {
            let (client, accepted) = unix_socket::UnixStream::pair().unwrap();
            let accepted = PolledSocket::new(driver, accepted).unwrap();
            let server_task = driver.spawn("grpc-server", async move {
                server.serve_connection_grpc(accepted).await
            });
            let replies = exchange_connection(driver, client, requests).await;
            server_task.await.unwrap();
            replies
        })
        .await
        .expect("gRPC exchange timed out")
}

async fn exchange_connection(
    driver: &DefaultDriver,
    client: unix_socket::UnixStream,
    requests: Vec<Request>,
) -> Vec<Reply> {
    let (mut client, connection) =
        h2::client::handshake(TokioSocket(PolledSocket::new(driver, client).unwrap()))
            .await
            .unwrap();
    let connection_task = driver.spawn("grpc-client", connection);
    let mut replies = Vec::new();
    for (request, chunks) in requests {
        let (response, mut output) = client.send_request(request, chunks.is_empty()).unwrap();
        let count = chunks.len();
        for (index, chunk) in chunks.into_iter().enumerate() {
            output.send_data(chunk.into(), index + 1 == count).unwrap();
        }
        let response = response.await.unwrap();
        let status = response.status();
        let mut input = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = input.data().await {
            let chunk = chunk.unwrap();
            input.flow_control().release_capacity(chunk.len()).unwrap();
            body.extend_from_slice(&chunk);
        }
        replies.push(Reply {
            status,
            body,
            trailers: input.trailers().await.unwrap(),
        });
    }
    drop(client);
    connection_task.await.unwrap();
    replies
}

// Test: Issue unary gRPC calls with split frames and every supported timeout unit.
// Expected: Service inputs, decoded deadlines, literal response bytes, and success
//       trailers survive the real HTTP/2 transport.
#[test]
fn grpc_unary_requests_preserve_payloads_and_deadlines() {
    DefaultPool::run_with(async |driver| {
        let mut server = Server::new();
        let mut incoming = server.add_service::<items::Example>();
        let cases = [
            (None, None),
            (Some("1H"), Some(Duration::from_secs(3600))),
            (Some("1M"), Some(Duration::from_secs(60))),
            (Some("10S"), Some(Duration::from_secs(10))),
            (Some("10000m"), Some(Duration::from_secs(10))),
            (Some("10000000u"), Some(Duration::from_secs(10))),
            (Some("1000000000n"), Some(Duration::from_secs(1))),
        ];
        let start = std::time::SystemTime::now();
        let handler = driver.spawn("grpc-handler", async move {
            for (_, expected_timeout) in cases {
                let (context, rpc) = incoming.next().await.unwrap();
                if let Some(duration) = expected_timeout {
                    let deadline = context.deadline().unwrap().system_time();
                    assert!(deadline >= start + duration);
                    assert!(deadline <= std::time::SystemTime::now() + duration);
                } else {
                    assert!(context.deadline().is_none());
                }
                match rpc {
                    items::Example::Method1(input, response) => {
                        assert_eq!(input.foo, "a");
                        assert_eq!(input.bar, "b");
                        response.send(Ok(items::Method1Response {
                            foo: "x".into(),
                            bar: "y".into(),
                        }));
                    }
                    _ => panic!("unexpected method"),
                }
            }
        });
        let path = format!("/{}/Method1", items::Example::NAME);
        let requests = cases
            .into_iter()
            .map(|(timeout, _)| {
                request(
                    &path,
                    Some("application/grpc+proto"),
                    timeout,
                    vec![
                        vec![0, 0],
                        vec![0, 0, 6],
                        vec![0x0a, 1, b'a'],
                        vec![0x12, 1, b'b'],
                    ],
                )
            })
            .collect();
        for reply in exchange(&driver, server, requests).await {
            assert_eq!(reply.status, http::StatusCode::OK);
            assert_eq!(reply.body, [0, 0, 0, 0, 6, 0x0a, 1, b'x', 0x12, 1, b'y']);
            assert_eq!(reply.trailers.unwrap()["grpc-status"], "0");
        }
        handler.await;
    });
}

// Test: Reject invalid HTTP methods, content types, paths, and timeout headers.
// Expected: Each malformed request receives its specific HTTP error status.
#[test]
fn grpc_rejects_invalid_http_requests() {
    DefaultPool::run_with(async |driver| {
        let mut get = request("/service/method", Some("application/grpc"), None, vec![]);
        *get.0.method_mut() = http::Method::GET;
        let requests = vec![
            get,
            request("/service/method", None, None, vec![]),
            request("/service/method", Some("application/json"), None, vec![]),
            request("/missing-method", Some("application/grpc"), None, vec![]),
            request(
                "/service/method",
                Some("application/grpc"),
                Some(""),
                vec![],
            ),
            request(
                "/service/method",
                Some("application/grpc"),
                Some("1x"),
                vec![],
            ),
            request(
                "/service/method",
                Some("application/grpc"),
                Some("abcS"),
                vec![],
            ),
        ];
        let replies = exchange(&driver, Server::new(), requests).await;
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.status.as_u16())
                .collect::<Vec<_>>(),
            [405, 415, 415, 404, 400, 400, 400]
        );
        assert!(replies.iter().all(|reply| reply.body.is_empty()));
    });
}

// Test: Route unknown, malformed, explicitly failed, and abandoned gRPC calls.
// Expected: HTTP stays successful while trailers preserve distinct RPC status codes,
//       messages, and protobuf status details.
#[test]
fn grpc_failures_preserve_status_trailers_and_details() {
    use base64::Engine;
    DefaultPool::run_with(async |driver| {
        let mut server = Server::new();
        let mut incoming = server.add_service::<items::Example>();
        let handler = driver.spawn("grpc-failure-handler", async move {
            for index in 0..2 {
                let (_, rpc) = incoming.next().await.unwrap();
                match rpc {
                    items::Example::Method1(input, response) => {
                        assert_eq!(input.foo, "a");
                        assert_eq!(input.bar, "b");
                        if index == 0 {
                            response.send(Err(crate::service::Status {
                                code: Code::PermissionDenied as i32,
                                message: "denied: x/y".into(),
                                details: vec![],
                            }));
                        } else {
                            drop(response);
                        }
                    }
                    _ => panic!("unexpected method"),
                }
            }
        });
        let path = format!("/{}/Method1", items::Example::NAME);
        let unknown_method = format!("/{}/Unknown", items::Example::NAME);
        let payload = vec![vec![0, 0, 0, 0, 6, 0x0a, 1, b'a', 0x12, 1, b'b']];
        let requests = vec![
            request("/unknown/Method1", Some("application/grpc"), None, vec![]),
            request(
                &unknown_method,
                Some("application/grpc"),
                None,
                payload.clone(),
            ),
            request(
                &path,
                Some("application/grpc"),
                None,
                vec![vec![0, 0, 0, 0, 1, 0xff]],
            ),
            request(&path, Some("application/grpc"), None, payload.clone()),
            request(&path, Some("application/grpc"), None, payload),
        ];
        let replies = exchange(&driver, server, requests).await;
        for (index, (reply, expected_code)) in
            replies.into_iter().zip([12, 12, 3, 7, 13]).enumerate()
        {
            assert_eq!(reply.status, http::StatusCode::OK);
            assert!(reply.body.is_empty());
            let trailers = reply.trailers.unwrap();
            assert_eq!(
                trailers["grpc-status"].to_str().unwrap(),
                expected_code.to_string()
            );
            let message = urlencoding::decode(trailers["grpc-message"].to_str().unwrap()).unwrap();
            let details = base64::engine::general_purpose::STANDARD
                .decode(trailers["grpc-status-details-bin"].as_bytes())
                .unwrap();
            let status =
                <crate::service::Status as prost::Message>::decode(details.as_slice()).unwrap();
            assert_eq!(status.code, expected_code);
            assert_eq!(status.message, message);
            match index {
                0 => assert_eq!(message, "unknown service unknown"),
                1 => assert_eq!(message, "unknown method Unknown"),
                3 => assert_eq!(message, "denied: x/y"),
                _ => assert!(!message.is_empty()),
            }
        }
        handler.await;
    });
}

// Test: Accept an HTTP/2 connection through the public gRPC listener loop.
// Expected: A request gets a real gRPC response and cancellation stops the listener.
#[test]
fn grpc_listener_accepts_requests_and_stops_on_cancel() {
    DefaultPool::run_with(async |driver| {
        let mut timeout = mesh::CancelContext::new().with_timeout(Duration::from_secs(5));
        timeout
            .until_cancelled(async {
                let (path, listener) = SocketPath::bind();
                let mut server = Server::new();
                let (cancel, cancelled) = mesh::oneshot();
                let run_driver = driver.clone();
                let server_task = driver.spawn("grpc-listener", async move {
                    server.run_grpc(&run_driver, listener, cancelled).await
                });
                let client = unix_socket::UnixStream::connect(&path.0).unwrap();
                let replies = exchange_connection(
                    &driver,
                    client,
                    vec![request(
                        "/unknown/Method1",
                        Some("application/grpc"),
                        None,
                        vec![],
                    )],
                )
                .await;
                assert_eq!(replies.len(), 1);
                assert_eq!(replies[0].status, http::StatusCode::OK);
                assert_eq!(replies[0].trailers.as_ref().unwrap()["grpc-status"], "12");
                cancel.send(());
                server_task.await.unwrap();
            })
            .await
            .expect("gRPC listener test timed out");
    });
}
