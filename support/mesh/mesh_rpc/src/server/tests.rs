// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Client;
use crate::Server;
use crate::client::ExistingConnection;
use crate::service::Code;
use crate::service::ServiceRpc;
use futures::StreamExt;
use futures::executor::block_on;
use pal_async::DefaultPool;
use pal_async::local::block_with_io;
use pal_async::socket::PolledSocket;
use test_with_tracing::test;

#[expect(clippy::allow_attributes)]
mod items {
    include!(concat!(env!("OUT_DIR"), "/ttrpc.example.v1.rs"));
}

// Test: Exchange a typed call and an unknown method over a paired connection.
// Expected: Request/reply fields survive, unknown methods report Unimplemented,
//       and both client and server finish after shutdown.
#[test]
fn client_server() {
    let (c, s) = unix_socket::UnixStream::pair().unwrap();
    let mut server = Server::new();
    let mut recv = server.add_service::<items::Example>();
    let server_thread = std::thread::spawn(move || {
        block_with_io(async |driver| server.run_single(&driver, s).await)
    });

    let client_thread = std::thread::spawn(move || {
        DefaultPool::run_with(async |driver| {
            let client = Client::new(
                &driver,
                ExistingConnection::new(PolledSocket::new(&driver, c).unwrap()),
            );
            let response = client
                .call()
                .start(
                    items::Example::Method1,
                    items::Method1Request {
                        foo: "abc".to_string(),
                        bar: "def".to_string(),
                    },
                )
                .await
                .unwrap();

            assert_eq!(&response.foo, "abc123");
            assert_eq!(&response.bar, "def456");

            let status = client
                .call()
                .start_raw(items::Example::NAME, "unknown", Vec::new())
                .await
                .unwrap_err();

            assert_eq!(status.code, Code::Unimplemented as i32);

            client.shutdown().await;
        })
    });

    block_on(async {
        let (_, req) = recv.next().await.unwrap();
        match req {
            items::Example::Method1(input, resp) => {
                assert_eq!(&input.foo, "abc");
                assert_eq!(&input.bar, "def");
                resp.send(Ok(items::Method1Response {
                    foo: input.foo + "123",
                    bar: input.bar + "456",
                }));
            }
            _ => panic!("{:?}", req),
        }

        assert!(recv.next().await.is_none());
    });

    client_thread.join().unwrap();
    server_thread.join().unwrap().unwrap();
}

#[cfg(feature = "grpc")]
mod grpc;

struct SocketPath(std::path::PathBuf);

impl SocketPath {
    /// Binds a unique test socket before taking ownership of its path cleanup.
    fn bind() -> (Self, unix_socket::UnixListener) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rpc-{}-{stamp:x}-{sequence}.sock",
            std::process::id()
        ));
        let listener = unix_socket::UnixListener::bind(&path).unwrap();
        (Self(path), listener)
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.0.display(),
                    %error,
                    "Failed to remove test socket"
                );
            }
        }
    }
}

// Test: Serve a request through a Unix listener and cancel its accept loop.
// Expected: The call reaches the registered service and cancellation stops cleanly.
#[pal_async::async_test]
async fn listener_accepts_requests_and_stops_on_cancel(driver: pal_async::DefaultDriver) {
    use pal_async::task::Spawn;
    let mut timeout = mesh::CancelContext::new().with_timeout(std::time::Duration::from_secs(5));
    timeout
        .until_cancelled(async {
            let (path, listener) = SocketPath::bind();
            let mut server = Server::new();
            let mut incoming = server.add_service::<items::Example>();
            let (cancel, cancelled) = mesh::oneshot();
            let run_driver = driver.clone();
            let server_task = driver.spawn("ttrpc-listener", async move {
                server.run(&run_driver, listener, cancelled).await
            });
            let handler = driver.spawn("ttrpc-listener-handler", async move {
                let (context, rpc) = incoming.next().await.unwrap();
                assert!(context.deadline().is_some());
                match rpc {
                    items::Example::Method1(input, response) => {
                        assert_eq!(input.foo, "input");
                        response.send(Ok(items::Method1Response {
                            foo: "output".into(),
                            bar: input.bar,
                        }));
                    }
                    _ => panic!("unexpected method"),
                }
            });
            let client = Client::new(
                &driver,
                crate::client::UnixDialier::new(driver.clone(), path.0.clone()),
            );
            let output = client
                .call()
                .timeout(Some(std::time::Duration::from_secs(2)))
                .start(
                    items::Example::Method1,
                    items::Method1Request {
                        foo: "input".into(),
                        bar: "echo".into(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(output.foo, "output");
            assert_eq!(output.bar, "echo");
            client.shutdown().await;
            handler.await;
            cancel.send(());
            server_task.await.unwrap();
        })
        .await
        .expect("ttrpc listener test timed out");
}
