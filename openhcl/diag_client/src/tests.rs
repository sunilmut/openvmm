// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use diag_proto::OpenhclDiag;
use diag_proto::UnderhillDiag;
use futures::StreamExt;
use mesh_rpc::server::RpcReceiver;
use mesh_rpc::service::Code;
use pal_async::DefaultDriver;
use pal_async::task::Task;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use unix_socket::UnixListener;
use unix_socket::UnixStream;

mod requests;
mod streams;

struct Fixture {
    client: DiagClient,
    underhill: RpcReceiver<UnderhillDiag>,
    openhcl: RpcReceiver<OpenhclDiag>,
    data: async_channel::Receiver<(u64, PolledSocket<UnixStream>)>,
    fail_data_at: Arc<AtomicU64>,
    _listener: Task<()>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(driver: DefaultDriver) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("diag.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut listener = PolledSocket::new(&driver, listener).unwrap();
        let mut server = mesh_rpc::Server::new();
        let underhill = server.add_service();
        let openhcl = server.add_service();
        let server = Arc::new(server);
        let (send_data, data) = async_channel::unbounded();
        let fail_data_at = Arc::new(AtomicU64::new(0));
        let failure = fail_data_at.clone();
        let connection_driver = driver.clone();
        let task = driver.spawn("fake-hybrid-vsock", async move {
            let mut connections = Vec::new();
            let mut next_id = 100u64;
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = PolledSocket::new(&connection_driver, stream).unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 32, "unexpected hybrid handshake");
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let port: u32 = request
                    .strip_prefix("CONNECT ")
                    .unwrap()
                    .trim_end()
                    .parse()
                    .unwrap();
                match port {
                    diag_proto::VSOCK_CONTROL_PORT => {
                        stream.write_all(b"OK 1\n").await.unwrap();
                        let server = server.clone();
                        connections.push(connection_driver.spawn("fake-diag-rpc", async move {
                            server.serve_connection(stream).await.unwrap();
                        }));
                    }
                    diag_proto::VSOCK_DATA_PORT => {
                        if failure.load(Ordering::SeqCst) == next_id - 99 {
                            stream.write_all(b"NO 2\n").await.unwrap();
                        } else {
                            stream.write_all(b"OK 2\n").await.unwrap();
                            stream.write_all(&next_id.to_ne_bytes()).await.unwrap();
                            send_data.send((next_id, stream)).await.unwrap();
                        }
                        next_id += 1;
                    }
                    _ => panic!("unexpected diagnostic port {port}"),
                }
            }
        });
        Self {
            client: DiagClient::from_hybrid_vsock(driver, &path),
            underhill,
            openhcl,
            data,
            fail_data_at,
            _listener: task,
            _directory: directory,
        }
    }
}

async fn underhill<T>(
    call: impl Future<Output = T>,
    receiver: &mut RpcReceiver<UnderhillDiag>,
    respond: impl FnOnce(UnderhillDiag),
) -> T {
    let (result, ()) = futures::join!(call, async {
        respond(receiver.next().await.unwrap().1);
    });
    result
}

async fn openhcl<T>(
    call: impl Future<Output = T>,
    receiver: &mut RpcReceiver<OpenhclDiag>,
    respond: impl FnOnce(OpenhclDiag),
) -> T {
    let (result, ()) = futures::join!(call, async {
        respond(receiver.next().await.unwrap().1);
    });
    result
}

fn denied() -> Status {
    Status {
        code: Code::PermissionDenied.into(),
        message: "injected diagnostic failure".to_owned(),
        details: Vec::new(),
    }
}
