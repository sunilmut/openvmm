// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The main pipette agent, which is run when the process starts.

use anyhow::Context;
use futures::AsyncRead;
use futures::AsyncWrite;
use futures::future::FutureExt;
use futures_concurrency::future::Race;
use mesh_remote::PointToPointMesh;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use pal_async::task::Spawn;
use pal_async::timer::PolledTimer;
use pipette_protocol::DiagnosticFile;
use pipette_protocol::PipetteBootstrap;
use pipette_protocol::PipetteRequest;
use socket2::Socket;
use std::time::Duration;
use std::time::SystemTime;
use unicycle::FuturesUnordered;
use vmsocket::VmAddress;
use vmsocket::VmSocket;

/// The transport used by the pipette agent to communicate with the host.
#[derive(Clone, Copy, Debug)]
pub enum Transport {
    /// Hyper-V sockets or virtio-vsock (the default).
    Vsock,
    /// TCP over a network interface (e.g. virtio-net + consomme).
    Tcp,
}

pub struct Agent {
    driver: DefaultDriver,
    mesh: PointToPointMesh,
    request_recv: mesh::Receiver<PipetteRequest>,
    diag_file_send: DiagnosticSender,
    watch_send: mesh::OneshotSender<()>,
}

#[derive(Clone)]
pub struct DiagnosticSender(mesh::Sender<DiagnosticFile>);

impl Agent {
    pub async fn new(driver: DefaultDriver, transport: Transport) -> anyhow::Result<Self> {
        match transport {
            Transport::Vsock => {
                let socket = (connect_client(&driver), connect_server(&driver))
                    .race()
                    .await;
                let local_vsock_cid = cfg_select! {
                    target_os = "linux" => Some(
                        vmsocket::local_vsock_cid()
                            .context("failed to query local AF_VSOCK CID")?,
                    ),
                    windows => None,
                };
                Self::from_conn(driver, socket, local_vsock_cid)
            }
            Transport::Tcp => {
                let socket = connect_server_tcp(&driver).await?;
                Self::from_conn(driver, socket, None)
            }
        }
    }

    fn from_conn(
        driver: DefaultDriver,
        conn: impl 'static + AsyncRead + AsyncWrite + Send + Unpin,
        local_vsock_cid: Option<u32>,
    ) -> anyhow::Result<Self> {
        eprintln!("Pipette handshaking with host");
        let (bootstrap_send, bootstrap_recv) = mesh::oneshot::<PipetteBootstrap>();
        let mesh = PointToPointMesh::new(&driver, conn, bootstrap_recv.into());

        let (request_send, request_recv) = mesh::channel();
        let (diag_file_send, diag_file_recv) = mesh::channel();
        let (watch_send, watch_recv) = mesh::oneshot();
        eprintln!("Pipette initializing tracing");
        let log = crate::trace::init_tracing();

        bootstrap_send.send(PipetteBootstrap {
            requests: request_send,
            local_vsock_cid,
            diag_file_recv,
            watch: watch_recv,
            log,
        });
        eprintln!("Pipette bootstrap sent to host");

        Ok(Self {
            driver,
            mesh,
            request_recv,
            diag_file_send: DiagnosticSender(diag_file_send),
            watch_send,
        })
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut tasks = FuturesUnordered::new();
        loop {
            futures::select! {
                req = self.request_recv.recv().fuse() => {
                    match req {
                        Ok(req) => {
                            tasks.push(handle_request(&self.driver, req, self.diag_file_send.clone()));
                        },
                        Err(e) => {
                            tracing::info!(?e, "request channel closed, shutting down");
                            break;
                        }
                    }
                }
                _ = tasks.next() => {}
            }
        }
        self.watch_send.send(());
        self.mesh.shutdown().await;
        Ok(())
    }
}

async fn connect_server(driver: &DefaultDriver) -> PolledSocket<Socket> {
    let server_core = async || {
        let mut socket = VmSocket::new()?;
        socket.bind(VmAddress::vsock_any(pipette_protocol::PIPETTE_PORT))?;
        let mut socket =
            PolledSocket::new(driver, socket.into()).context("failed to create polled socket")?;
        socket.listen(1)?;
        let socket = socket
            .accept()
            .await
            .context("failed to accept connection")?
            .0;
        PolledSocket::new(driver, socket).context("failed to create polled server socket")
    };

    match server_core().await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("failed to stand up server: {:?}", err);
            std::future::pending().await
        }
    }
}

async fn connect_client(driver: &DefaultDriver) -> PolledSocket<Socket> {
    let client_core = async || {
        let socket = VmSocket::new()?;
        // Extend the default timeout of 2 seconds, as tests are often run in
        // parallel on a host, causing very heavy load on the overall system.
        socket
            .set_connect_timeout(Duration::from_secs(5))
            .context("failed to set socket timeout")?;
        let mut socket = PolledSocket::new(driver, socket)
            .context("failed to create polled client socket")?
            .convert();
        socket
            .connect(&VmAddress::vsock_host(pipette_protocol::PIPETTE_PORT).into())
            .await
            .context("failed to connect")
            .map(|()| socket)
    };
    loop {
        let mut timer = PolledTimer::new(driver);
        match client_core().await {
            Ok(socket) => return socket,
            Err(err) => {
                eprintln!("failed to connect to server, retrying: {:?}", err);
                timer.sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Listen for an incoming TCP connection from the host on the pipette TCP port.
async fn connect_server_tcp(
    driver: &DefaultDriver,
) -> anyhow::Result<PolledSocket<std::net::TcpStream>> {
    let listener = std::net::TcpListener::bind(("0.0.0.0", pipette_protocol::PIPETTE_PORT as u16))
        .context("failed to bind TCP listener")?;
    eprintln!("{}", pipette_protocol::PIPETTE_READY_MARKER);
    listener
        .set_nonblocking(true)
        .context("failed to set nonblocking")?;
    let mut listener =
        PolledSocket::new(driver, listener).context("failed to create polled TCP listener")?;
    let (stream, addr) = listener
        .accept()
        .await
        .context("failed to accept TCP connection")?;
    stream
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY")?;
    eprintln!("Pipette accepted TCP connection from {addr}");
    PolledSocket::new(driver, stream).context("failed to create polled TCP stream")
}

async fn handle_request(
    driver: &DefaultDriver,
    req: PipetteRequest,
    _diag_file_send: DiagnosticSender,
) {
    match req {
        PipetteRequest::Ping(rpc) => rpc.handle_sync(|()| {
            tracing::info!("ping");
        }),
        PipetteRequest::Execute(rpc) => {
            rpc.handle_failable_sync(|req| crate::execute::handle_execute(driver, req))
        }
        PipetteRequest::Shutdown(rpc) => {
            rpc.handle_sync(|request| {
                tracing::info!(shutdown_type = ?request.shutdown_type, "shutdown request");
                // TODO: handle this inline without waiting. Currently we spawn
                // a task so that the response is sent before the shutdown
                // starts, since OpenVMM fails to notice that the connection is
                // closed if we power off while a response is pending.
                let mut timer = PolledTimer::new(driver);
                driver
                    .spawn("shutdown", async move {
                        // Because pipette runs as a system service on Windows
                        // it is able to issue a shutdown command before Windows
                        // has finished starting up and logging in the user. This
                        // can put the system into a stuck state, where it is
                        // completely unable to shut down. To avoid this, we
                        // wait for a longer period before attempting to shut down.
                        #[cfg(windows)]
                        timer.sleep(Duration::from_secs(5)).await;
                        #[cfg(not(windows))]
                        timer.sleep(Duration::from_millis(250)).await;
                        loop {
                            match crate::shutdown::handle_shutdown(request) {
                                Ok(()) => break,
                                Err(err) => {
                                    tracing::error!(
                                        error = err.as_ref() as &dyn std::error::Error,
                                        "failed to shut down"
                                    );
                                }
                            }
                            timer.sleep(Duration::from_secs(5)).await;
                            tracing::warn!("still waiting to shut down, trying again");
                        }
                    })
                    .detach();
                Ok(())
            })
        }
        PipetteRequest::ReadFile(rpc) => rpc.handle_failable(read_file).await,
        PipetteRequest::WriteFile(rpc) => rpc.handle_failable(write_file).await,
        PipetteRequest::ListDir(rpc) => rpc.handle_failable(list_dir).await,
        PipetteRequest::GetTime(rpc) => rpc.handle_sync(|()| SystemTime::now().into()),
        PipetteRequest::Crash(rpc) => rpc.handle_sync(|()| panic!("crash requested")),
        PipetteRequest::KernelCrash(rpc) => {
            rpc.handle_failable(async |()| {
                crate::crash::trigger_kernel_crash()?;
                std::future::pending::<()>().await;
                anyhow::Ok(())
            })
            .await
        }
        #[cfg(target_os = "linux")]
        PipetteRequest::Mount(rpc) => rpc.handle_failable_sync(crate::mount::handle_mount),
        #[cfg(not(target_os = "linux"))]
        PipetteRequest::Mount(rpc) => {
            rpc.handle_failable_sync(|_| anyhow::bail!("mount not supported on this platform"))
        }
    }
}

async fn read_file(mut request: pipette_protocol::ReadFileRequest) -> anyhow::Result<u64> {
    tracing::debug!(path = request.path, "Beginning file read request");
    let file = fs_err::File::open(request.path)?;
    let n = futures::io::copy(&mut futures::io::AllowStdIo::new(file), &mut request.sender).await?;
    tracing::debug!("file read request complete");
    Ok(n)
}

async fn write_file(mut request: pipette_protocol::WriteFileRequest) -> anyhow::Result<u64> {
    tracing::debug!(path = request.path, "Beginning file write request");
    let file = fs_err::File::create(request.path)?;
    let n = futures::io::copy(
        &mut request.receiver,
        &mut futures::io::AllowStdIo::new(file),
    )
    .await?;
    tracing::debug!("file write request complete");
    Ok(n)
}

async fn list_dir(
    request: pipette_protocol::ListDirRequest,
) -> anyhow::Result<pipette_protocol::ListDirResponse> {
    tracing::debug!(path = request.path, "Beginning list dir request");
    let mut files = Vec::new();
    for entry in fs_err::read_dir(request.path)? {
        files.push(
            entry?
                .file_name()
                .to_str()
                .context("filename not utf8")?
                .to_string(),
        );
    }
    tracing::debug!("list dir request complete");
    Ok(pipette_protocol::ListDirResponse { files })
}

impl DiagnosticSender {
    #[cfg_attr(not(windows), expect(dead_code))]
    pub async fn send(&self, filename: &str) -> anyhow::Result<()> {
        tracing::debug!(filename, "Beginning diagnostic file request");
        let file = fs_err::File::open(filename)?;
        let (recv_pipe, mut send_pipe) = mesh::pipe::pipe();
        self.0.send(DiagnosticFile {
            name: filename.to_owned(),
            receiver: recv_pipe,
        });
        futures::io::copy(&mut futures::io::AllowStdIo::new(file), &mut send_pipe).await?;
        drop(send_pipe);
        tracing::debug!("diagnostic request complete");
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;
    use pal_async::async_test;
    use std::os::unix::ffi::OsStrExt;

    // Test: Write a binary payload through the write-file request into an owned
    //       temporary directory, then read it back through the read-file request.
    // Expected: Both requests report the exact byte count and the bytes survive
    //       the round trip, including NUL and non-UTF-8 values.
    #[async_test]
    async fn file_requests_round_trip_binary_contents(_driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();

        let (receiver, mut writer) = mesh::pipe::pipe();
        let write = write_file(pipette_protocol::WriteFileRequest {
            path: path.to_str().unwrap().into(),
            receiver,
        });
        let feed = async {
            writer.write_all(&payload).await.unwrap();
            drop(writer);
        };
        let (written, ()) = futures::join!(write, feed);
        assert_eq!(written.unwrap(), payload.len() as u64);
        assert_eq!(fs_err::read(&path).unwrap(), payload);

        let (mut reader, sender) = mesh::pipe::pipe();
        let read = read_file(pipette_protocol::ReadFileRequest {
            path: path.to_str().unwrap().into(),
            sender,
        });
        let drain = async {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            out
        };
        let (count, out) = futures::join!(read, drain);
        assert_eq!(count.unwrap(), payload.len() as u64);
        assert_eq!(out, payload);
    }

    // Test: Read a missing file, write into a missing directory, list a
    //       directory with a non-UTF-8 entry, and list a normal directory.
    // Expected: Failures are reported as errors; a normal listing returns every
    //       entry name, and a non-UTF-8 name fails rather than being mangled.
    #[async_test]
    async fn file_request_failures_and_listing(_driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let (_reader, sender) = mesh::pipe::pipe();
        assert!(
            read_file(pipette_protocol::ReadFileRequest {
                path: missing.to_str().unwrap().into(),
                sender,
            })
            .await
            .is_err()
        );
        let (receiver, _writer) = mesh::pipe::pipe();
        assert!(
            write_file(pipette_protocol::WriteFileRequest {
                path: missing.join("child").to_str().unwrap().into(),
                receiver,
            })
            .await
            .is_err()
        );

        fs_err::write(dir.path().join("a"), b"").unwrap();
        fs_err::create_dir(dir.path().join("sub dir")).unwrap();
        let list = |path: &std::path::Path| {
            list_dir(pipette_protocol::ListDirRequest {
                path: path.to_str().unwrap().into(),
            })
        };
        let mut files = list(dir.path()).await.unwrap().files;
        files.sort();
        assert_eq!(files, ["a", "sub dir"]);
        assert!(list(&missing).await.is_err());

        fs_err::write(
            dir.path().join(std::ffi::OsStr::from_bytes(b"bad\xff")),
            b"",
        )
        .unwrap();
        let Err(error) = list(dir.path()).await else {
            panic!("non-UTF-8 entry unexpectedly listed");
        };
        assert_eq!(error.to_string(), "filename not utf8");
    }
}
