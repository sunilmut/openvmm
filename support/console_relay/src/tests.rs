// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::future::try_join;
use futures::future::try_join3;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::socket::PolledSocket;
use std::task::Poll;
use std::task::Waker;
use test_with_tracing::test;
use unix_socket::UnixListener;

mod launch_tests;

#[cfg(target_os = "linux")]
mod stdio_tests;

// Test: Bind a second console at an occupied socket path and request a missing relay endpoint or explicitly missing terminal.
// Expected: Errors retain their underlying I/O kind and useful operation context; an explicit terminal never silently falls back to another executable.
#[async_test]
async fn console_setup_errors_preserve_io_causes_and_context(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("occupied.sock");
    let _console = Console::new_from_path(driver.clone(), &socket_path).unwrap();
    let error = Console::new_from_path(driver.clone(), &socket_path)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "failed to create console socket");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::AddrInUse
    );
    let missing = directory.path().join("missing-terminal");
    let error = launch_console(
        Some(&missing),
        &socket_path,
        ConsoleLaunchOptions::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(error.to_string().contains("failed to launch terminal"));
    assert!(error.to_string().contains("missing-terminal"));
}

// Test: Request synchronous stdio relay to an absent Unix socket.
// Expected: Connection fails before entering terminal raw mode, with the original not-found cause and console-socket context intact.
#[test]
fn relay_connection_failure_does_not_require_a_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let error = relay_console(&directory.path().join("absent.sock"), "not opened").unwrap_err();
    assert_eq!(error.to_string(), "failed to connect to console socket");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}

// Test: Poll an unconnected console, connect a real client, and transfer binary bytes in both directions while half-closing output.
// Expected: The initial read remains pending, flush does not wait for a client, every byte arrives in order, and closing console output still permits the client's final input.
#[async_test]
async fn console_accepts_connections_and_preserves_binary_half_closed_io(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("console.sock");
    let mut console = Console::new_from_path(driver.clone(), &path).unwrap();
    let mut first = [0; 7];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut console)
            .poll_read(&mut cx, &mut first)
            .is_pending()
    );
    assert!(matches!(
        Pin::new(&mut console).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    let mut client = PolledSocket::connect_unix(&driver, &path).await.unwrap();
    let server = async {
        console.read_exact(&mut first).await?;
        assert_eq!(&first, b"hello\0\xff");
        console.write_all(b"reply\0\xfe").await?;
        console.flush().await?;
        console.close().await?;
        let mut tail = Vec::new();
        console.read_to_end(&mut tail).await?;
        assert_eq!(tail, b"tail\n");
        std::io::Result::Ok(())
    };
    let peer = async {
        client.write_all(b"hello\0\xff").await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        assert_eq!(response, b"reply\0\xfe");
        client.write_all(b"tail\n").await?;
        client.close().await?;
        std::io::Result::Ok(())
    };
    try_join(server, peer).await.unwrap();
}

// Test: Relay between a console client and an application socket, with both peers sending binary data before closing their write halves.
// Expected: Each peer receives only the other's complete payload and EOF; the relay finishes after both independent directions drain.
#[async_test]
async fn relay_drains_both_directions_and_propagates_half_close(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let console_path = directory.path().join("console.sock");
    let app_path = directory.path().join("application.sock");
    let mut console = Console::new_from_path(driver.clone(), &console_path).unwrap();
    let listener = UnixListener::bind(&app_path).unwrap();
    let mut listener = PolledSocket::new(&driver, listener).unwrap();
    let mut terminal = PolledSocket::connect_unix(&driver, &console_path)
        .await
        .unwrap();
    let mut application = PolledSocket::connect_unix(&driver, &app_path)
        .await
        .unwrap();
    let relay = async {
        let (stream, _) = listener.accept().await?;
        console.relay(PolledSocket::new(&driver, stream)?).await
    };
    let terminal_peer = async {
        terminal.write_all(b"terminal\0\xff").await?;
        terminal.close().await?;
        let mut response = Vec::new();
        terminal.read_to_end(&mut response).await?;
        assert_eq!(response, b"application\0\xfe");
        anyhow::Ok(())
    };
    let application_peer = async {
        application.write_all(b"application\0\xfe").await?;
        application.close().await?;
        let mut response = Vec::new();
        application.read_to_end(&mut response).await?;
        assert_eq!(response, b"terminal\0\xff");
        anyhow::Ok(())
    };
    try_join3(relay, terminal_peer, application_peer)
        .await
        .unwrap();
}

// Test: Relay a multi-megabyte request, half-close it, and send a large response only after the application observes EOF.
// Expected: Both directions drain every binary byte in order, and request EOF does not terminate the still-open response direction.
#[async_test]
async fn relay_preserves_large_response_started_after_request_eof(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let console_path = directory.path().join("console.sock");
    let app_path = directory.path().join("application.sock");
    let mut console = Console::new_from_path(driver.clone(), &console_path).unwrap();
    let listener = UnixListener::bind(&app_path).unwrap();
    let mut listener = PolledSocket::new(&driver, listener).unwrap();
    let mut terminal = PolledSocket::connect_unix(&driver, &console_path)
        .await
        .unwrap();
    let mut application = PolledSocket::connect_unix(&driver, &app_path)
        .await
        .unwrap();
    let request: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let response: Vec<u8> = request.iter().rev().map(|byte| byte ^ 0x5a).collect();
    let relay = async {
        let (stream, _) = listener.accept().await?;
        console.relay(PolledSocket::new(&driver, stream)?).await
    };
    let terminal_peer = async {
        terminal.write_all(&request).await?;
        terminal.close().await?;
        let mut received = Vec::new();
        terminal.read_to_end(&mut received).await?;
        assert_eq!(received, response);
        anyhow::Ok(())
    };
    let application_peer = async {
        let mut received = Vec::new();
        application.read_to_end(&mut received).await?;
        assert_eq!(received, request);
        application.write_all(&response).await?;
        application.close().await?;
        anyhow::Ok(())
    };
    try_join3(relay, terminal_peer, application_peer)
        .await
        .unwrap();
}
