// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Negotiate hybrid-vsock responses with valid, malformed, and truncated headers.
// Expected: The requested port is transmitted exactly; valid negotiation leaves
//       payload bytes unread, while invalid responses return non-retryable errors.
#[async_test]
async fn hybrid_handshakes_validate_responses_without_consuming_payload(driver: DefaultDriver) {
    for (reply, valid) in [
        (&b"OK 4294967295\nxy"[..], true),
        (&b"NO 0\n"[..], false),
        (&b"OK 12345678901\n"[..], false),
        (&b"O"[..], false),
        (&b"OK 4"[..], false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("handshake.sock");
        let mut listener = PolledSocket::new(&driver, UnixListener::bind(&path).unwrap()).unwrap();
        let peer = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = PolledSocket::new(&driver, socket).unwrap();
            let mut request = [0; 13];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"CONNECT 4321\n");
            socket.write_all(reply).await.unwrap();
        };
        let (result, ()) = futures::join!(connect_hybrid_vsock(&driver, &path, 4321), peer);
        if valid {
            let mut socket = result.unwrap();
            let mut bytes = [0; 2];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"xy");
        } else {
            let error = result.err().unwrap();
            assert!(error.retry_timeout().is_none());
            assert!(std::error::Error::source(&error).is_some());
        }
    }
}

// Test: Connect to a missing hybrid socket and receive a truncated data ID.
// Expected: Both failures are explicit, with data-ID failures retaining their
//       connection-ID context.
#[async_test]
async fn unavailable_sockets_and_truncated_data_ids_report_errors(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("absent.sock");
    let error = connect_hybrid_vsock(&driver, &path, 2).await.err().unwrap();
    assert!(error.retry_timeout().is_none());
    let mut listener = PolledSocket::new(&driver, UnixListener::bind(&path).unwrap()).unwrap();
    let client = DiagClient::from_hybrid_vsock(driver.clone(), &path);
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = PolledSocket::new(&driver, socket).unwrap();
        let mut request = [0; 10];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"CONNECT 2\n");
        socket.write_all(b"OK 2\nabcd").await.unwrap();
    };
    let (result, ()) = futures::join!(client.connect_data(), peer);
    assert_eq!(result.err().unwrap().to_string(), "reading connection id");
}

// Test: Stream file bytes using the data connection negotiated for ReadFile.
// Expected: Follow and path reach the peer, the RPC uses the negotiated ID,
//       and binary payload bytes are returned unchanged.
#[async_test]
async fn read_file_pairs_its_rpc_with_the_negotiated_stream(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut socket = underhill(
        fixture.client.read_file(true, "/tmp/a file".to_owned()),
        &mut fixture.underhill,
        |rpc| {
            let UnderhillDiag::ReadFile(request, response) = rpc else {
                panic!("expected ReadFile")
            };
            assert!(request.follow);
            assert_eq!(request.file_path, "/tmp/a file");
            assert_eq!(request.conn, 100);
            response.send(Ok(()));
        },
    )
    .await
    .unwrap();
    let (id, mut peer) = fixture.data.recv().await.unwrap();
    assert_eq!(id, 100);
    peer.write_all(&[0, 255, 17]).await.unwrap();
    drop(peer);
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, [0, 255, 17]);
}

// Test: Query, start, and stop packet capture with two separate data streams.
// Expected: Only Start allocates streams, requested snap length and connection
//       IDs reach the peer, and returned streams carry distinct packet bytes.
#[async_test]
async fn packet_capture_negotiates_distinct_streams_only_when_starting(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    for (operation, expected) in [
        (PacketCaptureOperation::Query, Operation::Query),
        (PacketCaptureOperation::Stop, Operation::Stop),
    ] {
        let (sockets, count) = underhill(
            fixture.client.packet_capture(operation, 2, 123),
            &mut fixture.underhill,
            |rpc| {
                let UnderhillDiag::PacketCapture(request, response) = rpc else {
                    panic!("expected capture request")
                };
                assert_eq!(request.operation, expected as i32);
                assert!(request.op_data.is_none());
                response.send(Ok(diag_proto::NetworkPacketCaptureResponse {
                    num_streams: 2,
                }));
            },
        )
        .await
        .unwrap();
        assert!(sockets.is_empty());
        assert_eq!(count, 2);
    }
    let (sockets, count) = underhill(
        fixture
            .client
            .packet_capture(PacketCaptureOperation::Start, 2, 65535),
        &mut fixture.underhill,
        |rpc| {
            let UnderhillDiag::PacketCapture(request, response) = rpc else {
                panic!("expected capture request")
            };
            assert_eq!(request.operation, Operation::Start as i32);
            let Some(OpData::StartData(data)) = request.op_data else {
                panic!("expected capture stream IDs");
            };
            assert_eq!(data.snaplen, 65535);
            assert_eq!(data.conns, [100, 101]);
            response.send(Ok(diag_proto::NetworkPacketCaptureResponse {
                num_streams: 2,
            }));
        },
    )
    .await
    .unwrap();
    assert_eq!((sockets.len(), count), (2, 2));
    for (index, mut socket) in sockets.into_iter().enumerate() {
        let (id, mut peer) = fixture.data.recv().await.unwrap();
        assert_eq!(id, 100 + index as u64);
        peer.write_all(&[index as u8, 255]).await.unwrap();
        let mut bytes = [0; 2];
        socket.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [index as u8, 255]);
    }
}

// Test: Spawn a process with all standard streams enabled and exchange bytes.
// Expected: Stdin, stdout, and stderr retain their independent negotiated IDs
//       and route payload bytes in the correct direction.
#[async_test]
async fn process_stdio_streams_keep_their_ids_and_directions(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver.clone());
    let mut command = fixture.client.exec("streaming");
    command.stdin(true).stdout(true).stderr(true);
    let mut process = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Exec(request, response) = rpc else {
            panic!("expected Exec")
        };
        assert_eq!(
            (request.stdin, request.stdout, request.stderr),
            (100, 101, 102)
        );
        response.send(Ok(diag_proto::ExecResponse { pid: 80 }));
    })
    .await
    .unwrap();
    let mut stdin = PolledSocket::new(&driver, process.stdin.take().unwrap()).unwrap();
    let mut stdout = PolledSocket::new(&driver, process.stdout.take().unwrap()).unwrap();
    let mut stderr = PolledSocket::new(&driver, process.stderr.take().unwrap()).unwrap();
    let (_, mut input_peer) = fixture.data.recv().await.unwrap();
    let (_, mut output_peer) = fixture.data.recv().await.unwrap();
    let (_, mut error_peer) = fixture.data.recv().await.unwrap();
    stdin.write_all(b"in").await.unwrap();
    let mut bytes = [0; 2];
    input_peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"in");
    output_peer.write_all(b"ou").await.unwrap();
    error_peer.write_all(b"er").await.unwrap();
    stdout.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ou");
    stderr.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"er");
    underhill(process.wait(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Wait(request, response) = rpc else {
            panic!("expected Wait")
        };
        assert_eq!(request.pid, 80);
        response.send(Ok(WaitResponse { exit_code: 0 }));
    })
    .await
    .unwrap();
}

// Test: Read empty, fragmented, coalesced, and maximum-size kmsg entries.
// Expected: NUL boundaries are removed without losing bytes, partial entries
//       remain pending, and a closed clean stream ends normally.
#[async_test]
async fn kmsg_preserves_entry_boundaries_across_socket_reads(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut stream = underhill(fixture.client.kmsg(true), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Kmsg(request, response) = rpc else {
            panic!("expected Kmsg")
        };
        assert!(request.follow);
        assert_eq!(request.conn, 100);
        response.send(Ok(()));
    })
    .await
    .unwrap();
    let (_, mut peer) = fixture.data.recv().await.unwrap();
    assert!(stream.next().now_or_never().is_none());
    peer.write_all(b"first\0\0seco").await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), b"first");
    assert!(stream.next().await.unwrap().unwrap().is_empty());
    assert!(stream.next().now_or_never().is_none());
    peer.write_all(b"nd\0last\0").await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), b"second");
    assert_eq!(stream.next().await.unwrap().unwrap(), b"last");
    let mut maximum = vec![0xaa; diag_proto::FILE_LINE_MAX];
    *maximum.last_mut().unwrap() = 0;
    peer.write_all(&maximum).await.unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        maximum[..maximum.len() - 1]
    );
    drop(peer);
    assert!(stream.next().await.is_none());
}

// Test: Receive a full kmsg buffer with no entry terminator.
// Expected: The stream reports InvalidData instead of truncating the entry or
//       treating an oversized record as a successful read.
#[async_test]
async fn kmsg_rejects_an_oversized_unterminated_entry(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut stream = underhill(fixture.client.kmsg(false), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Kmsg(request, response) = rpc else {
            panic!("expected Kmsg")
        };
        assert!(!request.follow);
        response.send(Ok(()));
    })
    .await
    .unwrap();
    let (_, mut peer) = fixture.data.recv().await.unwrap();
    peer.write_all(&vec![0xaa; diag_proto::FILE_LINE_MAX])
        .await
        .unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

// Test: Stream a core dump and stderr, with successful and failed remote exits.
// Expected: Payloads are copied exactly, verbose controls the command argument,
//       and a nonzero exit is returned as an error after both streams drain.
#[async_test]
async fn core_dump_copies_both_streams_and_checks_remote_exit(driver: DefaultDriver) {
    for (verbose, exit_code) in [(false, 0), (true, 17)] {
        let mut fixture = Fixture::new(driver.clone());
        let mut output = futures::io::Cursor::new(Vec::new());
        let mut errors = futures::io::Cursor::new(Vec::new());
        let peer = async {
            let (_, rpc) = fixture.underhill.next().await.unwrap();
            let UnderhillDiag::Exec(request, response) = rpc else {
                panic!("expected Exec")
            };
            assert_eq!(request.command, "/bin/underhill-dump");
            assert_eq!(
                request.args,
                if verbose {
                    vec!["-v", "42"]
                } else {
                    vec!["42"]
                }
            );
            assert!(request.raw_socket_io);
            assert_eq!(
                (request.stdin, request.stdout, request.stderr),
                (0, 100, 101)
            );
            response.send(Ok(diag_proto::ExecResponse { pid: 81 }));
            for bytes in [&b"core\0bytes"[..], &b"diagnostic stderr"[..]] {
                let (_, mut socket) = fixture.data.recv().await.unwrap();
                socket.write_all(bytes).await.unwrap();
            }
            let (_, rpc) = fixture.underhill.next().await.unwrap();
            let UnderhillDiag::Wait(request, response) = rpc else {
                panic!("expected Wait")
            };
            assert_eq!(request.pid, 81);
            response.send(Ok(WaitResponse { exit_code }));
        };
        let (result, ()) = futures::join!(
            fixture
                .client
                .core_dump(42, &mut output, &mut errors, verbose),
            peer
        );
        assert_eq!(output.into_inner(), b"core\0bytes");
        assert_eq!(errors.into_inner(), b"diagnostic stderr");
        if exit_code == 0 {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "underhill-dump failed with exit code 17"
            );
        }
    }
}

// IGNORED: KmsgStream returns a clean end of stream when the peer closes with
// an unterminated record buffered, silently losing the final diagnostic entry.
// Test: Close a kmsg stream after one complete record and a partial final record.
// Expected: The complete record is delivered, then truncation is an error rather
//       than a clean EOF or a successful incomplete record.
#[async_test]
#[ignore = "product bug: kmsg EOF silently discards an unterminated record"]
async fn kmsg_reports_a_truncated_final_record(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut stream = underhill(fixture.client.kmsg(false), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Kmsg(_, response) = rpc else {
            panic!("expected Kmsg")
        };
        response.send(Ok(()));
    })
    .await
    .unwrap();
    let (_, mut peer) = fixture.data.recv().await.unwrap();
    peer.write_all(b"complete\0unfinished").await.unwrap();
    drop(peer);
    assert_eq!(stream.next().await.unwrap().unwrap(), b"complete");
    let result = stream.next().await;
    assert!(
        matches!(result, Some(Err(_))),
        "expected a truncated-record error, got {result:?}"
    );
}
