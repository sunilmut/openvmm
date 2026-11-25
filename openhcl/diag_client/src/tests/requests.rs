// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh_rpc::client::ExistingConnection;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Ping a new server, an older server without Ping, and a rejecting server.
// Expected: Success and Unimplemented mean ready; other statuses reach the caller.
#[async_test]
async fn readiness_accepts_old_servers_but_preserves_real_failures(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    for code in [Code::Ok, Code::Unimplemented, Code::PermissionDenied] {
        let result = openhcl(
            fixture.client.wait_for_server(),
            &mut fixture.openhcl,
            |rpc| {
                let OpenhclDiag::Ping((), response) = rpc else {
                    panic!("expected Ping")
                };
                if code == Code::Ok {
                    response.send(Ok(()));
                } else {
                    response.send(Err(Status {
                        code: code.into(),
                        ..denied()
                    }));
                }
            },
        )
        .await;
        if code == Code::PermissionDenied {
            assert_eq!(
                result.unwrap_err().to_string(),
                "injected diagnostic failure"
            );
        } else {
            result.unwrap();
        }
    }
}

// Test: Send VM lifecycle operations and start arguments to a diagnostic peer.
// Expected: Each operation selects the correct RPC and retains environment
//       deletion, empty values, and argument order.
#[async_test]
async fn lifecycle_requests_preserve_operations_environment_and_arguments(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    underhill(
        fixture.client.start(
            [("EMPTY".into(), Some("".into())), ("REMOVE".into(), None)],
            ["first".into(), "two words".into()],
        ),
        &mut fixture.underhill,
        |rpc| {
            let UnderhillDiag::Start(request, response) = rpc else {
                panic!("expected Start")
            };
            assert_eq!(request.args, ["first", "two words"]);
            assert_eq!(request.env.len(), 2);
            assert_eq!(request.env[0].name, "EMPTY");
            assert_eq!(request.env[0].value.as_deref(), Some(""));
            assert_eq!(request.env[1].name, "REMOVE");
            assert_eq!(request.env[1].value, None);
            response.send(Ok(()));
        },
    )
    .await
    .unwrap();
    underhill(fixture.client.pause(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Pause((), response) = rpc else {
            panic!("expected Pause")
        };
        response.send(Ok(()));
    })
    .await
    .unwrap();
    underhill(fixture.client.resume(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Resume((), response) = rpc else {
            panic!("expected Resume")
        };
        response.send(Ok(()));
    })
    .await
    .unwrap();
    underhill(fixture.client.restart(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Restart((), response) = rpc else {
            panic!("expected Restart")
        };
        response.send(Ok(()));
    })
    .await
    .unwrap();
    underhill(fixture.client.crash(123), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Crash(request, response) = rpc else {
            panic!("expected Crash")
        };
        assert_eq!(request.pid, 123);
        response.send(Ok(()));
    })
    .await
    .unwrap();
}

// Test: Return saved-state and memory-profile bytes and reject a lifecycle RPC.
// Expected: Binary data and target PID are unchanged; server errors are explicit.
#[async_test]
async fn diagnostic_payloads_and_server_errors_reach_callers(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let saved = underhill(
        fixture.client.dump_saved_state(),
        &mut fixture.underhill,
        |rpc| {
            let UnderhillDiag::DumpSavedState((), response) = rpc else {
                panic!("expected state request")
            };
            response.send(Ok(diag_proto::DumpSavedStateResponse {
                data: vec![0, 255, 7],
            }));
        },
    )
    .await
    .unwrap();
    assert_eq!(saved, [0, 255, 7]);
    let trace = openhcl(
        fixture.client.memory_profile_trace(321),
        &mut fixture.openhcl,
        |rpc| {
            let OpenhclDiag::MemoryProfileTrace(request, response) = rpc else {
                panic!("expected profile request")
            };
            assert_eq!(request.pid, 321);
            response.send(Ok(diag_proto::MemoryProfileTraceResponse {
                data: vec![4, 0, 5],
            }));
        },
    )
    .await
    .unwrap();
    assert_eq!(trace, [4, 0, 5]);
    let error = underhill(fixture.client.resume(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Resume((), response) = rpc else {
            panic!("expected Resume")
        };
        response.send(Err(denied()));
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "injected diagnostic failure");
}

// Test: Build a command incrementally and wait for its remote PID.
// Expected: The remote request retains options and environment edits; the
//       public process reports the server's PID, exit code, and success flag.
#[async_test]
async fn exec_options_and_process_exit_status_round_trip(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    for exit_code in [0, 17] {
        let mut command = fixture.client.exec("/bin/example");
        command
            .args(["a"])
            .args(["b c"])
            .tty(true)
            .combine_stderr(true)
            .raw_socket_io(true)
            .env_clear()
            .env("A", "B")
            .env_remove("C");
        let process = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
            let UnderhillDiag::Exec(request, response) = rpc else {
                panic!("expected Exec")
            };
            assert_eq!(request.command, "/bin/example");
            assert_eq!(request.args, ["a", "b c"]);
            assert!(
                request.tty && request.combine_stderr && request.raw_socket_io && request.clear_env
            );
            assert_eq!((request.stdin, request.stdout, request.stderr), (0, 0, 0));
            assert_eq!(request.env[0].name, "A");
            assert_eq!(request.env[0].value.as_deref(), Some("B"));
            assert_eq!(request.env[1].name, "C");
            assert_eq!(request.env[1].value, None);
            response.send(Ok(diag_proto::ExecResponse { pid: 73 }));
        })
        .await
        .unwrap();
        assert_eq!(process.id(), 73);
        assert!(process.stdin.is_none() && process.stdout.is_none() && process.stderr.is_none());
        let status = underhill(process.wait(), &mut fixture.underhill, |rpc| {
            let UnderhillDiag::Wait(request, response) = rpc else {
                panic!("expected Wait")
            };
            assert_eq!(request.pid, 73);
            response.send(Ok(WaitResponse { exit_code }));
        })
        .await
        .unwrap();
        assert_eq!(status.exit_code(), exit_code);
        assert_eq!(status.success(), exit_code == 0);
    }
}

// Test: Reject command launch, then reject waiting for an accepted command.
// Expected: Both failures reach the public API without a fabricated process
//       or successful exit status.
#[async_test]
async fn exec_and_wait_failures_remain_errors(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let command = fixture.client.exec("denied");
    let error = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Exec(_, response) = rpc else {
            panic!("expected Exec")
        };
        response.send(Err(denied()));
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "injected diagnostic failure");
    let command = fixture.client.exec("gone");
    let process = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Exec(_, response) = rpc else {
            panic!("expected Exec")
        };
        response.send(Ok(diag_proto::ExecResponse { pid: 74 }));
    })
    .await
    .unwrap();
    let error = underhill(process.wait(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Wait(_, response) = rpc else {
            panic!("expected Wait")
        };
        response.send(Err(denied()));
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "injected diagnostic failure");
}

// Test: Request data IO from a client constructed with a single supplied stream.
// Expected: Extra-connection operations fail explicitly instead of reusing
//       the control stream or invoking an unavailable VM connector.
#[async_test]
async fn dialer_clients_reject_operations_requiring_additional_connections(driver: DefaultDriver) {
    let (client, _peer) = UnixStream::pair().unwrap();
    let client = DiagClient::from_dialer(
        driver.clone(),
        ExistingConnection::new(PolledSocket::new(&driver, client).unwrap()),
    );
    let error = client.connect_data().await.err().unwrap();
    assert!(
        error
            .to_string()
            .contains("cannot make additional connections")
    );
    let error = client
        .exec("example")
        .stdin(true)
        .spawn()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("failed to connect stdin"));
}

// Test: Issue a typed custom call rejected by the diagnostic peer.
// Expected: The caller receives the server's Unimplemented status.
#[async_test]
async fn custom_calls_preserve_protocol_status(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let status = openhcl(
        fixture.client.custom_call().start(OpenhclDiag::Ping, ()),
        &mut fixture.openhcl,
        |rpc| {
            let OpenhclDiag::Ping((), response) = rpc else {
                panic!("expected Ping")
            };
            response.send(Err(Status {
                code: Code::Unimplemented.into(),
                message: "unsupported extension".to_owned(),
                details: Vec::new(),
            }));
        },
    )
    .await
    .unwrap_err();
    assert_eq!(status.code, Code::Unimplemented as i32);
    assert_eq!(status.message, "unsupported extension");
}

// Test: Fail data-connection setup at each standard-IO allocation stage.
// Expected: Spawn errors name stdin, stdout, or stderr, making the failing
//       connection visible to callers.
#[async_test]
async fn stdio_connection_failures_identify_the_failing_stream(driver: DefaultDriver) {
    for (stage, name) in [(1, "stdin"), (2, "stdout"), (3, "stderr")] {
        let fixture = Fixture::new(driver.clone());
        fixture.fail_data_at.store(stage, Ordering::SeqCst);
        let error = fixture
            .client
            .exec("example")
            .stdin(true)
            .stdout(true)
            .stderr(true)
            .spawn()
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), format!("failed to connect {name}"));
    }
}

// IGNORED: ExecBuilder::spawn tests with_stdout while allocating stderr, so
// requesting stderr alone silently omits its socket.
// Test: Spawn a process with stderr enabled and stdout disabled.
// Expected: The returned process has stderr but no stdout.
#[async_test]
#[ignore = "product bug: stderr allocation depends on stdout instead of stderr"]
async fn stderr_only_commands_receive_a_stderr_socket(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut command = fixture.client.exec("example");
    command.stderr(true);
    let process = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Exec(_, response) = rpc else {
            panic!("expected Exec")
        };
        response.send(Ok(diag_proto::ExecResponse { pid: 75 }));
    })
    .await
    .unwrap();
    assert!(process.stdout.is_none());
    assert!(process.stderr.is_some());
}

// IGNORED: Enabling stdout also allocates stderr even when it was disabled.
// Test: Spawn a process with stdout enabled and stderr disabled.
// Expected: The returned process has stdout but no stderr.
#[async_test]
#[ignore = "product bug: stdout enables an unwanted stderr socket"]
async fn stdout_only_commands_do_not_allocate_stderr(driver: DefaultDriver) {
    let mut fixture = Fixture::new(driver);
    let mut command = fixture.client.exec("example");
    command.stdout(true);
    let process = underhill(command.spawn(), &mut fixture.underhill, |rpc| {
        let UnderhillDiag::Exec(_, response) = rpc else {
            panic!("expected Exec")
        };
        response.send(Ok(diag_proto::ExecResponse { pid: 76 }));
    })
    .await
    .unwrap();
    assert!(process.stdout.is_some());
    assert!(process.stderr.is_none());
}

// Test: Translate transport failures into the client's public retry guidance.
// Expected: A VM that has not started gets a one-second retry, a socket timeout
//       can retry immediately, and other failures are not retried.
#[test]
fn connection_errors_expose_retry_guidance_for_transport_failures() {
    for (kind, expected) in [
        (ErrorKind::AddrNotAvailable, Some(Duration::from_secs(1))),
        (ErrorKind::TimedOut, Some(Duration::ZERO)),
        (ErrorKind::PermissionDenied, None),
        (ErrorKind::ConnectionRefused, None),
    ] {
        let error = ConnectError::connect(std::io::Error::from(kind));
        assert_eq!(error.retry_timeout(), expected);
        assert!(std::error::Error::source(&error).is_some());
    }
}
