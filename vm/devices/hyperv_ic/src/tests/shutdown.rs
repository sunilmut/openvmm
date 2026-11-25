// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::shutdown::ShutdownIc;
use crate::test_helpers::restore;
use crate::test_helpers::start;
use hyperv_ic_protocol::MessageType;
use hyperv_ic_protocol::Status;
use hyperv_ic_protocol::shutdown as proto;
use hyperv_ic_resources::shutdown::ShutdownParams;
use hyperv_ic_resources::shutdown::ShutdownResult;
use hyperv_ic_resources::shutdown::ShutdownRpc;
use hyperv_ic_resources::shutdown::ShutdownType;
use mesh::rpc::RpcSend;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use vmbus_channel::test_helpers::stop_with_timeout;
use vmbus_channel::test_helpers::with_timeout;
use zerocopy::FromBytes;

// Test: Request shutdown before readiness, register multiple clients, acknowledge
//       a guest failure, and restore an idle, negotiated device.
// Expected: NotReady and AlreadyInProgress are distinct, failures allow retry,
//       and the restored device retains protocol support for a forced reboot.
#[async_test]
async fn readiness_retry_and_restore_are_visible_to_clients(driver: DefaultDriver) {
    let (send, recv) = mesh::channel();
    let (mut task, mut guest) = start(&driver, ShutdownIc::new(recv));
    let request = || ShutdownParams {
        shutdown_type: ShutdownType::PowerOff,
        force: false,
    };
    assert_eq!(
        with_timeout(&driver, send.call(ShutdownRpc::Shutdown, request()))
            .await
            .unwrap(),
        ShutdownResult::NotReady
    );
    let first = send.call(ShutdownRpc::WaitReady, ());
    let second = send.call(ShutdownRpc::WaitReady, ());
    guest.negotiate(proto::SHUTDOWN_VERSION_3_2).await;
    let first_disconnected = with_timeout(&driver, first).await.unwrap();
    let _second_disconnected = with_timeout(&driver, second).await.unwrap();
    drop(first_disconnected);
    let disconnected = with_timeout(&driver, send.call(ShutdownRpc::WaitReady, ()))
        .await
        .unwrap();
    let result = send.call(ShutdownRpc::Shutdown, request());
    let frame = guest.receive(MessageType::SHUTDOWN).await;
    assert_eq!(
        with_timeout(&driver, send.call(ShutdownRpc::Shutdown, request()))
            .await
            .unwrap(),
        ShutdownResult::AlreadyInProgress
    );
    guest.respond(&frame, Status::FAIL, &[]).await;
    assert_eq!(
        with_timeout(&driver, result).await.unwrap(),
        ShutdownResult::Failed(Status::FAIL.0)
    );
    stop_with_timeout(&mut task, &driver).await;
    let mut guest = restore(&driver, &mut task);
    assert!(with_timeout(&driver, disconnected).await.is_err());
    assert!(task.start());
    let _disconnected = with_timeout(&driver, send.call(ShutdownRpc::WaitReady, ()))
        .await
        .unwrap();
    let result = send.call(
        ShutdownRpc::Shutdown,
        ShutdownParams {
            shutdown_type: ShutdownType::Reboot,
            force: true,
        },
    );
    // A restored negotiated shutdown channel must not renegotiate first.
    let frame = guest.receive(MessageType::SHUTDOWN).await;
    assert_eq!(frame.header.message_version, proto::SHUTDOWN_VERSION_3_2);
    let message = proto::ShutdownMessage::read_from_bytes(&frame.body).unwrap();
    assert!(message.flags.force());
    assert!(message.flags.restart());
    assert!(!message.flags.hibernate());
    guest.respond(&frame, Status::SUCCESS, &[]).await;
    assert_eq!(
        with_timeout(&driver, result).await.unwrap(),
        ShutdownResult::Ok
    );
    stop_with_timeout(&mut task, &driver).await;
}
