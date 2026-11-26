// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public control-request cancellation and reply capabilities across transport.

#![cfg(target_os = "linux")]

use futures::FutureExt;
use futures::StreamExt;
use mesh::CancelContext;
use mesh::CancelReason;
use mesh::OwnedMessage;
use mesh::rpc::RpcSend;
use std::time::Duration;
use test_with_tracing::test;
use underhill_core::ControlRequest;

// Test: Transport a pending log-flush request, then cancel it at its origin.
// Expected: The received request still observes cancellation and its original
//       caller receives that cancellation result through the transported reply.
#[pal_async::async_test]
async fn transported_log_flush_preserves_cancellation_and_reply(_driver: pal_async::DefaultDriver) {
    let (context, mut cancel) = CancelContext::new()
        .with_timeout(Duration::from_secs(2))
        .with_cancel();
    let (send, mut recv) = mesh::channel();
    let response = send.call(ControlRequest::FlushLogs, context);
    let wire = OwnedMessage::new(recv.next().await.unwrap()).serialize();
    let request: ControlRequest = OwnedMessage::serialized(wire).parse().unwrap();
    let ControlRequest::FlushLogs(rpc) = request else {
        panic!("wrong control request variant");
    };
    let (mut context, reply) = rpc.split();
    assert!(context.cancelled().now_or_never().is_none());
    cancel.cancel();
    let result = context.until_cancelled(std::future::pending::<()>()).await;
    assert_eq!(result, Err(CancelReason::Cancelled));
    reply.complete(result);
    assert_eq!(response.await.unwrap(), Err(CancelReason::Cancelled));
}
