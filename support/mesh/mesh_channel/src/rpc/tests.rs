// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use pal_async::async_test;

// Test: Split a received RPC and complete its response separately from its input.
// Expected: The input and result are preserved and the caller waits for completion.
#[async_test]
async fn split_rpc_preserves_input_and_response() {
    let (send, request) = oneshot::<Rpc<u32, u32>>();
    let mut pending = Box::pin(send.call(std::convert::identity, 7));
    assert!(pending.as_mut().now_or_never().is_none());
    let request = request.await.unwrap();
    assert_eq!(*request.input(), 7);
    let (input, response) = request.split();
    assert_eq!(input, 7);
    response.complete(input * 3);
    assert_eq!(pending.await.unwrap(), 21);
}

// Test: Handle requests synchronously, asynchronously, and without a result listener.
// Expected: Handlers receive the input exactly once and connected callers get results.
#[async_test]
async fn handlers_deliver_results_and_detached_work_runs() {
    let (send, request) = oneshot::<Rpc<u32, u32>>();
    let pending = send.call(std::convert::identity, 9);
    request.await.unwrap().handle_sync(|input| input + 1);
    assert_eq!(pending.await.unwrap(), 10);
    let (send, mut requests) = crate::channel::<Rpc<u32, u32>>();
    let pending = send.call(std::convert::identity, 11);
    requests
        .recv()
        .await
        .unwrap()
        .handle(async |input| input * 2)
        .await;
    assert_eq!(pending.await.unwrap(), 22);
    let mut observed = None;
    Rpc::<u32, u32>::detached(13).handle_sync(|input| {
        observed = Some(input);
        input
    });
    assert_eq!(observed, Some(13));
}

// Test: Fail and succeed while handling a must-succeed request.
// Expected: Success reaches the caller; failure returns locally and closes the reply.
#[async_test]
async fn must_succeed_handler_distinguishes_local_failure() {
    let (send, request) = oneshot::<Rpc<u32, u32>>();
    let pending = send.call(std::convert::identity, 3);
    request
        .await
        .unwrap()
        .handle_must_succeed(async |input| Ok::<_, &str>(input + 4))
        .await
        .unwrap();
    assert_eq!(pending.await.unwrap(), 7);
    let (send, request) = oneshot::<Rpc<u32, u32>>();
    let pending = send.call(std::convert::identity, 3);
    assert_eq!(
        request
            .await
            .unwrap()
            .handle_must_succeed(async |_| Err("local failure"))
            .await,
        Err("local failure")
    );
    assert!(matches!(
        pending.await,
        Err(RpcError::Channel(RecvError::Closed))
    ));
}

// Test: Complete failable calls with both successful and failing handler results.
// Expected: Callers receive values or the original remote error, not channel errors.
#[async_test]
async fn failable_handlers_preserve_values_and_errors() {
    for fail in [false, true] {
        let (send, request) = oneshot::<Rpc<u32, RemoteResult<u32>>>();
        let pending = send.call_failable(std::convert::identity, 5);
        request.await.unwrap().handle_failable_sync(|input| {
            if fail {
                Err(std::io::Error::other("sync failure"))
            } else {
                Ok(input * 2)
            }
        });
        if fail {
            assert!(
                matches!(pending.await, Err(RpcError::Call(error)) if error.to_string() == "sync failure")
            );
        } else {
            assert_eq!(pending.await.unwrap(), 10);
        }
        let (send, request) = oneshot::<Rpc<u32, RemoteResult<u32>>>();
        let pending = send.call_failable(std::convert::identity, 5);
        request
            .await
            .unwrap()
            .handle_failable(async |input| {
                if fail {
                    Err(std::io::Error::other("async failure"))
                } else {
                    Ok(input * 3)
                }
            })
            .await;
        if fail {
            assert!(
                matches!(pending.await, Err(RpcError::Call(error)) if error.to_string() == "async failure")
            );
        } else {
            assert_eq!(pending.await.unwrap(), 15);
        }
    }
}

// Test: Explicitly fail a request and separately drop a responder without replying.
// Expected: Application failures and channel closure remain distinguishable.
#[async_test]
async fn explicit_failure_is_distinct_from_dropped_response() {
    let (send, request) = oneshot::<Rpc<(), RemoteResult<u32>>>();
    let pending = send.call_failable(std::convert::identity, ());
    request
        .await
        .unwrap()
        .fail(std::io::Error::other("request rejected"));
    assert!(
        matches!(pending.await, Err(RpcError::Call(error)) if error.to_string() == "request rejected")
    );
    let (send, request) = oneshot::<Rpc<(), Result<u32, &'static str>>>();
    let pending = send.call_failable(std::convert::identity, ());
    drop(request.await.unwrap());
    assert!(matches!(
        pending.await,
        Err(RpcError::Channel(RecvError::Closed))
    ));
}

struct FallibleSender<T>(Option<OneshotSender<T>>);

impl<T: Send + 'static> TryRpcSend for FallibleSender<T> {
    type Message = T;
    type Error = &'static str;

    fn try_send_rpc(self, message: T) -> Result<(), Self::Error> {
        self.0.ok_or("unavailable")?.send(message);
        Ok(())
    }
}

// Test: Send successful and rejected requests through the fallible-send adapter.
// Expected: Successful replies arrive and send failures are returned immediately.
#[async_test]
async fn fallible_senders_preserve_send_errors_and_replies() {
    let (send, request) = oneshot::<Rpc<u32, u32>>();
    let pending = FallibleSender(Some(send))
        .try_call(std::convert::identity, 17)
        .unwrap();
    request.await.unwrap().complete(23);
    assert_eq!(pending.await.unwrap(), 23);
    assert_eq!(
        FallibleSender::<Rpc<u32, u32>>(None)
            .try_call(std::convert::identity, 17)
            .unwrap_err(),
        "unavailable"
    );
    let (send, request) = oneshot::<Rpc<u32, Result<u32, &'static str>>>();
    let pending = FallibleSender(Some(send))
        .try_call_failable(std::convert::identity, 17)
        .unwrap();
    request.await.unwrap().complete(Err("call failure"));
    assert!(matches!(pending.await, Err(RpcError::Call("call failure"))));
    assert_eq!(
        FallibleSender::<Rpc<u32, Result<u32, &'static str>>>(None)
            .try_call_failable(std::convert::identity, 17)
            .unwrap_err(),
        "unavailable"
    );
}
