// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public input routing, state transitions and channel ownership.

use futures::FutureExt;
use futures::StreamExt;
use futures::future::Either;
use input_core::InputData;
use input_core::InputSource;
use input_core::KeyboardData;
use input_core::MouseData;
use mesh::rpc::RpcSend;
use state_unit::StateRequest;
use std::pin::Pin;
use test_with_tracing::test;
use vmm_core::input_distributor::InputDistributor;

async fn drive<T>(
    run: Pin<&mut impl Future<Output = ()>>,
    operation: impl Future<Output = T>,
) -> T {
    let operation = std::pin::pin!(operation);
    match futures::future::select(operation, run).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => panic!("distributor stopped before the operation completed"),
    }
}

// Test: Route input through unsorted device elevations, activation changes and
//       acknowledged VM stop/start requests, then shut down the state channel.
// Expected: Only the highest active device of each kind receives exact events;
//       paused input is discarded, conflicts preserve the old recipient and
//       state-channel shutdown returns ownership of the original input stream.
#[test]
fn priorities_pause_and_input_channel_ownership() {
    futures::executor::block_on(async {
        let (input, input_recv) = mesh::channel();
        let (state, mut state_recv) = mesh::channel();
        let mut distributor = InputDistributor::new(input_recv);
        let client = distributor.client().clone();
        let mut run = Box::pin(distributor.run(&mut state_recv));

        let mut high = drive(run.as_mut(), client.add_keyboard("high", 30))
            .await
            .unwrap();
        let mut low = drive(run.as_mut(), client.add_keyboard("low", 1))
            .await
            .unwrap();
        let mut middle = drive(run.as_mut(), client.add_keyboard("middle", 15))
            .await
            .unwrap();
        let mut mouse = drive(run.as_mut(), client.add_mouse("mouse", 1))
            .await
            .unwrap();
        assert!(
            drive(run.as_mut(), client.add_keyboard("conflict", 30))
                .await
                .is_err()
        );
        high.set_active(true).await;
        middle.set_active(true).await;
        low.set_active(true).await;
        mouse.set_active(true).await;

        input.send(InputData::Keyboard(KeyboardData {
            code: 0x10,
            make: true,
        }));
        input.send(InputData::Mouse(MouseData {
            button_mask: 1,
            x: 11,
            y: 12,
        }));
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert!(high.next().now_or_never().is_none());
        assert!(middle.next().now_or_never().is_none());
        assert!(low.next().now_or_never().is_none());
        assert!(mouse.next().now_or_never().is_none());

        drive(run.as_mut(), state.call(StateRequest::Start, ()))
            .await
            .unwrap();
        input.send(InputData::Keyboard(KeyboardData {
            code: 0xe038,
            make: true,
        }));
        let key = drive(run.as_mut(), high.next()).await.unwrap();
        assert_eq!((key.code, key.make), (0xe038, true));
        assert!(middle.next().now_or_never().is_none());
        assert!(low.next().now_or_never().is_none());

        high.set_active(false).await;
        input.send(InputData::Keyboard(KeyboardData {
            code: 0xe038,
            make: false,
        }));
        let key = drive(run.as_mut(), middle.next()).await.unwrap();
        assert_eq!((key.code, key.make), (0xe038, false));
        assert!(high.next().now_or_never().is_none());
        assert!(low.next().now_or_never().is_none());

        middle.set_active(false).await;
        low.set_active(false).await;
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x19,
            make: true,
        }));
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert!(low.next().now_or_never().is_none());
        low.set_active(true).await;
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x20,
            make: true,
        }));
        let key = drive(run.as_mut(), low.next()).await.unwrap();
        assert_eq!((key.code, key.make), (0x20, true));
        input.send(InputData::Mouse(MouseData {
            button_mask: 5,
            x: u16::MAX,
            y: 4097,
        }));
        let event = drive(run.as_mut(), mouse.next()).await.unwrap();
        assert_eq!((event.button_mask, event.x, event.y), (5, u16::MAX, 4097));
        assert!(high.next().now_or_never().is_none());
        assert!(middle.next().now_or_never().is_none());
        assert!(low.next().now_or_never().is_none());

        high.set_active(true).await;
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x21,
            make: true,
        }));
        let key = drive(run.as_mut(), high.next()).await.unwrap();
        assert_eq!((key.code, key.make), (0x21, true));
        assert!(low.next().now_or_never().is_none());
        high.set_active(false).await;

        drive(run.as_mut(), state.call(StateRequest::Stop, ()))
            .await
            .unwrap();
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x30,
            make: true,
        }));
        input.send(InputData::Mouse(MouseData {
            button_mask: 2,
            x: 21,
            y: 22,
        }));
        assert!(futures::poll!(run.as_mut()).is_pending());
        drive(run.as_mut(), state.call(StateRequest::Start, ()))
            .await
            .unwrap();
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x40,
            make: false,
        }));
        input.send(InputData::Mouse(MouseData {
            button_mask: 4,
            x: 31,
            y: 32,
        }));
        let key = drive(run.as_mut(), low.next()).await.unwrap();
        assert_eq!((key.code, key.make), (0x40, false));
        let event = drive(run.as_mut(), mouse.next()).await.unwrap();
        assert_eq!((event.button_mask, event.x, event.y), (4, 31, 32));
        assert!(low.next().now_or_never().is_none());
        assert!(mouse.next().now_or_never().is_none());

        drop(state);
        run.await;
        let mut returned = distributor.into_inner();
        input.send(InputData::Keyboard(KeyboardData {
            code: 0x50,
            make: true,
        }));
        let Some(InputData::Keyboard(key)) = returned.next().await else {
            panic!("original input channel was not preserved");
        };
        assert_eq!((key.code, key.make), (0x50, true));
    });
}

// Test: Register keyboard and mouse sources after their distributor is gone.
// Expected: Registration remains a successful no-op and both returned streams
//       terminate, rather than hanging or inventing input.
#[test]
fn vanished_distributor_returns_closed_sources() {
    futures::executor::block_on(async {
        let (_input, input_recv) = mesh::channel();
        let distributor = InputDistributor::new(input_recv);
        let client = distributor.client().clone();
        drop(distributor);
        let mut keyboard = client.add_keyboard("keyboard", 0).await.unwrap();
        let mut mouse = client.add_mouse("mouse", 0).await.unwrap();
        assert!(keyboard.next().await.is_none());
        assert!(mouse.next().await.is_none());
    });
}
