// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::simple::*;
use task_control::Cancelled;
use task_control::StopTask;
use test_with_tracing::test;
use vmcore::save_restore::SavedStateRoot;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

#[derive(Debug, mesh::payload::Protobuf, SavedStateRoot)]
#[mesh(package = "vmbus_channel.tests")]
struct CounterState {
    #[mesh(1)]
    count: u32,
}

struct CounterDevice {
    completed: mesh::Sender<u32>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
    closes: usize,
}

struct CounterRunner {
    channel: RawAsyncChannel<GpadlRingMem>,
    count: u32,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for CounterRunner {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl SimpleVmbusDevice for CounterDevice {
    type SavedState = CounterState;
    type Runner = CounterRunner;

    fn offer(&self) -> OfferParams {
        OfferParams::default()
    }

    fn inspect(&mut self, req: inspect::Request<'_>, _runner: Option<&mut CounterRunner>) {
        req.ignore();
    }

    fn open(
        &mut self,
        channel: RawAsyncChannel<GpadlRingMem>,
        _memory: GuestMemory,
    ) -> Result<CounterRunner, anyhow::Error> {
        Ok(CounterRunner {
            channel,
            count: 0,
            dropped: self.dropped.clone(),
        })
    }

    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        runner: &mut CounterRunner,
    ) -> Result<(), Cancelled> {
        loop {
            let result = stop
                .until_stopped(poll_fn(|cx| runner.channel.signal.poll_for_signal(cx)))
                .await?;
            assert!(result.is_ok());
            runner.count += 1;
            self.completed.send(runner.count);
        }
    }

    async fn close(&mut self) {
        self.closes += 1;
        assert_eq!(self.dropped.load(Ordering::SeqCst), self.closes);
    }

    fn supports_save_restore(
        &mut self,
    ) -> Option<
        &mut dyn SaveRestoreSimpleVmbusDevice<SavedState = CounterState, Runner = CounterRunner>,
    > {
        Some(self)
    }
}

impl SaveRestoreSimpleVmbusDevice for CounterDevice {
    fn save_open(&mut self, runner: &CounterRunner) -> CounterState {
        CounterState {
            count: runner.count,
        }
    }

    fn restore_open(
        &mut self,
        state: CounterState,
        channel: RawAsyncChannel<GpadlRingMem>,
    ) -> Result<CounterRunner, anyhow::Error> {
        Ok(CounterRunner {
            channel,
            count: state.count,
            dropped: self.dropped.clone(),
        })
    }
}

// Test: Save non-default progress and restore it into a fresh stopped device,
//       then save and restore the closed destination.
// Expected: Progress survives transfer, closed restore creates no runner, and
//       runners drop before each close callback.
#[test]
fn simple_device_restores_progress_and_drops_runner_before_close() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::SlimEvent);
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
        let (completed, mut observed) = mesh::channel();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handle = offer_simple_device(
            &source,
            &bus,
            CounterDevice {
                completed,
                dropped: dropped.clone(),
                closes: 0,
            },
            InitialDeviceState::Running,
        )
        .await
        .unwrap();
        let child = offers.recv().await.unwrap();
        assert!(
            child
                .request_send
                .call(ChannelRequest::Gpadl, ring_gpadl())
                .await
                .unwrap()
        );
        assert!(
            child
                .request_send
                .call(ChannelRequest::Open, open_request())
                .await
                .unwrap()
        );
        for expected in 1..=3 {
            child.event.deliver();
            assert_eq!(observed.recv().await.unwrap(), expected);
        }
        assert_eq!(
            child
                .request_send
                .call(
                    ChannelRequest::Modify,
                    ModifyRequest::TargetVp { target_vp: 3 }
                )
                .await
                .unwrap(),
            0
        );
        handle.stop().await;
        let saved = handle.save().await.unwrap().unwrap();
        child
            .request_send
            .call(ChannelRequest::Close, ())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert_eq!(device.unwrap().closes, 1);

        // A new wrapper cannot recover progress from the source's old runner.
        let (completed, mut observed) = mesh::channel();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handle = offer_simple_device(
            &source,
            &bus,
            CounterDevice {
                completed,
                dropped: dropped.clone(),
                closes: 0,
            },
            InitialDeviceState::Stopped,
        )
        .await
        .unwrap();
        let mut child = offers.recv().await.unwrap();
        let restore = handle.restore(saved);
        let response = async {
            let ChannelServerRequest::Restore(rpc) =
                child.server_request_recv.recv().await.unwrap()
            else {
                panic!("expected restore")
            };
            assert!(*rpc.input());
            rpc.complete(Ok(RestoreResult {
                open_request: Some(open_request()),
                gpadls: vec![RestoredGpadl {
                    request: ring_gpadl(),
                    accepted: true,
                }],
            }));
        };
        let (result, ()) = futures::join!(restore, response);
        result.unwrap();
        child.event.deliver();
        assert!(observed.recv().now_or_never().is_none());
        handle.start();
        assert_eq!(observed.recv().await.unwrap(), 4);
        handle.stop().await;
        child
            .request_send
            .call(ChannelRequest::Close, ())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let saved = handle.save().await.unwrap().unwrap();
        let restore = handle.restore(saved);
        let response = async {
            let ChannelServerRequest::Restore(rpc) =
                child.server_request_recv.recv().await.unwrap()
            else {
                panic!("expected restore")
            };
            assert!(!*rpc.input());
            rpc.complete(Ok(RestoreResult {
                open_request: None,
                gpadls: vec![],
            }));
        };
        let (result, ()) = futures::join!(restore, response);
        result.unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        handle.start();
        handle.stop().await;
        assert!(observed.recv().now_or_never().is_none());
        handle.reset().await;
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert_eq!(device.unwrap().closes, 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }));
}
