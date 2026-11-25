// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::channel::*;
use inspect::InspectMut;
use test_with_tracing::test;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SavedStateBlob;
use vmcore::save_restore::SavedStateRoot;

#[derive(Debug, mesh::payload::Protobuf, SavedStateRoot)]
#[mesh(package = "vmbus_channel.tests")]
struct State {
    #[mesh(1)]
    open: Vec<bool>,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Install(usize),
    Start,
    Stop,
    Open(u16),
    Close(u16),
    Target(u16, u32),
    Restore(usize),
}

#[derive(InspectMut)]
struct TestDevice {
    #[inspect(skip)]
    actions: Arc<Mutex<Vec<Action>>>,
    #[inspect(skip)]
    resources: Arc<Mutex<Option<DeviceResources>>>,
    #[inspect(skip)]
    open: Vec<bool>,
}

impl TestDevice {
    // Keep callbacks externally observable without inspecting production state.
    fn new() -> Self {
        Self {
            actions: Default::default(),
            resources: Default::default(),
            open: vec![false; 3],
        }
    }
}

#[async_trait]
impl VmbusDevice for TestDevice {
    fn offer(&self) -> OfferParams {
        OfferParams {
            interface_name: "test-device".into(),
            ..Default::default()
        }
    }

    fn max_subchannels(&self) -> u16 {
        2
    }

    fn install(&mut self, resources: DeviceResources) {
        self.actions
            .lock()
            .push(Action::Install(resources.channels.len()));
        *self.resources.lock() = Some(resources);
    }

    async fn open(&mut self, index: u16, request: &OpenRequest) -> Result<(), ChannelOpenError> {
        if request.open_data.target_vp == Some(u32::MAX) {
            anyhow::bail!("test device rejects the requested target");
        }
        self.open[usize::from(index)] = true;
        self.actions.lock().push(Action::Open(index));
        Ok(())
    }

    async fn close(&mut self, index: u16) {
        self.open[usize::from(index)] = false;
        self.actions.lock().push(Action::Close(index));
    }

    async fn retarget_vp(&mut self, index: u16, target: u32) {
        self.actions.lock().push(Action::Target(index, target));
    }

    fn start(&mut self) {
        self.actions.lock().push(Action::Start);
    }

    async fn stop(&mut self) {
        self.actions.lock().push(Action::Stop);
    }

    fn supports_save_restore(&mut self) -> Option<&mut dyn SaveRestoreVmbusDevice> {
        Some(self)
    }
}

#[async_trait]
impl SaveRestoreVmbusDevice for TestDevice {
    async fn save(&mut self) -> Result<SavedStateBlob, SaveError> {
        Ok(SavedStateBlob::new(State {
            open: self.open.clone(),
        }))
    }

    async fn restore(
        &mut self,
        mut control: RestoreControl<'_>,
        state: SavedStateBlob,
    ) -> Result<(), RestoreError> {
        let state: State = state.parse()?;
        let requests = control.restore(&state.open).await?;
        self.open = state.open;
        self.actions
            .lock()
            .push(Action::Restore(requests.iter().flatten().count()));
        Ok(())
    }
}

// Test: Offer a device, open and retarget it, stop it, and restart queued requests.
// Expected: Callbacks are ordered, stopped requests wait, and revoke returns the device.
#[test]
fn device_lifecycle_defers_requests_until_restart_and_returns_ownership() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::SlimEvent);
        let device = TestDevice::new();
        let actions = device.actions.clone();
        let handle = offer_channel(&driver, &bus, device).await.unwrap();
        let child = offers.recv().await.unwrap();
        handle.stop().await;
        handle.start();
        assert!(
            child
                .request_send
                .call(ChannelRequest::Open, open_request())
                .await
                .unwrap()
        );
        assert_eq!(
            child
                .request_send
                .call(
                    ChannelRequest::Modify,
                    ModifyRequest::TargetVp { target_vp: 7 }
                )
                .await
                .unwrap(),
            0
        );
        handle.stop().await;
        handle.stop().await;
        let pending = child.request_send.call(
            ChannelRequest::Modify,
            ModifyRequest::TargetVp { target_vp: 9 },
        );
        let mut pending = std::pin::pin!(pending);
        assert!(pending.as_mut().now_or_never().is_none());
        assert!(
            child
                .request_send
                .call(ChannelRequest::Gpadl, ring_gpadl())
                .await
                .unwrap()
        );
        assert!(pending.as_mut().now_or_never().is_none());
        handle.start();
        assert_eq!(pending.await.unwrap(), 0);
        child
            .request_send
            .call(ChannelRequest::Close, ())
            .await
            .unwrap();
        handle.stop().await;
        handle.reset().await;
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert!(device.is_some());
        assert_eq!(
            *actions.lock(),
            [
                Action::Install(3),
                Action::Stop,
                Action::Start,
                Action::Open(0),
                Action::Target(0, 7),
                Action::Stop,
                Action::Start,
                Action::Target(0, 9),
                Action::Close(0),
                Action::Stop
            ]
        );
    }));
}

// Test: Keep a GPADL view alive while the bus requests teardown.
// Expected: Teardown waits for the device's last view and later mappings are rejected.
#[test]
fn gpadl_teardown_rpc_waits_for_the_last_device_reference() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::OsEvent);
        let device = TestDevice::new();
        let resources = device.resources.clone();
        let handle = offer_channel(&driver, &bus, device).await.unwrap();
        let child = offers.recv().await.unwrap();
        assert!(
            child
                .request_send
                .call(ChannelRequest::Gpadl, ring_gpadl())
                .await
                .unwrap()
        );
        let mapper = resources.lock().as_ref().unwrap().gpadl_map.clone();
        let view = mapper.map(GpadlId(7)).unwrap();
        let teardown = child
            .request_send
            .call(ChannelRequest::TeardownGpadl, GpadlId(7));
        let mut teardown = std::pin::pin!(teardown);
        assert!(teardown.as_mut().now_or_never().is_none());
        // A stop RPC is a barrier: the teardown request was accepted by the worker.
        handle.stop().await;
        assert!(mapper.map(GpadlId(7)).is_err());
        assert!(teardown.as_mut().now_or_never().is_none());
        drop(view);
        teardown.await.unwrap();
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert!(device.is_some());
    }));
}

// Test: Reject an open at the device and then retry it with valid parameters.
// Expected: A failed open does not leave the channel marked open or prevent retry.
#[test]
fn rejected_opens_can_be_retried_without_closing_a_nonexistent_channel() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::SlimEvent);
        let handle = offer_generic_channel(&driver, &bus, Box::new(TestDevice::new()))
            .await
            .unwrap();
        let child = offers.recv().await.unwrap();
        let mut rejected = open_request();
        rejected.open_data.target_vp = Some(u32::MAX);
        assert!(
            !child
                .request_send
                .call(ChannelRequest::Open, rejected)
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
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert!(device.is_some());
    }));
}

// Test: Enable subchannels, open them, and close their primary with GPADLs present.
// Expected: Subchannels close first, their GPADLs disappear, and excess enables fail.
#[test]
fn primary_close_revokes_subchannels_and_releases_their_gpadls() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::SlimEvent);
        let device = TestDevice::new();
        let actions = device.actions.clone();
        let resources = device.resources.clone();
        let handle = offer_channel(&driver, &bus, device).await.unwrap();
        let primary = offers.recv().await.unwrap();
        let (control, mapper) = {
            let resources = resources.lock();
            let resources = resources.as_ref().unwrap();
            (
                resources.channel_control.clone(),
                resources.gpadl_map.clone(),
            )
        };
        assert!(control.enable_subchannels(3).is_err());
        control.enable_subchannels(2).unwrap();
        let first = offers.recv().await.unwrap();
        let second = offers.recv().await.unwrap();
        assert_eq!(
            (
                first.params.subchannel_index,
                second.params.subchannel_index
            ),
            (1, 2)
        );
        for child in [&primary, &first, &second] {
            assert!(
                child
                    .request_send
                    .call(ChannelRequest::Open, open_request())
                    .await
                    .unwrap()
            );
        }
        for (child, id) in [(&first, GpadlId(8)), (&second, GpadlId(9))] {
            child
                .request_send
                .call(ChannelRequest::Gpadl, GpadlRequest { id, ..ring_gpadl() })
                .await
                .unwrap();
            assert!(mapper.map(id).is_ok());
        }
        let close = async {
            primary
                .request_send
                .call(ChannelRequest::Close, ())
                .await
                .unwrap();
        };
        let revokes = async {
            futures::join!(finish_revoke(first), finish_revoke(second));
        };
        futures::join!(close, revokes);
        assert!(mapper.map(GpadlId(8)).is_err());
        assert!(mapper.map(GpadlId(9)).is_err());
        assert_eq!(
            &actions.lock()[4..],
            [Action::Close(1), Action::Close(2), Action::Close(0)]
        );
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(primary));
        assert!(device.is_some());
    }));
}

// Test: Save, restore an open primary and its GPADL, then save it again.
// Expected: Restore passes the server's open request through and preserves open state.
#[test]
fn restored_open_channels_recover_gpadls_and_save_their_open_state() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::OsEvent);
        let device = TestDevice::new();
        let resources = device.resources.clone();
        let actions = device.actions.clone();
        let handle = offer_channel(&driver, &bus, device).await.unwrap();
        let mut child = offers.recv().await.unwrap();
        handle.stop().await;
        let saved: State = handle.save().await.unwrap().unwrap().parse().unwrap();
        assert_eq!(saved.open, [false; 3]);
        let restore = handle.restore(SavedStateBlob::new(State { open: vec![true] }));
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
        assert_eq!(actions.lock().last(), Some(&Action::Restore(1)));
        assert!(
            resources
                .lock()
                .as_ref()
                .unwrap()
                .gpadl_map
                .map(GpadlId(7))
                .is_ok()
        );
        let saved: State = handle.save().await.unwrap().unwrap().parse().unwrap();
        assert_eq!(saved.open, [true]);
        let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
        assert!(device.is_some());
        assert_eq!(actions.lock().last(), Some(&Action::Close(0)));
    }));
}

// Test: Restore malformed GPADLs that the server either accepted or rejected.
// Expected: Accepted malformed memory fails restore; rejected memory stays unmapped.
#[test]
fn restore_rejects_malformed_accepted_gpadls_but_skips_unaccepted_ones() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        for accepted in [false, true] {
            let (bus, mut offers) = TestBus::new(Notification::OsEvent);
            let device = TestDevice::new();
            let resources = device.resources.clone();
            let handle = offer_channel(&driver, &bus, device).await.unwrap();
            let mut child = offers.recv().await.unwrap();
            handle.stop().await;
            let restore = handle.restore(SavedStateBlob::new(State { open: vec![false] }));
            let response = async {
                let ChannelServerRequest::Restore(rpc) =
                    child.server_request_recv.recv().await.unwrap()
                else {
                    panic!("expected restore")
                };
                assert!(!*rpc.input());
                rpc.complete(Ok(RestoreResult {
                    open_request: None,
                    gpadls: vec![RestoredGpadl {
                        request: GpadlRequest {
                            buf: vec![],
                            ..ring_gpadl()
                        },
                        accepted,
                    }],
                }));
            };
            let (result, ()) = futures::join!(restore, response);
            if accepted {
                assert!(format!("{:#}", result.unwrap_err()).contains("failed to restore gpadl"));
            } else {
                result.unwrap();
            }
            assert!(
                resources
                    .lock()
                    .as_ref()
                    .unwrap()
                    .gpadl_map
                    .map(GpadlId(7))
                    .is_err()
            );
            let (device, ()) = futures::join!(handle.revoke(), finish_revoke(child));
            assert!(device.is_some());
        }
    }));
}
