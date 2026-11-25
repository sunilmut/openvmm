// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::os::unix::fs::FileExt;
use test_with_tracing::test;

mod error_tests;

#[derive(Debug)]
struct Start {
    index: u16,
    features: u64,
    cursors: (u16, u16),
    marker: u32,
}
#[derive(Default)]
struct Calls {
    starts: Vec<Start>,
    stopped: Vec<u16>,
    active: bool,
    resets: usize,
    fail_next_start: bool,
}
struct Device(Arc<Mutex<Calls>>);
impl InspectMut for Device {
    fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
}
impl VirtioDevice for Device {
    fn traits(&self) -> DeviceTraits {
        VirtioDevice::traits(&MockDevice::new())
    }
    async fn read_registers_u32(&mut self, _offset: u16) -> u32 {
        0
    }
    async fn write_registers_u32(&mut self, _offset: u16, _value: u32) {}
    async fn start_queue(
        &mut self,
        index: u16,
        resources: QueueResources,
        features: &VirtioDeviceFeatures,
        initial: Option<QueueState>,
    ) -> anyhow::Result<()> {
        assert_eq!(
            (
                resources.params.size,
                resources.params.desc_addr,
                resources.params.avail_addr,
                resources.params.used_addr
            ),
            (256, 0, 0x1000, 0x2000)
        );
        let initial = initial.unwrap();
        let marker = resources.guest_memory.read_plain::<u32>(0x3000).unwrap();
        let mut calls = self.0.lock();
        calls.starts.push(Start {
            index,
            features: features.into_bits(),
            cursors: (initial.avail_index, initial.used_index),
            marker,
        });
        if std::mem::take(&mut calls.fail_next_start) {
            anyhow::bail!("injected queue start failure");
        }
        calls.active = true;
        Ok(())
    }
    async fn stop_queue(&mut self, index: u16) -> Option<QueueState> {
        let mut calls = self.0.lock();
        if index == 0 && std::mem::take(&mut calls.active) {
            calls.stopped.push(index);
            Some(QueueState {
                avail_index: 0x8023,
                used_index: 0x8045,
            })
        } else {
            None
        }
    }
    async fn reset(&mut self) {
        let mut calls = self.0.lock();
        calls.active = false;
        calls.resets += 1;
    }
}
async fn install_memory(frontend: &VhostUserSocket, marker: u32) {
    let file: std::fs::File = make_memfd(16384).into();
    file.write_all_at(&marker.to_le_bytes(), 0x3000).unwrap();
    assert_eq!(
        exchange_fds(
            frontend,
            VhostUserRequestCode::SET_MEM_TABLE,
            &mem_table_payload(0, 16384, 0x10000000),
            true,
            &[file.into()]
        )
        .await,
        0u64.to_le_bytes()
    );
}

// Test: Activate split and packed queues, replace their memory backing while active, disable them and consume their saved cursor reply, then reset and attempt activation without setup.
// Expected: Restart sees the new backing and exact stopped cursors, device feature bits exclude the control-only protocol bit, GET_VRING_BASE encodes the correct cursors once, and reset clears queue readiness while preserving reply-ACK negotiation.
#[async_test]
async fn memory_restart_and_saved_cursors_preserve_split_and_packed_contracts(
    driver: DefaultDriver,
) {
    for packed in [false, true] {
        let calls = Arc::new(Mutex::new(Calls::default()));
        let (front, back) = socket_pair();
        let frontend = VhostUserSocket::new(PolledSocket::new(&driver, front).unwrap());
        let backend = VhostUserSocket::new(PolledSocket::new(&driver, back).unwrap());
        let features = VirtioDeviceFeatures::new()
            .with_ring_packed(packed)
            .with_vhost_user_protocol_features(true);
        let client = async {
            enable_ack(&frontend).await;
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::SET_FEATURES,
                    VhostUserU64Msg {
                        value: features.into_bits()
                    }
                    .as_bytes(),
                    true
                )
                .await,
                0u64.to_le_bytes()
            );
            install_memory(&frontend, 0x11223344).await;
            setup_and_enable_queue(&frontend).await;
            let query = VhostUserVringState { index: 0, num: 1 };
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::SET_VRING_ENABLE,
                    query.as_bytes(),
                    true
                )
                .await,
                0u64.to_le_bytes()
            );
            assert_eq!(calls.lock().starts.len(), 1);
            install_memory(&frontend, 0x55667788).await;
            let disable = VhostUserVringState { index: 0, num: 0 };
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::SET_VRING_ENABLE,
                    disable.as_bytes(),
                    true
                )
                .await,
                0u64.to_le_bytes()
            );
            let expected = VhostUserVringState {
                index: 0,
                num: if packed { 0x80458023 } else { 0x8023 },
            };
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::GET_VRING_BASE,
                    disable.as_bytes(),
                    false
                )
                .await,
                expected.as_bytes()
            );
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::GET_VRING_BASE,
                    disable.as_bytes(),
                    false
                )
                .await,
                disable.as_bytes()
            );
            assert_eq!(
                exchange(&frontend, VhostUserRequestCode::RESET_DEVICE, &[], true).await,
                0u64.to_le_bytes()
            );
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::SET_VRING_ENABLE,
                    query.as_bytes(),
                    true
                )
                .await,
                0u64.to_le_bytes()
            );
            assert_eq!(calls.lock().starts.len(), 2);
            drop(frontend);
        };
        let (result, ()) = futures::join!(
            VhostUserDeviceServer::new(Box::new(Device(calls.clone()))).serve_connection(backend),
            client
        );
        result.unwrap();
        let calls = calls.lock();
        assert_eq!(calls.stopped, [0, 0]);
        assert_eq!(calls.resets, 2);
        assert_eq!(calls.starts.len(), 2);
        for start in &calls.starts {
            assert_eq!(start.index, 0);
            assert_eq!(start.features, features.into_bits() & !(1 << 30));
        }
        assert_eq!(calls.starts[0].cursors, (0, 0));
        assert_eq!(calls.starts[0].marker, 0x11223344);
        assert_eq!(calls.starts[1].cursors, (0x8023, 0x8045));
        assert_eq!(calls.starts[1].marker, 0x55667788);
    }
}
