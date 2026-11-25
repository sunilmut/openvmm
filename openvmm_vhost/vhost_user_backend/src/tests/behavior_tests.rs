// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;

mod listener_tests;
mod queue_tests;

#[derive(Default)]
struct RegisterCalls {
    reads: Vec<u16>,
    writes: Vec<(u16, u32)>,
    resets: usize,
}
struct ConfigDevice {
    inner: MockDevice,
    calls: Arc<Mutex<RegisterCalls>>,
}
impl InspectMut for ConfigDevice {
    fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
}
impl VirtioDevice for ConfigDevice {
    fn traits(&self) -> DeviceTraits {
        let mut value = VirtioDevice::traits(&self.inner);
        value.device_register_length = 8;
        value
    }
    async fn read_registers_u32(&mut self, offset: u16) -> u32 {
        self.calls.lock().reads.push(offset);
        match offset {
            0 => 0x44332211,
            4 => 0x88776655,
            _ => panic!("unexpected config offset {offset}"),
        }
    }
    async fn write_registers_u32(&mut self, offset: u16, value: u32) {
        self.calls.lock().writes.push((offset, value));
    }
    async fn start_queue(
        &mut self,
        idx: u16,
        resources: QueueResources,
        features: &VirtioDeviceFeatures,
        initial: Option<QueueState>,
    ) -> anyhow::Result<()> {
        VirtioDevice::start_queue(&mut self.inner, idx, resources, features, initial).await
    }
    async fn stop_queue(&mut self, idx: u16) -> Option<QueueState> {
        VirtioDevice::stop_queue(&mut self.inner, idx).await
    }
    async fn reset(&mut self) {
        self.calls.lock().resets += 1;
        VirtioDevice::reset(&mut self.inner).await;
    }
}
async fn exchange(
    frontend: &VhostUserSocket,
    code: VhostUserRequestCode,
    payload: &[u8],
    need_reply: bool,
) -> Vec<u8> {
    exchange_fds(frontend, code, payload, need_reply, &[]).await
}
async fn exchange_fds(
    frontend: &VhostUserSocket,
    code: VhostUserRequestCode,
    payload: &[u8],
    need_reply: bool,
    fds: &[OwnedFd],
) -> Vec<u8> {
    let hdr = VhostUserMsgHeader {
        request: code.0,
        flags: VHOST_USER_FLAG_VERSION
            | if need_reply {
                VHOST_USER_FLAG_NEED_REPLY
            } else {
                0
            },
        size: payload.len() as u32,
    };
    frontend.send_message(&hdr, payload, fds).await.unwrap();
    let (reply, data, fds) = frontend
        .recv_message(&mut ScmReceiver::new(VHOST_USER_MAX_FDS))
        .await
        .unwrap();
    assert!(reply.is_reply() && reply.version_valid());
    assert_eq!(reply.request, hdr.request);
    assert_eq!(reply.size as usize, data.len());
    assert!(fds.is_empty());
    data
}
async fn enable_ack(frontend: &VhostUserSocket) {
    let features = VhostUserU64Msg {
        value: VhostUserProtocolFeatures::new()
            .with_reply_ack(true)
            .with_config(true)
            .into_bits(),
    };
    assert_eq!(
        exchange(
            frontend,
            VhostUserRequestCode::SET_PROTOCOL_FEATURES,
            features.as_bytes(),
            true
        )
        .await,
        0u64.to_le_bytes()
    );
}

// Test: Exchange config reads and writes against a nonzero recording device, then send out-of-range/truncated requests followed by valid reads.
// Expected: Replies preserve the config header and exact little-endian bytes, writes use the requested offsets/values, invalid requests NACK without device I/O, and later valid requests still succeed; disconnect resets once.
#[async_test]
async fn config_wire_preserves_data_bounds_and_nack_recovery(driver: DefaultDriver) {
    let calls = Arc::new(Mutex::new(RegisterCalls::default()));
    let device = ConfigDevice {
        inner: MockDevice::new(),
        calls: calls.clone(),
    };
    let (front, back) = socket_pair();
    let frontend = VhostUserSocket::new(PolledSocket::new(&driver, front).unwrap());
    let backend = VhostUserSocket::new(PolledSocket::new(&driver, back).unwrap());
    let client = async {
        enable_ack(&frontend).await;
        let header = VhostUserConfigHeader {
            offset: 0,
            size: 6,
            flags: 0x91,
        };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::GET_CONFIG,
                header.as_bytes(),
                false
            )
            .await,
            [header.as_bytes(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]].concat()
        );
        let header = VhostUserConfigHeader {
            offset: 0,
            size: 8,
            flags: 0,
        };
        let payload = [
            header.as_bytes(),
            &[0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28],
        ]
        .concat();
        assert_eq!(
            exchange(&frontend, VhostUserRequestCode::SET_CONFIG, &payload, true).await,
            0u64.to_le_bytes()
        );
        for code in [
            VhostUserRequestCode::GET_CONFIG,
            VhostUserRequestCode::SET_CONFIG,
        ] {
            let invalid = VhostUserConfigHeader {
                offset: 4,
                size: 5,
                flags: 0,
            };
            assert_eq!(
                exchange(&frontend, code, invalid.as_bytes(), true).await,
                1u64.to_le_bytes()
            );
        }
        let header = VhostUserConfigHeader {
            offset: 0,
            size: 4,
            flags: 0,
        };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::SET_CONFIG,
                header.as_bytes(),
                true
            )
            .await,
            1u64.to_le_bytes()
        );
        assert_eq!(
            exchange(&frontend, VhostUserRequestCode::GET_CONFIG, &[0; 11], true).await,
            1u64.to_le_bytes()
        );
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::GET_CONFIG,
                header.as_bytes(),
                false
            )
            .await,
            [header.as_bytes(), &[0x11, 0x22, 0x33, 0x44]].concat()
        );
        drop(frontend);
    };
    let (result, ()) = futures::join!(
        VhostUserDeviceServer::new(Box::new(device)).serve_connection(backend),
        client
    );
    result.unwrap();
    let calls = calls.lock();
    assert_eq!(calls.reads, [0, 4, 0]);
    assert_eq!(calls.writes, [(0, 0x64738291), (4, 0x28374655)]);
    assert_eq!(calls.resets, 1);
}
