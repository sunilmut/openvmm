// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

async fn reply(socket: &VhostUserSocket, code: VhostUserRequestCode, payload: &[u8]) {
    socket
        .send_message(
            &VhostUserMsgHeader {
                request: code.0,
                flags: VHOST_USER_FLAG_VERSION | VHOST_USER_FLAG_REPLY,
                size: payload.len() as u32,
            },
            payload,
            &[] as &[OwnedFd],
        )
        .await
        .unwrap();
}

async fn scripted<F, Fut>(
    driver: &DefaultDriver,
    handler: F,
) -> (VhostUserFrontend, pal_async::task::Task<()>)
where
    F: FnOnce(VhostUserSocket) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (client, server) = socket_pair();
    let socket = VhostUserSocket::new(PolledSocket::new(driver, server).unwrap());
    let server = driver.spawn("scripted-config-peer", async move {
        let mut receiver = ScmReceiver::new(VHOST_USER_MAX_FDS);
        for (code, response) in [
            (
                VhostUserRequestCode::GET_FEATURES,
                Some(
                    VirtioDeviceFeatures::new()
                        .with_vhost_user_protocol_features(true)
                        .into_bits(),
                ),
            ),
            (
                VhostUserRequestCode::GET_PROTOCOL_FEATURES,
                Some(
                    VhostUserProtocolFeatures::new()
                        .with_config(true)
                        .with_reply_ack(true)
                        .into_bits(),
                ),
            ),
            (VhostUserRequestCode::SET_PROTOCOL_FEATURES, None),
            (VhostUserRequestCode::SET_OWNER, None),
        ] {
            let (header, _, fds) = socket.recv_message(&mut receiver).await.unwrap();
            assert_eq!(header.request, code.0);
            assert!(fds.is_empty());
            if let Some(value) = response {
                reply(&socket, code, VhostUserU64Msg { value }.as_bytes()).await;
            }
        }
        handler(socket).await;
    });
    let socket = VhostUserSocket::new(PolledSocket::new(driver, client).unwrap());
    let vm_driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())).simple();
    let frontend = VhostUserFrontend::from_socket(
        vm_driver,
        socket,
        VhostUserConfig {
            device_id: VirtioDeviceType::BLK,
            use_backend_config: true,
            queue_sizes: vec![16],
            config_patches: vec![],
        },
    )
    .await
    .unwrap();
    (frontend, server)
}

// Test: Respond to config reads with empty/header-only/short data and the wrong reply code, then a valid config DWORD.
// Expected: The frontend sends an exact zeroed GET_CONFIG request for every read, malformed/short/error replies return zero rather than stale bytes, and later valid data is returned unchanged.
#[async_test]
async fn config_read_failures_zero_the_result_and_valid_reads_recover(driver: DefaultDriver) {
    let (mut frontend, server) = scripted(&driver, |socket| async move {
        let mut receiver = ScmReceiver::new(VHOST_USER_MAX_FDS);
        for index in 0..5 {
            let (header, payload, fds) = socket.recv_message(&mut receiver).await.unwrap();
            assert_eq!(header.request, VhostUserRequestCode::GET_CONFIG.0);
            assert_eq!(header.flags, VHOST_USER_FLAG_VERSION);
            assert!(fds.is_empty());
            let request = VhostUserConfigHeader {
                offset: 4,
                size: 4,
                flags: 0,
            };
            assert_eq!(payload, [request.as_bytes(), &[0; 4]].concat());
            let mut payload = request.as_bytes().to_vec();
            match index {
                0 => payload.clear(),
                1 => {}
                2 => payload.extend_from_slice(&[0x91; 3]),
                _ => payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]),
            }
            reply(
                &socket,
                if index == 3 {
                    VhostUserRequestCode::GET_FEATURES
                } else {
                    VhostUserRequestCode::GET_CONFIG
                },
                &payload,
            )
            .await;
        }
    })
    .await;
    for expected in [0, 0, 0, 0, 0x44332211] {
        assert_eq!(frontend.read_registers_u32(4).await, expected);
    }
    drop(frontend);
    server.await;
}

// Test: Send exact config writes and return a truncated ACK, a backend error ACK, and a successful ACK before reading a valid config DWORD.
// Expected: Every write carries NEED_REPLY, the requested offset and exact little-endian bytes; rejected writes do not panic or desynchronize the socket, and the final read returns valid backend data.
#[async_test]
async fn config_write_ack_failures_preserve_wire_order_and_recover(driver: DefaultDriver) {
    let (mut frontend, server) = scripted(&driver, |socket| async move {
        let mut receiver = ScmReceiver::new(VHOST_USER_MAX_FDS);
        for index in 0..3 {
            let (header, payload, fds) = socket.recv_message(&mut receiver).await.unwrap();
            assert_eq!(header.request, VhostUserRequestCode::SET_CONFIG.0);
            assert_eq!(
                header.flags,
                VHOST_USER_FLAG_VERSION | VHOST_USER_FLAG_NEED_REPLY
            );
            assert!(fds.is_empty());
            let config = VhostUserConfigHeader {
                offset: 4,
                size: 4,
                flags: 0,
            };
            assert_eq!(
                payload,
                [config.as_bytes(), &0x91827364u32.to_le_bytes()].concat()
            );
            let ack = VhostUserU64Msg {
                value: u64::from(index == 1),
            };
            reply(
                &socket,
                VhostUserRequestCode::SET_CONFIG,
                if index == 0 { &[0; 7] } else { ack.as_bytes() },
            )
            .await;
        }
        let (header, _, _) = socket.recv_message(&mut receiver).await.unwrap();
        assert_eq!(header.request, VhostUserRequestCode::GET_CONFIG.0);
        let config = VhostUserConfigHeader {
            offset: 4,
            size: 4,
            flags: 0,
        };
        reply(
            &socket,
            VhostUserRequestCode::GET_CONFIG,
            &[config.as_bytes(), &[0x11, 0x22, 0x33, 0x44]].concat(),
        )
        .await;
    })
    .await;
    for _ in 0..3 {
        frontend.write_registers_u32(4, 0x91827364).await;
    }
    assert_eq!(frontend.read_registers_u32(4).await, 0x44332211);
    drop(frontend);
    server.await;
}
