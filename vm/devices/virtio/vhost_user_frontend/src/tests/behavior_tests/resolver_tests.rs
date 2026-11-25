// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::resolver::VhostUserFrontendResolver;
use test_with_tracing::test;
use virtio::resolve::VirtioResolveInput;
use virtio_resources::vhost_user::{VhostUserBlkHandle, VhostUserFsHandle, VhostUserGenericHandle};
use vm_resource::{AsyncResolveResource, ResourceResolver};

fn peer(driver: &DefaultDriver) -> (OwnedFd, pal_async::task::Task<()>) {
    let (client, server) = socket_pair();
    let socket = VhostUserSocket::new(PolledSocket::new(driver, server).unwrap());
    let mut device = MockBackendDevice::new();
    device.traits.device_register_length = 256;
    let server = VhostUserDeviceServer::new(Box::new(device));
    let task = driver.spawn("resolver-backend", async move {
        server.serve_connection(socket).await.unwrap();
    });
    (client.into(), task)
}

// Test: Resolve FS, BLK, and generic handles over connected backend sockets and read the resulting guest-visible traits/config.
// Expected: FS accepts an exact maximum-length tag and exposes it plus one request queue across two 1024-entry queues; BLK defaults to one 128-entry queue and patches its queue-count register; generic device ID and per-queue sizes are preserved without exposing the vhost-only feature bit.
#[async_test]
async fn resolved_handles_preserve_device_queue_and_config_contracts(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let resolver = ResourceResolver::new();
    let tag = "0123456789abcdefghijklmnopqrstuvwxyz";
    for kind in 0..3 {
        let (socket, backend) = peer(&driver);
        let input = VirtioResolveInput {
            driver_source: &source,
        };
        let mut device = match kind {
            0 => VhostUserFrontendResolver
                .resolve(
                    &resolver,
                    VhostUserFsHandle {
                        socket,
                        tag: tag.into(),
                        num_queues: None,
                        queue_size: None,
                    },
                    input,
                )
                .await
                .unwrap(),
            1 => VhostUserFrontendResolver
                .resolve(
                    &resolver,
                    VhostUserBlkHandle {
                        socket,
                        num_queues: None,
                        queue_size: None,
                    },
                    input,
                )
                .await
                .unwrap(),
            _ => VhostUserFrontendResolver
                .resolve(
                    &resolver,
                    VhostUserGenericHandle {
                        socket,
                        device_id: 0x1234,
                        queue_sizes: vec![16, 32],
                    },
                    input,
                )
                .await
                .unwrap(),
        };
        let traits = device.0.traits();
        assert!(!traits.device_features.vhost_user_protocol_features());
        match kind {
            0 => {
                assert_eq!(traits.device_id, VirtioDeviceType::FS);
                assert_eq!(traits.max_queues, 2);
                assert_eq!(device.0.queue_size(0), 1024);
                assert_eq!(device.0.queue_size(1), 1024);
                let expected = [tag.as_bytes(), &[1, 0, 0, 0]].concat();
                for (index, bytes) in expected.as_chunks::<4>().0.iter().copied().enumerate() {
                    assert_eq!(
                        device
                            .0
                            .read_registers_u32(index as u16 * 4)
                            .await
                            .to_le_bytes(),
                        bytes
                    );
                }
            }
            1 => {
                assert_eq!(traits.device_id, VirtioDeviceType::BLK);
                assert_eq!(traits.max_queues, 1);
                assert_eq!(device.0.queue_size(0), 128);
                assert_eq!(
                    device
                        .0
                        .read_registers_u32(std::mem::offset_of!(
                            virtio::spec::blk::VirtioBlkConfig,
                            num_queues
                        ) as u16)
                        .await,
                    1
                );
            }
            _ => {
                assert_eq!(traits.device_id, VirtioDeviceType(0x1234));
                assert_eq!(traits.max_queues, 2);
                assert_eq!(device.0.queue_size(0), 16);
                assert_eq!(device.0.queue_size(1), 32);
            }
        }
        drop(device);
        backend.await;
    }
}

// Test: Resolve empty generic queues, a 37-byte FS tag, and a non-socket BLK descriptor.
// Expected: Invalid geometry/tag inputs are rejected with specific context before socket use, and socket registration failures retain both BLK setup and registration context.
#[async_test]
async fn invalid_resources_are_rejected_with_actionable_context(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolver = ResourceResolver::new();
    let descriptor = || std::fs::File::open("/dev/null").unwrap().into();
    let result = VhostUserFrontendResolver
        .resolve(
            &resolver,
            VhostUserGenericHandle {
                socket: descriptor(),
                device_id: 2,
                queue_sizes: vec![],
            },
            VirtioResolveInput {
                driver_source: &source,
            },
        )
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("empty queues accepted"),
    };
    assert!(error.to_string().contains("non-empty queue_sizes"));
    let result = VhostUserFrontendResolver
        .resolve(
            &resolver,
            VhostUserFsHandle {
                socket: descriptor(),
                tag: "x".repeat(37),
                num_queues: None,
                queue_size: None,
            },
            VirtioResolveInput {
                driver_source: &source,
            },
        )
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("oversized tag accepted"),
    };
    assert!(
        error
            .to_string()
            .contains("exceeds maximum length of 36 bytes")
    );
    let result = VhostUserFrontendResolver
        .resolve(
            &resolver,
            VhostUserBlkHandle {
                socket: descriptor(),
                num_queues: None,
                queue_size: None,
            },
            VirtioResolveInput {
                driver_source: &source,
            },
        )
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("non-socket accepted"),
    };
    assert!(
        error
            .to_string()
            .contains("failed to set up vhost-user-blk device")
    );
    assert!(error.chain().any(|source| {
        source
            .to_string()
            .contains("failed to register vhost-user socket")
    }));
}
