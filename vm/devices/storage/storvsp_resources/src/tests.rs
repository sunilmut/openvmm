// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::OwnedMessage;
use mesh::rpc::RpcSend;
use pal_async::async_test;
use test_with_tracing::test;
use vm_resource::PlatformResource;

// Test: Transport SCSI controller configuration with a nontrivial device path
//       and separately selected I/O, subchannel and polling depths.
// Expected: Queue policies, device addressing and optional runtime-channel
//       absence survive serialization without swapping independent fields.
#[test]
fn controller_configuration_transport() {
    let instance_id = guid::guid!("01234567-89ab-cdef-0123-456789abcdef");
    for (io_queue_depth, poll_mode_queue_depth) in [(None, Some(5)), (Some(17), None)] {
        let serialized = OwnedMessage::new(ScsiControllerHandle {
            instance_id,
            io_queue_depth,
            max_sub_channel_count: 7,
            devices: vec![ScsiDeviceAndPath {
                path: ScsiPath {
                    path: 1,
                    target: 2,
                    lun: 7,
                },
                device: Resource::new(PlatformResource),
            }],
            requests: None,
            poll_mode_queue_depth,
        })
        .serialize();
        let restored: ScsiControllerHandle = OwnedMessage::serialized(serialized).parse().unwrap();
        assert_eq!(restored.instance_id, instance_id);
        assert_eq!(restored.io_queue_depth, io_queue_depth);
        assert_eq!(restored.max_sub_channel_count, 7);
        assert_eq!(restored.poll_mode_queue_depth, poll_mode_queue_depth);
        assert!(restored.requests.is_none());
        let [device] = restored.devices.as_slice() else {
            panic!("transport changed initial device count");
        };
        assert_eq!(
            device.path,
            ScsiPath {
                path: 1,
                target: 2,
                lun: 7
            }
        );
        assert_eq!(device.path.to_string(), "1:2:7");
        assert_eq!(device.device.id(), "platform");
    }
}

// Test: Transfer a controller's runtime receiver, then explicitly serialize
//       add/remove requests carrying live RPC reply channels through it.
// Expected: Both request variants retain their path and send acknowledgments
//       back to the original caller after the controller resource is moved.
#[async_test]
async fn runtime_requests_and_replies_survive_transport() {
    let (send, receive) = mesh::channel();
    let serialized = OwnedMessage::new(ScsiControllerHandle {
        instance_id: Guid::ZERO,
        io_queue_depth: None,
        max_sub_channel_count: 0,
        devices: Vec::new(),
        requests: Some(receive),
        poll_mode_queue_depth: None,
    })
    .serialize();
    let mut controller: ScsiControllerHandle =
        OwnedMessage::serialized(serialized).parse().unwrap();
    let mut receive = controller.requests.take().unwrap();
    let path = ScsiPath {
        path: 0,
        target: 3,
        lun: 11,
    };
    let added = send.call_failable(
        |rpc| {
            OwnedMessage::serialized(
                OwnedMessage::new(ScsiControllerRequest::AddDevice(rpc)).serialize(),
            )
            .parse::<ScsiControllerRequest>()
            .unwrap()
        },
        ScsiDeviceAndPath {
            path,
            device: Resource::new(PlatformResource),
        },
    );
    let ScsiControllerRequest::AddDevice(rpc) = receive.recv().await.unwrap() else {
        panic!("add request changed variant");
    };
    let (device, reply) = rpc.split();
    assert_eq!(device.path, path);
    assert_eq!(device.device.id(), "platform");
    reply.complete(Ok(()));
    added.await.unwrap();

    let removed = send.call_failable(
        |rpc| {
            OwnedMessage::serialized(
                OwnedMessage::new(ScsiControllerRequest::RemoveDevice(rpc)).serialize(),
            )
            .parse::<ScsiControllerRequest>()
            .unwrap()
        },
        path,
    );
    let ScsiControllerRequest::RemoveDevice(rpc) = receive.recv().await.unwrap() else {
        panic!("remove request changed variant");
    };
    let (received_path, reply) = rpc.split();
    assert_eq!(received_path, path);
    reply.complete(Ok(()));
    removed.await.unwrap();
}
