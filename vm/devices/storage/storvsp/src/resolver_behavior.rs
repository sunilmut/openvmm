// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::resolver::{StorvspIdeResolver, StorvspResolver};
use scsi_core::{ResolveScsiDeviceHandleParams, ResolvedScsiDevice};
use storvsp_resources::{
    ScsiControllerHandle, ScsiControllerRequest, ScsiDeviceAndPath, StorvspIdeDeviceHandle,
};
use test_with_tracing::test;
use vm_resource::kind::ScsiDeviceHandleKind;
use vm_resource::{ResolveResource, Resource, ResourceId, ResourceResolver};
use vmbus_channel::resources::{ResolveVmbusDeviceHandleParams, ResolvedVmbusDevice};

#[derive(mesh::MeshPayload)]
struct TestDisk {
    fail: bool,
}
impl ResourceId<ScsiDeviceHandleKind> for TestDisk {
    const ID: &'static str = "storvsp-behavior-disk";
}

struct DiskResolver;
impl ResolveResource<ScsiDeviceHandleKind, TestDisk> for DiskResolver {
    type Output = ResolvedScsiDevice;
    type Error = std::io::Error;
    fn resolve(
        &self,
        resource: TestDisk,
        _: ResolveScsiDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        if resource.fail {
            return Err(std::io::Error::other("test media resolution failed"));
        }
        Ok(scsidisk::SimpleScsiDisk::new(
            disklayer_ram::ram_disk(1024 * 1024, false).unwrap(),
            Default::default(),
        )
        .into())
    }
}

fn resolver() -> ResourceResolver {
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(DiskResolver);
    resolver.add_async_resolver(StorvspResolver);
    resolver.add_async_resolver(StorvspIdeResolver);
    resolver
}

fn device(path: ScsiPath, fail: bool) -> ScsiDeviceAndPath {
    ScsiDeviceAndPath {
        path,
        device: Resource::new(TestDisk { fail }),
    }
}

fn config(
    devices: Vec<ScsiDeviceAndPath>,
    requests: Option<mesh::Receiver<ScsiControllerRequest>>,
) -> ScsiControllerHandle {
    ScsiControllerHandle {
        instance_id: Guid::new_random(),
        io_queue_depth: Some(4),
        max_sub_channel_count: 2,
        devices,
        requests,
        poll_mode_queue_depth: Some(0),
    }
}

// Test: Resolve a controller and add or remove media through its request channel.
// Expected: Runtime requests succeed for valid media and report duplicate paths,
//       missing paths and media-resolution errors through their RPC replies.
#[async_test]
async fn runtime_controller_requests_report_media_and_path_errors(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolver = resolver();
    let (send, receive) = mesh::channel();
    let input = config(Vec::new(), Some(receive));
    let instance_id = input.instance_id;
    let resolved: ResolvedVmbusDevice = resolver
        .resolve(
            Resource::new(input),
            ResolveVmbusDeviceHandleParams {
                driver_source: &source,
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.0.offer().instance_id, instance_id);
    assert_eq!(
        resolved.0.offer().interface_id,
        storvsp_protocol::SCSI_INTERFACE_ID
    );
    assert_eq!(resolved.0.max_subchannels(), 2);
    let path = ScsiPath {
        path: 0,
        target: 3,
        lun: 5,
    };
    send.call_failable(ScsiControllerRequest::AddDevice, device(path, false))
        .await
        .unwrap();
    assert!(
        send.call_failable(ScsiControllerRequest::AddDevice, device(path, false))
            .await
            .is_err()
    );
    assert!(
        send.call_failable(
            ScsiControllerRequest::AddDevice,
            device(ScsiPath::default(), true)
        )
        .await
        .is_err()
    );
    send.call_failable(ScsiControllerRequest::RemoveDevice, path)
        .await
        .unwrap();
    assert!(
        send.call_failable(ScsiControllerRequest::RemoveDevice, path)
            .await
            .is_err()
    );
    drop(resolved);
    send.call_failable(ScsiControllerRequest::AddDevice, device(path, false))
        .await
        .unwrap();
    send.call_failable(ScsiControllerRequest::RemoveDevice, path)
        .await
        .unwrap();
    drop(send);
}

// Test: Resolve initial media lists containing backend failures or duplicate paths.
// Expected: Controller creation fails explicitly instead of dropping bad entries
//       or replacing a previously attached disk.
#[async_test]
async fn initial_controller_devices_reject_bad_media_and_duplicate_paths(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolver = resolver();
    for devices in [
        vec![device(ScsiPath::default(), true)],
        vec![
            device(ScsiPath::default(), false),
            device(ScsiPath::default(), false),
        ],
    ] {
        let result: Result<ResolvedVmbusDevice, _> = resolver
            .resolve(
                Resource::new(config(devices, None)),
                ResolveVmbusDeviceHandleParams {
                    driver_source: &source,
                },
            )
            .await;
        assert!(result.is_err());
    }
}

// Test: Resolve IDE accelerator resources for valid and invalid addresses.
// Expected: Valid offers expose the requested IDE channel/device identity; invalid
//       addresses and unresolved media fail instead of creating an offer.
#[async_test]
async fn ide_resources_validate_addresses_and_publish_guest_identity(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolver = resolver();
    for (channel_id, device_id, fail) in [
        (0, 0, false),
        (1, 1, false),
        (2, 0, false),
        (0, 2, false),
        (0, 0, true),
    ] {
        let resource = StorvspIdeDeviceHandle {
            channel_id,
            device_id,
            disk: Resource::new(TestDisk { fail }),
            io_queue_depth: None,
        };
        let result: Result<ResolvedVmbusDevice, _> = resolver
            .resolve(
                Resource::new(resource),
                ResolveVmbusDeviceHandleParams {
                    driver_source: &source,
                },
            )
            .await;
        if channel_id > 1 || device_id > 1 || fail {
            assert!(result.is_err());
        } else {
            let resolved = result.unwrap();
            let offer = resolved.0.offer();
            assert_eq!(
                offer.interface_id,
                storvsp_protocol::IDE_ACCELERATOR_INTERFACE_ID
            );
            assert_eq!(offer.instance_id.data1, u32::from(channel_id));
            assert_eq!(offer.instance_id.data2, u16::from(device_id));
            let ChannelType::Interface { user_defined } = offer.channel_type else {
                panic!("expected IDE interface");
            };
            let properties = storvsp_protocol::OfferProperties::read_from_prefix(&user_defined[..])
                .unwrap()
                .0;
            assert_eq!(properties.path_id, channel_id);
            assert_eq!(properties.target_id, device_id);
            assert_eq!(
                properties.flags,
                storvsp_protocol::OFFER_PROPERTIES_FLAG_IDE_DEVICE
            );
            assert_eq!(resolved.0.max_subchannels(), 0);
        }
    }
}
