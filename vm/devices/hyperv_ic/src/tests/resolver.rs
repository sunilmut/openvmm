// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::timesync::TimeSource;
use hyperv_ic_protocol::kvp;
use hyperv_ic_protocol::shutdown;
use hyperv_ic_protocol::timesync;
use hyperv_ic_resources::kvp::KvpIcHandle;
use hyperv_ic_resources::shutdown::ShutdownIcHandle;
use hyperv_ic_resources::timesync::TimesyncIcHandle;
use pal_async::DefaultDriver;
use pal_async::async_test;
use std::sync::atomic::AtomicU64;
use test_with_tracing::test;
use vm_resource::IntoResource;
use vm_resource::ResourceResolver;
use vm_resource::kind::VmbusDeviceHandleKind;
use vmbus_channel::bus::ChannelType;
use vmbus_channel::resources::ResolveVmbusDeviceHandleParams;
use vmcore::reference_time::ReferenceTimeSource;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

vm_resource::register_static_resolvers! {
    crate::resolver::ShutdownIcResolver,
    crate::resolver::KvpIcResolver,
    crate::resolver::TimesyncIcResolver,
}

// Test: Resolve each IC handle through resource dispatch, with and without the
//       timesync device's required platform time source.
// Expected: Missing time has an explicit error; resolved devices advertise the
//       correct guest interface and instance on message-mode pipe channels.
#[async_test]
async fn resource_dispatch_selects_correct_guest_interfaces(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let input = || ResolveVmbusDeviceHandleParams {
        driver_source: &driver_source,
    };
    let mut resolver = ResourceResolver::new();
    let missing = resolver
        .resolve::<VmbusDeviceHandleKind, _>(TimesyncIcHandle.into_resource(), input())
        .await;
    let Err(error) = missing else {
        panic!("timesync resolved without a time source")
    };
    let error = anyhow::Error::new(error);
    assert!(
        format!("{error:#}").contains("failed to resolve reference time"),
        "{error:#}"
    );
    resolver.add_resolver(ReferenceTimeSource::new(TimeSource {
        snapshot: None,
        counter: AtomicU64::new(0),
    }));
    let (_shutdown_send, recv) = mesh::channel();
    let shutdown_device = resolver
        .resolve::<VmbusDeviceHandleKind, _>(ShutdownIcHandle { recv }.into_resource(), input())
        .await
        .unwrap();
    let (_kvp_send, recv) = mesh::channel();
    let kvp_device = resolver
        .resolve::<VmbusDeviceHandleKind, _>(KvpIcHandle { recv }.into_resource(), input())
        .await
        .unwrap();
    let timesync_device = resolver
        .resolve::<VmbusDeviceHandleKind, _>(TimesyncIcHandle.into_resource(), input())
        .await
        .unwrap();
    for (device, interface, instance) in [
        (
            shutdown_device,
            shutdown::INTERFACE_ID,
            shutdown::INSTANCE_ID,
        ),
        (kvp_device, kvp::INTERFACE_ID, kvp::INSTANCE_ID),
        (
            timesync_device,
            timesync::INTERFACE_ID,
            timesync::INSTANCE_ID,
        ),
    ] {
        let offer = device.0.offer();
        assert_eq!(offer.interface_id, interface);
        assert_eq!(offer.instance_id, instance);
        assert!(matches!(
            offer.channel_type,
            ChannelType::Pipe {
                message_mode: true,
                ..
            }
        ));
    }
}
