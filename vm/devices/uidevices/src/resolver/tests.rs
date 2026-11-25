// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use input_core::MultiplexedInputHandle;
use input_core::{KeyboardData, MouseData, ResolvedInputSource};
use pal_async::{DefaultDriver, async_test};
use std::convert::Infallible;
use test_with_tracing::test;
use vm_resource::kind::{KeyboardInputHandleKind, MouseInputHandleKind};
use vm_resource::{ResolveResource, Resource};
use vmbus_channel::bus::ChannelType;
use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

struct InputResolver(mesh::Sender<(String, usize)>);

impl ResolveResource<KeyboardInputHandleKind, MultiplexedInputHandle> for InputResolver {
    type Output = ResolvedInputSource<KeyboardData>;
    type Error = Infallible;

    fn resolve(
        &self,
        resource: MultiplexedInputHandle,
        name: &str,
    ) -> Result<Self::Output, Self::Error> {
        self.0.send((name.to_owned(), resource.elevation));
        Ok(input_core::mesh_input::input_pair().0.into())
    }
}

impl ResolveResource<MouseInputHandleKind, MultiplexedInputHandle> for InputResolver {
    type Output = ResolvedInputSource<MouseData>;
    type Error = Infallible;

    fn resolve(
        &self,
        resource: MultiplexedInputHandle,
        name: &str,
    ) -> Result<Self::Output, Self::Error> {
        self.0.send((name.to_owned(), resource.elevation));
        Ok(input_core::mesh_input::input_pair().0.into())
    }
}

// Test: Resolve keyboard and mouse devices through the registered resource dispatch.
// Expected: Input labels/elevations reach their resolver and device offers retain identity.
#[async_test]
async fn input_resolution_forwards_source_parameters_and_device_identity(driver: DefaultDriver) {
    let driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let (send, mut calls) = mesh::channel();
    let mut resolver = ResourceResolver::new();
    resolver
        .add_async_resolver::<VmbusDeviceHandleKind, _, SynthKeyboardHandle, _>(VmbusUiResolver);
    resolver.add_async_resolver::<VmbusDeviceHandleKind, _, SynthMouseHandle, _>(VmbusUiResolver);
    resolver.add_resolver::<KeyboardInputHandleKind, _, _, _>(InputResolver(send.clone()));
    resolver.add_resolver::<MouseInputHandleKind, _, _, _>(InputResolver(send));
    let keyboard: ResolvedVmbusDevice = resolver
        .resolve(
            Resource::new(SynthKeyboardHandle {
                source: Resource::new(MultiplexedInputHandle { elevation: 3 }),
            }),
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await
        .unwrap();
    let mouse: ResolvedVmbusDevice = resolver
        .resolve(
            Resource::new(SynthMouseHandle {
                source: Resource::new(MultiplexedInputHandle { elevation: 7 }),
            }),
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await
        .unwrap();
    assert_eq!(calls.try_recv().unwrap(), ("synthkbd".to_owned(), 3));
    assert_eq!(calls.try_recv().unwrap(), ("synthmouse".to_owned(), 7));
    assert!(matches!(calls.try_recv(), Err(mesh::TryRecvError::Empty)));
    assert_eq!(keyboard.0.offer().interface_name, "keyboard");
    assert_eq!(
        keyboard.0.offer().interface_id,
        hyperv_keyboard_protocol::INTERFACE_GUID
    );
    assert_eq!(mouse.0.offer().interface_name, "mouse");
    assert_eq!(
        mouse.0.offer().interface_id,
        guid::guid!("cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a")
    );
    assert!(matches!(
        mouse.0.offer().channel_type,
        ChannelType::Device { pipe_packets: true }
    ));
}

// Test: Resolve each UI device without the resolver for its required input/framebuffer.
// Expected: Typed UI errors preserve the missing-child-resource failure.
#[async_test]
async fn missing_child_resources_retain_typed_resolution_errors(driver: DefaultDriver) {
    let driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let resolver = ResourceResolver::new();
    let keyboard = VmbusUiResolver
        .resolve(
            &resolver,
            SynthKeyboardHandle {
                source: Resource::new(MultiplexedInputHandle { elevation: 0 }),
            },
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await;
    assert!(matches!(
        keyboard,
        Err(InputError::InputSource(ResolveError::NoResolver { .. }))
    ));
    let mouse = VmbusUiResolver
        .resolve(
            &resolver,
            SynthMouseHandle {
                source: Resource::new(MultiplexedInputHandle { elevation: 0 }),
            },
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await;
    assert!(matches!(
        mouse,
        Err(InputError::InputSource(ResolveError::NoResolver { .. }))
    ));
    let video = VmbusUiResolver
        .resolve(
            &resolver,
            SynthVideoHandle {
                framebuffer: Resource::new(video_core::SharedFramebufferHandle),
                dirt_send: None,
            },
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await;
    assert!(matches!(
        video,
        Err(VideoError::Framebuffer(ResolveError::NoResolver { .. }))
    ));
}
