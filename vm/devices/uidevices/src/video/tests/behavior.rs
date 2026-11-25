// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_helpers::connected_gpadl_channels;
use test_with_tracing::test;

#[derive(Debug, PartialEq)]
enum Update {
    Map(u64),
    Unmap,
    Format(FramebufferFormat),
}

struct RecordingControl(mesh::Sender<Update>);

#[async_trait]
impl FramebufferControl for RecordingControl {
    async fn map(&mut self, gpa: u64) {
        self.0.send(Update::Map(gpa));
    }
    async fn unmap(&mut self) {
        self.0.send(Update::Unmap);
    }
    async fn set_format(&mut self, format: FramebufferFormat) {
        self.0.send(Update::Format(format));
    }
}

// Open the public video device with observable framebuffer-control callbacks.
fn fixture() -> (
    Video,
    VideoChannel,
    MessagePipe<GpadlRingMem>,
    mesh::Receiver<Update>,
) {
    let (host, guest, memory) = connected_gpadl_channels();
    let (send, receive) = mesh::channel();
    let mut device = Video::new(Box::new(RecordingControl(send)), None).unwrap();
    let channel = device.open(host, memory).unwrap();
    (device, channel, MessagePipe::new(guest).unwrap(), receive)
}

// Complete version negotiation through the public runner, without reading its state.
async fn negotiate(
    device: &mut Video,
    channel: &mut VideoChannel,
    guest: &mut MessagePipe<GpadlRingMem>,
) {
    send_packet(
        guest,
        protocol::MESSAGE_VERSION_REQUEST,
        &protocol::VersionRequestMessage {
            version: protocol::Version::new(3, 3),
        },
    )
    .await;
    let mut run = std::pin::pin!(StopTask::run_unstoppable(async |stop| device
        .run(stop, channel)
        .await));
    assert!(run.as_mut().now_or_never().is_none());
    let bytes = recv_bytes(guest).await;
    let (header, payload) = parse_header(&bytes);
    assert_eq!(header.typ.to_ne(), protocol::MESSAGE_VERSION_RESPONSE);
    let response = protocol::VersionResponseMessage::read_from_bytes(payload).unwrap();
    assert_eq!(response.is_accepted, 2);
}

// Verify the acknowledgement's type, declared length and echoed context on the wire.
async fn assert_ack(guest: &mut MessagePipe<GpadlRingMem>, kind: u32, context: u64) {
    let bytes = recv_bytes(guest).await;
    let (header, payload) = parse_header(&bytes);
    assert_eq!((header.typ.to_ne(), header.size.to_ne()), (kind, 8));
    assert_eq!(payload, context.to_le_bytes());
}

// Test: Set a VRAM address, then withdraw it while providing an ignored stale address.
// Expected: Mapping is preceded by unmapping; withdrawal only unmaps and each ack echoes its context.
#[async_test]
async fn video_vram_updates_preserve_order_and_echo_context() {
    let (mut video, mut channel, mut guest, mut updates) = fixture();
    negotiate(&mut video, &mut channel, &mut guest).await;
    for (context, specified, address) in [(0x123456789u64, 1, 0x4000u64), (0x987654321, 0, 0x9000)]
    {
        send_packet(
            &mut guest,
            protocol::MESSAGE_VRAM_LOCATION,
            &protocol::VramLocationMessage {
                user_context: context.into(),
                is_vram_gpa_address_specified: specified,
                vram_gpa_address: address.into(),
            },
        )
        .await;
        {
            let mut run = std::pin::pin!(StopTask::run_unstoppable(async |stop| video
                .run(stop, &mut channel)
                .await));
            assert!(run.as_mut().now_or_never().is_none());
        }
        assert_ack(&mut guest, protocol::MESSAGE_VRAM_LOCATION_ACK, context).await;
        assert_eq!(updates.try_recv().unwrap(), Update::Unmap);
        if specified != 0 {
            assert_eq!(updates.try_recv().unwrap(), Update::Map(address));
        }
        assert!(matches!(updates.try_recv(), Err(mesh::TryRecvError::Empty)));
    }
}

// Test: Serialize and restore a negotiated video channel, then change its display layout.
// Expected: No second handshake is needed; the format and acknowledgement context are preserved.
#[async_test]
async fn video_restore_resumes_framebuffer_updates_without_renegotiation() {
    let (mut video, mut channel, mut guest, mut updates) = fixture();
    negotiate(&mut video, &mut channel, &mut guest).await;
    let saved = video.supports_save_restore().unwrap().save_open(&channel);
    let saved = mesh::payload::decode(&mesh::payload::encode(saved)).unwrap();
    drop(channel);
    let (host, guest_channel, _memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest_channel).unwrap();
    let mut channel = video.restore_open(saved, host).unwrap();
    send_packet(
        &mut guest,
        protocol::MESSAGE_SITUATION_UPDATE,
        &protocol::SituationUpdateMessage {
            user_context: 0xfedcba9876543210u64.into(),
            video_output_count: 1,
            video_output: protocol::VideoOutputSituation {
                active: 1,
                primary_surface_vram_offset: 4096.into(),
                depth_bits: 32,
                width_pixels: 320.into(),
                height_pixels: 200.into(),
                pitch_bytes: 1536.into(),
            },
        },
    )
    .await;
    {
        let mut run = std::pin::pin!(StopTask::run_unstoppable(async |stop| video
            .run(stop, &mut channel)
            .await));
        assert!(run.as_mut().now_or_never().is_none());
    }
    assert_eq!(
        updates.try_recv().unwrap(),
        Update::Format(FramebufferFormat {
            width: 320,
            height: 200,
            bytes_per_line: 1536,
            offset: 4096,
        })
    );
    assert_ack(
        &mut guest,
        protocol::MESSAGE_SITUATION_UPDATE_ACK,
        0xfedcba9876543210,
    )
    .await;
    assert!(matches!(updates.try_recv(), Err(mesh::TryRecvError::Empty)));
}

// Test: Retry a rejected version and query resolutions with capacities zero and one below the limit.
// Expected: Valid retry succeeds; small-capacity responses contain no entries or trailing data.
#[async_test]
async fn video_version_retry_and_small_resolution_buffers(driver: DefaultDriver) {
    let (host, mut guest) = connected_message_pipes(16384);
    let (_device, control, _view) = framebuffer_fixture();
    let worker = start_worker(&driver, control, None, host);
    for (major, accepted) in [(99, 0), (3, 2)] {
        send_packet(
            &mut guest,
            protocol::MESSAGE_VERSION_REQUEST,
            &protocol::VersionRequestMessage {
                version: protocol::Version::new(major, 3),
            },
        )
        .await;
        let bytes = recv_bytes(&mut guest).await;
        let (header, payload) = parse_header(&bytes);
        assert_eq!(header.typ.to_ne(), protocol::MESSAGE_VERSION_RESPONSE);
        let response = protocol::VersionResponseMessage::read_from_bytes(payload).unwrap();
        assert_eq!(
            (response.version.major(), response.is_accepted),
            (major, accepted)
        );
    }
    for maximum in [0, protocol::MAXIMUM_RESOLUTIONS_COUNT - 1] {
        send_packet(
            &mut guest,
            protocol::MESSAGE_SUPPORTED_RESOLUTIONS_REQUEST,
            &protocol::SupportedResolutionsRequestMessage {
                maximum_resolution_count: maximum,
            },
        )
        .await;
        let bytes = recv_bytes(&mut guest).await;
        let (header, payload) = parse_header(&bytes);
        assert_eq!(
            header.typ.to_ne(),
            protocol::MESSAGE_SUPPORTED_RESOLUTIONS_RESPONSE
        );
        let response =
            protocol::SupportedResolutionsResponseMessage::read_from_bytes(payload).unwrap();
        assert_eq!(
            (response.resolution_count, response.default_resolution_index),
            (0, 0)
        );
        assert_eq!(
            &response.edid_block.0[..8],
            &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]
        );
    }
    drop(guest);
    worker.await.unwrap();
}

// Test: Send pointer updates and dirty hints without a dirty-region consumer.
// Expected: Ignored optional features do not change the framebuffer or disrupt later BIOS queries.
#[async_test]
async fn video_optional_pointer_and_dirty_hints_keep_channel_usable() {
    let (mut video, mut channel, mut guest, mut updates) = fixture();
    negotiate(&mut video, &mut channel, &mut guest).await;
    send_packet(
        &mut guest,
        protocol::MESSAGE_POINTER_POSITION,
        &protocol::PointerPositionMessage {
            is_visible: 1,
            video_output: 0,
            image_x: (-10).into(),
            image_y: 20.into(),
        },
    )
    .await;
    let shape = protocol::PointerShapeMessage {
        partial_index: 0xff,
        cursor_flags: 1,
        width_pixels: 1.into(),
        height_pixels: 1.into(),
        hotspot_x: 0.into(),
        hotspot_y: 0.into(),
    };
    let header = protocol::MessageHeader {
        typ: protocol::MESSAGE_POINTER_SHAPE.into(),
        size: ((size_of_val(&shape) + 4) as u32).into(),
    };
    guest
        .send_vectored(&[
            IoSlice::new(header.as_bytes()),
            IoSlice::new(shape.as_bytes()),
            IoSlice::new(&[0; 4]),
        ])
        .await
        .unwrap();
    send_dirt_packet(&mut guest, &[]).await;
    send_packet(
        &mut guest,
        protocol::MESSAGE_BIOS_INFO_REQUEST,
        &protocol::BiosInfoRequestMessage {},
    )
    .await;
    {
        let mut run = std::pin::pin!(StopTask::run_unstoppable(async |stop| video
            .run(stop, &mut channel)
            .await));
        assert!(run.as_mut().now_or_never().is_none());
    }
    let bytes = recv_bytes(&mut guest).await;
    let (header, payload) = parse_header(&bytes);
    assert_eq!(header.typ.to_ne(), protocol::MESSAGE_BIOS_INFO_RESPONSE);
    assert_eq!(
        protocol::BiosInfoResponseMessage::read_from_bytes(payload)
            .unwrap()
            .stop_device_supported
            .to_ne(),
        1
    );
    assert!(matches!(updates.try_recv(), Err(mesh::TryRecvError::Empty)));
}

// Test: Parse truncated video requests and a dirty list whose declared rectangle is absent.
// Expected: Malformed payloads return InvalidPacket; unknown messages retain their type.
#[test]
fn malformed_video_packets_return_typed_errors() {
    for kind in [
        protocol::MESSAGE_VERSION_REQUEST,
        protocol::MESSAGE_VRAM_LOCATION,
        protocol::MESSAGE_SITUATION_UPDATE,
        protocol::MESSAGE_POINTER_POSITION,
        protocol::MESSAGE_DIRT,
        protocol::MESSAGE_SUPPORTED_RESOLUTIONS_REQUEST,
    ] {
        let mut bytes = kind.to_le_bytes().to_vec();
        bytes.extend(0u32.to_le_bytes());
        assert!(matches!(parse_packet(&bytes), Err(Error::InvalidPacket)));
    }

    let mut bytes = protocol::MESSAGE_DIRT.to_le_bytes().to_vec();
    bytes.extend(2u32.to_le_bytes());
    bytes.extend([0, 1]);
    assert!(matches!(parse_packet(&bytes), Err(Error::InvalidPacket)));
    assert!(matches!(parse_packet(&[]), Err(Error::InvalidPacket)));
    let mut bytes = 0xdeadbeefu32.to_le_bytes().to_vec();
    bytes.extend(0u32.to_le_bytes());
    assert!(matches!(
        parse_packet(&bytes),
        Err(Error::UnknownMessageType(0xdeadbeef))
    ));
}

struct GatedControl {
    control: RecordingControl,
    gate: crate::test_helpers::GatedInput<()>,
}

#[async_trait]
impl FramebufferControl for GatedControl {
    async fn map(&mut self, gpa: u64) {
        use futures::StreamExt;
        self.gate.next().await.unwrap();
        self.control.map(gpa).await;
    }

    async fn unmap(&mut self) {
        self.control.unmap().await;
    }
    async fn set_format(&mut self, format: FramebufferFormat) {
        self.control.set_format(format).await;
    }
}

// Test: Request stop during an accepted VRAM map operation, then restart the public runner.
// Expected: Mapping happens once and its pending acknowledgement survives cancellation.
#[async_test]
async fn public_video_runner_preserves_pending_ack_across_cancellation(driver: DefaultDriver) {
    let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("video-lifecycle");
    let (host, guest, memory) = connected_gpadl_channels();
    let mut guest = MessagePipe::new(guest).unwrap();
    let (source, gate) = crate::test_helpers::gated_input(Some(()));
    let (send, mut updates) = mesh::channel();
    let mut device = Video::new(
        Box::new(GatedControl {
            control: RecordingControl(send),
            gate: source,
        }),
        None,
    )
    .unwrap();
    let channel = device.open(host, memory).unwrap();
    send_packet(
        &mut guest,
        protocol::MESSAGE_VERSION_REQUEST,
        &protocol::VersionRequestMessage {
            version: protocol::Version::new(3, 3),
        },
    )
    .await;
    send_packet(
        &mut guest,
        protocol::MESSAGE_VRAM_LOCATION,
        &protocol::VramLocationMessage {
            user_context: 5u64.into(),
            is_vram_gpa_address_specified: 1,
            vram_gpa_address: 0x4000u64.into(),
        },
    )
    .await;
    let mut task =
        task_control::TaskControl::new(crate::test_helpers::DeviceWorker { device, channel });
    task.insert(&worker_driver, "video", ());
    assert!(task.start());
    gate.stop(&mut task, &driver).await;
    let bytes = recv_bytes(&mut guest).await;
    assert_eq!(
        parse_header(&bytes).0.typ.to_ne(),
        protocol::MESSAGE_VERSION_RESPONSE
    );
    assert_eq!(updates.try_recv().unwrap(), Update::Unmap);
    assert_eq!(updates.try_recv().unwrap(), Update::Map(0x4000));
    let mut bytes = [0; 256];
    assert!(guest.recv(&mut bytes).now_or_never().is_none());
    assert!(task.start());
    with_timeout(
        &driver,
        assert_ack(&mut guest, protocol::MESSAGE_VRAM_LOCATION_ACK, 5),
    )
    .await;
    stop_with_timeout(&mut task, &driver).await;
    assert!(matches!(updates.try_recv(), Err(mesh::TryRecvError::Empty)));
}

// Test: Resolve a video resource against a real shared framebuffer control.
// Expected: The resulting device offers the video protocol and its required MMIO region.
#[async_test]
async fn video_resolution_preserves_offer_identity_and_memory_requirements(driver: DefaultDriver) {
    use vm_resource::{Resource, ResourceResolver};
    use vmbus_channel::resources::{ResolveVmbusDeviceHandleParams, ResolvedVmbusDevice};
    use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

    let (device, _control, _view) = framebuffer_fixture();
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(device.control());
    resolver.add_async_resolver::<vm_resource::kind::VmbusDeviceHandleKind, _, uidevices_resources::SynthVideoHandle, _>(
            crate::resolver::VmbusUiResolver,
        );
    let driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let video: ResolvedVmbusDevice = resolver
        .resolve(
            Resource::new(uidevices_resources::SynthVideoHandle {
                framebuffer: Resource::new(video_core::SharedFramebufferHandle),
                dirt_send: None,
            }),
            ResolveVmbusDeviceHandleParams {
                driver_source: &driver,
            },
        )
        .await
        .unwrap();
    let offer = video.0.offer();
    assert_eq!(offer.interface_name, "video");
    assert_eq!(
        offer.interface_id,
        guid::guid!("da0a7802-e377-4aac-8e77-0558eb1073f8")
    );
    assert_eq!(offer.mmio_megabytes, 8);
    assert!(matches!(
        offer.channel_type,
        ChannelType::Device { pipe_packets: true }
    ));
}
