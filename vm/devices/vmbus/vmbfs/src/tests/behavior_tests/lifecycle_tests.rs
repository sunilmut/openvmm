// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use guestmem::GuestMemory;
use test_with_tracing::test;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMap;
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_ring::IncomingRing;
use vmbus_ring::OutgoingRing;
use vmbus_ring::gparange::MultiPagedRangeBuf;

fn pair() -> (
    GuestMemory,
    RawAsyncChannel<GpadlRingMem>,
    MessagePipe<GpadlRingMem>,
) {
    let memory = GuestMemory::allocate(10 * 4096);
    let map = GpadlMap::new();
    for (id, first) in [(1, 0), (2, 5)] {
        let range = std::iter::once(5 * 4096).chain(first..first + 5).collect();
        map.add(
            GpadlId(id),
            MultiPagedRangeBuf::from_range_buffer(1, range).unwrap(),
        );
    }
    let make_ring = |id| {
        let view = map.clone().view().map(GpadlId(id)).unwrap();
        GpadlRingMem::new(AlignedGpadlView::new(view).unwrap(), &memory).unwrap()
    };
    let (host_signals, guest_signals) = vmbus_channel::connected_async_channels(16384);
    let host = RawAsyncChannel {
        in_ring: IncomingRing::new(make_ring(1)).unwrap(),
        out_ring: OutgoingRing::new(make_ring(2)).unwrap(),
        signal: host_signals.signal,
    };
    let guest = RawAsyncChannel {
        in_ring: IncomingRing::new(make_ring(2)).unwrap(),
        out_ring: OutgoingRing::new(make_ring(1)).unwrap(),
        signal: guest_signals.signal,
    };
    (memory, host, MessagePipe::new(guest).unwrap())
}

struct SavedWorker {
    device: VmbfsDevice,
    channel: VmbfsChannel,
}

impl AsyncRun<()> for SavedWorker {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        self.device.run(stop, &mut self.channel).await
    }
}

// Test: Open/save an unnegotiated device on real guest-memory GPADL rings, restore and negotiate it, then save/restore again and read without renegotiation.
// Expected: The advertised IMC channel is a message pipe, both negotiation states survive save/restore, the real device runner is stoppable, and restored Ready state serves exact file information immediately.
#[async_test]
async fn gpadl_open_and_restore_preserve_both_negotiation_states(driver: DefaultDriver) {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&[0x91; 37]).unwrap();
    let backing = single_file_backing::VmbfsSingleFileBacking::new("state.bin", file).unwrap();
    let mut device = VmbfsDevice::new(Box::new(backing));
    let offer = device.offer();
    assert_eq!(offer.interface_name, "vmbfs");
    assert_eq!(offer.instance_id, protocol::IMC_INSTANCE);
    assert_eq!(offer.interface_id, protocol::INTERFACE_TYPE);
    assert!(matches!(
        offer.channel_type,
        vmbus_channel::bus::ChannelType::Device { pipe_packets: true }
    ));
    assert!(device.supports_save_restore().is_some());
    let (memory, host, _guest) = pair();
    let channel = device.open(host, memory).unwrap();
    let saved = device.save_open(&channel);
    drop(channel);
    let (_memory, host, mut guest) = pair();
    let channel = device.restore_open(saved, host).unwrap();
    let mut task = TaskControl::new(SavedWorker { device, channel });
    task.insert(&driver, "vmbfs-restore", ());
    assert!(task.start());
    guest
        .try_send(&packet(
            protocol::MessageType::VERSION_REQUEST,
            protocol::VersionRequest {
                requested_version: protocol::Version::WIN10,
            }
            .as_bytes(),
        ))
        .unwrap();
    assert_eq!(
        receive(&driver, &mut guest).await,
        vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    stop_with_timeout(&mut task, &driver).await;
    let worker = task.task_mut();
    let saved = worker.device.save_open(&worker.channel);
    let (_memory, host, mut guest) = pair();
    worker.channel = worker.device.restore_open(saved, host).unwrap();
    assert!(task.start());
    guest
        .try_send(&packet(
            protocol::MessageType::GET_FILE_INFO_REQUEST,
            &path_bytes("\\state.bin"),
        ))
        .unwrap();
    let reply = receive(&driver, &mut guest).await;
    let (header, body) = protocol::MessageHeader::read_from_prefix(&reply).unwrap();
    assert_eq!(
        header.message_type,
        protocol::MessageType::GET_FILE_INFO_RESPONSE
    );
    let (info, tail) = protocol::GetFileInfoResponse::read_from_prefix(body).unwrap();
    assert_eq!(info.status, protocol::Status::SUCCESS);
    assert_eq!(info.file_size, 37);
    assert!(tail.is_empty());
    stop_with_timeout(&mut task, &driver).await;
}
