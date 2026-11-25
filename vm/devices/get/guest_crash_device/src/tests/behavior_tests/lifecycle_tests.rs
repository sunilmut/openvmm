// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use guestmem::GuestMemory;
use test_with_tracing::test;
use vmbus_channel::gpadl::{GpadlId, GpadlMap};
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmbus_ring::{IncomingRing, OutgoingRing};

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
        GpadlRingMem::new(
            AlignedGpadlView::new(map.clone().view().map(GpadlId(id)).unwrap()).unwrap(),
            &memory,
        )
        .unwrap()
    };
    let (host_signals, guest_signals) = connected_async_channels(16384);
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
struct PublicWorker {
    device: GuestCrashDevice,
    channel: GuestCrashChannel,
}

struct ErrorWorker<M: RingMem> {
    worker: Worker<M>,
    ended: Option<mesh::OneshotSender<bool>>,
}
impl<M: RingMem + Unpin + Sync + 'static> AsyncRun<()> for ErrorWorker<M> {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        let result = self.worker.run(stop, &mut ()).await;
        if let Some(ended) = self.ended.take() {
            ended.send(result.is_ok());
        }
        result
    }
}

// Test: Send an unknown message to the active public processing loop and await its explicit end notification.
// Expected: The malformed channel terminates promptly without cancellation, sends no reply, requests no dump file, and remains safely stoppable instead of spinning or accepting more work.
#[async_test]
async fn protocol_failure_terminates_worker_without_file_or_reply(driver: DefaultDriver) {
    let (host, guest) = connected_async_channels(16384);
    let mut guest = MessagePipe::new(guest).unwrap();
    let (sender, mut requests) = mesh::channel();
    let (ended, finished) = mesh::oneshot();
    let mut task = TaskControl::new(ErrorWorker {
        worker: worker(host, sender),
        ended: Some(ended),
    });
    task.insert(&driver, "crash-error-exit", ());
    assert!(task.start());
    guest
        .try_send(header(crash::MessageType(u64::MAX), Guid::ZERO).as_bytes())
        .unwrap();
    assert!(with_timeout(&driver, finished).await.unwrap());
    assert!(!with_timeout(&driver, task.stop()).await);
    assert!(requests.next().now_or_never().is_none());
    assert!(guest.recv(&mut [0; 256]).now_or_never().is_none());
}
impl AsyncRun<()> for PublicWorker {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        self.device.run(stop, &mut self.channel).await
    }
}

// Test: Open and run the advertised crash pipe on actual guest-memory GPADL rings, write exactly the configured maximum, complete and stop the public worker.
// Expected: The offer has the crash GUID/message mode and no save support, the full 64-byte binary dump reaches the host file unchanged, one completion notification arrives, and the file is requested only once.
#[async_test]
async fn public_gpadl_worker_transfers_exact_boundary_dump(driver: DefaultDriver) {
    let (send, mut requests) = mesh::channel();
    let mut device = GuestCrashDevice::new(send, 64);
    let offer = device.offer();
    assert_eq!(offer.interface_name, "guest_crash");
    assert_eq!(offer.instance_id, CRASHDUMP_GUID);
    assert_eq!(offer.interface_id, CRASHDUMP_GUID);
    assert!(matches!(
        offer.channel_type,
        vmbus_channel::bus::ChannelType::Pipe {
            message_mode: true,
            ..
        }
    ));
    assert!(device.supports_save_restore().is_none());
    let (memory, host, mut guest) = pair();
    let channel = device.open(host, memory).unwrap();
    let mut task = TaskControl::new(PublicWorker { device, channel });
    task.insert(&driver, "crash-public", ());
    assert!(task.start());
    let activity = Guid::from_slice(&[0x31; 16]);
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_START_V1, activity).as_bytes())
        .unwrap();
    let (done, response) = with_timeout(&driver, requests.next())
        .await
        .unwrap()
        .split();
    let mut file = tempfile::tempfile().unwrap();
    response.complete(Ok(file.try_clone().unwrap()));
    let expected = crash::DumpStartResponseV1 {
        header: header(crash::MessageType::RESPONSE_NIX_DUMP_START_V1, activity),
        status: 0,
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    let bytes: Vec<u8> = (0..64).map(|value| value ^ 0x91).collect();
    let write = crash::DumpWriteRequestV1 {
        header: header(crash::MessageType::REQUEST_NIX_DUMP_WRITE_V1, activity),
        offset: 0,
        size: 64,
    };
    guest.try_send(write.as_bytes()).unwrap();
    guest.try_send(&bytes).unwrap();
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_COMPLETE_V1, activity).as_bytes())
        .unwrap();
    with_timeout(&driver, done).await.unwrap();
    stop_with_timeout(&mut task, &driver).await;
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(file.metadata().unwrap().len(), 64);
    assert!(requests.next().now_or_never().is_none());
}

// Test: Submit every truncated crash header and unknown/wrong-state message types without a live transfer, then a truncated write during an accepted dump.
// Expected: Invalid messages return the specific truncated/type error without emitting responses, starting file I/O, mutating existing bytes, or falsely signaling completion.
#[async_test]
async fn malformed_headers_and_wrong_state_requests_are_rejected(driver: DefaultDriver) {
    for message in (0..size_of::<crash::Header>())
        .map(|length| vec![0; length])
        .chain([header(crash::MessageType(u64::MAX), Guid::ZERO)
            .as_bytes()
            .to_vec()])
    {
        let (host, guest) = connected_async_channels(16384);
        let mut guest = MessagePipe::new(guest).unwrap();
        let (send, mut requests) = mesh::channel();
        let mut worker = worker(host, send);
        guest.try_send(&message).unwrap();
        let error = advance(&mut worker, &driver).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains(if message.len() < size_of::<crash::Header>() {
                    "truncated message"
                } else {
                    "invalid message type"
                })
        );
        assert!(requests.next().now_or_never().is_none());
        assert!(guest.recv(&mut [0; 256]).now_or_never().is_none());
    }
    let (host, guest) = connected_async_channels(16384);
    let mut guest = MessagePipe::new(guest).unwrap();
    let (send, mut requests) = mesh::channel();
    let mut worker = worker(host, send);
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"original").unwrap();
    let done = open_dump(
        &mut worker,
        &mut guest,
        &mut requests,
        file.try_clone().unwrap(),
        &driver,
    )
    .await;
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_WRITE_V1, Guid::ZERO).as_bytes())
        .unwrap();
    assert!(
        advance(&mut worker, &driver)
            .await
            .unwrap_err()
            .to_string()
            .contains("truncated message")
    );
    guest
        .try_send(header(crash::MessageType::REQUEST_GET_CAPABILITIES_V1, Guid::ZERO).as_bytes())
        .unwrap();
    assert!(
        advance(&mut worker, &driver)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid message type")
    );
    assert!(done.now_or_never().is_none());
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original");
}
