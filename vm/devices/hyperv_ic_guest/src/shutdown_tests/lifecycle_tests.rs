// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use user_driver::lockmem::LockedMemory;
use user_driver::memory::MemoryBlock;
use vmbus_ring::{IncomingRing, OutgoingRing};

fn memory_pair() -> (
    RawAsyncChannel<MemoryBlockRingBuffer>,
    MessagePipe<MemoryBlockRingBuffer>,
) {
    let incoming = MemoryBlock::new(LockedMemory::new(5 * 4096).unwrap());
    let outgoing = MemoryBlock::new(LockedMemory::new(5 * 4096).unwrap());
    let (guest, host) = connected_async_channels(16384);
    let guest = RawAsyncChannel {
        in_ring: IncomingRing::new(MemoryBlockRingBuffer::new(incoming.clone())).unwrap(),
        out_ring: OutgoingRing::new(MemoryBlockRingBuffer::new(outgoing.clone())).unwrap(),
        signal: guest.signal,
    };
    let host = RawAsyncChannel {
        in_ring: IncomingRing::new(MemoryBlockRingBuffer::new(outgoing)).unwrap(),
        out_ring: OutgoingRing::new(MemoryBlockRingBuffer::new(incoming)).unwrap(),
        signal: host.signal,
    };
    (guest, MessagePipe::new(host).unwrap())
}

struct ClientWorker {
    ic: ShutdownGuestIc,
    channel: ShutdownGuestChannel,
}
impl AsyncRun<()> for ClientWorker {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        self.ic.run(stop, &mut self.channel).await
    }
}

// Test: Open the public shutdown client with actual MemoryBlock-backed rings, run negotiated shutdown I/O, stop/resume it, and send another shutdown without renegotiating.
// Expected: The client accepts its offer and reports no save/restore support, public run forwards exact requests and replies, and stopping/resuming retains negotiated protocol versions with no duplicate notification or response.
#[async_test]
async fn public_open_run_stop_and_resume_preserve_shutdown_protocol(driver: DefaultDriver) {
    let (guest, mut host) = memory_pair();
    let mut ic = ShutdownGuestIc::new();
    assert_eq!(ic.instance_id(), INSTANCE_ID);
    assert!(matches!(
        ic.offer(&FromZeros::new_zeroed()),
        OfferResponse::Open
    ));
    assert!(ic.supports_save_restore().is_none());
    let mut notifier = ic.get_shutdown_notifier();
    let channel = ic.open(0, guest).unwrap();
    let mut task = TaskControl::new(ClientWorker { ic, channel });
    task.insert(&driver, "shutdown-public-lifecycle", ());
    assert!(task.start());
    let packet = negotiation(&[FRAMEWORK_VERSION_1], &[SHUTDOWN_VERSION_3_1], true);
    host.send(&packet).await.unwrap();
    let response = receive(&driver, &mut host).await;
    let (header, _) = hyperv_ic_protocol::Header::read_from_prefix(&response).unwrap();
    assert_eq!(
        header.message_type,
        hyperv_ic_protocol::MessageType::VERSION_NEGOTIATION
    );
    assert_eq!(header.transaction_id, 0x51);
    for iteration in 0..2 {
        host.send(&shutdown_packet(false, false, iteration != 0))
            .await
            .unwrap();
        with_timeout(&driver, notifier.recv())
            .await
            .unwrap()
            .handle_sync(|params| {
                assert!(matches!(params.shutdown_type, ShutdownType::PowerOff));
                assert_eq!(params.force, iteration != 0);
                ShutdownResult::Ok
            });
        assert_eq!(
            receive(&driver, &mut host).await,
            shutdown_response(Status::SUCCESS)
        );
        stop_with_timeout(&mut task, &driver).await;
        assert!(notifier.recv().now_or_never().is_none());
        assert!(host.recv(&mut [0; 4096]).now_or_never().is_none());
        if iteration == 0 {
            assert!(task.start());
        }
    }
    task.task_mut().ic.close(0);
}
