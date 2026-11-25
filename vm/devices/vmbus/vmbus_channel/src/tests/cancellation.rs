// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_helpers::GatedRingMem;
use crate::test_helpers::gated_channels;
use crate::test_helpers::stop_with_timeout;
use guestmem::MemoryRead;
use task_control::AsyncRun;
use task_control::Cancelled;
use task_control::StopTask;
use task_control::TaskControl;
use test_with_tracing::test;
use vmbus_ring::OutgoingPacket;
use vmbus_ring::OutgoingPacketType;
use vmbus_ring::ReadError;

struct Echo {
    channel: RawAsyncChannel<GatedRingMem>,
}

fn send(channel: &RawAsyncChannel<GatedRingMem>, payload: &[u64]) {
    let mut offset = channel.out_ring.outgoing().unwrap();
    let range = channel
        .out_ring
        .write(
            &mut offset,
            &OutgoingPacket {
                transaction_id: 0,
                size: size_of_val(payload),
                typ: OutgoingPacketType::InBandNoCompletion,
            },
        )
        .unwrap();
    range.write_aligned_full(&channel.out_ring, payload);
    if channel.out_ring.commit_write(&mut offset) {
        channel.signal.signal_remote();
    }
}

async fn receive(channel: &RawAsyncChannel<GatedRingMem>) -> Vec<u8> {
    channel.in_ring.set_interrupt_mask(false);
    let mut offset = channel.in_ring.incoming().unwrap();
    poll_fn(|cx| match channel.in_ring.read(&mut offset) {
        Ok(packet) => {
            let payload = packet.payload.reader(&channel.in_ring).read_all().unwrap();
            if channel.in_ring.commit_read(&mut offset) {
                channel.signal.signal_remote();
            }
            Poll::Ready(payload)
        }
        Err(ReadError::Empty) => {
            if let Poll::Ready(result) = channel.signal.poll_for_signal(cx) {
                assert!(result.is_ok());
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
        Err(err) => panic!("invalid test packet: {err}"),
    })
    .await
}

impl AsyncRun<()> for Echo {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        loop {
            let payload = stop.until_stopped(receive(&self.channel)).await?;
            send(
                &self.channel,
                &[u64::from_ne_bytes(payload.try_into().unwrap())],
            );
        }
    }
}

// Test: Stop an echo worker during a gated packet read, then rearm and resume it.
// Expected: The accepted packet is echoed once; the next packet survives restart.
#[test]
fn read_gate_preserves_accepted_work_and_can_be_rearmed() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("channel-read-gate");
        let (host, guest, gate) = gated_channels(4096);
        send(&guest, &[1]);
        send(&guest, &[2]);
        let mut worker = TaskControl::new(Echo { channel: host });
        worker.insert(&worker_driver, "echo", ());
        assert!(worker.start());
        gate.stop(&mut worker, &driver).await;
        assert_eq!(receive(&guest).await, 1u64.to_ne_bytes());
        assert!(receive(&guest).now_or_never().is_none());
        gate.rearm();
        assert!(worker.start());
        gate.resume();
        assert_eq!(receive(&guest).await, 2u64.to_ne_bytes());
        stop_with_timeout(&mut worker, &driver).await;
        assert!(receive(&guest).now_or_never().is_none());
    }));
}
