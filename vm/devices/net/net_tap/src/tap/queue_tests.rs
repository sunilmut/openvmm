// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::RxId;
use crate::RxMetadata;
use crate::RxOffloadSupport;
use crate::StaleOffloadRecovery;
use crate::TapQueue;
use futures::FutureExt;
use guestmem::GuestMemory;
use net_backend::BufferAccess;
use net_backend::Queue;
use net_backend::RxBufferSegment;
use net_backend::TxFlags;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use test_with_tracing::test;
use zerocopy::IntoBytes;

struct Pool {
    memory: GuestMemory,
    capacity: u32,
    packets: Vec<(u32, RxMetadata, Vec<u8>)>,
}

impl Pool {
    fn new(capacity: u32) -> Self {
        Self {
            memory: GuestMemory::allocate(4096),
            capacity,
            packets: Vec::new(),
        }
    }
}

impl BufferAccess for Pool {
    fn guest_memory(&self) -> &GuestMemory {
        &self.memory
    }
    fn capacity(&self, _id: RxId) -> u32 {
        self.capacity
    }
    fn write_packet(&mut self, id: RxId, metadata: &RxMetadata, data: &[u8]) {
        self.packets.push((id.0, *metadata, data.to_vec()));
    }
    fn write_data(&mut self, _id: RxId, _data: &[u8]) {
        unreachable!("whole packet expected")
    }
    fn write_header(&mut self, _id: RxId, _metadata: &RxMetadata) {
        unreachable!("whole packet expected")
    }
    fn push_guest_addresses(&self, _id: RxId, _segments: &mut Vec<RxBufferSegment>) {
        unreachable!("copied packet path expected")
    }
}

fn queue(driver: &DefaultDriver) -> (TapQueue, UnixDatagram) {
    let (host, peer) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let tap = Tap {
        tap: File::from(OwnedFd::from(host)),
    };
    let slot = Arc::new(Mutex::new(Some(tap)));
    let recovery = Arc::new(Mutex::new(StaleOffloadRecovery::all()));
    (
        TapQueue::new(driver, slot, recovery, RxOffloadSupport::default()).unwrap(),
        peer,
    )
}

fn send(peer: &UnixDatagram, bytes: &[u8]) {
    let packet = [VirtioNetHdr::default().as_bytes(), bytes].concat();
    assert_eq!(peer.send(&packet).unwrap(), packet.len());
}

async fn wait_ready(driver: &DefaultDriver, queue: &mut TapQueue, pool: &mut Pool) {
    let mut timer = pal_async::timer::PolledTimer::new(driver);
    futures::select! {
        _ = std::future::poll_fn(|cx| queue.poll_ready(cx, pool)).fuse() => {},
        _ = timer.sleep(std::time::Duration::from_secs(5)).fuse() => panic!("RX readiness timed out"),
    }
}

// Test: Run RX over a packet-preserving Unix socket test transport, reject a frame above guest capacity, receive the next frame, then drop/recreate the queue around the same descriptor.
// Expected: Only fitting packets complete with exact IDs/data/metadata, oversized frames do not consume guest buffers, pending/completion behavior is correct, and queue teardown preserves a usable transport for recreation. Kernel TAP ioctls are not simulated.
#[async_test]
async fn rx_capacity_completion_and_queue_recreation_preserve_packets(driver: DefaultDriver) {
    let (mut queue, peer) = queue(&driver);
    let mut pool = Pool::new(64);
    queue.rx_avail(&mut pool, &[RxId(7)]);
    send(&peer, &[0x91; 65]);
    send(&peer, &[0x27; 64]);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    wait_ready(&driver, &mut queue, &mut pool).await;
    let mut done = [RxId(99)];
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, 7);
    assert_eq!(pool.packets.len(), 1);
    assert_eq!(pool.packets[0].0, 7);
    assert_eq!(pool.packets[0].1.len, 64);
    assert_eq!(pool.packets[0].2, vec![0x27; 64]);
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 0);
    let slot = queue.slot.clone();
    let recovery = queue.stale_offload_recovery_slot.clone();
    drop(queue);
    let mut queue = TapQueue::new(&driver, slot, recovery, RxOffloadSupport::default()).unwrap();
    assert!(queue.poll_ready(&mut cx, &mut pool).is_pending());
    queue.rx_avail(&mut pool, &[RxId(8)]);
    send(&peer, &[0x81; 31]);
    wait_ready(&driver, &mut queue, &mut pool).await;
    assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, 8);
    assert_eq!(pool.packets[1].2, vec![0x81; 31]);
}

fn segments(pool: &Pool, packet: &[u8], flags: TxFlags) -> Vec<TxSegment> {
    pool.memory.write_at(128, &packet[..17]).unwrap();
    pool.memory.write_at(1024, &packet[17..]).unwrap();
    vec![
        TxSegment {
            ty: TxSegmentType::Head(TxMetadata {
                id: TxId(19),
                segment_count: 2,
                len: packet.len() as u32,
                flags,
                l2_len: 14,
                l3_len: 20,
                ..Default::default()
            }),
            gpa: 128,
            len: 17,
        },
        TxSegment {
            ty: TxSegmentType::Tail,
            gpa: 1024,
            len: packet.len() as u32 - 17,
        },
    ]
}

// Test: Transmit fragmented guest packets through a real packet socket, with and without IPv4 header checksum offload, and observe synchronous completion.
// Expected: Exactly one complete wire packet per submission has a zero vnet prefix and the exact frame; the known IPv4 checksum is b861, and no deferred TX completions are published.
#[async_test]
async fn tx_fragmentation_and_ipv4_checksum_match_wire_contract(driver: DefaultDriver) {
    let (mut queue, peer) = queue(&driver);
    let mut pool = Pool::new(0);
    for offload in [false, true] {
        let mut frame = vec![0x81; 14 + 115];
        frame[14..34].copy_from_slice(&[
            0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0,
            0xc7,
        ]);
        let input = segments(
            &pool,
            &frame,
            TxFlags::new()
                .with_is_ipv4(true)
                .with_offload_ip_header_checksum(offload),
        );
        assert_eq!(queue.tx_avail(&mut pool, &input).unwrap(), (true, 2));
        let mut wire = vec![0; 4096];
        let length = peer.recv(&mut wire).unwrap();
        if offload {
            frame[24..26].copy_from_slice(&[0xb8, 0x61]);
        }
        assert_eq!(&wire[..length], [vec![0; 12], frame].concat());
        let mut done = [TxId(99)];
        assert_eq!(queue.tx_poll(&mut pool, &mut done).unwrap(), 0);
        assert_eq!(done[0].0, 99);
    }
}

// Test: Fill a nonblocking packet transport, submit one more packet, drain the peer, and transmit again.
// Expected: Backpressure drops the submitted packet with synchronous completion, publishes no extra datagram, and does not prevent a later packet from being sent intact.
#[async_test]
async fn tx_backpressure_drops_synchronously_and_recovers(driver: DefaultDriver) {
    let (mut queue, peer) = queue(&driver);
    let mut pool = Pool::new(0);
    let marker = vec![0xa7; 1024];
    let mut sent = 0;
    loop {
        match queue.tap.as_mut().unwrap().write(&marker) {
            Ok(length) => {
                assert_eq!(length, marker.len());
                sent += 1;
                assert!(sent < 10000);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("unexpected transport write: {error}"),
        }
    }
    let frame = vec![0x39; 64];
    let input = segments(&pool, &frame, TxFlags::new());
    assert_eq!(queue.tx_avail(&mut pool, &input).unwrap(), (true, 2));
    let mut wire = vec![0; 4096];
    for _ in 0..sent {
        let length = peer.recv(&mut wire).unwrap();
        assert_eq!(&wire[..length], marker);
    }
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.recv(&mut wire).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(queue.tx_avail(&mut pool, &input).unwrap(), (true, 2));
    let length = peer.recv(&mut wire).unwrap();
    assert_eq!(&wire[..length], [vec![0; 12], frame].concat());
}
