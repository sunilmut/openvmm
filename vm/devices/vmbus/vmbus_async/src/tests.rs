// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::async_dgram::{AsyncRecvExt, AsyncSendExt};
use crate::pipe::{
    BytePipe, MessagePipe, connected_byte_pipes, connected_message_pipes,
    connected_raw_message_pipes,
};
use crate::queue::{IncomingPacket, OutgoingPacket, Queue, connected_queues};
use futures::{AsyncReadExt, AsyncWriteExt};
use guestmem::MemoryRead;
use pal_async::async_test;
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use test_with_tracing::test;
use vmbus_channel::connected_async_channels;
use vmbus_ring::{OutgoingPacketType, PacketSize, PipeHeader};
use zerocopy::IntoBytes;

// Test: Exchange vectored datagrams through borrowed read and write halves.
// Expected: Fragments form one message, short exact receives fail, and the next
//       complete message remains readable.
#[async_test]
async fn vectored_messages_preserve_boundaries_and_exact_receive_errors() {
    let (mut host, mut guest) = connected_message_pipes(4096);
    let (mut reader, _) = host.split();
    let (_, mut writer) = guest.split();
    let mut borrowed_writer = &mut writer;
    borrowed_writer
        .send_vectored(&[IoSlice::new(b"abc"), IoSlice::new(b"def")])
        .await
        .unwrap();
    let mut first = [0; 2];
    let mut rest = [0; 6];
    let mut borrowed_reader = &mut reader;
    assert_eq!(
        borrowed_reader
            .recv_vectored(&mut [IoSliceMut::new(&mut first), IoSliceMut::new(&mut rest),])
            .await
            .unwrap(),
        6
    );
    assert_eq!(&first, b"ab");
    assert_eq!(&rest, b"cdef\0\0");
    AsyncSendExt::send(&mut borrowed_writer, b"hi")
        .await
        .unwrap();
    assert_eq!(
        AsyncRecvExt::recv_exact(&mut borrowed_reader, &mut [0; 3])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidData
    );
    borrowed_writer.send(b"next").await.unwrap();
    let mut next = [0; 4];
    borrowed_reader.recv_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"next");
}

// Test: Fill a message ring and wait for both space and complete consumption.
// Expected: Nonblocking sends report WouldBlock and readiness resumes after the
//       peer consumes the queued datagram.
#[async_test]
async fn message_backpressure_and_empty_notifications_follow_peer_reads() {
    let (mut host, mut guest) = connected_message_pipes(4096);
    host.wait_write_ready(4000).await.unwrap();
    host.try_send_vectored(&[IoSlice::new(&[0x5a; 2000]), IoSlice::new(&[0x5a; 2000])])
        .unwrap();
    assert_eq!(
        host.try_send(&[1; 100]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    let (_, mut writer) = host.split();
    let mut empty = Box::pin(writer.wait_empty());
    assert!(futures::poll!(&mut empty).is_pending());
    let mut bytes = [0; 4000];
    guest.recv_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [0x5a; 4000]);
    empty.await.unwrap();
    writer.wait_ready(4).await.unwrap();
    writer.try_send(b"tail").unwrap();
    guest.recv_exact(&mut bytes[..4]).await.unwrap();
    assert_eq!(&bytes[..4], b"tail");
}

// Test: Send raw datagrams and retry receiving a framed datagram into a larger buffer.
// Expected: Raw payloads are padded to eight bytes; undersized receives and oversized
//       sends fail without consuming or publishing a partial message.
#[async_test]
async fn raw_padding_and_message_size_errors_are_observable() {
    let (mut host, mut guest) = connected_raw_message_pipes(4096);
    host.wait_write_ready(3).await.unwrap();
    host.try_send(b"abc").unwrap();
    let mut padded = [0xff; 8];
    guest.recv_exact(&mut padded).await.unwrap();
    assert_eq!(&padded, b"abc\0\0\0\0\0");
    host.send(b"12345678").await.unwrap();
    guest.recv_exact(&mut padded).await.unwrap();
    assert_eq!(&padded, b"12345678");

    let (mut host, mut guest) = connected_message_pipes(4096);
    assert!(host.send(&[0; 4096]).await.is_err());
    host.try_send(b"retain").unwrap();
    assert!(guest.recv(&mut [0; 2]).await.is_err());
    let mut bytes = [0; 6];
    guest.recv_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"retain");
}

// Test: Read a byte stream in pieces, close its write half, and continue reading.
// Expected: Partial packets reassemble exactly and EOF remains visible on later reads.
#[async_test]
async fn split_byte_stream_preserves_partial_reads_and_eof() {
    let (mut host, mut guest) = connected_byte_pipes(4096);
    let (mut reader, mut reverse_writer) = BytePipe::split(&mut host);
    let (mut reverse_reader, mut writer) = BytePipe::split(&mut guest);
    writer.write_all(b"abcdefgh").await.unwrap();
    writer.flush().await.unwrap();
    writer.close().await.unwrap();
    let mut first = [0; 3];
    reader.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"abc");
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(&remaining, b"defgh");
    assert_eq!(reader.read(&mut [0; 1]).await.unwrap(), 0);
    reverse_writer.write_all(b"ok").await.unwrap();
    reverse_writer.close().await.unwrap();
    let mut reverse = Vec::new();
    reverse_reader.read_to_end(&mut reverse).await.unwrap();
    assert_eq!(&reverse, b"ok");
}

// Test: Send malformed pipe headers and non-data ring packets to pipe readers.
// Expected: Message and byte readers reject invalid types, truncated payloads,
//       and partial offsets instead of returning fabricated data.
#[async_test]
async fn pipe_readers_reject_malformed_wire_packets() {
    for (typ, header) in [
        (
            OutgoingPacketType::InBandNoCompletion,
            PipeHeader {
                packet_type: 99,
                len: 1,
            },
        ),
        (
            OutgoingPacketType::InBandNoCompletion,
            PipeHeader {
                packet_type: 1,
                len: 4096,
            },
        ),
        (
            OutgoingPacketType::Completion,
            PipeHeader {
                packet_type: 1,
                len: 1,
            },
        ),
    ] {
        let (host, peer) = connected_async_channels(4096);
        let mut host = MessagePipe::new(host).unwrap();
        let mut peer = Queue::new(peer).unwrap();
        peer.split()
            .1
            .write(OutgoingPacket {
                transaction_id: 7,
                packet_type: typ,
                payload: &[header.as_bytes()],
            })
            .await
            .unwrap();
        assert!(host.recv(&mut [0; 16]).await.is_err());
    }
    for (typ, header) in [
        (
            OutgoingPacketType::InBandNoCompletion,
            PipeHeader {
                packet_type: 99,
                len: 1,
            },
        ),
        (
            OutgoingPacketType::InBandNoCompletion,
            PipeHeader {
                packet_type: 1,
                len: 16,
            },
        ),
        (
            OutgoingPacketType::InBandNoCompletion,
            PipeHeader {
                packet_type: vmbus_ring::PIPE_PACKET_TYPE_PARTIAL,
                len: (2 << 16) | 2,
            },
        ),
        (
            OutgoingPacketType::Completion,
            PipeHeader {
                packet_type: 1,
                len: 1,
            },
        ),
    ] {
        let (host, peer) = connected_async_channels(4096);
        let mut host = BytePipe::new(host).unwrap();
        let mut peer = Queue::new(peer).unwrap();
        peer.split()
            .1
            .write(OutgoingPacket {
                transaction_id: 7,
                packet_type: typ,
                payload: &[header.as_bytes()],
            })
            .await
            .unwrap();
        assert!(host.read(&mut [0; 16]).await.is_err());
    }
}

// Test: Close byte streams normally and after a blocked writer loses its peer.
// Expected: Close publishes EOF, flush succeeds, and closing a disconnected full
//       ring succeeds while further writes report ConnectionReset.
#[async_test]
async fn byte_close_handles_normal_and_disconnected_peers() {
    let (mut host, mut guest) = connected_byte_pipes(4096);
    assert_eq!(host.write(&[]).await.unwrap(), 0);
    host.write_all(b"done").await.unwrap();
    host.flush().await.unwrap();
    host.close().await.unwrap();
    let mut bytes = Vec::new();
    guest.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"done");

    let (mut host, guest) = connected_byte_pipes(4096);
    let mut write = host.write_all(&[0; 8192]);
    assert!(futures::poll!(&mut write).is_pending());
    drop(write);
    drop(guest);
    assert_eq!(
        host.write(&[1; 2048]).await.unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
    host.close().await.unwrap();
}

// Test: Batch aligned packets, peek without consuming, and exchange a completion.
// Expected: Packet order, payloads, and transaction IDs survive batching and revert.
#[async_test]
async fn queue_batches_peek_and_completion_roundtrip() {
    let (mut host, mut guest) = connected_queues(4096);
    let (mut reader, mut writer) = host.split();
    assert!(reader.supports_pending_send_size());
    {
        let mut batch = writer.batched();
        assert!(batch.can_write(PacketSize::in_band(8)).unwrap());
        batch
            .try_write_aligned(
                41,
                OutgoingPacketType::InBandWithCompletion,
                &[0x1122334455667788],
            )
            .unwrap();
        batch
            .try_write_aligned(0, OutgoingPacketType::InBandNoCompletion, &[9])
            .unwrap();
    }
    let (mut peer_reader, mut peer_writer) = guest.split();
    {
        let mut peek = peer_reader.try_read().unwrap();
        let IncomingPacket::Data(data) = peek.as_ref() else {
            panic!("expected data")
        };
        assert_eq!(data.transaction_id(), Some(41));
        assert_eq!(
            data.reader().read_plain::<u64>().unwrap(),
            0x1122334455667788
        );
        peek.revert();
    }
    let mut batch = peer_reader.read_batch().await.unwrap();
    let values: Vec<_> = batch
        .packets()
        .map(|packet| {
            let IncomingPacket::Data(data) = packet.unwrap() else {
                panic!("expected data")
            };
            (
                data.transaction_id(),
                data.reader().read_plain::<u64>().unwrap(),
            )
        })
        .collect();
    assert_eq!(values, [(Some(41), 0x1122334455667788), (None, 9)]);
    drop(batch);
    peer_writer
        .write(OutgoingPacket {
            transaction_id: 41,
            packet_type: OutgoingPacketType::Completion,
            payload: &[b"complete"],
        })
        .await
        .unwrap();
    let completion = reader.read().await.unwrap();
    let IncomingPacket::Completion(completion) = &*completion else {
        panic!("expected completion")
    };
    assert_eq!(completion.transaction_id(), 41);
    let mut bytes = [0; 8];
    completion.reader().read(&mut bytes).unwrap();
    assert_eq!(&bytes, b"complete");
}

// Test: Read external descriptors with the wrong API or outside the transfer buffer.
// Expected: Wrong descriptor kinds and out-of-bounds transfers return typed errors.
#[async_test]
async fn queue_transfer_validation_and_empty_external_ranges() {
    use crate::queue::ExternalDataError;
    use guestmem::ranges::PagedRange;
    use vmbus_ring::TransferPageRange;
    use vmbus_ring::gparange::MultiPagedRangeBuf;

    let (mut host, mut guest) = connected_queues(4096);
    host.split()
        .1
        .write(OutgoingPacket {
            transaction_id: 0,
            packet_type: OutgoingPacketType::TransferPages(
                13,
                &[TransferPageRange {
                    byte_count: 16,
                    byte_offset: 4090,
                }],
            ),
            payload: &[],
        })
        .await
        .unwrap();
    let mut read = guest.split().0;
    let packet = read.try_read().unwrap();
    let IncomingPacket::Data(data) = &*packet else {
        panic!("expected data")
    };
    assert_eq!(data.transfer_buffer_id(), Some(13));
    let mut ranges = MultiPagedRangeBuf::new();
    assert!(matches!(
        data.read_external_ranges(&mut ranges),
        Err(ExternalDataError::WrongExternalDataType)
    ));
    assert!(
        data.read_transfer_ranges(PagedRange::new(0, 4096, &[1]).unwrap(), &mut ranges)
            .is_err()
    );
    drop(packet);

    host.split()
        .1
        .write(OutgoingPacket {
            transaction_id: 0,
            packet_type: OutgoingPacketType::InBandNoCompletion,
            payload: &[b"payload!"],
        })
        .await
        .unwrap();
    let packet = read.try_read().unwrap();
    let IncomingPacket::Data(data) = &*packet else {
        panic!("expected data")
    };
    assert_eq!(data.transfer_buffer_id(), None);
    assert_eq!(data.external_range_count(), 0);
    data.read_external_ranges(&mut ranges).unwrap();
    data.read_transfer_ranges(PagedRange::new(0, 4096, &[1]).unwrap(), &mut ranges)
        .unwrap();
    assert_eq!(ranges.iter().count(), 0);
}

// Test: Wait on an empty queue, then disconnect its peer.
// Expected: Pending reads fail with the public closed-channel classification.
#[async_test]
async fn queue_read_reports_peer_closure() {
    let (mut host, guest) = connected_queues(4096);
    let mut reader = host.split().0;
    let mut read = reader.read();
    assert!(futures::poll!(&mut read).is_pending());
    drop(guest);
    let error = match read.await {
        Err(error) => error,
        Ok(_) => panic!("closed queue returned data"),
    };
    assert!(error.is_closed_error());
    assert!(error.to_string().contains("closed"));
}

// Test: Cancel a datagram send blocked by a nearly full ring, then send again.
// Expected: Only committed messages arrive, and a smaller replacement sends normally.
#[async_test]
async fn cancelled_blocked_datagram_does_not_publish_or_block_reuse() {
    let (mut host, mut guest) = connected_message_pipes(4096);
    host.send(&[0x55; 4000]).await.unwrap();
    {
        let cancelled = [0x99; 4000];
        let mut send = host.send(&cancelled);
        assert!(futures::poll!(&mut send).is_pending());
    }

    let mut received = [0; 4000];
    guest.recv_exact(&mut received).await.unwrap();
    assert_eq!(received, [0x55; 4000]);

    // The replacement also crosses the ring end after the initial large packet.
    host.send(&[0x33; 100]).await.unwrap();
    let mut replacement = [0; 100];
    guest.recv_exact(&mut replacement).await.unwrap();
    assert_eq!(replacement, [0x33; 100]);
    let mut extra = [0; 1];
    assert!(futures::poll!(guest.recv(&mut extra)).is_pending());
    let (_, mut writer) = host.split();
    writer.wait_empty().await.unwrap();
}

// Test: Poll both split message halves while a send is blocked and input is empty.
// Expected: Peer progress wakes both tasks; the send completes intact, input
//       remains pending until a peer message arrives, and both directions recover.
#[async_test]
async fn split_message_halves_wake_on_peer_progress() {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (mut host, mut guest) = connected_message_pipes(4096);
    host.send(&[0x51; 4000]).await.unwrap();
    let (mut reader, mut writer) = host.split();
    let read_wakes = Arc::new(WakeCount::default());
    let write_wakes = Arc::new(WakeCount::default());
    let read_waker = Waker::from(read_wakes.clone());
    let write_waker = Waker::from(write_wakes.clone());
    let mut read_cx = Context::from_waker(&read_waker);
    let mut write_cx = Context::from_waker(&write_waker);
    let mut received = [0; 8];
    let mut read = Box::pin(reader.recv_exact(&mut received));
    let mut send = Box::pin(writer.send(&[0xa3; 4000]));
    assert!(send.as_mut().poll(&mut write_cx).is_pending());
    assert!(read.as_mut().poll(&mut read_cx).is_pending());

    let mut payload = [0; 4000];
    guest.recv_exact(&mut payload).await.unwrap();
    assert_eq!(payload, [0x51; 4000]);
    assert!(read_wakes.0.load(Ordering::SeqCst) > 0);
    assert!(write_wakes.0.load(Ordering::SeqCst) > 0);
    send.await.unwrap();
    assert!(read.as_mut().poll(&mut read_cx).is_pending());
    let previous_wakes = read_wakes.0.load(Ordering::SeqCst);
    guest.send(b"response").await.unwrap();
    assert!(read_wakes.0.load(Ordering::SeqCst) > previous_wakes);
    read.await.unwrap();
    assert_eq!(&received, b"response");
    guest.recv_exact(&mut payload).await.unwrap();
    assert_eq!(payload, [0xa3; 4000]);
    writer.wait_empty().await.unwrap();
    writer.send(b"reused").await.unwrap();
    let mut tail = [0; 6];
    guest.recv_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"reused");
}

// Test: Drop a partially consumed queue batch while a replacement write is blocked.
// Expected: Only consumed packets release space; the unread packet survives, the
//       writer resumes after batch drop, and replacement payload and ID are intact.
#[async_test]
async fn queue_batch_drop_releases_only_consumed_packets() {
    let (mut host, mut guest) = connected_queues(4096);
    let mut writer = host.split().1;
    for (id, payload) in [(11, &[0x61; 2000]), (12, &[0x72; 2000])] {
        writer
            .write(OutgoingPacket {
                transaction_id: id,
                packet_type: OutgoingPacketType::InBandWithCompletion,
                payload: &[payload],
            })
            .await
            .unwrap();
    }
    let mut replacement = writer.write(OutgoingPacket {
        transaction_id: 13,
        packet_type: OutgoingPacketType::InBandWithCompletion,
        payload: &[&[0x83; 2000]],
    });
    assert!(futures::poll!(&mut replacement).is_pending());
    let mut bytes = [0; 2000];
    {
        let mut reader = guest.split().0;
        let mut batch = reader.read_batch().await.unwrap();
        let IncomingPacket::Data(first) = batch.packets().next().unwrap().unwrap() else {
            panic!("expected data")
        };
        assert_eq!(first.transaction_id(), Some(11));
        first.reader().read(&mut bytes).unwrap();
        assert_eq!(bytes, [0x61; 2000]);
        assert!(futures::poll!(&mut replacement).is_pending());
    }
    replacement.await.unwrap();
    for (id, expected) in [(12, 0x72), (13, 0x83)] {
        let mut reader = guest.split().0;
        let packet = reader.read().await.unwrap();
        let IncomingPacket::Data(data) = &*packet else {
            panic!("expected data")
        };
        assert_eq!(data.transaction_id(), Some(id));
        data.reader().read(&mut bytes).unwrap();
        assert_eq!(bytes, [expected; 2000]);
    }
    assert!(matches!(
        guest.split().0.try_read(),
        Err(crate::queue::TryReadError::Empty)
    ));
}
