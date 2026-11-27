// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use futures::future::Either;
use pal_async::local::block_with_io;
use pal_async::timer::PolledTimer;
use std::future::Future;
use std::future::poll_fn;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::pin::pin;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use test_with_tracing::test;
use vmbus_async::async_dgram::AsyncRecvExt;

async fn within_timeout<T>(driver: &impl Driver, future: impl Future<Output = T>) -> T {
    let mut timer = PolledTimer::new(driver);
    match futures::future::select(pin!(future), pin!(timer.sleep(Duration::from_secs(5)))).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => panic!("UIO scenario did not complete within five seconds"),
    }
}

fn ring_backing() -> (File, Arc<SparseMapping>) {
    let size = 2 * CONTROL_SIZE + OUT_RING_SIZE + IN_RING_SIZE;
    let file = File::from(sparse_mmap::alloc_shared_memory(size, "uio-ring-test").unwrap());
    let mapping = Arc::new(SparseMapping::new(size).unwrap());
    mapping.map_file(0, size, &file, 0, true).unwrap();
    (file, mapping)
}

// The peer only consumes already-queued packets with interrupts masked.
struct PrequeuedSignal;

impl SignalVmbusChannel for PrequeuedSignal {
    fn signal_remote(&self) {
        panic!("masked peer unexpectedly signaled the host");
    }

    fn poll_for_signal(
        &self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), vmbus_channel::ChannelClosed>> {
        panic!("already-queued peer packet unexpectedly needed a notification");
    }
}

fn peer_channel(mapping: Arc<SparseMapping>) -> RawAsyncChannel<MappedRingMem> {
    RawAsyncChannel {
        in_ring: IncomingRing::new(MappedRingMem {
            mapping: mapping.clone(),
            offset: 0,
            len: OUT_RING_SIZE,
        })
        .unwrap(),
        out_ring: OutgoingRing::new(MappedRingMem {
            mapping,
            offset: CONTROL_SIZE + OUT_RING_SIZE,
            len: IN_RING_SIZE,
        })
        .unwrap(),
        signal: Box::new(PrequeuedSignal),
    }
}

fn socket_signal(driver: &impl Driver) -> (UioSignal, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let fd: OwnedFd = socket.into();
    let file = Arc::new(File::from(fd));
    let wait = PolledWait::new_with_size(driver, file.clone(), 4).unwrap();
    (
        UioSignal {
            file,
            wait: Mutex::new(wait),
        },
        peer,
    )
}

// Test: Read and write circular data at a nonzero mapping offset and update control.
// Expected: Wraps and normalized addresses match independent backing bytes;
//       control and surrounding pages remain separate from ring payload.
#[test]
fn mapped_ring_wraps_without_overwriting_control_or_adjacent_pages() {
    let offset = 2 * CONTROL_SIZE;
    let len = CONTROL_SIZE;
    let size = offset + CONTROL_SIZE + len + CONTROL_SIZE;
    let mapping = Arc::new(SparseMapping::new(size).unwrap());
    mapping.alloc(0, size).unwrap();
    let mut expected = vec![0xa5; size];
    mapping.write_at(0, &expected).unwrap();
    let ring = MappedRingMem {
        mapping: mapping.clone(),
        offset,
        len,
    };

    ring.control()[1].store(29, Ordering::SeqCst);
    expected[offset + 4..offset + 8].copy_from_slice(&29u32.to_ne_bytes());
    ring.write_at(len - 3, b"abcdef");
    expected[offset + CONTROL_SIZE + len - 3..offset + CONTROL_SIZE + len].copy_from_slice(b"abc");
    expected[offset + CONTROL_SIZE..offset + CONTROL_SIZE + 3].copy_from_slice(b"def");
    ring.write_at(len + 17, b"normalized");
    expected[offset + CONTROL_SIZE + 17..offset + CONTROL_SIZE + 27].copy_from_slice(b"normalized");
    let mut actual = vec![0; size];
    mapping.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);

    let payload: Vec<_> = (0..len).map(|index| (index % 251) as u8).collect();
    mapping.write_at(offset + CONTROL_SIZE, &payload).unwrap();
    for start in [17, len - 3, len, len + 17] {
        let mut actual = [0; 9];
        ring.read_at(start, &mut actual);
        let expected: Vec<_> = (0..actual.len())
            .map(|i| payload[(start + i) % len])
            .collect();
        assert_eq!(actual.as_slice(), expected);
    }
    assert_eq!(ring.control()[1].load(Ordering::SeqCst), 29);
}

// Test: Open a message pipe over a shared file and exchange distinct peer packets.
// Expected: Each direction reaches the opposite ring with unchanged message
//       boundaries and payload, proving both mappings use the correct offsets.
#[test]
fn mapped_message_pipe_exchanges_packets_in_both_directions() {
    block_with_io(async |driver| {
        within_timeout(&driver, async {
            let (file, mapping) = ring_backing();
            let mut local = message_pipe(&driver, file).unwrap();
            let mut peer = MessagePipe::new(peer_channel(mapping)).unwrap();
            local.try_send(b"guest-to-host").unwrap();
            let mut buffer = [0; 64];
            let n = peer.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"guest-to-host");
            peer.try_send(b"host-to-guest-with-different-length")
                .unwrap();
            let n = local.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"host-to-guest-with-different-length");
        })
        .await;
    });
}

// Test: Open a byte pipe over shared rings and read a write in smaller pieces.
// Expected: Partial reads preserve the complete ordered byte stream and the
//       reverse direction remains independent of the first ring's progress.
#[test]
fn mapped_byte_pipe_preserves_partial_reads_and_reverse_traffic() {
    block_with_io(async |driver| {
        within_timeout(&driver, async {
            let (file, mapping) = ring_backing();
            let mut local = byte_pipe(&driver, file).unwrap();
            let mut peer = BytePipe::new(peer_channel(mapping)).unwrap();
            local.write_all(b"partial-stream").await.unwrap();
            let mut prefix = [0; 3];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"par");
            let mut remainder = [0; 11];
            peer.read_exact(&mut remainder).await.unwrap();
            assert_eq!(&remainder, b"tial-stream");
            peer.write_all(b"reply").await.unwrap();
            let mut reply = [0; 5];
            local.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        })
        .await;
    });
}

// Test: Pass a non-mappable descriptor through all three channel entry points.
// Expected: Each preserves a mapping failure rather than returning a channel
//       or misclassifying the failure as a pipe or driver error.
#[test]
fn channel_entry_points_preserve_mapping_failure() {
    block_with_io(async |driver| {
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap()
        };
        for result in [
            channel(&driver, open()).map(|_| ()),
            byte_pipe(&driver, open()).map(|_| ()),
            message_pipe(&driver, open()).map(|_| ()),
        ] {
            match result {
                Err(Error(ErrorInner::Mmap(error))) => assert!(error.raw_os_error().is_some()),
                Err(error) => panic!("incorrect channel error: {error:?}"),
                Ok(()) => panic!("non-mappable descriptor produced a channel"),
            }
        }
    });
}

// Test: Discover a freshly generated instance that has no sysfs UIO entry.
// Expected: The API returns a discovery error retaining NotFound, rather
//       than attempting to open an unrelated device or reporting pipe failure.
#[test]
fn missing_instance_preserves_discovery_error() {
    let instance = Guid::new_random();
    assert!(
        !Path::new(&format!("/sys/bus/vmbus/devices/{instance}/uio")).exists(),
        "test instance unexpectedly exists"
    );
    match open_uio_device(&instance) {
        Err(Error(ErrorInner::Exist(error))) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
        Err(error) => panic!("incorrect discovery error: {error:?}"),
        Ok(_) => panic!("missing instance produced a device"),
    }
}

// Test: Send an outbound notification and queue two inbound four-byte signals.
// Expected: The outbound value is exactly one u32; each wait consumes just
//       one inbound signal, and the drained descriptor returns Pending.
#[test]
fn uio_signal_uses_four_byte_notifications_and_consumes_one_at_a_time() {
    block_with_io(async |driver| {
        within_timeout(&driver, async {
            let (signal, mut peer) = socket_signal(&driver);
            signal.signal_remote();
            let mut outbound = [0; 4];
            peer.read_exact(&mut outbound).unwrap();
            assert_eq!(outbound, 1u32.to_ne_bytes());
            peer.write_all(&[3u32.to_ne_bytes(), 9u32.to_ne_bytes()].concat())
                .unwrap();
            assert!(poll_fn(|cx| signal.poll_for_signal(cx)).await.is_ok());
            assert!(poll_fn(|cx| signal.poll_for_signal(cx)).await.is_ok());
            poll_fn(|cx| {
                assert!(signal.poll_for_signal(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        })
        .await;
    });
}

// Test: Poll a descriptor that reports readiness but fails when read.
// Expected: Unexpected transport failure becomes ChannelClosed without
//       requiring discoverable UIO identifiers or a real revoked device.
#[test]
fn unexpected_signal_read_failure_closes_the_channel() {
    block_with_io(async |driver| {
        within_timeout(&driver, async {
            let file = Arc::new(File::open("/").unwrap());
            let wait = PolledWait::new_with_size(&driver, file.clone(), 4).unwrap();
            let signal = UioSignal {
                file,
                wait: Mutex::new(wait),
            };
            assert!(poll_fn(|cx| signal.poll_for_signal(cx)).await.is_err());
        })
        .await;
    });
}
