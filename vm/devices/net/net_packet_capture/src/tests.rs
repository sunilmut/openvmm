// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::future::Either;
use guestmem::GuestMemory;
use net_backend::TxMetadata;
use net_backend::TxSegmentType;
use net_backend::loopback::LoopbackEndpoint;
use net_backend::tests::Bufs;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pcap_file::pcapng::Block;
use pcap_file::pcapng::PcapNgReader;
use std::io;
use std::io::Cursor;
use test_with_tracing::test;

#[derive(Clone, Debug, Default)]
struct Capture(Arc<parking_lot::Mutex<Output>>);

#[derive(Debug, Default)]
struct Output {
    bytes: Vec<u8>,
    fail: bool,
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = self.0.lock();
        if output.fail {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        output.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn endpoint() -> (PacketCaptureEndpoint, PacketCaptureEndpointControl) {
    PacketCaptureEndpoint::new(Box::new(LoopbackEndpoint::new()), "capture-test".into())
}

fn start(snaplen: u32, writers: Vec<Capture>) -> PacketCaptureParams<Capture> {
    PacketCaptureParams {
        operation: PacketCaptureOperation::Start,
        op_data: Some(OperationData::OpStartData(StartData { snaplen, writers })),
    }
}

fn stop() -> PacketCaptureParams<Capture> {
    PacketCaptureParams {
        operation: PacketCaptureOperation::Stop,
        op_data: None,
    }
}

// Drive the public endpoint action future while its control request is in flight.
async fn apply(
    endpoint: &mut PacketCaptureEndpoint,
    control: &PacketCaptureEndpointControl,
    params: PacketCaptureParams<Capture>,
) -> (PacketCaptureParams<Capture>, Option<EndpointAction>) {
    let request = Box::pin(control.packet_capture(params));
    let action = Box::pin(endpoint.wait_for_endpoint_action());
    match futures::future::select(request, action).await {
        Either::Left((reply, action)) => (reply.unwrap(), action.now_or_never()),
        Either::Right((action, reply)) => (reply.await.unwrap(), Some(action)),
    }
}

async fn queues(
    endpoint: &mut PacketCaptureEndpoint,
    driver: &DefaultDriver,
) -> Vec<Box<dyn Queue>> {
    let mut queues = Vec::new();
    endpoint
        .get_queues(
            vec![QueueConfig {
                driver: Box::new(driver.clone()),
                enabled_rx_offloads: Default::default(),
            }],
            None,
            &mut queues,
        )
        .await
        .unwrap();
    assert_eq!(queues.len(), 1);
    queues
}

fn packet(gpa: u64, len: u32, id: u32) -> TxSegment {
    TxSegment {
        ty: TxSegmentType::Head(TxMetadata {
            id: TxId(id),
            segment_count: 1,
            flags: Default::default(),
            len,
            l2_len: 0,
            l3_len: 0,
            l4_len: 0,
            transport_header_offset: 0,
            max_segment_size: 0,
            vlan: None,
        }),
        gpa,
        len,
    }
}

// Decode actual output rather than checking the capture object's private state.
fn decode(capture: &Capture) -> (Vec<u32>, Vec<(u32, Vec<u8>)>) {
    let bytes = capture.0.lock().bytes.clone();
    let mut reader = PcapNgReader::new(Cursor::new(bytes)).unwrap();
    let mut interfaces = Vec::new();
    let mut packets = Vec::new();
    while let Some(block) = reader.next_block() {
        match block.unwrap() {
            Block::InterfaceDescription(interface) => {
                assert_eq!(interface.linktype, DataLink::ETHERNET);
                interfaces.push(interface.snaplen);
            }
            Block::EnhancedPacket(packet) => {
                assert_eq!(packet.interface_id, 0);
                assert!(packet.timestamp > Duration::ZERO);
                packets.push((packet.original_len, packet.data.into_owned()));
            }
            block => panic!("unexpected capture block: {block:?}"),
        }
    }
    (interfaces, packets)
}

// Test: Query stream requirements and submit incomplete or disconnected control requests.
// Expected: Queries reserve one stream; invalid inputs and a closed endpoint return errors.
#[async_test]
async fn control_validation_and_stream_accounting(_driver: DefaultDriver) {
    let (endpoint, control) = endpoint();
    let query = control
        .packet_capture(PacketCaptureParams::<Capture> {
            operation: PacketCaptureOperation::Query,
            op_data: Some(OperationData::OpQueryData(4)),
        })
        .await
        .unwrap();
    assert!(matches!(query.op_data, Some(OperationData::OpQueryData(5))));
    for operation in [PacketCaptureOperation::Query, PacketCaptureOperation::Start] {
        let error = control
            .packet_capture(PacketCaptureParams::<Capture> {
                operation,
                op_data: None,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Expecting operational data"));
    }
    let error = control
        .packet_capture(start(64, Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Insufficient streams");
    drop(endpoint);
    assert!(control.packet_capture(stop()).await.is_err());
}

// Test: Start, replace and stop a capture while preserving the remaining output streams.
// Expected: Only enable/disable transitions require restart; replaced writers get fresh headers.
#[async_test]
async fn capture_lifecycle_preserves_streams_and_restart_edges(driver: DefaultDriver) {
    let (mut endpoint, control) = endpoint();
    assert!(apply(&mut endpoint, &control, stop()).await.1.is_none());
    let first = Capture::default();
    let second = Capture::default();
    let (reply, action) = apply(
        &mut endpoint,
        &control,
        start(7, vec![first.clone(), second.clone()]),
    )
    .await;
    assert!(matches!(action, Some(EndpointAction::RestartRequired)));
    let Some(OperationData::OpStartData(remaining)) = reply.op_data else {
        panic!("start lost its remaining streams");
    };
    assert_eq!(remaining.writers.len(), 1);
    let memory = GuestMemory::allocate(16384);
    memory.write_at(8192, b"packet").unwrap();
    let mut pool = Bufs::new(memory);
    let mut queues = queues(&mut endpoint, &driver).await;
    let queue = &mut queues[0];
    queue.rx_avail(&mut pool, &[RxId(0), RxId(1), RxId(2)]);
    queue.tx_avail(&mut pool, &[packet(8192, 6, 1)]).unwrap();
    assert_eq!(decode(&first), (vec![7], vec![(6, b"packet".to_vec())]));
    let (_, action) = apply(&mut endpoint, &control, start(3, remaining.writers)).await;
    assert!(action.is_none());
    queue.tx_avail(&mut pool, &[packet(8192, 6, 2)]).unwrap();
    assert_eq!(decode(&second), (vec![3], vec![(6, b"pac".to_vec())]));
    assert!(matches!(
        apply(&mut endpoint, &control, stop()).await.1,
        Some(EndpointAction::RestartRequired)
    ));
    queue.tx_avail(&mut pool, &[packet(8192, 6, 3)]).unwrap();
    assert_eq!(decode(&second).1.len(), 1);
    drop(queues);
    endpoint.stop().await;
}

// Test: Capture scattered transmit packets with zero, shorter and longer snapshot limits.
// Expected: PCAP records contain only each packet's captured prefix and retain original lengths.
#[async_test]
async fn transmit_snapshots_preserve_scatter_order_and_packet_boundaries(driver: DefaultDriver) {
    for snaplen in [0, 3, 6, 12] {
        let (mut endpoint, control) = endpoint();
        let capture = Capture::default();
        apply(
            &mut endpoint,
            &control,
            start(snaplen, vec![capture.clone()]),
        )
        .await;
        let memory = GuestMemory::allocate(16384);
        memory.write_at(8192, b"abc").unwrap();
        memory.write_at(9000, b"def").unwrap();
        let mut pool = Bufs::new(memory);
        let mut head = packet(8192, 6, 1);
        head.len = 3;
        let TxSegmentType::Head(metadata) = &mut head.ty else {
            unreachable!();
        };
        metadata.segment_count = 2;
        let segments = [
            packet(0, 0, 0),
            head,
            TxSegment {
                ty: TxSegmentType::Tail,
                gpa: 9000,
                len: 3,
            },
            packet(9000, 3, 2),
        ];
        let mut queues = queues(&mut endpoint, &driver).await;
        let queue = &mut queues[0];
        queue.rx_avail(&mut pool, &[RxId(0), RxId(1), RxId(2)]);
        assert_eq!(queue.tx_avail(&mut pool, &segments).unwrap(), (true, 4));
        let (interfaces, packets) = decode(&capture);
        if snaplen == 0 {
            assert!(interfaces.is_empty());
            assert!(packets.is_empty());
        } else {
            assert_eq!(interfaces, [snaplen]);
            assert_eq!(
                packets,
                [
                    (6, b"abcdef"[..6.min(snaplen as usize)].to_vec()),
                    (3, b"def"[..3.min(snaplen as usize)].to_vec()),
                ]
            );
        }
        drop(queues);
        endpoint.stop().await;
    }
}

// Test: Poll loopback receive buffers with zero, truncated, exact and larger snapshot lengths.
// Expected: RX completion and packet bytes survive capture; full-size original lengths are kept.
#[async_test]
async fn receive_capture_keeps_data_delivery_and_snapshot_lengths(driver: DefaultDriver) {
    for snaplen in [0, 5, 2048, 4096] {
        let (mut endpoint, control) = endpoint();
        let capture = Capture::default();
        apply(
            &mut endpoint,
            &control,
            start(snaplen, vec![capture.clone()]),
        )
        .await;
        let payload = vec![0x5a; 2048];
        let memory = GuestMemory::allocate(16384);
        memory.write_at(8192, &payload).unwrap();
        let mut pool = Bufs::new(memory);
        let mut queues = queues(&mut endpoint, &driver).await;
        let queue = &mut queues[0];
        queue.update_target_vp(3).await;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(queue.poll_ready(&mut cx, &mut pool).is_pending());
        queue.rx_avail(&mut pool, &[RxId(0)]);
        assert_eq!(
            queue.tx_avail(&mut pool, &[packet(8192, 2048, 1)]).unwrap(),
            (true, 1)
        );
        assert!(queue.poll_ready(&mut cx, &mut pool).is_ready());
        let mut received = [RxId(99)];
        assert_eq!(queue.rx_poll(&mut pool, &mut received).unwrap(), 1);
        assert_eq!(received[0].0, 0);
        assert_eq!(pool.rx_metadata(RxId(0)).unwrap().len, 2048);
        let mut delivered = vec![0; 2048];
        pool.guest_memory().read_at(0, &mut delivered).unwrap();
        assert_eq!(delivered, payload);
        assert_eq!(queue.tx_poll(&mut pool, &mut [TxId(0)]).unwrap(), 0);
        let (interfaces, packets) = decode(&capture);
        if snaplen == 0 {
            assert!(interfaces.is_empty());
            assert!(packets.is_empty());
        } else {
            assert_eq!(interfaces, [snaplen]);
            assert_eq!(
                packets,
                vec![(2048, payload[..2048.min(snaplen as usize)].to_vec()); 2]
            );
        }
        drop(queues);
        endpoint.stop().await;
    }
}

// Test: Fail the writer during interface creation or after a successful packet record.
// Expected: Packet delivery continues and capture stays disabled even if the writer recovers.
#[async_test]
async fn writer_failure_disables_capture_without_stopping_network_traffic(driver: DefaultDriver) {
    for successful_packets in [0, 1] {
        let (mut endpoint, control) = endpoint();
        let capture = Capture::default();
        apply(&mut endpoint, &control, start(64, vec![capture.clone()])).await;
        let memory = GuestMemory::allocate(16384);
        memory.write_at(8192, b"packet").unwrap();
        let mut pool = Bufs::new(memory);
        let mut queues = queues(&mut endpoint, &driver).await;
        let queue = &mut queues[0];
        queue.rx_avail(&mut pool, &[RxId(0), RxId(1), RxId(2)]);
        if successful_packets == 1 {
            queue.tx_avail(&mut pool, &[packet(8192, 6, 0)]).unwrap();
        }
        capture.0.lock().fail = true;
        assert_eq!(
            queue.tx_avail(&mut pool, &[packet(8192, 6, 1)]).unwrap(),
            (true, 1)
        );
        let before = capture.0.lock().bytes.clone();
        capture.0.lock().fail = false;
        assert_eq!(
            queue.tx_avail(&mut pool, &[packet(8192, 6, 2)]).unwrap(),
            (true, 1)
        );
        assert_eq!(capture.0.lock().bytes, before);
        let mut received = [RxId(99); 3];
        assert_eq!(
            queue.rx_poll(&mut pool, &mut received).unwrap(),
            successful_packets + 2
        );
        assert_eq!(decode(&capture).1.len(), successful_packets);
        apply(&mut endpoint, &control, stop()).await;
        drop(queues);
        endpoint.stop().await;
    }
}

// Test: Use a disabled capture endpoint for ordinary loopback traffic.
// Expected: Its native queue, capabilities and error results remain available without capture.
#[async_test]
async fn disabled_capture_preserves_endpoint_and_queue_contracts(driver: DefaultDriver) {
    let (mut endpoint, _control) = endpoint();
    assert_eq!(endpoint.endpoint_type(), "loopback");
    assert!(endpoint.is_ordered());
    assert!(!endpoint.tx_offload_support().tcp);
    assert_eq!(endpoint.multiqueue_support().indirection_table_size, 64);
    assert!(!endpoint.tx_fast_completions());
    assert_eq!(endpoint.link_speed(), LoopbackEndpoint::new().link_speed());
    assert!(endpoint.set_data_path_to_guest_vf(true).await.is_err());
    assert!(endpoint.get_data_path_to_guest_vf().await.is_err());
    let memory = GuestMemory::allocate(16384);
    memory.write_at(8192, b"plain").unwrap();
    let mut pool = Bufs::new(memory);
    let mut queues = queues(&mut endpoint, &driver).await;
    queues[0].rx_avail(&mut pool, &[RxId(0)]);
    assert_eq!(
        queues[0]
            .tx_avail(&mut pool, &[packet(8192, 5, 1)])
            .unwrap(),
        (true, 1)
    );
    let mut received = [RxId(99)];
    assert_eq!(queues[0].rx_poll(&mut pool, &mut received).unwrap(), 1);
    let mut bytes = [0; 5];
    pool.guest_memory().read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"plain");
    drop(queues);
    endpoint.stop().await;
}

// IGNORED: Capture startup unwraps a failed section-header write. Reproduced
//       unignored with a BrokenPipe writer; production changes are out of scope.
// Test: Fail the output stream before the initial capture section header is written.
// Expected: Starting capture returns an error instead of panicking on writer failure.
#[async_test]
#[ignore = "capture startup panics when the initial writer operation fails"]
async fn initial_writer_failure_is_reported_without_panicking(_driver: DefaultDriver) {
    let (_endpoint, control) = endpoint();
    let capture = Capture::default();
    capture.0.lock().fail = true;
    assert!(
        control
            .packet_capture(start(64, vec![capture]))
            .await
            .is_err()
    );
}

// IGNORED: Stream accounting uses unchecked addition. Reproduced unignored
//       with u32::MAX; production changes are out of scope.
// Test: Query one extra capture stream when the running stream count is already maximal.
// Expected: The query rejects overflow instead of panicking or wrapping the stream count.
#[async_test]
#[ignore = "stream-count query panics or wraps instead of rejecting overflow"]
async fn stream_count_overflow_is_reported_without_panicking(_driver: DefaultDriver) {
    let (_endpoint, control) = endpoint();
    assert!(
        control
            .packet_capture(PacketCaptureParams::<Capture> {
                operation: PacketCaptureOperation::Query,
                op_data: Some(OperationData::OpQueryData(u32::MAX)),
            })
            .await
            .is_err()
    );
}

// IGNORED: RX capture records the posted buffer capacity, including unused bytes,
//       instead of packet length. Reproduced unignored; no production fix here.
// Test: Receive a packet smaller than its posted buffer and decode the resulting capture.
// Expected: RX capture records the six-byte packet, not the entire receive-buffer capacity.
#[async_test]
#[ignore = "RX capture includes unused receive-buffer capacity"]
async fn receive_capture_uses_packet_length_not_buffer_capacity(driver: DefaultDriver) {
    let (mut endpoint, control) = endpoint();
    let capture = Capture::default();
    apply(&mut endpoint, &control, start(4096, vec![capture.clone()])).await;
    let memory = GuestMemory::allocate(16384);
    memory.write_at(8192, b"packet").unwrap();
    let mut pool = Bufs::new(memory);
    let mut queues = queues(&mut endpoint, &driver).await;
    queues[0].rx_avail(&mut pool, &[RxId(0)]);
    queues[0]
        .tx_avail(&mut pool, &[packet(8192, 6, 1)])
        .unwrap();
    assert_eq!(queues[0].rx_poll(&mut pool, &mut [RxId(99)]).unwrap(), 1);
    assert_eq!(decode(&capture).1, vec![(6, b"packet".to_vec()); 2]);
}
