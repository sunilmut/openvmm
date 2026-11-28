// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::bus::*;
use crate::gpadl::GpadlId;
use crate::gpadl::GpadlMap;
use crate::gpadl_ring::AlignedGpadlView;
use crate::gpadl_ring::GpadlRingMem;
use crate::test_helpers::with_timeout;
use async_trait::async_trait;
use futures::FutureExt;
use futures::StreamExt;
use guestmem::GuestMemory;
use mesh::rpc::RpcSend;
use parking_lot::Mutex;
use std::future::poll_fn;
use test_with_tracing::test;
use vmbus_core::protocol;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmcore::interrupt::Interrupt;

#[derive(Clone, Copy)]
enum Notification {
    OsEvent,
    SlimEvent,
}

#[derive(Clone)]
struct TestBus {
    offers: mesh::Sender<OfferInput>,
    memory: GuestMemory,
    notification: Notification,
}

impl TestBus {
    // Record offers while providing real guest memory for GPADLs.
    fn new(notification: Notification) -> (Self, mesh::Receiver<OfferInput>) {
        let (offers, recv) = mesh::channel();
        (
            Self {
                offers,
                memory: GuestMemory::allocate(16 * 4096),
                notification,
            },
            recv,
        )
    }
}

#[async_trait]
impl ParentBus for TestBus {
    async fn add_child(&self, request: OfferInput) -> anyhow::Result<OfferResources> {
        self.offers.send(request);
        Ok(OfferResources::new(self.memory.clone(), None))
    }

    fn clone_bus(&self) -> Box<dyn ParentBus> {
        Box::new(self.clone())
    }

    fn use_event(&self) -> bool {
        matches!(self.notification, Notification::OsEvent)
    }
}

// Construct a valid open request for two two-page rings in GPADL 7.
fn open_request() -> OpenRequest {
    OpenRequest::new(
        OpenData {
            target_vp: Some(0),
            ring_offset: 2,
            ring_gpadl_id: GpadlId(7),
            event_flag: 0,
            connection_id: 0,
            user_data: protocol::UserDefinedData::default(),
        },
        Interrupt::null(),
        protocol::FeatureFlags::new(),
        protocol::OfferFlags::new(),
    )
}

// Describe four consecutive pages for a bidirectional ring pair.
fn ring_gpadl() -> GpadlRequest {
    GpadlRequest {
        id: GpadlId(7),
        count: 1,
        buf: vec![16384, 0, 1, 2, 3],
    }
}

// Finish the server side of an offer's revocation, then close its request stream.
// Sender closure is also valid: primary revoke and primary close use it instead
// of an explicit Revoke RPC.
async fn finish_revoke(mut child: OfferInput) {
    if let Ok(request) = child.server_request_recv.recv().await {
        match request {
            ChannelServerRequest::Revoke(rpc) => {
                rpc.complete(());
            }
            ChannelServerRequest::Restore(_) => panic!("unexpected restore during revoke"),
        }
    }
}

// Test: Intersect offered confidential/pinning capabilities with negotiated features.
// Expected: Public and private memories are selected independently for rings and data.
#[test]
fn negotiated_memory_capabilities_select_the_correct_memory() {
    let public = GuestMemory::allocate(4096);
    let private = GuestMemory::allocate(4096);
    public.write_plain(0, &0x11u8).unwrap();
    private.write_plain(0, &0x22u8).unwrap();
    let resources = OfferResources::new(public, Some(private));
    for negotiated in [false, true] {
        for ring in [false, true] {
            for external in [false, true] {
                let mut request = open_request();
                request = OpenRequest::new(
                    request.open_data,
                    request.interrupt,
                    protocol::FeatureFlags::new()
                        .with_confidential_channels(negotiated)
                        .with_gpa_pinning(negotiated),
                    protocol::OfferFlags::new()
                        .with_confidential_ring_buffer(ring)
                        .with_confidential_external_memory(external)
                        .with_require_pinned_external_memory(external),
                );
                assert_eq!(request.is_external_memory_pinned, negotiated && external);
                assert_eq!(
                    resources
                        .guest_memory(&request)
                        .read_plain::<u8>(0)
                        .unwrap(),
                    if negotiated && external { 0x22 } else { 0x11 }
                );
                assert_eq!(
                    resources.ring_memory(&request).read_plain::<u8>(0).unwrap(),
                    if negotiated && ring { 0x22 } else { 0x11 }
                );
            }
        }
    }
}

// Test: Split an aligned GPADL and reject zero/end splits and unaligned ranges.
// Expected: Valid splits preserve page order; rejected splits retain the original view.
#[test]
fn aligned_gpadl_validation_and_splitting_preserve_page_ownership() {
    let map = GpadlMap::new();
    map.add(
        GpadlId(7),
        MultiPagedRangeBuf::from_range_buffer(1, vec![16384, 10, 11, 12, 13]).unwrap(),
    );
    let view = map.clone().view();
    for offset in [0, 4, 5] {
        let aligned = AlignedGpadlView::new(view.map(GpadlId(7)).unwrap()).unwrap();
        assert_eq!(
            aligned.split(offset).err().unwrap().gpns(),
            [10, 11, 12, 13]
        );
    }
    let (left, right) = AlignedGpadlView::new(view.map(GpadlId(7)).unwrap())
        .unwrap()
        .split(2)
        .unwrap_or_else(|_| panic!("valid split rejected"));
    assert_eq!(left.gpns(), [10, 11]);
    assert_eq!(right.gpns(), [12, 13]);
    for (count, buf) in [
        (0, vec![]),
        (1, vec![4095, 0]),
        (1, vec![1u64 << 32 | 4096, 1, 2]),
        (2, vec![4096, 0, 4096, 1]),
    ] {
        map.add(
            GpadlId(8),
            MultiPagedRangeBuf::from_range_buffer(count, buf).unwrap(),
        );
        assert!(AlignedGpadlView::new(view.map(GpadlId(8)).unwrap()).is_err());
    }
}

// Test: Read and write GPADL ring data across its circular page boundary.
// Expected: Data wraps into the same guest page and control words share guest memory.
#[test]
fn gpadl_ring_memory_wraps_data_and_shares_control_words() {
    let memory = GuestMemory::allocate(4 * 4096);
    let map = GpadlMap::new();
    map.add(
        GpadlId(7),
        MultiPagedRangeBuf::from_range_buffer(1, ring_gpadl().buf).unwrap(),
    );
    let view = map.clone().view().map(GpadlId(7)).unwrap();
    let (left, _) = AlignedGpadlView::new(view)
        .unwrap()
        .split(2)
        .unwrap_or_else(|_| panic!("valid split rejected"));
    let ring = GpadlRingMem::new(left, &memory).unwrap();
    assert_eq!(ring.len(), 4096);
    ring.write_at(4092, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        memory.read_plain::<[u8; 4]>(8192 - 4).unwrap(),
        [1, 2, 3, 4]
    );
    assert_eq!(memory.read_plain::<[u8; 4]>(4096).unwrap(), [5, 6, 7, 8]);
    let mut bytes = [0; 8];
    ring.read_at(4092, &mut bytes);
    assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 8]);
    ring.write_aligned(8, &[0x21; 8]);
    ring.read_aligned(8, &mut bytes);
    assert_eq!(bytes, [0x21; 8]);
    ring.control()[0].store(16, Ordering::SeqCst);
    assert_eq!(memory.read_plain::<u32>(0).unwrap(), 16);
}

// Test: Build rings with missing GPADLs, bad splits, and inaccessible guest pages.
// Expected: Each failure reports its specific category rather than constructing rings.
#[test]
fn ring_construction_distinguishes_invalid_layout_and_memory_errors() {
    use crate::gpadl_ring::Error;
    let memory = GuestMemory::allocate(4 * 4096);
    let map = GpadlMap::new();
    let view = map.clone().view();
    let mut data = open_request().open_data;
    assert!(matches!(
        gpadl_ring::make_rings(&memory, &view, &data),
        Err(Error::UnknownGpadlId(_))
    ));
    map.add(
        GpadlId(7),
        MultiPagedRangeBuf::from_range_buffer(1, ring_gpadl().buf).unwrap(),
    );
    for offset in [0, 4] {
        data.ring_offset = offset;
        assert!(matches!(
            gpadl_ring::make_rings(&memory, &view, &data),
            Err(Error::InvalidRingGpadl)
        ));
    }
    data.ring_offset = 2;
    map.add(
        GpadlId(7),
        MultiPagedRangeBuf::from_range_buffer(1, vec![16384, 10, 11, 12, 13]).unwrap(),
    );
    assert!(matches!(
        gpadl_ring::make_rings(&memory, &view, &data),
        Err(Error::Memory(_))
    ));
}

// Test: Send in-process channel notifications and close either endpoint.
// Expected: Signals reach the peer; guest closure is reported without a missed wake.
#[test]
fn connected_channels_deliver_signals_and_report_guest_closure() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (host, guest) = connected_async_channels(4096);
        assert!(
            poll_fn(|cx| host.signal.poll_for_signal(cx))
                .now_or_never()
                .is_none()
        );
        guest.signal.signal_remote();
        assert!(poll_fn(|cx| host.signal.poll_for_signal(cx)).await.is_ok());
        host.signal.signal_remote();
        assert!(poll_fn(|cx| guest.signal.poll_for_signal(cx)).await.is_ok());
        drop(guest);
        assert!(poll_fn(|cx| host.signal.poll_for_signal(cx)).await.is_err());
        let (host, guest) = connected_async_channels(4096);
        drop(host);
        assert!(
            poll_fn(|cx| guest.signal.poll_for_signal(cx))
                .now_or_never()
                .is_none()
        );
    }));
}

// Test: Poll a tagged stream while empty, then send data and close its source.
// Expected: Pending preserves the tag and closure emits exactly one terminal sentinel.
#[test]
fn tagged_stream_emits_one_terminal_sentinel_after_pending_and_items() {
    let (send, recv) = mesh::channel::<u32>();
    let mut stream = TaggedStream::new("source", recv);
    assert!(stream.next().now_or_never().is_none());
    send.send(17);
    assert_eq!(
        stream.next().now_or_never(),
        Some(Some(("source", Some(17))))
    );
    drop(send);
    assert_eq!(stream.next().now_or_never(), Some(Some(("source", None))));
    assert_eq!(stream.value(), None);
    assert_eq!(stream.next().now_or_never(), Some(None));
    assert_eq!(stream.next().now_or_never(), Some(None));
}

mod cancellation;
mod consumers;
mod lifecycle;
mod offer;
mod simple;
