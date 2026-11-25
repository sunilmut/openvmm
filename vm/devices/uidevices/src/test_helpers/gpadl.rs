// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use guestmem::GuestMemory;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::connected_async_channels;
use vmbus_channel::gpadl::{GpadlId, GpadlMap};
use vmbus_channel::gpadl_ring::{AlignedGpadlView, GpadlRingMem};
use vmbus_channel::simple::SimpleVmbusDevice;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmbus_ring::{IncomingRing, OutgoingRing};

// Pair real guest-backed rings with the existing in-process channel notifications.
pub fn connected_gpadl_channels() -> (
    RawAsyncChannel<GpadlRingMem>,
    RawAsyncChannel<GpadlRingMem>,
    GuestMemory,
) {
    let memory = GuestMemory::allocate(8 * 4096);
    let map = GpadlMap::new();
    for (id, first_page) in [(1, 0), (2, 4)] {
        let mut range = vec![4 * 4096];
        range.extend(first_page..first_page + 4);
        map.add(
            GpadlId(id),
            MultiPagedRangeBuf::from_range_buffer(1, range).unwrap(),
        );
    }
    let map = map.view();
    let ring = |id| {
        GpadlRingMem::new(
            AlignedGpadlView::new(map.map(GpadlId(id)).unwrap()).unwrap(),
            &memory,
        )
        .unwrap()
    };
    let (host, guest) = connected_async_channels(3 * 4096);
    let host = RawAsyncChannel {
        in_ring: IncomingRing::new(ring(1)).unwrap(),
        out_ring: OutgoingRing::new(ring(2)).unwrap(),
        signal: host.signal,
    };
    let guest = RawAsyncChannel {
        in_ring: IncomingRing::new(ring(2)).unwrap(),
        out_ring: OutgoingRing::new(ring(1)).unwrap(),
        signal: guest.signal,
    };
    (host, guest, memory)
}

pub struct DeviceWorker<D: SimpleVmbusDevice> {
    pub device: D,
    pub channel: D::Runner,
}

impl<D: SimpleVmbusDevice> task_control::AsyncRun<()> for DeviceWorker<D> {
    async fn run(
        &mut self,
        stop: &mut task_control::StopTask<'_>,
        _: &mut (),
    ) -> Result<(), task_control::Cancelled> {
        self.device.run(stop, &mut self.channel).await
    }
}
