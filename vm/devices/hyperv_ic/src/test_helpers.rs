// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use hyperv_ic_protocol::Header;
use hyperv_ic_protocol::HeaderFlags;
use hyperv_ic_protocol::MessageType;
use hyperv_ic_protocol::NegotiateMessage;
use hyperv_ic_protocol::Status;
use hyperv_ic_protocol::Version;
use pal_async::DefaultDriver;
use task_control::AsyncRun;
use task_control::Cancelled;
use task_control::StopTask;
use task_control::TaskControl;
use vmbus_async::async_dgram::AsyncRecvExt;
use vmbus_async::async_dgram::AsyncSendExt;
use vmbus_async::pipe::MessagePipe;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::connected_async_channels;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMap;
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_channel::simple::SimpleVmbusDevice;
use vmbus_channel::test_helpers::with_timeout;
use vmbus_ring::IncomingRing;
use vmbus_ring::OutgoingRing;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

pub struct Worker<T: SimpleVmbusDevice> {
    pub device: T,
    pub runner: T::Runner,
}

impl<T: SimpleVmbusDevice + 'static> AsyncRun<()> for Worker<T> {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        self.device.run(stop, &mut self.runner).await
    }
}

pub fn start<T: SimpleVmbusDevice + 'static>(
    driver: &DefaultDriver,
    mut device: T,
) -> (TaskControl<Worker<T>, ()>, Guest) {
    let (host, guest) = channels();
    let runner = device
        .open(host, guestmem::GuestMemory::allocate(4096))
        .unwrap();
    let mut task = TaskControl::new(Worker { device, runner });
    task.insert(driver, "ic-behavior", ());
    assert!(task.start());
    (task, Guest::new(driver, guest))
}

pub fn channels() -> (RawAsyncChannel<GpadlRingMem>, RawAsyncChannel<GpadlRingMem>) {
    let memory = guestmem::GuestMemory::allocate(10 * 4096);
    let map = GpadlMap::new();
    map.add(
        GpadlId(1),
        MultiPagedRangeBuf::from_range_buffer(1, vec![10 * 4096, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
            .unwrap(),
    );
    let rings = AlignedGpadlView::new(map.view().map(GpadlId(1)).unwrap()).unwrap();
    let (host_ring, guest_ring) = rings.split(5).ok().unwrap();
    let (host, guest) = connected_async_channels(16384);
    (
        RawAsyncChannel {
            in_ring: IncomingRing::new(GpadlRingMem::new(host_ring.clone(), &memory).unwrap())
                .unwrap(),
            out_ring: OutgoingRing::new(GpadlRingMem::new(guest_ring.clone(), &memory).unwrap())
                .unwrap(),
            signal: host.signal,
        },
        RawAsyncChannel {
            in_ring: IncomingRing::new(GpadlRingMem::new(guest_ring, &memory).unwrap()).unwrap(),
            out_ring: OutgoingRing::new(GpadlRingMem::new(host_ring, &memory).unwrap()).unwrap(),
            signal: guest.signal,
        },
    )
}

pub fn restore<T: SimpleVmbusDevice + 'static>(
    driver: &DefaultDriver,
    task: &mut TaskControl<Worker<T>, ()>,
) -> Guest {
    let worker = task.task_mut();
    let device = worker.device.supports_save_restore().unwrap();
    let saved = device.save_open(&worker.runner);
    let (host, guest) = channels();
    worker.runner = device.restore_open(saved, host).unwrap();
    Guest::new(driver, guest)
}

pub struct Frame {
    pub header: Header,
    pub body: Vec<u8>,
}

pub struct Guest {
    pub pipe: MessagePipe<GpadlRingMem>,
    driver: DefaultDriver,
}

impl Guest {
    pub fn new(driver: &DefaultDriver, channel: RawAsyncChannel<GpadlRingMem>) -> Self {
        Self {
            pipe: MessagePipe::new(channel).unwrap(),
            driver: driver.clone(),
        }
    }

    pub async fn receive(&mut self, expected: MessageType) -> Frame {
        let mut bytes = vec![0; hyperv_ic_protocol::MAX_MESSAGE_SIZE];
        let len = with_timeout(&self.driver, self.pipe.recv(&mut bytes))
            .await
            .unwrap();
        let (header, body) = Header::read_from_prefix(&bytes[..len]).unwrap();
        assert_eq!(header.message_type, expected);
        assert!(header.flags.transaction());
        assert!(header.flags.request());
        assert_eq!(header.message_size as usize, body.len());
        Frame {
            header,
            body: body.to_vec(),
        }
    }

    pub async fn respond(&mut self, request: &Frame, status: Status, body: &[u8]) {
        let header = Header {
            framework_version: request.header.framework_version,
            message_version: request.header.message_version,
            message_type: request.header.message_type,
            transaction_id: request.header.transaction_id,
            message_size: body.len() as u16,
            status,
            flags: HeaderFlags::new()
                .with_transaction(true)
                .with_response(true),
            ..FromZeros::new_zeroed()
        };
        with_timeout(
            &self.driver,
            self.pipe.send(&[header.as_bytes(), body].concat()),
        )
        .await
        .unwrap();
    }

    pub async fn negotiate(&mut self, version: Version) {
        let offer = self.receive(MessageType::VERSION_NEGOTIATION).await;
        let (counts, table) = NegotiateMessage::read_from_prefix(&offer.body).unwrap();
        let framework_count = counts.framework_version_count as usize;
        let count = framework_count + counts.message_version_count as usize;
        let versions: Vec<_> = table
            .chunks_exact(size_of::<Version>())
            .map(|bytes| Version::read_from_bytes(bytes).unwrap())
            .collect();
        assert_eq!(versions.len(), count);
        assert!(versions[..framework_count].contains(&hyperv_ic_protocol::FRAMEWORK_VERSION_3));
        assert!(versions[framework_count..].contains(&version));
        let counts = NegotiateMessage {
            framework_version_count: 1,
            message_version_count: 1,
            reserved: 0,
        };
        let versions = [hyperv_ic_protocol::FRAMEWORK_VERSION_3, version];
        self.respond(
            &offer,
            Status::SUCCESS,
            &[counts.as_bytes(), versions.as_bytes()].concat(),
        )
        .await;
    }
}
