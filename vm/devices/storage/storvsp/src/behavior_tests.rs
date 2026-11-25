// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::state;
use crate::*;
use futures::StreamExt;
use mesh::rpc::RpcSend;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::task::{Spawn, Task};
use vmbus_channel::bus::{
    ChannelRequest, ChannelServerRequest, GpadlRequest, OfferInput, OfferResources, OpenData,
    ParentBus, RestoreResult, RestoredGpadl,
};
use vmbus_channel::channel::{ChannelHandle, offer_channel};
use vmbus_channel::gpadl::GpadlMap;
use vmbus_channel::gpadl_ring::{GpadlRingMem, make_rings};
use vmbus_core::protocol::GpadlId;
use vmcore::interrupt::Interrupt;
use vmcore::notify::{Notify, PolledNotify};
use vmcore::slim_event::SlimEvent;
use vmcore::vm_task::SingleDriverBackend;

#[path = "resolver_behavior.rs"]
mod resolver_behavior;

#[path = "backend_behavior.rs"]
mod backend_behavior;

// Test: Request too many subchannels, retry within the limit and request them
//       both during initialization and after the controller is ready.
// Expected: Invalid counts fail, valid counts succeed and initialization
//       rejects a second creation request without preventing normal I/O.
#[async_test]
async fn subchannel_limits_allow_retry_and_ready_reconfiguration(driver: DefaultDriver) {
    use storvsp_protocol::{NtStatus, Operation};
    for during_initialization in [true, false] {
        let fixture = Fixture::new(&driver, &controller(), GuestMemory::allocate(65536)).await;
        let mut guest = fixture.open(&driver).await;
        for step in 0..3 {
            guest.negotiate_step(step).await;
        }
        if !during_initialization {
            guest.negotiate_step(3).await;
        }
        for (count, expected) in [(3u16, NtStatus::INVALID_PARAMETER), (2, NtStatus::SUCCESS)] {
            assert_eq!(
                guest
                    .exchange(Operation::CREATE_SUB_CHANNELS, count.as_bytes())
                    .await
                    .0
                    .status,
                expected
            );
        }
        if during_initialization {
            assert_eq!(
                guest
                    .exchange(Operation::CREATE_SUB_CHANNELS, 1u16.as_bytes())
                    .await
                    .0
                    .status,
                NtStatus::INVALID_DEVICE_STATE
            );
            guest.negotiate_step(3).await;
        }
        assert_eq!(
            guest
                .exchange(Operation::CREATE_SUB_CHANNELS, 1u16.as_bytes())
                .await
                .0
                .status,
            NtStatus::SUCCESS
        );
        assert_eq!(
            guest.exchange(Operation::RESET_BUS, &[]).await.0.status,
            NtStatus::SUCCESS
        );
        drop(guest);
        fixture.finish().await;
    }
}

async fn bounded<T>(driver: &DefaultDriver, operation: impl Future<Output = T>) -> T {
    let mut timer = pal_async::timer::PolledTimer::new(driver);
    match futures::future::select(
        std::pin::pin!(operation),
        std::pin::pin!(timer.sleep(std::time::Duration::from_secs(5))),
    )
    .await
    {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right(_) => panic!("storage test operation timed out"),
    }
}

struct Offer {
    send: mesh::Sender<ChannelRequest>,
    signal: Interrupt,
    plan: Arc<Mutex<Option<RestoreResult>>>,
    task: Task<()>,
}

#[derive(Clone)]
struct Bus {
    memory: GuestMemory,
    offers: Arc<Mutex<Vec<Offer>>>,
    driver: DefaultDriver,
}

#[async_trait]
impl ParentBus for Bus {
    async fn add_child(&self, request: OfferInput) -> anyhow::Result<OfferResources> {
        let plan = Arc::new(Mutex::new(None::<RestoreResult>));
        let restore_plan = plan.clone();
        let mut receive = request.server_request_recv;
        let task = self.driver.spawn("storvsp-test-bus", async move {
            while let Some(request) = receive.next().await {
                match request {
                    ChannelServerRequest::Restore(rpc) => {
                        rpc.handle_failable(async |open| {
                            let result = if open {
                                restore_plan
                                    .lock()
                                    .take()
                                    .expect("missing open restore plan")
                            } else {
                                RestoreResult {
                                    open_request: None,
                                    gpadls: Vec::new(),
                                }
                            };
                            anyhow::Ok(result)
                        })
                        .await;
                    }
                    ChannelServerRequest::Revoke(rpc) => {
                        rpc.complete(());
                        break;
                    }
                }
            }
        });
        self.offers.lock().push(Offer {
            send: request.request_send,
            signal: request.event,
            plan,
            task,
        });
        Ok(OfferResources::new(self.memory.clone(), None))
    }

    fn clone_bus(&self) -> Box<dyn ParentBus> {
        Box::new(self.clone())
    }
    fn use_event(&self) -> bool {
        false
    }
}

struct GuestSignal {
    host: Interrupt,
    receive: PolledNotify,
}
impl vmbus_channel::SignalVmbusChannel for GuestSignal {
    fn signal_remote(&self) {
        self.host.deliver();
    }
    fn poll_for_signal(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), vmbus_channel::ChannelClosed>> {
        self.receive.poll_wait(cx).map(Ok)
    }
}

struct Guest {
    queue: Queue<GpadlRingMem>,
    transaction: u64,
    driver: DefaultDriver,
}

impl Guest {
    async fn completion(&mut self, transaction_id: u64) -> (storvsp_protocol::Packet, Vec<u8>) {
        let (mut reader, _) = self.queue.split();
        let packet = bounded(&self.driver, reader.read()).await.unwrap();
        let IncomingPacket::Completion(packet) = &*packet else {
            panic!("expected completion");
        };
        assert_eq!(packet.transaction_id(), transaction_id);
        let mut reader = packet.reader();
        let header: storvsp_protocol::Packet = reader.read_plain().unwrap();
        assert_eq!(header.operation, storvsp_protocol::Operation::COMPLETE_IO);
        let mut payload = vec![0; reader.len()];
        reader.read(&mut payload).unwrap();
        (header, payload)
    }

    async fn scsi(
        &mut self,
        request: &storvsp_protocol::ScsiRequest,
        length: usize,
    ) -> (storvsp_protocol::Packet, storvsp_protocol::ScsiRequest) {
        let transaction_id = self.submit_scsi(request, length).await;
        let (header, payload) = self.completion(transaction_id).await;
        let response = storvsp_protocol::ScsiRequest::read_from_prefix(&payload)
            .unwrap()
            .0;
        (header, response)
    }

    async fn submit_scsi(&mut self, request: &storvsp_protocol::ScsiRequest, length: usize) -> u64 {
        let header = storvsp_protocol::Packet {
            operation: storvsp_protocol::Operation::EXECUTE_SRB,
            flags: 0,
            status: storvsp_protocol::NtStatus::SUCCESS,
        };
        let ranges: Vec<_> = (length != 0)
            .then(|| PagedRange::new(0, length, &[8]).unwrap())
            .into_iter()
            .collect();
        let packet_type = if ranges.is_empty() {
            OutgoingPacketType::InBandWithCompletion
        } else {
            OutgoingPacketType::GpaDirect(&ranges)
        };
        let transaction_id = self.transaction;
        self.transaction += 1;
        self.queue
            .split()
            .1
            .write(OutgoingPacket {
                packet_type,
                transaction_id,
                payload: &[header.as_bytes(), request.as_bytes()],
            })
            .await
            .unwrap();
        transaction_id
    }

    async fn exchange(
        &mut self,
        operation: storvsp_protocol::Operation,
        payload: &[u8],
    ) -> (storvsp_protocol::Packet, Vec<u8>) {
        let header = storvsp_protocol::Packet {
            operation,
            flags: 0,
            status: storvsp_protocol::NtStatus::SUCCESS,
        };
        let transaction_id = self.transaction;
        self.transaction += 1;
        self.queue
            .split()
            .1
            .write(OutgoingPacket {
                packet_type: OutgoingPacketType::InBandWithCompletion,
                transaction_id,
                payload: &[header.as_bytes(), payload],
            })
            .await
            .unwrap();
        self.completion(transaction_id).await
    }

    async fn negotiate_step(&mut self, phase: usize) {
        use storvsp_protocol::Operation;
        let version = storvsp_protocol::ProtocolVersion {
            major_minor: storvsp_protocol::VERSION_BLUE,
            reserved: 0,
        };
        let (operation, payload) = match phase {
            0 => (Operation::BEGIN_INITIALIZATION, &[][..]),
            1 => (Operation::QUERY_PROTOCOL_VERSION, version.as_bytes()),
            2 => (Operation::QUERY_PROPERTIES, &[][..]),
            3 => (Operation::END_INITIALIZATION, &[][..]),
            _ => panic!("invalid negotiation phase"),
        };
        assert_eq!(
            self.exchange(operation, payload).await.0.status,
            storvsp_protocol::NtStatus::SUCCESS
        );
    }
}

struct Fixture {
    bus: Bus,
    handle: ChannelHandle<StorageDevice>,
}

impl Fixture {
    async fn new(driver: &DefaultDriver, controller: &ScsiController, memory: GuestMemory) -> Self {
        let bus = Bus {
            memory,
            offers: Default::default(),
            driver: driver.clone(),
        };
        let device = StorageDevice::build_scsi(
            &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
            controller,
            Guid::new_random(),
            2,
            4,
        );
        let handle = offer_channel(driver, &bus, device).await.unwrap();
        Self { bus, handle }
    }

    fn channel(&self) -> (mesh::Sender<ChannelRequest>, Interrupt) {
        let offers = self.bus.offers.lock();
        (offers[0].send.clone(), offers[0].signal.clone())
    }

    fn rings(&self, driver: &DefaultDriver) -> (Guest, OpenRequest, GpadlRequest) {
        let notify = Notify::from_slim_event(Arc::new(SlimEvent::new()));
        let open = OpenRequest {
            open_data: OpenData {
                target_vp: Some(0),
                ring_offset: 4,
                ring_gpadl_id: GpadlId(1),
                event_flag: 0,
                connection_id: 0,
                user_data: UserDefinedData::new_zeroed(),
            },
            interrupt: notify.clone().interrupt(),
            use_confidential_ring: false,
            use_confidential_external_memory: false,
            is_external_memory_pinned: false,
        };
        let request = GpadlRequest {
            id: GpadlId(1),
            count: 1,
            buf: std::iter::once(32768).chain(0..8).collect(),
        };
        let guest_map = GpadlMap::new();
        let pages = std::iter::once(32768).chain(4..8).chain(0..4).collect();
        guest_map.add(
            GpadlId(1),
            MultiPagedRangeBuf::from_range_buffer(1, pages).unwrap(),
        );
        let (in_ring, out_ring) =
            make_rings(&self.bus.memory, &guest_map.view(), &open.open_data).unwrap();
        let guest = Guest {
            queue: Queue::new(RawAsyncChannel {
                in_ring,
                out_ring,
                signal: Box::new(GuestSignal {
                    host: self.channel().1,
                    receive: notify.pollable(driver).unwrap(),
                }),
            })
            .unwrap(),
            transaction: 100,
            driver: driver.clone(),
        };
        (guest, open, request)
    }

    async fn open(&self, driver: &DefaultDriver) -> Guest {
        let (guest, open, gpadl) = self.rings(driver);
        self.handle.start();
        let send = self.channel().0;
        assert!(send.call(ChannelRequest::Gpadl, gpadl).await.unwrap());
        assert!(send.call(ChannelRequest::Open, open).await.unwrap());
        guest
    }

    async fn finish(self) {
        bounded(&self.bus.driver, self.handle.stop()).await;
        let tasks: Vec<_> = std::mem::take(&mut *self.bus.offers.lock())
            .into_iter()
            .map(|offer| offer.task)
            .collect();
        bounded(&self.bus.driver, self.handle.revoke())
            .await
            .unwrap();
        for task in tasks {
            bounded(&self.bus.driver, task).await;
        }
    }
}

fn controller() -> ScsiController {
    let controller = ScsiController::new();
    let disk = scsidisk::SimpleScsiDisk::new(
        disklayer_ram::ram_disk(1024 * 1024, false).unwrap(),
        Default::default(),
    );
    controller
        .attach(ScsiPath::default(), ScsiControllerDisk::new(Arc::new(disk)))
        .unwrap();
    controller
}

// Test: Save and restore an open channel at every protocol negotiation boundary.
// Expected: A fresh device resumes the next guest exchange and reaches ready
//       without restarting negotiation or losing its configured disks.
#[async_test]
async fn snapshots_resume_each_negotiation_phase(driver: DefaultDriver) {
    for phase in 0..=4 {
        let memory = GuestMemory::allocate(65536);
        let controller = controller();
        let original = Fixture::new(&driver, &controller, memory.clone()).await;
        let mut guest = original.open(&driver).await;
        for step in 0..phase {
            guest.negotiate_step(step).await;
        }
        original.handle.stop().await;
        let saved = original.handle.save().await.unwrap().unwrap();
        drop(guest);
        original.finish().await;
        let restored = Fixture::new(&driver, &controller, memory).await;
        let (mut guest, open, request) = restored.rings(&driver);
        *restored.bus.offers.lock()[0].plan.lock() = Some(RestoreResult {
            open_request: Some(open),
            gpadls: vec![RestoredGpadl {
                request,
                accepted: true,
            }],
        });
        restored.handle.restore(saved).await.unwrap();
        restored.handle.start();
        for step in phase..4 {
            guest.negotiate_step(step).await;
        }
        let (reply, _) = guest
            .exchange(storvsp_protocol::Operation::RESET_BUS, &[])
            .await;
        assert_eq!(reply.status, storvsp_protocol::NtStatus::SUCCESS);
        drop(guest);
        restored.finish().await;
    }
}

// Test: Restore malformed snapshots with invalid channel counts and versions.
// Expected: Restore rejects each invalid input with an error before opening rings.
#[async_test]
async fn malformed_snapshots_reject_channel_counts_and_versions(driver: DefaultDriver) {
    for (count, protocol_state) in [
        (0, state::ProtocolState::Init(state::InitState::Begin)),
        (4, state::ProtocolState::Init(state::InitState::Begin)),
        (
            2,
            state::ProtocolState::Init(state::InitState::QueryVersion),
        ),
        (1, state::ProtocolState::Ready { version: 0xffff }),
        (
            1,
            state::ProtocolState::Init(state::InitState::QueryProperties { version: 0xffff }),
        ),
    ] {
        let fixture = Fixture::new(
            &driver,
            &ScsiController::new(),
            GuestMemory::allocate(65536),
        )
        .await;
        let state = state::SavedState {
            protocol_state,
            channels: vec![state::ChannelSavedState { channel: None }; count],
            drives: Vec::new(),
        };
        assert!(
            fixture
                .handle
                .restore(SavedStateBlob::new(state))
                .await
                .is_err()
        );
        fixture.finish().await;
    }
}

fn inquiry(lun: u8) -> storvsp_protocol::ScsiRequest {
    let mut request = storvsp_protocol::ScsiRequest::new_zeroed();
    request.length = storvsp_protocol::SCSI_REQUEST_LEN_V2 as u16;
    request.lun = lun;
    request.cdb_length = 6;
    request.data_in = 1;
    request.data_transfer_length = 96;
    request.payload[0] = ScsiOp::INQUIRY.0;
    request.payload[4] = 96;
    request
}

// Test: Enumerate absent LUNs using guest INQUIRY commands.
// Expected: The wire reply identifies an absent device, nonzero LUNs omit vendor
//       identity, and malformed directions, lengths and VPD requests fail.
#[async_test]
async fn absent_lun_inquiry_reports_identity_and_validates_cdb(driver: DefaultDriver) {
    let fixture = Fixture::new(
        &driver,
        &ScsiController::new(),
        GuestMemory::allocate(65536),
    )
    .await;
    let mut guest = fixture.open(&driver).await;
    for step in 0..4 {
        guest.negotiate_step(step).await;
    }
    for lun in [0, 3] {
        let (header, response) = guest.scsi(&inquiry(lun), 96).await;
        assert_eq!(header.status, storvsp_protocol::NtStatus::SUCCESS);
        assert_eq!(response.srb_status.status(), SrbStatus::SUCCESS);
        let mut data = [0; 96];
        fixture.bus.memory.read_at(32768, &mut data).unwrap();
        assert_eq!(data[0], 0x7f);
        if lun == 0 {
            assert_ne!(&data[8..36], &[0; 28]);
        } else {
            assert_eq!(&data[8..36], &[0; 28]);
        }
    }
    for (direction, allocation, flags, page, external_len) in [
        (0, 96, 0, 0, 96),
        (1, 1, 0, 0, 96),
        (1, 96, 1, 0, 96),
        (1, 96, 0, 1, 96),
        (1, 96, 0, 0, 8),
    ] {
        let mut request = inquiry(3);
        request.data_in = direction;
        request.payload[4] = allocation;
        request.payload[1] = flags;
        request.payload[2] = page;
        request.data_transfer_length = external_len as u32;
        let (header, response) = guest.scsi(&request, external_len).await;
        assert_ne!(header.status, storvsp_protocol::NtStatus::SUCCESS);
        assert_eq!(response.srb_status.status(), SrbStatus::INVALID_REQUEST);
        assert!(response.srb_status.autosense_valid());
    }
    drop(guest);
    fixture.finish().await;
}

// Test: Retry unsupported negotiation versions and issue messages out of order.
// Expected: Replies identify version and state errors, and a valid retry can
//       complete negotiation without reopening the channel.
#[async_test]
async fn negotiation_retries_recover_from_version_and_order_errors(driver: DefaultDriver) {
    use storvsp_protocol::{NtStatus, Operation, ProtocolVersion};
    let fixture = Fixture::new(
        &driver,
        &ScsiController::new(),
        GuestMemory::allocate(65536),
    )
    .await;
    let mut guest = fixture.open(&driver).await;
    guest.negotiate_step(0).await;
    assert_eq!(
        guest
            .exchange(Operation::QUERY_PROPERTIES, &[])
            .await
            .0
            .status,
        NtStatus::INVALID_DEVICE_STATE
    );
    let unsupported = ProtocolVersion {
        major_minor: 0xffff,
        reserved: 0,
    };
    assert_eq!(
        guest
            .exchange(Operation::QUERY_PROTOCOL_VERSION, unsupported.as_bytes())
            .await
            .0
            .status,
        NtStatus::REVISION_MISMATCH
    );
    guest.negotiate_step(1).await;
    assert_eq!(
        guest.exchange(Operation::RESET_BUS, &[]).await.0.status,
        NtStatus::INVALID_DEVICE_STATE
    );
    guest.negotiate_step(2).await;
    assert_eq!(
        guest.exchange(Operation::RESET_BUS, &[]).await.0.status,
        NtStatus::INVALID_DEVICE_STATE
    );
    guest.negotiate_step(3).await;
    for operation in [
        Operation::RESET_BUS,
        Operation::RESET_ADAPTER,
        Operation::RESET_LUN,
    ] {
        assert_eq!(
            guest.exchange(operation, &[]).await.0.status,
            NtStatus::SUCCESS
        );
    }
    drop(guest);
    fixture.finish().await;
}

// Test: Restore closed channels at each supported initialization stage.
// Expected: Restore accepts valid versions and subchannel counts, and the next
//       guest request is handled at the restored protocol boundary.
#[async_test]
async fn closed_snapshots_restore_legacy_and_subchannel_protocol_states(driver: DefaultDriver) {
    use storvsp_protocol::{NtStatus, Operation};
    for (protocol_state, channel_count, next_step) in [
        (state::ProtocolState::Init(state::InitState::Begin), 1, 0),
        (
            state::ProtocolState::Init(state::InitState::QueryVersion),
            1,
            1,
        ),
        (
            state::ProtocolState::Init(state::InitState::QueryProperties {
                version: storvsp_protocol::VERSION_WIN6,
            }),
            1,
            2,
        ),
        (
            state::ProtocolState::Init(state::InitState::EndInitialization {
                version: storvsp_protocol::VERSION_WIN7,
                can_create_subchannels: false,
            }),
            1,
            3,
        ),
        (
            state::ProtocolState::Init(state::InitState::EndInitialization {
                version: storvsp_protocol::VERSION_WIN8,
                can_create_subchannels: false,
            }),
            3,
            3,
        ),
        (
            state::ProtocolState::Ready {
                version: storvsp_protocol::VERSION_BLUE,
            },
            3,
            4,
        ),
    ] {
        let fixture = Fixture::new(
            &driver,
            &ScsiController::new(),
            GuestMemory::allocate(65536),
        )
        .await;
        let state = state::SavedState {
            protocol_state,
            channels: vec![state::ChannelSavedState { channel: None }; channel_count],
            drives: Vec::new(),
        };
        fixture
            .handle
            .restore(SavedStateBlob::new(state))
            .await
            .unwrap();
        let mut guest = fixture.open(&driver).await;
        for step in next_step..4 {
            guest.negotiate_step(step).await;
        }
        assert_eq!(
            guest.exchange(Operation::RESET_BUS, &[]).await.0.status,
            NtStatus::SUCCESS
        );
        drop(guest);
        fixture.finish().await;
    }
}

// Test: Read through the performance-test guest helper with multiple queued reads.
// Expected: Every read receives a successful storage completion without needing
//       a VM, physical disk or product binary.
#[cfg(feature = "ioperf")]
#[async_test]
async fn performance_guest_helper_completes_batched_reads(driver: DefaultDriver) {
    let mut tester = ioperf::PerfTester::new(driver).await;
    tester.read(1).await;
    tester.read(8).await;
}

// Test: Retry an absent-LUN inquiry after a direction error on the same channel.
// Expected: The error returns valid fixed sense without transferring data; the
//       successful retry reports only its own result and preserves buffer guards.
#[async_test]
async fn inquiry_error_sense_does_not_leak_into_successful_retry(driver: DefaultDriver) {
    let fixture = Fixture::new(
        &driver,
        &ScsiController::new(),
        GuestMemory::allocate(65536),
    )
    .await;
    let mut guest = fixture.open(&driver).await;
    for step in 0..4 {
        guest.negotiate_step(step).await;
    }
    fixture.bus.memory.write_at(32768, &[0x5a; 128]).unwrap();
    let mut invalid = inquiry(3);
    invalid.data_in = 0;
    let (header, response) = guest.scsi(&invalid, 96).await;
    assert_eq!(header.status, storvsp_protocol::NtStatus::IO_DEVICE_ERROR);
    assert_eq!(response.scsi_status, ScsiStatus::CHECK_CONDITION);
    assert_eq!(response.srb_status.status(), SrbStatus::INVALID_REQUEST);
    assert!(response.srb_status.autosense_valid());
    assert_eq!(response.data_transfer_length, 0);
    // Fixed-format sense: ILLEGAL REQUEST / INVALID FIELD IN CDB.
    assert_eq!(response.payload[0] & 0x7f, 0x70);
    assert_eq!(response.payload[2] & 0x0f, 0x05);
    assert_eq!(&response.payload[12..14], &[0x24, 0]);
    let mut data = [0; 128];
    fixture.bus.memory.read_at(32768, &mut data).unwrap();
    assert_eq!(data, [0x5a; 128]);

    let (header, response) = guest.scsi(&inquiry(3), 96).await;
    assert_eq!(header.status, storvsp_protocol::NtStatus::SUCCESS);
    assert_eq!(response.scsi_status, ScsiStatus::GOOD);
    assert_eq!(response.srb_status.status(), SrbStatus::SUCCESS);
    assert!(!response.srb_status.autosense_valid());
    assert_eq!(response.payload, [0; 20]);
    assert_eq!(response.data_transfer_length, 96);
    fixture.bus.memory.read_at(32768, &mut data).unwrap();
    assert_eq!(data[0], 0x7f);
    assert_eq!(&data[96..], &[0x5a; 32]);
    drop(guest);
    fixture.finish().await;
}
