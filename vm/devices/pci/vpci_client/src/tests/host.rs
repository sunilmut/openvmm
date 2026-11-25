// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::{MemoryAccess, VpciClient, VpciDevice, VpciDeviceDescription, VpciDeviceEject};
use guestmem::MemoryRead;
use parking_lot::Mutex;
use vmbus_async::queue::{IncomingPacket, OutgoingPacket, Queue};
use vmbus_ring::{FlatRingMem, OutgoingPacketType};
use vpci_protocol as protocol;
use zerocopy::{FromBytes, IntoBytes};

pub(super) const BASE: u64 = 0x1234_5678_0000;

pub(super) struct MemoryLog {
    pub bytes: Vec<u8>,
    pub writes: Vec<(u64, Vec<u8>)>,
}

pub(super) struct Memory(pub Arc<Mutex<MemoryLog>>);

impl MemoryAccess for Memory {
    fn gpa(&mut self) -> u64 {
        BASE
    }

    fn read(&mut self, address: u64, bytes: &mut [u8]) {
        let offset = (address - BASE - protocol::MMIO_PAGE_CONFIG_SPACE) as usize;
        bytes.copy_from_slice(&self.0.lock().bytes[offset..offset + bytes.len()]);
    }

    fn write(&mut self, address: u64, bytes: &[u8]) {
        let mut log = self.0.lock();
        log.writes.push((address, bytes.to_vec()));
        if address >= BASE + protocol::MMIO_PAGE_CONFIG_SPACE {
            let offset = (address - BASE - protocol::MMIO_PAGE_CONFIG_SPACE) as usize;
            log.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        } else {
            assert_eq!(address, BASE + protocol::MMIO_PAGE_SLOT_NUMBER);
        }
    }
}

// Supply distinct wire identities so routing and config-space tests cannot pass on zeroes.
pub(super) fn description(slot: u32, serial: u32) -> protocol::DeviceDescription2 {
    protocol::DeviceDescription2 {
        pnp_id: protocol::PnpId {
            vendor_id: 0x1234,
            device_id: 0x5678,
            revision_id: 5,
            prog_if: 4,
            sub_class: 3,
            base_class: 2,
            sub_vendor_id: 0x9abc,
            sub_system_id: 0xdef0,
        },
        slot: slot.into(),
        serial_num: serial,
        flags: protocol::DeviceDescription2Flags::new().with_numa_affinity_specified(true),
        numa_node: 7,
        rsvd: 0,
    }
}

pub(super) struct Host {
    pub queue: Queue<FlatRingMem>,
    driver: DefaultDriver,
}

impl Host {
    // Keep host reads bounded so an unexpected client packet cannot hang the suite.
    pub async fn receive(&mut self) -> (Option<u64>, Vec<u8>) {
        let (mut read, _) = self.queue.split();
        let packet = vmbus_channel::test_helpers::with_timeout(&self.driver, read.read())
            .await
            .unwrap();
        let IncomingPacket::Data(packet) = &*packet else {
            panic!("expected a client request");
        };
        let mut reader = packet.reader();
        let mut bytes = vec![0; reader.len()];
        reader.read(&mut bytes).unwrap();
        (packet.transaction_id(), bytes)
    }

    // Check the external request identity before a test supplies its response.
    pub async fn expect(&mut self, kind: protocol::MessageType) -> (u64, Vec<u8>) {
        let (tx, bytes) = self.receive().await;
        assert_eq!(
            protocol::MessageType::read_from_prefix(&bytes).unwrap().0,
            kind
        );
        (tx.unwrap(), bytes)
    }

    // Send raw packets without normalizing malformed lengths or host statuses.
    pub async fn send(&mut self, kind: OutgoingPacketType<'_>, tx: u64, bytes: &[u8]) {
        self.queue
            .split()
            .1
            .write(OutgoingPacket {
                transaction_id: tx,
                packet_type: kind,
                payload: &[bytes],
            })
            .await
            .unwrap();
    }

    pub async fn complete(&mut self, tx: u64, bytes: &[u8]) {
        self.send(OutgoingPacketType::Completion, tx, bytes).await;
    }

    pub async fn relations(&mut self, devices: &[protocol::DeviceDescription2]) {
        let header = protocol::QueryBusRelations2 {
            message_type: protocol::MessageType::BUS_RELATIONS2,
            device_count: devices.len() as u32,
            device: [],
        };
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(devices.as_bytes());
        self.send(OutgoingPacketType::InBandNoCompletion, 0, &bytes)
            .await;
    }

    pub async fn eject(&mut self, slot: u32) {
        self.send(
            OutgoingPacketType::InBandNoCompletion,
            0,
            protocol::PdoMessage {
                message_type: protocol::MessageType::EJECT,
                slot: slot.into(),
            }
            .as_bytes(),
        )
        .await;
    }

    // Initialize through the public device API while checking both host transactions.
    pub async fn init(
        &mut self,
        device: VpciDeviceDescription,
        bars: [u32; 6],
    ) -> (VpciDevice, VpciDeviceEject) {
        let driver = self.driver.clone();
        let init = device.init(
            Arc::new(TdispNoopResourceValidator::new()),
            IsolationType::None,
            Vtl::Vtl0,
        );
        let respond = async {
            let (tx, _) = self
                .expect(protocol::MessageType::CURRENT_RESOURCE_REQUIREMENTS)
                .await;
            self.complete(
                tx,
                protocol::QueryResourceRequirementsReply {
                    status: protocol::Status::SUCCESS,
                    bars,
                }
                .as_bytes(),
            )
            .await;
            let (tx, _) = self.expect(protocol::MessageType::ASSIGNED_RESOURCES).await;
            self.complete(tx, protocol::Status::SUCCESS.as_bytes())
                .await;
        };
        let (result, ()) = vmbus_channel::test_helpers::with_timeout(&driver, async {
            futures::join!(init, respond)
        })
        .await;
        result.unwrap()
    }
}

// Connect a real client worker to an explicitly driven host and observable MMIO interface.
pub(super) async fn connect(
    driver: &DefaultDriver,
    devices: &[protocol::DeviceDescription2],
) -> (
    Host,
    VpciClient,
    Vec<VpciDeviceDescription>,
    mesh::Receiver<VpciDeviceDescription>,
    Arc<Mutex<MemoryLog>>,
) {
    let (host, guest) = vmbus_channel::connected_async_channels(32768);
    let mut host = Host {
        queue: Queue::new(host).unwrap(),
        driver: driver.clone(),
    };
    let log = Arc::new(Mutex::new(MemoryLog {
        bytes: vec![0; 4096],
        writes: Vec::new(),
    }));
    let (send, added) = mesh::channel();
    let connect = VpciClient::connect(driver, guest, Box::new(Memory(log.clone())), send);
    let respond = async {
        let (tx, bytes) = host
            .expect(protocol::MessageType::QUERY_PROTOCOL_VERSION)
            .await;
        let query = protocol::QueryProtocolVersion::read_from_prefix(&bytes)
            .unwrap()
            .0;
        assert_eq!(query.protocol_version, protocol::ProtocolVersion::RB);
        host.complete(tx, protocol::Status::SUCCESS.as_bytes())
            .await;
        let (tx, bytes) = host.expect(protocol::MessageType::FDO_D0_ENTRY).await;
        assert_eq!(
            protocol::FdoD0Entry::read_from_prefix(&bytes)
                .unwrap()
                .0
                .mmio_start,
            BASE
        );
        host.relations(devices).await;
        host.complete(tx, protocol::Status::SUCCESS.as_bytes())
            .await;
    };
    let (client, ()) = vmbus_channel::test_helpers::with_timeout(driver, async {
        futures::join!(connect, respond)
    })
    .await;
    let (client, descriptions) = client.unwrap();
    (host, client, descriptions, added, log)
}
