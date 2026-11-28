// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromZeros;

fn endpoint(
    driver: &DefaultDriver,
    size: u64,
) -> (
    MockVpciGuestDevice,
    Arc<CloseableMutex<NullDevice>>,
    Arc<TestVpciInterruptController>,
) {
    let ids = HardwareIds {
        vendor_id: 0x1234,
        device_id: 0x5678,
        revision_id: 1,
        prog_if: ProgrammingInterface::NONE,
        base_class: ClassCode::BASE_SYSTEM_PERIPHERAL,
        sub_class: Subclass::BASE_SYSTEM_PERIPHERAL_OTHER,
        type0_sub_vendor_id: 0x1234,
        type0_sub_system_id: 1,
    };
    let device = Arc::new(CloseableMutex::new(NullDevice {
        config_space: ConfigSpaceType0Emulator::new(
            ids,
            vec![],
            vec![],
            DeviceBars::new().bar0(size, BarMemoryKind::Dummy),
        ),
    }));
    let controller = TestVpciInterruptController::new();
    (
        connected_device(driver, device.clone(), controller.clone()),
        device,
        controller,
    )
}

async fn exchange(guest: &mut MockVpciGuestDevice, bytes: &[u8]) -> Vec<u8> {
    let id = guest.transaction_id.fetch_add(1, Ordering::Relaxed);
    guest
        .host_queue
        .split()
        .1
        .write(OutgoingPacket {
            transaction_id: id,
            packet_type: OutgoingPacketType::InBandWithCompletion,
            payload: &[bytes],
        })
        .await
        .unwrap();
    let mut read = guest.host_queue.split().0;
    let packet = read.read().await.unwrap();
    let IncomingPacket::Completion(reply) = &*packet else {
        panic!("expected completion")
    };
    assert_eq!(reply.transaction_id(), id);
    reply.reader().read_all().unwrap()
}

async fn status(guest: &mut MockVpciGuestDevice, bytes: &[u8]) -> protocol::Status {
    protocol::Status::read_from_prefix(&exchange(guest, bytes).await)
        .unwrap()
        .0
}

fn pdo(message_type: protocol::MessageType) -> protocol::PdoMessage {
    protocol::PdoMessage {
        message_type,
        slot: SlotNumber::new(),
    }
}

async fn resources(guest: &mut MockVpciGuestDevice) -> protocol::PartialResourceList {
    let msg = protocol::GetResources {
        message_type: protocol::MessageType::GET_RESOURCES,
        slot: SlotNumber::new(),
        reserved: [0; 3],
    };
    protocol::PartialResourceList::read_from_prefix(&exchange(guest, msg.as_bytes()).await)
        .unwrap()
        .0
}

fn memory(address: u64, size: u64) -> protocol::PartialResourceDescriptor {
    let (shift, flags) = if size < 1 << 32 {
        (0, protocol::ResourceFlags::new())
    } else if size < 1 << 40 {
        (8, protocol::ResourceFlags::new().with_large_40(true))
    } else if size < 1 << 48 {
        (16, protocol::ResourceFlags::new().with_large_48(true))
    } else {
        (32, protocol::ResourceFlags::new().with_large_64(true))
    };
    protocol::PartialResourceDescriptor {
        resource_type: if shift == 0 {
            protocol::ResourceType::MEMORY
        } else {
            protocol::ResourceType::MEMORY_LARGE
        },
        share_disposition: 0,
        flags,
        address: address.into(),
        adjusted_len: (size >> shift) as u32,
        padding: 0,
    }
}

fn assignment(message_type: protocol::MessageType, size: u64) -> protocol::DeviceTranslate {
    let mut msg = protocol::DeviceTranslate::new_zeroed();
    msg.message_type = message_type;
    msg.mmio_resources[0] = memory(size * 2, size);
    msg
}

fn descriptor1() -> protocol::MsiResourceDescriptor {
    protocol::MsiResourceDescriptor {
        vector: 0x40,
        delivery_mode: protocol::DeliveryMode::FIXED,
        vector_count: 1,
        reserved: [0; 2],
        processor_mask: 1 << 3,
    }
}
fn descriptor2() -> protocol::MsiResourceDescriptor2 {
    let mut d = protocol::MsiResourceDescriptor2::new_zeroed();
    d.vector = 0x41;
    d.vector_count = 1;
    d.processor_count = 1;
    d.processor_array[0] = 4;
    d.delivery_mode = protocol::DeliveryMode::LOWEST_PRIORITY;
    d
}
fn descriptor3() -> protocol::MsiResourceDescriptor3 {
    let mut d = protocol::MsiResourceDescriptor3::new_zeroed();
    d.vector = 0x42;
    d.vector_count = 1;
    d.processor_count = 1;
    d.processor_array[0] = 5;
    d
}

// Test: Assign and retrieve each wire encoding of normal and large BAR resources.
// Expected: The reply and later resource query preserve the assigned address and length.
#[async_test]
async fn resource_assignment_roundtrips_all_memory_widths(driver: DefaultDriver) {
    for size in [0x1000, 1 << 32, 1 << 40, 1 << 48] {
        let (mut guest, _, _) = endpoint(&driver, size);
        guest.start_device(0x140000000).await;
        assert!(
            resources(&mut guest)
                .await
                .descriptors
                .iter()
                .all(|d| d.adjusted_len == 0)
        );
        let msg = assignment(protocol::MessageType::ASSIGNED_RESOURCES, size);
        let bytes = exchange(&mut guest, msg.as_bytes()).await;
        let reply = protocol::DeviceTranslateReply::read_from_prefix(&bytes)
            .unwrap()
            .0;
        assert_eq!(reply.status, protocol::Status::SUCCESS);
        assert_eq!(
            reply.mmio_resources[0].as_bytes(),
            msg.mmio_resources[0].as_bytes()
        );
        let current = resources(&mut guest).await;
        assert_eq!(current.count, 6);
        assert_eq!(
            current.descriptors[0].as_bytes(),
            msg.mmio_resources[0].as_bytes()
        );
        assert_eq!(
            status(
                &mut guest,
                pdo(protocol::MessageType::RELEASE_RESOURCES).as_bytes()
            )
            .await,
            protocol::Status::SUCCESS
        );
        assert!(
            resources(&mut guest)
                .await
                .descriptors
                .iter()
                .all(|d| d.adjusted_len == 0)
        );
    }
}

// Test: Assign interrupt resources in all three protocol formats and then release them.
// Expected: Returned MSI messages route to the requested CPU and stop after release.
#[async_test]
async fn assignment_translates_interrupt_formats_and_releases_mappings(driver: DefaultDriver) {
    for (message_type, extra, vector, cpu) in [
        (
            protocol::MessageType::ASSIGNED_RESOURCES,
            protocol::MsiResource::from(descriptor1())
                .as_bytes()
                .to_vec(),
            0x40,
            3,
        ),
        (
            protocol::MessageType::ASSIGNED_RESOURCES2,
            protocol::MsiResource2::from(descriptor2())
                .as_bytes()
                .to_vec(),
            0x41,
            4,
        ),
        (
            protocol::MessageType::ASSIGNED_RESOURCES3,
            protocol::MsiResource3::from(descriptor3())
                .as_bytes()
                .to_vec(),
            0x42,
            5,
        ),
    ] {
        let (mut guest, _, controller) = endpoint(&driver, 0x1000);
        guest.start_device(0x140000000).await;
        let mut msg = assignment(message_type, 0x1000);
        msg.msi_resource_count = 1;
        let mut request = msg.as_bytes().to_vec();
        request.extend_from_slice(&extra);
        let bytes = exchange(&mut guest, &request).await;
        let (reply, rest) = protocol::DeviceTranslateReply::read_from_prefix(&bytes).unwrap();
        assert_eq!(reply.status, protocol::Status::SUCCESS);
        assert_eq!(reply.slot, SlotNumber::new());
        assert_eq!(reply.reserved, 0);
        assert_eq!(
            reply.mmio_resources.as_bytes(),
            msg.mmio_resources.as_bytes()
        );
        assert_eq!(reply.msi_resource_count, 1);
        let (msi, padding) = protocol::MsiResourceRemapped::read_from_prefix(rest).unwrap();
        assert_eq!(msi.reserved, 0);
        assert_eq!(msi.message_count, 1);
        assert_eq!(msi.address, 0xfee0_0000);
        assert_eq!(msi.data_payload, 0);
        if message_type == protocol::MessageType::ASSIGNED_RESOURCES {
            assert!(padding.is_empty());
        } else {
            // V2 and V3 requests both receive the padded V2 remapped union.
            assert_eq!(padding, &[0; 56]);
        }
        controller.deliver_interrupt(msi.address, msi.data_payload);
        let interrupt = controller.get_next_interrupt().unwrap();
        assert_eq!((interrupt.vector, interrupt.destination), (vector, cpu));
        assert_eq!(
            status(
                &mut guest,
                pdo(protocol::MessageType::RELEASE_RESOURCES).as_bytes()
            )
            .await,
            protocol::Status::SUCCESS
        );
        controller.deliver_interrupt(msi.address, msi.data_payload);
        assert!(controller.get_next_interrupt().is_none());
    }
}

// Test: Submit unaligned, oversized, high-half, and malformed MMIO assignments.
// Expected: Each request returns BAD_DATA and leaves BAR resources unassigned.
#[async_test]
async fn invalid_assignments_are_rejected_without_changing_bars(driver: DefaultDriver) {
    let (mut guest, _, _) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    for case in 0..5 {
        let mut msg = assignment(protocol::MessageType::ASSIGNED_RESOURCES, 0x1000);
        match case {
            0 => msg.mmio_resources[0].address = 0x2001.into(),
            1 => msg.mmio_resources[0].adjusted_len = 0x2000,
            2 => msg.mmio_resources[1] = memory(0x3000, 0x1000),
            3 => {
                msg.mmio_resources[0].resource_type = protocol::ResourceType::MEMORY_LARGE;
            }
            4 => msg.msi_resource_count = protocol::MAX_SUPPORTED_INTERRUPT_MESSAGES + 1,
            _ => unreachable!(),
        }
        assert_eq!(
            status(&mut guest, msg.as_bytes()).await,
            protocol::Status::BAD_DATA
        );
        assert!(
            resources(&mut guest)
                .await
                .descriptors
                .iter()
                .all(|d| d.adjusted_len == 0)
        );
    }
}

// Test: Create and delete interrupts using all supported descriptor formats.
// Expected: Wire replies describe working routes; deleted and unknown routes do not deliver.
#[async_test]
async fn create_delete_interrupts_preserve_routing_and_lifetime(driver: DefaultDriver) {
    let (mut guest, _, controller) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    let requests = [
        protocol::CreateInterrupt {
            message_type: protocol::MessageType::CREATE_INTERRUPT,
            slot: SlotNumber::new(),
            interrupt: descriptor1(),
        }
        .as_bytes()
        .to_vec(),
        protocol::CreateInterrupt2 {
            message_type: protocol::MessageType::CREATE_INTERRUPT2,
            slot: SlotNumber::new(),
            interrupt: descriptor2(),
        }
        .as_bytes()
        .to_vec(),
        protocol::CreateInterrupt3 {
            message_type: protocol::MessageType::CREATE_INTERRUPT3,
            slot: SlotNumber::new(),
            interrupt: descriptor3(),
        }
        .as_bytes()
        .to_vec(),
    ];
    for (i, request) in requests.iter().enumerate() {
        let bytes = exchange(&mut guest, request).await;
        let reply = protocol::CreateInterruptReply::read_from_prefix(&bytes)
            .unwrap()
            .0;
        assert_eq!(reply.status, protocol::Status::SUCCESS);
        controller.deliver_interrupt(reply.interrupt.address, reply.interrupt.data_payload);
        let delivered = controller.get_next_interrupt().unwrap();
        assert_eq!(
            (delivered.vector, delivered.destination),
            (0x40 + i as u32, 3 + i as u32)
        );
        let delete = protocol::DeleteInterrupt {
            message_type: if i == 0 {
                protocol::MessageType::DELETE_INTERRUPT
            } else {
                protocol::MessageType::DELETE_INTERRUPT2
            },
            slot: SlotNumber::new(),
            interrupt: reply.interrupt,
        };
        assert_eq!(
            status(&mut guest, delete.as_bytes()).await,
            protocol::Status::SUCCESS
        );
        controller.deliver_interrupt(reply.interrupt.address, reply.interrupt.data_payload);
        assert!(controller.get_next_interrupt().is_none());
        assert_eq!(
            status(&mut guest, delete.as_bytes()).await,
            protocol::Status::BAD_DATA
        );
    }
}

// Test: Supply invalid vector counts, processor counts, and delivery modes.
// Expected: The server returns BAD_DATA and continues accepting resource queries.
#[async_test]
async fn malformed_interrupt_descriptors_do_not_poison_the_channel(driver: DefaultDriver) {
    let (mut guest, _, _) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    for case in 0..5 {
        let mut d = descriptor1();
        match case {
            0 => d.vector_count = 33,
            1 => d.processor_mask = u64::MAX,
            2 => d.delivery_mode = protocol::DeliveryMode(0xff),
            3 => d.processor_mask = 0,
            4 => d.vector_count = 0,
            _ => unreachable!(),
        }
        let msg = protocol::CreateInterrupt {
            message_type: protocol::MessageType::CREATE_INTERRUPT,
            slot: SlotNumber::new(),
            interrupt: d,
        };
        let result = status(&mut guest, msg.as_bytes()).await;
        assert_eq!(
            result,
            if case == 4 {
                protocol::Status::SUCCESS
            } else {
                protocol::Status::BAD_DATA
            }
        );
    }
    for v3 in [false, true] {
        for invalid_count in [false, true] {
            let bytes = if v3 {
                let mut d = descriptor3();
                if invalid_count {
                    d.vector_count = 33;
                } else {
                    d.processor_count = 33;
                }
                protocol::CreateInterrupt3 {
                    message_type: protocol::MessageType::CREATE_INTERRUPT3,
                    slot: SlotNumber::new(),
                    interrupt: d,
                }
                .as_bytes()
                .to_vec()
            } else {
                let mut d = descriptor2();
                if invalid_count {
                    d.vector_count = 33;
                } else {
                    d.processor_count = 33;
                }
                protocol::CreateInterrupt2 {
                    message_type: protocol::MessageType::CREATE_INTERRUPT2,
                    slot: SlotNumber::new(),
                    interrupt: d,
                }
                .as_bytes()
                .to_vec()
            };
            assert_eq!(status(&mut guest, &bytes).await, protocol::Status::BAD_DATA);
        }
    }
    assert_eq!(resources(&mut guest).await.count, 6);
}

// Test: Change device power, query requirements, and submit reset and invalid slots.
// Expected: Power changes reach PCI command bits and unsupported requests return explicit status.
#[async_test]
async fn power_requirements_and_invalid_device_requests(driver: DefaultDriver) {
    let (mut guest, pci, _) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    let query = pdo(protocol::MessageType::CURRENT_RESOURCE_REQUIREMENTS);
    let bytes = exchange(&mut guest, query.as_bytes()).await;
    let reply = protocol::QueryResourceRequirementsReply::read_from_prefix(&bytes)
        .unwrap()
        .0;
    assert_eq!(reply.status, protocol::Status::SUCCESS);
    assert_eq!(reply.bars[0] & !0xf, 0xfffff000);
    for (target_state, expected) in [
        (protocol::DevicePowerState::D0, true),
        (protocol::DevicePowerState::D3, false),
    ] {
        let msg = protocol::DevicePowerChange {
            message_type: protocol::MessageType::DEVICE_POWER_STATE_CHANGE,
            slot: SlotNumber::new(),
            target_state,
        };
        assert_eq!(
            status(&mut guest, msg.as_bytes()).await,
            protocol::Status::SUCCESS
        );
        let mut command = 0;
        pci.lock()
            .pci_cfg_read(
                4,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut command),
            )
            .unwrap();
        assert_eq!(command & 2 != 0, expected);
    }
    let msg = protocol::DevicePowerChange {
        message_type: protocol::MessageType::DEVICE_POWER_STATE_CHANGE,
        slot: SlotNumber::new(),
        target_state: protocol::DevicePowerState(99),
    };
    assert_eq!(
        status(&mut guest, msg.as_bytes()).await,
        protocol::Status::BAD_DATA
    );
    assert_eq!(
        status(
            &mut guest,
            pdo(protocol::MessageType::RESET_DEVICE).as_bytes()
        )
        .await,
        protocol::Status::NOT_SUPPORTED
    );
    assert_eq!(
        status(
            &mut guest,
            pdo(protocol::MessageType::EJECT_COMPLETE).as_bytes()
        )
        .await,
        protocol::Status::BAD_DATA
    );
    let mut msg = pdo(protocol::MessageType::RESET_DEVICE);
    msg.slot = SlotNumber::from(1);
    assert_eq!(
        status(&mut guest, msg.as_bytes()).await,
        protocol::Status::BAD_DATA
    );
    assert_eq!(
        status(&mut guest, protocol::MessageType::FDO_D0_EXIT.as_bytes()).await,
        protocol::Status::SUCCESS
    );
}

// Test: Send truncated and unknown packets after protocol negotiation.
// Expected: Each malformed request returns BAD_DATA without closing the channel.
#[async_test]
async fn truncated_packets_fail_without_disrupting_later_requests(driver: DefaultDriver) {
    let (mut guest, _, _) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    for message_type in [
        protocol::MessageType::ASSIGNED_RESOURCES,
        protocol::MessageType::ASSIGNED_RESOURCES2,
        protocol::MessageType::ASSIGNED_RESOURCES3,
        protocol::MessageType::CREATE_INTERRUPT,
        protocol::MessageType::CREATE_INTERRUPT2,
        protocol::MessageType::CREATE_INTERRUPT3,
        protocol::MessageType::DELETE_INTERRUPT,
        protocol::MessageType::GET_RESOURCES,
        protocol::MessageType::FDO_D0_ENTRY,
        protocol::MessageType::DEVICE_POWER_STATE_CHANGE,
        protocol::MessageType::VPCI_TDISP_COMMAND,
        protocol::MessageType(0xffff),
    ] {
        assert_eq!(
            status(&mut guest, message_type.as_bytes()).await,
            protocol::Status::BAD_DATA,
            "{message_type:?}"
        );
    }

    assert_eq!(status(&mut guest, &[]).await, protocol::Status::BAD_DATA);
    for message_type in [
        protocol::MessageType::ASSIGNED_RESOURCES,
        protocol::MessageType::ASSIGNED_RESOURCES2,
        protocol::MessageType::ASSIGNED_RESOURCES3,
    ] {
        let mut msg = assignment(message_type, 0x1000);
        msg.msi_resource_count = 1;
        assert_eq!(
            status(&mut guest, msg.as_bytes()).await,
            protocol::Status::BAD_DATA
        );
    }
    assert_eq!(resources(&mut guest).await.count, 6);
}

// Test: Send malformed and oversized TDISP payloads after negotiating RB.
// Expected: Invalid commands return BAD_DATA without disturbing later bus queries.
#[async_test]
async fn malformed_tdisp_payloads_are_rejected_on_rb(driver: DefaultDriver) {
    let (mut guest, _, _) = endpoint(&driver, 0x1000);
    guest.protocol_version = protocol::ProtocolVersion::RB;
    guest.start_device(0x140000000).await;
    for (length, data) in [
        (1, &[0xff][..]),
        (8, &[][..]),
        (protocol::MAX_VPCI_TDISP_COMMAND_SIZE as u64 + 1, &[][..]),
    ] {
        let header = protocol::VpciTdispCommandHeader {
            message_type: protocol::MessageType::VPCI_TDISP_COMMAND,
            slot: SlotNumber::new(),
            data_length: length,
        };
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        assert_eq!(status(&mut guest, &bytes).await, protocol::Status::BAD_DATA);
    }
    assert_eq!(resources(&mut guest).await.count, 6);
}

#[derive(Clone)]
struct Parent {
    driver: DefaultDriver,
    offers: Arc<parking_lot::Mutex<Vec<Guid>>>,
    fail: bool,
}

#[async_trait::async_trait]
impl vmbus_channel::bus::ParentBus for Parent {
    async fn add_child(
        &self,
        mut request: vmbus_channel::bus::OfferInput,
    ) -> anyhow::Result<vmbus_channel::bus::OfferResources> {
        if self.fail {
            anyhow::bail!("injected offer failure");
        }
        assert_eq!(
            request.params.interface_id,
            protocol::GUID_VPCI_VSP_CHANNEL_TYPE
        );
        self.offers.lock().push(request.params.instance_id);
        self.driver
            .spawn("test-parent", async move {
                let _keep_open = request.request_send;
                if let Ok(request) = request.server_request_recv.recv().await {
                    match request {
                        vmbus_channel::bus::ChannelServerRequest::Revoke(rpc) => {
                            rpc.complete(());
                        }
                        vmbus_channel::bus::ChannelServerRequest::Restore(_) => {
                            panic!("unexpected restore request")
                        }
                    }
                }
            })
            .detach();
        Ok(Default::default())
    }
    fn clone_bus(&self) -> Box<dyn vmbus_channel::bus::ParentBus> {
        Box::new(self.clone())
    }
    fn use_event(&self) -> bool {
        false
    }
}

fn bus_config() -> crate::bus::VpciBusConfig {
    crate::bus::VpciBusConfig {
        instance_id: Guid::new_random(),
        vtom: Some(1 << 47),
        vnode: Some(3),
    }
}

// Test: Offer a complete VPCI bus and drive its public lifecycle and revocation.
// Expected: The parent receives the expected channel and revocation completes idempotently.
#[async_test]
async fn bus_offer_lifecycle_and_revocation(driver: DefaultDriver) {
    use vmcore::device_state::ChangeDeviceState;
    use vmcore::save_restore::SaveRestore;
    use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};
    let (_, pci, controller) = endpoint(&driver, 0x1000);
    let parent = Parent {
        driver: driver.clone(),
        offers: Arc::default(),
        fail: false,
    };
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let config = bus_config();
    let id = config.instance_id;
    let mut bus = crate::bus::VpciBus::new(
        &source,
        config,
        pci,
        &mut ExternallyManagedMmioIntercepts,
        &parent,
        VpciInterruptMapper::new(controller),
    )
    .await
    .unwrap();
    assert_eq!(*parent.offers.lock(), [id]);
    assert!(bus.supports_mmio().is_some());
    assert!(bus.supports_poll_device().is_some());
    bus.eject_control().eject().await.unwrap();
    bus.start();
    bus.stop().await;
    bus.reset().await;
    let saved = bus.save().unwrap();
    bus.restore(saved).unwrap();
    bus.revoke().await;
    bus.revoke().await;
}

// Test: Publish a deferred bus offer and attempt publication after revocation.
// Expected: Successful publication reaches the parent; revoked buses reject new offers.
#[async_test]
async fn deferred_offers_honor_revocation_and_parent_failures(driver: DefaultDriver) {
    use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};
    let parent = Parent {
        driver: driver.clone(),
        offers: Arc::default(),
        fail: false,
    };
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    for (started, fail) in [(false, false), (true, false), (false, true)] {
        let (_, pci, controller) = endpoint(&driver, 0x1000);
        let (bus, offer) = crate::bus::VpciBus::new_unoffered(
            bus_config(),
            pci,
            &mut ExternallyManagedMmioIntercepts,
            VpciInterruptMapper::new(controller),
        )
        .unwrap();
        let bus = Arc::new(CloseableMutex::new(bus));
        let parent = Parent {
            fail,
            ..parent.clone()
        };
        let result = offer
            .offer_registered(&bus, &source, &parent, started)
            .await;
        if fail {
            assert!(format!("{:#}", result.unwrap_err()).contains("injected offer failure"));
        } else {
            result.unwrap();
        }
        let mut bus = bus.close_permanently().take();
        bus.revoke().await;
    }
    let (_, pci, controller) = endpoint(&driver, 0x1000);
    let (mut bus, offer) = crate::bus::VpciBus::new_unoffered(
        bus_config(),
        pci,
        &mut ExternallyManagedMmioIntercepts,
        VpciInterruptMapper::new(controller),
    )
    .unwrap();
    bus.revoke().await;
    let bus = Arc::new(CloseableMutex::new(bus));
    let err = offer
        .offer_registered(&bus, &source, &parent, false)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("revoked"));
    assert_eq!(parent.offers.lock().len(), 2);
}

// Test: Reject a malformed reassignment while a BAR and interrupt are in use.
// Expected: Existing resources still work, and release permits a new assignment.
#[async_test]
async fn rejected_reassignment_preserves_live_resources(driver: DefaultDriver) {
    let (mut guest, _, controller) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    let mut initial = assignment(protocol::MessageType::ASSIGNED_RESOURCES, 0x1000);
    initial.msi_resource_count = 1;
    let mut request = initial.as_bytes().to_vec();
    request.extend_from_slice(protocol::MsiResource::from(descriptor1()).as_bytes());
    let bytes = exchange(&mut guest, &request).await;
    let (reply, rest) = protocol::DeviceTranslateReply::read_from_prefix(&bytes).unwrap();
    assert_eq!(reply.status, protocol::Status::SUCCESS);
    assert_eq!(reply.msi_resource_count, 1);
    let interrupt = protocol::MsiResourceRemapped::read_from_prefix(rest)
        .unwrap()
        .0;
    let original = resources(&mut guest).await;

    // The first BAR would change if it were applied before validating BAR one.
    let mut invalid = assignment(protocol::MessageType::ASSIGNED_RESOURCES, 0x1000);
    invalid.mmio_resources[0] = memory(0x4000, 0x1000);
    invalid.mmio_resources[1] = memory(0x3000, 0x1000);
    assert_eq!(
        status(&mut guest, invalid.as_bytes()).await,
        protocol::Status::BAD_DATA
    );
    assert_eq!(resources(&mut guest).await.as_bytes(), original.as_bytes());
    controller.deliver_interrupt(interrupt.address, interrupt.data_payload);
    let delivered = controller.get_next_interrupt().unwrap();
    assert_eq!((delivered.vector, delivered.destination), (0x40, 3));
    assert!(controller.get_next_interrupt().is_none());

    assert_eq!(
        status(
            &mut guest,
            pdo(protocol::MessageType::RELEASE_RESOURCES).as_bytes()
        )
        .await,
        protocol::Status::SUCCESS
    );
    controller.deliver_interrupt(interrupt.address, interrupt.data_payload);
    assert!(controller.get_next_interrupt().is_none());

    let mut retry = assignment(protocol::MessageType::ASSIGNED_RESOURCES, 0x1000);
    retry.mmio_resources[0] = memory(0x6000, 0x1000);
    assert_eq!(
        status(&mut guest, retry.as_bytes()).await,
        protocol::Status::SUCCESS
    );
    let current = resources(&mut guest).await;
    assert_eq!(
        current.descriptors[0].as_bytes(),
        retry.mmio_resources[0].as_bytes()
    );
    assert!(
        current.descriptors[1..]
            .iter()
            .all(|resource| resource.adjusted_len == 0)
    );
}

// Test: Reject wrong-data and wrong-slot deletions while two interrupt routes are live.
// Expected: Rejected requests preserve both routes; deleting one leaves its peer working,
//       and release removes the remaining route without delivering stale interrupts.
#[async_test]
async fn interrupt_deletion_preserves_peer_routes(driver: DefaultDriver) {
    let (mut guest, _, controller) = endpoint(&driver, 0x1000);
    guest.start_device(0x140000000).await;
    let first = guest.register_interrupt(0x51, &[7]).await;
    let second = guest.register_interrupt(0x63, &[9]).await;
    assert_ne!(first.0, second.0);

    let mut delete = protocol::DeleteInterrupt {
        message_type: protocol::MessageType::DELETE_INTERRUPT2,
        slot: SlotNumber::new(),
        interrupt: protocol::MsiResourceRemapped {
            reserved: 0,
            message_count: 1,
            address: first.0,
            data_payload: first.1 + 1,
        },
    };
    assert_eq!(
        status(&mut guest, delete.as_bytes()).await,
        protocol::Status::BAD_DATA
    );
    delete.interrupt.data_payload = first.1;
    delete.slot = SlotNumber::from(1);
    assert_eq!(
        status(&mut guest, delete.as_bytes()).await,
        protocol::Status::BAD_DATA
    );
    controller.deliver_interrupt(first.0, first.1);
    controller.deliver_interrupt(second.0, second.1);
    for expected in [(0x51, 7), (0x63, 9)] {
        let delivered = controller.get_next_interrupt().unwrap();
        assert_eq!((delivered.vector, delivered.destination), expected);
    }
    assert!(controller.get_next_interrupt().is_none());

    delete.slot = SlotNumber::new();
    assert_eq!(
        status(&mut guest, delete.as_bytes()).await,
        protocol::Status::SUCCESS
    );
    controller.deliver_interrupt(first.0, first.1);
    controller.deliver_interrupt(second.0, second.1);
    let delivered = controller.get_next_interrupt().unwrap();
    assert_eq!((delivered.vector, delivered.destination), (0x63, 9));
    assert!(controller.get_next_interrupt().is_none());

    assert_eq!(
        status(
            &mut guest,
            pdo(protocol::MessageType::RELEASE_RESOURCES).as_bytes()
        )
        .await,
        protocol::Status::SUCCESS
    );
    controller.deliver_interrupt(first.0, first.1);
    controller.deliver_interrupt(second.0, second.1);
    assert!(controller.get_next_interrupt().is_none());
}
