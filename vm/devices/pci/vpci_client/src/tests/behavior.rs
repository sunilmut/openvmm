// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::host::*;
use super::*;
use chipset_device::pci::PciConfigByteEnable;
use futures::{FutureExt, StreamExt};
use guestmem::MemoryRead;
use test_with_tracing::test;
use vmbus_async::queue::{IncomingPacket, OutgoingPacket, Queue};
use vmbus_ring::OutgoingPacketType;
use vpci_protocol as protocol;
use zerocopy::{FromBytes, IntoBytes};

// Read the public PCI view without touching its private shadow state.
fn read_cfg(device: &crate::VpciDevice, offset: u16) -> u32 {
    let mut value = 0;
    device.read_cfg(
        offset,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
    );
    value
}

// Test: Program and probe 32/64-bit BARs, then enable MMIO with a partial command write.
// Expected: IDs and BAR encodings are preserved; BAR writes are deferred and flushed in order.
#[async_test]
async fn configuration_shadowing_preserves_byte_lanes_and_host_write_order(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, log) = connect(&driver, &[description(3, 91)]).await;
    let description = devices.pop().unwrap();
    assert_eq!(description.hw_ids().vendor_id, 0x1234);
    assert_eq!((description.numa_node(), description.serial_num()), (7, 91));
    let (device, eject) = host
        .init(description, [0xffff_f008, 0xffff_e004, u32::MAX, 0, 0, 0])
        .await;
    assert_eq!(read_cfg(&device, 0), 0x5678_1234);
    assert_eq!(read_cfg(&device, 8), 0x0203_0405);
    assert_eq!(read_cfg(&device, 0x2c), 0xdef0_9abc);
    device.write_cfg(
        0x10,
        ByteEnabledDwordWrite::with_all_bytes_enabled(u32::MAX),
    );
    assert_eq!(read_cfg(&device, 0x10), 0xffff_f008);
    device.write_cfg(
        0x10,
        ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234_5678),
    );
    device.write_cfg(
        0x10,
        ByteEnabledDwordWrite::new(0xabcd_0000, PciConfigByteEnable::HIGH_WORD),
    );
    assert_eq!(read_cfg(&device, 0x10), 0xabcd_5008);
    device.write_cfg(
        0x14,
        ByteEnabledDwordWrite::with_all_bytes_enabled(0x8765_4321),
    );
    device.write_cfg(0x18, ByteEnabledDwordWrite::with_all_bytes_enabled(1));
    assert_eq!(read_cfg(&device, 0x14), 0x8765_4004);
    assert_eq!(read_cfg(&device, 0x18), 1);
    assert!(log.lock().writes.is_empty());
    device.write_cfg(
        4,
        ByteEnabledDwordWrite::new(6, PciConfigByteEnable::LOW_WORD),
    );
    let mut expected = vec![(
        BASE + protocol::MMIO_PAGE_SLOT_NUMBER,
        3u32.to_ne_bytes().to_vec(),
    )];
    for (index, value) in [0xabcd_5008u32, 0x8765_4004, 1, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        expected.push((
            BASE + protocol::MMIO_PAGE_CONFIG_SPACE + 0x10 + index as u64 * 4,
            value.to_ne_bytes().to_vec(),
        ));
    }
    expected.push((
        BASE + protocol::MMIO_PAGE_CONFIG_SPACE + 4,
        6u16.to_ne_bytes().to_vec(),
    ));
    assert_eq!(log.lock().writes, expected);
    log.lock().bytes[4..8].copy_from_slice(&0xaabb_0004u32.to_ne_bytes());
    assert_eq!(read_cfg(&device, 4), 0xaabb_0006);
    let mut high = 0x1122_3344;
    device.read_cfg(
        4,
        ByteEnabledDwordRead::new(&mut high, PciConfigByteEnable::HIGH_WORD),
    );
    assert_eq!(high, 0xaabb_3344);
    log.lock().bytes[0x101] = 0x77;
    let mut partial = 0x1122_3344;
    device.read_cfg(
        0x100,
        ByteEnabledDwordRead::new(&mut partial, PciConfigByteEnable::BYTE1),
    );
    assert_eq!(partial, 0x1122_7744);
    device.write_cfg(
        0x100,
        ByteEnabledDwordWrite::new(0x0055_0000, PciConfigByteEnable::BYTE2),
    );
    assert_eq!(&log.lock().bytes[0x100..0x104], &[0, 0x77, 0x55, 0]);
    drop((device, eject, added));
    client.shutdown().await;
}

// Test: Remove an initialized device and an uninitialized description from the bus.
// Expected: Removal closes the public stream, blocks stale MMIO/MSI and rejects stale init.
#[async_test]
async fn surprise_removal_revokes_stale_device_access(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, log) =
        connect(&driver, &[description(0, 1), description(3, 2)]).await;
    let stale = devices.pop().unwrap();
    let (device, mut eject) = host.init(devices.pop().unwrap(), [0; 6]).await;
    host.relations(&[]).await;
    assert!(
        vmbus_channel::test_helpers::with_timeout(&driver, eject.next())
            .await
            .is_none()
    );
    log.lock().writes.clear();
    assert_eq!(read_cfg(&device, 0x100), u32::MAX);
    device.write_cfg(0x100, ByteEnabledDwordWrite::with_all_bytes_enabled(5));
    assert!(log.lock().writes.is_empty());
    let error = device
        .register_interrupt(
            1,
            &VpciInterruptParameters {
                vector: 33,
                multicast: false,
                target_processors: &[0],
            },
        )
        .await
        .unwrap_err();
    assert!(format!("{:#}", anyhow::Error::new(error)).contains("device is gone"));
    device.unregister_interrupt(0xfee0_1000, 33).await;
    let error = stale
        .init(
            Arc::new(TdispNoopResourceValidator::new()),
            IsolationType::None,
            Vtl::Vtl0,
        )
        .await
        .err()
        .expect("removed description initialized successfully");
    assert!(error.to_string().contains("device is gone"));
    drop((device, eject, added));
    client.shutdown().await;
}

// Test: Repeat a bus announcement, request eject twice, then release the initialized device.
// Expected: Neither announcement nor eject is duplicated; release emits one wire acknowledgement.
#[async_test]
async fn eject_notifications_and_completion_are_delivered_once(driver: DefaultDriver) {
    let wire = description(3, 91);
    let (mut host, client, mut devices, mut added, _log) = connect(&driver, &[wire]).await;
    let (device, mut eject) = host.init(devices.pop().unwrap(), [0; 6]).await;
    host.relations(&[wire]).await;
    host.eject(3).await;
    host.eject(3).await;
    assert!(
        vmbus_channel::test_helpers::with_timeout(&driver, eject.next())
            .await
            .is_some()
    );
    assert!(eject.next().now_or_never().is_none());
    assert!(matches!(added.try_recv(), Err(mesh::TryRecvError::Empty)));
    drop(device);
    let (tx, bytes) = host.receive().await;
    assert!(tx.is_none());
    let complete = protocol::PdoMessage::read_from_prefix(&bytes).unwrap().0;
    assert_eq!(complete.message_type, protocol::MessageType::EJECT_COMPLETE);
    assert_eq!(u32::from(complete.slot), 3);
    host.relations(&[]).await;
    assert!(
        vmbus_channel::test_helpers::with_timeout(&driver, eject.next())
            .await
            .is_none()
    );
    drop((eject, added));
    client.shutdown().await;
}

// Test: Replace a device in the same slot while retaining its old description.
// Expected: The replacement is hot-added with its new identity; stale generation init fails.
#[async_test]
async fn slot_replacement_invalidates_old_description_generations(driver: DefaultDriver) {
    let (mut host, client, mut devices, mut added, _log) =
        connect(&driver, &[description(3, 1)]).await;
    let stale = devices.pop().unwrap();
    host.relations(&[description(3, 2)]).await;
    let replacement = vmbus_channel::test_helpers::with_timeout(&driver, added.next())
        .await
        .unwrap();
    assert_eq!(replacement.serial_num(), 2);
    let error = stale
        .init(
            Arc::new(TdispNoopResourceValidator::new()),
            IsolationType::None,
            Vtl::Vtl0,
        )
        .await
        .err()
        .expect("stale generation initialized successfully");
    assert!(error.to_string().contains("device is gone"));
    drop((replacement, added));
    client.shutdown().await;
}

// Test: Reject out-of-range interrupt parameters before any host transaction is sent.
// Expected: Vector, count and processor conversion errors identify the rejected value.
#[async_test]
async fn interrupt_parameter_errors_are_reported_before_host_io(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, _log) = connect(&driver, &[description(0, 1)]).await;
    let (device, eject) = host.init(devices.pop().unwrap(), [0; 6]).await;
    for (count, vector, processors, message) in [
        (1, 256, vec![0], "starting vector too large: 256"),
        (65536, 1, vec![0], "invalid vector count: 65536"),
        (1, 1, vec![65536], "invalid processor number: 65536"),
    ] {
        let parameters = VpciInterruptParameters {
            vector,
            multicast: true,
            target_processors: &processors,
        };
        let error = vmbus_channel::test_helpers::with_timeout(
            &driver,
            device.register_interrupt(count, &parameters),
        )
        .await
        .unwrap_err();
        let error = anyhow::Error::new(error);
        assert!(format!("{error:#}").contains(message), "{error:#}");
    }
    assert!(host.queue.split().0.read().now_or_never().is_none());
    drop((device, eject, added));
    client.shutdown().await;
}

// Test: Return explicit host failure statuses for resource queries and interrupt mappings.
// Expected: Public init/MSI operations report errors rather than accepting unusable resources.
#[async_test]
async fn host_failure_statuses_reach_public_callers(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, _log) =
        connect(&driver, &[description(0, 1), description(3, 2)]).await;
    let invalid = devices.pop().unwrap();
    let init = invalid.init(
        Arc::new(TdispNoopResourceValidator::new()),
        IsolationType::None,
        Vtl::Vtl0,
    );
    let fail = async {
        let (tx, _) = host
            .expect(protocol::MessageType::CURRENT_RESOURCE_REQUIREMENTS)
            .await;
        host.complete(tx, protocol::Status::NOT_SUPPORTED.as_bytes())
            .await;
    };
    let (result, ()) = futures::join!(init, fail);
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("failed to query resource requirements")
    );
    let (device, eject) = host.init(devices.pop().unwrap(), [0; 6]).await;
    let map = device.register_interrupt(
        1,
        &VpciInterruptParameters {
            vector: 33,
            multicast: true,
            target_processors: &[0, 1],
        },
    );
    let fail = async {
        let (tx, bytes) = host.expect(protocol::MessageType::CREATE_INTERRUPT2).await;
        let request = protocol::CreateInterrupt2::read_from_prefix(&bytes)
            .unwrap()
            .0;
        assert_eq!(
            request.interrupt.delivery_mode,
            protocol::DeliveryMode::LOWEST_PRIORITY
        );
        host.complete(tx, protocol::Status::NOT_SUPPORTED.as_bytes())
            .await;
    };
    let (result, ()) = futures::join!(map, fail);
    assert!(
        format!("{:#}", anyhow::Error::new(result.unwrap_err()))
            .contains("failed to create interrupt")
    );
    let unmap = device.unregister_interrupt(0xfee0_1000, 33);
    let fail = async {
        let (tx, _) = host.expect(protocol::MessageType::DELETE_INTERRUPT).await;
        host.complete(tx, protocol::Status::NOT_SUPPORTED.as_bytes())
            .await;
    };
    futures::join!(unmap, fail);
    drop((device, eject, added));
    client.shutdown().await;
}

// Test: Send malformed bus relations, an invalid slot or a message outside the host protocol.
// Expected: The worker terminates cleanly and pending public operations fail, without panicking.
#[async_test]
async fn malformed_host_packets_close_pending_operations(driver: DefaultDriver) {
    let bad_relations = protocol::QueryBusRelations2 {
        message_type: protocol::MessageType::BUS_RELATIONS2,
        device_count: 1,
        device: [],
    }
    .as_bytes()
    .to_vec();
    for bytes in [
        0xdead_beefu32.to_ne_bytes().to_vec(),
        bad_relations,
        protocol::PdoMessage {
            message_type: protocol::MessageType::EJECT,
            slot: 77.into(),
        }
        .as_bytes()
        .to_vec(),
    ] {
        let (mut host, client, mut devices, added, _log) =
            connect(&driver, &[description(0, 1)]).await;
        host.send(OutgoingPacketType::InBandNoCompletion, 0, &bytes)
            .await;
        let init = devices.pop().unwrap().init(
            Arc::new(TdispNoopResourceValidator::new()),
            IsolationType::None,
            Vtl::Vtl0,
        );
        assert!(
            vmbus_channel::test_helpers::with_timeout(&driver, init)
                .await
                .is_err()
        );
        drop(added);
        client.shutdown().await;
    }
}

// Test: Negotiate against a host that rejects the newest version or all supported versions.
// Expected: Fallback queries preserve order; rejecting every version yields a contextual error.
#[async_test]
async fn negotiation_fallback_and_exhaustion_preserve_host_order() {
    for accept_older in [true, false] {
        let (host, guest) = vmbus_channel::connected_async_channels(32768);
        let mut host = Queue::new(host).unwrap();
        let mut connection = crate::VpciConnection {
            queue: Queue::new(guest).unwrap(),
        };
        let respond = async {
            for version in [protocol::ProtocolVersion::RB, protocol::ProtocolVersion::VB] {
                let (mut read, mut write) = host.split();
                let packet = read.read().await.unwrap();
                let IncomingPacket::Data(packet) = &*packet else {
                    panic!("expected negotiation")
                };
                let query: protocol::QueryProtocolVersion = packet.reader().read_plain().unwrap();
                assert_eq!(query.protocol_version, version);
                let status = if version == protocol::ProtocolVersion::VB && accept_older {
                    protocol::Status::SUCCESS
                } else {
                    protocol::Status::NOT_SUPPORTED
                };
                write
                    .write(OutgoingPacket {
                        transaction_id: packet.transaction_id().unwrap(),
                        packet_type: OutgoingPacketType::Completion,
                        payload: &[status.as_bytes()],
                    })
                    .await
                    .unwrap();
            }
        };
        let (result, ()) = futures::join!(connection.negotiate(), respond);
        if accept_older {
            assert_eq!(result.unwrap(), protocol::ProtocolVersion::VB);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "no supported VPCI protocol version found"
            );
        }
    }
}

// Test: Request TDISP activation on a device in a VM without isolation.
// Expected: Activation fails without enabling MMIO or flushing pending BAR writes.
#[async_test]
async fn unsupported_tdisp_activation_leaves_device_disabled(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, log) = connect(&driver, &[description(0, 1)]).await;
    let (device, eject) = host
        .init(devices.pop().unwrap(), [0xffff_f000, 0, 0, 0, 0, 0])
        .await;
    device.write_cfg(0x10, ByteEnabledDwordWrite::with_all_bytes_enabled(0x8000));
    assert!(
        !vmbus_channel::test_helpers::with_timeout(
            &driver,
            device.tdisp_on_device_activate(ByteEnabledDwordWrite::with_all_bytes_enabled(6)),
        )
        .await
    );
    assert!(log.lock().writes.is_empty());
    assert_eq!(read_cfg(&device, 4) & 6, 0);
    assert!(host.queue.split().0.read().now_or_never().is_none());
    drop((device, eject, added));
    client.shutdown().await;
}

// Test: Return oversized, undecodable and explicit failure replies to public TDISP queries.
// Expected: Each query reports a transport error; the worker remains usable for later requests.
#[async_test]
async fn invalid_tdisp_responses_fail_without_poisoning_the_worker(driver: DefaultDriver) {
    let (mut host, client, mut devices, added, _log) = connect(&driver, &[description(0, 1)]).await;
    let (device, eject) = host.init(devices.pop().unwrap(), [0; 6]).await;
    let oversized = protocol::VpciTdispCommandHeaderReply {
        status: protocol::Status::SUCCESS,
        slot: protocol::SlotNumber::from_bits(0),
        data_length: protocol::MAX_VPCI_TDISP_COMMAND_SIZE as u64 + 1,
    };
    let mut malformed = protocol::VpciTdispCommandHeaderReply {
        status: protocol::Status::SUCCESS,
        slot: protocol::SlotNumber::from_bits(0),
        data_length: 8,
    }
    .as_bytes()
    .to_vec();
    malformed.extend_from_slice(&[0xff; 8]);
    for reply in [
        oversized.as_bytes().to_vec(),
        malformed,
        protocol::Status::NOT_SUPPORTED.as_bytes().to_vec(),
        protocol::Status::UNSUCCESSFUL.as_bytes().to_vec(),
    ] {
        let query = device
            .tdisp()
            .get_device_interface_info(TDISP_MOCK_GUEST_PROTOCOL);
        let respond = async {
            let (tx, bytes) = host.expect(protocol::MessageType::VPCI_TDISP_COMMAND).await;
            let header = protocol::VpciTdispCommandHeader::read_from_prefix(&bytes)
                .unwrap()
                .0;
            assert_eq!(u32::from(header.slot), 0);
            host.complete(tx, &reply).await;
        };
        let (result, ()) = vmbus_channel::test_helpers::with_timeout(&driver, async {
            futures::join!(query, respond)
        })
        .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("failed to send tdisp command"));
    }
    drop((device, eject, added));
    client.shutdown().await;
}
