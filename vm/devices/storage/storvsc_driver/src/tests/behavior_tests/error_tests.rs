// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn version() -> storvsp_protocol::ProtocolVersion {
    storvsp_protocol::ProtocolVersion {
        major_minor: storvsp_protocol::VERSION_BLUE,
        reserved: 0,
    }
}

// Test: Disconnect the peer before initializing the public storage driver.
// Expected: Public run returns an error without panicking on the channel error.
#[async_test]
#[ignore = "Confirmed product bug: public run unwraps the negotiation channel error and panics"]
async fn known_bug_public_run_returns_error_when_peer_disconnects(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut storvsc = StorvscDriver::new(&source, version());
    let (guest, host) = connected_async_channels(16384);
    drop(host);
    assert!(storvsc.run(guest, 0).await.is_err());
}

// Test: Drop the host channel only after a submitted SCSI request is observed, then submit another request after stopping the driver.
// Expected: The in-flight request completes with Cancelled rather than hanging or reporting success; the later request reports a closed completion channel instead of reaching a dead worker.
#[async_test]
async fn channel_close_cancels_pending_request_and_stopped_requests_fail(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let mut storvsc = StorvscDriver::new(&source, version());
    let (guest, host) = connected_async_channels(16384);
    let request = generate_read_packet(0, 0, 0, 7, 512);
    let server = async {
        let mut queue = Queue::new(host).unwrap();
        for operation in [
            storvsp_protocol::Operation::BEGIN_INITIALIZATION,
            storvsp_protocol::Operation::QUERY_PROTOCOL_VERSION,
            storvsp_protocol::Operation::QUERY_PROPERTIES,
            storvsp_protocol::Operation::END_INITIALIZATION,
        ] {
            respond(
                &mut queue,
                operation,
                storvsp_protocol::ChannelProperties::new_zeroed().as_bytes(),
            )
            .await;
        }
        let (mut reader, _) = queue.split();
        let packet = reader.read().await.unwrap();
        let IncomingPacket::Data(data) = &*packet else {
            panic!("expected data request");
        };
        let mut input = data.reader();
        let header: storvsp_protocol::Packet = input.read_plain().unwrap();
        assert_eq!(header.operation, storvsp_protocol::Operation::EXECUTE_SRB);
        assert_eq!(input.read_n::<u8>(input.len()).unwrap(), request.as_bytes());
    };
    let client = async {
        storvsc.run(guest, 0).await.unwrap();
        assert!(matches!(
            storvsc.send_request(&request, 0x1000, 512).await,
            Err(StorvscError(StorvscErrorInner::Cancelled))
        ));
        storvsc.stop().await;
        assert!(matches!(
            storvsc.send_request(&request, 0x1000, 512).await,
            Err(StorvscError(StorvscErrorInner::CompletionError(_)))
        ));
    };
    futures::join!(server, client);
}

// Test: Return a wrong transaction, failed storage status, or in-band data instead of a completion during initialization.
// Expected: Negotiation returns the precise transaction/status/packet-type error, never marks initialization complete, and rejects an unsupported version with its dedicated error.
#[async_test]
async fn negotiation_rejects_mismatched_completions_and_unsupported_version(
    _driver: DefaultDriver,
) {
    for mode in 0..4 {
        let (guest, host) = connected_async_channels(16384);
        let (_sender, receiver) = mesh_channel::channel();
        let mut storvsc = Storvsc::new(guest, version(), receiver).unwrap();
        let server = async {
            let mut queue = Queue::new(host).unwrap();
            if mode == 3 {
                respond(
                    &mut queue,
                    storvsp_protocol::Operation::BEGIN_INITIALIZATION,
                    &[],
                )
                .await;
            }
            let (mut reader, mut writer) = queue.split();
            let packet = reader.read().await.unwrap();
            let IncomingPacket::Data(data) = &*packet else {
                panic!("expected request");
            };
            let transaction = data.transaction_id().unwrap();
            drop(packet);
            let header = storvsp_protocol::Packet {
                operation: storvsp_protocol::Operation::COMPLETE_IO,
                flags: 0,
                status: if mode >= 2 {
                    storvsp_protocol::NtStatus::INVALID_DEVICE_STATE
                } else {
                    storvsp_protocol::NtStatus::SUCCESS
                },
            };
            let padding = [0; storvsp_protocol::SCSI_REQUEST_LEN_MAX];
            writer
                .batched()
                .try_write(&OutgoingPacket {
                    transaction_id: if mode == 0 {
                        transaction + 17
                    } else {
                        transaction
                    },
                    packet_type: if mode == 1 {
                        OutgoingPacketType::InBandWithCompletion
                    } else {
                        OutgoingPacketType::Completion
                    },
                    payload: &[header.as_bytes(), &padding],
                })
                .unwrap();
        };
        let ((), result) = futures::join!(server, storvsc.negotiate());
        let error = result.unwrap_err();
        match mode {
            0 => assert!(matches!(
                error,
                StorvscError(StorvscErrorInner::PacketError(
                    PacketError::UnexpectedTransaction(18)
                ))
            )),
            1 => assert!(matches!(
                error,
                StorvscError(StorvscErrorInner::PacketError(
                    PacketError::InvalidPacketType
                ))
            )),
            2 => assert!(matches!(
                error,
                StorvscError(StorvscErrorInner::PacketError(
                    PacketError::UnexpectedStatus(storvsp_protocol::NtStatus::INVALID_DEVICE_STATE)
                ))
            )),
            3 => assert!(matches!(
                error,
                StorvscError(StorvscErrorInner::UnsupportedProtocolVersion)
            )),
            _ => unreachable!(),
        }
        assert!(!storvsc.has_negotiated);
    }
}
