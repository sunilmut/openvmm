// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::*;
use test_with_tracing::test;
use vmcore::vm_task::{SingleDriverBackend, VmTaskDriverSource};

mod error_tests;

async fn respond<M: RingMem>(
    queue: &mut Queue<M>,
    expected: storvsp_protocol::Operation,
    response: &[u8],
) -> Vec<u8> {
    let (mut reader, mut writer) = queue.split();
    let packet = reader.read().await.unwrap();
    let IncomingPacket::Data(data) = &*packet else {
        panic!("expected data request");
    };
    let transaction = data.transaction_id().unwrap();
    let mut input = data.reader();
    let header: storvsp_protocol::Packet = input.read_plain().unwrap();
    assert_eq!(header.operation, expected);
    assert_eq!(header.status, storvsp_protocol::NtStatus::SUCCESS);
    let body = input.read_n(input.len()).unwrap();
    drop(packet);
    let header = storvsp_protocol::Packet {
        operation: storvsp_protocol::Operation::COMPLETE_IO,
        flags: 0,
        status: storvsp_protocol::NtStatus::SUCCESS,
    };
    let padding = vec![0; storvsp_protocol::SCSI_REQUEST_LEN_MAX - response.len()];
    writer
        .batched()
        .try_write(&OutgoingPacket {
            transaction_id: transaction,
            packet_type: OutgoingPacketType::Completion,
            payload: &[header.as_bytes(), response, &padding],
        })
        .unwrap();
    body
}

// Test: Use the public driver before initialization, negotiate it against a recording ring peer, exchange binary SCSI requests and rerun over a fresh channel.
// Expected: Before run it returns Uninitialized; both runs preserve request identity/CDB/transfer length in successful completions, and stop/rerun does not leave the old worker or request channel in use.
#[async_test]
async fn public_driver_runs_stops_and_reconnects_with_exact_completions(driver: DefaultDriver) {
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let mut storvsc = StorvscDriver::new(
        &source,
        storvsp_protocol::ProtocolVersion {
            major_minor: storvsp_protocol::VERSION_BLUE,
            reserved: 0,
        },
    );
    let request = generate_write_packet(2, 1, 3, 0x1234, 4096);
    assert!(matches!(
        storvsc.send_request(&request, 0x1000, 4096).await,
        Err(StorvscError(StorvscErrorInner::Uninitialized))
    ));
    for iteration in 0..2 {
        let (guest, host) = connected_async_channels(16384);
        let read = generate_read_packet(2, 1, 3, 0x1234, 4096);
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
            for expected in [request, read] {
                assert_eq!(
                    respond(
                        &mut queue,
                        storvsp_protocol::Operation::EXECUTE_SRB,
                        expected.as_bytes()
                    )
                    .await,
                    expected.as_bytes()
                );
            }
        };
        let client = async {
            storvsc.run(guest, iteration).await.unwrap();
            for expected in [request, read] {
                let completion = storvsc.send_request(&expected, 4096, 4096).await.unwrap();
                assert_eq!(completion.as_bytes(), expected.as_bytes());
            }
            storvsc.stop().await;
        };
        futures::join!(server, client);
    }
}

// Test: Submit three outstanding worker requests over a real ring and return their distinct SCSI completions in a different order.
// Expected: Transaction IDs remain distinct, each receiver gets only its own complete result, and unrelated receivers stay pending until their corresponding reply arrives.
#[async_test]
async fn reordered_completions_preserve_outstanding_request_identity(_driver: DefaultDriver) {
    let (guest, host) = connected_async_channels(16384);
    let (_sender, receiver) = mesh_channel::channel();
    let mut storvsc = Storvsc::new(
        guest,
        storvsp_protocol::ProtocolVersion {
            major_minor: storvsp_protocol::VERSION_BLUE,
            reserved: 0,
        },
        receiver,
    )
    .unwrap();
    let mut queue = storvsc.queue;
    let mut host = Queue::new(host).unwrap();
    let requests = [
        generate_write_packet(2, 1, 3, 7, 512),
        generate_read_packet(1, 2, 4, 0x1122, 1024),
        generate_read_packet(3, 0, 5, 0x3344, 2048),
    ];
    let mut receivers = Vec::new();
    let mut transactions = Vec::new();
    for request in &requests {
        let (sender, receiver) = mesh_channel::channel();
        storvsc
            .inner
            .send_request(request, 0x1000, 4096, &mut queue.split().1, sender)
            .unwrap();
        receivers.push(receiver);
        let (mut reader, _) = host.split();
        let packet = reader.read().await.unwrap();
        let IncomingPacket::Data(data) = &*packet else {
            panic!("expected data request");
        };
        let transaction = data.transaction_id().unwrap();
        assert!(!transactions.contains(&transaction));
        transactions.push(transaction);
        let mut input = data.reader();
        let header: storvsp_protocol::Packet = input.read_plain().unwrap();
        assert_eq!(header.operation, storvsp_protocol::Operation::EXECUTE_SRB);
        assert_eq!(input.read_n::<u8>(input.len()).unwrap(), request.as_bytes());
    }
    let mut completed = [false; 3];
    for index in [2, 0, 1] {
        let header = storvsp_protocol::Packet {
            operation: storvsp_protocol::Operation::COMPLETE_IO,
            flags: 0,
            status: storvsp_protocol::NtStatus::SUCCESS,
        };
        host.split()
            .1
            .batched()
            .try_write(&OutgoingPacket {
                transaction_id: transactions[index],
                packet_type: OutgoingPacketType::Completion,
                payload: &[header.as_bytes(), requests[index].as_bytes()],
            })
            .unwrap();
        let (mut reader, _) = queue.split();
        let packet = reader.read().await.unwrap();
        storvsc.inner.handle_packet(packet.as_ref()).unwrap();
        let result = receivers[index].recv().await.unwrap().completion.unwrap();
        assert_eq!(result.as_bytes(), requests[index].as_bytes());
        completed[index] = true;
        for (index, receiver) in receivers.iter_mut().enumerate() {
            if !completed[index] {
                assert!(receiver.recv().now_or_never().is_none());
            }
        }
    }
}
