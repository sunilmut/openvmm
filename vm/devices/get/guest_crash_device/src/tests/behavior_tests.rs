// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod error_tests;
mod lifecycle_tests;

async fn advance<M: RingMem + Unpin>(
    worker: &mut Worker<M>,
    driver: &DefaultDriver,
) -> anyhow::Result<()> {
    let mut buffer = vec![0; crash::MAX_DUMP_PAYLOAD_SIZE];
    with_timeout(
        driver,
        worker
            .device
            .process_message(&mut worker.channel, &mut buffer),
    )
    .await
}

async fn open_dump<M: RingMem + Unpin>(
    worker: &mut Worker<M>,
    guest: &mut MessagePipe<M>,
    requests: &mut mesh::Receiver<FailableRpc<mesh::OneshotReceiver<()>, File>>,
    file: File,
    driver: &DefaultDriver,
) -> mesh::OneshotReceiver<()> {
    let activity = Guid::from_slice(&[0x31; 16]);
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_START_V1, activity).as_bytes())
        .unwrap();
    advance(worker, driver).await.unwrap();
    let (done, response) = requests.next().await.unwrap().split();
    response.complete(Ok(file));
    advance(worker, driver).await.unwrap();
    let expected = crash::DumpStartResponseV1 {
        header: header(crash::MessageType::RESPONSE_NIX_DUMP_START_V1, activity),
        status: 0,
    };
    assert_eq!(receive(guest, driver).await, expected.as_bytes());
    done
}

// Test: Exchange capability and dump-configuration requests on the same ordinary message ring, preserving distinct activity IDs and recovering the device's original resources.
// Expected: Responses contain exactly the requested activity ID, Linux capability bit, ELF type and configured 64-byte limit; no file RPC occurs, and into_inner returns the still-live request channel with the same limit.
#[async_test]
async fn configuration_replies_preserve_exact_wire_contracts(driver: DefaultDriver) {
    let (host, guest) = connected_async_channels(16384);
    let mut guest = MessagePipe::new(guest).unwrap();
    let (send, mut requests) = mesh::channel();
    let mut worker = worker(host, send);
    let mut buffer = vec![0; crash::MAX_DUMP_PAYLOAD_SIZE];
    let activity = Guid::from_slice(&[0x91; 16]);
    guest
        .try_send(header(crash::MessageType::REQUEST_GET_CAPABILITIES_V1, activity).as_bytes())
        .unwrap();
    with_timeout(
        &driver,
        worker
            .device
            .process_message(&mut worker.channel, &mut buffer),
    )
    .await
    .unwrap();
    let expected = crash::DumpCapabilitiesResponseV1 {
        header: header(crash::MessageType::RESPONSE_GET_CAPABILITIES_V1, activity),
        capabilities: crash::Capabilities::new().with_linux_config_v1(true),
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    let activity = Guid::from_slice(&[0x82; 16]);
    guest
        .try_send(header(crash::MessageType::REQUEST_GET_NIX_DUMP_CONFIG_V1, activity).as_bytes())
        .unwrap();
    with_timeout(
        &driver,
        worker
            .device
            .process_message(&mut worker.channel, &mut buffer),
    )
    .await
    .unwrap();
    let expected = crash::DumpConfigResponseV1 {
        header: header(
            crash::MessageType::RESPONSE_GET_NIX_DUMP_CONFIG_V1,
            activity,
        ),
        config: crash::ConfigV1 {
            max_dump_size: 64,
            dump_type: crash::DumpType::ELF,
        },
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    assert!(requests.next().now_or_never().is_none());
    let (sender, maximum) = worker.device.into_inner();
    assert_eq!(maximum, 64);
    let (done, notification) = mesh::oneshot();
    let response = sender.call_failable(|value| value, notification);
    let request = requests.next().await.unwrap();
    let (notification, request) = request.split();
    request.complete(Ok(tempfile::tempfile().unwrap()));
    assert_eq!(response.await.unwrap().metadata().unwrap().len(), 0);
    done.send(());
    notification.await.unwrap();
}
