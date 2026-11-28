// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::poll;
use mesh::CancelContext;
use std::task::Poll;
use std::time::Duration;
use test_with_tracing::test;
use vmbus_channel::bus::ChannelType;
use vmbus_core::HvsockConnectRequest;

pub(super) async fn bounded<F: Future>(future: F) -> F::Output {
    CancelContext::new()
        .with_timeout(Duration::from_secs(5))
        .until_cancelled(future)
        .await
        .expect("hvsocket test timed out")
}

// Test: Connect directly from the host to a guest hvsocket and exchange data.
// Expected: The offered service is correct and bytes plus half-close propagate in both directions.
#[async_test]
async fn direct_host_connection_relays_data_and_half_closes(driver: DefaultDriver) {
    bounded(async {
        let memory = GuestMemory::allocate(4 * 4096);
        let (offers, mut received) = mesh::channel();
        let channel = HvsockRelayChannel::new();
        let _server = channel.server_half;
        let relay = HvsockRelay::new(
            driver.clone(),
            Arc::new(TestBus {
                memory: memory.clone(),
                offers,
            }),
            channel.relay_half,
            None,
            None,
        )
        .unwrap();
        let service = Guid::new_random();
        let mut ctx = CancelContext::new();
        let connect = relay.connect(&mut ctx, service);
        let offer = received.next().await.unwrap();
        assert_eq!(offer.params.interface_id, service);
        assert!(matches!(
            offer.params.channel_type,
            ChannelType::HvSocket {
                is_connect: true,
                is_for_container: false,
                ..
            }
        ));
        let (mut guest, socket) =
            futures::join!(open_guest_pipe(&driver, &memory, &offer), connect);
        let mut host = PolledSocket::new(&driver, socket.unwrap()).unwrap();
        host.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        guest.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        guest.write_all(b"pong").await.unwrap();
        host.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        host.close().await.unwrap();
        assert_eq!(guest.read(&mut payload).await.unwrap(), 0);
        guest.close().await.unwrap();
        assert_eq!(host.read(&mut payload).await.unwrap(), 0);
    })
    .await;
}

// Test: Cancel a host connection after its channel is offered but before the guest opens it.
// Expected: Connect reports cancellation and the outstanding channel request receiver is released.
#[async_test]
async fn cancelled_host_connection_releases_the_unopened_offer(driver: DefaultDriver) {
    bounded(async {
        let (offers, mut received) = mesh::channel();
        let channel = HvsockRelayChannel::new();
        let _server = channel.server_half;
        let relay = HvsockRelay::new(
            driver.clone(),
            Arc::new(TestBus {
                memory: GuestMemory::allocate(4 * 4096),
                offers,
            }),
            channel.relay_half,
            None,
            None,
        )
        .unwrap();
        let (mut ctx, cancel) = CancelContext::new().with_cancel();
        let connect = relay.connect(&mut ctx, Guid::new_random());
        let offer = received.next().await.unwrap();
        drop(cancel);
        assert!(connect.await.is_err());
        let response = offer
            .request_send
            .call(
                ChannelRequest::Gpadl,
                GpadlRequest {
                    id: GpadlId(1),
                    count: 1,
                    buf: vec![4096, 0],
                },
            )
            .await;
        assert!(response.is_err());
    })
    .await;
}

// Test: Request guest-to-host connections without a listener path or with a rejected offer.
// Expected: Each request receives one failed response preserving its service and endpoint IDs.
#[async_test]
async fn guest_connection_failures_always_report_the_original_request(driver: DefaultDriver) {
    bounded(async {
        for configured in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("vsock");
            let service = Guid::new_random();
            let _listener =
                UnixListener::bind(dir.path().join(format!("vsock_{service}"))).unwrap();
            let path = configured.then_some(base);
            let (offers, mut received) = mesh::channel();
            let channel = HvsockRelayChannel::new();
            let mut server = channel.server_half;
            let _relay = HvsockRelay::new(
                driver.clone(),
                Arc::new(OfferRecorder(offers)),
                channel.relay_half,
                path.clone(),
                None,
            )
            .unwrap();
            let request = HvsockConnectRequest {
                service_id: service,
                endpoint_id: Guid::new_random(),
                silo_id: Guid::new_random(),
                hosted_silo_unaware: false,
            };
            server.request_send.send(request);
            let response = server.response_receive.next().await.unwrap();
            assert!(!response.success);
            assert_eq!(response.service_id, request.service_id);
            assert_eq!(response.endpoint_id, request.endpoint_id);
            if path.is_some() {
                let offer = received.next().await.unwrap();
                assert_eq!(offer.interface_id, request.service_id);
                assert_eq!(offer.instance_id, request.endpoint_id);
            }
            assert!(matches!(
                poll!(server.response_receive.next()),
                Poll::Pending
            ));
        }
    })
    .await;
}

// Test: Request a host Unix service from the guest and open its offered hvsocket channel.
// Expected: Success precedes opening, host connection waits for the guest, and payloads flow both ways.
#[async_test]
async fn guest_connection_opens_host_socket_only_after_channel_open(driver: DefaultDriver) {
    bounded(async {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vsock");
        let service = Guid::new_random();
        let path = dir.path().join(format!("vsock_{service}"));
        let mut listener = PolledSocket::new(&driver, UnixListener::bind(&path).unwrap()).unwrap();
        let memory = GuestMemory::allocate(4 * 4096);
        let (offers, mut received) = mesh::channel();
        let channel = HvsockRelayChannel::new();
        let mut server = channel.server_half;
        let _relay = HvsockRelay::new(
            driver.clone(),
            Arc::new(TestBus {
                memory: memory.clone(),
                offers,
            }),
            channel.relay_half,
            Some(base),
            None,
        )
        .unwrap();
        let endpoint = Guid::new_random();
        server.request_send.send(HvsockConnectRequest {
            service_id: service,
            endpoint_id: endpoint,
            silo_id: Guid::ZERO,
            hosted_silo_unaware: false,
        });
        let offer = received.next().await.unwrap();
        assert_eq!(offer.params.interface_id, service);
        assert_eq!(offer.params.instance_id, endpoint);
        assert!(matches!(
            offer.params.channel_type,
            ChannelType::HvSocket {
                is_connect: false,
                ..
            }
        ));
        let response = server.response_receive.next().await.unwrap();
        assert!(response.success);
        assert_eq!(response.service_id, service);
        assert_eq!(response.endpoint_id, endpoint);
        assert!(matches!(
            poll!(std::pin::pin!(listener.accept())),
            Poll::Pending
        ));
        let (mut guest, accepted) =
            futures::join!(open_guest_pipe(&driver, &memory, &offer), listener.accept());
        let mut host = PolledSocket::new(&driver, accepted.unwrap().0).unwrap();
        guest.write_all(b"data").await.unwrap();
        let mut payload = [0; 4];
        host.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"data");
        host.write_all(b"back").await.unwrap();
        guest.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"back");
        guest.close().await.unwrap();
        assert_eq!(host.read(&mut payload).await.unwrap(), 0);
        host.close().await.unwrap();
        assert_eq!(guest.read(&mut payload).await.unwrap(), 0);
    })
    .await;
}
