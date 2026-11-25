// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::FatalGetError;
use crate::GuestEmulationTransportClient;
use futures_concurrency::future::Join;
use pal_async::task::Task;
use vmbus_async::pipe::MessagePipe;
use vmbus_ring::FlatRingMem;
use zerocopy::FromBytes;

pub struct Host(pub MessagePipe<FlatRingMem>);

impl Host {
    pub async fn receive(&mut self) -> Vec<u8> {
        let mut bytes = vec![0; get_protocol::MAX_MESSAGE_SIZE];
        let len = self.0.recv(&mut bytes).await.unwrap();
        bytes.truncate(len);
        bytes
    }

    pub async fn expect(&mut self, expected: &[u8]) {
        assert_eq!(self.receive().await, expected);
    }

    pub async fn send(&mut self, bytes: &[u8]) {
        self.0.send(bytes).await.unwrap();
    }

    pub async fn exchange<T>(
        &mut self,
        call: impl Future<Output = T>,
        request: &[u8],
        response: &[u8],
    ) -> T {
        let peer = async {
            self.expect(request).await;
            self.send(response).await;
        };
        (call, peer).join().await.0
    }
}

pub async fn setup(
    driver: &DefaultDriver,
) -> (
    GuestEmulationTransportClient,
    Host,
    Task<Result<(), FatalGetError>>,
) {
    let (host, guest) = vmbus_async::pipe::connected_message_pipes(
        get_protocol::MAX_MESSAGE_SIZE + vmbus_ring::PAGE_SIZE,
    );
    let mut host = Host(host);
    let peer = async {
        let request = get_protocol::VersionRequest::read_from_bytes(&host.receive().await).unwrap();
        assert_eq!(request.version, ProtocolVersion::NICKEL_REV2);
        host.send(get_protocol::VersionResponse::new(true).as_bytes())
            .await;
    };
    let (worker, ()) = (
        GuestEmulationTransportWorker::with_pipe(driver, guest),
        peer,
    )
        .join()
        .await;
    let (worker, task) = worker.unwrap();
    (worker.new_client(), host, task)
}

pub async fn barrier(client: &GuestEmulationTransportClient, host: &mut Host) {
    let time = host
        .exchange(
            client.host_time(),
            get_protocol::TimeRequest::new().as_bytes(),
            get_protocol::TimeResponse::new(0, 123, 0, false).as_bytes(),
        )
        .await;
    assert_eq!(time.utc, 123);
}
