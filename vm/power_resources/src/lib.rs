// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Power request resources, for powering off, restarting, and hibernating VMs.

#![forbid(unsafe_code)]

use mesh::payload::Protobuf;
use std::sync::Arc;
use vm_resource::CanResolveTo;
use vm_resource::ResourceKind;

/// Resource kind for power requests.
pub enum PowerRequestHandleKind {}

impl ResourceKind for PowerRequestHandleKind {
    const NAME: &'static str = "power_request";
}

impl CanResolveTo<PowerRequestClient> for PowerRequestHandleKind {
    type Input<'a> = ();
}

/// Type erased object for requesting power state changes.
#[derive(Clone)]
pub struct PowerRequestClient(Arc<dyn Fn(PowerRequest) + Send + Sync>);

impl PowerRequestClient {
    /// Issues a power request.
    pub fn power_request(&self, request: PowerRequest) {
        (self.0)(request)
    }
}

impl<T: 'static + Fn(PowerRequest) + Send + Sync> From<T> for PowerRequestClient {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

/// A VM power request.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Protobuf)]
pub enum PowerRequest {
    /// Power off the VM.
    PowerOff,
    /// Restart the VM.
    Reset,
    /// Hibernate the VM.
    Hibernate,
    /// Triple fault the VM.
    TripleFault {
        /// The VP that caused the triple fault.
        vp: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::payload::decode;
    use mesh::payload::encode;
    use test_with_tracing::test;

    // Test: Deliver serialized power requests through original and cloned clients.
    // Expected: Every request arrives exactly once with its kind and fault VP
    //       intact after the original is dropped; the final client releases
    //       the delivery channel.
    #[test]
    fn cloned_clients_preserve_serialized_power_request_delivery() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let client = PowerRequestClient::from(move |request| sender.send(request).unwrap());
        let survivor = client.clone();
        let requests = [
            PowerRequest::PowerOff,
            PowerRequest::Reset,
            PowerRequest::Hibernate,
            PowerRequest::TripleFault { vp: 0 },
            PowerRequest::TripleFault { vp: u32::MAX },
        ];
        for request in &requests[..3] {
            client.power_request(decode(&encode(*request)).unwrap());
        }
        drop(client);
        for request in &requests[3..] {
            let delivered = decode(&encode(*request)).unwrap();
            let peer = survivor.clone();
            std::thread::spawn(move || peer.power_request(delivered))
                .join()
                .unwrap();
        }
        drop(survivor);
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), requests);
        assert_eq!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
    }
}
