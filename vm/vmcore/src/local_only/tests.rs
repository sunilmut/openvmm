// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{LocalOnly, LocalOnlyError};
use mesh::payload::SerializedMessage;
use std::sync::Arc;
use test_with_tracing::test;

#[derive(mesh::MeshPayload)]
struct Envelope {
    value: LocalOnly<Arc<u32>>,
}

#[derive(mesh::MeshPayload)]
struct Empty;

// Test: Clone a local-only shared object and send it through an in-process mesh channel.
// Expected: Cloning/conversion/channel delivery preserve Arc identity, not merely an equal copy of the value.
#[test]
fn local_mesh_delivery_preserves_shared_object_identity() {
    let value = Arc::new(0xfeed_beef);
    let wrapped: LocalOnly<_> = value.clone().into();
    let cloned = wrapped.clone();
    assert!(Arc::ptr_eq(&value, &cloned.0));
    let (send, mut receive) = mesh::channel::<Envelope>();
    send.send(Envelope { value: cloned });
    let received = futures::executor::block_on(receive.recv()).unwrap();
    assert!(Arc::ptr_eq(&value, &received.value.0));
}

// Test: Serialize a local-only object or omit its field entirely before decoding the destination message.
// Expected: Both explicit and default field decoding reject the process-bound object with LocalOnlyError in the error chain.
#[test]
fn serialized_and_missing_local_only_fields_fail_with_the_typed_boundary_error() {
    for serialized in [
        SerializedMessage::from_message(Envelope {
            value: Arc::new(7).into(),
        }),
        SerializedMessage::from_message(Empty),
        SerializedMessage {
            data: vec![0x0a, 0x00],
            resources: Vec::new(),
        },
    ] {
        let result: Result<Envelope, _> = serialized.into_message();
        let error = result
            .err()
            .expect("local-only message must not deserialize");
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut found = false;
        while let Some(error) = cause {
            if error.is::<LocalOnlyError>() {
                found = true;
                break;
            }
            cause = error.source();
        }
        assert!(found, "missing LocalOnlyError in {error:?}");
    }
}
