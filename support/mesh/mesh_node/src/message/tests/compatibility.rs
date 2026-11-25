// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::local_node::Port;
use crate::resource::SerializedMessage;
use test_with_tracing::test;

// Test: Encode nested messages from both owned values and borrowed wire views.
// Expected: Both representations decode to the same complete payload.
#[test]
fn nested_owned_and_borrowed_messages_preserve_their_payloads() {
    let bytes = mesh_protobuf::encode((String::from("nested\0value"), 37u32));
    for message in [
        Message::new((String::from("nested\0value"), 37u32)),
        Message::serialized(&bytes, vec![]),
    ] {
        let serialized = SerializedMessage::from_message((message,));
        let (message,): (OwnedMessage,) = OwnedMessage::serialized(serialized).parse().unwrap();
        assert_eq!(
            message.parse::<(String, u32)>().unwrap(),
            (String::from("nested\0value"), 37)
        );
    }
    let (data, resources) = Message::from(OwnedMessage::default()).serialize();
    assert!(data.is_empty());
    assert!(resources.is_empty());
}

// Test: Decode repeated occurrences of a nested owned-message field.
// Expected: Protobuf merging retains earlier fields absent from the later message.
#[test]
fn repeated_nested_messages_merge_instead_of_replacing_earlier_fields() {
    let first = SerializedMessage::from_message((OwnedMessage::new((11u32, String::new())),));
    let second =
        SerializedMessage::from_message((OwnedMessage::new((0u32, String::from("second"))),));
    let mut data = first.data;
    data.extend(second.data);
    let (message,): (OwnedMessage,) = OwnedMessage::serialized(SerializedMessage {
        data,
        resources: vec![],
    })
    .parse()
    .unwrap();
    assert_eq!(
        message.parse::<(u32, String)>().unwrap(),
        (11, String::from("second"))
    );
}

// Test: Serialize and decode a port capability, then decode a message lacking it.
// Expected: The transferred endpoint stays live, while a missing port is an error.
#[test]
fn serialized_port_fields_transfer_ownership_and_require_a_resource() {
    let (port, peer) = Port::new_pair();
    let wire = OwnedMessage::new((port,)).serialize();
    assert_eq!(wire.resources.len(), 1);
    let (port,): (Port,) = OwnedMessage::serialized(wire).parse().unwrap();
    assert!(!peer.is_closed().unwrap());
    drop(port);
    assert!(peer.is_closed().unwrap());
    assert!(Message::serialized(&[], vec![]).parse::<(Port,)>().is_err());
}
