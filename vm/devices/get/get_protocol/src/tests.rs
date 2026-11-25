// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod message_tests;
mod service_tests;

fn packet(kind: u8, id: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1, kind];
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn wire<Message: IntoBytes + FromBytes + Immutable + KnownLayout>(
    message: Message,
    expected: &[u8],
) {
    assert_eq!(message.as_bytes(), expected);
    assert_eq!(
        Message::read_from_bytes(expected).unwrap().as_bytes(),
        expected
    );
    for len in 0..expected.len() {
        assert!(Message::read_from_bytes(&expected[..len]).is_err());
    }
}

// Test: Construct each typed header and convert raw headers with every message category, including unknown version/ID values.
// Expected: Header bytes are exact, a category mismatch fails, and matching headers preserve unknown version/ID values without panicking or coercing them.
#[test]
fn typed_headers_validate_category_and_preserve_wire_identity() {
    let request = HeaderHostRequest::new(HostRequests(0x1234));
    assert_eq!(request.as_bytes(), [1, 2, 0x34, 0x12]);
    assert_eq!(request.message_id(), HostRequests(0x1234));
    let response = HeaderHostResponse::new(HostRequests(0x5678));
    assert_eq!(response.as_bytes(), [1, 3, 0x78, 0x56]);
    assert_eq!(response.message_id(), HostRequests(0x5678));
    let host = HeaderHostNotification::new(HostNotifications(0x9abc));
    assert_eq!(host.as_bytes(), [1, 1, 0xbc, 0x9a]);
    assert_eq!(host.message_id(), HostNotifications(0x9abc));
    let guest = HeaderGuestNotification::new(GuestNotifications(0xdef0));
    assert_eq!(guest.as_bytes(), [1, 4, 0xf0, 0xde]);
    assert_eq!(guest.message_id(), GuestNotifications(0xdef0));
    for kind in 0..=u8::MAX {
        let raw = HeaderRaw {
            message_version: MessageVersions(0xa5),
            message_type: MessageTypes(kind),
            message_id: 0x8877,
        };
        macro_rules! check {
            ($header:ty,$kind:expr) => {
                let result = <$header>::try_from(raw);
                assert_eq!(result.is_ok(), kind == $kind);
                if let Ok(header) = result {
                    assert_eq!(header.as_bytes(), [0xa5, kind, 0x77, 0x88]);
                }
            };
        }
        check!(HeaderHostRequest, 2);
        check!(HeaderHostResponse, 3);
        check!(HeaderHostNotification, 1);
        check!(HeaderGuestNotification, 4);
    }
}
