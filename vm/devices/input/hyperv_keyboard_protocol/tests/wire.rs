// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Independent synthetic-keyboard negotiation, LED and keystroke wire vectors.

use hyperv_keyboard_protocol::*;
use test_with_tracing::test;
use zerocopy::{FromBytes, IntoBytes};

// Test: Decode independent request, response and LED-message byte vectors.
// Expected: Header/body boundaries, version ordering and full-width response,
//       LED and reserved fields match the native protocol layout.
#[test]
fn negotiation_and_led_wire_layout() {
    let request = [1, 0, 0, 0, 0, 0, 1, 0];
    let (header, body) = MessageHeader::read_from_prefix(&request).unwrap();
    assert_eq!(header.message_type, MESSAGE_PROTOCOL_REQUEST);
    let version = MessageProtocolRequest::read_from_bytes(body).unwrap();
    assert_eq!(version.version, VERSION_WIN8);
    assert_eq!([header.as_bytes(), version.as_bytes()].concat(), request);

    let response = [2, 0, 0, 0, 1, 0, 0, 0x80];
    let (header, body) = MessageHeader::read_from_prefix(&response).unwrap();
    assert_eq!(header.message_type, MESSAGE_PROTOCOL_RESPONSE);
    let accepted = MessageProtocolResponse::read_from_bytes(body).unwrap();
    assert_eq!(accepted.accepted, 0x8000_0001);
    assert_eq!([header.as_bytes(), accepted.as_bytes()].concat(), response);

    let leds = [4, 0, 0, 0, 7, 0x80, 0xef, 0xbe];
    let (header, body) = MessageHeader::read_from_prefix(&leds).unwrap();
    assert_eq!(header.message_type, MESSAGE_SET_LED_INDICATORS);
    let state = MessageLedIndicatorsState::read_from_bytes(body).unwrap();
    assert_eq!(state.led_flags, 0x8007);
    assert_eq!(state.padding, 0xbeef);
    assert_eq!([header.as_bytes(), state.as_bytes()].concat(), leds);
}

// Test: Encode extended break and Unicode events and decode unknown flag bits.
// Expected: Distinct scan-code/padding/flag offsets preserve all eight body
//       bytes and the native E0/E1/break/Unicode flag assignments.
#[test]
fn keystroke_wire_flags_and_reserved_fields() {
    for (make_code, flags, expected) in [
        (
            0x1d,
            KEYSTROKE_IS_BREAK | KEYSTROKE_IS_E0,
            [0x1d, 0, 0, 0, 6, 0, 0, 0],
        ),
        (0x45, KEYSTROKE_IS_E1, [0x45, 0, 0, 0, 8, 0, 0, 0]),
        (0x20ac, KEYSTROKE_IS_UNICODE, [0xac, 0x20, 0, 0, 1, 0, 0, 0]),
    ] {
        let event = MessageKeystroke {
            make_code,
            padding: 0,
            flags,
        };
        let packet = [
            MessageHeader {
                message_type: MESSAGE_EVENT,
            }
            .as_bytes(),
            event.as_bytes(),
        ]
        .concat();
        assert_eq!(&packet[..4], &[3, 0, 0, 0]);
        assert_eq!(&packet[4..], &expected);
    }

    let unknown = [0x34, 0x12, 0xaa, 0x55, 0x0a, 0, 0, 0x80];
    let event = MessageKeystroke::read_from_bytes(&unknown).unwrap();
    assert_eq!(event.make_code, 0x1234);
    assert_eq!(event.padding, 0x55aa);
    assert_eq!(event.flags, 0x8000_000a);
    assert_ne!(event.flags & KEYSTROKE_IS_BREAK, 0);
    assert_ne!(event.flags & KEYSTROKE_IS_E1, 0);
    assert_eq!(event.flags & (KEYSTROKE_IS_E0 | KEYSTROKE_IS_UNICODE), 0);
    assert_eq!(event.as_bytes(), unknown);
}
