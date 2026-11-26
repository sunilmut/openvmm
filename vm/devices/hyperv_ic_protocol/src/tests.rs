// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromZeros;

// Test: Decode an independently framed IC response and emit a request using
//       asymmetric version components and a nonzero transaction ID.
// Expected: Protocol versions, status and directional flags retain their wire
//       positions; version diagnostics distinguish the major and minor.
#[test]
fn common_header_wire_interoperability() {
    let response = [
        3, 0, 0, 0, 4, 0, 4, 0, 1, 0, 24, 0, 5, 0, 0, 128, 0xa7, 5, 0, 0,
    ];
    let mut header = Header::read_from_bytes(&response).unwrap();
    assert_eq!(header.framework_version, Version::new(3, 0));
    assert_eq!(header.message_version, Version::new(4, 1));
    assert_eq!(header.framework_version.to_string(), "3.0");
    assert_eq!(header.message_version.to_string(), "4.1");
    assert_eq!(header.message_type, MessageType::TIME_SYNC);
    assert_eq!(header.message_size, 24);
    assert_eq!(header.status, Status(0x80000005));
    assert_eq!(header.transaction_id, 0xa7);
    assert!(header.flags.transaction());
    assert!(header.flags.response());
    assert!(!header.flags.request());
    header.status = Status::SUCCESS;
    header.flags = HeaderFlags::new().with_transaction(true).with_request(true);
    let mut expected = response;
    expected[12..16].fill(0);
    expected[17] = 3;
    assert_eq!(header.as_bytes(), expected);
}

// Test: Decode a peer's version negotiation payload with multiple independent
//       framework and message versions and preserve future minor versions.
// Expected: Counts partition the trailing version list, and a re-encoded
//       response uses the chosen version without swapping its components.
#[test]
fn negotiation_payload_wire_interoperability() {
    let bytes = [
        2, 0, 3, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 4, 0, 1, 0, 4, 0, 0, 0, 3, 0, 0, 0,
    ];
    let (message, rest) = NegotiateMessage::read_from_prefix(&bytes).unwrap();
    assert_eq!(message.framework_version_count, 2);
    assert_eq!(message.message_version_count, 3);
    let versions: Vec<_> = rest
        .chunks_exact(4)
        .map(|bytes| Version::read_from_bytes(bytes).unwrap())
        .collect();
    assert_eq!(
        versions,
        [
            Version::new(3, 0),
            Version::new(1, 0),
            Version::new(4, 1),
            Version::new(4, 0),
            Version::new(3, 0),
        ]
    );
    assert!(versions[2] > versions[3]);
    assert!(versions[3] > versions[0]);
    let reply = NegotiateMessage {
        framework_version_count: 1,
        message_version_count: 1,
        reserved: 0,
    };
    let output = [
        reply.as_bytes(),
        versions[0].as_bytes(),
        versions[2].as_bytes(),
    ]
    .concat();
    assert_eq!(output, [1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 1, 0]);
}

// Test: Emit legacy and version-four time samples containing distinct full-width
//       timestamps and independently decode a version-four peer sample.
// Expected: Old round-trip time and new VM reference time occupy their defined
//       fields; sync/sample flags and NTP metadata do not overlap timestamps.
#[test]
fn time_sample_wire_interoperability() {
    use crate::timesync::*;

    let legacy = TimesyncMessage {
        parent_time: 0x0123456789abcdefu64.into(),
        child_time: 0xfedcba9876543210u64.into(),
        round_trip_time: 0x8877665544332211u64.into(),
        flags: TimesyncFlags::new().with_sync(true),
        reserved: [0; 3],
    };
    assert_eq!(
        legacy.as_bytes(),
        [
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
            0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 0, 0, 0,
        ]
    );
    let bytes = [
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe, 2, 1, 7, 0, 0, 0, 0, 0,
    ];
    let sample = TimesyncMessageV4::read_from_bytes(&bytes).unwrap();
    assert_eq!(sample.parent_time.get(), 0x0123456789abcdef);
    assert_eq!(sample.vm_reference_time, 0xfedcba9876543210);
    assert!(!sample.flags.sync());
    assert!(sample.flags.sample());
    assert_eq!(sample.leap_indicator, 1);
    assert_eq!(sample.stratum, 7);
    let mut emitted = TimesyncMessageV4::new_zeroed();
    emitted.parent_time = sample.parent_time;
    emitted.vm_reference_time = sample.vm_reference_time;
    emitted.flags = TimesyncFlags::new().with_sample(true);
    emitted.leap_indicator = 1;
    emitted.stratum = 7;
    assert_eq!(emitted.as_bytes(), bytes);
}
