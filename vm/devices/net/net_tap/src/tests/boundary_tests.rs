// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Apply IPv4 and IPv6 length/checksum fixups to truncated headers, invalid IPv4 IHL, and a non-IPv6 header.
// Expected: Invalid or incomplete headers are returned byte-for-byte unchanged rather than being partially overwritten or indexed beyond the frame.
#[test]
fn incomplete_ip_headers_are_not_modified() {
    for (length, version) in [(0, 0x45), (14, 0x45), (33, 0x45), (34, 0x44), (59, 0x4f)] {
        let mut frame = vec![0xa7; length];
        if length > 14 {
            frame[14] = version;
        }
        let original = frame.clone();
        fixup_ipv4_header_checksum(&mut frame, 14);
        assert_eq!(frame, original);
    }
    for (length, version) in [(0, 0x60), (14, 0x60), (53, 0x60), (54, 0x40)] {
        let mut frame = vec![0xa7; length];
        if length > 14 {
            frame[14] = version;
        }
        let original = frame.clone();
        fixup_ipv6_payload_length(&mut frame, 14);
        assert_eq!(frame, original);
    }
}

// Test: Apply GSO checksum-seed repair to missing/truncated IP or transport headers, unsupported IP versions/protocols, and incomplete IPv6 extension-header chains.
// Expected: When the transport checksum field cannot safely be located, the full frame and its original seed are unchanged.
#[test]
fn malformed_gso_headers_never_corrupt_the_frame() {
    let mut cases = vec![vec![], vec![0xa7; 14]];
    for (length, version, protocol) in [
        (33, 0x45, 6),
        (34, 0x44, 6),
        (59, 0x4f, 6),
        (41, 0x45, 6),
        (40, 0x45, 17),
        (64, 0x45, 50),
        (53, 0x60, 6),
        (55, 0x60, 0),
        (56, 0x60, 0),
        (60, 0x60, 17),
        (80, 0x70, 6),
    ] {
        let mut frame = vec![0xa7; length];
        frame[14] = version;
        if version >> 4 == 4 {
            frame[20..22].fill(0);
            frame[23] = protocol;
        } else if version >> 4 == 6 {
            frame[20] = protocol;
            if length > 54 {
                frame[54] = 6;
            }
            if length > 55 {
                frame[55] = 1;
            }
        }
        cases.push(frame);
    }
    for mut frame in cases {
        let original = frame.clone();
        fixup_gso_pseudo_header(&mut frame, 14);
        assert_eq!(frame, original);
    }
}
