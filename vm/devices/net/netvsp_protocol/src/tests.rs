// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rndisprot::*;
use net_backend_core::VlanMetadata;
use test_with_tracing::test;
use zerocopy::{FromBytes, IntoBytes};

// Test: Change IPv4/TCP checksum metadata into IPv6/UDP metadata.
// Expected: Exact wire flags and header offsets change without disturbing reserved
//       bits; the ten-bit offset boundary cannot overwrite adjacent fields.
#[test]
fn transmit_checksum_profiles_preserve_reserved_wire_bits() {
    let tcp4 = TxTcpIpChecksumInfo(u32::MAX)
        .set_is_ipv4(true)
        .set_is_ipv6(false)
        .set_tcp_checksum(true)
        .set_udp_checksum(false)
        .set_ip_header_checksum(true)
        .set_tcp_header_offset(34);
    assert_eq!(tcp4.as_bytes(), &[0xf5, 0xff, 0x22, 0xfc]);
    assert!(tcp4.is_ipv4());
    assert!(!tcp4.is_ipv6());
    assert!(tcp4.tcp_checksum());
    assert!(!tcp4.udp_checksum());
    assert!(tcp4.ip_header_checksum());
    assert_eq!(tcp4.tcp_header_offset(), 34);
    let udp6 = tcp4
        .set_is_ipv4(false)
        .set_is_ipv6(true)
        .set_tcp_checksum(false)
        .set_udp_checksum(true)
        .set_ip_header_checksum(false)
        .set_tcp_header_offset(54);
    assert_eq!(udp6.as_bytes(), &[0xea, 0xff, 0x36, 0xfc]);
    assert!(!udp6.is_ipv4());
    assert!(udp6.is_ipv6());
    assert!(!udp6.tcp_checksum());
    assert!(udp6.udp_checksum());
    assert!(!udp6.ip_header_checksum());
    let boundary = udp6.set_tcp_header_offset(1023);
    assert_eq!(boundary.as_bytes(), &[0xea, 0xff, 0xff, 0xff]);
    assert_eq!(boundary.tcp_header_offset(), 1023);
    let wrapped = boundary.set_tcp_header_offset(1024);
    assert_eq!(wrapped.as_bytes(), &[0xea, 0xff, 0, 0xfc]);
    assert_eq!(wrapped.tcp_header_offset(), 0);
}

// Test: Replace receive checksum evidence for valid TCP and corrupt UDP/TCP packets.
// Expected: Success, failure, loopback and invalid-value qualifiers retain their
//       distinct wire meanings, and replacing evidence clears stale flags.
#[test]
fn receive_checksum_evidence_does_not_mix_success_and_failure_flags() {
    let valid = RxTcpIpChecksumInfo(0xa5a5ffff)
        .set_tcp_checksum_failed(false)
        .set_udp_checksum_failed(false)
        .set_ip_checksum_failed(false)
        .set_tcp_checksum_succeeded(true)
        .set_udp_checksum_succeeded(false)
        .set_ip_checksum_succeeded(true)
        .set_loopback(true)
        .set_tcp_checksum_value_invalid(false)
        .set_ip_checksum_value_invalid(false);
    assert_eq!(valid.as_bytes(), &[0x68, 0xfe, 0xa5, 0xa5]);
    assert!(!valid.tcp_checksum_failed());
    assert!(!valid.udp_checksum_failed());
    assert!(!valid.ip_checksum_failed());
    assert!(valid.tcp_checksum_succeeded());
    assert!(!valid.udp_checksum_succeeded());
    assert!(valid.ip_checksum_succeeded());
    assert!(valid.loopback());
    assert!(!valid.tcp_checksum_value_invalid());
    assert!(!valid.ip_checksum_value_invalid());
    let udp_failure = valid
        .set_tcp_checksum_succeeded(false)
        .set_ip_checksum_succeeded(false)
        .set_loopback(false)
        .set_udp_checksum_failed(true)
        .set_ip_checksum_failed(true)
        .set_ip_checksum_value_invalid(true);
    assert_eq!(udp_failure.as_bytes(), &[6, 0xff, 0xa5, 0xa5]);
    assert!(udp_failure.udp_checksum_failed());
    assert!(udp_failure.ip_checksum_failed());
    assert!(udp_failure.ip_checksum_value_invalid());
    assert!(!udp_failure.tcp_checksum_succeeded());
    let tcp_failure = udp_failure
        .set_udp_checksum_failed(false)
        .set_ip_checksum_failed(false)
        .set_ip_checksum_value_invalid(false)
        .set_tcp_checksum_failed(true)
        .set_tcp_checksum_value_invalid(true)
        .set_ip_checksum_succeeded(true);
    assert_eq!(tcp_failure.as_bytes(), &[0xa1, 0xfe, 0xa5, 0xa5]);
    assert!(tcp_failure.tcp_checksum_failed());
    assert!(tcp_failure.tcp_checksum_value_invalid());
    assert!(!tcp_failure.udp_checksum_failed());
}

// Test: Decode IPv4/IPv6 large-send metadata and maximum-width wire fields.
// Expected: MSS and TCP-header offsets remain distinct from type/IP-version bits;
//       IPv6 packets do not get classified as IPv4.
#[test]
fn large_send_wire_fields_preserve_mss_offset_and_ip_version() {
    for (word, mss, offset, ipv6) in [
        (0x422005b4u32, 1460, 34, false),
        (0xc36005a0, 1440, 54, true),
        (u32::MAX, 1048575, 1023, true),
    ] {
        let info = TcpLsoInfo::read_from_bytes(&word.to_le_bytes()).unwrap();
        assert_eq!(info.mss(), mss);
        assert_eq!(info.tcp_header_offset(), offset);
        assert_eq!(info.is_ipv6(), ipv6);
        assert_eq!(info.is_ipv4(), !ipv6);
    }
}

// Test: Translate VLAN priority, DEI and a full-width ID through RNDIS metadata.
// Expected: All tag fields survive; unrecognized reserved upper bits are not
//       copied into newly produced metadata.
#[test]
fn vlan_conversion_preserves_tag_fields_without_forwarding_reserved_bits() {
    let received = EthVlanInfo::read_from_bytes(&[0xcd, 0xab, 0xad, 0xde]).unwrap();
    let tag = VlanMetadata::from(received);
    assert_eq!(tag.priority(), 5);
    assert!(tag.drop_eligible_indicator());
    assert_eq!(tag.vlan_id(), 0xabc);
    let encoded = EthVlanInfo::from(tag);
    assert_eq!(encoded.as_bytes(), &[0xcd, 0xab, 0, 0]);
    let last_valid = VlanMetadata::new()
        .with_priority(7)
        .with_drop_eligible_indicator(true)
        .with_vlan_id(4094);
    let encoded = EthVlanInfo::from(last_valid);
    assert_eq!(encoded.as_bytes(), &[0xef, 0xff, 0, 0]);
    let decoded = VlanMetadata::from(encoded);
    assert_eq!(decoded.into_bits(), last_valid.into_bits());
}

// Test: Decode a complete offload-control message with asymmetric and future modes.
// Expected: TX/RX directions stay distinct; no-change and unknown modes yield
//       no update rather than accidentally disabling existing offloads.
#[test]
fn offload_control_wire_modes_distinguish_directions_and_no_change() {
    let mut wire = [0u8; 20];
    wire[..4].copy_from_slice(&[0x80, 1, 20, 0]);
    wire[4..9].copy_from_slice(&[0, 1, 2, 3, 4]);
    wire[11] = 1;
    wire[12] = 2;
    let controls = NdisOffloadParameters::read_from_bytes(&wire).unwrap();
    assert_eq!(
        [
            controls.ipv4_checksum.tx_rx(),
            controls.tcp4_checksum.tx_rx(),
            controls.udp4_checksum.tx_rx(),
            controls.tcp6_checksum.tx_rx(),
            controls.udp6_checksum.tx_rx(),
        ],
        [
            None,
            Some((false, false)),
            Some((true, false)),
            Some((false, true)),
            Some((true, true)),
        ]
    );
    assert_eq!(controls.lsov1.enable(), None);
    assert_eq!(controls.lsov2_ipv4.enable(), Some(false));
    assert_eq!(controls.lsov2_ipv6.enable(), Some(true));
    wire[4..13].fill(0xff);
    let future = NdisOffloadParameters::read_from_bytes(&wire).unwrap();
    assert_eq!(future.as_bytes(), wire);
    for checksum in [
        future.ipv4_checksum,
        future.tcp4_checksum,
        future.udp4_checksum,
        future.tcp6_checksum,
        future.udp6_checksum,
    ] {
        assert_eq!(checksum.tx_rx(), None);
    }
    for lso in [future.lsov1, future.lsov2_ipv4, future.lsov2_ipv6] {
        assert_eq!(lso.enable(), None);
    }
}
