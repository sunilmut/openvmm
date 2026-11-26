// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromZeros;

// Test: Decode firmware TDI_INFO responses, including unknown 16-bit statuses.
// Expected: Firmware success, invalid and unbound remain distinct; unrecognized
//       values are rejected without truncating them to a known status.
#[test]
fn tdi_info_status_from_wire() {
    for (raw, expected) in [
        (0u16, Some(TioMsgTdiStatus::Success)),
        (1, Some(TioMsgTdiStatus::Invalid)),
        (2, Some(TioMsgTdiStatus::Unbound)),
        (3, None),
        (0x100, None),
        (0x101, None),
        (0x102, None),
        (u16::MAX, None),
    ] {
        let mut bytes = [0; 192];
        bytes[..2].copy_from_slice(&0x8137u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&raw.to_le_bytes());
        let response = TioMsgTdiInfoRsp::read_from_bytes(&bytes).unwrap();
        assert_eq!(response.guest_device_id, 0x8137);
        assert_eq!(TioMsgTdiStatus::from_u16(response.tdi_status), expected);
        assert_eq!(response.as_bytes(), bytes);
    }
}

// Test: Decode distinct TDI_INFO digests, algorithm fields and a full-width
//       report counter from an independently constructed firmware response.
// Expected: Adjacent 48-byte digests and the trailing counter remain independent.
#[test]
fn tdi_info_attestation_fields_from_wire() {
    let mut bytes = [0; 192];
    bytes[..2].copy_from_slice(&0x1234u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x10203040u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0x50607080u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0xfedcba9876543210u64.to_le_bytes());
    bytes[32..80].fill(0x31);
    bytes[80..128].fill(0x52);
    bytes[128..176].fill(0x73);
    bytes[176..184].copy_from_slice(&0x8877665544332211u64.to_le_bytes());
    let response = TioMsgTdiInfoRsp::read_from_bytes(&bytes).unwrap();
    assert_eq!(response.guest_device_id, 0x1234);
    assert_eq!(response.meas_digest_info, 0x10203040);
    assert_eq!(response.lock_flags, 0x50607080);
    assert_eq!(response.spdm_algos, 0xfedcba9876543210);
    assert_eq!(response.certs_digest, [0x31; 48]);
    assert_eq!(response.meas_digest, [0x52; 48]);
    assert_eq!(response.interface_report_digest, [0x73; 48]);
    assert_eq!(response.tdi_report_count, 0x8877665544332211);
    assert_eq!(response.as_bytes(), bytes);
}

// Test: Serialize MMIO validation requests for all independent force/validated
//       combinations with a high GPA, nonzero offset and distinct range ID.
// Expected: Flags use separate low bits, page count/offset are not interchanged,
//       and all reserved wire bytes remain zero.
#[test]
fn mmio_validation_request_wire_fields() {
    for (validated, force, expected_flags) in [
        (false, false, 0),
        (true, false, 1),
        (false, true, 2),
        (true, true, 3),
    ] {
        let mut request = TioMsgMmioValidateReq::new_zeroed();
        request.guest_device_id = 0x3412;
        request.subrange_base = 0x00123456789ab000;
        request.subrange_page_count = 0x10203;
        request.range_offset = 0x40506;
        request.range_id = 0x7856;
        request.validated_flags = TioMsgMmioValidateReqFlags::new()
            .with_validated(validated)
            .with_force_validated(force);
        let mut expected = [0; 48];
        expected[..2].copy_from_slice(&[0x12, 0x34]);
        expected[16..24].copy_from_slice(&[0, 0xb0, 0x9a, 0x78, 0x56, 0x34, 0x12, 0]);
        expected[24..28].copy_from_slice(&[3, 2, 1, 0]);
        expected[28..32].copy_from_slice(&[6, 5, 4, 0]);
        expected[32] = expected_flags;
        expected[34..36].copy_from_slice(&[0x56, 0x78]);
        assert_eq!(request.as_bytes(), expected);
    }
}
