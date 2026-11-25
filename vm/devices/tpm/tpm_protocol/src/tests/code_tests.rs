// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tpm20proto::*;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Decode the defined TPM command-code range including reserved holes, round-trip recognized values through the wire wrapper, and reject unknown codes.
// Expected: Each assigned command retains its numeric identity and big-endian bytes; reserved/unknown codes never alias a neighboring command.
#[test]
fn command_codes_preserve_assigned_values_and_reject_reserved_holes() {
    for raw in 0..=0x200 {
        let expected =
            (0x11f..=0x198).contains(&raw) && ![0x123, 0x15a, 0x15f, 0x166, 0x175].contains(&raw);
        let parsed = CommandCodeEnum::from_u32(raw);
        assert_eq!(parsed.is_some(), expected, "code {raw:x}");
        if let Some(parsed) = parsed {
            assert_eq!(parsed as u32, raw);
            let wire = CommandCode::from(parsed);
            assert_eq!(raw, wire);
            assert_eq!(wire.as_bytes(), raw.to_be_bytes());
            assert_eq!(wire.into_enum(), Some(parsed));
        }
    }
    assert!(CommandCodeEnum::from_u32(u32::MAX).is_none());
}

// Test: Decode every 16-bit session tag and known TPM failure/warning/hash identifiers, preserving their wire identities.
// Expected: Exactly the assigned session tags are accepted, known response/hash codes round-trip, and unknown identifiers do not become valid values.
#[test]
fn session_response_and_hash_code_tables_do_not_alias_values() {
    let tags = [
        0x8000, 0x8001, 0x8002, 0x8014, 0x8015, 0x8016, 0x8017, 0x8018, 0x8019, 0x801a, 0x801b,
        0x801c, 0x801d, 0x8021, 0x8022, 0x8023, 0x8024, 0x8029,
    ];
    for raw in 0..=u16::MAX {
        let parsed = SessionTagEnum::from_u16(raw);
        assert_eq!(parsed.is_some(), tags.contains(&raw));
        if let Some(parsed) = parsed {
            assert_eq!(parsed as u16, raw);
            let wire = SessionTag::from(parsed);
            assert_eq!(raw, wire);
            assert_eq!(wire.as_bytes(), raw.to_be_bytes());
        }
    }
    let codes = [
        0, 0x84, 0x85, 0x8b, 0x8e, 0x95, 0x9a, 0x9f, 0x101, 0x145, 0x14a, 0x155, 0x901, 0x902,
        0x903, 0x904, 0x905, 0x906, 0x908, 0x909, 0x90a, 0x920, 0x921, 0x922, 0x923, 0x97f,
    ];
    for raw in 0..=0xa00 {
        assert_eq!(
            ResponseCode::from_u32(raw).map(|code| code as u32),
            codes.contains(&raw).then_some(raw)
        );
    }
    assert!(ResponseCode::from_u32(u32::MAX).is_none());
    for raw in [4u16, 11, 12, 13, 18] {
        let parsed = AlgIdEnum::from_u16(raw).unwrap();
        let wire = AlgId::from(parsed);
        assert_eq!(raw, wire);
        assert_eq!(wire.as_bytes(), raw.to_be_bytes());
    }
    assert!(AlgIdEnum::from_u16(u16::MAX).is_none());
}

// Test: Build the documented provisioned AK and platform-created AK certificate attribute masks.
// Expected: Only the required TPM specification bits are set, including restricted signing/no-DA for AK and platform-created owner/auth read access for its certificate.
#[test]
fn provisioned_key_and_certificate_masks_match_required_bits() {
    assert_eq!(
        crate::expected_ak_attributes().as_bytes(),
        0x00050472u32.to_be_bytes()
    );
    assert_eq!(u32::from(crate::platform_akcert_attributes()), 0x42060004);
    let handle = ReservedHandle::new(TPM20_HT_PERSISTENT, 0x123456);
    assert_eq!(0x81123456u32, handle);
    assert_eq!(handle.as_bytes(), [0x81, 0x12, 0x34, 0x56]);
}
