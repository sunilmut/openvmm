// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::OWNER;
use crate::signature_list::*;
use crate::{ParsedNvramEntry, parse_nvram_entry};
use std::borrow::Cow;
use test_with_tracing::test;
use uefi_specs::uefi::nvram::signature_list::{
    EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID, EFI_SIGNATURE_DATA,
};
use zerocopy::IntoBytes;

// Frame reference signature-list bytes independently of the production serializer.
fn wire(kind: guid::Guid, signature_size: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = kind.as_bytes().to_vec();
    bytes.extend(u32::try_from(28 + payload.len()).unwrap().to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(signature_size.to_le_bytes());
    bytes.extend(payload);
    bytes
}

// Test: Parse every recognized secure-boot variable from an independent digest list.
// Expected: Each name dispatches to a SHA-256 list with the exact owner and digest.
#[test]
fn secure_boot_names_preserve_signature_owner_and_digest() {
    let mut payload = OWNER.as_bytes().to_vec();
    payload.extend([0x5a; 32]);
    let bytes = wire(EFI_CERT_SHA256_GUID, 48, &payload);
    for name in ["KEK", "db", "dbx", "PK", "dbDefault", "MokList", "MokListX"] {
        let ParsedNvramEntry::SignatureList(lists) = parse_nvram_entry(name, &bytes).unwrap()
        else {
            panic!("expected signature variable {name}");
        };
        assert_eq!(
            lists,
            [SignatureList::Sha256(vec![SignatureData::new_sha256(
                OWNER,
                Cow::Borrowed(&[0x5a; 32])
            )])]
        );
    }
}

// Test: Collect duplicate digests/certificates with both equal and different owners.
// Expected: Exact duplicates collapse, but distinct owners and payloads remain.
#[test]
fn signature_set_deduplicates_by_owner_and_payload() {
    let other = guid::guid!("10213243-5465-7687-98a9-bacbdcedfe0f");
    let mut bytes = Vec::new();
    for owner in [OWNER, OWNER, other] {
        SignatureList::Sha256(vec![SignatureData::new_sha256(owner, Cow::Owned([1; 32]))])
            .extend_as_spec_signature_list(&mut bytes);
        SignatureList::X509(SignatureData::new_x509(
            owner,
            Cow::Borrowed(b"certificate blob"),
        ))
        .extend_as_spec_signature_list(&mut bytes);
    }
    let set = ParseSignatureLists::new(&bytes)
        .collect_signature_set()
        .unwrap();
    assert_eq!(set.len(), 4);
    for owner in [OWNER, other] {
        assert!(set.contains(&(
            EFI_SIGNATURE_DATA {
                signature_owner: owner
            },
            Cow::Borrowed(&[1; 32][..])
        )));
        assert!(set.contains(&(
            EFI_SIGNATURE_DATA {
                signature_owner: owner
            },
            Cow::Borrowed(&b"certificate blob"[..])
        )));
    }
}

// Test: Filter signature payloads selectively, then reject all signatures.
// Expected: Only the selected digest remains; rejected certificates and empty lists disappear.
#[test]
fn payload_filter_removes_empty_signature_lists() {
    let mut bytes = Vec::new();
    SignatureList::Sha256(vec![
        SignatureData::new_sha256(OWNER, Cow::Owned([1; 32])),
        SignatureData::new_sha256(OWNER, Cow::Owned([2; 32])),
    ])
    .extend_as_spec_signature_list(&mut bytes);
    SignatureList::X509(SignatureData::new_x509(
        OWNER,
        Cow::Borrowed(b"certificate blob"),
    ))
    .extend_as_spec_signature_list(&mut bytes);
    let lists = ParseSignatureLists::new(&bytes)
        .collect_signature_lists(|_, data| match data {
            SignatureDataPayload::Sha256(digest) => *digest == [2; 32],
            SignatureDataPayload::X509(certificate) => {
                assert_eq!(certificate, b"certificate blob");
                false
            }
        })
        .unwrap();
    assert_eq!(
        lists,
        [SignatureList::Sha256(vec![SignatureData::new_sha256(
            OWNER,
            Cow::Owned([2; 32])
        )])]
    );
    assert!(
        ParseSignatureLists::new(&bytes)
            .collect_signature_lists(|_, _| false)
            .unwrap()
            .is_empty()
    );
}

// Test: Parse truncated signature-list framing and unsupported signature GUIDs.
// Expected: Header, data-length and unsupported-type failures remain distinguishable.
#[test]
fn malformed_signature_framing_has_typed_errors() {
    let bytes = wire(EFI_CERT_SHA256_GUID, 48, &[0; 48]);
    for length in 1..28 {
        assert!(matches!(
            ParseSignatureLists::new(&bytes[..length]).collect_signature_lists(|_, _| true),
            Err(ParseError::InvalidHeader)
        ));
    }
    assert!(matches!(
        ParseSignatureLists::new(&bytes[..bytes.len() - 1]).collect_signature_lists(|_, _| true),
        Err(ParseError::TruncatedData)
    ));
    let bytes = wire(guid::Guid::ZERO, 48, &[]);
    assert!(matches!(
        ParseSignatureLists::new(&bytes).collect_signature_lists(|_, _| true),
        Err(ParseError::UnsupportedSignatureType(guid::Guid::ZERO))
    ));
}

// Test: Parse digest/certificate lists with inconsistent entry sizes or short owners.
// Expected: SHA-256 and X509 errors identify the specific invalid payload boundary.
#[test]
fn malformed_signature_entries_have_typed_errors() {
    let bytes = wire(EFI_CERT_SHA256_GUID, 47, &[0; 48]);
    assert!(matches!(
        ParseSignatureLists::new(&bytes).collect_signature_lists(|_, _| true),
        Err(ParseError::Sha256InvalidSigSize(47))
    ));
    let bytes = wire(EFI_CERT_SHA256_GUID, 48, &[0; 47]);
    assert!(matches!(
        ParseSignatureLists::new(&bytes).collect_signature_lists(|_, _| true),
        Err(ParseError::Sha256TruncatedData)
    ));
    let bytes = wire(EFI_CERT_X509_GUID, 17, &[0; 16]);
    assert!(matches!(
        ParseSignatureLists::new(&bytes).collect_signature_lists(|_, _| true),
        Err(ParseError::X509InvalidSigSize(17, 16))
    ));
    let bytes = wire(EFI_CERT_X509_GUID, 15, &[0; 15]);
    assert!(matches!(
        ParseSignatureLists::new(&bytes).collect_signature_lists(|_, _| true),
        Err(ParseError::X509InvalidHeader)
    ));
}

// IGNORED: The list parser subtracts the header size without checking the declared
//       list size first. A zero-sized list panics with subtraction overflow.
//
// Test: Declare a signature list smaller than its mandatory 28-byte header.
// Expected: Every undersized list returns an error instead of panicking or wrapping.
#[test]
#[ignore = "product bug: undersized signature lists underflow during header subtraction"]
fn undersized_signature_list_is_rejected_without_panicking() {
    for size in 0..28u32 {
        let mut bytes = wire(EFI_CERT_SHA256_GUID, 48, &[]);
        bytes[16..20].copy_from_slice(&size.to_le_bytes());
        assert!(
            ParseSignatureLists::new(&bytes)
                .collect_signature_lists(|_, _| true)
                .is_err()
        );
    }
}

// IGNORED: The collector unconditionally unwraps the first certificate. An empty
//       X509 list reaches that unwrap and panics instead of returning a parse error.
//
// Test: Collect an X509 list with no owner or certificate entry.
// Expected: The malformed list returns an error instead of unwrapping an absent entry.
#[test]
#[ignore = "product bug: empty X509 lists unwrap a nonexistent first certificate"]
fn empty_x509_list_is_rejected_without_panicking() {
    let bytes = wire(EFI_CERT_X509_GUID, 0, &[]);
    assert!(
        ParseSignatureLists::new(&bytes)
            .collect_signature_lists(|_, _| true)
            .is_err()
    );
}
