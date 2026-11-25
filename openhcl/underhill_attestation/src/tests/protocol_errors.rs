// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::igvm_attest::ak_cert;
use crate::igvm_attest::key_release;
use crate::igvm_attest::wrapped_key;
use crate::key_protector::GetKeysFromKeyProtectorError;
use crate::key_protector::KeyProtectorExt;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto::HashAlgorithm;
use crypto::rsa::RsaKeyPair;
use openhcl_attestation_protocol::igvm_attest::akv;
use openhcl_attestation_protocol::igvm_attest::get::IgvmAttestCommonResponseHeader;
use openhcl_attestation_protocol::igvm_attest::get::IgvmAttestResponseVersion;
use openhcl_attestation_protocol::vmgs::KeyProtector;
use test_with_tracing::test;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

fn legacy_response(payload: &[u8]) -> Vec<u8> {
    let mut header = IgvmAttestCommonResponseHeader {
        data_size: (size_of::<IgvmAttestCommonResponseHeader>() + payload.len()) as u32,
        version: IgvmAttestResponseVersion::VERSION_1,
    };
    let mut response = header.as_mut_bytes().to_vec();
    response.extend_from_slice(payload);
    response
}

// Test: Supply a wrapped DES key one byte shorter than its RSA modulus requires.
// Expected: Key rotation rejects the exact size mismatch without changing either protector entry.
#[test]
fn short_wrapped_des_key_is_rejected_without_mutating_the_protector() {
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let mut protector = KeyProtector::new_zeroed();
    let original = protector.as_bytes().to_vec();
    let error = protector
        .unwrap_and_rotate_keys(&rsa, Some(&[0; 255]), 0, 1)
        .unwrap_err();
    assert!(matches!(
        error,
        GetKeysFromKeyProtectorError::InvalidWrappedDesKeySize {
            key_size: 255,
            expected_size: 256
        }
    ));
    assert_eq!(protector.as_bytes(), original);
}

// Test: RSA-unwrap an otherwise valid ciphertext whose plaintext is not an AES-256 key.
// Expected: Rotation rejects the plaintext length before using it or changing the protector.
#[test]
fn incorrect_rsa_plaintext_length_cannot_become_a_rotation_key() {
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let wrapped = rsa
        .oaep_encrypt(&[0x21; 31], HashAlgorithm::Sha256)
        .unwrap();
    let mut protector = KeyProtector::new_zeroed();
    let original = protector.as_bytes().to_vec();
    let error = protector
        .unwrap_and_rotate_keys(&rsa, Some(&wrapped), 0, 1)
        .unwrap_err();
    assert!(matches!(
        error,
        GetKeysFromKeyProtectorError::InvalidRsaUnwrapOutputSize {
            output_size: 31,
            expected_size: 32
        }
    ));
    assert_eq!(protector.as_bytes(), original);
}

// Test: Unwrap a correctly padded AES ciphertext containing a short ingress DEK.
// Expected: Rotation rejects the 31-byte DEK and does not commit a new egress entry.
#[test]
fn incorrect_aes_plaintext_length_cannot_become_an_ingress_key() {
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let des = [0x31; 32];
    let wrapped_des = rsa.oaep_encrypt(&des, HashAlgorithm::Sha256).unwrap();
    let wrapped_dek = crypto::aes_kwp::AesKeyWrap::new(&des)
        .unwrap()
        .wrapper()
        .unwrap()
        .wrap(&[0x41; 31])
        .unwrap();
    let mut protector = KeyProtector::new_zeroed();
    protector.dek[0].dek_buffer[..wrapped_dek.len()].copy_from_slice(&wrapped_dek);
    let original = protector.as_bytes().to_vec();
    let error = protector
        .unwrap_and_rotate_keys(&rsa, Some(&wrapped_des), 0, 1)
        .unwrap_err();
    assert!(matches!(
        error,
        GetKeysFromKeyProtectorError::InvalidAesUnwrapOutputSize {
            output_size: 31,
            expected_size: 32
        }
    ));
    assert_eq!(protector.as_bytes(), original);
}

// Test: Parse signed key-release JWTs with a forged signature or an invalid certificate encoding.
// Expected: Valid tokens release the expected bytes; forged or unverifiable tokens release nothing.
#[test]
fn key_release_rejects_forged_and_unverifiable_signed_tokens() {
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let (header, body, signature) =
        crate::test_helpers::generate_base64_encoded_jwt_components(&rsa);
    let valid = legacy_response(format!("{header}.{body}.{signature}").as_bytes());
    assert_eq!(
        key_release::parse_response(&valid, 256)
            .unwrap()
            .wrapped_key,
        b"test"
    );
    let forged = URL_SAFE_NO_PAD.encode([0; 256]);
    let response = legacy_response(format!("{header}.{body}.{forged}").as_bytes());
    assert!(matches!(
        key_release::parse_response(&response, 256),
        Err(key_release::KeyReleaseError::VerifyAkvJwtSignatureFailed)
    ));
    let mut bad_header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&header).unwrap()).unwrap();
    bad_header["x5c"][0] = serde_json::Value::String("!".into());
    let bad_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&bad_header).unwrap());
    let response = legacy_response(format!("{bad_header}.{body}.{signature}").as_bytes());
    assert!(matches!(
        key_release::parse_response(&response, 256),
        Err(key_release::KeyReleaseError::VerifyAkvJwtSignature(
            crate::jwt::JwtError::DecodeBase64JwtX509Certificate(_)
        ))
    ));
}

// Test: Supply a malformed JWT and a valid signed JWT whose inner key blob is not JSON.
// Expected: Response parsing distinguishes JWT framing from invalid wrapped-key content.
#[test]
fn key_release_reports_malformed_outer_and_inner_payloads() {
    let response = legacy_response(&vec![b'!'; 1024]);
    assert!(matches!(
        key_release::parse_response(&response, 256),
        Err(key_release::KeyReleaseError::ParseAkvJwt(_))
    ));
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let (header, _, _) = crate::test_helpers::generate_base64_encoded_jwt_components(&rsa);
    let body = akv::AkvKeyReleaseJwtBody {
        response: akv::AkvKeyReleaseResponse {
            key: akv::AkvKeyReleaseKeyObject {
                key: akv::AkvJwk {
                    key_hsm: b"not-json".to_vec(),
                },
            },
        },
    };
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
    let payload = format!("{header}.{body}");
    let signature = URL_SAFE_NO_PAD.encode(
        rsa.pkcs1_sign(payload.as_bytes(), HashAlgorithm::Sha256)
            .unwrap(),
    );
    let response = legacy_response(format!("{payload}.{signature}").as_bytes());
    assert!(matches!(
        key_release::parse_response(&response, 256),
        Err(key_release::KeyReleaseError::GetWrappedKeyFromAkvJwtBody(_))
    ));
}

// Test: Parse a full-size wrapped-key response containing invalid JSON.
// Expected: The parser reports a JSON error with the supplied payload, not a key or a size error.
#[test]
fn wrapped_key_rejects_invalid_json_at_an_otherwise_valid_payload_size() {
    let payload = vec![b'!'; 1024];
    let response = legacy_response(&payload);
    match wrapped_key::parse_response(&response) {
        Err(wrapped_key::WrappedKeyError::WrappedKeyResponsePayloadToJson {
            json_data, ..
        }) => {
            assert_eq!(json_data.as_bytes(), payload);
        }
        _ => panic!("malformed JSON was not rejected by the wrapped-key parser"),
    }
}

// Test: Send response version zero to each versioned attestation payload parser.
// Expected: All parsers reject the unsupported version before interpreting payload bytes.
#[test]
fn version_zero_is_not_interpreted_as_a_legacy_payload() {
    let mut header = IgvmAttestCommonResponseHeader {
        data_size: size_of::<IgvmAttestCommonResponseHeader>() as u32,
        version: IgvmAttestResponseVersion(0),
    };
    let response = header.as_mut_bytes();
    assert!(matches!(
        ak_cert::parse_response(response),
        Err(ak_cert::AkCertError::InvalidResponseVersion(0))
    ));
    assert!(matches!(
        wrapped_key::parse_response(response),
        Err(wrapped_key::WrappedKeyError::InvalidResponseVersion(0))
    ));
    assert!(matches!(
        key_release::parse_response(response, 256),
        Err(key_release::KeyReleaseError::InvalidResponseVersion(0))
    ));
}

// Test: Parse provenance data ending with a truncated multibyte UTF8 character.
// Expected: The returned diagnostic preserves every invalid byte without panicking or replacing it.
#[test]
fn truncated_utf8_provenance_keeps_exact_bytes_in_the_error() {
    let error = crate::get_provenance_claims(b"prefix\xf0\x9f").unwrap_err();
    let mut source: &dyn std::error::Error = &error;
    while let Some(cause) = source.source() {
        source = cause;
    }
    assert_eq!(
        source.to_string(),
        r"JWT data is not valid UTF-8: prefix\xF0\x9F"
    );
}

// Test: Change only JSON whitespace in a signed key-release JWT body.
// Expected: The unchanged signature rejects the changed bytes; signing those
//       exact bytes again releases the same key, without imposing JSON canonicalization.
#[test]
fn key_release_signature_binds_the_original_serialized_body() {
    let rsa = RsaKeyPair::generate(2048).unwrap();
    let (header, body, signature) =
        crate::test_helpers::generate_base64_encoded_jwt_components(&rsa);
    let valid = legacy_response(format!("{header}.{body}.{signature}").as_bytes());
    assert_eq!(
        key_release::parse_response(&valid, 256)
            .unwrap()
            .wrapped_key,
        b"test"
    );
    let mut changed_body = URL_SAFE_NO_PAD.decode(&body).unwrap();
    changed_body.push(b' ');
    let changed_body = URL_SAFE_NO_PAD.encode(changed_body);
    let payload = format!("{header}.{changed_body}");
    let changed = legacy_response(format!("{payload}.{signature}").as_bytes());
    assert!(matches!(
        key_release::parse_response(&changed, 256),
        Err(key_release::KeyReleaseError::VerifyAkvJwtSignatureFailed)
    ));
    let signature = URL_SAFE_NO_PAD.encode(
        rsa.pkcs1_sign(payload.as_bytes(), HashAlgorithm::Sha256)
            .unwrap(),
    );
    let signed = legacy_response(format!("{payload}.{signature}").as_bytes());
    assert_eq!(
        key_release::parse_response(&signed, 256)
            .unwrap()
            .wrapped_key,
        b"test"
    );
}
