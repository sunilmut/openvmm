// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::igvm_attest::get::runtime_claims::*;
use crate::igvm_attest::get::*;
use crate::vmgs::*;
use serde_json::json;
use test_with_tracing::test;
use zerocopy::IntoBytes;

fn vm_configuration() -> AttestationVmConfig {
    AttestationVmConfig {
        current_time: Some(1234),
        root_cert_thumbprint: "test-root".into(),
        console_enabled: true,
        interactive_console_enabled: false,
        ipmi_enabled: true,
        secure_boot: true,
        tpm_enabled: true,
        tpm_version: AttestationTpmVersion::V185,
        tpm_persisted: true,
        filtered_vpci_devices_allowed: false,
        vm_unique_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
        vmgs_provisioner: None,
        hardware_sealing_policy: HardwareSealingPolicy::Hash,
    }
}

// Test: Produce key-release claims containing binary RSA parameters and VM policy.
// Expected: The host receives the exact key role, unpadded URL-safe parameters and
//       legacy policy names, without certificate-renewal or empty user-data claims.
#[test]
fn key_release_claims_have_independent_json_contract() {
    let claims = RuntimeClaims::key_release_request_runtime_claims(
        &[1, 0, 1],
        &[0xfb, 0xff, 0x80, 0, 1],
        &vm_configuration(),
    );
    assert_eq!(
        serde_json::to_value(claims).unwrap(),
        json!({
            "keys": [{
                "kid": "HCLTransferKey",
                "key_ops": ["encrypt"],
                "kty": "RSA",
                "e": "AQAB",
                "n": "-_-AAAE"
            }],
            "vm-configuration": {
                "current-time": 1234,
                "root-cert-thumbprint": "test-root",
                "console-enabled": true,
                "interactive-console-enabled": false,
                "ipmi-enabled": true,
                "secure-boot": true,
                "tpm-enabled": true,
                "tpm-version": "185",
                "tpm-persisted": true,
                "filtered-vpci-devices-allowed": false,
                "vmUniqueId": "00112233-4455-6677-8899-aabbccddeeff",
                "hardware-sealing-policy": "hash"
            }
        })
    );
}

// Test: Produce certificate claims with distinct AK/EK keys and binary guest input.
// Expected: Signing/encryption identities cannot be swapped, guest input uses hex
//       rather than text/base64, and absent renewal metadata stays absent.
#[test]
fn certificate_claims_keep_ak_ek_roles_and_binary_user_data_distinct() {
    let mut config = vm_configuration();
    config.current_time = None;
    config.tpm_version = AttestationTpmVersion::V138;
    let claims = RuntimeClaims::ak_cert_runtime_claims(
        &[1, 0, 1],
        &[0xfb, 0xff],
        &[3],
        &[0xff, 0xfb],
        &config,
        &[0, 0x7f, 0x80, 0xff],
    );
    let encoded = serde_json::to_value(&claims).unwrap();
    assert_eq!(
        encoded["keys"],
        json!([
            {"kid": "HCLAkPub", "key_ops": ["sign"], "kty": "RSA",
             "e": "AQAB", "n": "-_8"},
            {"kid": "HCLEkPub", "key_ops": ["encrypt"], "kty": "RSA",
             "e": "Aw", "n": "__s"}
        ])
    );
    assert_eq!(encoded["user-data"], "007f80ff");
    assert_eq!(encoded["vm-configuration"]["tpm-version"], "1.38");
    assert!(encoded["vm-configuration"].get("current-time").is_none());
    assert!(encoded.get("akcert").is_none());
    let decoded: RuntimeClaims = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.keys[0].n, [0xfb, 0xff]);
    assert_eq!(decoded.keys[1].n, [0xff, 0xfb]);
    assert_eq!(decoded.user_data, "007f80ff");
}

// Test: Serialize a version-two TDX key-release request with an extension and claims.
// Expected: The C wire layout keeps header, report, request-data and capability
//       offsets stable, including the separate total and variable-data lengths.
#[test]
fn extended_attestation_request_matches_host_wire_layout() {
    let claims = br#"{"keys":[]}"#;
    let mut attestation_report = [0; SNP_VM_REPORT_SIZE];
    attestation_report[..TDX_VM_REPORT_SIZE].fill(0xa5);
    let request = IgvmAttestRequestBase {
        header: IgvmAttestRequestHeader::new(1251, IgvmAttestRequestType::KEY_RELEASE_REQUEST, 0),
        attestation_report,
        request_data: IgvmAttestRequestData::new(
            IgvmAttestRequestVersion::VERSION_2,
            35,
            IgvmAttestReportType::TDX_VM_REPORT,
            IgvmAttestHashType::SHA_256,
            11,
        ),
    };
    let extension = IgvmAttestRequestDataExt::new(
        IgvmCapabilityBitMap::new()
            .with_error_code(true)
            .with_retry(true)
            .with_skip_hw_unsealing(true)
            .with_use_rsa_aes_key_wrap_384(true)
            .with_corim_endorsement(true),
    );
    let mut wire = request.as_bytes().to_vec();
    wire.extend_from_slice(extension.as_bytes());
    wire.extend_from_slice(claims);
    assert_eq!(wire.len(), 1251);
    assert_eq!(
        &wire[..32],
        &[
            0x48, 0x43, 0x4c, 0x41, 2, 0, 0, 0, 0xe3, 4, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
    assert_eq!(&wire[32..1056], &[0xa5; 1024]);
    assert_eq!(&wire[1056..1216], &[0; 160]);
    assert_eq!(
        &wire[1216..1236],
        &[35, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 11, 0, 0, 0]
    );
    assert_eq!(&wire[1236..1240], &[0x1f, 0, 0, 0]);
    assert_eq!(&wire[1240..], claims);
}

// Test: Persist a TDX version-three protector carrying both complete SVN arrays.
// Expected: The on-disk layout keeps the TEE tag and all 32 SVN bytes, zeroes
//       reserved header bytes, and places IV/ciphertext/HMAC at fixed offsets.
#[test]
fn tdx_hardware_protector_preserves_both_svn_arrays_in_vmgs_layout() {
    let svn = std::array::from_fn(|index| u8::try_from(index + 1).unwrap());
    let protector = HardwareKeyProtectorV3 {
        header: HardwareKeyProtectorHeaderV3::new(128, HW_KEY_PROTECTOR_TEE_TYPE_TDX, svn, 1),
        iv: [0x42; 16],
        ciphertext: [0x83; 32],
        hmac: [0xc4; 32],
    };
    let wire = protector.as_bytes();
    assert_eq!(wire.len(), 128);
    assert_eq!(&wire[..12], &[3, 0, 0, 0, 128, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(
        &wire[12..28],
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(
        &wire[28..44],
        &[
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        ]
    );
    assert_eq!(&wire[44..48], &[1, 0, 0, 0]);
    assert_eq!(&wire[48..64], &[0x42; 16]);
    assert_eq!(&wire[64..96], &[0x83; 32]);
    assert_eq!(&wire[96..128], &[0xc4; 32]);
}
