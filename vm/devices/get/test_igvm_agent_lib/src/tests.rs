// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crypto::HashAlgorithm;
use openhcl_attestation_protocol::igvm_attest::get::runtime_claims::{
    AttestationTpmVersion, AttestationVmConfig, HardwareSealingPolicy, RsaJwk, RuntimeClaims,
};
use openhcl_attestation_protocol::igvm_attest::{akv, cps};
use test_with_tracing::test;
use zerocopy::FromZeros;

#[derive(Clone, Copy)]
enum WrapScheme {
    Default,
    Sha384,
}

impl WrapScheme {
    #[expect(
        deprecated,
        reason = "the legacy key-wrap protocol requires RSA-OAEP with SHA-1"
    )]
    fn hash(self) -> HashAlgorithm {
        match self {
            Self::Default => HashAlgorithm::Sha1,
            Self::Sha384 => HashAlgorithm::Sha384,
        }
    }
}

// Send the same fixed header, capability extension and claims layout as a guest.
fn request(ty: IgvmAttestRequestType, claims: &[u8], scheme: WrapScheme) -> Vec<u8> {
    let mut base = IgvmAttestRequestBase::new_zeroed();
    base.header.request_type = ty;
    base.request_data.version = IGVM_ATTEST_REQUEST_CURRENT_VERSION;
    base.request_data.variable_data_size = claims.len().try_into().unwrap();
    let mut extension = IgvmAttestRequestDataExt::new_zeroed();
    extension
        .capability_bitmap
        .set_use_rsa_aes_key_wrap_384(matches!(scheme, WrapScheme::Sha384));
    [base.as_bytes(), extension.as_bytes(), claims].concat()
}

// Include a decoy key so success also checks selection by key ID, not array position.
fn claims(transfer: &RsaKeyPair) -> RuntimeClaims {
    let public = transfer.to_components().unwrap();
    let config = AttestationVmConfig {
        current_time: None,
        root_cert_thumbprint: String::new(),
        console_enabled: false,
        interactive_console_enabled: false,
        ipmi_enabled: false,
        secure_boot: true,
        tpm_enabled: true,
        tpm_version: AttestationTpmVersion::V185,
        tpm_persisted: true,
        filtered_vpci_devices_allowed: false,
        vm_unique_id: "agent-unit-test".into(),
        vmgs_provisioner: None,
        hardware_sealing_policy: HardwareSealingPolicy::None,
    };
    let mut claims = RuntimeClaims::key_release_request_runtime_claims(
        &public.public_exponent,
        &public.modulus,
        &config,
    );
    let mut decoy = RsaJwk::get_transfer_key_jwks(&[1, 0, 1], &[0x91; 256]).remove(0);
    decoy.kid = "NotTheTransferKey".into();
    claims.keys.insert(0, decoy);
    claims
}

// The three response types share this fixed header wire layout.
fn decode(response: (Vec<u8>, u32)) -> (IgvmAttestKeyReleaseResponseHeader, Vec<u8>) {
    let (bytes, len) = response;
    assert_eq!(bytes.len(), len as usize);
    let (header, payload) = IgvmAttestKeyReleaseResponseHeader::read_from_prefix(&bytes).unwrap();
    assert_eq!(header.data_size, len);
    assert_eq!(header.version, IGVM_ATTEST_RESPONSE_CURRENT_VERSION);
    assert_eq!(header.error_info.reserved, [0; 3]);
    (header, payload.to_vec())
}

fn success(response: (Vec<u8>, u32), scheme: WrapScheme) -> Vec<u8> {
    let (header, payload) = decode(response);
    assert_eq!(
        (
            header.error_info.error_code,
            header.error_info.http_status_code
        ),
        (0, 0)
    );
    assert!(!header.error_info.igvm_signal.retry());
    assert!(!header.error_info.igvm_signal.skip_hw_unsealing());
    assert!(!header.error_info.igvm_signal.no_renew_cert());
    assert_eq!(
        header.error_info.igvm_signal.rsa_aes_key_wrap_384_used(),
        matches!(scheme, WrapScheme::Sha384)
    );
    payload
}

// Decode the public JWT envelope and decrypt its PKCS#11 RSA-AES wrapped private key.
// This agent deliberately emits an unsigned test JWT; no authenticity claim is made.
fn released_key(payload: &[u8], transfer: &RsaKeyPair, scheme: WrapScheme) -> RsaKeyPair {
    let jwt = std::str::from_utf8(payload)
        .unwrap()
        .split('.')
        .collect::<Vec<_>>();
    assert_eq!(jwt.len(), 3);
    assert!(jwt[2].is_empty());
    let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header: akv::AkvKeyReleaseJwtHeader =
        serde_json::from_slice(&base64.decode(jwt[0]).unwrap()).unwrap();
    assert_eq!(header.alg, "RS256");
    assert!(header.x5c.is_empty());
    let body: akv::AkvKeyReleaseJwtBody =
        serde_json::from_slice(&base64.decode(jwt[1]).unwrap()).unwrap();
    let blob: akv::AkvKeyReleaseKeyBlob =
        serde_json::from_slice(&body.response.key.key.key_hsm).unwrap();
    let rsa_len = transfer.modulus_size();
    assert!(blob.ciphertext.len() > rsa_len);
    assert_eq!((blob.ciphertext.len() - rsa_len) % 8, 0);
    let kek = transfer
        .oaep_decrypt(&blob.ciphertext[..rsa_len], scheme.hash())
        .unwrap();
    assert_eq!(kek.len(), 32);
    let wrong_scheme = match scheme {
        WrapScheme::Default => WrapScheme::Sha384,
        WrapScheme::Sha384 => WrapScheme::Default,
    };
    assert!(
        transfer
            .oaep_decrypt(&blob.ciphertext[..rsa_len], wrong_scheme.hash())
            .is_err()
    );
    let wrapping = crypto::aes_kwp::AesKeyWrap::new(&kek).unwrap();
    let der = wrapping
        .unwrapper()
        .unwrap()
        .unwrap(&blob.ciphertext[rsa_len..])
        .unwrap();
    RsaKeyPair::from_pkcs8_der(&der).unwrap()
}

fn wrapped_ciphertext(payload: &[u8]) -> Vec<u8> {
    let blob: cps::VmmdBlob = serde_json::from_slice(payload).unwrap();
    let encryption = blob.disk_encryption_settings.encryption_info;
    assert_eq!(
        encryption.key_reference,
        serde_json::json!({
            "key_info": {"host": "name"}, "attestation_info": {"host": "attestation_name"}
        })
    );
    assert_eq!(encryption.aes_info.ciphertext.len(), 256);
    encryption.aes_info.ciphertext
}

fn successful_plan() -> IgvmAgentTestSetting {
    IgvmAgentTestSetting::TestPlan(HashMap::from([
        (
            IgvmAttestRequestType::WRAPPED_KEY_REQUEST,
            VecDeque::from([
                IgvmAgentAction::RespondSuccess,
                IgvmAgentAction::RespondSuccess,
                IgvmAgentAction::RespondSuccess,
            ]),
        ),
        (
            IgvmAttestRequestType::KEY_RELEASE_REQUEST,
            VecDeque::from([
                IgvmAgentAction::RespondSuccess,
                IgvmAgentAction::RespondSuccess,
            ]),
        ),
    ]))
}

// Test: Wrap a disk key, release its RSA key using both OAEP schemes, and wrap the disk key again.
// Expected: Default and scripted replies decrypt end-to-end, negotiate the requested hash and retain both keys.
#[test]
fn wrapped_and_released_keys_round_trip_both_hash_schemes_without_rotating() {
    let transfer = RsaKeyPair::generate(2048).unwrap();
    let claims = serde_json::to_vec(&claims(&transfer)).unwrap();
    for setting in [None, Some(successful_plan())] {
        let mut agent = TestIgvmAgent::new("key-round-trip");
        if let Some(setting) = setting {
            agent.install_plan_from_setting(&setting);
        }
        let wrapped_request = request(
            IgvmAttestRequestType::WRAPPED_KEY_REQUEST,
            b"{}",
            WrapScheme::Default,
        );
        let first = wrapped_ciphertext(&success(
            agent.handle_request(&wrapped_request).unwrap(),
            WrapScheme::Default,
        ));
        let mut previous_key = None;
        let mut previous_des = None;
        for scheme in [WrapScheme::Default, WrapScheme::Sha384] {
            let release = request(IgvmAttestRequestType::KEY_RELEASE_REQUEST, &claims, scheme);
            let payload = success(agent.handle_request(&release).unwrap(), scheme);
            let key = released_key(&payload, &transfer, scheme);
            let public = key.to_components().unwrap();
            if let Some(expected) = &previous_key {
                assert_eq!(&public, expected);
            }
            previous_key = Some(public);
            let des = key.oaep_decrypt(&first, HashAlgorithm::Sha256).unwrap();
            assert_eq!(des.len(), 32);
            if let Some(expected) = &previous_des {
                assert_eq!(&des, expected);
            }
            previous_des = Some(des.clone());
            let next = wrapped_ciphertext(&success(
                agent.handle_request(&wrapped_request).unwrap(),
                WrapScheme::Default,
            ));
            assert_eq!(key.oaep_decrypt(&next, HashAlgorithm::Sha256).unwrap(), des);
        }
    }
}

// Test: Request key release before the first wrapped-key request, with and without a scripted success.
// Expected: The released private key decrypts the subsequently wrapped disk key without explicit initialization.
#[test]
fn key_release_before_wrapping_initializes_a_matching_persistent_key_pair() {
    let transfer = RsaKeyPair::generate(2048).unwrap();
    let claims = serde_json::to_vec(&claims(&transfer)).unwrap();
    for setting in [None, Some(successful_plan())] {
        let mut agent = TestIgvmAgent::new("release-first");
        if let Some(setting) = setting {
            agent.install_plan_from_setting(&setting);
        }
        let release = request(
            IgvmAttestRequestType::KEY_RELEASE_REQUEST,
            &claims,
            WrapScheme::Default,
        );
        let key = released_key(
            &success(agent.handle_request(&release).unwrap(), WrapScheme::Default),
            &transfer,
            WrapScheme::Default,
        );
        let wrapped = request(
            IgvmAttestRequestType::WRAPPED_KEY_REQUEST,
            b"{}",
            WrapScheme::Default,
        );
        let ciphertext = wrapped_ciphertext(&success(
            agent.handle_request(&wrapped).unwrap(),
            WrapScheme::Default,
        ));
        assert_eq!(
            key.oaep_decrypt(&ciphertext, HashAlgorithm::Sha256)
                .unwrap()
                .len(),
            32
        );
    }
}

// Test: Interleave independent plans for every request type and attempt to reinstall a different plan.
// Expected: Error headers retain their signal/status contracts; one-shot and sticky timeouts differ, without reset.
#[test]
fn scripted_failures_and_timeouts_are_independent_sticky_and_installed_once() {
    let types = [
        IgvmAttestRequestType::WRAPPED_KEY_REQUEST,
        IgvmAttestRequestType::KEY_RELEASE_REQUEST,
        IgvmAttestRequestType::AK_CERT_REQUEST,
    ];
    let plan = types
        .into_iter()
        .map(|ty| {
            (
                ty,
                VecDeque::from([
                    IgvmAgentAction::RespondFailure,
                    IgvmAgentAction::RespondFailureSkipHwUnsealing,
                    IgvmAgentAction::NoResponse,
                    IgvmAgentAction::RespondFailure,
                    IgvmAgentAction::AlwaysNoResponse,
                ]),
            )
        })
        .collect();
    let mut agent = TestIgvmAgent::new("failure-plan");
    agent.install_plan_from_setting(&IgvmAgentTestSetting::TestPlan(plan));
    for (code, skip) in [(0x1234, false), (0x5678, true)] {
        for ty in types {
            let (header, payload) = decode(
                agent
                    .handle_request(&request(ty, b"{}", WrapScheme::Default))
                    .unwrap(),
            );
            assert!(payload.is_empty());
            assert_eq!(
                (
                    header.error_info.error_code,
                    header.error_info.http_status_code
                ),
                (code, 400)
            );
            let signals =
                u32::from_ne_bytes(header.error_info.igvm_signal.as_bytes().try_into().unwrap());
            assert_eq!(signals, if skip { 1 << 1 } else { 0 });
        }
        agent.install_plan_from_setting(&IgvmAgentTestSetting::TestPlan(HashMap::new()));
    }
    for ty in types {
        let request = request(ty, b"{}", WrapScheme::Default);
        assert_eq!(agent.handle_request(&request).unwrap(), (vec![], 0));
        let (header, payload) = decode(agent.handle_request(&request).unwrap());
        assert_eq!(header.error_info.error_code, 0x1234);
        assert!(payload.is_empty());
    }
    for _ in 0..4 {
        for ty in types {
            assert_eq!(
                agent
                    .handle_request(&request(ty, b"{}", WrapScheme::Default))
                    .unwrap(),
                (vec![], 0)
            );
        }
    }
}

// Test: Run short/extended certificate retry presets and the state-refresh preset to exhaustion.
// Expected: Each preset emits its documented failure count, then success; state refresh remains unavailable afterward.
#[test]
fn certificate_retry_and_state_refresh_presets_keep_their_response_sequences() {
    for (config, failures) in [
        (IgvmAttestTestConfig::AkCertRequestFailureAndRetry, 2),
        (
            IgvmAttestTestConfig::AkCertRequestFailureAndRetryExtended,
            6,
        ),
        (IgvmAttestTestConfig::StateRefresh, 0),
    ] {
        let mut agent = TestIgvmAgent::new("certificate-presets");
        agent.install_plan_from_setting(&IgvmAgentTestSetting::TestConfig(config));
        let request = request(
            IgvmAttestRequestType::AK_CERT_REQUEST,
            b"{}",
            WrapScheme::Default,
        );
        for _ in 0..failures {
            let (header, payload) = decode(agent.handle_request(&request).unwrap());
            assert_eq!(header.error_info.error_code, 0x1234);
            assert!(payload.is_empty());
        }
        for _ in 0..2 {
            assert_eq!(
                success(agent.handle_request(&request).unwrap(), WrapScheme::Default),
                [0xab; 2500]
            );
        }
        if matches!(config, IgvmAttestTestConfig::StateRefresh) {
            for _ in 0..3 {
                assert_eq!(agent.handle_request(&request).unwrap(), (vec![], 0));
            }
        }
    }
}

// Test: Run both key-release failure presets across their two initial-boot successes.
// Expected: The third response has the configured failure/signal and all later requests receive no transport response.
#[test]
fn key_release_failure_presets_account_for_initial_boot_requests() {
    let transfer = RsaKeyPair::generate(2048).unwrap();
    let claims = serde_json::to_vec(&claims(&transfer)).unwrap();
    for (config, code, skip) in [
        (IgvmAttestTestConfig::KeyReleaseFailure, 0x1234, false),
        (
            IgvmAttestTestConfig::KeyReleaseFailureSkipHwUnsealing,
            0x5678,
            true,
        ),
    ] {
        let mut agent = TestIgvmAgent::new("key-failure-presets");
        agent.install_plan_from_setting(&IgvmAgentTestSetting::TestConfig(config));
        let request = request(
            IgvmAttestRequestType::KEY_RELEASE_REQUEST,
            &claims,
            WrapScheme::Default,
        );
        for _ in 0..2 {
            let payload = success(agent.handle_request(&request).unwrap(), WrapScheme::Default);
            assert_eq!(
                released_key(&payload, &transfer, WrapScheme::Default).modulus_size(),
                256
            );
        }
        let (header, payload) = decode(agent.handle_request(&request).unwrap());
        assert!(payload.is_empty());
        assert_eq!(header.error_info.error_code, code);
        assert_eq!(header.error_info.igvm_signal.skip_hw_unsealing(), skip);
        for _ in 0..3 {
            assert_eq!(agent.handle_request(&request).unwrap(), (vec![], 0));
        }
    }
}

// Test: Supply malformed headers, versions, extension/claims lengths and unsupported request types.
// Expected: Typed protocol errors are returned before dispatch, and a later valid request still succeeds.
#[test]
fn malformed_requests_and_unsupported_types_return_explicit_errors() {
    let mut agent = TestIgvmAgent::new("bad-requests");
    let valid = request(
        IgvmAttestRequestType::AK_CERT_REQUEST,
        b"{}",
        WrapScheme::Default,
    );
    for bytes in [
        &[][..],
        &valid[..size_of::<IgvmAttestRequestBase>()],
        &valid[..valid.len() - 1],
    ] {
        assert!(matches!(
            agent.handle_request(bytes),
            Err(Error::InvalidIgvmAttestRequest)
        ));
    }
    let mut base = IgvmAttestRequestBase::read_from_prefix(&valid).unwrap().0;
    base.request_data.version = IgvmAttestRequestVersion::VERSION_1;
    let old = [
        base.as_bytes(),
        &valid[size_of::<IgvmAttestRequestBase>()..],
    ]
    .concat();
    assert!(matches!(
        agent.handle_request(&old),
        Err(Error::InvalidIgvmAttestRequestVersion { .. })
    ));
    for action in [
        None,
        Some(IgvmAgentAction::RespondSuccess),
        Some(IgvmAgentAction::RespondFailure),
    ] {
        let unknown = IgvmAttestRequestType(0xffff);
        let mut agent = TestIgvmAgent::new("unsupported-type");
        if let Some(action) = action {
            agent.install_plan_from_setting(&IgvmAgentTestSetting::TestPlan(HashMap::from([(
                unknown,
                VecDeque::from([action]),
            )])));
        }
        assert!(matches!(
            agent.handle_request(&request(unknown, b"{}", WrapScheme::Default)),
            Err(Error::UnsupportedIgvmAttestRequestType(0xffff))
        ));
    }
    assert_eq!(
        success(agent.handle_request(&valid).unwrap(), WrapScheme::Default),
        [0xab; 2500]
    );
}

// Test: Reject malformed runtime claims and valid claims without the named transfer key.
// Expected: Distinct typed errors identify parse versus missing-key failures and do not poison a later valid release.
#[test]
fn bad_runtime_claims_do_not_prevent_a_later_valid_key_release() {
    let transfer = RsaKeyPair::generate(2048).unwrap();
    let mut agent = TestIgvmAgent::new("claim-errors");
    for claims in [b"not JSON".as_slice(), b"{}"] {
        assert!(matches!(
            agent.handle_request(&request(
                IgvmAttestRequestType::KEY_RELEASE_REQUEST,
                claims,
                WrapScheme::Default
            )),
            Err(Error::KeyReleaseError(
                KeyReleaseError::InvalidRuntimeClaims
            ))
        ));
    }
    let mut missing = claims(&transfer);
    missing.keys.remove(1);
    let missing = serde_json::to_vec(&missing).unwrap();
    assert!(matches!(
        agent.handle_request(&request(
            IgvmAttestRequestType::KEY_RELEASE_REQUEST,
            &missing,
            WrapScheme::Default
        )),
        Err(Error::KeyReleaseError(
            KeyReleaseError::MissingTransferKeyInRuntimeClaims
        ))
    ));
    let valid = serde_json::to_vec(&claims(&transfer)).unwrap();
    let response = success(
        agent
            .handle_request(&request(
                IgvmAttestRequestType::KEY_RELEASE_REQUEST,
                &valid,
                WrapScheme::Default,
            ))
            .unwrap(),
        WrapScheme::Default,
    );
    assert_eq!(
        released_key(&response, &transfer, WrapScheme::Default).modulus_size(),
        256
    );
}

// Test: Alternate transfer-key recipients and their JWK positions on one agent.
// Expected: Each response decrypts with its current recipient and releases the
//       same persistent private key, including when returning to the first client.
#[test]
fn key_release_uses_each_requests_transfer_key_without_rotating_the_persistent_key() {
    let recipients = [
        RsaKeyPair::generate(2048).unwrap(),
        RsaKeyPair::generate(2048).unwrap(),
    ];
    for setting in [None, Some(successful_plan())] {
        let mut agent = TestIgvmAgent::new("changing-transfer-keys");
        if let Some(setting) = setting {
            agent.install_plan_from_setting(&setting);
        }
        let mut persistent_key = None;
        for recipient in [0, 1, 0] {
            let transfer = &recipients[recipient];
            let mut runtime_claims = claims(transfer);
            if recipient == 1 {
                runtime_claims.keys.swap(0, 1);
            }
            let release = request(
                IgvmAttestRequestType::KEY_RELEASE_REQUEST,
                &serde_json::to_vec(&runtime_claims).unwrap(),
                WrapScheme::Sha384,
            );
            let payload = success(agent.handle_request(&release).unwrap(), WrapScheme::Sha384);
            let key = released_key(&payload, transfer, WrapScheme::Sha384)
                .to_components()
                .unwrap();
            if let Some(expected) = &persistent_key {
                assert_eq!(&key, expected);
            } else {
                persistent_key = Some(key);
            }
        }
    }
}
