// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::kdf::Kbkdf;
use crate::kdf::KdfError;
use crate::kdf::KdfParams;
use crate::kdf::Mac;
use crate::kdf::Mode;
use crate::kdf::derive;
use crate::params::Params;
use crate::params::ParamsBuilder;
use openssl::hash::MessageDigest;
use test_with_tracing::test;

// Test: Derive two SHA-256 counter-mode blocks with a label and context.
// Expected: All 64 bytes match an independent SP800-108 HMAC calculation,
//       and repeated derivation with cloned parameters returns identical bytes.
#[test]
fn counter_mode_matches_independent_multiblock_known_answer() {
    let mut params = Kbkdf::new(
        MessageDigest::sha256(),
        b"label".to_vec(),
        (0..32).collect(),
    );
    params.set_context(b"context".to_vec());
    let expected = hex::decode(concat!(
        "a96742dab629385c2fda3ab31ff80ae5ab8f18d61a903f75d4cb97422e3b95864",
        "f650329d558a492707fde746725067868d9647d1a5d07f510bb09aa8d05efaa",
    ))
    .unwrap();
    for _ in 0..3 {
        let mut output = [0; 64];
        derive(params.clone(), &mut output).unwrap();
        assert_eq!(output.as_slice(), expected);
    }
}

// Test: Derive a partial final SHA-384 feedback block with an explicit initial seed.
// Expected: Every output byte matches the independently calculated feedback
//       chain, including bytes after the second full MAC block.
#[test]
fn feedback_mode_preserves_seed_context_and_partial_final_block() {
    let mut params = Kbkdf::new(
        MessageDigest::sha384(),
        b"label".to_vec(),
        (0..32).collect(),
    );
    params.set_mode(Mode::Feedback);
    params.set_mac(Mac::Hmac);
    params.set_context(b"context".to_vec());
    params.set_seed((0..48).collect());
    let mut output = [0; 100];
    derive(params, &mut output).unwrap();
    assert_eq!(
        output.as_slice(),
        hex::decode(concat!(
            "fa05a79b823e138355da3e6f97385cf5f9b2f1cf41d6f334bd6893283da76f3e",
            "88c365748e744ac1f91a8515606549a41e818ecbe01f554e5ea94c636e7069bec",
            "5c02532e86f0cfe01efc82bd2ff1096e6de10ae0781459d5a6757e1bc4edf186",
            "2c0fdef",
        ))
        .unwrap()
    );
}

// Test: Independently toggle SP800-108 length and separator fields.
// Expected: Each combination produces its own known output, preventing either
//       option from being ignored or applied to the wrong field.
#[test]
fn counter_mode_length_and_separator_options_match_known_answers() {
    for (use_l, separator, expected) in [
        (
            false,
            false,
            "0fe4b5076dc772a0076c15e673dc9e39e59e8f0ec665dfc73eef720ccbdd93cfa1",
        ),
        (
            false,
            true,
            "19bdc672b44386a16d24fc66994d9ef8accf1ed1caa159904bac6d59107f7669cd",
        ),
        (
            true,
            false,
            "557f65e18739029d41c64253f0f7d076cfabe1ffd7ca4ec7c34d5049412bd2dfc6",
        ),
        (
            true,
            true,
            "bba6ba4f8e2784c56bd9162a3fbae2094aab6413115afd9cb49133845c5dc78a9e",
        ),
    ] {
        let mut params = Kbkdf::new(MessageDigest::sha256(), b"label".to_vec(), b"key".to_vec());
        params.set_context(b"context".to_vec());
        params.set_l(use_l);
        params.set_separator(separator);
        let mut output = [0; 33];
        derive(params, &mut output).unwrap();
        assert_eq!(output.as_slice(), hex::decode(expected).unwrap());
    }
}

// Test: Derive with no optional label, context, or feedback seed.
// Expected: Omitted optional fields produce the standard empty-label output
//       rather than retaining data from a prior derivation.
#[test]
fn omitted_optional_inputs_match_empty_label_known_answer() {
    let params = Kbkdf::new(MessageDigest::sha256(), Vec::new(), b"key".to_vec());
    let mut output = [0; 32];
    derive(params, &mut output).unwrap();
    assert_eq!(
        output.as_slice(),
        hex::decode("f05b7d2344cfc066608ca1c9177658a28515f793260153e746d67f4aaf56fa07").unwrap()
    );
}

struct Hkdf {
    key: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
}

impl KdfParams for Hkdf {
    fn kdf_name(&self) -> String {
        "HKDF".into()
    }

    fn to_params(&self) -> Result<Params, KdfError> {
        let mut params = ParamsBuilder::with_capacity(1);
        params.add_string(c"digest", c"SHA256")?;
        params.add_slice(c"key", &self.key)?;
        params.add_slice(c"salt", &self.salt)?;
        params.add_slice(c"info", &self.info)?;
        Ok(params.build())
    }
}

// Test: Use caller-defined parameter bundles for RFC5869 HKDF test cases 1 and 3.
// Expected: Both standard and empty salt/info inputs match the published
//       42-byte outputs after builder storage grows beyond its initial capacity.
#[test]
fn custom_parameter_bundles_match_rfc5869_vectors_including_empty_inputs() {
    for (salt, info, expected) in [
        (
            (0..13).collect(),
            (0xf0..=0xf9).collect(),
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865",
            ),
        ),
        (
            Vec::new(),
            Vec::new(),
            concat!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8",
            ),
        ),
    ] {
        let params = Hkdf {
            key: vec![0x0b; 22],
            salt,
            info,
        };
        let mut output = [0; 42];
        derive(params, &mut output).unwrap();
        assert_eq!(output.as_slice(), hex::decode(expected).unwrap());
    }
}

struct NamedKdf(&'static str);

impl KdfParams for NamedKdf {
    fn kdf_name(&self) -> String {
        self.0.into()
    }

    fn to_params(&self) -> Result<Params, KdfError> {
        Ok(ParamsBuilder::with_capacity(0).build())
    }
}

// Test: Use an embedded-NUL name, an unavailable algorithm, and missing HKDF inputs.
// Expected: Name conversion, algorithm lookup and OpenSSL parameter validation
//       each return the corresponding public error without panicking.
#[test]
fn invalid_names_and_missing_parameters_return_distinct_public_errors() {
    let mut output = [0xa5; 32];
    assert!(matches!(
        derive(NamedKdf("HKDF\0extra"), &mut output),
        Err(KdfError::NulError(_))
    ));
    assert!(matches!(
        derive(NamedKdf("OPENVMM-NO-SUCH-KDF"), &mut output),
        Err(KdfError::NoSuchKdf)
    ));
    match derive(NamedKdf("HKDF"), &mut output) {
        Err(KdfError::Ssl(error)) => assert!(!error.errors().is_empty()),
        other => panic!("expected OpenSSL parameter error, got {other:?}"),
    }
}

// Test: Format a parameter bundle containing secret key, label and context bytes.
// Expected: Public diagnostic output does not disclose plaintext or hex-encoded
//       secret contents, even when the bundle contains several parameter types.
#[test]
fn parameter_diagnostics_do_not_disclose_secret_contents() {
    let secret = b"sensitive-derivation-key-that-must-never-be-logged";
    let mut params = Kbkdf::new(MessageDigest::sha256(), Vec::new(), secret.to_vec());
    params.set_context(secret.to_vec());
    let diagnostics = format!("{:?}", params.to_params().unwrap());
    assert!(!diagnostics.contains(std::str::from_utf8(secret).unwrap()));
    assert!(!diagnostics.contains(&hex::encode(secret)));
    assert!(!diagnostics.is_empty());
}

// IGNORED: CMAC parameter conversion never supplies the required cipher name,
//       so deriving with the advertised CMAC option fails.
//
// Test: Derive AES-128-CMAC counter-mode output from a valid 16-byte key.
// Expected: The advertised CMAC option succeeds and matches an independent
//       SP800-108 result rather than failing for a missing cipher parameter.
#[ignore = "product bug: CMAC mode has no cipher parameter"]
#[test]
fn cmac_mode_derives_with_a_valid_aes128_key() {
    let mut params = Kbkdf::new(
        MessageDigest::sha256(),
        b"label".to_vec(),
        (0..16).collect(),
    );
    params.set_mac(Mac::Cmac);
    params.set_context(b"context".to_vec());
    let mut output = [0; 32];
    derive(params, &mut output).unwrap();
    assert_eq!(
        output.as_slice(),
        hex::decode("4a63599f94bd3bf38b763386bb5397c690a3a40600f96a691059cc001c163c49").unwrap()
    );
}
