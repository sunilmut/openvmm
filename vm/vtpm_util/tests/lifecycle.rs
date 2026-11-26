// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public vTPM blob restore/export lifecycle regressions.

use std::fs;
use test_with_tracing::test;
use tpm_protocol::tpm20proto::AlgIdEnum;
use tpm_protocol::tpm20proto::protocol::Tpm2bPublic;
use vtpm_util::TpmVersion;

static TPM_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

// Test: Restore each supported blob version twice and export its persisted SRK.
// Expected: Fresh engine lifetimes yield identical valid RSA-2048/SHA256 public
//       areas, and exporting never changes the input NV state.
#[test]
fn repeated_srk_export_preserves_blob_and_key_identity() {
    let _guard = TPM_LOCK.lock();
    let directory = tempfile::tempdir_in(".").unwrap();
    for (name, version) in [("138", TpmVersion::V138), ("185", TpmVersion::V185)] {
        let blob = directory.path().join(format!("{name}.blob"));
        let first = directory.path().join(format!("{name}-first.tpm2b"));
        let second = directory.path().join(format!("{name}-second.tpm2b"));
        match version {
            TpmVersion::V138 => vtpm_util::create_vtpm_blob_file(blob.to_str().unwrap()).unwrap(),
            TpmVersion::V185 => {
                vtpm_util::create_vtpm_blob_file_with_version(blob.to_str().unwrap(), version)
                    .unwrap()
            }
        }
        let original = fs::read(&blob).unwrap();
        for output in [&first, &second] {
            match version {
                TpmVersion::V138 => {
                    vtpm_util::write_srk(blob.to_str().unwrap(), output.to_str().unwrap()).unwrap()
                }
                TpmVersion::V185 => vtpm_util::write_srk_with_version(
                    blob.to_str().unwrap(),
                    output.to_str().unwrap(),
                    version,
                )
                .unwrap(),
            }
            assert_eq!(fs::read(&blob).unwrap(), original);
        }
        let public = fs::read(&first).unwrap();
        assert_eq!(public, fs::read(&second).unwrap());
        let parsed = Tpm2bPublic::deserialize(&public).unwrap();
        assert_eq!(usize::from(parsed.size.get()) + 2, public.len());
        assert_eq!(parsed.public_area.my_type, AlgIdEnum::RSA.into());
        assert_eq!(parsed.public_area.name_alg, AlgIdEnum::SHA256.into());
        assert_eq!(parsed.public_area.parameters.key_bits.get(), 2048);
        assert_eq!(parsed.public_area.unique.size.get(), 256);
        assert!(
            parsed.public_area.unique.buffer[..256]
                .iter()
                .any(|&b| b != 0)
        );
        vtpm_util::print_key_name(first.to_str().unwrap()).unwrap();
    }
}

// Test: Export an SRK from missing and truncated persisted-state files.
// Expected: Both versions return contextual errors without publishing output or
//       modifying the invalid source; failed restore releases its engine.
#[test]
fn failed_restore_does_not_publish_an_srk() {
    let _guard = TPM_LOCK.lock();
    let directory = tempfile::tempdir_in(".").unwrap();
    let input = directory.path().join("input.blob");
    let output = directory.path().join("output.tpm2b");
    let error =
        vtpm_util::write_srk(input.to_str().unwrap(), output.to_str().unwrap()).unwrap_err();
    assert_eq!(error.to_string(), "failed to read vTPM blob file");
    assert!(!output.exists());
    let invalid = b"truncated NV state";
    fs::write(&input, invalid).unwrap();
    for (name, version) in [("138", TpmVersion::V138), ("185", TpmVersion::V185)] {
        vtpm_util::write_srk_with_version(
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            version,
        )
        .unwrap_err();
        assert!(!output.exists());
        assert_eq!(fs::read(&input).unwrap(), invalid);
        let valid = directory.path().join(format!("recovered-{name}.blob"));
        vtpm_util::create_vtpm_blob_file_with_version(valid.to_str().unwrap(), version).unwrap();
        vtpm_util::write_srk_with_version(
            valid.to_str().unwrap(),
            output.to_str().unwrap(),
            version,
        )
        .unwrap();
        Tpm2bPublic::deserialize(&fs::read(&output).unwrap()).unwrap();
        fs::remove_file(&output).unwrap();
    }
}
