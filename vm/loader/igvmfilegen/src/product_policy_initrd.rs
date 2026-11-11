// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Append measured product policy to the OpenHCL initrd.

use anyhow::Context as _;
use igvmfilegen_config::Config;
use igvmfilegen_config::Image;
use product_policy::ProductPolicy;

pub fn apply_to_config(config: &mut Config, policy_json: &str) -> anyhow::Result<()> {
    let policy: ProductPolicy =
        serde_json::from_str(policy_json).context("parsing product policy JSON")?;
    validate(&policy)?;

    let mut has_openhcl = false;
    for (index, guest) in config.guest_configs.iter().enumerate() {
        if let Image::Openhcl { product_policy, .. } = &guest.image {
            has_openhcl = true;
            anyhow::ensure!(
                product_policy.is_none(),
                "--product-policy conflicts with inline product_policy in guest config {index}"
            );
        }
    }
    anyhow::ensure!(
        has_openhcl,
        "--product-policy requires at least one OpenHCL image"
    );

    for guest in &mut config.guest_configs {
        if let Image::Openhcl { product_policy, .. } = &mut guest.image {
            *product_policy = Some(policy.clone());
        }
    }
    Ok(())
}

fn validate(policy: &ProductPolicy) -> anyhow::Result<()> {
    let (require_secure_boot, require_vars, require_bcd, custom_uefi_json) = match policy {
        ProductPolicy::Sivm(p) => (
            p.require_secure_boot,
            p.require_secure_boot_vars,
            p.require_bcd_integrity,
            &p.custom_uefi_json,
        ),
        ProductPolicy::Cwcow(p) => (
            p.require_secure_boot,
            p.require_secure_boot_vars,
            p.require_bcd_integrity,
            &p.custom_uefi_json,
        ),
    };
    anyhow::ensure!(
        !(require_secure_boot && (require_vars || require_bcd) && custom_uefi_json.is_empty()),
        "product policy requires non-empty custom_uefi_json"
    );
    Ok(())
}

pub fn append(initrd: &mut Vec<u8>, policy: &ProductPolicy) -> anyhow::Result<()> {
    validate(policy)?;
    let bytes = product_policy::encode_product_policy(policy);
    initrd_cpio::append_to_initrd(
        initrd,
        product_policy::PRODUCT_POLICY_PATH.trim_start_matches('/'),
        &bytes,
        0o100400,
    )
    .context("failed to append product policy to OpenHCL initrd")
}

#[cfg(test)]
mod tests {
    use super::*;
    use product_policy::cwcow::CwcowPolicy;
    use product_policy::sivm::SivmPolicy;
    use std::collections::BTreeMap;
    use std::io::Read as _;
    use test_with_tracing::test;

    const SIVM_JSON: &str = r#"{
        "sivm": {
            "require_ephemeral_vmgs": false,
            "require_secure_boot": true,
            "require_secure_boot_vars": true,
            "require_bcd_integrity": false,
            "custom_uefi_json": "e30="
        }
    }"#;

    const CWCOW_JSON: &str = r#"{
        "cwcow": {
            "require_ephemeral_vmgs": false,
            "require_secure_boot": true,
            "require_secure_boot_vars": true,
            "require_bcd_integrity": false,
            "custom_uefi_json": "e30=",
            "require_secure_avic": false
        }
    }"#;

    fn openhcl_config() -> Config {
        serde_json::from_str(include_str!("../../manifests/openhcl-x64-cvm-release.json")).unwrap()
    }

    fn assert_rejected_without_changes(config: &mut Config, json: &str, message: &str) {
        let before = serde_json::to_value(&*config).unwrap();
        let error = apply_to_config(config, json).unwrap_err();
        assert!(
            format!("{error:#}").contains(message),
            "unexpected error: {error:#}"
        );
        assert_eq!(serde_json::to_value(config).unwrap(), before);
    }

    #[test]
    fn standalone_policy_applies_to_all_platforms_and_round_trips_through_initrd() {
        let mut config = openhcl_config();
        apply_to_config(&mut config, SIVM_JSON).unwrap();
        let expected = ProductPolicy::Sivm(SivmPolicy {
            require_secure_boot: true,
            require_secure_boot_vars: true,
            custom_uefi_json: b"{}".to_vec(),
            ..Default::default()
        });

        assert_eq!(config.guest_configs.len(), 3);
        for guest in &config.guest_configs {
            let Image::Openhcl { product_policy, .. } = &guest.image else {
                panic!("expected OpenHCL image");
            };
            let policy = product_policy.as_ref().unwrap();
            assert_eq!(policy, &expected);

            let mut initrd = Vec::new();
            initrd_cpio::append_to_initrd(&mut initrd, "init", b"existing init", 0o100400).unwrap();
            let original = initrd.clone();
            append(&mut initrd, policy).unwrap();
            assert_eq!(initrd[..original.len()], original);
            let files = extract_files(&initrd);
            assert_eq!(files["init"], b"existing init");
            assert_eq!(
                product_policy::decode_product_policy(
                    &files[product_policy::PRODUCT_POLICY_PATH.trim_start_matches('/')]
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn standalone_policy_preserves_other_image_types() {
        let mut config = openhcl_config();
        config.guest_configs[0].image = Image::None;
        let before = serde_json::to_value(&config.guest_configs[0]).unwrap();
        apply_to_config(&mut config, SIVM_JSON).unwrap();
        assert_eq!(
            serde_json::to_value(&config.guest_configs[0]).unwrap(),
            before
        );
        for guest in &config.guest_configs[1..] {
            assert!(matches!(
                &guest.image,
                Image::Openhcl {
                    product_policy: Some(ProductPolicy::Sivm(_)),
                    ..
                }
            ));
        }
    }

    #[test]
    fn standalone_policy_rejects_inline_conflict_without_partial_application() {
        let mut config = openhcl_config();
        let Image::Openhcl { product_policy, .. } = &mut config.guest_configs[2].image else {
            panic!("expected OpenHCL image");
        };
        *product_policy = Some(ProductPolicy::Sivm(SivmPolicy::default()));
        assert_rejected_without_changes(&mut config, SIVM_JSON, "guest config 2");
    }

    #[test]
    fn standalone_policy_requires_openhcl() {
        let mut config: Config =
            serde_json::from_str(include_str!("../../manifests/uefi-x64.json")).unwrap();
        assert_rejected_without_changes(&mut config, SIVM_JSON, "at least one OpenHCL image");
        config.guest_configs.clear();
        assert_rejected_without_changes(&mut config, SIVM_JSON, "at least one OpenHCL image");
    }

    #[test]
    fn standalone_policy_rejects_invalid_json_and_schema() {
        for json in [
            "{",
            r#"{"unknown_product": {}}"#,
            &SIVM_JSON.replace("\"require_ephemeral_vmgs\"", "\"unknown_field\""),
            &SIVM_JSON.replace("e30=", "***"),
        ] {
            assert_rejected_without_changes(&mut openhcl_config(), json, "parsing product policy");
        }
    }

    #[test]
    fn standalone_policy_validates_before_applying() {
        for json in [
            SIVM_JSON.replace("e30=", ""),
            CWCOW_JSON.replace("e30=", ""),
        ] {
            assert_rejected_without_changes(
                &mut openhcl_config(),
                &json,
                "non-empty custom_uefi_json",
            );
        }
    }

    #[test]
    fn standalone_policy_accepts_cwcow() {
        let mut config = openhcl_config();
        apply_to_config(&mut config, CWCOW_JSON).unwrap();
        for guest in &config.guest_configs {
            let Image::Openhcl { product_policy, .. } = &guest.image else {
                panic!("expected OpenHCL image");
            };
            assert_eq!(
                product_policy.as_ref().unwrap(),
                &ProductPolicy::Cwcow(CwcowPolicy {
                    require_secure_boot: true,
                    require_secure_boot_vars: true,
                    custom_uefi_json: b"{}".to_vec(),
                    ..Default::default()
                })
            );
        }
    }

    fn extract_files(initrd: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut archive = Vec::new();
        flate2::read::MultiGzDecoder::new(initrd)
            .read_to_end(&mut archive)
            .unwrap();
        let mut files = BTreeMap::new();
        let mut offset = 0;
        while offset < archive.len() {
            let header = &archive[offset..offset + 110];
            assert_eq!(&header[..6], b"070701");
            let field = |start| {
                usize::from_str_radix(std::str::from_utf8(&header[start..start + 8]).unwrap(), 16)
                    .unwrap()
            };
            let size = field(54);
            let name_size = field(94);
            let name_start = offset + 110;
            let name = std::str::from_utf8(&archive[name_start..name_start + name_size - 1])
                .unwrap()
                .to_owned();
            assert_eq!(archive[name_start + name_size - 1], 0);
            offset = (name_start + name_size).next_multiple_of(4);
            if name != "TRAILER!!!" {
                assert_eq!(field(14), 0o100400);
                files.insert(name, archive[offset..offset + size].to_vec());
            }
            offset = (offset + size).next_multiple_of(4);
        }
        files
    }

    #[test]
    fn appended_policy_preserves_layers_and_overrides_previous_policy() {
        let mut initrd = Vec::new();
        initrd_cpio::append_to_initrd(&mut initrd, "init", b"existing init", 0o100400).unwrap();
        initrd_cpio::append_to_initrd(&mut initrd, "extra-layer", b"extra data", 0o100400).unwrap();
        let old_policy = ProductPolicy::Sivm(SivmPolicy::default());
        append(&mut initrd, &old_policy).unwrap();
        let original = initrd.clone();

        let policy = ProductPolicy::Sivm(SivmPolicy {
            require_secure_boot: true,
            require_secure_boot_vars: true,
            custom_uefi_json: vec![0xA5; 8192],
            ..Default::default()
        });
        append(&mut initrd, &policy).unwrap();
        assert_eq!(&initrd[..original.len()], &original);
        let files = extract_files(&initrd);
        assert_eq!(files["init"], b"existing init");
        assert_eq!(files["extra-layer"], b"extra data");
        let bytes = &files[product_policy::PRODUCT_POLICY_PATH.trim_start_matches('/')];
        assert_eq!(
            product_policy::decode_product_policy(bytes).unwrap(),
            policy
        );
    }

    #[test]
    fn cwcow_policy_round_trips_through_initrd() {
        let policy = ProductPolicy::Cwcow(CwcowPolicy {
            require_secure_boot: true,
            ..Default::default()
        });
        let mut initrd = Vec::new();
        append(&mut initrd, &policy).unwrap();
        let files = extract_files(&initrd);
        let bytes = &files[product_policy::PRODUCT_POLICY_PATH.trim_start_matches('/')];
        assert_eq!(
            product_policy::decode_product_policy(bytes).unwrap(),
            policy
        );
    }

    #[test]
    fn invalid_policy_does_not_modify_initrd() {
        for policy in [
            ProductPolicy::Sivm(SivmPolicy {
                require_secure_boot: true,
                require_secure_boot_vars: true,
                ..Default::default()
            }),
            ProductPolicy::Cwcow(CwcowPolicy {
                require_secure_boot: true,
                require_bcd_integrity: true,
                ..Default::default()
            }),
        ] {
            let mut initrd = vec![1, 2, 3];
            let error = append(&mut initrd, &policy).unwrap_err();
            assert!(error.to_string().contains("non-empty custom_uefi_json"));
            assert_eq!(initrd, [1, 2, 3]);
        }
    }
}
