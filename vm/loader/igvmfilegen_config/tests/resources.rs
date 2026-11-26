// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manifest resource discovery and validation through the public configuration API.

use igvmfilegen_config::*;
use std::collections::HashMap;
use std::ffi::CString;
use test_with_tracing::test;

// Test: Resolve resources for an OpenHCL image with both firmware and Linux.
// Expected: Missing payloads are reported in order and adding their paths
//       satisfies the complete configuration, including serialized resources.
#[test]
fn combined_image_resources_are_checked_as_a_whole() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "guest_arch": "x64",
        "guest_configs": {"none": {
            "guest_svn": 0, "max_vtl": 2,
            "image": {"openhcl": {
                "memory_page_count": 4096, "uefi": true,
                "linux": {"use_initrd": true, "command_line": "console=ttyS0"}
            }}
        }}
    }))
    .unwrap();
    let required = config.required_resources();
    assert_eq!(
        required,
        [
            ResourceType::UnderhillKernel,
            ResourceType::OpenhclBoot,
            ResourceType::UnderhillInitrd,
            ResourceType::Uefi,
            ResourceType::LinuxKernel,
            ResourceType::LinuxInitrd,
        ]
    );
    let root = std::env::current_dir().unwrap();
    let mut paths = HashMap::from([
        (ResourceType::UnderhillKernel, root.join("kernel")),
        (ResourceType::OpenhclBoot, root.join("boot")),
        (ResourceType::UnderhillInitrd, root.join("initrd")),
        (ResourceType::Uefi, root.join("firmware")),
    ]);
    let resources = Resources::new(paths.clone()).unwrap();
    let missing = resources.check_required(&required).unwrap_err();
    assert_eq!(
        missing.0,
        [ResourceType::LinuxKernel, ResourceType::LinuxInitrd]
    );
    assert!(missing.to_string().contains("LinuxInitrd"));
    paths.insert(ResourceType::LinuxKernel, root.join("linux"));
    paths.insert(ResourceType::LinuxInitrd, root.join("linux-initrd"));
    let resources = Resources::new(paths).unwrap();
    resources.check_required(&required).unwrap();
    let serialized = serde_json::to_string(&resources).unwrap();
    let restored: Resources = serde_json::from_str(&serialized).unwrap();
    restored.check_required(&required).unwrap();
    assert_eq!(
        restored.get(ResourceType::LinuxKernel),
        Some(&root.join("linux"))
    );
}

// Test: Request no payload, firmware only, or Linux without an initrd.
// Expected: Discovery does not require unrelated optional boot artifacts.
#[test]
fn minimal_image_resources_do_not_require_optional_payloads() {
    for (image, expected) in [
        (Image::None, vec![]),
        (
            Image::Uefi {
                config_type: UefiConfigType::None,
            },
            vec![ResourceType::Uefi],
        ),
        (
            Image::Linux(LinuxImage {
                use_initrd: false,
                command_line: CString::new("").unwrap(),
            }),
            vec![ResourceType::LinuxKernel],
        ),
    ] {
        assert_eq!(image.required_resources(), expected);
    }
}

// Test: Read duplicate guest entries from a serialized manifest.
// Expected: The second entry is rejected rather than silently replacing a guest.
#[test]
fn duplicate_guest_configuration_is_rejected() {
    let manifest = r#"{
        "guest_arch": "x64",
        "guest_configs": {
            "none": {"guest_svn": 1, "max_vtl": 0, "image": "none"},
            "none": {"guest_svn": 2, "max_vtl": 0, "image": "none"}
        }
    }"#;
    let error = serde_json::from_str::<Config>(manifest).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("duplicate guest config for None"),
        "{error}"
    );
}

// Test: Construct and deserialize resources containing a relative payload path.
// Expected: Both entry points identify the invalid resource and its path.
#[test]
fn relative_resource_paths_report_the_offending_payload() {
    let root = std::env::current_dir().unwrap();
    let paths = HashMap::from([
        (ResourceType::Uefi, root.join("firmware")),
        (ResourceType::LinuxKernel, "./linux".into()),
    ]);
    let error = Resources::new(paths.clone()).unwrap_err().to_string();
    assert!(error.contains("LinuxKernel"), "{error}");
    assert!(error.contains("./linux"), "{error}");

    let serialized = serde_json::json!({"resources": paths});
    let error = serde_json::from_value::<Resources>(serialized)
        .unwrap_err()
        .to_string();
    assert!(error.contains("LinuxKernel"), "{error}");
    assert!(error.contains("./linux"), "{error}");
}
