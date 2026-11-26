// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public command-line normalization across structured and legacy UEFI options.

use clap::Parser;
use clap::ValueEnum;
use openvmm_entry::Options;
use std::path::Path;
use test_with_tracing::test;

// Test: Combine each legacy UEFI policy switch with structured firmware/debug
//       options and legacy console/diagnostic values.
// Expected: Only the requested legacy policy is enabled; unrelated structured
//       settings and the exact console/diagnostic selections survive merging.
#[test]
fn legacy_switches_merge_without_enabling_unrelated_firmware_policies() {
    for (legacy, expected) in [
        (
            "--uefi-enable-memory-protections",
            [true, false, false, false, false],
        ),
        (
            "--uefi-force-dma-bounce",
            [false, true, false, false, false],
        ),
        (
            "--uefi-force-firmware-version",
            [false, false, true, false, false],
        ),
        ("--disable-frontpage", [false, false, false, true, false]),
        (
            "--default-boot-always-attempt",
            [false, false, false, false, true],
        ),
    ] {
        let options = Options::try_parse_from([
            "openvmm",
            "--uefi",
            "firmware=chosen.fd,debug",
            "--uefi-console-mode",
            "com2",
            "--efi-diagnostics-log-level",
            "info",
            legacy,
        ])
        .unwrap();
        let firmware = options.effective_uefi().unwrap().unwrap();
        assert_eq!(
            [
                firmware.enable_memory_protections,
                firmware.force_dma_bounce,
                firmware.force_firmware_version,
                firmware.disable_frontpage,
                firmware.default_boot_always_attempt,
            ],
            expected,
            "{legacy}"
        );
        assert!(firmware.debug, "{legacy}");
        assert_eq!(firmware.firmware.as_deref(), Some(Path::new("chosen.fd")));
        assert_eq!(
            firmware
                .console
                .unwrap()
                .to_possible_value()
                .unwrap()
                .get_name(),
            "com2"
        );
        assert_eq!(
            firmware
                .diagnostics
                .unwrap()
                .to_possible_value()
                .unwrap()
                .get_name(),
            "info"
        );
    }
}

// Test: Supply the same scalar UEFI option through structured and legacy forms,
//       including identical values.
// Expected: Normalization rejects ambiguous sources rather than silently
//       choosing one, and identifies both conflicting command-line spellings.
#[test]
fn duplicate_uefi_sources_conflict_even_when_their_values_agree() {
    for (key, value, legacy) in [
        ("firmware", "same.fd", "--uefi-firmware"),
        ("console", "com1", "--uefi-console-mode"),
        ("diagnostics", "info", "--efi-diagnostics-log-level"),
    ] {
        let structured = format!("{key}={value}");
        let options =
            Options::try_parse_from(["openvmm", "--uefi", structured.as_str(), legacy, value])
                .unwrap();
        let error = options.effective_uefi().unwrap_err().to_string();
        assert!(error.contains(&format!("--uefi {key}=")), "{error}");
        assert!(error.contains(legacy), "{error}");
    }
}
