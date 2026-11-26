// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::{Command, Output};
use test_with_tracing::test;

fn run_build_script(host: &str, guest: Option<&str>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tests::guest_arch_directives_distinguish_native_and_cross_guest_builds",
            "--nocapture",
        ])
        .env("OPENVMM_BUILD_ARCH_TEST_CHILD", "1")
        // xtask-fmt allow-target-arch oneoff-guest-arch-impl
        .env("CARGO_CFG_TARGET_ARCH", host)
        .env_remove("OPENVMM_GUEST_TARGET");
    if let Some(guest) = guest {
        command.env("OPENVMM_GUEST_TARGET", guest);
    }
    command.output().unwrap()
}

// Test: Run the public build-script emitter with native, cross-guest and invalid targets.
// Expected: Exact Cargo directives select the guest independently of the host,
//       advertise supported cfg values, and reject unsupported targets explicitly.
#[test]
fn guest_arch_directives_distinguish_native_and_cross_guest_builds() {
    // The parent checks the child's output without mutating shared environment state.
    if std::env::var_os("OPENVMM_BUILD_ARCH_TEST_CHILD").is_some() {
        crate::emit_guest_arch();
        return;
    }
    for (host, guest, expected_guest, native) in [
        ("x86_64", None, "x86_64", true),
        ("aarch64", None, "aarch64", true),
        ("x86_64", Some("x86_64"), "x86_64", true),
        ("aarch64", Some("aarch64"), "aarch64", true),
        ("x86_64", Some("aarch64"), "aarch64", false),
        ("aarch64", Some("x86_64"), "x86_64", false),
    ] {
        let output = run_build_script(host, guest);
        assert!(
            output.status.success(),
            "host={host}, guest={guest:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let directives: Vec<_> = stdout
            .lines()
            .filter(|line| line.starts_with("cargo:"))
            .collect();
        let mut expected = vec![
            "cargo:rerun-if-env-changed=OPENVMM_GUEST_TARGET".to_owned(),
            format!("cargo:rustc-cfg=guest_arch=\"{expected_guest}\""),
        ];
        if native {
            expected.push("cargo:rustc-cfg=guest_is_native".to_owned());
        }
        expected.extend([
            "cargo:rustc-check-cfg=cfg(guest_arch, values(\"x86_64\",\"aarch64\"))".to_owned(),
            "cargo:rustc-check-cfg=cfg(guest_is_native)".to_owned(),
        ]);
        assert_eq!(directives, expected, "host={host}, guest={guest:?}");
    }
    for (host, guest) in [
        ("x86_64", Some("riscv64")),
        ("aarch64", Some("")),
        ("riscv64", None),
    ] {
        let output = run_build_script(host, guest);
        assert!(!output.status.success(), "host={host}, guest={guest:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("unknown guest arch"), "{stderr}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("cargo:rustc-cfg=guest_arch="), "{stdout}");
    }
}
