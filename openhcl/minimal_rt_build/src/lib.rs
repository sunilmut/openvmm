// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

/// Initializes compiler flags for building a minimal kernel using the
/// `minimal_rt` crate.
///
/// Only does anything if the `MINIMAL_RT_BUILD` environment variable is set.
///
/// Also, sets the `minimal_rt` `cfg` so that code can detect that it should
/// build for running as a minimal kernel.
pub fn init() -> bool {
    println!("cargo:rustc-check-cfg=cfg(minimal_rt)");

    // If the user sets this environment variable, build the binary for use as a
    // boot loader. Otherwise, just build a stub binary for unit tests, clippy,
    // rust-analyzer, etc.
    //
    // We don't use a feature for this because because this would break
    // `--all-features`. We don't use a profile or something for this because
    // cargo doesn't want us to know about custom profiles. There's no other
    // mechanism I know of to communicate this information through cargo.
    println!("cargo:rerun-if-env-changed=MINIMAL_RT_BUILD");
    if matches!(
        std::env::var("MINIMAL_RT_BUILD").as_deref().ok(),
        None | Some("")
    ) {
        return false;
    }

    let triple = std::env::var("TARGET").unwrap();
    let unsupported = |supported_triple| {
        panic!(
            "build is only supported with the {} target, not {}, clear MINIMAL_RT_BUILD",
            supported_triple, triple
        );
    };
    // xtask-fmt allow-target-arch sys-crate
    match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => {
            // This is the supported triple for x86-64 because, compared to a
            // linux target, it disables the red zone (needed to prevent
            // interrupts from overwriting the stack) and it disables use of SSE
            // by default (needed to avoid accidentally using SSE intrinstics in
            // various places).
            //
            // No special linker flags are needed.
            if triple != "x86_64-unknown-none" {
                unsupported("x86_64-unknown-none");
            }
        }
        "aarch64" => {
            match triple.as_str() {
                "aarch64-minimal_rt-none" => {
                    // This is a custom target, defined via
                    // aarch64-minimal_rt-none.json. So, it requires
                    // RUSTC_BOOTSTRAP=1 or an unstable toolchain in order to
                    // use `-Zbuild-std`.
                    //
                    // It is aarch64-unknown-none with support for static PIE
                    // binaries, which we need to support loading the image
                    // anywhere in PA space.
                }
                "aarch64-unknown-linux-musl" => {
                    // This target works (it supports static PIE binaries) and
                    // does not require an unstable toolchain, but it is
                    // difficult to build from non-Linux host environments.
                    //
                    // This does require some tweaks to the linker flags.
                    //
                    // Don't include the _start entry point.
                    println!("cargo:rustc-link-arg=-nostartfiles");
                    // Make the executable relocatable.
                    println!("cargo:rustc-link-arg=-static-pie");
                }
                _ => {
                    unsupported("aarch64-unknown-linux-musl");
                }
            }
        }
        arch => panic!("unsupported arch {arch}"),
    }

    println!("cargo:rustc-cfg=minimal_rt");
    true
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::process::Output;
    use test_with_tracing::test;

    fn run_build(build: Option<&str>, arch: Option<&str>, target: Option<&str>) -> Output {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "tests::build_script_fixture",
            "--ignored",
            "--nocapture",
        ]);
        for (key, value) in [
            ("MINIMAL_RT_BUILD", build),
            // xtask-fmt allow-target-arch sys-crate
            ("CARGO_CFG_TARGET_ARCH", arch),
            ("TARGET", target),
        ] {
            command.env_remove(key);
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        command.output().unwrap()
    }

    fn directives(output: &Output) -> Vec<String> {
        String::from_utf8(output.stdout.clone())
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("cargo:"))
            .map(str::to_owned)
            .collect()
    }

    // Test: Invoke the real build initializer in an isolated child environment.
    // Expected: Its returned build mode and Cargo directives reach the parent;
    //       this fixture is not independently selected during ordinary test runs.
    #[test]
    #[ignore = "subprocess fixture for build environment tests, not a product regression"]
    fn build_script_fixture() {
        println!("build-enabled={}", super::init());
    }

    // Test: Leave the build switch unset or empty without Cargo target metadata.
    // Expected: Initialization remains a stub build and emits only cfg validation
    //       and environment-change tracking, without consulting absent target variables.
    #[test]
    fn absent_or_empty_switch_is_a_stub_build() {
        for build in [None, Some("")] {
            let output = run_build(build, None, None);
            assert!(output.status.success(), "{output:?}");
            assert_eq!(
                directives(&output),
                [
                    "cargo:rustc-check-cfg=cfg(minimal_rt)",
                    "cargo:rerun-if-env-changed=MINIMAL_RT_BUILD",
                ]
            );
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("build-enabled=false")
            );
        }
    }

    // Test: Enable each supported architecture/target combination in child processes.
    // Expected: Only the ARM64 musl target receives static-PIE/no-start-files flags;
    //       every supported target enables minimal_rt, even with switch text "0".
    #[test]
    fn supported_targets_emit_only_their_required_linker_flags() {
        for (arch, target, linker_flags) in [
            ("x86_64", "x86_64-unknown-none", false),
            ("aarch64", "aarch64-minimal_rt-none", false),
            ("aarch64", "aarch64-unknown-linux-musl", true),
        ] {
            let output = run_build(Some("0"), Some(arch), Some(target));
            assert!(output.status.success(), "{output:?}");
            let mut expected = vec![
                "cargo:rustc-check-cfg=cfg(minimal_rt)",
                "cargo:rerun-if-env-changed=MINIMAL_RT_BUILD",
            ];
            if linker_flags {
                expected.extend([
                    "cargo:rustc-link-arg=-nostartfiles",
                    "cargo:rustc-link-arg=-static-pie",
                ]);
            }
            expected.push("cargo:rustc-cfg=minimal_rt");
            assert_eq!(directives(&output), expected);
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("build-enabled=true")
            );
        }
    }

    // Test: Request unsupported architectures and incompatible target triples.
    // Expected: Build initialization fails with actionable diagnostics and does
    //       not emit the minimal_rt cfg or linker flags for an unsupported target.
    #[test]
    fn unsupported_targets_fail_without_enabling_minimal_rt() {
        for (arch, target, diagnostic) in [
            ("x86_64", "x86_64-unknown-linux-musl", "x86_64-unknown-none"),
            (
                "aarch64",
                "aarch64-unknown-none",
                "aarch64-unknown-linux-musl",
            ),
            (
                "riscv64",
                "riscv64gc-unknown-none-elf",
                "unsupported arch riscv64",
            ),
        ] {
            let output = run_build(Some("yes"), Some(arch), Some(target));
            assert!(!output.status.success());
            assert!(
                std::str::from_utf8(&output.stderr)
                    .unwrap()
                    .contains(diagnostic)
            );
            assert_eq!(
                directives(&output),
                [
                    "cargo:rustc-check-cfg=cfg(minimal_rt)",
                    "cargo:rerun-if-env-changed=MINIMAL_RT_BUILD",
                ]
            );
        }
    }
}
