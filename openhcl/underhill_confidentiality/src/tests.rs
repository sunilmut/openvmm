// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::prelude::rust_2024::*;
use std::process::Command;
use test_with_tracing::test;

fn filtering(values: [Option<&std::ffi::OsStr>; 4]) -> bool {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tests::policy_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("CONFIDENTIALITY_FIXTURE", "1");
    for (name, value) in [
        crate::OPENHCL_CONFIDENTIAL_ENV_VAR_NAME,
        crate::LEGACY_CONFIDENTIAL_ENV_VAR_NAME,
        crate::OPENHCL_CONFIDENTIAL_DEBUG_ENV_VAR_NAME,
        crate::LEGACY_CONFIDENTIAL_DEBUG_ENV_VAR_NAME,
    ]
    .into_iter()
    .zip(values)
    {
        match value {
            Some(value) => {
                command.env(name, value);
            }
            None => {
                command.env_remove(name);
            }
        }
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let output = String::from_utf8(output.stdout).unwrap();
    if output.lines().any(|line| line == "filtering:true") {
        true
    } else {
        assert!(
            output.lines().any(|line| line == "filtering:false"),
            "{output}"
        );
        false
    }
}

// Test: Resolve confidentiality and debug policy for current and legacy flags.
// Expected: Either confidential flag enables restrictions; either debug flag
//       explicitly disables them, without coupling the two independent inputs.
#[test]
fn current_and_legacy_flags_preserve_diagnostic_restriction_policy() {
    for confidential in [false, true] {
        for debug in [false, true] {
            for legacy_cvm in [false, true] {
                for legacy_debug in [false, true] {
                    let values = [
                        if confidential {
                            Some("1".as_ref())
                        } else {
                            None
                        },
                        if legacy_cvm { Some("1".as_ref()) } else { None },
                        if debug { Some("1".as_ref()) } else { None },
                        if legacy_debug {
                            Some("1".as_ref())
                        } else {
                            None
                        },
                    ];
                    assert_eq!(
                        filtering(values),
                        (confidential || legacy_cvm) && !(debug || legacy_debug)
                    );
                }
            }
        }
    }
}

// Test: Supply explicitly disabled and empty flags alongside enabled aliases.
// Expected: Disabled values neither enable restrictions/debugging themselves
//       nor mask an independently enabled alias.
#[test]
fn empty_and_zero_flags_do_not_mask_enabled_aliases() {
    for disabled in ["", "0"] {
        let disabled = Some(disabled.as_ref());
        assert!(!filtering([disabled; 4]));
        assert!(filtering([
            disabled,
            Some("1".as_ref()),
            disabled,
            disabled
        ]));
        assert!(filtering([
            Some("1".as_ref()),
            disabled,
            disabled,
            disabled
        ]));
        assert!(!filtering([
            Some("1".as_ref()),
            disabled,
            disabled,
            Some("1".as_ref())
        ]));
        assert!(!filtering([
            disabled,
            Some("1".as_ref()),
            Some("1".as_ref()),
            disabled
        ]));
    }
}

// Test: Evaluate the public policy with process-isolated environment inputs.
// Expected: The diagnostic restriction decision is emitted without mutation
//       of shared environment variables or private OnceLock state.
// IGNORED: Parent tests invoke this fixture in isolated child processes.
//       Its ignored status is host-fixture control, not a product failure.
#[test]
#[ignore = "subprocess fixture invoked by parent tests"]
fn policy_fixture() {
    assert_eq!(std::env::var("CONFIDENTIALITY_FIXTURE").unwrap(), "1");
    std::println!("filtering:{}", crate::confidential_filtering_enabled());
}
