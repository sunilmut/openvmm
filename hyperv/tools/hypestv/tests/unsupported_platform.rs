// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Behavior of the non-Windows build of hypestv.

#![cfg(not(windows))]

// Test: Run the hypestv binary built for a non-Windows host, with and without
//       a VM name argument.
// Expected: It exits with status 1 and explains on stderr that the platform
//       is unsupported, writing nothing to stdout.
#[test]
fn non_windows_build_reports_unsupported_platform() {
    for args in [&[][..], &["my-vm"]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_hypestv"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(
            output.stderr, b"not supported on this platform\n",
            "{args:?}"
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}
