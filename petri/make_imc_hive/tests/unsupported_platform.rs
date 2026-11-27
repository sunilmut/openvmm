// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Behavior of the non-Windows build of make_imc_hive.

#![cfg(not(windows))]

// Test: Run the make_imc_hive binary built for a non-Windows host, with and
//       without an output path argument.
// Expected: It exits with status 1 and explains on stderr that the OS is
//       unsupported, writing nothing to stdout and creating no output file.
#[test]
fn non_windows_build_reports_unsupported_os() {
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("imc.hiv");
    for args in [vec![], vec![output_path.clone().into_os_string()]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_make_imc_hive"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(output.stderr, b"not supported on this OS\n", "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(!output_path.exists());
}
