// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod nv_tests;
mod report_tests;

fn config(args: &[&str]) -> Result<Config, String> {
    config_from_cli(
        Cli::try_parse_from(std::iter::once("tpm_guest_tests").chain(args.iter().copied()))
            .unwrap(),
    )
}

// Test: Parse every command's supported text/hex/geometry options into the configuration consumed by the TPM runner.
// Expected: Binary values, NV indices/sizes, retry count, output path, and report flags retain their exact user-supplied meaning rather than being dropped or routed to another action.
#[test]
fn command_configuration_preserves_exact_arguments() {
    let value = config(&[
        "ak_cert",
        "--expected-data",
        "certificate",
        "--retry",
        "3",
        "--output-file",
        "cert.bin",
    ])
    .unwrap();
    assert!(value.ak_cert && !value.report);
    assert_eq!(value.ak_cert_expected.unwrap(), b"certificate");
    assert_eq!(value.ak_cert_retry_attempts, 3);
    assert_eq!(
        value.ak_cert_output_file.unwrap(),
        PathBuf::from("cert.bin")
    );
    let value = config(&[
        "report",
        "--user-data",
        "guest-input",
        "--show-runtime-claims",
    ])
    .unwrap();
    assert!(value.report && value.show_runtime_claims && !value.ak_cert);
    assert_eq!(value.user_data.unwrap(), b"guest-input");
    assert_eq!(
        config(&["report", "--user-data-hex", "0x0091ff"])
            .unwrap()
            .user_data
            .unwrap(),
        [0, 0x91, 0xff]
    );
    let value = config(&["nv_define", "--index", "0x1500016", "--size", "65535"])
        .unwrap()
        .nv_define
        .unwrap();
    assert_eq!((value.index, value.size), (0x1500016, u16::MAX));
    let value = config(&["nv_write", "--index", "1500016", "--data-hex", "0091ff"])
        .unwrap()
        .nv_write
        .unwrap();
    assert_eq!(value.index, 0x1500016);
    assert_eq!(value.data, [0, 0x91, 0xff]);
    let value = config(&[
        "nv_read",
        "--index",
        "1500016",
        "--expected-data-hex",
        "0x00ff",
    ])
    .unwrap()
    .nv_read
    .unwrap();
    assert_eq!(value.index, 0x1500016);
    assert_eq!(value.expected.unwrap(), [0, 0xff]);
    assert!(
        config(&["nv_read", "--index", "1500016"])
            .unwrap()
            .nv_read
            .unwrap()
            .expected
            .is_none()
    );
}

// Test: Supply malformed hex data, conflicting text/hex flags, out-of-range NV indices and sizes, and invalid retry values.
// Expected: CLI/config validation rejects each invalid input with its relevant option context and never attempts TPM I/O.
#[test]
fn invalid_cli_inputs_are_rejected_before_tpm_access() {
    for (args, option) in [
        (
            vec!["ak_cert", "--expected-data-hex", "0"],
            "--expected-data-hex",
        ),
        (vec!["report", "--user-data-hex", "q0"], "--user-data-hex"),
        (
            vec!["nv_write", "--index", "1", "--data-hex", "0q"],
            "--data-hex",
        ),
        (
            vec!["nv_read", "--index", "1", "--expected-data-hex", "q0"],
            "--expected-data-hex",
        ),
    ] {
        assert!(config(&args).unwrap_err().contains(option));
    }
    for args in [
        vec![
            "ak_cert",
            "--expected-data",
            "a",
            "--expected-data-hex",
            "61",
        ],
        vec!["report", "--user-data", "a", "--user-data-hex", "61"],
        vec!["nv_read", "--index", "100000000"],
        vec!["nv_read", "--index", "invalid"],
        vec!["nv_define", "--index", "1", "--size", "65536"],
        vec!["ak_cert", "--retry", "0"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("tpm_guest_tests").chain(args)).is_err());
    }
    assert_eq!(
        parse_hex_bytes(" 0x0091aBff ").unwrap(),
        [0, 0x91, 0xab, 0xff]
    );
    assert!(parse_hex_bytes("").unwrap().is_empty());
    assert_eq!(parse_nv_index(" 0xffffffff ").unwrap(), u32::MAX);
}

// Test: Build guest-input payloads at zero/short/exact capacity and above capacity, plus the default timestamped request.
// Expected: Explicit bytes are unchanged with only trailing zero padding to 64 bytes; 65 bytes fail, and the default embeds a parseable timestamp and zero tail.
#[test]
fn guest_input_payload_preserves_binary_data_and_capacity() {
    for length in [0, 1, 63, 64] {
        let input = vec![0x91; length];
        let payload = build_guest_input_payload(Some(&input)).unwrap();
        assert_eq!(payload.len(), 64);
        assert_eq!(&payload[..length], input);
        assert!(payload[length..].iter().all(|byte| *byte == 0));
    }
    assert!(
        build_guest_input_payload(Some(&[0x91; 65]))
            .unwrap_err()
            .to_string()
            .contains("exceeds 64 byte guest input size")
    );
    let payload = build_guest_input_payload(None).unwrap();
    assert_eq!(&payload[..16], b"tpm_guest_tests ");
    assert!(u64::from_str_radix(std::str::from_utf8(&payload[16..32]).unwrap(), 16).is_ok());
    assert_eq!(&payload[32..], &[0; 32]);
}
