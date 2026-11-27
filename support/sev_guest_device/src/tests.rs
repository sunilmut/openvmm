// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use nix::errno::Errno;
use test_with_tracing::test;

fn unsupported_device() -> SevGuestDevice {
    SevGuestDevice {
        file: std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("standard Linux null device"),
    }
}

// Test: Request an SNP report using a file that does not implement SNP ioctls.
// Expected: The public API returns the report-specific ioctl error and ENOTTY,
//       never a success-shaped zero report.
#[test]
fn report_failure_preserves_operation_and_errno() {
    match unsupported_device().get_report([0x43; 64], 0) {
        Err(Error::SnpGetReportIoctl(errno)) => assert_eq!(errno, Errno::ENOTTY),
        Err(error) => panic!("incorrect report error: {error:?}"),
        Ok(_) => panic!("unsupported descriptor returned a report"),
    }
}

// IGNORED: entry304-bug1 was reproduced enabled: get_derived_key maps the
//       ENOTTY failure to SnpGetReportIoctl instead of SnpGetDerivedKeyIoctl.
//       Retain until the production error classification is corrected.
//
// Test: Request an SNP derived key using an unsupported file descriptor.
// Expected: Failure is classified as a derived-key ioctl error with ENOTTY,
//       rather than being misreported as an attestation-report failure.
#[test]
#[ignore = "entry304-bug1: derived-key ioctl failure is mislabeled as report failure"]
fn derived_key_failure_preserves_operation_and_errno() {
    match unsupported_device().get_derived_key(0, 0, 0, 0, 0) {
        Err(Error::SnpGetDerivedKeyIoctl(errno)) => assert_eq!(errno, Errno::ENOTTY),
        Err(error) => panic!("incorrect derived-key error: {error:?}"),
        Ok(_) => panic!("unsupported descriptor returned a key"),
    }
}

// Test: Issue each public TIO request through an unsupported descriptor.
// Expected: Every request propagates its ioctl failure and ENOTTY, without
//       treating a zero-initialized response buffer as firmware success.
#[test]
fn tio_requests_propagate_transport_failure() {
    let device = unsupported_device();
    let write = false;
    let validated = true;
    let force_validated = false;
    let enable_dma = false;
    let requests = [
        ("TDI info", device.tio_msg_tdi_info_req(7).map(|_| ())),
        (
            "MMIO config",
            device
                .tio_msg_mmio_config_req(7, 1, write, TioMsgMmioConfigReqFlags::new())
                .map(|_| ()),
        ),
        (
            "MMIO validate",
            device
                .tio_msg_mmio_validate_req(7, 0x200000, 1, 0, 1, validated, force_validated)
                .map(|_| ()),
        ),
        (
            "SDTE write",
            device
                .tio_msg_sdte_write_req(7, enable_dma, 0, 0)
                .map(|_| ()),
        ),
    ];
    for (operation, result) in requests {
        match result {
            Err(Error::TioGuestRequestIoctl(errno)) => {
                assert_eq!(errno, Errno::ENOTTY, "{operation}")
            }
            Err(error) => panic!("incorrect {operation} error: {error:?}"),
            Ok(()) => panic!("unsupported descriptor succeeded for {operation}"),
        }
    }
}

// Test: Combine non-TEE memory and WRITE flags, then try each compatible alternative.
// Expected: The forbidden combination is rejected before ioctl; non-TEE reads
//       and TEE writes proceed far enough to return the transport error.
#[test]
fn mmio_config_rejects_only_incompatible_non_tee_write() {
    let device = unsupported_device();
    let non_tee = TioMsgMmioConfigReqFlags::new().with_non_tee_mem(true);
    let write = true;
    match device.tio_msg_mmio_config_req(7, 1, write, non_tee) {
        Err(Error::InvalidTioRequestParameters(message)) => {
            assert!(message.contains("non_tee_mem"), "{message}");
            assert!(message.contains("WRITE"), "{message}");
        }
        Err(error) => panic!("incorrect parameter error: {error:?}"),
        Ok(_) => panic!("incompatible flags were accepted"),
    }
    let read = false;
    assert!(matches!(
        device.tio_msg_mmio_config_req(7, 1, read, non_tee),
        Err(Error::TioGuestRequestIoctl(Errno::ENOTTY))
    ));
    assert!(matches!(
        device.tio_msg_mmio_config_req(7, 1, write, TioMsgMmioConfigReqFlags::new()),
        Err(Error::TioGuestRequestIoctl(Errno::ENOTTY))
    ));
}

// IGNORED: Requires a real SNP guest and /dev/sev-guest with an ioctl ABI
//       matching the selected standard or experimental TIO feature.
//
// Test: Request a real attestation report with distinct caller-provided data.
// Expected: The firmware report preserves that data and the requested VMPL.
#[test]
#[ignore = "requires SNP guest and matching sev-guest ioctl ABI"]
fn snp_report_preserves_requested_data_and_vmpl() {
    let device = SevGuestDevice::open().expect("SNP guest device available");
    let user_data = [0x43; 64];
    let report = device
        .get_report(user_data, 0)
        .expect("SNP report request succeeds");
    assert!(
        report.report_data == user_data,
        "report preserves requested data"
    );
    assert_eq!(report.vmpl, 0);
}
