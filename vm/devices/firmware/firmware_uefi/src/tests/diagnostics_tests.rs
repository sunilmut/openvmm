// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::behavior_tests::submit;
use super::*;
use crate::service::diagnostics::DiagnosticsEmitter;
use pal_async::async_test;
use std::mem::offset_of;
use uefi_specs::hyperv::advanced_logger::{
    AdvancedLoggerInfo, AdvancedLoggerMessageEntryV2, DXE_PHASE, SIG_ENTRY, SIG_HEADER,
};
use uefi_specs::hyperv::debug_level::DEBUG_ERROR;

// Test: Deliver a watchdog timeout notification after programming a valid diagnostics buffer.
// Expected: Polling automatically processes the batch so normal reads cannot duplicate it, while explicit reprocessing still returns the exact message.
#[async_test]
async fn watchdog_notification_flushes_diagnostics_without_losing_operator_access(
    driver: DefaultDriver,
) {
    let TestDevice { mut dev, gm, .. } = test_device(&driver, false).await;
    let gpa = write_diagnostics(&gm);
    submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, gpa);
    let (timeout_send, timeout_recv) = mesh::channel();
    dev.watchdog_recv = timeout_recv;
    timeout_send.send(());
    dev.poll_device(&mut Context::from_waker(Waker::noop()));
    assert_eq!(diagnostics(&mut dev, false), "");
    assert_eq!(
        diagnostics(&mut dev, true),
        "(123 ticks) [ERROR] [DXE]: firmware-diagnostic-probe\n"
    );
}

fn write_diagnostics(gm: &GuestMemory) -> u32 {
    let gpa = 0x4000;
    let offset = 0x100_u32;
    let entry = u64::from(gpa + offset);
    let message = b"firmware-diagnostic-probe\n";
    let header_size = size_of::<AdvancedLoggerMessageEntryV2>() as u16;
    let used = (usize::from(header_size) + message.len()).next_multiple_of(8) as u32;
    gm.write_plain(
        u64::from(gpa) + offset_of!(AdvancedLoggerInfo, signature) as u64,
        &u32::from_le_bytes(SIG_HEADER),
    )
    .unwrap();
    gm.write_plain(
        u64::from(gpa) + offset_of!(AdvancedLoggerInfo, log_buffer_offset) as u64,
        &offset,
    )
    .unwrap();
    gm.write_plain(
        u64::from(gpa) + offset_of!(AdvancedLoggerInfo, log_current_offset) as u64,
        &(offset + used),
    )
    .unwrap();
    gm.write_plain(
        u64::from(gpa) + offset_of!(AdvancedLoggerInfo, log_buffer_size) as u64,
        &used,
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, signature) as u64,
        &u32::from_le_bytes(SIG_ENTRY),
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, major_version) as u64,
        &2_u8,
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, debug_level) as u64,
        &DEBUG_ERROR,
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, time_stamp) as u64,
        &123_u64,
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, phase) as u64,
        &DXE_PHASE,
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, message_len) as u64,
        &(message.len() as u16),
    )
    .unwrap();
    gm.write_plain(
        entry + offset_of!(AdvancedLoggerMessageEntryV2, message_offset) as u64,
        &header_size,
    )
    .unwrap();
    gm.write_at(entry + u64::from(header_size), message)
        .unwrap();
    gpa
}

fn diagnostics(dev: &mut UefiDevice, allow_reprocess: bool) -> String {
    dev.process_diagnostics(allow_reprocess, DiagnosticsEmitter::String, None)
        .unwrap()
        .unwrap()
}

// Test: Request diagnostics processing through the management action with valid levels/destinations and invalid arguments.
// Expected: Functional service reads show valid requests consumed the batch and invalid arguments did not; the management response is never used to verify output or state.
#[async_test]
async fn management_diagnostics_requests_process_only_valid_arguments(driver: DefaultDriver) {
    for (request, consumed) in [
        ("default", true),
        ("default,stdout", true),
        ("info,stdout", true),
        ("full,stdout", true),
        ("default,tracing", true),
        ("info,tracing", true),
        ("full,tracing", true),
        ("bogus,stdout", false),
        ("info,bogus", false),
    ] {
        let TestDevice { mut dev, gm, .. } = test_device(&driver, false).await;
        let gpa = write_diagnostics(&gm);
        submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, gpa);
        let _ = inspect::update("process_diagnostics", request, &mut dev).await;
        assert_eq!(
            diagnostics(&mut dev, false),
            if consumed {
                ""
            } else {
                "(123 ticks) [ERROR] [DXE]: firmware-diagnostic-probe\n"
            },
            "request {request}"
        );
    }
}

// Test: Request management diagnostics processing with a guest buffer whose header lies outside RAM, then attempt normal automatic processing.
// Expected: The action does not panic and the failed batch is marked processed so automatic processing does not repeatedly read the invalid guest address; no management response is inspected.
#[async_test]
async fn management_diagnostics_failure_suppresses_repeated_bad_guest_reads(driver: DefaultDriver) {
    for destination in ["stdout", "tracing"] {
        let TestDevice { mut dev, .. } = test_device(&driver, false).await;
        submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, 0xfffff000);
        let _ = inspect::update(
            "process_diagnostics",
            &format!("full,{destination}"),
            &mut dev,
        )
        .await;
        assert_eq!(diagnostics(&mut dev, false), "");
        assert!(
            dev.process_diagnostics(true, DiagnosticsEmitter::String, None)
                .is_err()
        );
    }
}

// Test: Submit a valid guest diagnostics buffer with default, disabled, and overridden rate limits, then reset and submit again.
// Expected: The service returns the exact decoded message before submission, guest submission suppresses subsequent duplicate processing, and reset permits the message to be processed again.
#[async_test]
async fn guest_diagnostics_submission_suppresses_duplicates_and_reset_rearms(
    driver: DefaultDriver,
) {
    for limit in [None, Some(0), Some(7)] {
        let TestDevice { mut dev, gm, .. } = test_device(&driver, false).await;
        dev.diagnostics_rate_limit = limit;
        let gpa = write_diagnostics(&gm);
        submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, gpa);
        let expected = "(123 ticks) [ERROR] [DXE]: firmware-diagnostic-probe\n";
        assert_eq!(diagnostics(&mut dev, true), expected);
        dev.reset().await;
        submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, gpa);
        submit(&mut dev, UefiCommand::PROCESS_EFI_DIAGNOSTICS, 0);
        assert_eq!(diagnostics(&mut dev, false), "");
        dev.reset().await;
        submit(&mut dev, UefiCommand::SET_EFI_DIAGNOSTICS_GPA, gpa);
        assert_eq!(diagnostics(&mut dev, false), expected);
    }
}
