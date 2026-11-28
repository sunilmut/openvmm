// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::TdispGuestOperationError;
use crate::TdispGuestRequestInterface;
use crate::tests::mocks::LastCall;
use crate::tests::mocks::new_machine;
use tdisp_proto::TdispGuestUnbindReason;
use tdisp_proto::TdispReportType;
use test_with_tracing::test;

// These witnesses consume the state through public guest operations, rather
// than reading the machine's private state. Call them after checking callbacks.
fn assert_unlocked(machine: &mut impl TdispGuestRequestInterface) {
    machine.request_lock_device_resources().unwrap();
    machine.request_start_tdi().unwrap();
}

fn assert_locked(machine: &mut impl TdispGuestRequestInterface) {
    machine.request_start_tdi().unwrap();
}

fn assert_running(machine: &mut impl TdispGuestRequestInterface) {
    assert_eq!(
        machine
            .request_attestation_report(TdispReportType::InterfaceReport)
            .unwrap(),
        [0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert!(matches!(
        machine.request_start_tdi(),
        Err(TdispGuestOperationError::InvalidDeviceState)
    ));
}

// ── Valid forward-progress transitions ───────────────────────────────────────

// Test: Bind a negotiated, unlocked device through the guest interface.
// Expected: The host binds it and a subsequent start is permitted.
#[test]
fn test_bind_transitions_unlocked_to_locked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::BindDevice));
    assert_locked(&mut mock.machine);
}

// Test: Start a bound device through the guest interface.
// Expected: The host starts it; reports succeed but a repeated start is rejected.
#[test]
fn test_start_tdi_transitions_locked_to_run() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine.request_start_tdi().unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::StartDevice));
    assert_running(&mut mock.machine);
}

// Test: Bind, start and gracefully unbind a negotiated device.
// Expected: Each host action succeeds in order and a fresh bind/start is allowed.
#[test]
fn test_full_lifecycle() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::BindDevice));

    mock.machine.request_start_tdi().unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::StartDevice));

    mock.machine
        .request_unbind(TdispGuestUnbindReason::Graceful)
        .unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// ── Unbind from each state ────────────────────────────────────────────────────

// Test: Unbind a device whose resources are locked.
// Expected: The host unbinds it and the guest can bind and start again.
#[test]
fn test_unbind_from_locked_resets_to_unlocked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine
        .request_unbind(TdispGuestUnbindReason::Graceful)
        .unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Unbind a running device.
// Expected: The host unbinds it and the guest can bind and start again.
#[test]
fn test_unbind_from_run_resets_to_unlocked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine.request_start_tdi().unwrap();
    mock.machine
        .request_unbind(TdispGuestUnbindReason::Graceful)
        .unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Unbind a device that is already unlocked.
// Expected: Unbind still reaches the host and does not prevent a new lifecycle.
#[test]
fn test_unbind_from_unlocked_stays_unlocked() {
    let mut mock = new_machine();
    // Unlocked -> Unlocked is an explicitly permitted transition.
    mock.machine
        .request_unbind(TdispGuestUnbindReason::Graceful)
        .unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Bind a device again after a successful unbind.
// Expected: The second host bind succeeds and the guest can start the device.
#[test]
fn test_rebind_after_unbind() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine
        .request_unbind(TdispGuestUnbindReason::Graceful)
        .unwrap();
    // The device is back in Unlocked and can go through the flow again.
    mock.machine.request_lock_device_resources().unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::BindDevice));
    assert_locked(&mut mock.machine);
}

// Test: Unbind through the guest interface with the known Unknown reason.
// Expected: The reason is tolerated; unbind succeeds and permits a new lifecycle.
#[test]
fn test_unbind_with_unknown_reason_still_succeeds() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    // Unknown is not a valid guest-initiated reason, but the unbind still
    // completes (the reason is recorded as invalid in the history).
    mock.machine
        .request_unbind(TdispGuestUnbindReason::Unknown)
        .unwrap();
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// ── Invalid transitions (error + automatic reset to Unlocked) ────────────────

// Test: Request a second bind while the device is locked.
// Expected: InvalidDeviceState triggers host unbind and permits a fresh lifecycle.
#[test]
fn test_bind_from_locked_fails_and_resets_to_unlocked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();

    let err = mock.machine.request_lock_device_resources().unwrap_err();
    assert!(matches!(err, TdispGuestOperationError::InvalidDeviceState));
    // The failed bind triggers an internal unbind_all to reset the device.
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Request a bind while the device is running.
// Expected: InvalidDeviceState triggers host unbind and permits a fresh lifecycle.
#[test]
fn test_bind_from_run_fails_and_resets_to_unlocked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine.request_start_tdi().unwrap();

    let err = mock.machine.request_lock_device_resources().unwrap_err();
    assert!(matches!(err, TdispGuestOperationError::InvalidDeviceState));
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Request a start before binding a negotiated device.
// Expected: InvalidDeviceState triggers host unbind and leaves binding usable.
#[test]
fn test_start_tdi_from_unlocked_fails_and_resets_to_unlocked() {
    let mut mock = new_machine();

    let err = mock.machine.request_start_tdi().unwrap_err();
    assert!(matches!(err, TdispGuestOperationError::InvalidDeviceState));
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Request a second start while the device is running.
// Expected: InvalidDeviceState triggers host unbind and permits a fresh lifecycle.
#[test]
fn test_start_tdi_from_run_fails_and_resets_to_unlocked() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine.request_start_tdi().unwrap();

    let err = mock.machine.request_start_tdi().unwrap_err();
    assert!(matches!(err, TdispGuestOperationError::InvalidDeviceState));
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// ── Attestation report ────────────────────────────────────────────────────────

// Test: Request an interface report from a locked device.
// Expected: The exact host payload is returned and the guest can still start.
#[test]
fn test_attestation_report_from_locked_succeeds() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();

    let report = mock
        .machine
        .request_attestation_report(TdispReportType::InterfaceReport)
        .unwrap();
    assert_eq!(report, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        *mock.last_call.lock(),
        Some(LastCall::GetDeviceReport(TdispReportType::InterfaceReport))
    );
    assert_locked(&mut mock.machine);
}

// Test: Request an interface report from a running device.
// Expected: The exact host payload is returned without permitting another start.
#[test]
fn test_attestation_report_from_run_succeeds() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();
    mock.machine.request_start_tdi().unwrap();

    let report = mock
        .machine
        .request_attestation_report(TdispReportType::InterfaceReport)
        .unwrap();
    assert_eq!(report, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        *mock.last_call.lock(),
        Some(LastCall::GetDeviceReport(TdispReportType::InterfaceReport))
    );
    assert_running(&mut mock.machine);
}

// Test: Request an interface report from an unlocked device.
// Expected: The state error triggers host unbind and allows a fresh lifecycle.
#[test]
fn test_attestation_report_from_unlocked_fails_and_resets_to_unlocked() {
    let mut mock = new_machine();

    let err = mock
        .machine
        .request_attestation_report(TdispReportType::InterfaceReport)
        .unwrap_err();
    assert!(matches!(
        err,
        TdispGuestOperationError::InvalidGuestAttestationReportState
    ));
    // The state-check failure triggers unbind_all before returning the error.
    assert_eq!(*mock.last_call.lock(), Some(LastCall::UnbindDevice));
    assert_unlocked(&mut mock.machine);
}

// Test: Request the guest device ID before binding a negotiated device.
// Expected: The complete little-endian identity is returned without unbinding.
#[test]
fn test_guest_device_id_report_from_unlocked_succeeds() {
    let mut mock = new_machine();

    // GuestDeviceId identifies the device rather than describing attestation
    // state, so it is exempt from the Locked/Run requirement that every other
    // report type is subject to.
    let report = mock
        .machine
        .request_attestation_report(TdispReportType::GuestDeviceId)
        .unwrap();
    assert_eq!(report, [99, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        *mock.last_call.lock(),
        Some(LastCall::GetDeviceReport(TdispReportType::GuestDeviceId))
    );
    assert_unlocked(&mut mock.machine);
}

// Test: Request the Invalid report type from a locked device.
// Expected: The type error does not call the host or prevent starting the device.
#[test]
fn test_attestation_report_invalid_type_from_locked_returns_error_without_state_change() {
    let mut mock = new_machine();
    mock.machine.request_lock_device_resources().unwrap();

    // TdispReportType::Invalid is rejected before the host interface is
    // consulted, so the last call must still be the BindDevice from setup.
    let err = mock
        .machine
        .request_attestation_report(TdispReportType::Invalid)
        .unwrap_err();
    assert!(matches!(
        err,
        TdispGuestOperationError::InvalidGuestAttestationReportType
    ));
    assert_eq!(*mock.last_call.lock(), Some(LastCall::BindDevice));
    assert_locked(&mut mock.machine);
}
