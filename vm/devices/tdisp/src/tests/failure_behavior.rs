// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::TdispHostDeviceInterface;
use crate::devicereport::deserialize_tdi_report;
use crate::test_helpers::NullTdispHostInterface;
use crate::test_helpers::TDISP_MOCK_DEVICE_ID;
use crate::test_helpers::new_null_tdisp_interface;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Operation {
    Negotiate,
    Bind,
    Start,
    Unbind,
    Report,
    Mmio,
}

struct Host {
    inner: NullTdispHostInterface,
    fail: Option<Operation>,
    protocol: Option<i32>,
    calls: Vec<Operation>,
}

impl Host {
    fn check(&mut self, operation: Operation) -> anyhow::Result<()> {
        self.calls.push(operation);
        anyhow::ensure!(
            self.fail != Some(operation),
            "injected {operation:?} failure"
        );
        Ok(())
    }
}

impl TdispHostDeviceInterface for Host {
    fn tdisp_negotiate_protocol(
        &mut self,
        protocol: TdispGuestProtocolType,
    ) -> anyhow::Result<crate::TdispDeviceInterfaceInfo> {
        self.check(Operation::Negotiate)?;
        let mut info = self.inner.tdisp_negotiate_protocol(protocol)?;
        if let Some(value) = self.protocol {
            info.guest_protocol_type = value;
        }
        Ok(info)
    }
    fn tdisp_bind_device(&mut self) -> anyhow::Result<()> {
        self.check(Operation::Bind)?;
        self.inner.tdisp_bind_device()
    }
    fn tdisp_start_device(&mut self) -> anyhow::Result<()> {
        self.check(Operation::Start)?;
        self.inner.tdisp_start_device()
    }
    fn tdisp_unbind_device(&mut self) -> anyhow::Result<()> {
        self.check(Operation::Unbind)?;
        self.inner.tdisp_unbind_device()
    }
    fn tdisp_get_device_report(&mut self, report: TdispReportType) -> anyhow::Result<Vec<u8>> {
        self.check(Operation::Report)?;
        self.inner.tdisp_get_device_report(report)
    }
    fn tdisp_modify_mmio_range(
        &mut self,
        action: TdispMmioRangeAction,
        range_id: u16,
        gpa_base: u64,
        length: u64,
    ) -> anyhow::Result<()> {
        self.check(Operation::Mmio)?;
        self.inner
            .tdisp_modify_mmio_range(action, range_id, gpa_base, length)
    }
}

fn fixture() -> (TdispHostDeviceTargetEmulator, Arc<Mutex<Host>>) {
    let host = Arc::new(Mutex::new(Host {
        inner: NullTdispHostInterface {},
        fail: None,
        protocol: None,
        calls: Vec::new(),
    }));
    (
        TdispHostDeviceTargetEmulator::new(host.clone(), "fault-test"),
        host,
    )
}

fn check(
    response: &tdisp_proto::GuestToHostResponse,
    result: TdispGuestOperationErrorCode,
    before: TdispTdiState,
    after: TdispTdiState,
) {
    assert_eq!(response.result, result as i32);
    assert_eq!(response.tdi_state_before, before as i32);
    assert_eq!(response.tdi_state_after, after as i32);
}

// Test: Run repeated complete guest lifecycles against the public null provider.
// Expected: Wire-visible states remain correct after history rollover, device
//       identity stays stable and the interface report describes no MMIO ranges.
#[test]
fn null_provider_supports_repeated_guest_lifecycles_and_reports() {
    let mut emulator = new_null_tdisp_interface("initial-name");
    emulator.set_debug_device_id("assigned-name");
    emulator.reset();
    check(
        &dispatch_roundtrip(&mut emulator, negotiate_cmd(99)),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Unlocked,
        TdispTdiState::Unlocked,
    );
    for _ in 0..16 {
        let identity = dispatch_roundtrip(
            &mut emulator,
            get_tdi_report_cmd(99, TdispReportType::GuestDeviceId),
        );
        let Some(Response::GetTdiReport(identity)) = identity.response else {
            panic!("missing device identity")
        };
        assert_eq!(identity.report_buffer, TDISP_MOCK_DEVICE_ID.to_le_bytes());
        check(
            &dispatch_roundtrip(&mut emulator, bind_cmd(99)),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Unlocked,
            TdispTdiState::Locked,
        );
        let report = dispatch_roundtrip(
            &mut emulator,
            get_tdi_report_cmd(99, TdispReportType::InterfaceReport),
        );
        let Some(Response::GetTdiReport(report)) = report.response else {
            panic!("missing report")
        };
        let parsed = deserialize_tdi_report(&report.report_buffer).unwrap();
        assert!(parsed.mmio_interface_info.is_empty());
        assert!(parsed.device_specific_info.is_empty());
        check(
            &dispatch_roundtrip(
                &mut emulator,
                modify_mmio_range_cmd(99, TdispMmioRangeAction::BlockMmioRange, 2, 0x8000, 0x1000),
            ),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Locked,
            TdispTdiState::Locked,
        );
        check(
            &dispatch_roundtrip(&mut emulator, start_tdi_cmd(99)),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Locked,
            TdispTdiState::Run,
        );
        check(
            &dispatch_roundtrip(
                &mut emulator,
                unbind_cmd(99, TdispGuestUnbindReason::Graceful),
            ),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Run,
            TdispTdiState::Unlocked,
        );
    }
}

// Test: Fail individual backend operations and retry through serialized commands.
// Expected: Guests receive HostFailedToProcessCommand with the correct visible
//       state and can retry successfully after the backend recovers.
#[test]
fn backend_failures_remain_visible_and_allow_guest_retry() {
    for operation in [
        Operation::Negotiate,
        Operation::Bind,
        Operation::Start,
        Operation::Unbind,
        Operation::Report,
        Operation::Mmio,
    ] {
        let (mut emulator, host) = fixture();
        if operation != Operation::Negotiate {
            dispatch_roundtrip(&mut emulator, negotiate_cmd(1));
        }
        if !matches!(operation, Operation::Negotiate | Operation::Bind) {
            dispatch_roundtrip(&mut emulator, bind_cmd(1));
        }
        host.lock().fail = Some(operation);
        let command = match operation {
            Operation::Negotiate => negotiate_cmd(1),
            Operation::Bind => bind_cmd(1),
            Operation::Start => start_tdi_cmd(1),
            Operation::Unbind => unbind_cmd(1, TdispGuestUnbindReason::Graceful),
            Operation::Report => get_tdi_report_cmd(1, TdispReportType::InterfaceReport),
            Operation::Mmio => {
                modify_mmio_range_cmd(1, TdispMmioRangeAction::BlockMmioRange, 2, 0x8000, 0x1000)
            }
        };
        let before = if matches!(operation, Operation::Negotiate | Operation::Bind) {
            TdispTdiState::Unlocked
        } else {
            TdispTdiState::Locked
        };
        let after = if operation == Operation::Unbind {
            TdispTdiState::Unlocked
        } else {
            before
        };
        let response = dispatch_roundtrip(&mut emulator, command.clone());
        check(
            &response,
            TdispGuestOperationErrorCode::HostFailedToProcessCommand,
            before,
            after,
        );
        assert_eq!(host.lock().calls.last(), Some(&operation));
        host.lock().fail = None;
        let retry = dispatch_roundtrip(&mut emulator, command);
        assert_eq!(retry.result, TdispGuestOperationErrorCode::Success as i32);
        assert_eq!(retry.tdi_state_before, after as i32);
    }
}

// Test: Request state-changing operations before negotiating a guest protocol.
// Expected: Each command returns InvalidDeviceState and no backend operation
//       executes before a successful negotiation.
#[test]
fn unnegotiated_commands_never_reach_the_backend() {
    for command in [
        bind_cmd(1),
        start_tdi_cmd(1),
        unbind_cmd(1, TdispGuestUnbindReason::Graceful),
        get_tdi_report_cmd(1, TdispReportType::InterfaceReport),
        modify_mmio_range_cmd(1, TdispMmioRangeAction::BlockMmioRange, 0, 0x8000, 0x1000),
    ] {
        let (mut emulator, host) = fixture();
        let response = dispatch_roundtrip(&mut emulator, command);
        check(
            &response,
            TdispGuestOperationErrorCode::InvalidDeviceState,
            TdispTdiState::Unlocked,
            TdispTdiState::Unlocked,
        );
        assert!(host.lock().calls.is_empty());
    }
}

// Test: Negotiate against a backend returning an invalid or unknown protocol ID.
// Expected: The reply is rejected explicitly, then a corrected backend reply
//       allows negotiation without reconstructing the device.
#[test]
fn invalid_backend_protocols_do_not_poison_negotiation_retry() {
    for protocol in [TdispGuestProtocolType::Invalid as i32, i32::MAX] {
        let (mut emulator, host) = fixture();
        host.lock().protocol = Some(protocol);
        let response = dispatch_roundtrip(&mut emulator, negotiate_cmd(1));
        check(
            &response,
            TdispGuestOperationErrorCode::InvalidGuestProtocolRequest,
            TdispTdiState::Unlocked,
            TdispTdiState::Unlocked,
        );
        host.lock().protocol = None;
        assert_eq!(
            dispatch_roundtrip(&mut emulator, negotiate_cmd(1)).result,
            TdispGuestOperationErrorCode::Success as i32
        );
    }
}

// Test: Send unknown integer discriminants for protocol, report and unbind enums.
// Expected: Wire decoding rejects each value. Direct command dispatch returns
//       the corresponding input error without changing the Locked TDI state.
#[test]
fn unknown_guest_enum_values_are_rejected_at_the_wire_boundary() {
    let (mut emulator, host) = fixture();
    dispatch_roundtrip(&mut emulator, negotiate_cmd(1));
    dispatch_roundtrip(&mut emulator, bind_cmd(1));
    let calls = host.lock().calls.clone();
    for (command, error) in [
        (
            Command::GetDeviceInterfaceInfo(TdispCommandRequestGetDeviceInterfaceInfo {
                guest_protocol_type: i32::MAX,
            }),
            TdispGuestOperationErrorCode::InvalidGuestProtocolRequest,
        ),
        (
            Command::GetTdiReport(TdispCommandRequestGetTdiReport {
                report_type: i32::MAX,
            }),
            TdispGuestOperationErrorCode::InvalidGuestAttestationReportType,
        ),
        (
            Command::Unbind(TdispCommandRequestUnbind {
                unbind_reason: i32::MAX,
            }),
            TdispGuestOperationErrorCode::InvalidGuestUnbindReason,
        ),
    ] {
        let command = GuestToHostCommand {
            device_id: 1,
            command: Some(command),
        };
        assert!(deserialize_command(&serialize_command(&command)).is_err());
        let response = emulator.tdisp_handle_guest_command(command).unwrap();
        check(
            &response,
            error,
            TdispTdiState::Locked,
            TdispTdiState::Locked,
        );
        assert!(response.response.is_none());
    }
    assert_eq!(host.lock().calls, calls);
}

// Test: Read a null-provider report type it does not implement and parse a
//       truncated vendor-data length in an otherwise valid interface report.
// Expected: Both operations return explicit errors rather than incomplete data.
#[test]
fn unsupported_reports_and_truncated_vendor_lengths_return_errors() {
    assert!(
        NullTdispHostInterface {}
            .tdisp_get_device_report(TdispReportType::Invalid)
            .is_err()
    );
    for extra in 1..4 {
        let mut bytes = vec![0; crate::devicereport::TDI_REPORT_HEADER_SIZE + extra];
        *bytes.last_mut().unwrap() = 1;
        let error = deserialize_tdi_report(&bytes).unwrap_err();
        assert!(error.to_string().contains("DEVICE_SPECIFIC_INFO_LEN"));
    }
}

// Test: Interleave two devices while one encounters start and state errors.
// Expected: Failure and teardown affect only that device; the other keeps
//       running and reporting while the failed device binds and starts again.
#[test]
fn device_failures_do_not_interrupt_another_devices_lifecycle() {
    let (mut first, first_host) = fixture();
    let (mut second, _) = fixture();
    for (device, id) in [(&mut first, 11), (&mut second, 22)] {
        check(
            &dispatch_roundtrip(device, negotiate_cmd(id)),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Unlocked,
            TdispTdiState::Unlocked,
        );
        check(
            &dispatch_roundtrip(device, bind_cmd(id)),
            TdispGuestOperationErrorCode::Success,
            TdispTdiState::Unlocked,
            TdispTdiState::Locked,
        );
    }

    first_host.lock().fail = Some(Operation::Start);
    check(
        &dispatch_roundtrip(&mut first, start_tdi_cmd(11)),
        TdispGuestOperationErrorCode::HostFailedToProcessCommand,
        TdispTdiState::Locked,
        TdispTdiState::Locked,
    );
    check(
        &dispatch_roundtrip(&mut second, start_tdi_cmd(22)),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Locked,
        TdispTdiState::Run,
    );
    check(
        &dispatch_roundtrip(&mut first, bind_cmd(11)),
        TdispGuestOperationErrorCode::InvalidDeviceState,
        TdispTdiState::Locked,
        TdispTdiState::Unlocked,
    );
    let response = dispatch_roundtrip(
        &mut second,
        get_tdi_report_cmd(22, TdispReportType::InterfaceReport),
    );
    check(
        &response,
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Run,
        TdispTdiState::Run,
    );
    let Some(Response::GetTdiReport(report)) = response.response else {
        panic!("missing running device report")
    };
    assert!(deserialize_tdi_report(&report.report_buffer).is_ok());

    first_host.lock().fail = None;
    check(
        &dispatch_roundtrip(&mut first, bind_cmd(11)),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Unlocked,
        TdispTdiState::Locked,
    );
    check(
        &dispatch_roundtrip(&mut first, start_tdi_cmd(11)),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Locked,
        TdispTdiState::Run,
    );
    check(
        &dispatch_roundtrip(
            &mut second,
            unbind_cmd(22, TdispGuestUnbindReason::Graceful),
        ),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Run,
        TdispTdiState::Unlocked,
    );
    check(
        &dispatch_roundtrip(
            &mut first,
            get_tdi_report_cmd(11, TdispReportType::InterfaceReport),
        ),
        TdispGuestOperationErrorCode::Success,
        TdispTdiState::Run,
        TdispTdiState::Run,
    );
}
