// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::RelayTdisp;
use super::SCRATCH_OFFSET;
use super::TestHost;
use super::TestRelay;
use super::command;
use super::connect_relay;
use super::connect_relay_with;
use crate::AllowedDevice;
use crate::CreateMemoryAccess;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::PciConfigByteEnable;
use chipset_device::pci::PciConfigSpace;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pci_core::spec::cfg_space::HeaderType00;
use pci_core::spec::hwid::HardwareIds;
use tdisp::TdispIsolationReport;
use tdisp::TdispTdiState;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vpci_client::MemoryAccess;

// Test: Apply every combination of optional hardware-ID constraints.
// Expected: Matching IDs pass; changing any constrained field rejects the device.
#[test]
fn each_hardware_id_constraint_is_independent() {
    let hw = HardwareIds {
        vendor_id: 0x1414,
        device_id: 0x1234,
        revision_id: 7,
        prog_if: 2.into(),
        sub_class: 3.into(),
        base_class: 4.into(),
        type0_sub_vendor_id: 0x5678,
        type0_sub_system_id: 0x9abc,
    };
    let changed = [
        HardwareIds {
            vendor_id: hw.vendor_id ^ 1,
            ..hw
        },
        HardwareIds {
            device_id: hw.device_id ^ 1,
            ..hw
        },
        HardwareIds {
            revision_id: hw.revision_id ^ 1,
            ..hw
        },
        HardwareIds {
            prog_if: 5.into(),
            ..hw
        },
        HardwareIds {
            sub_class: 5.into(),
            ..hw
        },
        HardwareIds {
            base_class: 5.into(),
            ..hw
        },
        HardwareIds {
            type0_sub_vendor_id: hw.type0_sub_vendor_id ^ 1,
            ..hw
        },
        HardwareIds {
            type0_sub_system_id: hw.type0_sub_system_id ^ 1,
            ..hw
        },
    ];
    for mask in 0u16..256 {
        let filter = AllowedDevice {
            vendor_id: (mask & 1 != 0).then_some(hw.vendor_id),
            device_id: (mask & 2 != 0).then_some(hw.device_id),
            revision_id: (mask & 4 != 0).then_some(hw.revision_id),
            prog_if: (mask & 8 != 0).then_some(hw.prog_if),
            sub_class: (mask & 16 != 0).then_some(hw.sub_class),
            base_class: (mask & 32 != 0).then_some(hw.base_class),
            sub_vendor_id: (mask & 64 != 0).then_some(hw.type0_sub_vendor_id),
            sub_system_id: (mask & 128 != 0).then_some(hw.type0_sub_system_id),
        };
        assert!(filter.allows(&hw), "matching IDs with mask {mask:#x}");
        for (field, changed) in changed.iter().enumerate() {
            assert_eq!(
                filter.allows(changed),
                mask & (1 << field) == 0,
                "mask {mask:#x}, changed field {field}"
            );
        }
    }
}

// Test: Request isolation information from a probed TDISP-capable device twice.
// Expected: Each request yields a ready report and releases the TDI for programming.
#[async_test]
async fn isolation_reports_attest_then_release_the_device(driver: DefaultDriver) {
    let relay = connect_relay_with(
        &driver,
        TestHost {
            offers_tdisp: true,
            accepts_rb: true,
        },
        RelayTdisp::Probe,
    )
    .await;
    for _ in 0..2 {
        let report = relay
            .relay
            .lock()
            .supports_tdisp_relay()
            .unwrap()
            .tdisp_isolation_report();
        assert!(
            matches!(report.await, TdispIsolationReport::Ready { .. }),
            "a capable device must provide an attested isolation report"
        );
        assert_eq!(
            relay.device.tdisp().tdi_state().await,
            TdispTdiState::Unlocked
        );
    }
    // The guest can still activate the device after querying its resources.
    let activate = relay.deferred_write(
        HeaderType00::STATUS_COMMAND.0,
        command(true),
        PciConfigByteEnable::LOW_WORD,
    );
    relay.drive(activate.write_future()).await.unwrap();
    assert_eq!(relay.device.tdisp().tdi_state().await, TdispTdiState::Run);
}

// Test: Request isolation information for a device without TDISP support.
// Expected: The caller gets NotTdispCapable without changing host configuration.
#[async_test]
async fn non_tdisp_isolation_report_does_not_touch_the_host(driver: DefaultDriver) {
    let relay = connect_relay(&driver, false).await;
    let report = relay
        .relay
        .lock()
        .supports_tdisp_relay()
        .unwrap()
        .tdisp_isolation_report();
    assert!(matches!(
        report.await,
        TdispIsolationReport::NotTdispCapable
    ));
    assert!(relay.written_offsets().is_empty());
    assert_eq!(
        relay.device.tdisp().tdi_state().await,
        TdispTdiState::Unlocked
    );
}

// Test: Stop with activation, deactivation and an ordinary write still pending.
// Expected: Stop completes all callers in order without a device-polling loop.
#[async_test]
async fn stop_finishes_pending_operations_and_queued_writes(driver: DefaultDriver) {
    let relay = connect_relay(&driver, true).await;
    let activate = relay.deferred_write(
        HeaderType00::STATUS_COMMAND.0,
        command(true),
        PciConfigByteEnable::LOW_WORD,
    );
    let deactivate = relay.deferred_write(
        HeaderType00::STATUS_COMMAND.0,
        command(false),
        PciConfigByteEnable::LOW_WORD,
    );
    let scratch = relay.deferred_write(SCRATCH_OFFSET, 0x1234_5678, PciConfigByteEnable::FULL);
    let TestRelay {
        relay,
        device,
        cfg,
        _server,
        client: _client,
    } = relay;
    let mut relay = relay.into_inner();
    relay.stop().await;
    activate.write_future().await.unwrap();
    deactivate.write_future().await.unwrap();
    scratch.write_future().await.unwrap();
    assert_eq!(device.tdisp().tdi_state().await, TdispTdiState::Unlocked);
    assert_eq!(
        cfg.lock().writes.last(),
        Some(&(SCRATCH_OFFSET, 0x1234_5678))
    );
    let mut value = 0;
    relay
        .pci_cfg_read(
            SCRATCH_OFFSET,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
        )
        .unwrap();
    assert_eq!(value, 0x1234_5678);
    // Stopping again must not replay writes or leave a pending completion.
    let writes = cfg.lock().writes.clone();
    relay.stop().await;
    assert_eq!(cfg.lock().writes, writes);
}

// Test: Write only status bytes while MMIO is disabled and while it is enabled.
// Expected: Untouched command bytes cannot accidentally trigger TDISP transitions.
#[async_test]
async fn status_only_writes_preserve_mmio_enable_state(driver: DefaultDriver) {
    let relay = connect_relay(&driver, true).await;
    let offset = HeaderType00::STATUS_COMMAND.0;
    let status_bytes = PciConfigByteEnable::new(0b1100).unwrap();
    assert!(matches!(
        relay.write(offset, command(true), status_bytes),
        IoResult::Ok
    ));
    assert_eq!(relay.read(offset) & command(true), 0);
    assert_eq!(
        relay.device.tdisp().tdi_state().await,
        TdispTdiState::Unlocked
    );
    let activate = relay.deferred_write(offset, command(true), PciConfigByteEnable::LOW_WORD);
    relay.drive(activate.write_future()).await.unwrap();
    assert!(matches!(relay.write(offset, 0, status_bytes), IoResult::Ok));
    assert_eq!(relay.read(offset) & command(true), command(true));
    assert_eq!(relay.device.tdisp().tdi_state().await, TdispTdiState::Run);
}

// Test: Attempt activation against a host that rejects TDISP commands.
// Expected: MMIO stays disabled, but deferred callers and queued writes complete.
#[async_test]
async fn failed_attestation_keeps_mmio_disabled_without_stranding_writes(driver: DefaultDriver) {
    let relay = connect_relay_with(
        &driver,
        TestHost {
            offers_tdisp: false,
            accepts_rb: true,
        },
        RelayTdisp::Assume(true),
    )
    .await;
    let activate = relay.deferred_write(
        HeaderType00::STATUS_COMMAND.0,
        command(true),
        PciConfigByteEnable::LOW_WORD,
    );
    let scratch = relay.deferred_write(SCRATCH_OFFSET, 0xabcd_1234, PciConfigByteEnable::FULL);
    relay.drive(activate.write_future()).await.unwrap();
    relay.drive(scratch.write_future()).await.unwrap();
    assert_eq!(
        relay.read(HeaderType00::STATUS_COMMAND.0) & command(true),
        0
    );
    assert_eq!(
        relay.device.tdisp().tdi_state().await,
        TdispTdiState::Unlocked
    );
    assert_eq!(relay.read(SCRATCH_OFFSET), 0xabcd_1234);
}

struct UnavailableBar;

impl CreateMemoryAccess for UnavailableBar {
    fn create_memory_access(&self, _gpa: u64) -> anyhow::Result<Box<dyn MemoryAccess>> {
        anyhow::bail!("test BAR mapping unavailable")
    }
}

// Test: Run the mock flow when the register BAR cannot be mapped.
// Expected: The original mapping failure retains flow context and no TDI is bound.
#[async_test]
async fn mock_flow_mapping_errors_remain_contextual(driver: DefaultDriver) {
    let relay = connect_relay(&driver, true).await;
    let err = crate::tdispmock::run_test_flow(relay.device.clone(), &UnavailableBar, 0x1000_0000)
        .await
        .unwrap_err();
    let message = format!("{err:#}");
    for expected in [
        "failed to exercise TDISP attestation flow",
        "failed to map the device's register BAR",
        "test BAR mapping unavailable",
    ] {
        assert!(message.contains(expected), "{message}");
    }
    assert_eq!(
        relay.device.tdisp().tdi_state().await,
        TdispTdiState::Unlocked
    );
}
