// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Request TDISP device/interface reports for page-aligned and partial-page MSI-X BAR sizes.
// Expected: IDs use the wire byte order and the reports describe correct sizes, IDs and TEE attributes.
#[test]
fn tdisp_reports_describe_controller_bars_and_round_up_msix_pages() {
    for (msix_bar_len, pages) in [(0x1000, 1), (0x1001, 2)] {
        let mut interface = FaultControllerTdispInterface {
            ranges: Default::default(),
            msix_bar_len,
        };
        let id = interface
            .tdisp_get_device_report(TdispReportType::GuestDeviceId)
            .unwrap();
        assert_eq!(id.len(), 8);
        assert_eq!(
            u64::from_le_bytes(id.try_into().unwrap()),
            TDISP_MOCK_DEVICE_ID
        );
        let bytes = interface
            .tdisp_get_device_report(TdispReportType::InterfaceReport)
            .unwrap();
        let report = tdisp::devicereport::deserialize_tdi_report(&bytes).unwrap();
        assert_eq!(report.mmio_interface_info.len(), 2);
        let registers = &report.mmio_interface_info[0];
        assert_eq!(
            (
                registers.range_id,
                registers.first_4k_page_offset,
                registers.num_4k_pages
            ),
            (0, 0, 16)
        );
        assert!(!registers.flags.is_non_tee_mem());
        let msix = &report.mmio_interface_info[1];
        assert_eq!(
            (msix.range_id, msix.first_4k_page_offset, msix.num_4k_pages),
            (4, 0, pages)
        );
        assert!(msix.flags.is_non_tee_mem());
        assert!(msix.flags.range_maps_msix_table());
        assert!(msix.flags.range_maps_msix_pba());
        assert!(report.device_specific_info.is_empty());
        assert!(
            interface
                .tdisp_get_device_report(TdispReportType::Invalid)
                .is_err()
        );
        assert!(
            interface
                .tdisp_modify_mmio_range(TdispMmioRangeAction::Invalid, 0, 0, 4096)
                .is_err()
        );
    }
}
