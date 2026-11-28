// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests for reading and writing the TDI interface report.

use crate::devicereport::TDI_REPORT_HEADER_SIZE;
use crate::devicereport::TdiReportStruct;
use crate::devicereport::TdispTdiReportInterfaceInfo;
use crate::devicereport::TdispTdiReportMmioFlags;
use crate::devicereport::TdispTdiReportMmioInterfaceInfo;
use crate::devicereport::deserialize_tdi_report;
use crate::devicereport::serialize_tdi_report;
use test_with_tracing::test;

/// A report from a TDI with two MMIO ranges: a 64K range of TEE memory and a
/// 4K range mapping the MSI-X table.
fn two_range_report() -> TdiReportStruct {
    TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new().with_generate_dma_without_pasid(true),
        msi_x_message_control: 0x8001,
        lnr_control: 0x1234,
        tph_control: 0xabcd_0123,
        mmio_interface_info: vec![
            TdispTdiReportMmioInterfaceInfo {
                first_4k_page_offset: 0xf000_0000,
                num_4k_pages: 16,
                flags: TdispTdiReportMmioFlags::new(),
                range_id: 0,
            },
            TdispTdiReportMmioInterfaceInfo {
                first_4k_page_offset: 0x1_f001_0000,
                num_4k_pages: 1,
                flags: TdispTdiReportMmioFlags::new()
                    .with_range_maps_msix_table(true)
                    .with_is_non_tee_mem(true),
                range_id: 4,
            },
        ],
        device_specific_info: Vec::new(),
    }
}

// Test: Round-trip an interface report with distinct MMIO ranges and flags.
// Expected: Every control field and each ordered range field survives unchanged.
#[test]
fn report_survives_a_round_trip() {
    let report = two_range_report();
    let parsed = deserialize_tdi_report(&serialize_tdi_report(&report)).unwrap();

    assert_eq!(
        parsed.interface_info.into_bits(),
        report.interface_info.into_bits()
    );
    assert_eq!(parsed.msi_x_message_control, report.msi_x_message_control);
    assert_eq!(parsed.lnr_control, report.lnr_control);
    assert_eq!(parsed.tph_control, report.tph_control);
    assert_eq!(parsed.mmio_interface_info.len(), 2);
    for (parsed, original) in parsed
        .mmio_interface_info
        .iter()
        .zip(report.mmio_interface_info.iter())
    {
        assert_eq!(parsed.first_4k_page_offset, original.first_4k_page_offset);
        assert_eq!(parsed.num_4k_pages, original.num_4k_pages);
        assert_eq!(parsed.flags.into_bits(), original.flags.into_bits());
        assert_eq!(parsed.range_id, original.range_id);
    }
}

// Test: Serialize a report containing two MMIO ranges.
// Expected: The wire count is two and the length includes both complete records.
#[test]
fn range_count_comes_from_the_range_list() {
    let report = two_range_report();
    let buffer = serialize_tdi_report(&report);
    assert_eq!(&buffer[12..16], &[2, 0, 0, 0]);

    // The header, one entry per range, then the device specific info length.
    assert_eq!(
        buffer.len(),
        TDI_REPORT_HEADER_SIZE
            + 2 * size_of::<TdispTdiReportMmioInterfaceInfo>()
            + size_of::<u32>()
    );
}

// Test: Serialize and decode a report with no MMIO ranges or vendor data.
// Expected: The header and zero vendor length decode to an empty range list.
#[test]
fn a_report_with_no_ranges_is_the_header_and_a_zero_length() {
    let report = TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
        device_specific_info: Vec::new(),
    };

    let buffer = serialize_tdi_report(&report);
    // The header, no ranges, then a device specific info length of zero.
    assert_eq!(buffer.len(), TDI_REPORT_HEADER_SIZE + size_of::<u32>());
    assert!(
        deserialize_tdi_report(&buffer)
            .unwrap()
            .mmio_interface_info
            .is_empty()
    );
}

// Test: Round-trip vendor bytes containing embedded and trailing zeroes.
// Expected: The complete vendor payload survives without string-like truncation.
#[test]
fn device_specific_info_survives_a_round_trip() {
    let mut report = two_range_report();
    report.device_specific_info = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];

    let parsed = deserialize_tdi_report(&serialize_tdi_report(&report)).unwrap();
    assert_eq!(parsed.device_specific_info, report.device_specific_info);
}

// Test: Decode a report that ends immediately after its two MMIO records.
// Expected: Both ranges are accepted and absent vendor data is reported as empty.
#[test]
fn a_report_ending_after_the_ranges_has_no_device_specific_info() {
    let report = two_range_report();
    let mut buffer = serialize_tdi_report(&report);

    // Not every device appends the length, so a report may end here.
    buffer.truncate(buffer.len() - size_of::<u32>());

    let parsed = deserialize_tdi_report(&buffer).unwrap();
    assert_eq!(parsed.mmio_interface_info.len(), 2);
    assert!(parsed.device_specific_info.is_empty());
}

// Test: Decode a report whose vendor length exceeds the remaining bytes.
// Expected: Decoding fails rather than accepting incomplete vendor data.
#[test]
fn a_device_specific_info_length_past_the_end_is_rejected() {
    let report = two_range_report();
    let mut buffer = serialize_tdi_report(&report);

    // Claim eight bytes of device specific info without supplying any.
    let len_offset = buffer.len() - size_of::<u32>();
    buffer[len_offset..].copy_from_slice(&8u32.to_ne_bytes());

    assert!(deserialize_tdi_report(&buffer).is_err());
}

// PCIe DEVICE_INTERFACE_REPORT layout: 16-byte header, two 16-byte ranges,
// then a four-byte vendor length and six vendor bytes. This fixture is not
// generated by either serialization function under test.
const PCIE_REPORT: &[u8] = &[
    0x02, 0x00, 0x00, 0x00, 0x01, 0x80, 0x34, 0x12, 0x23, 0x01, 0xcd, 0xab, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00,
    0x06, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
];

// Test: Serialize a two-range report with a 64-bit address and binary vendor data.
// Expected: The complete bytes match the independently specified PCIe layout,
//       including field order, reserved bytes, flags, counts and vendor length.
#[test]
fn report_serialization_matches_independent_pcie_bytes() {
    let mut report = two_range_report();
    report.device_specific_info = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];
    assert_eq!(serialize_tdi_report(&report), PCIE_REPORT);
}

// Test: Decode independent PCIe report bytes and then overwrite the input.
// Expected: All controls, ordered MMIO fields and binary vendor data are correct
//       and remain owned by the decoded report after the input changes.
#[test]
fn independent_pcie_report_decodes_to_complete_owned_payload() {
    let mut bytes = PCIE_REPORT.to_vec();
    let parsed = deserialize_tdi_report(&bytes).unwrap();
    bytes.fill(0);

    assert_eq!(parsed.interface_info.into_bits(), 0x0002);
    assert_eq!(parsed.msi_x_message_control, 0x8001);
    assert_eq!(parsed.lnr_control, 0x1234);
    assert_eq!(parsed.tph_control, 0xabcd_0123);
    assert_eq!(parsed.mmio_interface_info.len(), 2);
    let first = &parsed.mmio_interface_info[0];
    assert_eq!(first.first_4k_page_offset, 0xf000_0000);
    assert_eq!(first.num_4k_pages, 16);
    assert_eq!(first.flags.into_bits(), 0);
    assert_eq!(first.range_id, 0);
    let second = &parsed.mmio_interface_info[1];
    assert_eq!(second.first_4k_page_offset, 0x1_f001_0000);
    assert_eq!(second.num_4k_pages, 1);
    assert_eq!(second.flags.into_bits(), 0x0005);
    assert_eq!(second.range_id, 4);
    assert_eq!(parsed.device_specific_info, [0xde, 0xad, 0xbe, 0xef, 0, 0]);
}
