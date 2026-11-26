// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::linux;
use crate::paravisor::CommandLinePolicy;
use crate::paravisor::ImportedRegionDescriptor;
use crate::paravisor::PageRegionDescriptor;
use crate::paravisor::ParavisorCommandLine;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

// Test: Interpret measured command-line pages at empty, UTF-8 and capacity limits.
// Expected: Length selects bytes rather than a trailing NUL; invalid UTF-8
//       returns None and full-capacity text is accepted without truncation.
#[test]
fn measured_command_line_pages() {
    let mut page = ParavisorCommandLine::new_zeroed();
    assert_eq!(page.command_line(), Some(""));
    let text = "console=ttyS0 label=é";
    page.policy = CommandLinePolicy::APPEND_CHOSEN;
    page.static_command_line_len = text.len() as u16;
    page.static_command_line.fill(0xff);
    page.static_command_line[..text.len()].copy_from_slice(text.as_bytes());
    let wire = page.as_bytes();
    assert_eq!(&wire[..4], &[1, 0, text.len() as u8, 0]);
    let decoded = ParavisorCommandLine::read_from_bytes(wire).unwrap();
    assert_eq!(decoded.command_line(), Some(text));
    page.static_command_line_len -= 1;
    assert_eq!(page.command_line(), None);
    page.static_command_line.fill(b'x');
    page.static_command_line_len = page.static_command_line.len() as u16;
    assert_eq!(page.command_line().unwrap().len(), 4092);
    assert!(
        page.command_line()
            .unwrap()
            .bytes()
            .all(|byte| byte == b'x')
    );
}

// Test: Encode accepted and shared imported regions plus zero-count terminators.
// Expected: The ABI uses page numbers and 64-bit counts with zero padding;
//       zero-count entries terminate regardless of their nonzero base address.
#[test]
fn imported_region_wire_pages() {
    for accepted in [false, true] {
        let region = ImportedRegionDescriptor::new(0x1_0000_0002, 3, accepted);
        let mut expected = [0; 24];
        expected[..8].copy_from_slice(&0x1_0000_0002u64.to_le_bytes());
        expected[8..16].copy_from_slice(&3u64.to_le_bytes());
        expected[16] = u8::from(accepted);
        assert_eq!(region.as_bytes(), expected);
        let decoded = ImportedRegionDescriptor::read_from_bytes(&expected).unwrap();
        assert_eq!(decoded.pages(), Some((0x1_0000_0002, 3, accepted)));
        let terminator = ImportedRegionDescriptor::new(0x1_0000_0002, 0, accepted);
        assert_eq!(
            ImportedRegionDescriptor::read_from_bytes(terminator.as_bytes())
                .unwrap()
                .pages(),
            None
        );
    }
    let region = PageRegionDescriptor::new(0, 1);
    let decoded = PageRegionDescriptor::read_from_bytes(region.as_bytes()).unwrap();
    assert_eq!(decoded.pages(), Some((0, 1)));
    assert_eq!(PageRegionDescriptor::new(17, 0).pages(), None);
}

// Test: Populate a Linux zero-page boot handoff with RSDP, command-line and E820 data.
// Expected: The 4096-byte ABI places each value at Linux's documented offset
//       and leaves unused bytes zero, preserving the kernel handoff contract.
#[test]
fn linux_zero_page_wire_offsets() {
    let mut header = linux::setup_header::new_zeroed();
    header.cmd_line_ptr = 0x1234_5678u32.into();
    let mut params = linux::boot_params {
        acpi_rsdp_addr: 0x1_2345_6000,
        hdr: header,
        e820_entries: 1,
        ..Default::default()
    };
    params.e820_map[0] = linux::e820entry {
        addr: 0x1_0000_0000u64.into(),
        size: 0x20_0000u64.into(),
        typ: linux::E820_RAM.into(),
    };
    let bytes = params.as_bytes();
    let mut expected = [0; 4096];
    expected[0x70..0x78].copy_from_slice(&0x1_2345_6000u64.to_le_bytes());
    expected[0x1e8] = 1;
    expected[0x228..0x22c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    expected[0x2d0..0x2d8].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
    expected[0x2d8..0x2e0].copy_from_slice(&0x20_0000u64.to_le_bytes());
    expected[0x2e0..0x2e4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(bytes, expected);
    assert!(linux::boot_params::read_from_bytes(&expected[..4095]).is_err());
}

// Test: Classify device-tree memory usage across RAM, MMIO and unknown wire types.
// Expected: VTL2-owned MMIO is not RAM; future unknown types belong to neither
//       class, preventing a device range from becoming allocatable memory.
#[test]
fn device_tree_memory_classification() {
    use crate::shim::MemoryVtlType;
    let entries = [
        (MemoryVtlType::VTL0, true, false),
        (MemoryVtlType::VTL2_RAM, true, true),
        (MemoryVtlType::VTL2_CONFIG, true, true),
        (MemoryVtlType::VTL2_SIDECAR_IMAGE, true, true),
        (MemoryVtlType::VTL2_SIDECAR_NODE, true, true),
        (MemoryVtlType::VTL0_MMIO, false, false),
        (MemoryVtlType::VTL2_MMIO, false, true),
        (MemoryVtlType::VTL2_RESERVED, true, true),
        (MemoryVtlType::VTL2_GPA_POOL, true, true),
        (MemoryVtlType::VTL2_TDX_PAGE_TABLES, true, true),
        (MemoryVtlType::VTL2_BOOTSHIM_LOG_BUFFER, true, true),
        (MemoryVtlType::VTL2_PERSISTED_STATE_HEADER, true, true),
        (MemoryVtlType::VTL2_PERSISTED_STATE_PROTOBUF, true, true),
        (MemoryVtlType(13), false, false),
        (MemoryVtlType(u32::MAX), false, false),
    ];
    for (usage, ram, vtl2) in entries {
        assert_eq!(usage.ram(), ram, "wire type {}", usage.0);
        assert_eq!(usage.vtl2(), vtl2, "wire type {}", usage.0);
    }
}
