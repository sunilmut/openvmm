// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::builder::Builder;
use crate::builder::OemInfo;
use crate::builder::Table;
use crate::dsdt::AmlObject;
use crate::dsdt::Dsdt;
use crate::dsdt::PciRoutingTable;
use crate::dsdt::PciRoutingTableEntry;
use acpi_spec::madt;
use alloc::vec;
use alloc::vec::Vec;
use memory_range::MemoryRange;
use test_with_tracing::test;
use zerocopy::IntoBytes;

const OEM: OemInfo = OemInfo {
    oem_id: *b"UNITVM",
    oem_tableid: *b"TESTTABL",
    oem_revision: 0x1234,
    creator_id: *b"TEST",
    creator_revision: 0x5678,
};

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
}

fn verify_table(bytes: &[u8], signature: &[u8; 4]) {
    assert_eq!(&bytes[..4], signature);
    assert_eq!(u32_at(bytes, 4) as usize, bytes.len());
    assert_eq!(checksum(bytes), 0);
}

fn table_at(bytes: &[u8], base: u64, address: u64) -> &[u8] {
    let offset = usize::try_from(address - base).unwrap();
    assert_eq!(offset % 8, 0);
    &bytes[offset..offset + u32_at(bytes, offset + 4) as usize]
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn memory_resources(bytes: &[u8]) -> Vec<(u64, u64, u64)> {
    bytes
        .windows(46)
        .filter(|r| r[..3] == [0x8a, 0x2b, 0])
        .map(|r| (u64_at(r, 14), u64_at(r, 22), u64_at(r, 38)))
        .collect()
}

fn interrupts(bytes: &[u8]) -> Vec<(u8, u32)> {
    bytes
        .windows(9)
        .filter(|r| r[..3] == [0x89, 6, 0])
        .map(|r| {
            assert_eq!(r[4], 1);
            (r[3], u32_at(r, 5))
        })
        .collect()
}

// Test: Build an image above 4 GiB containing raw DSDT/SRAT tables and a typed
//       MADT with an extra interrupt-routing entry.
// Expected: RSDP/XSDT pointers retain all 64 bits, omit DSDT from XSDT, preserve
//       table data/OEM overrides, align tables, and have valid checksums.
#[test]
fn complete_image_preserves_addresses_payloads_and_root_checksums() {
    const BASE: u64 = 0x1_0000_1000;
    let mut builder = Builder::new(BASE, OEM);
    let dsdt = Dsdt::new().to_bytes();
    let dsdt_address = builder.append_raw(&dsdt);
    let iso = madt::MadtInterruptSourceOverride::new(0, 2, None, None);
    let madt = madt::Madt {
        apic_addr: 0xfee0_0000,
        flags: madt::MADT_PCAT_COMPAT,
    };
    let madt_address = builder.append(&Table::new_dyn(
        5,
        Some(*b"OVERRIDE"),
        &madt,
        &[iso.as_bytes()],
    ));
    let srat = Table::new(3, None, &acpi_spec::srat::SratHeader::new()).to_vec(&OEM);
    let srat_address = builder.append_raw(&srat);
    let (rsdp, image) = builder.build();
    assert_eq!(&rsdp[..8], b"RSD PTR ");
    assert_eq!(rsdp[15], 2);
    assert_eq!(u32_at(&rsdp, 20) as usize, rsdp.len());
    assert_eq!(checksum(&rsdp[..20]), 0);
    assert_eq!(checksum(&rsdp), 0);
    assert_eq!(&rsdp[9..15], &OEM.oem_id);
    assert_eq!(u32_at(&rsdp, 16), 0);
    assert_eq!(table_at(&image, BASE, dsdt_address), dsdt);
    let emitted_madt = table_at(&image, BASE, madt_address);
    verify_table(emitted_madt, b"APIC");
    assert_eq!(emitted_madt[8], 5);
    assert_eq!(&emitted_madt[10..16], &OEM.oem_id);
    assert_eq!(&emitted_madt[16..24], b"OVERRIDE");
    assert_eq!(u32_at(emitted_madt, 24), OEM.oem_revision);
    assert_eq!(&emitted_madt[28..32], &OEM.creator_id);
    assert_eq!(u32_at(emitted_madt, 32), OEM.creator_revision);
    assert_eq!(&emitted_madt[36..44], madt.as_bytes());
    assert_eq!(&emitted_madt[44..], iso.as_bytes());
    assert_eq!(table_at(&image, BASE, srat_address), srat);
    let xsdt = table_at(&image, BASE, u64_at(&rsdp, 24));
    verify_table(xsdt, b"XSDT");
    assert_eq!(&xsdt[16..24], &OEM.oem_tableid);
    let pointers: Vec<_> = xsdt[36..].chunks_exact(8).map(|p| u64_at(p, 0)).collect();
    assert_eq!(pointers, [madt_address, srat_address]);
    for (address, table) in [
        (dsdt_address, &dsdt[..]),
        (madt_address, emitted_madt),
        (srat_address, &srat[..]),
    ] {
        let end = (address - BASE) as usize + table.len();
        let padded_end = end.next_multiple_of(8);
        assert!(image[end..padded_end].iter().all(|&b| b == 0));
    }
}

// Test: Build an image without any supplied tables.
// Expected: A valid RSDP points to an empty XSDT at the requested base address;
//       no uninitialized pointers or nonzero padding are emitted.
#[test]
fn empty_image_still_has_valid_root_tables() {
    let (rsdp, image) = Builder::new(0x8000, OEM).build();
    assert_eq!(u64_at(&rsdp, 24), 0x8000);
    assert_eq!(checksum(&rsdp[..20]), 0);
    assert_eq!(checksum(&rsdp), 0);
    let xsdt = table_at(&image, 0x8000, 0x8000);
    verify_table(xsdt, b"XSDT");
    assert_eq!(xsdt.len(), 36);
    assert_eq!(&image[36..], &[0; 4]);
}

// Test: Encode PCI interrupt routes using a direct GSI and a named link device.
// Expected: The AML package contains both four-element entries with the exact
//       address, pin, source and source-index values in their defined wire forms.
#[test]
fn routing_table_encodes_direct_and_link_sources() {
    let mut table = PciRoutingTable::new();
    table.add_entry(PciRoutingTableEntry {
        address: 0x0002_ffff,
        pin: 0,
        source: None,
        source_index: 11,
    });
    table.add_entry(PciRoutingTableEntry {
        address: 0x0003_0001,
        pin: 1,
        source: Some(b"LNKA".to_vec()),
        source_index: 0,
    });
    assert_eq!(
        table.to_bytes(),
        [
            0x08, b'_', b'P', b'R', b'T', 0x12, 0x23, 2, 0x12, 0x0e, 4, 0x0c, 0xff, 0xff, 2, 0, 0,
            0, 0x0c, 11, 0, 0, 0, 0x12, 0x11, 4, 0x0c, 1, 0, 3, 0, 1, b'L', b'N', b'K', b'A', 0x0c,
            0, 0, 0, 0,
        ]
    );
}

// Test: Generate a legacy PCI root with explicit and wildcard-function routes,
//       optional high MMIO, and a VMBus child under the PCI root.
// Expected: AML exposes the requested ranges and routes, and VMBus has the PCI
//       namespace path without an unsolicited interrupt resource.
#[test]
fn legacy_pci_resources_and_vmbus_parent_match_configuration() {
    let low = MemoryRange::new(0x8000_0000..0x9000_0000);
    for high in [
        MemoryRange::new(0..0),
        MemoryRange::new(0x1_0000_0000..0x1_1000_0000),
    ] {
        let mut dsdt = Dsdt::new();
        dsdt.add_pci(low, high, &[((2, Some(3)), 5), ((7, None), 11)]);
        dsdt.add_vmbus(true, None);
        let bytes = dsdt.to_bytes();
        verify_table(&bytes, b"DSDT");
        assert!(contains(&bytes, b"\\\x2f\x03_SB_PCI0VMBS"));
        assert!(contains(
            &bytes,
            &[0x0c, 3, 0, 2, 0, 0, 0, 0x0c, 5, 0, 0, 0]
        ));
        assert!(contains(
            &bytes,
            &[0x0c, 0xff, 0xff, 7, 0, 0, 0, 0x0c, 11, 0, 0, 0]
        ));
        let mut expected = vec![(low.start(), low.end() - 1, low.len())];
        if !high.is_empty() {
            expected.push((high.start(), high.end() - 1, high.len()));
        }
        assert_eq!(memory_resources(&bytes), expected);
        assert!(interrupts(&bytes).is_empty());
    }
}

// Test: Generate VMBus under a non-PCI MMIO module, varying absent/present low
//       and high windows and providing an interrupt.
// Expected: Only configured windows appear; the interrupt is edge-triggered,
//       and the power methods target the device's advertised status name.
#[test]
fn mmio_module_omits_empty_windows_and_describes_vmbus_interrupt() {
    for (low, high) in [
        (MemoryRange::new(0..0), MemoryRange::new(0..0)),
        (
            MemoryRange::new(0x9000_0000..0xa000_0000),
            MemoryRange::new(0..0),
        ),
        (
            MemoryRange::new(0..0),
            MemoryRange::new(0x2_0000_0000..0x2_1000_0000),
        ),
    ] {
        let mut dsdt = Dsdt::new();
        dsdt.add_mmio_module(low, high);
        dsdt.add_vmbus(false, Some(30));
        let bytes = dsdt.to_bytes();
        verify_table(&bytes, b"DSDT");
        assert!(contains(&bytes, b"\\\x2f\x03_SB_VMODVMBS"));
        let expected: Vec<_> = [low, high]
            .into_iter()
            .filter(|r| !r.is_empty())
            .map(|r| (r.start(), r.end() - 1, r.len()))
            .collect();
        assert_eq!(memory_resources(&bytes), expected);
        assert_eq!(interrupts(&bytes), [(3, 30)]);
        assert!(contains(&bytes, b"\x7bSTA_\x0a\x0dSTA_"));
        assert!(contains(&bytes, b"\x7dSTA_\x0a\x0fSTA_"));
        assert!(contains(&bytes, b"\xa4STA_"));
    }
}

// Test: Generate legacy and SBSA UART descriptions through their public helpers.
// Expected: The legacy UART has an exclusive edge IRQ; SBSA advertises its
//       MMIO range, ARM hardware ID, UID and exclusive level-triggered interrupt.
#[test]
fn uart_helpers_expose_architecture_appropriate_resources() {
    let mut legacy = Dsdt::new();
    legacy.add_uart(b"\\_SB.UAR1", b"COM1", 1, 0x3f8, 4);
    let bytes = legacy.to_bytes();
    verify_table(&bytes, b"DSDT");
    assert_eq!(interrupts(&bytes), [(3, 4)]);
    assert!(contains(&bytes, b"COM1\0"));
    let mut sbsa = Dsdt::new();
    sbsa.add_sbsa_uart(b"\\_SB.UAR2", 2, 0x0900_0000, 0x1000, 33);
    let bytes = sbsa.to_bytes();
    verify_table(&bytes, b"DSDT");
    assert!(contains(&bytes, b"\x08_HID\x0dARMH0011\0"));
    assert!(contains(&bytes, b"\x08_UID\x0a\x02"));
    assert_eq!(interrupts(&bytes), [(1, 33)]);
    assert_eq!(
        memory_resources(&bytes),
        [(0x0900_0000, 0x0900_0fff, 0x1000)]
    );
}

// IGNORED: PciRoutingTable writes the pin as a raw byte. Pin two therefore
// produces an invalid AML opcode instead of a BytePrefix integer.
//
// Test: Encode a PCI INTC route, whose zero-based pin number is two.
// Expected: AML represents two as BytePrefix followed by 2, rather than treating
//       the pin value as an AML opcode.
#[test]
#[ignore = "product regression: PCI pin two is not encoded as an AML integer"]
fn routing_pin_two_uses_an_aml_integer_encoding() {
    let mut table = PciRoutingTable::new();
    table.add_entry(PciRoutingTableEntry {
        address: 0x0002_ffff,
        pin: 2,
        source: None,
        source_index: 11,
    });
    assert_eq!(
        table.to_bytes(),
        [
            0x08, b'_', b'P', b'R', b'T', 0x12, 0x12, 1, 0x12, 0x0f, 4, 0x0c, 0xff, 0xff, 2, 0,
            0x0a, 2, 0, 0x0c, 11, 0, 0, 0,
        ]
    );
}
