// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mcfg::*;
use test_with_tracing::test;

fn table(body: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 44];
    raw[..4].copy_from_slice(b"MCFG");
    raw[4..8].copy_from_slice(&(44u32 + body.len() as u32).to_le_bytes());
    raw.extend_from_slice(body);
    raw
}

// Test: Serialize and parse multiple independently encoded PCI segment/ECAM ranges and all truncated boundaries.
// Expected: Segment order and exact address/bus values survive, reserved fields are zero, and header/body errors are precisely classified without extra callbacks.
#[test]
fn mcfg_wire_ranges_and_parser_boundaries() {
    assert_eq!(McfgHeader::new().as_bytes(), &[0; 8]);
    let range = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x12, 0x34, 0, 0, 0, 0,
    ];
    assert_eq!(
        McfgSegmentBusRange::new(0x8877665544332211, 0xaa99, 0x12, 0x34).as_bytes(),
        range
    );
    let mut body = range.to_vec();
    body.extend_from_slice(&range);
    let raw = table(&body);
    let mut found = Vec::new();
    let (header, fixed) = parse_mcfg(&raw, |range| found.push(range.as_bytes())).unwrap();
    assert_eq!(header.signature, *b"MCFG");
    assert_eq!(fixed.rsvd.get(), 0);
    assert_eq!(found, [&range[..], &range[..]]);
    for len in 0..36 {
        assert!(matches!(
            parse_mcfg(&raw[..len], |_| panic!("unexpected range")),
            Err(ParseMcfgError::MissingAcpiHeader)
        ));
    }
    let mut bad = table(&[]);
    bad[0] = b'X';
    assert!(matches!(
        parse_mcfg(&bad, |_| {}),
        Err(ParseMcfgError::InvalidSignature([b'X', b'C', b'F', b'G']))
    ));
    let mut bad = table(&[]);
    bad[4..8].copy_from_slice(&45u32.to_le_bytes());
    assert!(matches!(
        parse_mcfg(&bad, |_| {}),
        Err(ParseMcfgError::MismatchedLength(45, 44))
    ));
    for len in 36..44 {
        let mut bad = raw[..len].to_vec();
        bad[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        assert!(matches!(
            parse_mcfg(&bad, |_| {}),
            Err(ParseMcfgError::MissingFixedHeader)
        ));
    }
    for len in 1..16 {
        assert!(matches!(
            parse_mcfg(&table(&range[..len]), |_| panic!("unexpected range")),
            Err(ParseMcfgError::BadSegmentBusRange)
        ));
    }
}

// Test: Convert borrowed NUMA and ECAM tables to owned tables and independently use each owned constructor, then discard the source byte buffers.
// Expected: Both ownership APIs retain exact records, table headers, and order with no lifetime dependency on the raw input; malformed tables still propagate parse errors.
#[test]
#[cfg(feature = "alloc")]
fn owned_tables_preserve_records_after_input_is_dropped() {
    let cpu = SratApic::new(7, 0x44332211);
    let memory = SratMemory::new(0x12345000, 0x56789000, 9);
    let mut body = cpu.as_bytes().to_vec();
    body.extend_from_slice(memory.as_bytes());
    let raw = srat_table(&body);
    let borrowed = BorrowedSrat::new(&raw).unwrap();
    assert_eq!(borrowed.apics[0].as_bytes(), cpu.as_bytes());
    assert_eq!(borrowed.memory[0].as_bytes(), memory.as_bytes());
    let converted = OwnedSrat::from(borrowed);
    let constructed = OwnedSrat::new(&raw).unwrap();
    drop(raw);
    for owned in [converted, constructed] {
        assert_eq!(owned.acpi_header.signature, *b"SRAT");
        assert_eq!(owned.srat_header.rsvd1.get(), 1);
        assert_eq!(owned.apics.len(), 1);
        assert_eq!(owned.memory.len(), 1);
        assert_eq!(owned.apics[0].as_bytes(), cpu.as_bytes());
        assert_eq!(owned.memory[0].as_bytes(), memory.as_bytes());
    }
    assert!(matches!(
        OwnedSrat::new(&[]),
        Err(ParseSratError::MissingAcpiHeader)
    ));
    let range = McfgSegmentBusRange::new(0x12345678000, 4, 0x20, 0x3f);
    let raw = table(range.as_bytes());
    let borrowed = BorrowedMcfg::new(&raw).unwrap();
    assert_eq!(borrowed.segment_bus_ranges[0].as_bytes(), range.as_bytes());
    let converted = OwnedMcfg::from(borrowed);
    let constructed = OwnedMcfg::new(&raw).unwrap();
    drop(raw);
    for owned in [converted, constructed] {
        assert_eq!(owned.acpi_header.signature, *b"MCFG");
        assert_eq!(owned.mcfg_header.rsvd.get(), 0);
        assert_eq!(owned.segment_bus_ranges.len(), 1);
        assert_eq!(owned.segment_bus_ranges[0].as_bytes(), range.as_bytes());
    }
    assert!(matches!(
        OwnedMcfg::new(&[]),
        Err(ParseMcfgError::MissingAcpiHeader)
    ));
}
