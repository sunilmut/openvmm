// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::srat::*;
use std::vec;
use std::vec::Vec;
use test_with_tracing::test;
use zerocopy::IntoBytes;

mod iort_tests;
mod mcfg_tests;
mod platform_tests;

fn srat_table(body: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 48];
    raw[..4].copy_from_slice(b"SRAT");
    raw[4..8].copy_from_slice(&(48u32 + body.len() as u32).to_le_bytes());
    raw[36] = 1;
    raw.extend_from_slice(body);
    raw
}

// Test: Serialize NUMA CPU, memory and PCI initiator constructors with nonzero multi-byte values.
// Expected: ACPI field offsets, little-endian split domains/addresses, enabled bits and all reserved bytes match independent ABI fixtures.
#[test]
fn srat_constructors_match_acpi_wire_layout() {
    assert_eq!(
        SratHeader::new().as_bytes(),
        &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    let apic = SratApic::new(0xab, 0x44332211);
    assert_eq!(
        apic.as_bytes(),
        &[
            0, 16, 0x11, 0xab, 1, 0, 0, 0, 0, 0x22, 0x33, 0x44, 0, 0, 0, 0
        ]
    );
    let x2 = SratX2Apic::new(0x88776655, 0x44332211);
    assert_eq!(
        x2.as_bytes(),
        &[
            2, 24, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );
    let gicc = SratGicc::new(0x88776655, 0x44332211);
    assert_eq!(
        gicc.as_bytes(),
        &[
            3, 18, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    let memory = SratMemory::new(0x8877665544332211, 0x123456789, 0x44332211);
    let mut expected = [0; 40];
    expected[..8].copy_from_slice(&[1, 40, 0x11, 0x22, 0x33, 0x44, 0, 0]);
    expected[8..16].copy_from_slice(&0x8877665544332211u64.to_le_bytes());
    expected[16..24].copy_from_slice(&0x123456789u64.to_le_bytes());
    expected[28] = 1;
    assert_eq!(memory.as_bytes(), expected);
    let pci = SratGenericInitiator::new_pci(0x1234, 0x56, 0xff, 0xfd, 0x44332211);
    let mut expected = [0; 32];
    expected[..12].copy_from_slice(&[5, 32, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x34, 0x12, 0x56, 0xfd]);
    expected[24] = 1;
    assert_eq!(pci.as_bytes(), expected);
}

// Test: Parse an independently encoded mixed CPU/memory SRAT and every truncated structure/header boundary.
// Expected: Callbacks observe exact original records in order; malformed lengths/signatures/types return typed errors without inventing callbacks.
#[test]
fn srat_parser_preserves_records_and_rejects_malformed_tables() {
    let apic = [
        0, 16, 0x11, 0xab, 1, 0, 0, 0, 0, 0x22, 0x33, 0x44, 0, 0, 0, 0,
    ];
    let mut memory = [0; 40];
    memory[0] = 1;
    memory[1] = 40;
    memory[2] = 9;
    memory[8] = 0x80;
    memory[12] = 2;
    memory[16] = 0x40;
    memory[28] = 1;
    let mut body = apic.to_vec();
    body.extend_from_slice(&memory);
    body.extend_from_slice(&apic);
    let raw = srat_table(&body);
    let mut cpus = Vec::new();
    let mut memories = Vec::new();
    let (header, fixed) = parse_srat(
        &raw,
        |cpu| cpus.push(cpu.as_bytes()),
        |mem| memories.push(mem.as_bytes()),
    )
    .unwrap();
    assert_eq!(header.signature, *b"SRAT");
    assert_eq!(fixed.rsvd1.get(), 1);
    assert_eq!(cpus, [&apic[..], &apic[..]]);
    assert_eq!(memories, [&memory[..]]);
    for len in 0..36 {
        assert!(matches!(
            parse_srat(
                &raw[..len],
                |_| panic!("unexpected CPU"),
                |_| panic!("unexpected memory")
            ),
            Err(ParseSratError::MissingAcpiHeader)
        ));
    }
    let mut invalid = srat_table(&[]);
    invalid[0] = b'X';
    assert!(matches!(
        parse_srat(&invalid, |_| {}, |_| {}),
        Err(ParseSratError::InvalidSignature([b'X', b'R', b'A', b'T']))
    ));
    let mut invalid = srat_table(&[]);
    invalid[4..8].copy_from_slice(&49u32.to_le_bytes());
    assert!(matches!(
        parse_srat(&invalid, |_| {}, |_| {}),
        Err(ParseSratError::MismatchedLength {
            in_header: 49,
            actual: 48
        })
    ));
    for len in 36..48 {
        let mut raw = raw[..len].to_vec();
        raw[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        assert!(matches!(
            parse_srat(&raw, |_| {}, |_| {}),
            Err(ParseSratError::MissingFixedHeader)
        ));
    }
    for len in 1..16 {
        assert!(matches!(
            parse_srat(
                &srat_table(&apic[..len]),
                |_| panic!("unexpected CPU"),
                |_| panic!("unexpected memory")
            ),
            Err(ParseSratError::BadApic)
        ));
    }
    for len in 1..40 {
        assert!(matches!(
            parse_srat(
                &srat_table(&memory[..len]),
                |_| panic!("unexpected CPU"),
                |_| panic!("unexpected memory")
            ),
            Err(ParseSratError::BadMemory)
        ));
    }
    assert!(matches!(
        parse_srat(&srat_table(&[0xfe]), |_| {}, |_| {}),
        Err(ParseSratError::UnknownType(0xfe))
    ));
}

// Test: Change only the declared length of otherwise valid SRAT CPU and memory records, with a successful full-record control.
// Expected: Invalid declared lengths fail before delivering that record to a topology callback, rather than treating available bytes as a valid affinity entry.
#[test]
#[ignore = "Confirmed product bug: SRAT parser accepts a zero declared APIC length and invokes its callback"]
fn known_bug_srat_parser_rejects_invalid_declared_record_lengths() {
    let apic = SratApic::new(0xab, 0x44332211);
    let memory = SratMemory::new(0x100000000, 0x200000, 7);
    for (record, cpu_count, memory_count) in [(apic.as_bytes(), 1, 0), (memory.as_bytes(), 0, 1)] {
        let mut cpus = 0;
        let mut memories = 0;
        parse_srat(&srat_table(record), |_| cpus += 1, |_| memories += 1).unwrap();
        assert_eq!((cpus, memories), (cpu_count, memory_count));
        for declared in [0, 1, record.len() as u8 - 1, record.len() as u8 + 1] {
            let mut malformed = record.to_vec();
            malformed[1] = declared;
            let mut cpus = 0;
            let mut memories = 0;
            let raw = srat_table(&malformed);
            let result = parse_srat(&raw, |_| cpus += 1, |_| memories += 1);
            assert!(
                result.is_err(),
                "accepted declared record length {declared}"
            );
            assert_eq!((cpus, memories), (0, 0));
        }
    }
}

// Test: Parse valid CPU and memory records followed by an unknown type and another valid CPU record.
// Expected: Callbacks retain exactly the accepted prefix and parsing returns the unknown-type error without visiting later records.
#[test]
fn srat_parser_stops_after_unknown_record_without_losing_accepted_prefix() {
    let apic = SratApic::new(0xab, 0x44332211);
    let memory = SratMemory::new(0x100000000, 0x200000, 7);
    let body = [apic.as_bytes(), memory.as_bytes(), &[0xfe], apic.as_bytes()].concat();
    let raw = srat_table(&body);
    let mut cpus = Vec::new();
    let mut memories = Vec::new();
    let result = parse_srat(
        &raw,
        |cpu| cpus.push(cpu.as_bytes()),
        |memory| memories.push(memory.as_bytes()),
    );
    assert!(matches!(result, Err(ParseSratError::UnknownType(0xfe))));
    assert_eq!(cpus, [apic.as_bytes()]);
    assert_eq!(memories, [memory.as_bytes()]);
}
