// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate std;

use crate::builder::Builder;
use crate::builder::BuilderConfig;
use crate::builder::Error as BuildError;
use crate::parser::Parser;
use std::string::String;
use std::string::ToString;
use std::vec;
use std::vec::Vec;
use test_with_tracing::test;
use zerocopy::IntoBytes;

mod malformed;

// Encode wire words independently of the builder being tested.
fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

// Use u32 storage so malformed-wire tests still satisfy the parser's alignment contract.
fn wire(structure: &[u8], strings: &[u8]) -> Vec<u32> {
    let strings_offset = 56 + structure.len();
    let total = (strings_offset + strings.len() + 3) & !3;
    let header = [
        0xd00d_feed,
        total as u32,
        56,
        strings_offset as u32,
        40,
        17,
        16,
        7,
        strings.len() as u32,
        structure.len() as u32,
    ];
    let mut bytes = words(&header);
    bytes.resize(56, 0);
    bytes.extend_from_slice(structure);
    bytes.extend_from_slice(strings);
    bytes.resize(total, 0);
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_ne_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn field(blob: &mut [u32], index: usize, value: u32) {
    blob.as_mut_bytes()[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
}

fn parse_error(blob: &[u8]) -> String {
    match Parser::new(blob) {
        Err(error) => error.to_string(),
        Ok(parser) => match parser.root() {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed FDT was accepted"),
        },
    }
}

// Test: Round-trip every array/list form, an empty property, binary chunks and multiple reservations.
// Expected: Big-endian values, string separators, byte lengths and reservation order are exact.
#[test]
fn property_combinators_preserve_wire_values() {
    let mut buffer = [0u32; 256];
    let reservations = [
        crate::ReserveEntry {
            address: 0x3000.into(),
            size: 0x1000.into(),
        },
        crate::ReserveEntry {
            address: 0x1000.into(),
            size: 0x1000.into(),
        },
    ];
    let mut builder = Builder::new(BuilderConfig {
        blob_buffer: buffer.as_mut_bytes(),
        string_table_cap: 128,
        memory_reservations: &reservations,
    })
    .unwrap();
    let names = [
        "flag", "u32s", "u64s", "sequence", "strings", "binary", "empty",
    ];
    let ids: Vec<_> = names
        .iter()
        .map(|name| builder.add_string(name).unwrap())
        .collect();
    let len = builder
        .start_node("")
        .unwrap()
        .add_null(ids[0])
        .unwrap()
        .add_u32_array(ids[1], &[0x0102_0304, u32::MAX])
        .unwrap()
        .add_u64_array(ids[2], &[0x0102_0304_0506_0708, u64::MAX])
        .unwrap()
        .add_u64_list(ids[3], (1..=3).map(|value| value << 32))
        .unwrap()
        .add_str_array(ids[4], &["alpha", "", "omega"])
        .unwrap()
        .add_prop_array(ids[5], &[&[0xaa, 0], &[0x7f]])
        .unwrap()
        .add_u32_array(ids[6], &[])
        .unwrap()
        .end_node()
        .unwrap()
        .build(7)
        .unwrap();
    let bytes = &buffer.as_bytes()[..len];
    assert_eq!(Parser::read_total_size(&bytes[..40]).unwrap(), len);
    let parser = Parser::new(bytes).unwrap();
    assert_eq!(parser.total_size, len);
    assert_eq!(parser.boot_cpuid_phys, 7);
    assert_eq!(
        parser
            .memory_reservations()
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
        reservations
    );
    let root = parser.root().unwrap();
    assert_eq!(
        root.properties()
            .map(|prop| prop.unwrap().name)
            .collect::<Vec<_>>(),
        names
    );
    assert!(root.find_property("flag").unwrap().unwrap().data.is_empty());
    let property = root.find_property("u32s").unwrap().unwrap();
    assert_eq!(property.data, &[1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(property.read_u32(1).unwrap(), u32::MAX);
    assert!(property.read_u32(2).is_err());
    assert!(property.read_u64(usize::MAX).is_err());
    let property = root.find_property("u64s").unwrap().unwrap();
    assert_eq!(
        property.as_64_list().unwrap().collect::<Vec<_>>(),
        [0x0102_0304_0506_0708, u64::MAX]
    );
    assert_eq!(
        root.find_property("sequence")
            .unwrap()
            .unwrap()
            .as_64_list()
            .unwrap()
            .collect::<Vec<_>>(),
        [1u64 << 32, 2u64 << 32, 3u64 << 32]
    );
    assert_eq!(
        root.find_property("strings").unwrap().unwrap().data,
        b"alpha\0\0omega\0"
    );
    assert_eq!(
        root.find_property("binary").unwrap().unwrap().data,
        &[0xaa, 0, 0x7f]
    );
    assert_eq!(
        root.find_property("empty")
            .unwrap()
            .unwrap()
            .as_64_list()
            .unwrap()
            .count(),
        0
    );
    assert!(root.find_property("absent").unwrap().is_none());
}

// Test: Parse a tree containing NOP padding around properties, children and the root.
// Expected: Padding is invisible and properties/children retain their names and payloads.
#[test]
fn nop_padding_is_skipped_at_every_tree_boundary() {
    let blob = wire(
        &words(&[
            4,
            1,
            0,
            4,
            3,
            4,
            0,
            0x1234_5678,
            4,
            1,
            0x6300_0000,
            4,
            2,
            4,
            2,
            4,
            9,
        ]),
        b"p\0",
    );
    let parser = Parser::new(blob.as_bytes()).unwrap();
    let root = parser.root().unwrap();
    assert_eq!(
        root.find_property("p")
            .unwrap()
            .unwrap()
            .read_u32(0)
            .unwrap(),
        0x1234_5678
    );
    let children = root
        .children()
        .map(|node| node.unwrap().name)
        .collect::<Vec<_>>();
    assert_eq!(children, ["c"]);
    assert_eq!(root.properties().count(), 1);
}

// Test: Fill string/structure capacities exactly and exceed them by one byte or one token.
// Expected: Valid exact-fit trees parse; insufficient string, node-padding and final-token space return errors.
#[test]
fn builder_capacity_boundaries_return_out_of_space() {
    let mut buffer = [0u32; 64];
    let mut builder = Builder::new(BuilderConfig {
        blob_buffer: buffer.as_mut_bytes(),
        string_table_cap: 4,
        memory_reservations: &[],
    })
    .unwrap();
    assert_eq!(
        builder.add_string("abcd").unwrap_err(),
        BuildError::OutOfSpace
    );
    let id = builder.add_string("abc").unwrap();
    assert_eq!(builder.add_string("").unwrap_err(), BuildError::OutOfSpace);
    let len = builder
        .start_node("")
        .unwrap()
        .add_null(id)
        .unwrap()
        .end_node()
        .unwrap()
        .build(0)
        .unwrap();
    assert!(
        Parser::new(&buffer.as_bytes()[..len])
            .unwrap()
            .root()
            .unwrap()
            .find_property("abc")
            .unwrap()
            .unwrap()
            .data
            .is_empty()
    );

    // Header + reservation sentinel + string capacity is 60 bytes.
    let mut buffer = [0u32; 32];
    let builder = Builder::new(BuilderConfig {
        blob_buffer: &mut buffer.as_mut_bytes()[..65],
        string_table_cap: 4,
        memory_reservations: &[],
    })
    .unwrap();
    assert!(matches!(
        builder.start_node(""),
        Err(BuildError::OutOfSpace)
    ));
    let builder = Builder::new(BuilderConfig {
        blob_buffer: &mut buffer.as_mut_bytes()[..72],
        string_table_cap: 4,
        memory_reservations: &[],
    })
    .unwrap();
    assert_eq!(
        builder
            .start_node("")
            .unwrap()
            .end_node()
            .unwrap()
            .build(0)
            .unwrap_err(),
        BuildError::OutOfSpace
    );
}
