// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::iort::*;
use std::vec::Vec;
use test_with_tracing::test;
use zerocopy::IntoBytes;

fn header(kind: u8, length: u16, revision: u8, id: u32, count: u32, offset: u32) -> Vec<u8> {
    let mut bytes = std::vec![kind];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.push(revision);
    for value in [id, count, offset] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

// Test: Build root-complex and ITS nodes with zero and multiple trailing IDs/mappings, varying ATS support.
// Expected: Serialized lengths/offsets/revisions, cache coherency, segment, address width and ID mapping fields match the ACPI IORT ABI, including reserved zeroes.
#[test]
fn root_complex_and_its_nodes_describe_trailing_arrays() {
    assert_eq!(
        Iort::new(4).as_bytes(),
        &[4, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0]
    );
    for count in [0, 2] {
        for ats in [false, true] {
            let root = IortPciRootComplex::new(0x44332211, 0x6655, count, ats);
            let mut expected = header(
                2,
                36 + count as u16 * 20,
                3,
                0x44332211,
                count,
                if count == 0 { 0 } else { 36 },
            );
            expected.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 3]);
            expected.extend_from_slice(&u32::from(ats).to_le_bytes());
            expected.extend_from_slice(&[0x55, 0x66, 0, 0, 64, 0, 0, 0]);
            assert_eq!(root.as_bytes(), expected);
        }
        let its = IortItsGroup::new(0x44332211, count);
        let mut expected = header(0, 20 + count as u16 * 4, 1, 0x44332211, 0, 0);
        expected.extend_from_slice(&count.to_le_bytes());
        assert_eq!(its.as_bytes(), expected);
    }
    let mapping = IortIdMapping::new(0x102, 0x304, 0x506, 0x708, 1);
    assert_eq!(
        mapping.as_bytes(),
        &[2, 1, 0, 0, 4, 3, 0, 0, 6, 5, 0, 0, 8, 7, 0, 0, 1, 0, 0, 0]
    );
}

// Test: Serialize SMMUv3 nodes with no mappings and an explicit device-ID mapping index.
// Expected: COHACC is always set; DEVICEID_VALID is conditional, the mapping offset/length includes trailing entries, and all address/interrupt fields retain exact little-endian values.
#[test]
fn smmu_nodes_encode_mapping_flags_and_interrupts() {
    for count in [0, 2] {
        let node =
            IortSmmuV3::new_with_device_id_mapping(7, 0x8877665544332211, count, 0x1122, 0x3344, 1);
        let mut expected = header(
            4,
            68 + count as u16 * 20,
            5,
            7,
            count,
            if count == 0 { 0 } else { 68 },
        );
        expected.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
        expected.extend_from_slice(&(if count == 0 { 1u32 } else { 17u32 }).to_le_bytes());
        expected.extend_from_slice(&[0; 16]);
        for value in [0x1122u32, 0, 0x3344, 0, 0, 1] {
            expected.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(node.as_bytes(), expected);
        let default = IortSmmuV3::new(7, 0x8877665544332211, count, 0x1122, 0x3344);
        expected[64..68].copy_from_slice(&[0; 4]);
        assert_eq!(default.as_bytes(), expected);
    }
}

// Test: Assemble RMR nodes with absent/present mappings and descriptors followed by the corresponding arrays.
// Expected: Header lengths cover the whole node, mappings precede descriptors at the advertised offsets, and descriptor address/length/reserved bytes are exact.
#[test]
fn reserved_memory_nodes_locate_mappings_before_descriptors() {
    for count in [0, 2] {
        for ranges in [0, 2] {
            let node = IortRmr::new(9, 3, ranges, count);
            let mut expected = header(
                6,
                28 + 20 * (count + ranges) as u16,
                3,
                9,
                count,
                if count == 0 { 0 } else { 28 },
            );
            for value in [3, ranges, if ranges == 0 { 0 } else { 28 + 20 * count }] {
                expected.extend_from_slice(&value.to_le_bytes());
            }
            assert_eq!(node.as_bytes(), expected);
            let mut wire = node.as_bytes().to_vec();
            for _ in 0..count {
                wire.extend_from_slice(IortIdMapping::new(1, 2, 3, 48, 0).as_bytes());
            }
            for _ in 0..ranges {
                wire.extend_from_slice(
                    IortRmrDescriptor::new(0x8877665544332211, 0x123456789).as_bytes(),
                );
            }
            assert_eq!(wire.len(), 28 + 20 * (count + ranges) as usize);
            if ranges > 0 {
                let offset = (28 + 20 * count) as usize;
                assert_eq!(
                    &wire[offset..offset + 20],
                    &[
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x89, 0x67, 0x45, 0x23, 1,
                        0, 0, 0, 0, 0, 0, 0
                    ]
                );
            }
        }
    }
}
