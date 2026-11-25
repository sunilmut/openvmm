// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::aarch64::*;
use crate::x64::*;
use crate::{Error, IdentityMapSize};
use test_with_tracing::test;
use zerocopy::{FromZeros, IntoBytes};

// Read the serialized descriptor at its hardware-defined physical address.
fn descriptor(bytes: &[u8], base: u64, table: u64, index: usize) -> u64 {
    let offset = usize::try_from(table - base).unwrap() + index * 8;
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

// Walk x64 hardware descriptors, including permissions inherited from directories.
fn x64_mapping(bytes: &[u8], base: u64, va: u64, root_level: u8) -> Option<(u64, u64, bool)> {
    let mut table = base;
    let mut writable = true;
    for level in (0..=root_level).rev() {
        let shift = 12 + u32::from(level) * 9;
        let entry = descriptor(bytes, base, table, ((va >> shift) & 511) as usize);
        if entry & 1 == 0 {
            return None;
        }
        writable &= entry & 2 != 0;
        let address = entry & 0x000f_ffff_ffff_f000;
        if level == 0 || entry & 0x80 != 0 {
            let size = 1u64 << shift;
            return Some(((address & !(size - 1)) | (va & (size - 1)), size, writable));
        }
        table = address;
    }
    panic!("page-table walk did not reach a leaf");
}

// Walk ARM64 hardware descriptors without depending on the allocator's table order.
fn arm_mapping(bytes: &[u8], base: u64, va: u64) -> Option<(u64, u64, u64)> {
    let mut table = base;
    for level in 0..4 {
        let shift = 39 - level * 9;
        let entry = descriptor(bytes, base, table, ((va >> shift) & 511) as usize);
        if entry & 1 == 0 {
            return None;
        }
        let address = entry & 0x0000_7fff_ffff_f000;
        if level == 3 || entry & 2 == 0 {
            let size = 1u64 << shift;
            return Some(((address & !(size - 1)) | (va & (size - 1)), size, entry));
        }
        table = address;
    }
    panic!("page-table walk did not reach a leaf");
}

// Test: Build adjacent read-only/writable pages, a hole, and a read-only 1GB leaf.
// Expected: Serialized tables translate mapped addresses and preserve effective permissions.
#[test]
fn x64_ranges_preserve_permissions_and_leave_holes_unmapped() {
    let base = 0x10_0000;
    let ranges = [
        MappedRange::new(0, 0x1000).read_only(),
        MappedRange::new(0x2000, 0x3000),
        MappedRange::new(0x4000_0000, 0x8000_0000).read_only(),
    ];
    let mut tables = vec![PageTable::new_zeroed(); 8];
    let mut output = vec![0; 8 * 4096];
    let bytes = PageTableBuilder::new(base, &mut tables, &mut output, &ranges)
        .unwrap()
        .build()
        .unwrap();
    for (va, page_size, writable) in [
        (0, 4096, false),
        (4095, 4096, false),
        (8192, 4096, true),
        (12287, 4096, true),
        (0x4000_0000, 0x4000_0000, false),
        (0x7fff_ffff, 0x4000_0000, false),
    ] {
        assert_eq!(
            x64_mapping(bytes, base, va, 3),
            Some((va, page_size, writable))
        );
    }
    for hole in [4096, 8191, 12288, 0x8000_0000] {
        assert_eq!(x64_mapping(bytes, base, hole, 3), None);
    }
}

// Test: Relocate each x64 descriptor kind and then clear it.
// Expected: Raw hardware flags survive relocation, and clearing removes presence and the address.
#[test]
fn x64_descriptor_relocation_preserves_leaf_and_permission_flags() {
    for (kind, initial_address, flags) in [
        (
            PageTableEntryType::Leaf1GbPage(0x4000_0000),
            0x4000_0000,
            0xe3,
        ),
        (PageTableEntryType::Leaf2MbPage(0x20_0000), 0x20_0000, 0xe3),
        (PageTableEntryType::Leaf4kPage(0x5000), 0x5000, 0x63),
        (PageTableEntryType::Pde(0x6000), 0x6000, 0x23),
    ] {
        let mut entry = PageTableEntry::new_zeroed();
        entry.set_entry(kind);
        assert_eq!(
            u64::from_le_bytes(entry.as_bytes().try_into().unwrap()),
            initial_address | flags
        );
        entry.set_addr(0x8000_0000);
        assert_eq!(
            u64::from_le_bytes(entry.as_bytes().try_into().unwrap()),
            0x8000_0000 | flags
        );
        assert_eq!(entry.gpa(), Some(0x8000_0000));
        assert_eq!(entry.get_addr(), 0x8000_0000);
        entry.clear();
        assert_eq!(entry.gpa(), None);
        assert_eq!(entry.as_bytes(), &[0; 8]);
    }
}

// Test: Build a linked 4GB identity map and a biased 8GB map whose root is a PDPT.
// Expected: Boundary addresses translate correctly, the extent is exact, and the PML4 link survives.
#[test]
fn x64_identity_maps_honor_links_bias_and_eight_gigabyte_extent() {
    let base = 0x10_0000;
    for (size, bias, extent, root_level, expected_tables) in [
        (IdentityMapSize::Size4Gb, 0, 0x1_0000_0000, 3, 6),
        (IdentityMapSize::Size8Gb, 0x4000_0000, 0x2_0000_0000, 2, 9),
    ] {
        let mut tables = vec![PageTable::new_zeroed(); 10];
        let mut output = vec![0; 10 * 4096];
        let builder = IdentityMapBuilder::new(base, size, &mut tables, &mut output)
            .unwrap()
            .with_address_bias(bias);
        let builder = if bias == 0 {
            builder.with_pml4e_link((0x20_0000, 1 << 39))
        } else {
            builder
        };
        let bytes = builder.build();
        assert_eq!(bytes.len(), expected_tables * 4096);
        for va in [0, 0x1f_ffff, 0xffff_ffff, extent - 1] {
            assert_eq!(
                x64_mapping(bytes, base, va, root_level),
                Some((va + bias, 0x20_0000, true))
            );
        }
        assert_eq!(x64_mapping(bytes, base, extent, root_level), None);
        if bias == 0 {
            assert_eq!(descriptor(bytes, base, base, 1), 0x20_0023);
        } else {
            assert_eq!(
                x64_mapping(bytes, base, 0x1_0000_0000, root_level),
                Some((0x1_4000_0000, 0x20_0000, true))
            );
        }
    }
}

// Test: Supply unsorted x64 mappings and mismatched identity-map buffers.
// Expected: The exact validation errors are returned before the caller's buffers are modified.
#[test]
fn x64_invalid_builder_inputs_leave_output_untouched() {
    let mut tables = vec![PageTable::new_zeroed(); 4];
    let mut output = vec![0x5a; 4 * 4096];
    let ranges = [
        MappedRange::new(0x2000, 0x3000),
        MappedRange::new(0, 0x1000),
    ];
    assert_eq!(
        PageTableBuilder::new(0, &mut tables, &mut output, &ranges).err(),
        Some(Error::UnsortedMappings)
    );
    assert_eq!(
        IdentityMapBuilder::new(
            0,
            IdentityMapSize::Size4Gb,
            &mut tables,
            &mut output[..4096]
        )
        .err(),
        Some(Error::BadBufferSize {
            bytes_buf: 4096,
            struct_buf: 4 * 4096
        })
    );
    assert!(output.iter().all(|&b| b == 0x5a));
}

// Test: Decode and re-encode an architectural MAIR value and all eight descriptor indices.
// Expected: Attribute bytes and index bit positions match the wire format, including first-match lookup.
#[test]
fn arm_memory_attributes_match_architectural_register_and_descriptor_encodings() {
    let register = MemoryAttributeIndirectionEl1::from(0xffbb_4400_ffbb_4400);
    let attributes = [
        MemoryAttributeEl1::Device_nGnRnE,
        MemoryAttributeEl1::Normal_NonCacheable,
        MemoryAttributeEl1::Normal_WriteThrough,
        MemoryAttributeEl1::Normal_WriteBack,
    ];
    assert_eq!(
        register.0,
        [
            attributes[0],
            attributes[1],
            attributes[2],
            attributes[3],
            attributes[0],
            attributes[1],
            attributes[2],
            attributes[3]
        ]
    );
    assert_eq!(u64::from(register), 0xffbb_4400_ffbb_4400);
    assert_eq!(
        register.index_of(MemoryAttributeEl1::Normal_WriteBack),
        Some(MemoryAttributeIndex::Index3)
    );
    assert_eq!(
        MemoryAttributeIndirectionEl1::default().index_of(MemoryAttributeEl1::Normal_WriteBack),
        None
    );
    for index in 0..8u64 {
        let entry = Aarch64PageBlockEntry::new().with_mair_idx(MemoryAttributeIndex::from(index));
        assert_eq!(u64::from(entry) & 0x1c, index << 2);
        assert_eq!(u64::from(entry.mair_idx()), index);
    }
}

// Test: Map ARM64 pages with all four execute policies.
// Expected: Hardware XN bits match each policy while translations and memory attributes remain valid.
#[test]
fn arm_execute_policies_are_encoded_independently() {
    let base = 0x10_0000;
    let mut output = vec![0; 4 * 4096];
    let policies = [
        (Arm64NoExecute::Off, 0),
        (Arm64NoExecute::UserOnly, 1 << 54),
        (Arm64NoExecute::PrivilegedOnly, 1 << 53),
        (Arm64NoExecute::Full, (1 << 53) | (1 << 54)),
    ];
    {
        let mut table = Arm64PageTableSpace::new(base as usize, &mut output).unwrap();
        for (index, (policy, _)) in policies.iter().enumerate() {
            table
                .map_pages(
                    0x20_0000 + index as u64 * 4096,
                    VirtualAddress::from(index as u64 * 4096),
                    1,
                    Arm64PageSize::Small,
                    MemoryAttributeIndex::Index5,
                    *policy,
                )
                .unwrap();
        }
    }
    for (index, (policy, expected_xn)) in policies.iter().enumerate() {
        let (pa, size, entry) = arm_mapping(&output, base, index as u64 * 4096).unwrap();
        assert_eq!((pa, size), (0x20_0000 + index as u64 * 4096, 4096));
        assert_eq!(entry & ((1 << 53) | (1 << 54)), *expected_xn);
        assert_eq!(entry & 0x1c, 5 << 2);
        assert_eq!(entry & 0x703, 0x703);
        let mut restricted = Arm64PageBlockEntry::from(entry | (1 << 53) | (1 << 54));
        restricted.set_xn(*policy);
        assert_eq!(u64::from(restricted), entry);
    }
}

// Test: Build an ARM64 identity map spanning a 1GB block and a final 2MB block.
// Expected: Both ends translate identically with write-back/UserOnly attributes and no extra mapping.
#[test]
fn arm_identity_builder_emits_mixed_block_sizes_and_requested_attributes() {
    let base = 0x10_0000;
    let start = 0x4000_0000;
    let size = 0x4020_0000;
    let mut output = vec![0xaa; 5 * 4096];
    let mair = MemoryAttributeIndirectionEl1::from(0xffbb_4400_ffbb_4400);
    let bytes = build_identity_page_tables_aarch64(base, start, size, mair, &mut output);
    assert_eq!(bytes.len(), 3 * 4096);
    for (va, page_size) in [
        (start, 0x4000_0000),
        (0x7fff_ffff, 0x4000_0000),
        (0x8000_0000, 0x20_0000),
        (start + size - 1, 0x20_0000),
    ] {
        let (pa, actual_size, entry) = arm_mapping(bytes, base, va).unwrap();
        assert_eq!((pa, actual_size), (va, page_size));
        assert_eq!(entry & 0x1c, 3 << 2);
        assert_eq!(entry & ((1 << 53) | (1 << 54)), 1 << 54);
    }
    assert_eq!(arm_mapping(bytes, base, start - 1), None);
    assert_eq!(arm_mapping(bytes, base, start + size), None);
    assert!(output[3 * 4096..].iter().all(|&b| b == 0xaa));
}

// Test: Reject malformed ARM64 table-space geometry.
// Expected: Misaligned roots, partial pages, and empty storage return distinct errors without writes.
#[test]
fn arm_invalid_table_storage_is_rejected_without_writing() {
    for (base, len, expected) in [
        (1, 4096, Arm64PageMapError::MisalignedPhysAddress),
        (0, 4095, Arm64PageMapError::InvalidMappingSize),
        (0, 0, Arm64PageMapError::EmptyMapping),
    ] {
        let mut output = vec![0x5a; len];
        assert_eq!(
            Arm64PageTableSpace::new(base, &mut output).err(),
            Some(expected)
        );
        assert!(output.iter().all(|&b| b == 0x5a));
    }
}

// Test: Reject invalid ARM64 mapping arguments, then make a valid mapping in the same space.
// Expected: Each error identifies the invalid input and rejected requests do not poison later maps.
#[test]
fn arm_mapping_validation_retains_errors_and_allows_retry() {
    let mut output = vec![0; 4 * 4096];
    {
        let mut table = Arm64PageTableSpace::new(0, &mut output).unwrap();
        for (pa, va, size, expected) in [
            (1, 0, 4096, Arm64PageMapError::MisalignedPhysAddress),
            (0, 0, 4095, Arm64PageMapError::InvalidMappingSize),
            (0, 0, 0, Arm64PageMapError::EmptyMapping),
            (0, 1, 4096, Arm64PageMapError::MisalignedVirtAddress),
            (
                0,
                0x0000_8000_0000_0000,
                4096,
                Arm64PageMapError::NonCanonicalVirtAddress,
            ),
        ] {
            assert_eq!(
                table.map_range(
                    pa,
                    VirtualAddress::from(va),
                    size,
                    MemoryAttributeIndex::Index0,
                    Arm64NoExecute::Off
                ),
                Err(expected)
            );
        }
        for (pa, va, count, size, expected) in [
            (
                0x1000,
                0,
                1,
                Arm64PageSize::Large,
                Arm64PageMapError::MisalignedPhysAddress,
            ),
            (
                0,
                0x1000,
                1,
                Arm64PageSize::Large,
                Arm64PageMapError::MisalignedVirtAddress,
            ),
            (
                0,
                1,
                1,
                Arm64PageSize::Small,
                Arm64PageMapError::MisalignedVirtAddress,
            ),
            (
                0,
                0x0000_8000_0000_0000,
                1,
                Arm64PageSize::Small,
                Arm64PageMapError::NonCanonicalVirtAddress,
            ),
            (
                0,
                0,
                0,
                Arm64PageSize::Small,
                Arm64PageMapError::EmptyMapping,
            ),
        ] {
            assert_eq!(
                table.map_pages(
                    pa,
                    VirtualAddress::from(va),
                    count,
                    size,
                    MemoryAttributeIndex::Index0,
                    Arm64NoExecute::Off
                ),
                Err(expected)
            );
        }
        table
            .map_pages(
                0x20_0000,
                VirtualAddress::from(0),
                1,
                Arm64PageSize::Small,
                MemoryAttributeIndex::Index0,
                Arm64NoExecute::Off,
            )
            .unwrap();
    }
    let (pa, size, _) = arm_mapping(&output, 0, 0).unwrap();
    assert_eq!((pa, size), (0x20_0000, 4096));
}

// Test: Try to replace an ARM64 block with a duplicate block and a smaller nested page.
// Expected: Both fail as already mapped, leaving the original translation intact.
#[test]
fn arm_existing_block_cannot_be_overwritten_or_split_implicitly() {
    let mut output = vec![0; 4 * 4096];
    {
        let mut table = Arm64PageTableSpace::new(0, &mut output).unwrap();
        table
            .map_pages(
                0x40_0000,
                VirtualAddress::from(0),
                1,
                Arm64PageSize::Large,
                MemoryAttributeIndex::Index0,
                Arm64NoExecute::Full,
            )
            .unwrap();
        for size in [Arm64PageSize::Large, Arm64PageSize::Small] {
            assert_eq!(
                table.map_pages(
                    0x80_0000,
                    VirtualAddress::from(0),
                    1,
                    size,
                    MemoryAttributeIndex::Index0,
                    Arm64NoExecute::Off
                ),
                Err(Arm64PageMapError::AlreadyMapped)
            );
        }
    }
    let (pa, size, entry) = arm_mapping(&output, 0, 0x1f_ffff).unwrap();
    assert_eq!((pa, size), (0x5f_ffff, 0x20_0000));
    assert_eq!(entry & ((1 << 53) | (1 << 54)), (1 << 53) | (1 << 54));
}

// Test: Map a read-only range with 4KB edges, 2MB shoulders, and a 1GB interior.
// Expected: Hardware walks select each correct leaf size, retain identity and
//       read-only permissions, and leave the bytes just outside the range unmapped.
#[test]
fn x64_mixed_leaf_sizes_preserve_exact_range_edges_and_permissions() {
    let base = 0x10_0000;
    let ranges = [MappedRange::new(0x3fdf_f000, 0x8020_1000).read_only()];
    let mut tables = vec![PageTable::new_zeroed(); 8];
    let mut output = vec![0; 8 * 4096];
    let bytes = PageTableBuilder::new(base, &mut tables, &mut output, &ranges)
        .unwrap()
        .build()
        .unwrap();
    for (va, page_size) in [
        (0x3fdf_f000, 4096),
        (0x3fdf_ffff, 4096),
        (0x3fe0_0000, 0x20_0000),
        (0x3fff_ffff, 0x20_0000),
        (0x4000_0000, 0x4000_0000),
        (0x7fff_ffff, 0x4000_0000),
        (0x8000_0000, 0x20_0000),
        (0x801f_ffff, 0x20_0000),
        (0x8020_0000, 4096),
        (0x8020_0fff, 4096),
    ] {
        assert_eq!(
            x64_mapping(bytes, base, va, 3),
            Some((va, page_size, false))
        );
    }
    for outside in [0x3fdf_efff, 0x8020_1000] {
        assert_eq!(x64_mapping(bytes, base, outside, 3), None);
    }
}
