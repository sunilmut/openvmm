// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Decode an independently laid-out file table and update typed file IDs
//       at the beginning, a normal NVRAM slot and the final reserved slot.
// Expected: Metadata and authenticated-encryption fields have their disk ABI
//       offsets; typed mutations preserve every neighboring entry and byte.
#[test]
fn file_table_disk_offsets_and_typed_updates() {
    let mut image = [0x93; 4096];
    for (slot, offset) in [(0, 0x1234_u32), (3, 0x5678), (63, 0x9abc)] {
        let start = slot * 64;
        image[start..start + 4].copy_from_slice(&offset.to_le_bytes());
        image[start + 4..start + 8].copy_from_slice(&0x2345_u32.to_le_bytes());
        image[start + 8..start + 16].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
        image[start + 44..start + 48].copy_from_slice(&0x8000_0003_u32.to_le_bytes());
    }
    let mut table = VmgsFileTable::read_from_bytes(&image).unwrap();
    for (id, offset) in [
        (FileId::FILE_TABLE, 0x1234),
        (FileId::TPM_NVRAM, 0x5678),
        (FileId::EXTENDED_FILE_TABLE, 0x9abc),
    ] {
        let entries: &[VmgsFileEntry] = &table.entries;
        assert_eq!(entries[id].offset, offset);
        assert_eq!(entries[id].allocation_size, 0x2345);
        assert_eq!(entries[id].valid_data_size, 0x0123_4567_89ab_cdef);
        assert_eq!(entries[id].nonce, [0x93; 12]);
        assert_eq!(entries[id].authentication_tag, [0x93; 16]);
        assert!(entries[id].attributes.encrypted());
        assert!(entries[id].attributes.authenticated());
        let entries: &mut [VmgsFileEntry] = &mut table.entries;
        entries[id].valid_data_size = 0x1122_3344_5566_7788;
        let start = id.0 as usize * 64 + 8;
        image[start..start + 8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
    }
    assert_eq!(table.as_bytes(), image);
}

// Test: Load extended entries with distinct opaque keys and reserved attribute
//       bits, then replace only the last slot's key through a typed file ID.
// Expected: All key bytes and unknown attributes round-trip without changing
//       the preceding slot, reserved bytes or any unrelated disk content.
#[test]
fn extended_table_preserves_opaque_keys_and_unknown_attributes() {
    let mut image = [0x71; 4096];
    image[63 * 64..63 * 64 + 4].copy_from_slice(&0x8000_0001_u32.to_le_bytes());
    image[63 * 64 + 4..63 * 64 + 36].fill(0xa6);
    let mut table = VmgsExtendedFileTable::read_from_bytes(&image).unwrap();
    let entries: &[VmgsExtendedFileEntry] = &table.entries;
    assert_eq!(
        entries[FileId::EXTENDED_FILE_TABLE].encryption_key,
        [0xa6; 32]
    );
    assert_eq!(entries[FileId::TPM_NVRAM].encryption_key, [0x71; 32]);
    assert!(entries[FileId::EXTENDED_FILE_TABLE].attributes.encrypted());
    assert!(
        !entries[FileId::EXTENDED_FILE_TABLE]
            .attributes
            .authenticated()
    );

    let entries: &mut [VmgsExtendedFileEntry] = &mut table.entries;
    entries[FileId::EXTENDED_FILE_TABLE].encryption_key = [0x28; 32];
    image[63 * 64 + 4..63 * 64 + 36].fill(0x28);
    assert_eq!(table.as_bytes(), image);
}

// Test: Decode the complete V3 header from independently positioned fields,
//       including both key slots and a future unknown algorithm identifier.
// Expected: Scalar widths, key/nonce/tag ordering and forward-compatible
//       markers survive byte-exact round-trip; changing sequence is isolated.
#[test]
fn header_key_slots_and_future_identifiers_round_trip() {
    let mut image = [0x4b; 168];
    image[..8].copy_from_slice(b"GUESTRTS");
    image[8..12].copy_from_slice(&0x0003_0000_u32.to_le_bytes());
    image[12..16].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    image[16..20].copy_from_slice(&0x89ab_cdef_u32.to_le_bytes());
    image[20..24].copy_from_slice(&168_u32.to_le_bytes());
    image[24..28].copy_from_slice(&9_u32.to_le_bytes());
    image[28..32].copy_from_slice(&1_u32.to_le_bytes());
    image[32..34].copy_from_slice(&0x1234_u16.to_le_bytes());
    image[34..36].copy_from_slice(&0x8001_u16.to_le_bytes());
    for (start, value) in [(36, 0x12_u8), (100, 0x67)] {
        image[start..start + 12].fill(value);
        image[start + 16..start + 32].fill(value + 1);
        image[start + 32..start + 64].fill(value + 2);
    }
    let mut header = VmgsHeader::read_from_bytes(&image).unwrap();
    assert_eq!(header.signature.to_le_bytes(), *b"GUESTRTS");
    assert_eq!(header.version, 0x0003_0000);
    assert_eq!(header.checksum, 0x1234_5678);
    assert_eq!(header.sequence, 0x89ab_cdef);
    assert_eq!(header.header_size, 168);
    assert_eq!(header.file_table_offset, 9);
    assert_eq!(header.file_table_size, 1);
    assert_eq!(header.encryption_algorithm.0, 0x1234);
    assert!(header.markers.reprovisioned());
    for (key, value) in header.metadata_keys.iter().zip([0x12, 0x67]) {
        assert_eq!(key.nonce, [value; 12]);
        assert_eq!(key.authentication_tag, [value + 1; 16]);
        assert_eq!(key.encryption_key, [value + 2; 32]);
        assert_eq!(key.reserved, 0x4b4b_4b4b);
    }
    assert_eq!(header.as_bytes(), image);
    header.sequence = 7;
    image[16..20].copy_from_slice(&7_u32.to_le_bytes());
    assert_eq!(header.as_bytes(), image);
}
