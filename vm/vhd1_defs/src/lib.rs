// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VHD1 file format definitions.
//!
//! Currently incomplete (missing defs for non-fixed disks).

#![expect(missing_docs)]
#![forbid(unsafe_code)]
#![no_std]

use self::packed_nums::*;
use guid::Guid;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

#[expect(non_camel_case_types)]
mod packed_nums {
    pub type u32_be = zerocopy::U32<zerocopy::BigEndian>;
    pub type u64_be = zerocopy::U64<zerocopy::BigEndian>;
}

#[repr(C)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct VhdFooter {
    pub cookie: u64_be,
    pub features: u32_be,
    pub file_format_version: u32_be,
    pub data_offset: u64_be,
    pub time_stamp: u32_be,
    pub creator_application: u32_be,
    pub creator_version: u32_be,
    pub creator_host_os: u32_be,
    pub original_size: u64_be,
    pub current_size: u64_be,
    pub disk_geometry: u32_be,
    pub disk_type: u32_be,
    pub checksum: u32_be,
    pub unique_id: Guid,
    pub saved_state: u8,
    pub reserved: [u8; 427],
}

impl VhdFooter {
    pub const LEN: u64 = 512;
    pub const ALIGNMENT: u64 = 512;

    pub const COOKIE_MAGIC: u64_be = u64_be::from_bytes(*b"conectix");
    pub const FEATURE_MASK: u32 = 0x2;
    pub const FILE_FORMAT_VERSION_MAGIC: u32 = 0x00010000;
    pub const FIXED_DATA_OFFSET: u64 = !0;
    pub const CREATOR_VERSION_MAGIC: u32 = 0x000a0000;
    pub const DISK_TYPE_FIXED: u32 = 2;

    pub fn new_fixed(size: u64, guid: Guid) -> Self {
        let mut footer = Self {
            cookie: Self::COOKIE_MAGIC,
            features: Self::FEATURE_MASK.into(),
            file_format_version: Self::FILE_FORMAT_VERSION_MAGIC.into(),
            data_offset: Self::FIXED_DATA_OFFSET.into(),
            creator_version: Self::CREATOR_VERSION_MAGIC.into(),
            original_size: size.into(),
            current_size: size.into(),
            disk_type: Self::DISK_TYPE_FIXED.into(),
            ..FromZeros::new_zeroed()
        };

        footer.unique_id = guid;
        footer.checksum = footer.compute_checksum().into();
        footer
    }

    pub fn compute_checksum(&self) -> u32 {
        !(self.as_bytes().iter().map(|b| *b as u32).sum::<u32>()
            - self
                .checksum
                .as_bytes()
                .iter()
                .map(|b| *b as u32)
                .sum::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::VhdFooter;
    use test_with_tracing::test;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    fn fixed_footer_bytes() -> [u8; 512] {
        let mut bytes = [0; 512];
        bytes[..8].copy_from_slice(b"conectix");
        bytes[8..16].copy_from_slice(&[0, 0, 0, 2, 0, 1, 0, 0]);
        bytes[16..24].fill(0xff);
        bytes[32..36].copy_from_slice(&[0, 10, 0, 0]);
        bytes[40..56].copy_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
            0,
        ]);
        bytes[60..68].copy_from_slice(&[0, 0, 0, 2, 0xff, 0xff, 0xe6, 0x13]);
        bytes[68..84].copy_from_slice(&[
            0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0,
        ]);
        bytes
    }

    // Test: Create fixed-disk metadata with a capacity above 32 bits and mixed-byte GUID.
    // Expected: The entire footer matches the big-endian on-disk fixture, including
    //       capacity, fixed-disk marker, GUID byte order, checksum and zero padding.
    #[test]
    fn fixed_footer_matches_disk_fixture() {
        let footer = VhdFooter::new_fixed(
            0x1234_5678_9abc_de00,
            guid::guid!("11223344-5566-7788-99aa-bbccddeeff00"),
        );
        assert_eq!(footer.as_bytes(), &fixed_footer_bytes());
    }

    // Test: Recalculate a parsed footer containing a stale checksum, then alter
    //       its saved-state byte and the last reserved byte.
    // Expected: The stored checksum is excluded, but both metadata changes are
    //       included; recalculation does not mutate the original on-disk bytes.
    #[test]
    fn checksum_excludes_itself_but_includes_entire_footer() {
        let mut bytes = fixed_footer_bytes();
        bytes[64..68].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let footer = VhdFooter::read_from_bytes(&bytes).unwrap();
        assert_eq!(footer.compute_checksum(), 0xffff_e613);
        assert_eq!(footer.as_bytes(), &bytes);
        bytes[84] = 1;
        bytes[511] = 255;
        let footer = VhdFooter::read_from_bytes(&bytes).unwrap();
        assert_eq!(footer.compute_checksum(), 0xffff_e513);
        assert_eq!(footer.as_bytes(), &bytes);
    }
}
