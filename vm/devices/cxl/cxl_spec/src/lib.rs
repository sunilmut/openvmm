// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CXL specification constants and register definitions.

#![no_std]
#![forbid(unsafe_code)]

pub mod component_registers;
pub mod pci_registers;

use bitfield_struct::bitfield;
use inspect::Inspect;

/// CFMWS window restrictions bitfield.
#[bitfield(u16)]
pub struct CfmwsWindowRestrictions {
    /// Bit 0: Device Coherent (HDM-D / HDM-DB when BI is set).
    pub device_coherent: bool,
    /// Bit 1: Host-only Coherent (HDM-H).
    pub host_only_coherent: bool,
    /// Bit 2: Window is configured for volatile memory.
    pub volatile: bool,
    /// Bit 3: Window is configured for persistent memory.
    pub persistent: bool,
    /// Bit 4: Fixed Device Configuration.
    pub fixed_device_configuration: bool,
    /// Bit 5: Back-Invalidate (BI) enabled.
    pub bi: bool,
    #[bits(10)]
    _reserved: u16,
}

impl CfmwsWindowRestrictions {
    /// No restrictions set.
    pub const NONE: Self = Self::new();

    /// Bit 0: Device Coherent (HDM-D / HDM-DB when BI is set).
    pub const DEVICE_COHERENT: Self = Self::new().with_device_coherent(true);
    /// Bit 1: Host-only Coherent (HDM-H).
    pub const HOST_ONLY_COHERENT: Self = Self::new().with_host_only_coherent(true);
    /// Bit 2: Window is configured for volatile memory.
    pub const VOLATILE: Self = Self::new().with_volatile(true);
    /// Bit 3: Window is configured for persistent memory.
    pub const PERSISTENT: Self = Self::new().with_persistent(true);
    /// Bit 4: Fixed Device Configuration.
    pub const FIXED_DEVICE_CONFIGURATION: Self = Self::new().with_fixed_device_configuration(true);
    /// Bit 5: Back-Invalidate (BI) enabled.
    pub const BI: Self = Self::new().with_bi(true);

    /// Mask of all currently defined CFMWS window restriction bits.
    pub const VALID_BITS_MASK: u16 = (1 << 6) - 1;

    /// Returns the raw 16-bit bitmap value.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Creates a restrictions value from a raw 16-bit bitmap.
    ///
    /// Returns `None` when any reserved bit (15:6) is set.
    pub const fn try_from_bits(bits: u16) -> Option<Self> {
        if Self::is_valid_bits(bits) {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns true if `bits` only contains currently defined restriction bits.
    pub const fn is_valid_bits(bits: u16) -> bool {
        (bits & !Self::VALID_BITS_MASK) == 0
    }

    /// True when all bits in `other` are present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.bits() & other.bits()) == other.bits()
    }
}

impl core::ops::BitOr for CfmwsWindowRestrictions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.bits() | rhs.bits())
    }
}

impl core::ops::BitOrAssign for CfmwsWindowRestrictions {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.bits() | rhs.bits());
    }
}

impl PartialEq for CfmwsWindowRestrictions {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for CfmwsWindowRestrictions {}

/// CFMWS Interleave Ways (IW) encoding values.
pub struct InterleaveWays;

impl InterleaveWays {
    /// 0h = 1-way (no interleaving).
    pub const WAY_1: u8 = 0x0;
    /// 1h = 2-way interleaving.
    pub const WAY_2: u8 = 0x1;
    /// 2h = 4-way interleaving.
    pub const WAY_4: u8 = 0x2;
    /// 3h = 8-way interleaving.
    pub const WAY_8: u8 = 0x3;
    /// 4h = 16-way interleaving (CXL.mem only).
    pub const WAY_16: u8 = 0x4;
    /// 8h = 3-way interleaving (CXL.mem only).
    pub const WAY_3: u8 = 0x8;
    /// 9h = 6-way interleaving (CXL.mem only).
    pub const WAY_6: u8 = 0x9;
    /// Ah = 12-way interleaving (CXL.mem only).
    pub const WAY_12: u8 = 0xA;
}

/// CFMWS Interleave Granularity (IG) encoding values.
pub struct InterleaveGranularity;

impl InterleaveGranularity {
    /// 0h = 256 bytes.
    pub const BYTES_256: u8 = 0x0;
    /// 1h = 512 bytes.
    pub const BYTES_512: u8 = 0x1;
    /// 2h = 1024 bytes (1 KiB).
    pub const BYTES_1024: u8 = 0x2;
    /// 3h = 2048 bytes (2 KiB).
    pub const BYTES_2048: u8 = 0x3;
    /// 4h = 4096 bytes (4 KiB).
    pub const BYTES_4096: u8 = 0x4;
    /// 5h = 8192 bytes (8 KiB).
    pub const BYTES_8192: u8 = 0x5;
    /// 6h = 16384 bytes (16 KiB).
    pub const BYTES_16384: u8 = 0x6;
}

/// CFMWS Interleave Arithmetic encoding values.
pub struct InterleaveArithmetic;

impl InterleaveArithmetic {
    /// 00h = Standard Modulo arithmetic.
    pub const STANDARD_MODULO: u8 = 0x00;
    /// 01h = Modulo arithmetic combined with XOR.
    pub const MODULO_XOR: u8 = 0x01;
}

/// CXL HDM decoder HPA alignment in bytes.
pub const CXL_HPA_ALIGNMENT: u64 = 256 * 1024 * 1024;

/// CXL Host Bridge Component Registers (CHBCR) aperture size in bytes.
pub const CXL_HOST_BRIDGE_COMPONENT_REGISTERS_SIZE_BYTES: u64 = 64 * 1024;

/// CXL Component Registers aperture size in bytes.
pub const CXL_COMPONENT_REGISTERS_SIZE_BYTES: u64 = 64 * 1024;

/// CXL Component Register Range: CXL.io reserved window start.
pub const CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_OFFSET: u64 = 0x0000;
/// CXL Component Register Range: CXL.io reserved window size.
pub const CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_SIZE_BYTES: u64 = 0x1000;

/// CXL Component Register Range: CXL.cachemem primary range start.
pub const CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_OFFSET: u64 = 0x1000;
/// CXL Component Register Range: CXL.cachemem primary range size.
pub const CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_SIZE_BYTES: u64 = 0x1000;

/// CXL Component Register Range: CXL.cachemem extended ranges start.
pub const CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_OFFSET: u64 = 0x2000;
/// CXL Component Register Range: CXL.cachemem extended ranges size.
pub const CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_SIZE_BYTES: u64 = 0xC000;

/// CXL Component Register Range: CXL RAB/MUX register block start.
pub const CXL_COMPONENT_REG_RANGE_RAB_MUX_OFFSET: u64 = 0xE000;
/// CXL Component Register Range: CXL RAB/MUX register block size.
pub const CXL_COMPONENT_REG_RANGE_RAB_MUX_SIZE_BYTES: u64 = 0x0400;

/// CXL.cachemem architectural register-directory region size (one 4-KiB page).
pub const CXL_CACHEMEM_REGION_SIZE_BYTES: u64 = 0x1000;

/// Offset of the CXL.cachemem capability-array header within a 4-KiB region.
pub const CXL_CACHEMEM_CAPABILITY_ARRAY_HEADER_OFFSET: u64 = 0x0000;

/// Offset of the first CXL.cachemem capability header entry within a 4-KiB region.
pub const CXL_CACHEMEM_CAPABILITY_ARRAY_FIRST_ENTRY_OFFSET: u64 = 0x0004;

/// Size of one CXL.cachemem capability header entry.
pub const CXL_CACHEMEM_CAPABILITY_ARRAY_ENTRY_SIZE_BYTES: u64 = 4;

/// Maximum `Array_Size` representable in the cachemem capability header.
pub const CXL_CACHEMEM_CAPABILITY_ARRAY_MAX_ENTRIES: usize = u8::MAX as usize;

/// Capability IDs in this inclusive range are disallowed in extended ranges.
pub const CXL_CACHEMEM_EXTENDED_FORBIDDEN_CAPABILITY_ID_MIN: u16 = 0x0001;

/// Capability IDs in this inclusive range are disallowed in extended ranges.
pub const CXL_CACHEMEM_EXTENDED_FORBIDDEN_CAPABILITY_ID_MAX: u16 = 0x000A;

/// CXL cache/mem capability header (offset 0x0 in each 4-KiB cachemem page).
pub struct CxlCacheMemCapabilityHeader;

impl CxlCacheMemCapabilityHeader {
    /// `CXL_Capability_ID` value for the header itself.
    pub const CAPABILITY_ID: u8 = 0x01;

    /// `CXL_Capability_Version` value for this header format.
    pub const CAPABILITY_VERSION: u8 = 0x01;

    /// `CXL_Cache_Mem_Version` value for this implementation.
    pub const CACHE_MEM_VERSION: u8 = 0x01;

    /// Encodes the header dword with the given capability entry count.
    ///
    /// Returns `None` if `array_size` exceeds the 8-bit `Array_Size` field.
    pub fn encode(array_size: usize) -> Option<u32> {
        let array_size = u8::try_from(array_size).ok()?;
        Some(
            u32::from(Self::CAPABILITY_ID)
                | (u32::from(Self::CAPABILITY_VERSION) << 16)
                | (u32::from(Self::CACHE_MEM_VERSION) << 20)
                | (u32::from(array_size) << 24),
        )
    }
}

/// One cache/mem capability-array entry dword (after the page header).
pub struct CxlCacheMemCapabilityArrayEntry;

impl CxlCacheMemCapabilityArrayEntry {
    /// Encodes one capability entry.
    ///
    /// - `capability_id` maps to bits 15:0
    /// - `capability_version` maps to bits 19:16
    /// - `pointer` is a byte offset in the page and maps as DW offset in bits 31:20
    ///
    /// Returns `None` when `capability_version` exceeds 4 bits, `pointer` is not
    /// dword-aligned, or pointer DW offset exceeds 12 bits.
    pub fn encode(capability_id: u16, capability_version: u8, pointer: u16) -> Option<u32> {
        if capability_version > 0x0f || !pointer.is_multiple_of(4) {
            return None;
        }

        let pointer_dw = u32::from(pointer >> 2);
        if pointer_dw > 0x0fff {
            return None;
        }

        Some(u32::from(capability_id) | (u32::from(capability_version) << 16) | (pointer_dw << 20))
    }
}

/// CXL Component Register Range: trailing reserved window start.
pub const CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_OFFSET: u64 = 0xE400;
/// CXL Component Register Range: trailing reserved window size.
pub const CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_SIZE_BYTES: u64 = 0x1C00;

/// CXL component register block type.
///
/// Each type is constrained to a fixed section of the 64-KiB CXL component
/// register aperture.
#[expect(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Inspect)]
pub enum CxlComponentRegisterType {
    /// CXL.cachemem primary register section.
    CacheMemRegister,
    /// CXL.cachemem extended register section.
    CacheMemExtendedRegister,
    /// CXL RAB/MUX register section.
    CxlArbMuxRegister,
}

impl CxlComponentRegisterType {
    /// Register type for the CXL.cachemem primary section.
    pub const CXL_CACHE_MEM_REGISTER: Self = Self::CacheMemRegister;

    /// Register type for the CXL.cachemem extended section.
    pub const CXL_CACHE_MEM_EXTENDED_REGISTER: Self = Self::CacheMemExtendedRegister;

    /// Register type for the CXL RAB/MUX section.
    pub const CXL_ARB_MUX_REGISTER: Self = Self::CxlArbMuxRegister;
}

/// CEDT CHBS structure type.
pub const CEDT_STRUCTURE_TYPE_CHBS: u8 = 0;

/// CEDT CFMWS structure type.
pub const CEDT_STRUCTURE_TYPE_CFMWS: u8 = 1;

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::CEDT_STRUCTURE_TYPE_CFMWS;
    use super::CEDT_STRUCTURE_TYPE_CHBS;
    use super::CXL_CACHEMEM_CAPABILITY_ARRAY_MAX_ENTRIES;
    use super::CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_OFFSET;
    use super::CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_SIZE_BYTES;
    use super::CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_OFFSET;
    use super::CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_SIZE_BYTES;
    use super::CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_OFFSET;
    use super::CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_SIZE_BYTES;
    use super::CXL_COMPONENT_REG_RANGE_RAB_MUX_OFFSET;
    use super::CXL_COMPONENT_REG_RANGE_RAB_MUX_SIZE_BYTES;
    use super::CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_OFFSET;
    use super::CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_SIZE_BYTES;
    use super::CXL_COMPONENT_REGISTERS_SIZE_BYTES;
    use super::CfmwsWindowRestrictions;
    use super::CxlCacheMemCapabilityArrayEntry;
    use super::CxlCacheMemCapabilityHeader;
    use super::CxlComponentRegisterType;
    use super::InterleaveArithmetic;
    use super::InterleaveGranularity;
    use super::InterleaveWays;

    #[test]
    fn cfmws_window_restriction_bits() {
        assert_eq!(CfmwsWindowRestrictions::DEVICE_COHERENT.bits(), 1 << 0);
        assert_eq!(CfmwsWindowRestrictions::HOST_ONLY_COHERENT.bits(), 1 << 1);
        assert_eq!(CfmwsWindowRestrictions::VOLATILE.bits(), 1 << 2);
        assert_eq!(CfmwsWindowRestrictions::PERSISTENT.bits(), 1 << 3);
        assert_eq!(
            CfmwsWindowRestrictions::FIXED_DEVICE_CONFIGURATION.bits(),
            1 << 4
        );
        assert_eq!(CfmwsWindowRestrictions::BI.bits(), 1 << 5);
    }

    #[test]
    fn cfmws_window_restriction_combine_and_contains() {
        let restrictions = CfmwsWindowRestrictions::DEVICE_COHERENT
            | CfmwsWindowRestrictions::VOLATILE
            | CfmwsWindowRestrictions::BI;

        assert!(restrictions.contains(CfmwsWindowRestrictions::DEVICE_COHERENT));
        assert!(restrictions.contains(CfmwsWindowRestrictions::VOLATILE));
        assert!(restrictions.contains(CfmwsWindowRestrictions::BI));
        assert!(!restrictions.contains(CfmwsWindowRestrictions::PERSISTENT));
    }

    #[test]
    fn cfmws_window_restriction_from_bits_checks_reserved_bits() {
        assert!(CfmwsWindowRestrictions::try_from_bits(0x003f).is_some());
        assert!(CfmwsWindowRestrictions::try_from_bits(0x0000).is_some());
        assert!(CfmwsWindowRestrictions::try_from_bits(0x0040).is_none());
        assert!(CfmwsWindowRestrictions::try_from_bits(0x8000).is_none());
    }

    #[test]
    fn cfmws_interleave_way_encodings() {
        assert_eq!(InterleaveWays::WAY_1, 0x0);
        assert_eq!(InterleaveWays::WAY_2, 0x1);
        assert_eq!(InterleaveWays::WAY_4, 0x2);
        assert_eq!(InterleaveWays::WAY_8, 0x3);
        assert_eq!(InterleaveWays::WAY_16, 0x4);
        assert_eq!(InterleaveWays::WAY_3, 0x8);
        assert_eq!(InterleaveWays::WAY_6, 0x9);
        assert_eq!(InterleaveWays::WAY_12, 0xA);
    }

    #[test]
    fn cfmws_interleave_granularity_encodings() {
        assert_eq!(InterleaveGranularity::BYTES_256, 0x0);
        assert_eq!(InterleaveGranularity::BYTES_512, 0x1);
        assert_eq!(InterleaveGranularity::BYTES_1024, 0x2);
        assert_eq!(InterleaveGranularity::BYTES_2048, 0x3);
        assert_eq!(InterleaveGranularity::BYTES_4096, 0x4);
        assert_eq!(InterleaveGranularity::BYTES_8192, 0x5);
        assert_eq!(InterleaveGranularity::BYTES_16384, 0x6);
    }

    #[test]
    fn cfmws_interleave_arithmetic_encodings() {
        assert_eq!(InterleaveArithmetic::STANDARD_MODULO, 0x00);
        assert_eq!(InterleaveArithmetic::MODULO_XOR, 0x01);
    }

    #[test]
    fn cedt_structure_type_encodings() {
        assert_eq!(CEDT_STRUCTURE_TYPE_CHBS, 0);
        assert_eq!(CEDT_STRUCTURE_TYPE_CFMWS, 1);
    }

    #[test]
    fn cxl_component_register_type_aliases() {
        assert_eq!(
            CxlComponentRegisterType::CXL_CACHE_MEM_REGISTER,
            CxlComponentRegisterType::CacheMemRegister
        );
        assert_eq!(
            CxlComponentRegisterType::CXL_CACHE_MEM_EXTENDED_REGISTER,
            CxlComponentRegisterType::CacheMemExtendedRegister
        );
        assert_eq!(
            CxlComponentRegisterType::CXL_ARB_MUX_REGISTER,
            CxlComponentRegisterType::CxlArbMuxRegister
        );
    }

    #[test]
    fn cxl_cachemem_capability_header_encoding() {
        let encoded = CxlCacheMemCapabilityHeader::encode(1).expect("valid header");
        assert_eq!(encoded, 0x0111_0001);
    }

    #[test]
    fn cxl_cachemem_capability_header_rejects_large_array_size() {
        assert!(
            CxlCacheMemCapabilityHeader::encode(CXL_CACHEMEM_CAPABILITY_ARRAY_MAX_ENTRIES + 1)
                .is_none()
        );
    }

    #[test]
    fn cxl_cachemem_capability_array_entry_encoding() {
        let encoded =
            CxlCacheMemCapabilityArrayEntry::encode(0x20, 1, 0x0008).expect("valid entry");
        assert_eq!(encoded, 0x0021_0020);
    }

    #[test]
    fn cxl_cachemem_capability_array_entry_rejects_invalid_fields() {
        assert!(CxlCacheMemCapabilityArrayEntry::encode(0x20, 0x10, 0x0008).is_none());
        assert!(CxlCacheMemCapabilityArrayEntry::encode(0x20, 1, 0x0002).is_none());
    }

    #[test]
    fn cxl_component_register_ranges_cover_full_aperture() {
        assert_eq!(CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_OFFSET, 0x0000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_OFFSET, 0x1000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_OFFSET, 0x2000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_RAB_MUX_OFFSET, 0xE000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_OFFSET, 0xE400);

        assert_eq!(CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_SIZE_BYTES, 0x1000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_SIZE_BYTES, 0x1000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_SIZE_BYTES, 0xC000);
        assert_eq!(CXL_COMPONENT_REG_RANGE_RAB_MUX_SIZE_BYTES, 0x0400);
        assert_eq!(CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_SIZE_BYTES, 0x1C00);

        let total = CXL_COMPONENT_REG_RANGE_CXL_IO_RESERVED_SIZE_BYTES
            + CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_SIZE_BYTES
            + CXL_COMPONENT_REG_RANGE_CACHEMEM_EXTENDED_SIZE_BYTES
            + CXL_COMPONENT_REG_RANGE_RAB_MUX_SIZE_BYTES
            + CXL_COMPONENT_REG_RANGE_TRAILING_RESERVED_SIZE_BYTES;
        assert_eq!(total, CXL_COMPONENT_REGISTERS_SIZE_BYTES);
    }

    // Test: Encode every defined HDM decoder count and reject unsupported counts, including native integer limits.
    // Expected: The capability count field represents 1, even counts through 16, then multiples of four through 32; other counts are rejected.
    #[test]
    fn hdm_decoder_count_accepts_only_defined_capability_codes() {
        use crate::component_registers::hdm_decoder::encode_decoder_count;

        let counts = [1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32];
        for count in 0..=40 {
            let expected = counts.iter().position(|&defined| defined == count);
            assert_eq!(encode_decoder_count(count), expected.map(|code| code as u8));
        }
        assert_eq!(encode_decoder_count(usize::MAX), None);
    }

    // Test: Change HDM global control and capability fields in registers whose neighboring and reserved bits are already set.
    // Expected: Writable control bits occupy bits 0 and 1, and decoder/target/coherency fields do not modify neighboring bits.
    #[test]
    fn hdm_register_fields_preserve_neighboring_and_reserved_bits() {
        use crate::component_registers::hdm_decoder as hdm;

        assert_eq!(hdm::CXL_HDM_DECODER_GLOBAL_CONTROL_WRITABLE_MASK, 3);
        for raw in [0, u32::MAX, 0xa5a5_5a5a] {
            for poison in [false, true] {
                for enable in [false, true] {
                    let control = hdm::CxlHdmDecoderGlobalControlRegister::from(raw)
                        .with_poison_on_decode_error_enable(poison)
                        .with_hdm_decoder_enable(enable);
                    assert_eq!(
                        control.into_bits(),
                        (raw & 0xffff_fffc) | u32::from(poison) | (u32::from(enable) << 1)
                    );
                    assert_eq!(control.poison_on_decode_error_enable(), poison);
                    assert_eq!(control.hdm_decoder_enable(), enable);
                }
            }
            let capability = hdm::CxlHdmDecoderCapabilityRegister::from(raw)
                .with_decoder_count(5)
                .with_target_count(12)
                .with_supported_coherency_modes(2);
            assert_eq!(capability.into_bits(), (raw & !0x0060_00ff) | 0x0040_00c5);
            assert_eq!(capability.decoder_count(), 5);
            assert_eq!(capability.target_count(), 12);
            assert_eq!(capability.supported_coherency_modes(), 2);
        }
    }

    // Test: Decode all raw CFMWS restriction words and combine every pair of valid restriction sets.
    // Expected: Reserved bits are rejected, union/assignment preserve exactly the requested bits, and containment requires every requested bit.
    #[test]
    fn cfmws_restrictions_preserve_complete_set_algebra() {
        for raw in 0..=u16::MAX {
            let parsed = CfmwsWindowRestrictions::try_from_bits(raw);
            assert_eq!(parsed.is_some(), raw < 64);
            assert_eq!(CfmwsWindowRestrictions::is_valid_bits(raw), raw < 64);
            if let Some(restrictions) = parsed {
                assert_eq!(restrictions.bits(), raw);
            }
        }
        for left in 0..64 {
            for right in 0..64 {
                let left_set = CfmwsWindowRestrictions::try_from_bits(left).unwrap();
                let right_set = CfmwsWindowRestrictions::try_from_bits(right).unwrap();
                let union = left_set | right_set;
                let mut assigned = left_set;
                assigned |= right_set;
                assert_eq!(union.bits(), left | right);
                assert_eq!(assigned.bits(), left | right);
                assert_eq!(assigned, union);
                assert_eq!(left_set == right_set, left == right);
                assert_eq!(left_set.contains(right_set), left & right == right);
            }
        }
    }

    // Test: Encode every defined HDM interleave and coherency mode for register consumers.
    // Expected: Granularity and coherency codes are sequential, while 3/6/12-way interleave uses the distinct 8/9/10 codes.
    #[test]
    fn hdm_interleave_and_coherency_wire_codes() {
        use crate::component_registers::hdm_decoder::CxlHdmDecoderInterleaveGranularity as Granularity;
        use crate::component_registers::hdm_decoder::CxlHdmDecoderInterleaveWays as Ways;
        use crate::component_registers::hdm_decoder::CxlHdmSupportedCoherencyModes as Coherency;

        for (mode, expected) in [
            (Granularity::Bytes256, 0),
            (Granularity::Bytes512, 1),
            (Granularity::Bytes1024, 2),
            (Granularity::Bytes2048, 3),
            (Granularity::Bytes4096, 4),
            (Granularity::Bytes8192, 5),
            (Granularity::Bytes16384, 6),
        ] {
            assert_eq!(mode.bits(), expected);
        }
        for (mode, expected) in [
            (Ways::Way1, 0),
            (Ways::Way2, 1),
            (Ways::Way4, 2),
            (Ways::Way8, 3),
            (Ways::Way16, 4),
            (Ways::Way3, 8),
            (Ways::Way6, 9),
            (Ways::Way12, 10),
        ] {
            assert_eq!(mode.bits(), expected);
        }
        for (mode, expected) in [
            (Coherency::Unknown, 0),
            (Coherency::DeviceCoherent, 1),
            (Coherency::HostOnlyCoherent, 2),
            (Coherency::HostOnlyOrDeviceCoherent, 3),
        ] {
            assert_eq!(mode.bits(), expected);
        }
    }

    // Test: Encode DVSEC media/class, interleave, timeouts, cache units and locator identifiers using their defined wire values.
    // Expected: Each semantic value produces its specified code, including CDAT, different timeout scales and vendor-specific locator code 255.
    #[test]
    fn dvsec_semantic_values_preserve_wire_encodings() {
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecCacheSizeUnit as Cache;
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecDesiredInterleave as Interleave;
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecMediaType as Media;
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecMemoryActiveTimeout as Active;
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecMemoryClass as Class;
        use crate::pci_registers::cxl_device_dvsec::CxlDeviceDvsecResetTimeout as Reset;
        use crate::pci_registers::register_locator_dvsec::CxlRegisterLocatorRegisterBir as Bir;
        use crate::pci_registers::register_locator_dvsec::CxlRegisterLocatorRegisterBlockIdentifier as Block;

        for (actual, expected) in [
            (Media::VolatileMemory.bits(), 0),
            (Media::NonVolatileMemory.bits(), 1),
            (Media::Cdat.bits(), 2),
            (Class::Memory.bits(), 0),
            (Class::Storage.bits(), 1),
            (Class::Cdat.bits(), 2),
            (Interleave::NoInterleave.bits(), 0),
            (Interleave::Granularity256Bytes.bits(), 1),
            (Interleave::Interleave4Kb.bits(), 2),
            (Interleave::Bytes512.bits(), 3),
            (Interleave::Bytes1024.bits(), 4),
            (Interleave::Bytes2048.bits(), 5),
            (Interleave::Bytes8192.bits(), 6),
            (Interleave::Bytes16384.bits(), 7),
            (Active::Seconds1.bits(), 0),
            (Active::Seconds4.bits(), 1),
            (Active::Seconds16.bits(), 2),
            (Active::Seconds64.bits(), 3),
            (Active::Seconds256.bits(), 4),
            (Reset::Milliseconds10.bits(), 0),
            (Reset::Milliseconds100.bits(), 1),
            (Reset::Seconds1.bits(), 2),
            (Reset::Seconds10.bits(), 3),
            (Reset::Seconds100.bits(), 4),
            (Cache::NotReported.bits(), 0),
            (Cache::Kib64.bits(), 1),
            (Cache::Mib1.bits(), 2),
            (Bir::BAR_10H.bits(), 0),
            (Bir::BAR_14H.bits(), 1),
            (Bir::BAR_18H.bits(), 2),
            (Bir::BAR_1CH.bits(), 3),
            (Bir::BAR_20H.bits(), 4),
            (Bir::BAR_24H.bits(), 5),
            (Block::EMPTY.bits(), 0),
            (Block::COMPONENT_REGISTERS.bits(), 1),
            (Block::BAR_VIRTUALIZATION_ACL_REGISTERS.bits(), 2),
            (Block::CXL_DEVICE_REGISTERS.bits(), 3),
            (Block::CPMU_REGISTERS.bits(), 4),
            (Block::CHMU_REGISTERS.bits(), 5),
            (Block::DESIGNATED_VENDOR_SPECIFIC.bits(), 255),
        ] {
            assert_eq!(actual, expected);
        }
    }

    // Test: Encode cache/mem capability pointers for consumers that add the extracted 12-bit field directly to the register-block base.
    // Expected: The field retains the byte offset rather than dividing it by four, with the capability ID and version unchanged.
    #[test]
    #[ignore = "product bug: cache/mem capability pointer encodes one quarter of the byte offset"]
    fn cachemem_pointer_is_a_byte_offset_for_register_consumers() {
        for (pointer, expected) in [
            (0x0000, 0x0003_0005),
            (0x0080, 0x0803_0005),
            (0x0400, 0x4003_0005),
            (0x0ffc, 0xffc3_0005),
        ] {
            let encoded = CxlCacheMemCapabilityArrayEntry::encode(5, 3, pointer).unwrap();
            assert_eq!(encoded, expected);
            assert_eq!(encoded >> 20, u32::from(pointer));
        }
    }
}
