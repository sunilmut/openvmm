// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types and constants related to the UEFI spec.
//!
//! This crate is divided into 3 submodules:
//!
//! - `uefi`: types directly lifted from the official UEFI spec
//! - `hyperv`: types specific to the Hyper-V UEFI implementation
//! - `linux`: types specific to UEFI on Linux

#![expect(missing_docs)]
#![forbid(unsafe_code)]
#![no_std]

// TODO: find a nice way to create const `Ucs2LeSlice` instances, and use proper
// `const`ants instead of runtime methods...
#[cfg(feature = "std")]
macro_rules! defn_nvram_var {
    ($varname:ident = ($guid:expr, $name:literal)) => {
        #[expect(clippy::allow_attributes)]
        #[allow(non_snake_case)]
        pub fn $varname() -> (Guid, &'static ucs2::Ucs2LeSlice) {
            use ucs2::Ucs2LeSlice;
            use zerocopy::IntoBytes;

            (
                $guid,
                Ucs2LeSlice::from_slice_with_nul(wchar::wchz!(u16, $name).as_bytes()).unwrap(),
            )
        }
    };
}

pub mod hyperv;
pub mod linux;
pub mod uefi;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use crate::hyperv::common::EfiStatus64NoErrorBit;
    use crate::uefi::common::{EfiStatus, EfiStatus64};
    use crate::uefi::time::{EFI_TIME, EfiDaylight, EfiTimezone};
    use test_with_tracing::test;
    use zerocopy::{FromBytes, IntoBytes};

    // Test: Encode/decode full-width and legacy statuses, including warnings, unknown codes and unaligned wire input.
    // Expected: Full-width bytes preserve every bit; legacy encoding clears only bit 63 and decoding promotes every nonzero code to an error.
    #[test]
    fn status_wire_encodings_preserve_full_width_and_legacy_lossiness() {
        assert_eq!(EfiStatus::default(), EfiStatus::SUCCESS);
        for (raw, bytes, legacy_bytes, legacy_decoded) in [
            (0, [0; 8], [0; 8], 0),
            (
                5,
                [5, 0, 0, 0, 0, 0, 0, 0],
                [5, 0, 0, 0, 0, 0, 0, 0],
                0x8000_0000_0000_0005,
            ),
            (
                0x8000_0000_0000_0005,
                [5, 0, 0, 0, 0, 0, 0, 0x80],
                [5, 0, 0, 0, 0, 0, 0, 0],
                0x8000_0000_0000_0005,
            ),
            (
                0x8102_0304_0506_0708,
                [8, 7, 6, 5, 4, 3, 2, 0x81],
                [8, 7, 6, 5, 4, 3, 2, 1],
                0x8102_0304_0506_0708,
            ),
            (
                u64::MAX,
                [0xff; 8],
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
                u64::MAX,
            ),
            (
                0x8000_0000_0000_0000,
                [0, 0, 0, 0, 0, 0, 0, 0x80],
                [0; 8],
                0,
            ),
        ] {
            let status = EfiStatus(raw);
            let wire = EfiStatus64::from(status);
            assert_eq!(wire.as_bytes(), bytes);
            assert_eq!(EfiStatus::from(wire).0, raw);
            let mut unaligned = [0xa5; 9];
            unaligned[1..].copy_from_slice(&bytes);
            assert_eq!(
                EfiStatus::from(EfiStatus64::read_from_bytes(&unaligned[1..]).unwrap()).0,
                raw
            );
            let legacy = EfiStatus64NoErrorBit::from(status);
            assert_eq!(legacy.as_bytes(), legacy_bytes);
            assert_eq!(EfiStatus::from(legacy).0, legacy_decoded);
            unaligned[1..].copy_from_slice(&legacy_bytes);
            assert_eq!(
                EfiStatus::from(EfiStatus64NoErrorBit::read_from_bytes(&unaligned[1..]).unwrap()).0,
                legacy_decoded
            );
        }
    }

    // Test: Validate ordinary/unspecified timezones, out-of-range offsets, and each reserved daylight bit.
    // Expected: Valid interior offsets and the unspecified sentinel pass; out-of-range offsets and reserved bits are rejected.
    #[test]
    fn time_metadata_rejects_invalid_offsets_and_reserved_daylight_bits() {
        for timezone in [-1439, 0, 1439, 2047] {
            assert!(EfiTimezone(timezone).valid());
        }
        for timezone in [i16::MIN, -1441, 1441, 2046, 2048, i16::MAX] {
            assert!(!EfiTimezone(timezone).valid());
        }
        for raw in 0..=3 {
            assert!(EfiDaylight::from(raw).valid());
        }
        for bit in 2..8 {
            assert!(!EfiDaylight::from((1 << bit) | 3).valid());
        }
        assert_eq!(EFI_TIME::default().as_bytes(), [0; 16]);
        assert_eq!(EFI_TIME::ZEROED.as_bytes(), [0; 16]);
    }

    // Test: Check both documented inclusive timezone endpoints after passing interior and unspecified controls.
    // Expected: UTC offsets of -1440 and +1440 minutes are valid under UEFI section 8.3.
    #[test]
    #[ignore = "product bug: EfiTimezone::valid rejects inclusive UEFI offsets -1440 and +1440"]
    fn timezone_accepts_both_documented_inclusive_endpoints() {
        for timezone in [-1439, 0, 1439, 2047] {
            assert!(EfiTimezone(timezone).valid());
        }
        assert_eq!(
            [EfiTimezone(-1440).valid(), EfiTimezone(1440).valid()],
            [true, true]
        );
    }

    // Test: Format a fixed wall clock with UTC, unspecified zone and fractional seconds.
    // Expected: Output preserves local components, nine-digit nanoseconds and omits the unspecified zone.
    #[test]
    fn time_display_preserves_wall_clock_fraction_and_zone() {
        use std::string::ToString;
        let mut time = EFI_TIME {
            year: 2026,
            month: 2,
            day: 3,
            hour: 4,
            minute: 5,
            second: 6,
            ..EFI_TIME::ZEROED
        };
        assert_eq!(time.to_string(), "2026-02-03T04:05:06Z");
        time.nanosecond = 7;
        assert_eq!(time.to_string(), "2026-02-03T04:05:06.000000007Z");
        time.timezone = EfiTimezone(2047);
        assert_eq!(time.to_string(), "2026-02-03T04:05:06.000000007");
        time.nanosecond = 0;
        assert_eq!(time.to_string(), "2026-02-03T04:05:06");
    }

    // Test: Translate UEFI TimeZone into an ISO offset after verifying the UTC control.
    // Expected: Localtime = UTC - TimeZone, so a positive UEFI value yields a negative ISO offset and vice versa.
    #[test]
    #[ignore = "product bug: EFI_TIME display reverses the ISO sign of UEFI TimeZone"]
    fn time_display_translates_uefi_timezone_sign_to_iso_offset() {
        use std::string::ToString;
        let mut time = EFI_TIME {
            year: 2026,
            month: 2,
            day: 3,
            hour: 4,
            minute: 5,
            second: 6,
            ..EFI_TIME::ZEROED
        };
        assert_eq!(time.to_string(), "2026-02-03T04:05:06Z");
        time.timezone = EfiTimezone(345);
        let west = time.to_string();
        time.timezone = EfiTimezone(-210);
        let east = time.to_string();
        assert_eq!(
            (west.as_str(), east.as_str()),
            ("2026-02-03T04:05:06-05:45", "2026-02-03T04:05:06+03:30")
        );
    }

    // Test: Validate defined and reserved NVRAM attribute bits and decode grouped boot failure status values.
    // Expected: All eight defined attributes are accepted independently and together; reserved bits are rejected and grouping preserves unknown upper-word IDs.
    #[test]
    fn variable_attribute_masks_and_boot_groups_preserve_wire_meaning() {
        use crate::hyperv::boot_bios_log::BootDeviceStatus;
        use crate::uefi::nvram::{EFI_VARIABLE_AUTHENTICATION_2, EfiVariableAttributes};
        assert_eq!(u32::from(EfiVariableAttributes::DEFAULT_ATTRIBUTES), 7);
        assert_eq!(
            u32::from(EfiVariableAttributes::DEFAULT_ATTRIBUTES_VOLATILE),
            6
        );
        assert_eq!(
            u32::from(EfiVariableAttributes::DEFAULT_ATTRIBUTES_TIME_BASED_AUTH),
            0x27
        );
        for raw in [0, 1, 2, 4, 8, 16, 32, 64, 128, 255] {
            assert!(!EfiVariableAttributes::from(raw).contains_unsupported_bits());
        }
        for bit in 8..32 {
            assert!(EfiVariableAttributes::from((1 << bit) | 7).contains_unsupported_bits());
        }
        assert_eq!(BootDeviceStatus::default(), BootDeviceStatus::BOOT_PENDING);
        for (raw, group) in [
            (0, 0),
            (0x10007, 0x10000),
            (0x20003, 0x20000),
            (0x3000b, 0x30000),
            (0xabcd_1234, 0xabcd_0000),
        ] {
            assert_eq!(BootDeviceStatus(raw).get_boot_device_status_group(), group);
        }
        let auth = EFI_VARIABLE_AUTHENTICATION_2::DUMMY.as_bytes();
        assert_eq!(&auth[..16], &[0; 16]);
        assert_eq!(&auth[16..24], &[24, 0, 0, 0, 0, 2, 0xf1, 0x0e]);
        assert_eq!(
            crate::uefi::boot::EfiRtPropertiesTable::NONE_SUPPORTED.as_bytes(),
            [1, 0, 8, 0, 0, 0, 0, 0]
        );
    }

    // Test: Classify secure-boot policy by both vendor GUID and exact UCS-2 name, including same-name/different-vendor and case variants.
    // Expected: PK/KEK require the global vendor, all image-security variables are policy, and unrelated global/Hyper-V/Linux variables remain non-policy.
    #[cfg(feature = "std")]
    #[test]
    fn secure_boot_policy_identity_uses_vendor_and_exact_variable_name() {
        use crate::uefi::nvram::{is_secure_boot_policy_var, vars};
        for (vendor, name) in [vars::PK(), vars::KEK(), vars::DB(), vars::DBX()] {
            assert!(is_secure_boot_policy_var(vendor, name));
        }
        for (vendor, name) in [
            vars::SECURE_BOOT(),
            vars::SETUP_MODE(),
            vars::DBDEFAULT(),
            crate::hyperv::nvram::vars::SECURE_BOOT_ENABLE(),
            crate::hyperv::nvram::vars::CURRENT_POLICY(),
            crate::hyperv::nvram::vars::OS_LOADER_INDICATIONS(),
            crate::linux::nvram::vars::MOK_LIST(),
            crate::linux::nvram::vars::MOK_LISTX(),
        ] {
            assert!(!is_secure_boot_policy_var(vendor, name));
        }
        assert_eq!(vars::PK().1.as_bytes(), &[b'P', 0, b'K', 0, 0, 0]);
        assert!(!is_secure_boot_policy_var(guid::Guid::ZERO, vars::PK().1));
        let lower = ucs2::Ucs2LeSlice::from_slice_with_nul(&[b'p', 0, b'k', 0, 0, 0]).unwrap();
        assert!(!is_secure_boot_policy_var(vars::EFI_GLOBAL_VARIABLE, lower));
        assert!(is_secure_boot_policy_var(
            vars::IMAGE_SECURITY_DATABASE_GUID,
            lower
        ));
        assert!(!is_secure_boot_policy_var(
            vars::EFI_GLOBAL_VARIABLE,
            vars::DB().1
        ));
    }
}
