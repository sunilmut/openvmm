// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::paravisor::tests::RecordingImporter;
use test_with_tracing::test;

fn reset_registers() -> Vec<X86Register> {
    vec![
        X86Register::MtrrDefType(0xc00),
        X86Register::MtrrFix64k00000(0x0606060606060606),
        X86Register::MtrrFix16k80000(0x0606060606060606),
        X86Register::MtrrFix4kE0000(0x0606060606060606),
        X86Register::MtrrFix4kE8000(0x0606060606060606),
        X86Register::MtrrFix4kF0000(0x0606060606060606),
        X86Register::MtrrFix4kF8000(0x0606060606060606),
        X86Register::Cs(SegmentRegister {
            base: 0xf0000,
            limit: 0xffff,
            selector: 0xf000,
            attributes: 0x9b,
        }),
    ]
}

// Test: Load a BIOS with distinguishable lower/upper halves at minimum, ordinary, and 4-GiB RAM ceilings.
// Expected: The full image is placed below the ceiling, only its upper half is mirrored below 1 MiB, and reset/cache registers are exact.
#[test]
fn bios_full_image_and_reset_alias_preserve_distinct_payload_regions() {
    let mut image = vec![0x11; IMAGE_SIZE as usize];
    image[0x20000..].fill(0x22);
    for ceiling in [IMAGE_SIZE, 0x100000, 0x80000000, FOUR_GB] {
        let mut importer = RecordingImporter::<X86Register>::new();
        load(&mut importer, Some(&image), Some(ceiling)).unwrap();
        assert_eq!(importer.pages.len(), 2);
        let full = &importer.pages[0];
        assert_eq!(full.tag, "pcat-image");
        assert_eq!(full.base * HV_PAGE_SIZE, ceiling - IMAGE_SIZE);
        assert_eq!(full.count, 64);
        assert_eq!(full.data, image);
        assert!(matches!(full.acceptance, BootPageAcceptance::Exclusive));
        let alias = &importer.pages[1];
        assert_eq!(alias.tag, "pcat-top-pages");
        assert_eq!(alias.base * HV_PAGE_SIZE, 0xe0000);
        assert_eq!(alias.count, 32);
        assert_eq!(alias.data, vec![0x22; 0x20000]);
        assert!(matches!(alias.acceptance, BootPageAcceptance::Exclusive));
        assert_eq!(importer.registers, reset_registers());
    }
}

// Test: Initialize PCAT with firmware already supplied by RAM or ROM.
// Expected: No image imports occur and the same exact reset/cache register contract is still published.
#[test]
fn preloaded_bios_initializes_registers_without_importing_image_data() {
    let mut importer = RecordingImporter::<X86Register>::new();
    load(&mut importer, None, None).unwrap();
    assert!(importer.pages.is_empty());
    assert_eq!(importer.registers, reset_registers());
}

// Test: Supply incorrect BIOS lengths and absent, zero, unaligned, or over-4-GiB RAM ceilings.
// Expected: Specific input errors occur before any guest image or register mutation.
#[test]
fn invalid_bios_size_and_ram_ceiling_fail_before_imports() {
    let mut importer = RecordingImporter::<X86Register>::new();
    for length in [0, 1, IMAGE_SIZE as usize - 1, IMAGE_SIZE as usize + 1] {
        assert!(matches!(
            load(&mut importer, Some(&vec![0; length]), Some(FOUR_GB)),
            Err(Error::InvalidImageSize)
        ));
    }
    let image = vec![0; IMAGE_SIZE as usize];
    for ceiling in [None, Some(0), Some(1), Some(FOUR_GB + HV_PAGE_SIZE)] {
        assert!(matches!(
            load(&mut importer, Some(&image), ceiling),
            Err(Error::InvalidMaxRamBelow4gb)
        ));
    }
    assert!(importer.pages.is_empty());
    assert!(importer.registers.is_empty());
}

// IGNORED: The existing PCAT loader subtracts the BIOS size before rejecting
//       this undersized ceiling. Keep this regression until the product fix.
//
// Test: Supply a page-aligned RAM ceiling smaller than the BIOS image itself.
// Expected: The loader reports an invalid ceiling instead of panicking or wrapping the firmware address.
#[test]
#[ignore = "known product bug: a RAM ceiling below the BIOS size underflows the import page base"]
fn known_bug_too_small_ram_ceiling_is_rejected_without_underflow() {
    let mut importer = RecordingImporter::<X86Register>::new();
    let image = vec![0; IMAGE_SIZE as usize];
    assert!(matches!(
        load(&mut importer, Some(&image), Some(HV_PAGE_SIZE)),
        Err(Error::InvalidMaxRamBelow4gb)
    ));
    assert!(importer.pages.is_empty());
    assert!(importer.registers.is_empty());
}
