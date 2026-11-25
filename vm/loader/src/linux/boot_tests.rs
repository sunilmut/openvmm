// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::paravisor::tests::RecordingImporter;
use std::io::Cursor;
use test_with_tracing::test;

// Test: Load a bzImage whose preferred address plus decompression region extends beyond its short payload.
// Expected: Only protected-mode payload reaches the kernel GPA, entry uses the 64-bit offset, and initrd starts after decompression memory.
#[test]
fn bzimage_payload_and_initrd_respect_the_decompression_region() {
    for with_initrd in [false, true] {
        let mut importer = RecordingImporter::<X86Register>::new();
        let mut kernel = Cursor::new(crate::bzimage::tests::make_test_bzimage());
        let mut initrd = Cursor::new(b"initrd-data".to_vec());
        let config = with_initrd.then_some(InitrdConfig {
            initrd: &mut initrd,
            size: 11,
            initrd_address: InitrdAddressType::AfterKernel,
        });
        let info =
            load_kernel_and_initrd_x64(&mut importer, &mut kernel, 0x400000, config).unwrap();
        assert_eq!(info.kernel.gpa, 0x400000);
        assert_eq!(info.kernel.size, HV_PAGE_SIZE);
        assert_eq!(info.kernel.entrypoint, 0x400200);
        assert!(info.bzimage_setup_header.is_some());
        let payload = importer
            .pages
            .iter()
            .find(|region| region.tag == "linux-kernel")
            .unwrap();
        assert_eq!(payload.base * HV_PAGE_SIZE, 0x400000);
        assert_eq!(payload.count, 1);
        assert_eq!(&payload.data[..1024], &[0xcc; 1024]);
        assert!(payload.data[1024..].iter().all(|byte| *byte == 0));
        if with_initrd {
            let initrd = info.initrd.unwrap();
            assert_eq!(initrd.gpa, 0x2000000);
            assert_eq!(initrd.size, 11);
            let imported = importer
                .pages
                .iter()
                .find(|region| region.tag == "linux-initrd")
                .unwrap();
            assert_eq!(imported.base * HV_PAGE_SIZE, initrd.gpa);
            assert_eq!(&imported.data[..11], b"initrd-data");
        } else {
            assert!(info.initrd.is_none());
        }
    }
}

// Test: Reject ARM64 flat images with bad magic, big-endian data, non-4K pages, low-memory-only placement, or truncated headers.
// Expected: Each unsupported format returns its exact flat-loader error before any guest page or register import.
#[test]
fn arm64_flat_image_validation_rejects_unsupported_header_contracts() {
    for case in 0..5 {
        let mut image = tests::test_arm64_image();
        let mut header = Aarch64ImageHeader::read_from_prefix(image.get_ref())
            .unwrap()
            .0;
        match case {
            0 => header.magic = *b"BAD!",
            1 => {
                header.flags = Aarch64ImageFlags::from(header.flags)
                    .with_big_endian(true)
                    .into()
            }
            2 => {
                header.flags = Aarch64ImageFlags::from(header.flags)
                    .with_page_size(Aarch64ImagePageSize::PAGE16_K)
                    .into()
            }
            3 => {
                header.flags = Aarch64ImageFlags::from(header.flags)
                    .with_any_start_address(false)
                    .into()
            }
            4 => {}
            _ => unreachable!(),
        }
        image.get_mut()[..size_of::<Aarch64ImageHeader>()].copy_from_slice(header.as_bytes());
        if case == 4 {
            image.get_mut().truncate(10);
        }
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        let error = load_kernel_and_initrd_arm64(&mut importer, &mut image, 0x600000, None, None)
            .unwrap_err();
        assert!(matches!(
            (case, error),
            (0, Error::FlatLoader(FlatLoaderError::BadImageMagic))
                | (1, Error::FlatLoader(FlatLoaderError::BigEndianKernelImage))
                | (
                    2,
                    Error::FlatLoader(FlatLoaderError::FourKibPageImageIsRequired)
                )
                | (3, Error::FlatLoader(FlatLoaderError::LowMemoryKernel))
                | (4, Error::FlatLoader(FlatLoaderError::ReadKernelImage))
        ));
        assert!(importer.pages.is_empty());
        assert!(importer.registers.is_empty());
    }
}

// Test: Load an ARM64 image with legacy zero image_size and an opaque device-tree payload.
// Expected: File size supplies the kernel extent, DTB is imported at the next page, and the reported range covers only its actual bytes.
#[test]
fn arm64_flat_image_uses_file_size_and_places_device_tree_after_kernel() {
    let mut image = tests::test_arm64_image();
    let mut header = Aarch64ImageHeader::read_from_prefix(image.get_ref())
        .unwrap()
        .0;
    header.image_size = 0;
    image.get_mut()[..size_of::<Aarch64ImageHeader>()].copy_from_slice(header.as_bytes());
    let blob = b"opaque-device-tree";
    let mut importer = RecordingImporter::<Aarch64Register>::new();
    let info = load_kernel_and_initrd_arm64(&mut importer, &mut image, 0x600000, None, Some(blob))
        .unwrap();
    assert_eq!(info.kernel.gpa, 0x600000);
    assert_eq!(info.kernel.size, HV_PAGE_SIZE);
    assert_eq!(info.kernel.entrypoint, 0x600000);
    assert_eq!(info.dtb, Some(0x601000..0x601000 + blob.len() as u64));
    let imported = importer
        .pages
        .iter()
        .find(|region| region.tag == "linux-device-tree")
        .unwrap();
    assert_eq!(imported.base * HV_PAGE_SIZE, 0x601000);
    assert_eq!(imported.count, 1);
    assert_eq!(imported.data, blob);
    assert!(matches!(imported.acceptance, BootPageAcceptance::Exclusive));
}

// Test: Set direct ARM64 Linux boot registers with and without a device-tree range.
// Expected: PC and optional X0 are exact, exception masks are set, MMU is disabled with caches enabled, and translation walks are disabled.
#[test]
fn arm64_direct_boot_registers_match_linux_entry_and_mmu_contract() {
    for with_dtb in [false, true] {
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        let info = LoadInfo {
            kernel: KernelInfo {
                gpa: 0x400000,
                size: 0x1000,
                entrypoint: 0x400080,
            },
            initrd: None,
            dtb: with_dtb.then_some(0x600000..0x601000),
            bzimage_setup_header: None,
        };
        set_direct_boot_registers_arm64(&mut importer, &info).unwrap();
        assert!(importer.registers.contains(&Aarch64Register::Pc(0x400080)));
        assert!(importer.registers.contains(&Aarch64Register::Cpsr(0x3c5)));
        assert!(importer.registers.contains(&Aarch64Register::Ttbr0El1(0)));
        assert!(importer.registers.contains(&Aarch64Register::Ttbr1El1(0)));
        assert!(importer.registers.contains(&Aarch64Register::VbarEl1(0)));
        assert_eq!(
            importer.registers.contains(&Aarch64Register::X0(0x600000)),
            with_dtb
        );
        for register in &importer.registers {
            match register {
                Aarch64Register::SctlrEl1(value) => assert_eq!(value & 0x1005, 0x1004),
                Aarch64Register::TcrEl1(value) => {
                    assert_eq!(value & ((1 << 7) | (1 << 23)), (1 << 7) | (1 << 23))
                }
                _ => {}
            }
        }
    }
}
