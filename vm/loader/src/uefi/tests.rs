// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::aarch64;
use super::{
    ConfigType, Error, IMAGE_NT_SIGNATURE, ImageNtHeaders32, ImageOptionalHeader32,
    SEC_FIRMWARE_VOLUME_OFFSET, firmware_volume, x86_64,
};
use crate::importer::Aarch64Register;
use crate::importer::{
    BootPageAcceptance, IgvmParameterType, IsolationType, StartupMemoryType, X86Register,
};
use crate::paravisor::tests::RecordingImporter;
use crate::paravisor::tests::assert_register;
use hvdef::HV_PAGE_SIZE;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

fn firmware() -> (Vec<u8>, u64) {
    let mut image = vec![0; x86_64::IMAGE_SIZE as usize];
    let volume = firmware_volume::FirmwareVolumeHeader {
        signature: firmware_volume::FV_SIGNATURE,
        header_length: size_of::<firmware_volume::FirmwareVolumeHeader>() as u16,
        fv_length: 0x1000,
        ..FromZeros::new_zeroed()
    };
    let file_size = size_of::<firmware_volume::FfsFileHeader>()
        + size_of::<firmware_volume::CommonSectionHeader>()
        + 512;
    let file = firmware_volume::FfsFileHeader {
        file_type: firmware_volume::FILETYPE_SECURITY_CORE,
        size: [
            file_size as u8,
            (file_size >> 8) as u8,
            (file_size >> 16) as u8,
        ],
        ..FromZeros::new_zeroed()
    };
    let section = firmware_volume::CommonSectionHeader {
        size: [4, 2, 0],
        section_type: firmware_volume::SECTION_PE32,
    };
    let pe = ImageNtHeaders32 {
        signature: IMAGE_NT_SIGNATURE,
        optional_header: ImageOptionalHeader32 {
            address_of_entry_point: 0x100,
            ..FromZeros::new_zeroed()
        },
        ..FromZeros::new_zeroed()
    };
    let volume_base = SEC_FIRMWARE_VOLUME_OFFSET as usize;
    let file_base = volume_base + size_of_val(&volume);
    let section_base = file_base + size_of_val(&file);
    let pe_base = section_base + size_of_val(&section);
    for (offset, data) in [
        (
            volume_base + std::mem::offset_of!(firmware_volume::FirmwareVolumeHeader, signature),
            volume.signature.to_le_bytes().as_slice(),
        ),
        (
            volume_base
                + std::mem::offset_of!(firmware_volume::FirmwareVolumeHeader, header_length),
            volume.header_length.to_le_bytes().as_slice(),
        ),
        (
            volume_base + std::mem::offset_of!(firmware_volume::FirmwareVolumeHeader, fv_length),
            volume.fv_length.to_le_bytes().as_slice(),
        ),
        (
            file_base + std::mem::offset_of!(firmware_volume::FfsFileHeader, file_type),
            [file.file_type].as_slice(),
        ),
        (
            file_base + std::mem::offset_of!(firmware_volume::FfsFileHeader, size),
            file.size.as_slice(),
        ),
        (
            section_base + std::mem::offset_of!(firmware_volume::CommonSectionHeader, section_type),
            [section.section_type].as_slice(),
        ),
        (
            section_base + std::mem::offset_of!(firmware_volume::CommonSectionHeader, size),
            section.size.as_slice(),
        ),
        (pe_base, pe.as_bytes()),
    ] {
        image[offset..offset + data.len()].copy_from_slice(data);
    }
    let entry = SEC_FIRMWARE_VOLUME_OFFSET
        + size_of_val(&volume) as u64
        + size_of_val(&file) as u64
        + size_of_val(&section) as u64
        + 0x100;
    (image, entry)
}

// Test: Load a firmware volume containing a SEC-core PE section without a config blob.
// Expected: Firmware bytes, page tables, CR3/RIP/RBP, and reported image/total extents match the x86 UEFI boot contract.
#[test]
fn x64_uefi_load_preserves_firmware_and_sets_sec_boot_registers() {
    let (image, entry) = firmware();
    let mut importer = RecordingImporter::<X86Register>::new();
    let info = x86_64::load(&mut importer, &image, ConfigType::None, true).unwrap();
    assert_eq!(info.firmware_base, 0x100000);
    assert_eq!(info.firmware_size, 0x600000);
    assert_eq!(info.total_size, 0x709000);
    let firmware = importer
        .pages
        .iter()
        .find(|region| region.tag == "uefi-image")
        .unwrap();
    assert_eq!(firmware.base, 0x100000 / HV_PAGE_SIZE);
    assert_eq!(firmware.count, 0x600000 / HV_PAGE_SIZE);
    assert_eq!(firmware.data, image);
    assert!(matches!(firmware.acceptance, BootPageAcceptance::Exclusive));
    let tables = importer
        .pages
        .iter()
        .find(|region| region.tag == "uefi-page-tables")
        .unwrap();
    assert_eq!(tables.base, 0x700000 / HV_PAGE_SIZE);
    assert_eq!(tables.count, 6);
    assert_eq!(tables.data.len(), 6 * HV_PAGE_SIZE as usize);
    assert_register(&importer.registers, X86Register::Rip(0x100000 + entry));
    assert_register(&importer.registers, X86Register::Cr3(0x700000));
    assert_register(&importer.registers, X86Register::Rbp(0x6e0000));
    assert!(importer.areas.is_empty());
    assert!(importer.parameters.is_empty());
}

// Test: Disable Hyper-V, supply wrong firmware sizes, or omit the required SEC firmware-volume signature.
// Expected: Specific load errors are returned before any guest pages, registers, or parameter areas are imported.
#[test]
fn x64_uefi_rejects_unsupported_environment_and_invalid_firmware_before_imports() {
    let mut importer = RecordingImporter::<X86Register>::new();
    assert!(matches!(
        x86_64::load(&mut importer, &[], ConfigType::None, false),
        Err(Error::HvRequired)
    ));
    for length in [0, 1, x86_64::IMAGE_SIZE as usize - 1] {
        assert!(matches!(
            x86_64::load(&mut importer, &vec![0; length], ConfigType::None, true),
            Err(Error::InvalidImageSize)
        ));
    }
    assert!(matches!(
        x86_64::load(
            &mut importer,
            &vec![0; x86_64::IMAGE_SIZE as usize],
            ConfigType::None,
            true
        ),
        Err(Error::NoSecEntryPoint)
    ));
    assert!(importer.pages.is_empty());
    assert!(importer.registers.is_empty());
    assert!(importer.areas.is_empty());
}

// Test: Load enlightened SNP firmware without configuring the shared-GPA boundary.
// Expected: The typed shared-boundary error is returned without publishing any guest state.
#[test]
fn x64_uefi_snp_requires_shared_gpa_boundary_before_importing() {
    let (image, _) = firmware();
    let mut importer = RecordingImporter::<X86Register>::new();
    importer.config.isolation_type = IsolationType::Snp;
    importer.config.paravisor_present = false;
    assert!(matches!(
        x86_64::load(&mut importer, &image, ConfigType::Igvm, true),
        Err(Error::InvalidSharedGpaBoundary)
    ));
    assert!(importer.pages.is_empty());
    assert!(importer.registers.is_empty());
    assert!(importer.areas.is_empty());
}

// Test: Load UEFI using ordinary and enlightened-SNP IGVM parameter areas.
// Expected: Header offsets resolve to exact parameter imports, extents match startup memory, and SNP special pages retain distinct ownership.
#[test]
fn x64_uefi_igvm_offsets_reference_parameter_areas_and_snp_special_pages() {
    let (image, _) = firmware();
    for snp in [false, true] {
        let mut importer = RecordingImporter::<X86Register>::new();
        if snp {
            importer.config.isolation_type = IsolationType::Snp;
            importer.config.paravisor_present = false;
            importer.config.shared_gpa_boundary_bits = Some(47);
        }
        let info = x86_64::load(&mut importer, &image, ConfigType::Igvm, true).unwrap();
        let base = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-config-base-page")
            .unwrap();
        assert_eq!(base.base * HV_PAGE_SIZE, 0x709000);
        let params = super::igvm::UEFI_IGVM_PARAMETER_INFO::read_from_prefix(&base.data)
            .unwrap()
            .0;
        assert_eq!(params.parameter_page_count, if snp { 90 } else { 83 });
        assert_eq!(
            info.total_size,
            0x709000 + u64::from(params.parameter_page_count) * HV_PAGE_SIZE
        );
        assert_eq!(importer.startup.len(), 1);
        assert_eq!(importer.startup[0].0, 0);
        assert_eq!(importer.startup[0].1 * HV_PAGE_SIZE, info.total_size);
        assert!(matches!(importer.startup[0].2, StartupMemoryType::Ram));
        for (tag, offset, count) in [
            ("uefi-loader-block", params.loader_block_offset, 1),
            (
                "uefi-command-line",
                params.command_line_offset,
                params.command_line_page_count,
            ),
            (
                "uefi-memory-map",
                params.memory_map_offset,
                params.memory_map_page_count,
            ),
            ("uefi-madt", params.madt_offset, params.madt_page_count),
            ("uefi-srat", params.srat_offset, params.srat_page_count),
        ] {
            let (index, area) = importer
                .areas
                .iter()
                .enumerate()
                .find(|(_, area)| area.tag == tag)
                .unwrap();
            assert_eq!(area.base, base.base + u64::from(offset));
            assert_eq!(area.count, count);
            assert!(offset + count <= params.parameter_page_count);
            let (_, byte_offset, kind) = importer
                .parameters
                .iter()
                .find(|(area, _, _)| *area as usize == index)
                .unwrap();
            assert_eq!(*byte_offset, 0);
            assert!(matches!(
                (tag, kind),
                ("uefi-loader-block", IgvmParameterType::VpCount)
                    | ("uefi-command-line", IgvmParameterType::CommandLine)
                    | ("uefi-memory-map", IgvmParameterType::MemoryMap)
                    | ("uefi-madt", IgvmParameterType::Madt)
                    | ("uefi-srat", IgvmParameterType::Srat)
            ));
        }
        let scratch = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-memory-map-scratch")
            .unwrap();
        assert_eq!(
            scratch.base,
            base.base + u64::from(params.uefi_memory_map_offset)
        );
        assert_eq!(scratch.count, u64::from(params.uefi_memory_map_page_count));
        assert!(matches!(
            scratch.acceptance,
            BootPageAcceptance::ExclusiveUnmeasured
        ));
        let shared = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-igvm-page-tables");
        let cpuid = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-cpuid-page");
        assert_eq!(shared.is_some(), snp);
        assert_eq!(cpuid.is_some(), snp);
        if snp {
            let shared = shared.unwrap();
            assert_eq!(shared.base, base.base + 1);
            assert_eq!(shared.count, 5);
            let cpuid = cpuid.unwrap();
            assert_eq!(cpuid.base, base.base + u64::from(params.cpuid_pages_offset));
            assert!(matches!(cpuid.acceptance, BootPageAcceptance::CpuidPage));
            assert_eq!(
                importer.vp_context_page,
                Some(params.vp_context_page_number)
            );
            assert_eq!(
                params.vp_context_page_number,
                base.base + u64::from(params.parameter_page_count)
            );
            assert_register(&importer.registers, X86Register::R12(0x709000));
        } else {
            assert_eq!(params.vp_context_page_number, 0xfffff);
            assert_eq!(importer.vp_context_page, None);
            assert_eq!(params.cpuid_pages_offset, 0);
        }
    }
}

// Test: Load ARM64 UEFI without a config blob for both Hyper-V and generic platforms.
// Expected: Firmware, stack, page tables, PC, boot arguments, and platform type match the firmware ABI.
#[test]
fn arm64_uefi_imports_firmware_stack_tables_and_platform_boot_arguments() {
    let image = vec![0x5a; aarch64::IMAGE_SIZE as usize];
    for hyperv in [false, true] {
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        let info = aarch64::load(&mut importer, &image, ConfigType::None, hyperv).unwrap();
        assert_eq!(info.firmware_base, 0);
        assert_eq!(info.firmware_size, 0x800000);
        assert_eq!(info.total_size, 0x824000);
        let firmware = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-image")
            .unwrap();
        assert_eq!(firmware.base, 0);
        assert_eq!(firmware.count, 0x800000 / HV_PAGE_SIZE);
        assert_eq!(firmware.data, image);
        assert!(matches!(firmware.acceptance, BootPageAcceptance::Exclusive));
        let stack = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-stack")
            .unwrap();
        assert_eq!(stack.base * HV_PAGE_SIZE, 0x800000);
        assert_eq!(stack.count, 32);
        assert!(stack.data.is_empty());
        let tables = importer
            .pages
            .iter()
            .find(|region| region.tag == "uefi-page-tables")
            .unwrap();
        assert_eq!(tables.base * HV_PAGE_SIZE, 0x820000);
        assert_eq!(tables.count, 4);
        assert_register(&importer.registers, Aarch64Register::Pc(0x1000));
        assert_register(&importer.registers, Aarch64Register::X0(0x1000));
        assert_register(&importer.registers, Aarch64Register::X1(0x820000));
        assert_register(&importer.registers, Aarch64Register::Ttbr0El1(0x820000));
        let platform = if hyperv {
            loader_defs::uefi::SecPlatformType::HYPERV
        } else {
            loader_defs::uefi::SecPlatformType::GENERIC
        };
        assert_register(&importer.registers, Aarch64Register::X2(platform.0));
    }
}

// Test: Load ARM64 UEFI with a wrong image length or the unsupported IGVM config style.
// Expected: Wrong lengths import nothing; IGVM is rejected before registers are published, preserving only already accepted fixed regions.
#[test]
fn arm64_uefi_rejects_wrong_image_size_and_unsupported_igvm_configuration() {
    for length in [0, 1, aarch64::IMAGE_SIZE as usize - 1] {
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        assert!(matches!(
            aarch64::load(&mut importer, &vec![0; length], ConfigType::None, true),
            Err(Error::InvalidImageSize)
        ));
        assert!(importer.pages.is_empty());
        assert!(importer.registers.is_empty());
    }
    let mut importer = RecordingImporter::<Aarch64Register>::new();
    let result = aarch64::load(
        &mut importer,
        &vec![0; aarch64::IMAGE_SIZE as usize],
        ConfigType::Igvm,
        true,
    );
    assert!(matches!(result, Err(Error::InvalidConfigType(_))));
    assert_eq!(
        importer
            .pages
            .iter()
            .map(|region| region.tag)
            .collect::<Vec<_>>(),
        ["uefi-image", "uefi-stack", "uefi-page-tables"]
    );
    assert!(importer.registers.is_empty());
}
