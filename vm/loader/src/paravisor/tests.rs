// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::importer::{GuestArch, ParameterAreaIndex};
use std::io::Cursor;
use test_with_tracing::test;
use zerocopy::FromBytes;

pub(crate) struct ImportedPages {
    pub(crate) base: u64,
    pub(crate) count: u64,
    pub(crate) tag: &'static str,
    pub(crate) acceptance: BootPageAcceptance,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct ParameterArea {
    pub(crate) base: u64,
    pub(crate) count: u32,
    pub(crate) tag: String,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct RecordingImporter<Register: GuestArch> {
    pub(crate) config: IsolationConfig,
    pub(crate) pages: Vec<ImportedPages>,
    pub(crate) registers: Vec<Register>,
    pub(crate) areas: Vec<ParameterArea>,
    pub(crate) parameters: Vec<(u32, u32, IgvmParameterType)>,
    pub(crate) vp_context_page: Option<u64>,
    pub(crate) startup: Vec<(u64, u64, StartupMemoryType)>,
}

impl<Register: GuestArch> RecordingImporter<Register> {
    pub(crate) fn new() -> Self {
        Self {
            config: IsolationConfig {
                isolation_type: IsolationType::None,
                paravisor_present: true,
                shared_gpa_boundary_bits: None,
            },
            pages: Vec::new(),
            registers: Vec::new(),
            areas: Vec::new(),
            parameters: Vec::new(),
            vp_context_page: None,
            startup: Vec::new(),
        }
    }
}

impl<Register: GuestArch> ImageLoad<Register> for RecordingImporter<Register> {
    fn isolation_config(&self) -> IsolationConfig {
        IsolationConfig {
            isolation_type: match self.config.isolation_type {
                IsolationType::None => IsolationType::None,
                IsolationType::Vbs => IsolationType::Vbs,
                IsolationType::Snp => IsolationType::Snp,
                IsolationType::Tdx => IsolationType::Tdx,
            },
            paravisor_present: self.config.paravisor_present,
            shared_gpa_boundary_bits: self.config.shared_gpa_boundary_bits,
        }
    }

    fn create_parameter_area(
        &mut self,
        base: u64,
        count: u32,
        tag: &str,
    ) -> anyhow::Result<ParameterAreaIndex> {
        self.create_parameter_area_with_data(base, count, tag, &[])
    }

    fn create_parameter_area_with_data(
        &mut self,
        base: u64,
        count: u32,
        tag: &str,
        data: &[u8],
    ) -> anyhow::Result<ParameterAreaIndex> {
        let index = ParameterAreaIndex(self.areas.len() as u32);
        self.areas.push(ParameterArea {
            base,
            count,
            tag: tag.to_owned(),
            data: data.to_vec(),
        });
        Ok(index)
    }

    fn import_parameter(
        &mut self,
        area: ParameterAreaIndex,
        offset: u32,
        kind: IgvmParameterType,
    ) -> anyhow::Result<()> {
        self.parameters.push((area.0, offset, kind));
        Ok(())
    }

    fn import_pages(
        &mut self,
        base: u64,
        count: u64,
        tag: &'static str,
        acceptance: BootPageAcceptance,
        data: &[u8],
    ) -> anyhow::Result<()> {
        self.pages.push(ImportedPages {
            base,
            count,
            tag,
            acceptance,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn import_vp_register(&mut self, register: Register) -> anyhow::Result<()> {
        self.registers.push(register);
        Ok(())
    }

    fn verify_startup_memory_available(
        &mut self,
        base: u64,
        count: u64,
        kind: StartupMemoryType,
    ) -> anyhow::Result<()> {
        self.startup.push((base, count, kind));
        Ok(())
    }
    fn set_vp_context_page(&mut self, page: u64) -> anyhow::Result<()> {
        self.vp_context_page = Some(page);
        Ok(())
    }
    fn relocation_region(
        &mut self,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: bool,
        _: bool,
        _: u16,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn page_table_relocation(&mut self, _: u64, _: u64, _: u64, _: u16) -> anyhow::Result<()> {
        Ok(())
    }
    fn set_imported_regions_config_page(&mut self, _: u64) {}
}

fn no_vtl0() -> Vtl0Config<'static> {
    Vtl0Config {
        supports_pcat: false,
        supports_uefi: None,
        supports_linux: None,
    }
}

// Test: Advertise PCAT and a direct-Linux VTL0 payload with non-page-sized kernel/initrd lengths.
// Expected: Measured descriptors round extents up, preserve entrypoint/exact initrd length, and reference an exclusively imported NUL-terminated command line.
#[test]
fn x64_vtl0_linux_measured_metadata_preserves_payload_extents_and_command() {
    let command = std::ffi::CString::new("root=/dev/vda console=ttyS0").unwrap();
    for with_initrd in [false, true] {
        let mut importer = RecordingImporter::<X86Register>::new();
        let vtl0 = Vtl0Config {
            supports_pcat: true,
            supports_uefi: None,
            supports_linux: Some(Vtl0Linux {
                command_line: &command,
                load_info: crate::linux::LoadInfo {
                    kernel: KernelInfo {
                        gpa: 0x100000,
                        size: 0x2100,
                        entrypoint: 0x100080,
                    },
                    initrd: with_initrd.then_some(InitrdInfo {
                        gpa: 0x300000,
                        size: 0x1001,
                    }),
                    dtb: None,
                    bzimage_setup_header: None,
                },
            }),
        };
        load_openhcl_x64(
            &mut importer,
            &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
            &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
            None,
            CommandLineType::Static(""),
            None,
            Some(0x400000 / HV_PAGE_SIZE),
            0x10000,
            vtl0,
        )
        .unwrap();
        let measured = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-measured-config")
            .unwrap();
        let measured = ParavisorMeasuredVtl0Config::read_from_prefix(&measured.data)
            .unwrap()
            .0;
        assert!(measured.supported_vtl0.pcat_supported());
        assert!(measured.supported_vtl0.linux_direct_supported());
        assert!(!measured.supported_vtl0.uefi_supported());
        assert_eq!(measured.linux_info.kernel_region.base_page_number, 0x100);
        assert_eq!(measured.linux_info.kernel_region.page_count, 3);
        assert_eq!(measured.linux_info.kernel_entrypoint, 0x100080);
        assert_eq!(
            measured.linux_info.initrd_region.base_page_number,
            if with_initrd { 0x300 } else { 0 }
        );
        assert_eq!(
            measured.linux_info.initrd_region.page_count,
            if with_initrd { 2 } else { 0 }
        );
        assert_eq!(
            measured.linux_info.initrd_size,
            if with_initrd { 0x1001 } else { 0 }
        );
        let imported = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-vtl0-linux-command-line")
            .unwrap();
        assert_eq!(imported.data, command.as_bytes_with_nul());
        assert!(matches!(imported.acceptance, BootPageAcceptance::Exclusive));
        assert_eq!(
            measured.linux_info.command_line.base_page_number,
            imported.base
        );
        assert_eq!(measured.linux_info.command_line.page_count, 1);
        assert_eq!(imported.count, 1);
    }
}

// Test: Insert an optional sidecar ELF between the OpenHCL kernel and boot shim.
// Expected: Sidecar starts on the next 2-MiB boundary, the shim follows its full extent, and shim parameters reserve the exact sidecar size.
#[test]
fn x64_sidecar_alignment_and_shim_extent_follow_the_boot_abi() {
    let mut importer = RecordingImporter::<X86Register>::new();
    let mut sidecar = crate::linux::tests::test_elf(0x80, &[(0, HV_PAGE_SIZE)]);
    load_openhcl_x64(
        &mut importer,
        &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
        &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
        Some(&mut sidecar),
        CommandLineType::Static(""),
        None,
        Some(0x400000 / HV_PAGE_SIZE),
        0x10000,
        no_vtl0(),
    )
    .unwrap();
    let sidecar = importer
        .pages
        .iter()
        .find(|region| region.tag == "sidecar-kernel")
        .unwrap();
    assert_eq!(sidecar.base * HV_PAGE_SIZE, 0x800000);
    assert_eq!(sidecar.count, 1);
    assert!(matches!(sidecar.acceptance, BootPageAcceptance::Exclusive));
    assert!(sidecar.data.iter().all(|byte| *byte == 0));
    let shim = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-boot-shim")
        .unwrap();
    assert_eq!(shim.base * HV_PAGE_SIZE, 0x801000);
    assert!(importer.registers.contains(&X86Register::Rip(0x801000)));
    let params = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-shim-params")
        .unwrap();
    let params = ShimParamsRaw::read_from_prefix(&params.data).unwrap().0;
    assert_eq!(params.sidecar_size, HV_PAGE_SIZE);
    assert_eq!(params.kernel_entry_offset, -0x201000);
}

// Test: Load OpenHCL with an unaligned explicit memory base or a memory size that is not large-page aligned.
// Expected: The exact offending byte address/size is returned before any image, parameter, or register import.
#[test]
fn x64_unaligned_memory_is_rejected_before_guest_imports() {
    for (base, count, offending) in [
        (Some(1), 512, HV_PAGE_SIZE),
        (Some(512), 1, HV_PAGE_SIZE),
        (None, 513, 513 * HV_PAGE_SIZE),
    ] {
        let mut importer = RecordingImporter::<X86Register>::new();
        let result = load_openhcl_x64(
            &mut importer,
            &mut Cursor::new(Vec::<u8>::new()),
            &mut Cursor::new(Vec::<u8>::new()),
            None,
            CommandLineType::Static(""),
            None,
            base,
            count,
            no_vtl0(),
        );
        assert!(matches!(result, Err(Error::MemoryUnaligned(actual)) if actual == offending));
        assert!(importer.pages.is_empty());
        assert!(importer.registers.is_empty());
        assert!(importer.areas.is_empty());
        assert!(importer.parameters.is_empty());
    }
}

// Test: Load minimal kernel/shim ELF images into fixed-address OpenHCL memory with a static command line.
// Expected: Images and RIP use the boot ABI addresses, command bytes are preserved, and all parameter references fit guest memory.
#[test]
fn x64_fixed_load_places_images_boot_registers_command_and_parameter_areas() {
    let mut importer = RecordingImporter::<X86Register>::new();
    load_openhcl_x64(
        &mut importer,
        &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
        &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
        None,
        CommandLineType::Static("console=ttyS0"),
        None,
        Some(0x400000 / HV_PAGE_SIZE),
        0x10000,
        no_vtl0(),
    )
    .unwrap();
    for (tag, base) in [
        ("underhill-kernel", 0x600000),
        ("underhill-boot-shim", 0x601000),
    ] {
        let image = importer
            .pages
            .iter()
            .find(|region| region.tag == tag)
            .unwrap();
        assert_eq!(image.base * HV_PAGE_SIZE, base);
        assert_eq!(image.count, 1);
        assert!(matches!(image.acceptance, BootPageAcceptance::Exclusive));
        assert!(image.data.iter().all(|byte| *byte == 0));
    }
    assert!(
        importer
            .registers
            .iter()
            .any(|register| matches!(register, X86Register::Rip(0x601000)))
    );
    let command = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-command-line")
        .unwrap();
    assert_eq!(command.base * HV_PAGE_SIZE, 0x604000);
    assert_eq!(command.count, 1);
    let command = ParavisorCommandLine::read_from_prefix(&command.data)
        .unwrap()
        .0;
    assert_eq!(command.policy, CommandLinePolicy::STATIC);
    assert_eq!(command.static_command_line_len, 13);
    assert_eq!(&command.static_command_line[..13], b"console=ttyS0");
    assert!(
        command.static_command_line[13..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(!importer.areas.is_empty());
    let mut ranges = Vec::new();
    for area in &importer.areas {
        assert!(!area.tag.is_empty());
        assert!(area.count > 0);
        assert!(area.base >= 0x400000 / HV_PAGE_SIZE);
        assert!(area.base + u64::from(area.count) <= 0x400000 / HV_PAGE_SIZE + 0x10000);
        assert!(area.data.len() <= area.count as usize * HV_PAGE_SIZE as usize);
        ranges.push((area.base, area.base + u64::from(area.count)));
    }
    ranges.sort_unstable();
    assert!(ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0));
    assert!(!importer.parameters.is_empty());
    for (area, offset, _) in &importer.parameters {
        let area = &importer.areas[*area as usize];
        assert!(u64::from(*offset) < u64::from(area.count) * HV_PAGE_SIZE);
    }
}

// Test: Load an initrd with the standard CRC32 test vector and an appendable host command line.
// Expected: Imported bytes, initrd length/relative address/CRC, and command-line policy match the bootshim ABI.
#[test]
fn x64_initrd_bytes_crc_and_appendable_command_are_preserved() {
    let mut importer = RecordingImporter::<X86Register>::new();
    let mut initrd = Cursor::new(b"123456789".to_vec());
    load_openhcl_x64(
        &mut importer,
        &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
        &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
        None,
        CommandLineType::HostAppendable("root=/dev/vda"),
        Some((&mut initrd, 9)),
        Some(0x400000 / HV_PAGE_SIZE),
        0x10000,
        no_vtl0(),
    )
    .unwrap();
    let initrd = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-initrd")
        .unwrap();
    assert_eq!(initrd.base * HV_PAGE_SIZE, 0x602000);
    assert_eq!(initrd.count, 1);
    assert!(matches!(initrd.acceptance, BootPageAcceptance::Exclusive));
    assert_eq!(&initrd.data[..9], b"123456789");
    assert!(initrd.data[9..].iter().all(|byte| *byte == 0));
    let params = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-shim-params")
        .unwrap();
    let params = ShimParamsRaw::read_from_prefix(&params.data).unwrap().0;
    assert_eq!(params.initrd_size, 9);
    assert_eq!(params.initrd_offset, HV_PAGE_SIZE as i64);
    assert_eq!(params.initrd_crc, 0xcbf43926);
    assert_eq!(params.kernel_entry_offset, -(HV_PAGE_SIZE as i64));
    let command = importer
        .pages
        .iter()
        .find(|region| region.tag == "underhill-command-line")
        .unwrap();
    let command = ParavisorCommandLine::read_from_prefix(&command.data)
        .unwrap()
        .0;
    assert_eq!(command.policy, CommandLinePolicy::APPEND_CHOSEN);
    assert_eq!(command.static_command_line_len, 13);
    assert_eq!(&command.static_command_line[..13], b"root=/dev/vda");
}

// Test: Load the same minimal OpenHCL image for SNP and TDX isolation.
// Expected: Kernel pages are shared, boot metadata remains exclusive, bounce memory is reserved, and SNP alone emits special pages.
#[test]
fn x64_confidential_loads_use_shared_kernel_and_isolation_specific_pages() {
    for isolation in [IsolationType::Snp, IsolationType::Tdx] {
        let is_snp = isolation == IsolationType::Snp;
        let mut importer = RecordingImporter::<X86Register>::new();
        importer.config.isolation_type = isolation;
        importer.config.shared_gpa_boundary_bits = Some(47);
        load_openhcl_x64(
            &mut importer,
            &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
            &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
            None,
            CommandLineType::Static(""),
            None,
            Some(0x400000 / HV_PAGE_SIZE),
            0x10000,
            no_vtl0(),
        )
        .unwrap();
        let kernel = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-kernel")
            .unwrap();
        assert_eq!(kernel.base * HV_PAGE_SIZE, 0x800000);
        assert!(matches!(kernel.acceptance, BootPageAcceptance::Shared));
        for tag in [
            "underhill-boot-shim",
            "underhill-command-line",
            "underhill-shim-params",
            "underhill-page-tables",
        ] {
            let region = importer
                .pages
                .iter()
                .find(|region| region.tag == tag)
                .unwrap();
            assert!(matches!(region.acceptance, BootPageAcceptance::Exclusive));
        }
        let params = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-shim-params")
            .unwrap();
        let params = ShimParamsRaw::read_from_prefix(&params.data).unwrap().0;
        assert_eq!(params.bounce_buffer_size, 0x200000);
        assert_eq!(params.bounce_buffer_start, 0x600000 - 0x801000);
        assert_eq!(
            params.supported_isolation_type,
            if is_snp {
                loader_defs::shim::SupportedIsolationType::SNP
            } else {
                loader_defs::shim::SupportedIsolationType::TDX
            }
        );
        let secrets = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-snp-secrets-page");
        let cpuid = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-snp-cpuid-page");
        assert_eq!(secrets.is_some(), is_snp);
        assert_eq!(cpuid.is_some(), is_snp);
        if let (Some(secrets), Some(cpuid)) = (secrets, cpuid) {
            assert!(matches!(
                secrets.acceptance,
                BootPageAcceptance::SecretsPage
            ));
            assert!(matches!(cpuid.acceptance, BootPageAcceptance::CpuidPage));
            assert_eq!(cpuid.data.len(), size_of::<HV_PSP_CPUID_PAGE>());
        }
    }
}

// Test: Supply a command line one byte larger than the bootshim command-line region.
// Expected: The exact rejected size is returned without publishing command pages, parameter areas, or boot registers.
#[test]
fn x64_oversized_command_line_fails_before_boot_configuration_is_published() {
    let mut importer = RecordingImporter::<X86Register>::new();
    let command = "x".repeat(COMMAND_LINE_SIZE + 1);
    let result = load_openhcl_x64(
        &mut importer,
        &mut crate::linux::tests::test_elf(0x100000, &[(0x100000, HV_PAGE_SIZE)]),
        &mut crate::linux::tests::test_elf(0, &[(0, HV_PAGE_SIZE)]),
        None,
        CommandLineType::Static(&command),
        None,
        Some(0x400000 / HV_PAGE_SIZE),
        0x10000,
        no_vtl0(),
    );
    assert!(
        matches!(result, Err(Error::CommandLineSize(actual)) if actual == COMMAND_LINE_SIZE + 1)
    );
    assert!(
        importer
            .pages
            .iter()
            .all(|region| ["underhill-kernel", "underhill-boot-shim"].contains(&region.tag))
    );
    assert!(importer.areas.is_empty());
    assert!(importer.parameters.is_empty());
    assert!(importer.registers.is_empty());
}

fn arm_vtl0() -> Vtl0Config<'static> {
    Vtl0Config {
        supports_pcat: false,
        supports_uefi: Some((
            crate::uefi::LoadInfo {
                firmware_base: 0x100000,
                firmware_size: 0x10000,
                total_size: 0x20000,
            },
            vec![0xa6; HV_PAGE_SIZE as usize],
        )),
        supports_linux: None,
    }
}

// Test: Load ARM64 OpenHCL from a flat kernel and ELF shim, with and without an initrd and with VTL0 UEFI support.
// Expected: Imported kernel/context bytes, PC/X0, relative boot metadata, CRC, and measured UEFI descriptors match the ABI.
#[test]
fn arm64_load_preserves_kernel_initrd_boot_registers_and_uefi_context() {
    for with_initrd in [false, true] {
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        let mut kernel = crate::linux::tests::test_arm64_image();
        let expected_kernel = kernel.get_ref().clone();
        let mut initrd = Cursor::new(b"123456789".to_vec());
        let initrd_config = with_initrd.then_some((&mut initrd as &mut dyn ReadSeek, 9));
        load_openhcl_arm64(
            &mut importer,
            &mut kernel,
            &mut crate::linux::tests::test_elf_for_arch(
                object::elf::EM_AARCH64,
                0,
                &[(0, HV_PAGE_SIZE)],
            ),
            CommandLineType::Static("console=ttyAMA0"),
            initrd_config,
            Some(0x400000 / HV_PAGE_SIZE),
            0x10000,
            arm_vtl0(),
        )
        .unwrap();
        let kernel = importer
            .pages
            .iter()
            .find(|region| region.tag == "linux-kernel")
            .unwrap();
        assert_eq!(kernel.base * HV_PAGE_SIZE, 0x600000);
        assert_eq!(kernel.count, 1);
        assert_eq!(kernel.data, expected_kernel);
        assert!(matches!(kernel.acceptance, BootPageAcceptance::Exclusive));
        let shim_base = if with_initrd { 0x801000 } else { 0x601000 };
        assert!(importer.registers.iter().any(
            |register| matches!(register, Aarch64Register::Pc(address) if *address == shim_base)
        ));
        assert!(
            importer
                .registers
                .iter()
                .any(|register| matches!(register, Aarch64Register::X0(8192)))
        );
        let params = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-shim-params")
            .unwrap();
        let params = ShimParamsRaw::read_from_prefix(&params.data).unwrap().0;
        assert_eq!(params.initrd_size, if with_initrd { 9 } else { 0 });
        assert_eq!(params.initrd_crc, if with_initrd { 0xcbf43926 } else { 0 });
        if with_initrd {
            assert_eq!(params.initrd_offset, -(HV_PAGE_SIZE as i64));
            let initrd = importer
                .pages
                .iter()
                .find(|region| region.tag == "linux-initrd")
                .unwrap();
            assert_eq!(initrd.base * HV_PAGE_SIZE, 0x800000);
            assert_eq!(&initrd.data[..9], b"123456789");
        }
        assert_eq!(params.bounce_buffer_size, 0);
        assert_eq!(params.sidecar_size, 0);
        assert_eq!(params.memory_size, 0x10000 * HV_PAGE_SIZE);
        let context = importer
            .pages
            .iter()
            .find(|region| region.tag == "openhcl-uefi-vp-context")
            .unwrap();
        assert_eq!(context.count, 1);
        assert_eq!(context.data, vec![0xa6; HV_PAGE_SIZE as usize]);
        let measured = importer
            .pages
            .iter()
            .find(|region| region.tag == "underhill-measured-config")
            .unwrap();
        let measured = ParavisorMeasuredVtl0Config::read_from_prefix(&measured.data)
            .unwrap()
            .0;
        assert!(measured.supported_vtl0.uefi_supported());
        assert!(!measured.supported_vtl0.pcat_supported());
        assert_eq!(
            measured.uefi_info.firmware.base_page_number,
            0x100000 / HV_PAGE_SIZE
        );
        assert_eq!(
            measured.uefi_info.firmware.page_count,
            0x20000 / HV_PAGE_SIZE
        );
    }
}

// Test: Supply unaligned ARM64 OpenHCL base or size with otherwise supported VTL0 configuration.
// Expected: The exact memory-alignment error is returned without importing pages, parameters, or registers.
#[test]
fn arm64_unaligned_memory_is_rejected_before_guest_imports() {
    for (base, count, offending) in [
        (Some(1), 512, HV_PAGE_SIZE),
        (Some(512), 513, 513 * HV_PAGE_SIZE),
    ] {
        let mut importer = RecordingImporter::<Aarch64Register>::new();
        let result = load_openhcl_arm64(
            &mut importer,
            &mut Cursor::new(Vec::<u8>::new()),
            &mut Cursor::new(Vec::<u8>::new()),
            CommandLineType::Static(""),
            None,
            base,
            count,
            arm_vtl0(),
        );
        assert!(matches!(result, Err(Error::MemoryUnaligned(actual)) if actual == offending));
        assert!(importer.pages.is_empty());
        assert!(importer.areas.is_empty());
        assert!(importer.registers.is_empty());
    }
}
