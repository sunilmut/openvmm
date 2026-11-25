// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vm_topology::processor::TopologyBuilder;
use vm_topology::processor::x86::X86VpInfo;

mod register_tests;

// Use a deterministic CPUID model, not the host CPU or a hypervisor partition.
fn x86_caps() -> (virt::x86::X86PartitionCapabilities, X86VpInfo) {
    let topology = TopologyBuilder::new_x86().build(1).unwrap();
    let caps =
        virt::x86::X86PartitionCapabilities::from_cpuid(&topology, &mut |leaf, _| match leaf {
            0 => [1, 0, 0, 0],
            1 => [0, 0, 1 << 21, 0],
            _ => [0; 4],
        })
        .unwrap();
    (caps, topology.vps_arch().next().unwrap())
}

fn layout() -> MemoryLayout {
    MemoryLayout::new(0x10000, &[], &[], &[], None).unwrap()
}

// Test: Import data spanning two pages into prefilled memory.
// Expected: Data is copied exactly, the entire unused tail is zeroed and neighboring pages remain untouched.
#[test]
fn import_pages_writes_data_zeroes_tail_and_preserves_neighbors() {
    let memory = GuestMemory::allocate(0x10000);
    memory.fill_at(0, 0xa5, 0x10000).unwrap();
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(memory.clone(), &layout, Vtl::Vtl0);
    let data = vec![0x73; HV_PAGE_SIZE as usize + 3];
    loader
        .import_pages(1, 2, "payload", BootPageAcceptance::Exclusive, &data)
        .unwrap();
    let mut bytes = vec![0; 0x10000];
    memory.read_at(0, &mut bytes).unwrap();
    assert!(bytes[..0x1000].iter().all(|&b| b == 0xa5));
    assert_eq!(&bytes[0x1000..0x1000 + data.len()], &data);
    assert!(bytes[0x1000 + data.len()..0x3000].iter().all(|&b| b == 0));
    assert!(bytes[0x3000..].iter().all(|&b| b == 0xa5));
    let initial = loader.initial_regs_and_page_imports();
    assert_eq!(
        initial.page_imports,
        [InitialPageImport {
            range: MemoryRange::new(0x1000..0x3000),
            import_type: InitialPageImportType::Normal,
            tag: "payload"
        }]
    );
}

// Test: Request overlapping imports after valid data has already been accepted.
// Expected: Both partial overlaps are refused and neither overwrites the accepted data or import metadata.
#[test]
fn overlapping_page_imports_leave_accepted_bytes_and_metadata_intact() {
    let memory = GuestMemory::allocate(0x10000);
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(memory.clone(), &layout, Vtl::Vtl0);
    loader
        .import_pages(
            2,
            2,
            "original",
            BootPageAcceptance::Exclusive,
            &[0x73; 8192],
        )
        .unwrap();
    for (base, count) in [(1, 2), (3, 2)] {
        let error = loader
            .import_pages(
                base,
                count,
                "overlap",
                BootPageAcceptance::Shared,
                &[0x42; 8192],
            )
            .unwrap_err();
        assert!(error.to_string().contains("overlaps original"));
    }
    assert_eq!(
        memory.read_plain::<[u8; 8192]>(0x2000).unwrap(),
        [0x73; 8192]
    );
    let imports = loader.initial_regs_and_page_imports().page_imports;
    assert_eq!(
        imports,
        [InitialPageImport {
            range: MemoryRange::new(0x2000..0x4000),
            import_type: InitialPageImportType::Normal,
            tag: "original"
        }]
    );
}

// Test: Import oversized data, overflowing byte addresses/counts and inaccessible guest memory.
// Expected: Every invalid transfer returns an error rather than accepting a truncated or wrapped request.
#[test]
fn invalid_transfer_lengths_addresses_and_guest_memory_return_errors() {
    let layout = layout();
    let limit = u64::MAX / HV_PAGE_SIZE;
    for (base, count, data) in [
        (0, 1, vec![0; 4097]),
        (limit + 1, 1, vec![]),
        (0, limit + 1, vec![]),
        (limit, 1, vec![]),
        (16, 1, vec![1]),
        (16, 1, vec![]),
    ] {
        let mut loader =
            Loader::<X86Register>::new(GuestMemory::allocate(0x10000), &layout, Vtl::Vtl0);
        assert!(
            loader
                .import_pages(base, count, "invalid", BootPageAcceptance::Exclusive, &data)
                .is_err()
        );
    }
}

// Test: Collect adjacent imports with matching metadata and with different tags/acceptance.
// Expected: Only equal metadata coalesces and every acceptance mode maps to the correct import type.
#[test]
fn coalescing_preserves_tag_acceptance_boundaries_and_all_import_types() {
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(GuestMemory::allocate(0x10000), &layout, Vtl::Vtl0);
    for (page, tag, acceptance) in [
        (3, "normal", BootPageAcceptance::Exclusive),
        (1, "normal", BootPageAcceptance::Exclusive),
        (2, "normal", BootPageAcceptance::Exclusive),
        (4, "different-tag", BootPageAcceptance::Exclusive),
        (5, "different-tag", BootPageAcceptance::Shared),
        (6, "unmeasured", BootPageAcceptance::ExclusiveUnmeasured),
        (7, "context", BootPageAcceptance::VpContext),
        (8, "secrets", BootPageAcceptance::SecretsPage),
        (9, "cpuid", BootPageAcceptance::CpuidPage),
        (10, "xstate", BootPageAcceptance::CpuidExtendedStatePage),
    ] {
        loader.accept_new_range(page, 1, tag, acceptance).unwrap();
    }
    loader.import_vp_register(X86Register::Rip(0x1234)).unwrap();
    let mut initial = loader.initial_regs_and_page_imports();
    assert_eq!(initial.regs, [X86Register::Rip(0x1234)]);
    let expected = [
        (1, 4, "normal", InitialPageImportType::Normal),
        (4, 5, "different-tag", InitialPageImportType::Normal),
        (5, 6, "different-tag", InitialPageImportType::Shared),
        (6, 7, "unmeasured", InitialPageImportType::NormalUnmeasured),
        (7, 8, "context", InitialPageImportType::VpContext),
        (8, 9, "secrets", InitialPageImportType::Secrets),
        (9, 10, "cpuid", InitialPageImportType::Cpuid),
        (10, 11, "xstate", InitialPageImportType::CpuidExtendedState),
    ]
    .into_iter()
    .map(|(start, end, tag, import_type)| InitialPageImport {
        range: MemoryRange::from_4k_gpn_range(start..end),
        import_type,
        tag,
    })
    .collect::<Vec<_>>();
    initial
        .page_imports
        .sort_by_key(|import| import.range.start());
    assert_eq!(initial.page_imports, expected);
}

// Test: Verify startup RAM across normal RAM, MMIO holes, a separate VTL2 range and arithmetic limits.
// Expected: Requests fit wholly in one eligible range; protected RAM additionally requires VTL2.
#[test]
fn startup_memory_checks_ram_holes_vtl_and_exact_boundaries() {
    let layout = MemoryLayout::new(
        0xc000,
        &[MemoryRange::new(0x4000..0x8000)],
        &[],
        &[],
        Some(MemoryRange::new(0x20000..0x24000)),
    )
    .unwrap();
    for vtl in [Vtl::Vtl0, Vtl::Vtl2] {
        let mut loader = Loader::<X86Register>::new(GuestMemory::allocate(0x10000), &layout, vtl);
        let isolation = loader.isolation_config();
        assert!(!isolation.paravisor_present);
        assert_eq!(
            isolation.isolation_type,
            loader::importer::IsolationType::None
        );
        assert!(isolation.shared_gpa_boundary_bits.is_none());
        for (base, count) in [(0, 4), (8, 8), (15, 1)] {
            loader
                .verify_startup_memory_available(base, count, StartupMemoryType::Ram)
                .unwrap();
        }
        for (base, count) in [
            (0, 0),
            (3, 2),
            (4, 1),
            (7, 2),
            (16, 1),
            (u64::MAX / HV_PAGE_SIZE + 1, 1),
            (0, u64::MAX / HV_PAGE_SIZE + 1),
            (u64::MAX / HV_PAGE_SIZE, 1),
        ] {
            assert!(
                loader
                    .verify_startup_memory_available(base, count, StartupMemoryType::Ram)
                    .is_err()
            );
        }
        for (base, count) in [(0, 1), (32, 4), (35, 1)] {
            assert_eq!(
                loader
                    .verify_startup_memory_available(
                        base,
                        count,
                        StartupMemoryType::Vtl2ProtectableRam
                    )
                    .is_ok(),
                vtl == Vtl::Vtl2
            );
        }
        assert!(
            loader
                .verify_startup_memory_available(32, 1, StartupMemoryType::Ram)
                .is_err()
        );
        for (base, count) in [(31, 2), (35, 2)] {
            assert!(
                loader
                    .verify_startup_memory_available(
                        base,
                        count,
                        StartupMemoryType::Vtl2ProtectableRam
                    )
                    .is_err()
            );
        }
    }
}

// Test: Reject VP-context GPAs that overflow either the page index or converted byte range.
// Expected: Failed directives do not appear in the ordered import collection.
#[test]
fn overflowing_vp_context_directives_are_rejected_without_recording_them() {
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(GuestMemory::allocate(0x10000), &layout, Vtl::Vtl0);
    for page in [
        u64::MAX,
        u64::MAX / HV_PAGE_SIZE + 1,
        u64::MAX / HV_PAGE_SIZE,
    ] {
        assert!(loader.record_vp_context_import(page, "overflow").is_err());
    }
    assert!(
        loader
            .initial_regs_and_ordered_page_imports()
            .page_imports
            .is_empty()
    );
}

// Test: Build an SNP VMSA from imported registers after reserving and zeroing its context page.
// Expected: Serialized guest memory decodes to the requested state; duplicate finalization/configuration is refused.
#[test]
fn snp_vmsa_serializes_imported_state_and_enforces_one_time_finalization() {
    let memory = GuestMemory::allocate(0x10000);
    memory.fill_at(0, 0xa5, 0x10000).unwrap();
    let layout = layout();
    let (caps, bsp) = x86_caps();
    let config = virt::x86::snp::SnpVmsaConfig {
        restricted_injection: true,
    };
    let mut loader = Loader::<X86Register>::new(memory.clone(), &layout, Vtl::Vtl0);
    assert!(loader.finalize_snp_vmsa(&caps, &bsp, config).is_err());
    loader.set_vp_context_page(1).unwrap();
    assert_eq!(memory.read_plain::<[u8; 4096]>(0x1000).unwrap(), [0; 4096]);
    assert!(loader.set_vp_context_page(2).is_err());
    for register in [
        X86Register::Rip(0x1234),
        X86Register::Rsp(0x5678),
        X86Register::Rflags(0x202),
        X86Register::Pat(0x0007_0406_0007_0406),
    ] {
        loader.import_vp_register(register).unwrap();
    }
    loader.finalize_snp_vmsa(&caps, &bsp, config).unwrap();
    let vmsa = memory.read_plain(0x1000).unwrap();
    let state = virt::x86::snp::state_from_vmsa(&vmsa).unwrap();
    assert_eq!(
        (
            state.registers.rip,
            state.registers.rsp,
            state.registers.rflags
        ),
        (0x1234, 0x5678, 0x202)
    );
    assert_eq!(state.pat, 0x0007_0406_0007_0406);
    assert!(state.restricted_injection);
    let saved = memory.read_plain::<[u8; 4096]>(0x1000).unwrap();
    assert!(loader.finalize_snp_vmsa(&caps, &bsp, config).is_err());
    assert!(loader.import_vp_register(X86Register::Cr3(0x9000)).is_err());
    assert_eq!(memory.read_plain::<[u8; 4096]>(0x1000).unwrap(), saved);
    assert_eq!(
        memory.read_plain::<[u8; 4096]>(0x2000).unwrap(),
        [0xa5; 4096]
    );
}

// Test: Configure a VP-context page outside the guest-memory backing.
// Expected: The zeroing failure is returned as an error instead of reporting a usable context page.
#[test]
fn inaccessible_vp_context_memory_returns_a_zeroing_error() {
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(GuestMemory::allocate(0x1000), &layout, Vtl::Vtl0);
    let error = loader.set_vp_context_page(1).unwrap_err();
    assert!(error.to_string().contains("unable to zero VP context page"));
}

// Test: Import an empty-data image region next to a payload loaded earlier.
// Expected: Every empty-data page is zeroed and retained in the accepted range,
//       without changing the existing payload or either neighboring guard page.
#[test]
fn empty_data_import_zeroes_whole_pages_without_discarding_or_overwriting_ranges() {
    let memory = GuestMemory::allocate(0x10000);
    memory.fill_at(0, 0xa5, 0x10000).unwrap();
    let layout = layout();
    let mut loader = Loader::<X86Register>::new(memory.clone(), &layout, Vtl::Vtl0);
    loader
        .import_pages(3, 1, "image", BootPageAcceptance::Exclusive, &[0x73; 4096])
        .unwrap();
    loader
        .import_pages(1, 2, "image", BootPageAcceptance::Exclusive, &[])
        .unwrap();
    let mut bytes = vec![0; 0x10000];
    memory.read_at(0, &mut bytes).unwrap();
    assert!(bytes[..0x1000].iter().all(|&b| b == 0xa5));
    assert!(bytes[0x1000..0x3000].iter().all(|&b| b == 0));
    assert!(bytes[0x3000..0x4000].iter().all(|&b| b == 0x73));
    assert!(bytes[0x4000..].iter().all(|&b| b == 0xa5));
    assert_eq!(
        loader.initial_regs_and_page_imports().page_imports,
        [InitialPageImport {
            range: MemoryRange::new(0x1000..0x4000),
            import_type: InitialPageImportType::Normal,
            tag: "image"
        }]
    );
}
