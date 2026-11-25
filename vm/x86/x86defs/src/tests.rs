// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate std;

use super::*;
use std::format;

// Test: Classify addresses around both canonical boundaries for four- and five-level paging.
// Expected: Only sign-extended addresses are accepted, including the extreme addresses.
#[test]
fn canonical_addresses_follow_the_selected_paging_width() {
    for bits in [48, 57] {
        let half = 1_u64 << (bits - 1);
        for address in [0, half - 1, u64::MAX - half + 1, u64::MAX] {
            assert!(is_canonical_address(address, bits));
        }
        for address in [half, u64::MAX - half] {
            assert!(!is_canonical_address(address, bits));
        }
    }
}

// Test: Build a large system descriptor and its selector for a guest GDT.
// Expected: Both eight-byte entries retain the architectural little-endian layout.
#[test]
fn system_descriptor_serialization_preserves_both_gdt_entries() {
    let attributes = SegmentAttributes::new()
        .with_present(true)
        .with_segment_type(9);
    let selector = SegmentSelector::from_gdt_index(5, 3);
    assert_eq!(selector.as_bits(), 0x2b);
    assert_eq!(attributes.as_bits(), 0x89);
    let entry = LargeGdtEntry {
        limit_low: 0x67,
        base_low: 0x7788,
        base_middle: 0x66,
        attr_low: attributes.as_bits() as u8,
        attr_high: 0,
        base_high: 0x55,
        base_upper: 0x11223344,
        mbz: 0,
    };
    assert_eq!(
        entry.get_gdt_entries().as_bytes(),
        &[
            0x67, 0, 0x88, 0x77, 0x66, 0x89, 0, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0
        ]
    );
}

// Test: Relocate a writable user page while preserving its access and execution flags.
// Expected: The PTE changes only its page frame and exports the updated physical address.
#[test]
fn page_relocation_preserves_page_permissions() {
    let mut pte = Pte::new()
        .with_present(true)
        .with_read_write(true)
        .with_user(true)
        .with_no_execute(true)
        .with_address(0x12345000);
    assert_eq!(pte.address(), 0x12345000);
    assert_eq!(pte.into_bits(), 0x8000000012345007);
    pte.set_address(0xabcde000);
    assert_eq!(pte.address(), 0xabcde000);
    assert_eq!(pte.into_bits(), 0x80000000abcde007);
}

// Test: Try to encode a physical address that is not page aligned.
// Expected: PTE construction rejects the address rather than discarding low bits.
#[test]
#[should_panic]
fn pte_rejects_unaligned_physical_addresses() {
    Pte::new().with_address(0x1234);
}

// Test: Apply an architectural flag mask to the reset RFLAGS value.
// Expected: Reset retains the mandatory bit while unrelated flags remain clear.
#[test]
fn reset_flags_and_bit_masks_preserve_architectural_bits() {
    assert_eq!(RFlags::at_reset().into_bits(), 2);
    let masked = RFlags::from_bits(0x246) & RFlags::from_bits(0x202);
    assert_eq!(masked.into_bits(), 0x202);
}

// Test: Decode VMCS field widths and the basic reason within a failed VM entry.
// Expected: Width encodings and exit flags do not overlap neighboring fields.
#[test]
fn vmx_field_and_exit_encodings_decode_architectural_values() {
    use vmx::*;
    for (bits, expected) in [
        (0, FieldWidth::Width16),
        (1, FieldWidth::Width64),
        (2, FieldWidth::Width32),
        (3, FieldWidth::WidthNatural),
    ] {
        let field = VmcsField::from_bits(bits << 13 | 0x12);
        assert_eq!(field.field_width(), expected);
        assert_eq!(
            VmcsField::new().with_field_width(expected).into_bits(),
            bits << 13
        );
    }
    let exit = VmxExit::from_bits(0x80000030);
    assert_eq!(exit.basic_reason(), VmxExitBasic::EPT_VIOLATION);
    assert!(exit.vm_enter_failed());
    assert_eq!(
        VmxExit::new()
            .with_basic_reason(VmxExitBasic::CPUID)
            .into_bits(),
        10
    );
}

// Test: Decode all descriptor-table load/store instruction qualifiers.
// Expected: Each opcode maps to its architectural instruction and load/store direction.
#[test]
fn vmx_descriptor_instruction_qualifiers_distinguish_loads_and_stores() {
    use vmx::*;
    for (bits, gdtr, ldtr, load) in [
        (
            0,
            GdtrOrIdtrInstruction::Sgdt,
            LdtrOrTrInstruction::Sldt,
            false,
        ),
        (
            1,
            GdtrOrIdtrInstruction::Sidt,
            LdtrOrTrInstruction::Str,
            false,
        ),
        (
            2,
            GdtrOrIdtrInstruction::Lgdt,
            LdtrOrTrInstruction::Lldt,
            true,
        ),
        (
            3,
            GdtrOrIdtrInstruction::Lidt,
            LdtrOrTrInstruction::Ltr,
            true,
        ),
    ] {
        let a = GdtrOrIdtrInstructionInfo::from_bits(bits << 28).instruction();
        let b = LdtrOrTrInstructionInfo::from_bits(bits << 28).instruction();
        assert_eq!(a, gdtr);
        assert_eq!(b, ldtr);
        assert_eq!(a.is_load(), load);
        assert_eq!(b.is_load(), load);
        assert_eq!(
            GdtrOrIdtrInstructionInfo::new()
                .with_instruction(a)
                .into_bits(),
            bits << 28
        );
        assert_eq!(
            LdtrOrTrInstructionInfo::new()
                .with_instruction(b)
                .into_bits(),
            bits << 28
        );
    }
}

// Test: Encode TDX page levels, return codes, context, and extended-exit qualifiers.
// Expected: Architectural values retain their documented positions in register operands.
#[test]
fn tdx_register_operands_preserve_levels_codes_and_context() {
    use tdx::*;
    for (bits, level) in [
        (0, TdgMemPageLevel::Size4k),
        (1, TdgMemPageLevel::Size2Mb),
        (2, TdgMemPageLevel::Size1Gb),
    ] {
        let operand = TdgMemPageReleaseRcx::from_bits(0x12345000 | bits);
        assert_eq!(operand.level(), level);
        assert_eq!(
            TdgMemPageReleaseRcx::new()
                .with_level(level)
                .with_gpa_page_number(0x12345)
                .into_bits(),
            0x12345000 | bits
        );
    }
    let result = TdCallResult::from_bits(0xc0000100_12345678);
    assert_eq!(result.code(), TdCallResultCode::OPERAND_INVALID);
    assert_eq!(result.details(), 0x12345678);
    assert_eq!(
        TdCallResult::new()
            .with_code(TdCallResultCode::OPERAND_INVALID)
            .with_details(7)
            .into_bits(),
        0xc0000100_00000007
    );
    let context = TdxExtendedFieldCode::new().with_context_code(TdxContextCode::TD_VCPU);
    assert_eq!(
        TdxExtendedFieldCode::from_bits(context.into_bits()).context_code(),
        TdxContextCode::TD_VCPU
    );
    let exit = TdxExtendedExitQualification::from_bits(6);
    assert_eq!(
        exit.ty(),
        TdxExtendedExitQualificationType::PENDING_EPT_VIOLATION
    );
    assert_eq!(
        TdxExtendedExitQualification::new()
            .with_ty(exit.ty())
            .into_bits(),
        6
    );
}

// Test: Decode each TDX metadata width using a raw field-code operand.
// Expected: The decoded width and re-encoded operand agree with the wire bits.
#[test]
fn tdx_metadata_field_sizes_decode_all_encodings() {
    use tdx::*;
    for (bits, size) in [
        (0, FieldSize::Invalid),
        (1, FieldSize::Size16Bit),
        (2, FieldSize::Size32Bit),
        (3, FieldSize::Size64Bit),
    ] {
        let field = TdxExtendedFieldCode::from_bits(bits << 32);
        assert_eq!(field.field_size() as u64, bits);
        assert_eq!(
            TdxExtendedFieldCode::new()
                .with_field_size(size)
                .into_bits(),
            bits << 32
        );
    }
}

// Test: Decode a reserved TDX page level supplied by a register operand.
// Expected: The invalid level is rejected rather than interpreted as a supported page size.
#[test]
#[should_panic(expected = "invalid TdgMemPageLevel value")]
fn tdx_rejects_reserved_page_levels() {
    tdx::TdgMemPageReleaseRcx::from_bits(3).level();
}

// Test: Serialize SNP segment and XMM registers with distinct high and low halves.
// Expected: Both register representations preserve the complete 128-bit hardware layout.
#[test]
fn snp_register_serialization_preserves_all_128_bits() {
    let raw = 0x1122334455667788_99aabbccddeeff00_u128;
    let selector = snp::SevSelector::from(raw);
    assert_eq!(selector.base, 0x1122334455667788);
    assert_eq!(selector.limit, 0x99aabbcc);
    assert_eq!(selector.attrib, 0xddee);
    assert_eq!(selector.selector, 0xff00);
    assert_eq!(selector.as_bytes(), raw.to_le_bytes());
    assert_eq!(selector.as_u128(), raw);
    let xmm = snp::SevXmmRegister::from(raw);
    assert_eq!(xmm.as_bytes(), raw.to_le_bytes());
    assert_eq!(xmm.as_u128(), raw);
    assert_eq!(u8::from(snp::Vmpl::Vmpl3), 3);
}

// Test: Decode the GHCB page trailer from guest-provided bytes and re-encode its tags.
// Expected: Unknown usage and protocol encodings survive without truncation.
#[test]
fn ghcb_trailer_preserves_protocol_and_usage_encodings() {
    let mut bytes = [0; 4096];
    bytes[4090..4092].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes[4092..].copy_from_slice(&0x89abcdef_u32.to_le_bytes());
    let page = snp::GhcbPage::read_from_bytes(&bytes).unwrap();
    assert_eq!(page.protocol_version.into_bits(), 0x1234);
    assert_eq!(page.ghcb_usage.into_bits(), 0x89abcdef);
    assert_eq!(
        snp::GhcbProtocolVersion::from_bits(0x1234)
            .into_bits()
            .to_le_bytes(),
        bytes[4090..4092]
    );
    assert_eq!(
        snp::GhcbUsage::from_bits(0x89abcdef)
            .into_bits()
            .to_le_bytes(),
        bytes[4092..]
    );
}

// Test: Convert legacy APIC destinations and virtualized MSI destinations.
// Expected: Routing IDs occupy their wire fields without changing the interrupt vector.
#[test]
fn apic_and_msi_destination_updates_preserve_other_message_bits() {
    let mut icr = apic::Icr::new().with_vector(0x42).with_xapic_mda(0x34);
    assert_eq!(icr.into_bits(), 0x34000000_00000042);
    assert_eq!(icr.xapic_mda(), 0x34);
    icr.set_xapic_mda(0x56);
    assert_eq!(icr.into_bits(), 0x56000000_00000042);
    assert_eq!(apic::ApicRegister::ICR0.x2apic_msr(), 0x830);
    let mut address = msi::MsiAddress::from_bits(0xfee0000c).with_virt_destination(0x1234);
    assert_eq!(address.into_bits(), 0xfee3424c);
    assert_eq!(address.virt_destination(), 0x1234);
    address.set_virt_destination(0x7fff);
    assert_eq!(address.virt_destination(), 0x7fff);
    assert_eq!(address.into_bits() & 0xfff0000f, 0xfee0000c);
}

// Test: Decode CPUID vendor registers, classify compatible CPUs, and format invalid bytes.
// Expected: Register order matches CPUID and invalid UTF-8 produces readable byte diagnostics.
#[test]
fn cpuid_vendors_preserve_register_order_and_diagnostics() {
    use cpuid::Vendor;
    for (vendor, intel, amd) in [
        (Vendor::INTEL, true, false),
        (Vendor::AMD, false, true),
        (Vendor::HYGON, false, true),
        (Vendor(*b"OtherVendor!"), false, false),
    ] {
        let (ebx, ecx, edx) = vendor.to_ebx_ecx_edx();
        assert_eq!(Vendor::from_ebx_ecx_edx(ebx, ecx, edx), vendor);
        assert_eq!(vendor.is_intel_compatible(), intel);
        assert_eq!(vendor.is_amd_compatible(), amd);
    }
    assert_eq!(format!("{}", Vendor::INTEL), "GenuineIntel");
    assert_eq!(format!("{:>14}", Vendor::AMD), "  AuthenticAMD");
    assert_eq!(
        format!("{}", Vendor([0xff; 12])),
        "[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]"
    );
}

// Test: Generate full-width architectural register values from fuzzing input.
// Expected: High bits survive generation and both known and arbitrary vendor paths work.
#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_register_generation_retains_full_width_fields() {
    use arbitrary::{Arbitrary, Unstructured};
    let bytes = [0xff; 64];
    assert_eq!(
        SegmentAttributes::arbitrary(&mut Unstructured::new(&bytes))
            .unwrap()
            .as_bits(),
        u16::MAX
    );
    let segment = SegmentRegister::arbitrary(&mut Unstructured::new(&bytes)).unwrap();
    assert_eq!(segment.base, u64::MAX);
    assert_eq!(segment.limit, u32::MAX);
    assert_eq!(segment.selector, u16::MAX);
    assert_eq!(segment.attributes.as_bits(), u16::MAX);
    assert_eq!(
        RFlags::arbitrary(&mut Unstructured::new(&bytes))
            .unwrap()
            .into_bits(),
        u64::MAX
    );
    let mut known = false;
    let mut other = false;
    for seed in 0..=255 {
        let bytes = [seed; 64];
        let vendor = cpuid::Vendor::arbitrary(&mut Unstructured::new(&bytes)).unwrap();
        if [
            cpuid::Vendor::INTEL,
            cpuid::Vendor::AMD,
            cpuid::Vendor::HYGON,
        ]
        .contains(&vendor)
        {
            known = true;
        } else {
            other = true;
        }
    }
    assert!(known && other);
}

// Test: Flip each bit of positive and negative canonical guest addresses.
// Expected: Payload bits stay valid; any broken sign-extension bit is rejected.
#[test]
fn canonical_validation_checks_every_sign_extension_bit() {
    for bits in [48, 57] {
        for address in [0x1234_5678_u64, !0x1234_5678_u64] {
            for bit in 0..64 {
                let changed = address ^ (1_u64 << bit);
                assert_eq!(
                    is_canonical_address(changed, bits),
                    bit < bits - 1,
                    "{bits}-bit address {changed:#018x}, changed bit {bit}"
                );
            }
        }
    }
}
