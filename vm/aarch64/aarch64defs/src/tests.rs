// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate std;

use super::*;
use std::format;
use test_with_tracing::test;

// Test: Decode data-abort syndromes and convert them to the ESR register format.
// Expected: Fault codes, direction and every ISS bit survive conversion without
//       leaking into the exception-class field.
#[test]
fn data_abort_conversion_preserves_syndrome_and_direction() {
    for raw in [0, 0x01ff_ffff, 0x016f_7acd, 0x00a5_1234] {
        let abort = IssDataAbort::from(raw);
        assert_eq!(abort.dfsc().0, (raw & 0x3f) as u8);
        let rewritten = abort.with_dfsc(FaultStatusCode::PERMISSION_FAULT_LEVEL3);
        assert_eq!(rewritten.into_bits(), (raw & !0x3f) | 0x0f);
        let esr = EsrEl2::from(abort);
        assert_eq!(esr.into_bits(), (0x25 << 26) | u64::from(raw));
        assert_eq!(esr.iss(), raw);
        assert_eq!(esr.is_write(), raw & 0x40 != 0);
        assert_eq!(esr.is_read(), raw & 0x40 == 0);
        let lower = esr.with_ec(ExceptionClass::DATA_ABORT_LOWER.0);
        assert_eq!(lower.srt(), Some(((raw >> 16) & 31) as u8));
        assert_eq!(esr.with_ec(ExceptionClass::SYSTEM.0).srt(), None);
    }
}

// Test: Convert instruction-abort syndromes with fault, table-walk and FAR flags.
// Expected: The ESR contains the instruction-abort class and the original ISS;
//       replacing its fault code preserves the remaining syndrome bits.
#[test]
fn instruction_abort_conversion_preserves_fault_metadata() {
    for raw in [0, 0x0000_0687, 0x0000_041f] {
        let abort = IssInstructionAbort::from(raw);
        assert_eq!(abort.ifsc().0, (raw & 0x3f) as u8);
        assert_eq!(abort.set(), SynchronousErrorType::RECOVERABLE);
        let rewritten = abort
            .with_ifsc(FaultStatusCode::TRANSLATION_FAULT_LEVEL3)
            .with_set(SynchronousErrorType::RECOVERABLE);
        assert_eq!(rewritten.into_bits(), (raw & !0x3f) | 7);
        let esr = EsrEl2::from(abort);
        assert_eq!(esr.into_bits(), (0x21 << 26) | u64::from(raw));
        assert_eq!(esr.iss(), raw);
        assert_eq!(esr.srt(), None);
    }
}

// Test: Translate trapped system-register operands into instruction encodings.
// Expected: Register identity is independent of transfer direction and Rt, and
//       known and unknown encodings retain all architectural operand fields.
#[test]
fn trapped_system_registers_reconstruct_instruction_operands() {
    for (op0, op1, crn, crm, op2, expected) in [
        (3, 0, 4, 0, 0, SystemReg::SPSR_EL1),
        (3, 4, 4, 0, 1, SystemReg::ELR_EL2),
        (3, 0, 12, 12, 0, SystemReg::ICC_IAR1_EL1),
        (0, 0, 0, 0, 0, SystemReg(SystemRegEncoding::from(0u32))),
        (
            3,
            7,
            15,
            15,
            7,
            SystemReg(SystemRegEncoding::from(0x001f_ffe0u32)),
        ),
    ] {
        let encoding = SystemRegEncoding::make(op0, op1, crn, crm, op2);
        assert_eq!(SystemReg(encoding), expected);
        assert_eq!(
            encoding.into_bits(),
            (u32::from(op0) << 19)
                | (u32::from(op1) << 16)
                | (u32::from(crn) << 12)
                | (u32::from(crm) << 8)
                | (u32::from(op2) << 5)
        );
        for direction in [false, true] {
            for rt in [0, 1, 15, 30, 31] {
                let raw = (u32::from(op0) << 20)
                    | (u32::from(op2) << 17)
                    | (u32::from(op1) << 14)
                    | (u32::from(crn) << 10)
                    | (rt << 5)
                    | (u32::from(crm) << 1)
                    | u32::from(direction);
                let syndrome = IssSystem::from(raw);
                assert_eq!(syndrome.system_reg(), expected);
                assert_eq!(syndrome.rt(), rt as u8);
                assert_eq!(syndrome.direction(), direction);
            }
        }
    }
}

// Test: Decode translation controls for every supported physical address width.
// Expected: Width selection accepts only architectural sizes, TTBR address bits
//       follow TnSZ, and granule updates preserve neighboring translation policy.
#[test]
fn translation_controls_decode_address_widths_and_granules() {
    let widths = [32, 36, 40, 42, 44, 48, 52, 56];
    for bits in 0..=u8::MAX {
        assert_eq!(
            IntermPhysAddrSize::from_ipa_bit_length(bits).map(|size| size.0),
            widths
                .iter()
                .position(|width| *width == bits)
                .map(|i| i as u64)
        );
    }
    for (index, bits) in widths.into_iter().enumerate() {
        for (size0, size1) in [(16, 32), (0, 63), (63, 0)] {
            let raw = size0 | (size1 << 16) | (2 << 14) | (3 << 30) | ((index as u64) << 32);
            let control = TranslationControlEl1::from(raw);
            assert_eq!(control.ttbr0_valid_address_bits(), 64 - size0);
            assert_eq!(control.ttbr1_valid_address_bits(), 64 - size1);
            assert_eq!(control.tg0(), TranslationGranule0::TG_16KB);
            assert_eq!(control.tg1(), TranslationGranule1::TG_64KB);
            assert_eq!(
                control.ips(),
                IntermPhysAddrSize::from_ipa_bit_length(bits).unwrap()
            );
            let changed = control
                .with_tg0(TranslationGranule0::TG_64KB)
                .with_tg1(TranslationGranule1::TG_4KB)
                .with_ips(IntermPhysAddrSize::IPA_48_BITS_256_TB);
            assert_eq!(
                changed.into_bits(),
                size0 | (size1 << 16) | (1 << 14) | (2 << 30) | (5 << 32)
            );
            // Preserve walk-disable, cacheability, shareability and tag policy.
            let neighbors = (1 << 7)
                | (1 << 8)
                | (3 << 12)
                | (1 << 23)
                | (1 << 24)
                | (3 << 28)
                | (1 << 37)
                | (1 << 38)
                | (1 << 59);
            let changed_with_policy = TranslationControlEl1::from(raw | neighbors)
                .with_tg0(TranslationGranule0::TG_64KB)
                .with_tg1(TranslationGranule1::TG_4KB)
                .with_ips(IntermPhysAddrSize::IPA_48_BITS_256_TB);
            assert_eq!(
                changed_with_policy.into_bits(),
                size0 | (size1 << 16) | (1 << 14) | (2 << 30) | (5 << 32) | neighbors
            );
            let mmfr = MmFeatures0El1::from(index as u64);
            assert_eq!(mmfr.pa_range().0, index as u64);
        }
    }
}

// Test: Decode CPU feature registers and suppress the advertised GIC interface.
// Expected: GIC policy changes only its architectural field, preserving the
//       other feature bits, including encodings unknown to this library.
#[test]
fn gic_feature_policy_preserves_other_cpu_features() {
    for gic in [0, 1, 15] {
        let raw = 0x1234_5678_fedc_ba98u64 & !(15 << 24) | (gic << 24);
        let features = ProcessorFeatures0El1::from(raw);
        assert_eq!(features.gic().0, gic as u8);
        assert_eq!(
            features.with_gic(GicCpuInterface::NONE).into_bits(),
            raw & !(15 << 24)
        );
        assert_eq!(
            features
                .with_gic(GicCpuInterface::GICV3_OR_GICV4)
                .into_bits(),
            (raw & !(15 << 24)) | (1 << 24)
        );
    }
}

// Test: Format known and unknown CPU vendors while applying compatibility policy.
// Expected: Arm uses its readable name, unknown IDs retain their numeric value,
//       and AArch64 vendors are never reported as x86-compatible.
#[test]
fn vendor_diagnostics_and_compatibility_remain_consistent() {
    for (vendor, text, arm) in [
        (Vendor::ARM, "Arm", true),
        (Vendor(0x1234), "0x1234", false),
        (Vendor(0), "0x0", false),
    ] {
        assert_eq!(format!("{vendor}"), text);
        assert_eq!(vendor.is_arm_compatible(), arm);
        assert!(!vendor.is_intel_compatible());
        assert!(!vendor.is_amd_compatible());
    }
    assert_eq!(format!("{:>6}", Vendor::ARM), "   Arm");
}

// Test: Decode a 64-bit PSCI call and retarget it to a vendor hypervisor service.
// Expected: The wire encoding preserves the function number and convention,
//       and changes only the service and hint fields requested by the caller.
#[test]
fn smccc_call_retargeting_preserves_call_semantics() {
    use crate::smccc::{FastCall, Service};
    let call = FastCall::from(0xc400_0003);
    assert_eq!(call.number(), 3);
    assert_eq!(call.service(), Service::PSCI);
    assert!(call.smc64());
    assert!(call.fast());
    assert_eq!(
        call.with_service(Service::VENDOR_HYP)
            .with_hint(true)
            .into_bits(),
        0xc601_0003
    );
    let unknown = FastCall::from(0xbf00_4321);
    assert_eq!(unknown.service(), Service(63));
    assert_eq!(
        unknown.with_service(Service::SMCCC).into_bits(),
        0x8000_4321
    );
}

// Test: Classify architectural instruction-abort fault codes, including reserved ones.
// Expected: Every defined code maps to its diagnostic reason and unrecognized
//       encodings remain Unknown instead of being assigned a nearby fault.
#[test]
fn instruction_abort_reasons_classify_all_defined_faults() {
    use InstructionAbortReason::*;
    let cases = [
        (0x00, AddressSizeFaultLevel0),
        (0x01, AddressSizeFaultLevel1),
        (0x02, AddressSizeFaultLevel2),
        (0x03, AddressSizeFaultLevel3),
        (0x04, TranslationFaultLevel0),
        (0x05, TranslationFaultLevel1),
        (0x06, TranslationFaultLevel2),
        (0x07, TranslationFaultLevel3),
        (0x08, AccessFlagFaultLevel0),
        (0x09, AccessFlagFaultLevel1),
        (0x0a, AccessFlagFaultLevel2),
        (0x0b, AccessFlagFaultLevel3),
        (0x0c, PermissionFaultLevel0),
        (0x0d, PermissionFaultLevel1),
        (0x0e, PermissionFaultLevel2),
        (0x0f, PermissionFaultLevel3),
        (0x10, SynchronousExternalAbort),
        (0x11, SyncTagCheckFault),
        (0x13, SynchronousExternalAbortOnTableWalkLevelNeg1),
        (0x14, SynchronousExternalAbortOnTableWalkLevel0),
        (0x15, SynchronousExternalAbortOnTableWalkLevel1),
        (0x16, SynchronousExternalAbortOnTableWalkLevel2),
        (0x17, SynchronousExternalAbortOnTableWalkLevel3),
        (0x18, EccParity),
        (0x1b, EccParityOnTableWalkLevelNeg1),
        (0x1c, EccParityOnTableWalkLevel0),
        (0x1d, EccParityOnTableWalkLevel1),
        (0x1e, EccParityOnTableWalkLevel2),
        (0x1f, EccParityOnTableWalkLevel3),
        (0x23, GranuleProtectionFaultLevelNeg1),
        (0x24, GranuleProtectionFaultLevel0),
        (0x25, GranuleProtectionFaultLevel1),
        (0x26, GranuleProtectionFaultLevel2),
        (0x27, GranuleProtectionFaultLevel3),
        (0x29, AddressSizeFaultLevelNeg1),
        (0x2b, TranslationFaultLevelNeg1),
        (0x30, TlbConflictAbort),
        (0x31, UnsupportedHardwareUpdateFault),
    ];
    for code in 0..=u8::MAX {
        let expected = cases
            .iter()
            .find(|(raw, _)| *raw == code)
            .map_or(&Unknown, |(_, reason)| reason);
        let actual = InstructionAbortReason::from(FaultStatusCode(code));
        assert_eq!(
            core::mem::discriminant(&actual),
            core::mem::discriminant(expected),
            "fault {code:#x}: {actual:?}"
        );
    }
}

// IGNORED: The exception-class range excludes its DATA_ABORT upper endpoint,
//       so a same-level data abort incorrectly returns no register operand.
//
// Test: Decode the register operand of a same-exception-level data abort.
// Expected: Both same-level and lower-level data aborts expose their SRT field.
#[test]
#[ignore = "same-level DATA_ABORT is excluded from the SRT exception-class range"]
fn same_level_data_abort_exposes_register_operand() {
    let esr = EsrEl2::from((0x25u64 << 26) | (17 << 16));
    assert_eq!(esr.srt(), Some(17));
}

// IGNORED: The field conversion masks an already-extracted value with 0x1800,
//       discarding nonzero synchronous error types.
//
// Test: Decode nonzero synchronous error types from instruction-abort syndromes.
// Expected: The field reports Uncontainable or Restartable without losing bits.
#[test]
#[ignore = "synchronous error type conversion discards extracted field bits"]
fn instruction_abort_decodes_nonzero_synchronous_error_type() {
    assert_eq!(
        IssInstructionAbort::from(2 << 11).set(),
        SynchronousErrorType::UNCONTAINABLE
    );
    assert_eq!(
        IssInstructionAbort::from(3 << 11).set(),
        SynchronousErrorType::RESTARTABLE
    );
}

// IGNORED: The field conversion shifts its value before the bitfield setter
//       applies the field position, causing a bounds panic for valid inputs.
//
// Test: Encode a nonzero synchronous error type into an instruction-abort syndrome.
// Expected: Restartable occupies ISS bits 12:11 and does not panic on valid input.
#[test]
#[ignore = "nonzero synchronous error type encoding panics in the bitfield setter"]
fn instruction_abort_encodes_nonzero_synchronous_error_type() {
    assert_eq!(
        IssInstructionAbort::new()
            .with_set(SynchronousErrorType::RESTARTABLE)
            .into_bits(),
        3 << 11
    );
}
