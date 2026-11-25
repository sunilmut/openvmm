// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Convert every scalar x86 boot register to IGVM and back with zero and high-bit patterns.
// Expected: The intermediate register identity and all value bits survive both conversion directions.
#[test]
fn x86_scalar_register_conversions_preserve_identity_and_value() {
    macro_rules! check {
        ($($variant:ident),+ $(,)?) => {$({
            for value in [0u64, 0x8123_4567_89ab_cdef] {
                let expected = X86Register::$variant(value);
                let encoded: igvm::registers::X86Register = expected.into();
                assert!(matches!(&encoded, igvm::registers::X86Register::$variant(actual) if *actual == value));
                assert_eq!(X86Register::from(encoded), expected);
            }
        })+};
    }
    check!(
        Cr0,
        Cr3,
        Cr4,
        Efer,
        Pat,
        Rbp,
        Rip,
        Rsi,
        Rsp,
        R8,
        R9,
        R10,
        R11,
        R12,
        Rflags,
        MtrrDefType,
        MtrrPhysBase0,
        MtrrPhysMask0,
        MtrrPhysBase1,
        MtrrPhysMask1,
        MtrrPhysBase2,
        MtrrPhysMask2,
        MtrrPhysBase3,
        MtrrPhysMask3,
        MtrrPhysBase4,
        MtrrPhysMask4,
        MtrrFix64k00000,
        MtrrFix16k80000,
        MtrrFix4kE0000,
        MtrrFix4kE8000,
        MtrrFix4kF0000,
        MtrrFix4kF8000
    );
}

// Test: Convert every x86 descriptor-table and segment register with distinct nontrivial fields.
// Expected: Register identities, 64-bit bases, limits, selectors, and attributes survive without truncation or field swaps.
#[test]
fn x86_descriptor_register_conversions_preserve_every_field() {
    macro_rules! table {
        ($($variant:ident),+ $(,)?) => {$({
            let expected = X86Register::$variant(TableRegister { base: 0x1234_5678_9abc_def0, limit: 0x1357 });
            let encoded: igvm::registers::X86Register = expected.into();
            match &encoded {
                igvm::registers::X86Register::$variant(actual) => {
                    assert_eq!(actual.base, 0x1234_5678_9abc_def0);
                    assert_eq!(actual.limit, 0x1357);
                }
                other => panic!("wrong table register: {other:?}"),
            }
            assert_eq!(X86Register::from(encoded), expected);
        })+};
    }
    macro_rules! segment {
        ($($variant:ident),+ $(,)?) => {$({
            let expected = X86Register::$variant(SegmentRegister {
                base: 0x1234_5678_9abc_def0, limit: 0xfedc_ba98, selector: 0x1357, attributes: 0x2468,
            });
            let encoded: igvm::registers::X86Register = expected.into();
            match &encoded {
                igvm::registers::X86Register::$variant(actual) => {
                    assert_eq!(actual.base, 0x1234_5678_9abc_def0);
                    assert_eq!(actual.limit, 0xfedc_ba98);
                    assert_eq!(actual.selector, 0x1357);
                    assert_eq!(actual.attributes, 0x2468);
                }
                other => panic!("wrong segment register: {other:?}"),
            }
            assert_eq!(X86Register::from(encoded), expected);
        })+};
    }
    table!(Gdtr, Idtr);
    segment!(Ds, Es, Fs, Gs, Ss, Cs, Tr);
}

// Test: Convert every ARM64 boot register to IGVM and back with zero and high-bit patterns.
// Expected: Each intermediate register keeps its architectural identity and exact 64-bit value.
#[test]
fn arm64_register_conversions_preserve_identity_and_value() {
    macro_rules! check {
        ($($variant:ident),+ $(,)?) => {$({
            for value in [0u64, 0xfedc_ba98_7654_3210] {
                let expected = Aarch64Register::$variant(value);
                let encoded: igvm::registers::AArch64Register = expected.into();
                assert!(matches!(&encoded, igvm::registers::AArch64Register::$variant(actual) if *actual == value));
                assert_eq!(Aarch64Register::from(encoded), expected);
            }
        })+};
    }
    check!(
        Pc, X0, X1, X2, X3, X4, X5, X6, X7, Cpsr, VbarEl1, Ttbr0El1, Ttbr1El1, MairEl1, SctlrEl1,
        TcrEl1
    );
}
