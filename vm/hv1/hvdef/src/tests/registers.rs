// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate std;

use super::*;
use hypercall::HvRegisterAssoc;
use std::vec::Vec;
use test_with_tracing::test;

// Test: Serialize scalar register writes from every supported integer width.
// Expected: Values are zero-extended to 128 bits, padding is zero, and shared names keep their ID.
#[test]
fn scalar_register_associations_zero_extend_values_and_preserve_wire_layout() {
    let cases = [
        (
            HvRegisterValue::from(0xabu8),
            AlignedU128::from(0xabu8),
            0xabu128,
        ),
        (
            HvRegisterValue::from(0xabcd_u16),
            AlignedU128::from(0xabcd_u16),
            0xabcdu128,
        ),
        (
            HvRegisterValue::from(0x89abcdefu32),
            AlignedU128::from(0x89abcdefu32),
            0x89abcdefu128,
        ),
        (
            HvRegisterValue::from(0x0123456789abcdefu64),
            AlignedU128::from(0x0123456789abcdefu64),
            0x0123456789abcdefu128,
        ),
        (
            HvRegisterValue::from(0xfedcba98765432100123456789abcdefu128),
            AlignedU128::from_ne_bytes(0xfedcba98765432100123456789abcdefu128.to_ne_bytes()),
            0xfedcba98765432100123456789abcdefu128,
        ),
    ];
    for (value, aligned, expected) in cases {
        let x64_name = HvX64RegisterName::from(HvAllArchRegisterName::VpIndex);
        let arm_name = HvArm64RegisterName::from(HvAllArchRegisterName::VpIndex);
        let owned = HvRegisterAssoc::from((x64_name, value));
        let borrowed = HvRegisterAssoc::from(&(arm_name, value));
        assert_eq!(owned.as_bytes(), borrowed.as_bytes());
        assert_eq!(
            &owned.as_bytes()[..16],
            &[3, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&owned.as_bytes()[16..], expected.to_le_bytes());
        assert_eq!(aligned.as_ne_bytes(), expected.to_ne_bytes());
        assert_eq!(value.as_u128(), expected);
    }
    let value = HvRegisterValue::from(0xfedcba98765432100123456789abcdefu128);
    assert_eq!(value.as_u64(), 0x0123456789abcdef);
    assert_eq!(value.as_u32(), 0x89abcdef);
    assert_eq!(value.as_u16(), 0xcdef);
    assert_eq!(value.as_u8(), 0xef);
    let intercept = HvX64RegisterAccessInfo::new_source_value(value);
    assert_eq!(intercept.as_bytes(), value.as_bytes());
}

// Test: Serialize segment and descriptor-table register values in both conversion directions.
// Expected: Architectural fields occupy their specified bytes without truncating high addresses.
#[test]
fn segment_and_table_register_values_match_the_hypercall_abi() {
    let segment = HvX64SegmentRegister {
        base: 0x1122334455667788,
        limit: 0xaabbccdd,
        selector: 0x1234,
        attributes: 0xabcd,
    };
    let bytes = [
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xdd, 0xcc, 0xbb, 0xaa, 0x34, 0x12, 0xcd,
        0xab,
    ];
    let value = HvRegisterValue::from(segment);
    assert_eq!(value.as_bytes(), &bytes);
    assert_eq!(value.as_segment(), segment);
    assert_eq!(
        HvX64SegmentRegister::from(HvRegisterValue::read_from_bytes(&bytes).unwrap()),
        segment
    );
    let table = HvX64TableRegister {
        pad: [0; 3],
        limit: 0x1234,
        base: 0x1122334455667788,
    };
    let bytes = [
        0, 0, 0, 0, 0, 0, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];
    let value = HvRegisterValue::from(table);
    assert_eq!(value.as_bytes(), &bytes);
    assert_eq!(value.as_table(), table);
    assert_eq!(
        HvX64TableRegister::from(HvRegisterValue::read_from_bytes(&bytes).unwrap()),
        table
    );
}

fn segment(selector: u16) -> HvX64SegmentRegister {
    HvX64SegmentRegister {
        base: u64::from(selector) << 32,
        limit: 0xfffff,
        selector,
        attributes: 0xc093,
    }
}

// Test: Expand a nonuniform startup context into the VP register-write list.
// Expected: Every startup field appears once under the correct register name with zero padding.
#[test]
fn initial_x64_context_expands_every_field_into_its_matching_register() {
    let context = hypercall::InitialVpContextX64 {
        rip: 0x1000,
        rsp: 0x2000,
        rflags: 0x202,
        cs: segment(8),
        ds: segment(16),
        es: segment(24),
        fs: segment(32),
        gs: segment(40),
        ss: segment(48),
        tr: segment(56),
        ldtr: segment(64),
        idtr: HvX64TableRegister {
            pad: [0; 3],
            limit: 0x7ff,
            base: 0x3000,
        },
        gdtr: HvX64TableRegister {
            pad: [0; 3],
            limit: 0x3ff,
            base: 0x4000,
        },
        efer: 0x500,
        cr0: 0x80010033,
        cr3: 0x5000,
        cr4: 0x620,
        msr_cr_pat: 0x0007040600070406,
    };
    use HvX64RegisterName as R;
    let expected: [(HvX64RegisterName, HvRegisterValue); 18] = [
        (R::Rip, 0x1000u64.into()),
        (R::Rsp, 0x2000u64.into()),
        (R::Rflags, 0x202u64.into()),
        (R::Cs, segment(8).into()),
        (R::Ds, segment(16).into()),
        (R::Es, segment(24).into()),
        (R::Fs, segment(32).into()),
        (R::Gs, segment(40).into()),
        (R::Ss, segment(48).into()),
        (R::Tr, segment(56).into()),
        (R::Ldtr, segment(64).into()),
        (R::Idtr, context.idtr.into()),
        (R::Gdtr, context.gdtr.into()),
        (R::Efer, 0x500u64.into()),
        (R::Cr0, 0x80010033u64.into()),
        (R::Cr3, 0x5000u64.into()),
        (R::Cr4, 0x620u64.into()),
        (R::Pat, 0x0007040600070406u64.into()),
    ];
    let actual: Vec<_> = context.as_hv_register_assocs().collect();
    assert_eq!(actual.len(), expected.len());
    for (actual, (name, value)) in actual.iter().zip(expected) {
        assert_eq!(actual.name, HvRegisterName::from(name));
        assert_eq!(actual.pad, [0; 3]);
        assert_eq!(actual.value, value);
    }
}
