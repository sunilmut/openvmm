// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn registers(result: CpuidResult) -> [u32; 4] {
    [result.eax, result.ebx, result.ecx, result.edx]
}

// Test: Serialize distinct 128-bit feature/enlightenment patterns and several CPU limits.
// Expected: Low-to-high words map to EAX/EBX/ECX/EDX without feature-leaf swaps, and both CPU limit fields preserve the requested count.
#[test]
fn standard_feature_leaves_preserve_register_word_order_and_cpu_limits() {
    for count in [0, 1, 4096] {
        let leaves = make_hv_cpuid_leaves(
            HvFeatures::from_bits(0xfedc_ba98_7654_3210_89ab_cdef_0123_4567),
            HvEnlightenmentInformation::from_bits(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            count,
        );
        assert_eq!(leaves[0].0.0, hvdef::HV_CPUID_FUNCTION_MS_HV_FEATURES);
        assert_eq!(
            registers(leaves[0].1),
            [0x0123_4567, 0x89ab_cdef, 0x7654_3210, 0xfedc_ba98]
        );
        assert_eq!(
            leaves[1].0.0,
            hvdef::HV_CPUID_FUNCTION_MS_HV_ENLIGHTENMENT_INFORMATION
        );
        assert_eq!(
            registers(leaves[1].1),
            [0xddee_ff00, 0x99aa_bbcc, 0x5566_7788, 0x1122_3344]
        );
        assert_eq!(
            leaves[2].0.0,
            hvdef::HV_CPUID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS
        );
        assert_eq!(registers(leaves[2].1), [count, count, 0, 0]);
    }
}

// Test: Serialize isolated hardware-feature and configuration leaves with different values in every register word.
// Expected: Each leaf retains its identity and every high/low input bit in architectural register order.
#[test]
fn isolated_feature_leaves_preserve_identity_and_all_register_bits() {
    let leaves = make_isolated_hv_cpuid_leaves(
        HvHardwareFeatures::from_bits(0xfedc_ba98_7654_3210_89ab_cdef_0123_4567),
        HvIsolationConfiguration::from_bits(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
    );
    assert_eq!(
        leaves[0].0.0,
        hvdef::HV_CPUID_FUNCTION_MS_HV_HARDWARE_FEATURES
    );
    assert_eq!(
        registers(leaves[0].1),
        [0x0123_4567, 0x89ab_cdef, 0x7654_3210, 0xfedc_ba98]
    );
    assert_eq!(
        leaves[1].0.0,
        hvdef::HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION
    );
    assert_eq!(
        registers(leaves[1].1),
        [0xddee_ff00, 0x99aa_bbcc, 0x5566_7788, 0x1122_3344]
    );
}

// Test: Process hypervisor leaves with isolation visible and hidden alongside unrelated CPUID namespaces.
// Expected: Vendor/interface/version data are exact, only hidden HV extensions disappear, and applying the feature mask clears isolation without changing supported features.
#[test]
fn isolation_hiding_filters_only_hypervisor_extensions_and_isolation_privilege() {
    let features = SUPPORTED_FEATURES.with_privileges(SUPPORTED_PRIVILEGES.with_isolation(true));
    let feature_leaves = make_hv_cpuid_leaves(features, HvEnlightenmentInformation::new(), 4);
    for hide in [false, true] {
        let mut leaves: Vec<_> = feature_leaves
            .iter()
            .map(|(function, result)| CpuidLeaf::new(function.0, registers(*result)))
            .collect();
        for function in [
            7,
            0x5000_0000,
            u32::MAX,
            hvdef::HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION,
            0x4fff_ffff,
        ] {
            leaves.push(CpuidLeaf::new(function, [1, 2, 3, 4]));
        }
        process_hv_cpuid_leaves(&mut leaves, hide, [10, 20, 30, 40]);
        let vendor = leaves
            .iter()
            .find(|leaf| leaf.function == hvdef::HV_CPUID_FUNCTION_HV_VENDOR_AND_MAX_FUNCTION)
            .unwrap();
        assert_eq!(
            vendor.result,
            [
                if hide {
                    hvdef::HV_CPUID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS
                } else {
                    hvdef::HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION
                },
                u32::from_le_bytes(*b"Micr"),
                u32::from_le_bytes(*b"osof"),
                u32::from_le_bytes(*b"t Hv"),
            ]
        );
        assert_eq!(
            leaves
                .iter()
                .find(|leaf| leaf.function == hvdef::HV_CPUID_FUNCTION_HV_INTERFACE)
                .unwrap()
                .result,
            [u32::from_le_bytes(*b"Hv#1"), 0, 0, 0]
        );
        assert_eq!(
            leaves
                .iter()
                .find(|leaf| leaf.function == hvdef::HV_CPUID_FUNCTION_MS_HV_VERSION)
                .unwrap()
                .result,
            [10, 20, 30, 40]
        );
        for function in [7, 0x5000_0000, u32::MAX] {
            assert_eq!(
                leaves
                    .iter()
                    .find(|leaf| leaf.function == function)
                    .unwrap()
                    .result,
                [1, 2, 3, 4]
            );
        }
        for function in [
            hvdef::HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION,
            0x4fff_ffff,
        ] {
            assert_eq!(leaves.iter().any(|leaf| leaf.function == function), !hide);
        }
        let actual = virt::CpuidLeafSet::new(leaves).result(
            hvdef::HV_CPUID_FUNCTION_MS_HV_FEATURES,
            0,
            &[0; 4],
        );
        let expected = if hide { SUPPORTED_FEATURES } else { features }.into_bits();
        assert_eq!(
            actual,
            [
                expected as u32,
                (expected >> 32) as u32,
                (expected >> 64) as u32,
                (expected >> 96) as u32,
            ]
        );
    }
}
