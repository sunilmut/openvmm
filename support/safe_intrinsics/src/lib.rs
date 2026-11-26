// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides a safe wrapper around some CPU instructions.
//!
//! This is needed because Rust's intrinsics are marked unsafe (despite
//! these few being completely safe to invoke).

#![no_std]
// UNSAFETY: Calling a cpu intrinsic.
#![expect(unsafe_code)]

/// Invokes the cpuid instruction with input values `eax` and `ecx`.
#[cfg(target_arch = "x86_64")]
pub fn cpuid(eax: u32, ecx: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid_count(eax, ecx)
}

/// Invokes the rdtsc instruction.
#[cfg(target_arch = "x86_64")]
pub fn rdtsc() -> u64 {
    // SAFETY: The tsc is safe to read.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Emit a store fence to flush the processor's store buffer
pub fn store_fence() {
    cfg_select! {
        target_arch = "x86_64" => {
            // SAFETY: this instruction has no safety requirements.
            unsafe { core::arch::x86_64::_mm_sfence() }
        }
        target_arch = "aarch64" => {
            // SAFETY: this instruction has no safety requirements.
            unsafe { core::arch::asm!("dsb st", options(nostack)) };
        }
    }

    // Make the compiler aware.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
}

/// Read the CNTFRQ_EL0 system register, which contains the frequency of the
/// system timer in Hz. This is used to determine the frequency of the
/// system timer for the current execution level (EL0).
#[cfg(target_arch = "aarch64")]
pub fn read_cntfrq_el0() -> u64 {
    let freq: u64;
    // SAFETY: no safety requirements, just reading an EL0 sysreg
    unsafe {
        core::arch::asm!(
            "mrs {cntfrq}, cntfrq_el0",
            cntfrq = out(reg) freq,
            options(nomem, nostack, preserves_flags)
        );
    };
    freq
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))] // xtask-fmt allow-target-arch cpu-intrinsic
mod contract_tests {
    extern crate std;

    use test_with_tracing::test;

    // Test: Compare CPUID vendor registers and the decoded processor signature
    //       against the independently published Linux processor inventory.
    // Expected: Register order and leaf selection describe a real host CPU,
    //       without assuming a particular CPU vendor, model or feature set.
    #[test]
    fn cpuid_matches_linux_processor_identity() {
        let inventory = std::fs::read_to_string("/proc/cpuinfo").unwrap();
        let vendor = super::cpuid(0, 0);
        assert!(vendor.eax >= 1);
        let mut vendor_bytes = [0; 12];
        vendor_bytes[..4].copy_from_slice(&vendor.ebx.to_le_bytes());
        vendor_bytes[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
        vendor_bytes[8..].copy_from_slice(&vendor.ecx.to_le_bytes());
        let vendor_name = core::str::from_utf8(&vendor_bytes).unwrap();

        let signature = super::cpuid(1, 0).eax;
        let base_family = (signature >> 8) & 0xf;
        let family = base_family
            + if base_family == 0xf {
                (signature >> 20) & 0xff
            } else {
                0
            };
        let model = ((signature >> 4) & 0xf)
            + if matches!(base_family, 6 | 0xf) {
                ((signature >> 16) & 0xf) << 4
            } else {
                0
            };
        let stepping = signature & 0xf;

        // A heterogeneous host may expose more than one processor signature.
        assert!(inventory.split("\n\n").any(|processor| {
            let field = |name| {
                processor.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    (key.trim() == name).then_some(value.trim())
                })
            };
            let number = |name| field(name).and_then(|value| value.parse::<u32>().ok());
            field("vendor_id") == Some(vendor_name)
                && number("cpu family") == Some(family)
                && number("model") == Some(model)
                && number("stepping") == Some(stepping)
        }));
    }
}
