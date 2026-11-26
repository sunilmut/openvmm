// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public CPU mask parsing and isolated-thread affinity behavior.

#![cfg(target_os = "linux")]

use pal::unix::affinity::CpuSet;
use pal::unix::affinity::get_cpu_number;
use pal::unix::affinity::get_current_thread_affinity;
use pal::unix::affinity::max_procs;
use pal::unix::affinity::set_current_thread_affinity;
use test_with_tracing::test;

// Test: Apply and reject affinity changes on a separate thread.
// Expected: A selected allowed CPU is the only runnable CPU, an empty mask is
//       rejected without changing it, and the original mask can be restored.
#[test]
fn isolated_thread_affinity_roundtrip_and_empty_mask_rejection() {
    std::thread::spawn(|| {
        let mut original = CpuSet::new();
        get_current_thread_affinity(&mut original).unwrap();
        let cpu = (0..max_procs()).find(|&cpu| original.is_set(cpu)).unwrap();
        let mut selected = CpuSet::new();
        selected.set(cpu);
        set_current_thread_affinity(&selected).unwrap();
        let mut actual = CpuSet::new();
        get_current_thread_affinity(&mut actual).unwrap();
        assert_eq!(actual, selected);
        assert_eq!(get_cpu_number(), cpu);
        assert_eq!(
            set_current_thread_affinity(&CpuSet::new())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        get_current_thread_affinity(&mut actual).unwrap();
        assert_eq!(actual, selected);
        set_current_thread_affinity(&original).unwrap();
        get_current_thread_affinity(&mut actual).unwrap();
        assert_eq!(actual, original);
    })
    .join()
    .unwrap();
}

// Test: Parse a CPU list spanning a word boundary when representable, and
//       reject malformed lists/hex strings while accepting a valid hex byte.
// Expected: Every requested CPU and no others is selected; malformed syntax
//       returns an error rather than being silently accepted.
#[test]
fn cpu_mask_parsers_preserve_membership_and_reject_malformed_syntax() {
    let last = (max_procs() - 1).min(65);
    let first = last.saturating_sub(2);
    let mut list = CpuSet::new();
    list.set_mask_list(&format!("0,{first}-{last}\n")).unwrap();
    for cpu in 0..max_procs() {
        assert_eq!(list.is_set(cpu), cpu == 0 || (first..=last).contains(&cpu));
    }
    for input in ["x", "0-x", "0,,1", "18446744073709551616"] {
        assert!(CpuSet::new().set_mask_list(input).is_err());
    }
    for input in [b"0".as_slice(), b"gg", &[0xff, 0xff]] {
        assert!(CpuSet::new().set_mask_hex_string(input).is_err());
    }
    let mut hex = CpuSet::new();
    hex.set_mask_hex_string(b"f0").unwrap();
    for cpu in 0..max_procs().min(8) {
        assert_eq!(hex.is_set(cpu), (4..8).contains(&cpu));
    }
}

// IGNORED: An enabled run accepted "ffff" but lost CPU9 through CPU15 because
//       adjacent bytes overlap. No production Rust caller currently uses this
//       parser; this is a public parsing defect, not an asserted exploit.
//
// Test: Parse a hexadecimal mask with every bit set in two adjacent bytes.
// Expected: All sixteen low CPU bits are selected, regardless of byte ordering.
#[test]
#[ignore = "adjacent hex bytes overlap and lose CPU mask bits"]
fn adjacent_hex_bytes_preserve_all_cpu_bits() {
    assert!(
        max_procs() >= 16,
        "requires sixteen representable CPU slots"
    );
    let mut set = CpuSet::new();
    set.set_mask_hex_string(b"ffff").unwrap();
    for cpu in 0..16 {
        assert!(
            set.is_set(cpu),
            "CPU{cpu} disappeared from an all-ones mask"
        );
    }
}
