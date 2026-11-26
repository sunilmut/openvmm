// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::HeapProfiler;
use std::hint::black_box;
use test_with_tracing::test;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

// Test: Repeatedly capture sessions with allocations spanning a restart.
// Expected: Each capture is valid heap-profile JSON containing its own
//       allocations, not earlier totals; dropping permits a fresh session.
#[test]
fn captures_reset_allocation_totals_and_release_the_profiler() {
    let output = std::path::Path::new("dhat-heap.json");
    assert!(
        !output.exists(),
        "refusing to overwrite an existing profile"
    );
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file("dhat-heap.json");
        }
    }
    let _cleanup = Cleanup;
    let mut profiler = HeapProfiler::new();
    let first = black_box(vec![0x59; 1_048_583]);
    let first_capture = profiler.capture_and_restart();
    let second = black_box(vec![0xa3; 8191]);
    assert_eq!(first[0], 0x59);
    drop(first);
    let second_capture = profiler.capture_and_restart();
    assert_eq!(second[8190], 0xa3);
    drop(second);
    drop(profiler);

    let total_bytes = |capture: &[u8]| {
        let profile: serde_json::Value = serde_json::from_slice(capture).unwrap();
        assert_eq!(profile["mode"], "rust-heap");
        assert_eq!(profile["pid"].as_u64(), Some(u64::from(std::process::id())));
        profile["pps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|point| point["tb"].as_u64().unwrap())
            .sum::<u64>()
    };
    assert!(total_bytes(&first_capture) >= 1_048_583);
    let second_total = total_bytes(&second_capture);
    assert!(second_total >= 8191);
    assert!(second_total < 1_048_583, "previous session totals survived");

    let mut fresh = HeapProfiler::new();
    let allocation = black_box(vec![0x47; 16_381]);
    let capture = fresh.capture_and_restart();
    assert_eq!(allocation[16_380], 0x47);
    assert!(total_bytes(&capture) >= 16_381);
}
