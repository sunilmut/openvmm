// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public numeric parser and bounded VP-list expansion regressions.

use test_with_tracing::test;
use vmm_cli::BracketRangeList;
use vmm_cli::MemorySize;

// Test: Parse the largest representable value and the first overflowing value
//       for every binary-size suffix, with and without the optional byte marker.
// Expected: Exact byte counts are retained; multiplication never wraps or
//       saturates, and malformed/non-ASCII numeric input is rejected.
#[test]
fn memory_size_overflow_boundaries() {
    assert_eq!(
        u64::MAX.to_string().parse::<MemorySize>().unwrap(),
        MemorySize(u64::MAX)
    );
    for (suffix, maximum, expected) in [
        (
            "K",
            18_014_398_509_481_983u64,
            18_446_744_073_709_550_592u64,
        ),
        ("M", 17_592_186_044_415, 18_446_744_073_708_503_040),
        ("G", 17_179_869_183, 18_446_744_072_635_809_792),
        ("T", 16_777_215, 18_446_742_974_197_923_840),
    ] {
        for bytes_marker in ["", "B"] {
            let accepted = format!("{maximum}{suffix}{bytes_marker}");
            assert_eq!(
                accepted.parse::<MemorySize>().unwrap(),
                MemorySize(expected),
                "{accepted}"
            );
            let overflowing = format!("{}{suffix}{bytes_marker}", maximum + 1);
            assert!(overflowing.parse::<MemorySize>().is_err(), "{overflowing}");
        }
    }
    for invalid in ["18446744073709551616", "B", "KB", "1KBx", "１２K", "éG"] {
        assert!(invalid.parse::<MemorySize>().is_err(), "{invalid}");
    }
}

// Test: Expand parsed VP ranges at the strict bound and combined-length limit.
// Expected: Range order and repeated values are preserved when the result fits;
//       an excessive combined count or any out-of-bound endpoint is rejected.
#[test]
fn range_expansion_checks_combined_count_and_endpoints() {
    let ordered: BracketRangeList = "[3, 1-2, 1]".parse().unwrap();
    assert_eq!(ordered.expand_below(4).unwrap(), [3, 1, 2, 1]);
    let excess: BracketRangeList = "[0-1,0-1]".parse().unwrap();
    assert!(excess.expand_below(2).is_err());
    let edge: BracketRangeList = "[4294967294]".parse().unwrap();
    assert_eq!(edge.expand_below(u32::MAX).unwrap(), [u32::MAX - 1]);
    for value in ["[4294967295]", "[4294967294-4294967295]"] {
        let list: BracketRangeList = value.parse().unwrap();
        assert!(list.expand_below(u32::MAX).is_err());
    }
    for invalid in ["[4294967296]", "[1-0]", "[0-4294967296]"] {
        assert!(invalid.parse::<BracketRangeList>().is_err(), "{invalid}");
    }
}
