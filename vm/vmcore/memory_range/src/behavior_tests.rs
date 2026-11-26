// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;

use crate::MemoryRange;
use crate::RangeWalkResult;
use crate::walk_ranges;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use test_with_tracing::test;

// Test: Align the final representable 4KB page inward to a 2MB boundary.
// Expected: No aligned subrange fits, so the result is empty without overflowing address arithmetic.
#[test]
#[ignore = "product bug: aligned_subrange overflows rounding up near MAX_ADDRESS"]
fn highest_address_inward_alignment_returns_empty() {
    let range = MemoryRange::new(MemoryRange::MAX_ADDRESS - 4096..MemoryRange::MAX_ADDRESS);
    assert_eq!(range.aligned_subrange(2 * 1024 * 1024), MemoryRange::EMPTY);
}

// Test: Construct checked byte/page/native ranges at valid and invalid boundaries and address bytes immediately before, within and after a two-page range.
// Expected: Invalid alignment/order is rejected, conversions preserve endpoints, and membership/offsets obey half-open byte semantics.
#[test]
fn checked_construction_and_byte_membership_preserve_boundaries() {
    for raw in [
        0..0,
        4096..12288,
        MemoryRange::MAX_ADDRESS - 4096..MemoryRange::MAX_ADDRESS,
    ] {
        let range = MemoryRange::try_new(raw.clone()).unwrap();
        assert_eq!(core::ops::Range::<u64>::from(range), raw);
        assert_eq!(MemoryRange::try_from(raw).unwrap(), range);
        assert_eq!(
            MemoryRange::from_4k_gpn_range(range.start_4k_gpn()..range.end_4k_gpn()),
            range
        );
    }
    assert_eq!(
        MemoryRange::try_from(4096usize..12288usize).unwrap(),
        MemoryRange::new(4096..12288)
    );
    for (start, end) in [(1, 4096), (0, 4097), (8192, 4096)] {
        let raw = start..end;
        assert!(MemoryRange::try_new(raw.clone()).is_err());
        assert!(MemoryRange::try_from(raw).is_err());
    }
    assert!(MemoryRange::try_from(1usize..4096usize).is_err());
    let range = MemoryRange::new(4096..12288);
    for (address, offset) in [
        (4095, None),
        (4096, Some(0)),
        (12287, Some(8191)),
        (12288, None),
    ] {
        assert_eq!(range.offset_of(address), offset);
        assert_eq!(range.contains_addr(address), offset.is_some());
    }
    assert_eq!(range.len(), 8192);
    assert_eq!(range.page_count_4k(), 2);
    assert_eq!(range.page_count_2m(), 1);
    assert_eq!(format!("{range}"), "0x1000-0x3000");
    assert_eq!(
        range.split_at_offset(4096),
        (MemoryRange::new(4096..8192), MemoryRange::new(8192..12288))
    );
    assert_eq!(
        range.split_at_offset(0),
        (MemoryRange::new(4096..4096), range)
    );
    assert_eq!(
        range.split_at_offset(8192),
        (range, MemoryRange::new(12288..12288))
    );
}

// Test: Bound unaligned bytes outward and select aligned pages inward, then intersect contained, touching and disjoint ranges.
// Expected: Outward alignment retains every input byte, inward alignment never extends the input, and intersections contain exactly shared bytes.
#[test]
fn alignment_and_intersection_respect_containment() {
    assert_eq!(
        MemoryRange::bounding(0x1234..0x3456),
        MemoryRange::new(0x1000..0x4000)
    );
    assert_eq!(
        MemoryRange::bounding_aligned(0x1234..0x3456, 0x200000),
        MemoryRange::new(0..0x200000)
    );
    let range = MemoryRange::new(0x1000..0x10000);
    assert_eq!(
        range.aligned_subrange(0x2000),
        MemoryRange::new(0x2000..0x10000)
    );
    assert_eq!(
        MemoryRange::new(0x1000..0x2000).aligned_subrange(0x4000),
        MemoryRange::EMPTY
    );
    for (other, expected, overlaps, contains) in [
        (0x2000..0x4000, 0x2000..0x4000, true, true),
        (0..0x2000, 0x1000..0x2000, true, false),
        (0x10000..0x11000, 0x10000..0x10000, false, false),
        (0x20000..0x21000, 0..0, false, false),
    ] {
        let other = MemoryRange::new(other);
        assert_eq!(range.intersection(&other), MemoryRange::new(expected));
        assert_eq!(range.overlaps(&other), overlaps);
        assert_eq!(range.contains(&other), contains);
    }
}

// Test: Walk all pairs of four-page membership bitmaps at zero and the final representable address, including empty entries and tags on each side.
// Expected: Nonempty output exactly partitions the address domain, classifies every page independently, preserves side-specific tags, and labels all outside gaps Neither.
#[test]
fn tagged_range_walk_matches_independent_page_membership() {
    for base in [0, MemoryRange::MAX_ADDRESS / 4096 - 4] {
        for left_mask in 0u8..16 {
            for right_mask in 0u8..16 {
                let ranges = |mask, tag| {
                    let mut ranges = vec![(MemoryRange::EMPTY, tag)];
                    for page in 0..4 {
                        if mask & (1 << page) != 0 {
                            ranges.push((
                                MemoryRange::from_4k_gpn_range(base + page..base + page + 1),
                                tag,
                            ));
                        }
                    }
                    ranges.push((
                        MemoryRange::new(MemoryRange::MAX_ADDRESS..MemoryRange::MAX_ADDRESS),
                        tag,
                    ));
                    ranges
                };
                let output: Vec<_> =
                    walk_ranges(ranges(left_mask, "left"), ranges(right_mask, "right")).collect();
                let mut end = 0;
                for (range, kind) in &output {
                    assert_eq!(range.start(), end);
                    assert!(!range.is_empty());
                    end = range.end();
                    if range.end_4k_gpn() <= base || range.start_4k_gpn() >= base + 4 {
                        assert_eq!(*kind, RangeWalkResult::Neither);
                    }
                }
                assert_eq!(end, MemoryRange::MAX_ADDRESS);
                for page in 0..4 {
                    let expected =
                        match (left_mask & (1 << page) != 0, right_mask & (1 << page) != 0) {
                            (false, false) => RangeWalkResult::Neither,
                            (true, false) => RangeWalkResult::Left("left"),
                            (false, true) => RangeWalkResult::Right("right"),
                            (true, true) => RangeWalkResult::Both("left", "right"),
                        };
                    let matches: Vec<_> = output
                        .iter()
                        .filter(|(range, _)| range.contains_addr((base + page) * 4096 + 17))
                        .collect();
                    assert_eq!(matches.len(), 1);
                    assert_eq!(matches[0].1, expected);
                }
            }
        }
    }
}
