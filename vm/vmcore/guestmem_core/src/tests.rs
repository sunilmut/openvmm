// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AccessError;
use crate::GuestMemoryBackingError;
use crate::GuestMemoryError;
use crate::GuestMemoryErrorKind;
use crate::GuestMemoryOperation;
use crate::MemoryRead;
use crate::MemoryWrite;
use crate::PAGE_SIZE;
use crate::PageFaultError;
use crate::gpn_to_gpa;
use crate::ranges::AddressRange;
use crate::ranges::PagedRange;
use crate::ranges::PagedRanges;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::error::Error;

// Test: Read typed values and then consume the remaining byte stream.
// Expected: Reads advance by their byte lengths and return the original bytes.
#[test]
fn sequential_reads_preserve_values_and_cursor() {
    let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut reader = bytes.as_slice();
    assert_eq!(reader.read_plain::<[u8; 2]>().unwrap(), [1, 2]);
    reader.skip(1).unwrap();
    assert_eq!(reader.read_n::<[u8; 2]>(2).unwrap(), [[4, 5], [6, 7]]);
    assert_eq!(reader.read_all().unwrap(), [8]);
    assert!(reader.read_all().unwrap().is_empty());
}

// Test: Attempt reads and skips beyond a slice, followed by a valid read.
// Expected: Failed operations leave both the output and read position unchanged.
#[test]
fn failed_slice_reads_do_not_consume_or_overwrite() {
    let mut reader = [1u8, 2].as_slice();
    let mut output = [0x55; 3];
    assert!(matches!(
        reader.read(&mut output),
        Err(AccessError::OutOfRange(2, 3))
    ));
    assert_eq!(output, [0x55; 3]);
    assert!(matches!(reader.skip(3), Err(AccessError::OutOfRange(2, 3))));
    assert!(reader.read_plain::<u32>().is_err());
    assert!(reader.read_n::<u32>(1).is_err());
    assert_eq!(reader.read_all().unwrap(), [1, 2]);
}

// Test: Cap a reader, reject oversized operations, and consume its exact budget.
// Expected: Limits clamp to available data and rejected operations preserve bytes.
#[test]
fn limited_reads_enforce_the_remaining_budget() {
    let bytes = [1u8, 2, 3, 4, 5];
    let mut reader = MemoryRead::limit(bytes.as_slice(), 4);
    assert_eq!(reader.len(), 4);
    assert!(matches!(
        reader.read(&mut [0; 5]),
        Err(AccessError::OutOfRange(4, 5))
    ));
    assert!(matches!(reader.skip(5), Err(AccessError::OutOfRange(4, 5))));
    reader.skip(1).unwrap();
    assert_eq!(reader.read_all().unwrap(), [2, 3, 4]);
    assert_eq!(reader.len(), 0);
    assert_eq!(
        MemoryRead::limit(bytes.as_slice(), 20).read_all().unwrap(),
        bytes
    );
}

// Test: Write, fill, and zero adjacent regions through a slice writer.
// Expected: Operations advance without changing bytes outside their region.
#[test]
fn sequential_writes_fill_and_zero_the_requested_regions() {
    let mut bytes = [0xffu8; 8];
    let mut writer = bytes.as_mut_slice();
    writer.write(&[1, 2]).unwrap();
    MemoryWrite::fill(&mut writer, 0x33, 2).unwrap();
    writer.zero(2).unwrap();
    assert_eq!(MemoryWrite::len(&writer), 2);
    writer.write(&[]).unwrap();
    assert_eq!(bytes, [1, 2, 0x33, 0x33, 0, 0, 0xff, 0xff]);
}

// Test: Reject oversized writes and fills before accepting an exact-size write.
// Expected: Rejected operations change neither the destination nor its cursor.
#[test]
fn failed_slice_writes_are_non_destructive() {
    let mut bytes = [0xffu8; 2];
    let mut writer = bytes.as_mut_slice();
    assert!(matches!(
        writer.write(&[1, 2, 3]),
        Err(AccessError::OutOfRange(2, 3))
    ));
    assert!(matches!(
        MemoryWrite::fill(&mut writer, 0, 3),
        Err(AccessError::OutOfRange(2, 3))
    ));
    writer.write(&[3, 4]).unwrap();
    assert_eq!(bytes, [3, 4]);
}

// Test: Use a byte-limited writer with rejected, partial, and exact operations.
// Expected: Only bytes within the cap change and failed operations spend no budget.
#[test]
fn limited_writes_protect_the_tail() {
    let mut bytes = [0xffu8; 7];
    let mut writer = MemoryWrite::limit(bytes.as_mut_slice(), 4);
    assert_eq!(writer.len(), 4);
    assert!(matches!(
        writer.write(&[0; 5]),
        Err(AccessError::OutOfRange(4, 5))
    ));
    assert!(matches!(
        writer.fill(0, 5),
        Err(AccessError::OutOfRange(4, 5))
    ));
    writer.write(&[1, 2]).unwrap();
    writer.fill(3, 2).unwrap();
    assert_eq!(writer.len(), 0);
    assert_eq!(bytes, [1, 2, 3, 3, 0xff, 0xff, 0xff]);
    MemoryWrite::limit(bytes.as_mut_slice(), 20)
        .zero(7)
        .unwrap();
    assert_eq!(bytes, [0; 7]);
}

// Test: Split an unaligned range and then skip and truncate its tail.
// Expected: Iterated addresses retain page offsets and exclude discarded bytes.
#[test]
fn range_splitting_and_trimming_preserve_guest_addresses() {
    let gpns = [4, 5, 9];
    let range = PagedRange::new(100, 2 * PAGE_SIZE, &gpns).unwrap();
    let (head, mut tail) = range.split(PAGE_SIZE - 100);
    assert_eq!(
        head.ranges().next().unwrap().unwrap(),
        AddressRange::from(16484..20480)
    );
    tail.skip(10);
    tail.truncate(20);
    assert_eq!(tail.offset(), 10);
    assert_eq!(tail.gpns(), [5]);
    assert_eq!(
        tail.ranges().next().unwrap().unwrap(),
        AddressRange::from(20490..20510)
    );
    let (empty, entire) = range.try_split(0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(entire.len(), range.len());
    assert!(range.try_split(range.len() + 1).is_none());
    assert!(range.try_subrange(range.len(), 1).is_none());
    assert!(range.try_subrange(range.len() + 1, 0).is_none());
    assert!(PagedRange::empty().ranges().next().is_none());
}

// Test: Split exactly at the range end and take a page-crossing subrange.
// Expected: The end split is empty and the subrange reports both guest pages.
#[test]
fn checked_ranges_handle_end_and_page_boundaries() {
    let range = PagedRange::new(10, PAGE_SIZE + 20, &[4, 9]).unwrap();
    let (head, tail) = range.try_split(range.len()).unwrap();
    assert_eq!(head.len(), range.len());
    assert!(tail.is_empty());
    let middle = range.subrange(PAGE_SIZE - 20, 30);
    assert_eq!(middle.offset(), PAGE_SIZE - 10);
    assert_eq!(middle.gpns(), [4, 9]);
    let ranges = middle.ranges().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(
        ranges,
        [
            AddressRange::from(20470..20480),
            AddressRange::from(36864..36884)
        ]
    );
    assert_eq!(ranges[0].len(), 10);
    assert!(!ranges[0].is_empty());
    assert!(AddressRange::from(4..4).is_empty());
}

// Test: Ask for an out-of-bounds subrange.
// Expected: The checked convenience method panics with an invalid-subrange message.
#[test]
#[should_panic(expected = "invalid subrange")]
fn invalid_subrange_panics() {
    PagedRange::empty().subrange(0, 1);
}

// Test: Iterate a page number that cannot be represented as a guest address.
// Expected: Iteration reports an invalid-GPN error instead of wrapping the address.
#[test]
fn invalid_guest_page_reports_an_error() {
    let gpns = [u64::MAX / PAGE_SIZE as u64 + 1];
    assert!(gpn_to_gpa(gpns[0]).is_err());
    let range = PagedRange::new(0, 1, &gpns).unwrap();
    let err = range.ranges().next().unwrap().unwrap_err();
    let backing = GuestMemoryBackingError::gpn(err);
    let error = GuestMemoryError::new(
        &Arc::from("test"),
        None,
        GuestMemoryOperation::Read,
        backing,
    );
    assert_eq!(error.kind(), GuestMemoryErrorKind::OutOfRange);
    assert_eq!(
        error.to_string(),
        "guest memory 'test': read error: failed to access memory"
    );
}

// Test: Skip across a range boundary before truncating a discontiguous buffer.
// Expected: Iteration includes only the retained addresses, in logical order.
#[test]
fn multiple_ranges_skip_across_discontiguous_pages() {
    let first = PagedRange::new(20, 10, &[3]).unwrap();
    let second = PagedRange::new(40, 30, &[8]).unwrap();
    let mut ranges = PagedRanges::new([first, second]);
    ranges.skip(15);
    ranges.truncate(5);
    let result = ranges
        .paged_ranges()
        .flat_map(|r| r.ranges())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(result, [AddressRange::from(32813..32818)]);
}

// Test: Wrap memory failures with ranges and precise fault addresses.
// Expected: Diagnostics retain the operation, error kind, and underlying source.
#[test]
fn memory_errors_preserve_fault_context() {
    let name = Arc::from("ram");
    for (range, gpa, suffix) in [
        (Some(0x100..0x200), 0x100, "0x100-0x200"),
        (Some(0x100..0x200), 0x180, "0x100-0x200 at 0x180"),
        (None, 0x180, "memory at 0x180"),
    ] {
        let error = GuestMemoryError::new(
            &name,
            range,
            GuestMemoryOperation::Write,
            GuestMemoryBackingError::new(GuestMemoryErrorKind::VtlProtected, gpa, "protected"),
        );
        assert_eq!(error.kind(), GuestMemoryErrorKind::VtlProtected);
        assert_eq!(
            error.to_string(),
            alloc::format!("guest memory 'ram': write error: failed to access {suffix}")
        );
        assert_eq!(error.source().unwrap().to_string(), "protected");
    }
}

// Test: Report failures for each memory operation through the public error type.
// Expected: Diagnostics name the failed operation without losing the root cause.
#[test]
fn memory_errors_identify_each_operation() {
    for (op, text) in [
        (GuestMemoryOperation::Read, "read"),
        (GuestMemoryOperation::Fill, "fill"),
        (GuestMemoryOperation::CompareExchange, "compare exchange"),
        (GuestMemoryOperation::Lock, "lock"),
        (GuestMemoryOperation::Subrange, "subrange"),
        (GuestMemoryOperation::Probe, "probe"),
    ] {
        let error = GuestMemoryError::new(
            &Arc::from("ram"),
            None,
            op,
            GuestMemoryBackingError::other(0, "backing failed"),
        );
        assert_eq!(error.kind(), GuestMemoryErrorKind::Other);
        assert!(
            error
                .to_string()
                .contains(&alloc::format!(": {text} error:"))
        );
        let access = AccessError::from(error);
        assert_eq!(
            access.source().unwrap().source().unwrap().to_string(),
            "backing failed"
        );
    }
}

// Test: Construct explicit and uncategorized page-fault failures.
// Expected: Callers receive the supplied reason and the appropriate error category.
#[test]
fn page_fault_errors_retain_their_reason() {
    let error = PageFaultError::new(GuestMemoryErrorKind::NotShared, "private page");
    assert_eq!(error.kind, GuestMemoryErrorKind::NotShared);
    assert_eq!(error.err.to_string(), "private page");
    let error = PageFaultError::other("unavailable");
    assert_eq!(error.kind, GuestMemoryErrorKind::Other);
    assert_eq!(error.err.to_string(), "unavailable");
}

// Test: Apply successive skips and every valid truncation to a scatter/gather
//       buffer with empty segments, page crossings, and independent offsets.
// Expected: Every retained window yields exactly its original guest addresses,
//       without including gaps or losing bytes at segment and page boundaries.
#[test]
fn scatter_gather_windows_preserve_the_logical_byte_sequence() {
    let segments = [
        PagedRange::empty(),
        PagedRange::new(PAGE_SIZE - 2, 4, &[4, 9]).unwrap(),
        PagedRange::empty(),
        PagedRange::new(7, 3, &[12]).unwrap(),
        PagedRange::new(PAGE_SIZE - 1, 5, &[1, 7]).unwrap(),
        PagedRange::empty(),
    ];
    let page = PAGE_SIZE as u64;
    let expected = [
        5 * page - 2,
        5 * page - 1,
        9 * page,
        9 * page + 1,
        12 * page + 7,
        12 * page + 8,
        12 * page + 9,
        2 * page - 1,
        7 * page,
        7 * page + 1,
        7 * page + 2,
        7 * page + 3,
    ];

    for start in 0..=expected.len() {
        for len in 0..=expected.len() - start {
            let mut ranges = PagedRanges::new(segments);
            ranges.skip(start / 2);
            ranges.skip(start - start / 2);
            ranges.truncate(len);
            let addresses = ranges
                .paged_ranges()
                .flat_map(PagedRange::ranges)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .flat_map(|range| range.start..range.end)
                .collect::<Vec<_>>();
            assert_eq!(
                addresses,
                expected[start..start + len],
                "start={start}, len={len}"
            );
        }
    }
}
