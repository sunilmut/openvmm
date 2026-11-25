// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::GuestMemory;
use super::PAGE_SIZE;
use crate::MemoryRead;
use crate::MemoryWrite;
use crate::ranges::GuestMemoryView;
use crate::ranges::PagedRanges;
use test_with_tracing::test;

// Test: Stream distinct bytes into overlapping guest ranges, then gather them.
// Expected: Later writes win at aliases, reads retain range order, and guards survive.
#[test]
fn overlapping_ranges_preserve_sequential_copy_order() {
    let memory = GuestMemory::allocate(PAGE_SIZE);
    memory.fill_at(0, 0xa5, PAGE_SIZE).unwrap();
    let pages = [0];
    let first = crate::PagedRange::new(4, 6, &pages).unwrap();
    let second = crate::PagedRange::new(6, 6, &pages).unwrap();
    let mut writer = PagedRanges::new([first, second]).writer(&memory);
    writer
        .write(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        .unwrap();
    assert_eq!(writer.len(), 0);

    let mut actual = vec![0; PAGE_SIZE];
    memory.read_at(0, &mut actual).unwrap();
    let mut expected = vec![0xa5; PAGE_SIZE];
    expected[4..12].copy_from_slice(&[1, 2, 7, 8, 9, 10, 11, 12]);
    assert_eq!(actual, expected);

    let mut reader = PagedRanges::new([first, second]).reader(&memory);
    let mut gathered = [0; 12];
    reader.read(&mut gathered[..5]).unwrap();
    assert_eq!(reader.len(), 7);
    reader.read(&mut gathered[5..]).unwrap();
    assert_eq!(reader.len(), 0);
    assert_eq!(gathered, [1, 2, 7, 8, 9, 10, 7, 8, 9, 10, 11, 12]);
}

// Test: Fault on the second range after copying a valid prefix in either direction.
// Expected: Completed ranges stay consumed; retries preserve the faulting cursor and suffix.
#[test]
fn later_range_fault_retains_completed_progress() {
    let memory = GuestMemory::allocate(PAGE_SIZE);
    memory.fill_at(0, 0xa5, PAGE_SIZE).unwrap();
    memory.write_at(0, &[0x11, 0x22, 0x33, 0x44]).unwrap();
    let pages = [0, 1];
    let first = crate::PagedRange::new(0, 2, &pages[..1]).unwrap();
    let missing = crate::PagedRange::new(0, 2, &pages[1..]).unwrap();
    let last = crate::PagedRange::new(2, 2, &pages[..1]).unwrap();

    let mut reader = PagedRanges::new([first, missing, last]).reader(&memory);
    let mut output = [0xcc; 6];
    assert!(matches!(
        reader.read(&mut output),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(output, [0x11, 0x22, 0xcc, 0xcc, 0xcc, 0xcc]);
    assert_eq!(reader.len(), 4);
    assert!(matches!(
        reader.read(&mut output[2..4]),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(reader.len(), 4);
    reader.skip(2).unwrap();
    reader.read(&mut output[4..]).unwrap();
    assert_eq!(output, [0x11, 0x22, 0xcc, 0xcc, 0x33, 0x44]);
    assert_eq!(reader.len(), 0);

    let mut writer = PagedRanges::new([first, missing, last]).writer(&memory);
    assert!(matches!(
        writer.write(&[1, 2, 3, 4, 5, 6]),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(writer.len(), 4);
    assert!(matches!(
        writer.write(&[7, 8]),
        Err(crate::AccessError::Memory(_))
    ));
    assert_eq!(writer.len(), 4);
    let mut expected = vec![0xa5; PAGE_SIZE];
    expected[..4].copy_from_slice(&[1, 2, 0x33, 0x44]);
    let mut actual = vec![0; PAGE_SIZE];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
}
