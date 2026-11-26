// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public VMRS memory streaming, padding and source failure behavior.

use hvs_file::reader::HvsFileReader;
use hyperv_dump::GuestMemoryReader;
use hyperv_dump::PartitionStateBuilder;
use hyperv_dump::ProcessorArch;
use hyperv_dump::VmrsWriter;
use memory_range::MemoryRange;
use std::io;
use std::io::Cursor;
use test_with_tracing::test;

const BLOCK: u64 = 1024 * 1024;
const HIGH_GPA: u64 = 0x1_0000_2000;

struct RangeReader;

impl GuestMemoryReader for RangeReader {
    fn read_gpa(&mut self, gpa: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = gpa.checked_add(buf.len() as u64).unwrap();
        let fill = if end <= BLOCK + 4096 {
            0x5c
        } else if gpa >= HIGH_GPA && end <= HIGH_GPA + 4096 {
            0xa7
        } else {
            return Err(io::Error::other("read outside declared guest RAM"));
        };
        assert!(buf.len() <= BLOCK as usize);
        buf.fill(fill);
        Ok(())
    }
}

// Test: Stream a full block plus a page, followed by a disjoint high-GPA page.
// Expected: Both partial blocks retain full uncompressed size with zero tails,
//       and the next range starts after two allocated block slots, not 257 pages.
#[test]
fn partial_blocks_are_zero_padded_and_next_range_uses_full_block_slots() {
    let partition = PartitionStateBuilder::new(ProcessorArch::X64).finish();
    let mut writer = VmrsWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.add_memory_range(MemoryRange::new(0..BLOCK + 4096));
    writer.add_memory_range(MemoryRange::new(HIGH_GPA..HIGH_GPA + 4096));
    let file = writer.finish(&partition, &mut RangeReader).unwrap();
    let mut reader = HvsFileReader::open(file).unwrap();
    let full = reader.read_array("/savedstate/RamBlock0").unwrap();
    assert_eq!(full, vec![0x5c; BLOCK as usize]);
    for (index, fill) in [(1, 0x5c), (2, 0xa7)] {
        let data = reader
            .read_array(&format!("/savedstate/RamBlock{index}"))
            .unwrap();
        assert_eq!(data.len(), BLOCK as usize);
        assert_eq!(data[..4096], [fill; 4096]);
        assert!(data[4096..].iter().all(|&b| b == 0));
    }
    let first = reader.read_array("/savedstate/RamMemoryBlock0").unwrap();
    let second = reader.read_array("/savedstate/RamMemoryBlock1").unwrap();
    let word =
        |bytes: &[u8], offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    assert_eq!(word(&first, 8), 257);
    assert_eq!(word(&first, 16), 0);
    assert_eq!(word(&second, 8), 1);
    assert_eq!(word(&second, 16), 512);
    assert_eq!(word(&second, 24), HIGH_GPA / 4096);
}

struct FaultingReader;

impl GuestMemoryReader for FaultingReader {
    fn read_gpa(&mut self, gpa: u64, buf: &mut [u8]) -> io::Result<()> {
        if gpa == 0 {
            buf.fill(0x38);
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unreadable guest page",
        ))
    }
}

// Test: Fail guest-memory access after a successful streamed block.
// Expected: Dump completion fails with the memory source's error instead of
//       silently substituting zeroes or acknowledging a complete dump.
#[test]
fn midstream_guest_memory_error_fails_dump_completion() {
    let partition = PartitionStateBuilder::new(ProcessorArch::X64).finish();
    let mut writer = VmrsWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.add_memory_range(MemoryRange::new(0..2 * BLOCK));
    let error = writer.finish(&partition, &mut FaultingReader).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(error.to_string().contains("unreadable guest page"));
}
