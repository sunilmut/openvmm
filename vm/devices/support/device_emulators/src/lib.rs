// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Utilities for implementing device emulators.

#![forbid(unsafe_code)]

/// Performs a device register read as a series of 32-bit reads.
pub fn read_as_u32_chunks<F, Num>(offset: Num, data: &mut [u8], mut read_u32: F)
where
    F: FnMut(Num) -> u32,
    Num: Into<u64> + TryFrom<u64>,
    <Num as TryFrom<u64>>::Error: std::fmt::Debug,
{
    let offset = offset.into();
    let mut next_offset = offset;
    let remaining_data = if offset & 3 != 0 {
        let val = read_u32((offset & !3).try_into().unwrap());
        let val = val.to_ne_bytes();
        let u32_offset = (offset & 3) as usize;
        let byte_count = std::cmp::min(4 - u32_offset, data.len());
        data[..byte_count].copy_from_slice(&val[u32_offset..(byte_count + u32_offset)]);
        next_offset += u64::try_from(byte_count).unwrap();
        let (_, rem) = data.split_at_mut(byte_count);
        rem
    } else {
        data
    };

    for next_chunk in remaining_data.chunks_exact_mut(4) {
        let val = read_u32(next_offset.try_into().unwrap());
        next_offset += 4;
        next_chunk.copy_from_slice(&val.to_ne_bytes());
    }
    let extra_bytes = remaining_data.chunks_exact_mut(4).into_remainder();
    if !extra_bytes.is_empty() {
        let val = read_u32(next_offset.try_into().unwrap());
        let val = val.to_ne_bytes();
        extra_bytes.copy_from_slice(&val[..extra_bytes.len()]);
    }
}

/// The request type for [`write_as_u32_chunks`].
pub enum ReadWriteRequestType {
    /// A read request.
    Read,
    /// A write request with the given value.
    Write(u32),
}

/// Performs a device register write as a series of 32-bit reads and writes.
///
/// NOTE: We read u32 and then write back when we chunk.  Because of this, the borrow checker
///       requires a single mutable closure that implements both read/write semantics.
pub fn write_as_u32_chunks<F, Num>(offset: Num, data: &[u8], mut read_write_u32: F)
where
    F: FnMut(Num, ReadWriteRequestType) -> Option<u32>,
    Num: Into<u64> + TryFrom<u64>,
    <Num as TryFrom<u64>>::Error: std::fmt::Debug,
{
    let offset = offset.into();
    let mut next_offset = offset;
    let remaining_data = if next_offset & 3 != 0 {
        let val = read_write_u32(
            (next_offset & !3).try_into().unwrap(),
            ReadWriteRequestType::Read,
        )
        .expect("Read for ReadWriteFn didn't return u32");
        let mut val = val.to_ne_bytes();
        let u32_offset = (next_offset & 3) as usize;
        let byte_count = std::cmp::min(4 - u32_offset, data.len());
        val[u32_offset..(byte_count + u32_offset)].copy_from_slice(&data[..byte_count]);
        next_offset += u64::try_from(byte_count).unwrap();
        read_write_u32(
            (offset & !3).try_into().unwrap(),
            ReadWriteRequestType::Write(u32::from_ne_bytes(val)),
        );
        let (_, rem) = data.split_at(byte_count);
        rem
    } else {
        data
    };
    for next_chunk in remaining_data.chunks_exact(4) {
        let val = u32::from_ne_bytes(
            next_chunk
                .try_into()
                .expect("4 byte chunk should convert to u32"),
        );
        read_write_u32(
            next_offset.try_into().unwrap(),
            ReadWriteRequestType::Write(val),
        );
        next_offset += 4;
    }
    let extra_bytes = remaining_data.chunks_exact(4).remainder();
    if !extra_bytes.is_empty() {
        let val = read_write_u32(next_offset.try_into().unwrap(), ReadWriteRequestType::Read)
            .expect("Read for ReadWriteFn didn't return u32");
        let mut val = val.to_ne_bytes();
        for (i, &extra_data) in extra_bytes.iter().enumerate() {
            val[i] = extra_data;
        }
        let val = u32::from_ne_bytes(val);
        read_write_u32(
            next_offset.try_into().unwrap(),
            ReadWriteRequestType::Write(val),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Read byte ranges spanning each initial lane and both partial/full trailing words.
    // Expected: Output equals the selected native-endian byte range; each intersecting aligned register is read exactly once and output guards survive.
    #[test]
    fn reads_select_exact_lanes_and_visit_only_intersecting_registers() {
        let registers: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
        for offset in 0u16..8 {
            for length in 1..=13 {
                let mut output = [0xcc; 15];
                let mut reads = Vec::new();
                read_as_u32_chunks(offset, &mut output[1..1 + length], |address| {
                    reads.push(address);
                    let start = usize::from(address);
                    u32::from_ne_bytes(registers[start..start + 4].try_into().unwrap())
                });
                let start = usize::from(offset);
                assert_eq!(&output[1..1 + length], &registers[start..start + length]);
                assert_eq!(output[0], 0xcc);
                assert!(output[1 + length..].iter().all(|byte| *byte == 0xcc));
                let expected: Vec<_> = (0u16..32)
                    .step_by(4)
                    .filter(|address| {
                        usize::from(*address) < start + length && usize::from(*address) + 4 > start
                    })
                    .collect();
                assert_eq!(reads, expected);
            }
        }
        read_as_u32_chunks(4u16, &mut [], |_| {
            panic!("aligned empty read accessed a register")
        });
    }

    // Test: Write all byte lanes and lengths spanning multiple registers.
    // Expected: Only the requested bytes change, partial words use read-then-write, and complete words are written without a read.
    #[test]
    fn writes_preserve_neighbor_bytes_and_avoid_reads_for_full_words() {
        for offset in 0u32..8 {
            for length in 1..=13 {
                let mut registers: [u8; 32] = std::array::from_fn(|index| index as u8);
                let mut expected = registers;
                let payload: Vec<u8> = (0..length).map(|index| 0xf0 - index as u8).collect();
                let start = offset as usize;
                expected[start..start + length].copy_from_slice(&payload);
                let mut operations = Vec::new();
                write_as_u32_chunks(offset, &payload, |address, request| {
                    let start = address as usize;
                    match request {
                        ReadWriteRequestType::Read => {
                            operations.push((address, false));
                            Some(u32::from_ne_bytes(
                                registers[start..start + 4].try_into().unwrap(),
                            ))
                        }
                        ReadWriteRequestType::Write(value) => {
                            operations.push((address, true));
                            registers[start..start + 4].copy_from_slice(&value.to_ne_bytes());
                            None
                        }
                    }
                });
                assert_eq!(registers, expected);
                let mut expected_operations = Vec::new();
                for address in (0u32..32).step_by(4) {
                    let word_start = address as usize;
                    if word_start < start + length && word_start + 4 > start {
                        if word_start < start || word_start + 4 > start + length {
                            expected_operations.push((address, false));
                        }
                        expected_operations.push((address, true));
                    }
                }
                assert_eq!(operations, expected_operations);
            }
        }
        write_as_u32_chunks(4u32, &[], |_, _| {
            panic!("aligned empty write accessed a register")
        });
    }
}
