// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Decode fixed little-endian qid vectors, including a truncated final entry.
// Expected: Type/version/path retain their independent values and truncation returns EINVAL.
#[test]
fn qid_sequences_preserve_wire_values_and_report_truncation() {
    let bytes = [
        2, 0, 0x80, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4, 5, 6, 7, 8, 2, 4, 3, 2, 1, 8, 7, 6, 5, 4,
        3, 2, 1,
    ];
    let mut qids = SliceReader::new(&bytes).qids().unwrap();
    let first = qids.next().unwrap().unwrap();
    assert_eq!(
        (first.qid_type, first.version, first.path),
        (0x80, 0x78563412, 0x0807060504030201)
    );
    let second = qids.next().unwrap().unwrap();
    assert_eq!(
        (second.qid_type, second.version, second.path),
        (2, 0x01020304, 0x0102030405060708)
    );
    assert!(qids.next().is_none());
    let mut truncated = SliceReader::new(&bytes[..bytes.len() - 1]).qids().unwrap();
    truncated.next().unwrap().unwrap();
    assert!(matches!(truncated.next(), Some(Err(lx::Error::EINVAL))));
    assert!(truncated.next().is_none());
}

// Test: Decode length-prefixed strings with embedded NUL or non-UTF8 bytes, then a suffix.
// Expected: String normalization never changes the declared wire boundary of following data.
#[test]
fn string_normalization_preserves_following_field_boundaries() {
    let mut reader = SliceReader::new(b"\x05\x00a\0bcd\x34\x12");
    assert_eq!(reader.string().unwrap().as_bytes(), b"a");
    assert_eq!(reader.u16().unwrap(), 0x1234);
    let mut reader = SliceReader::new(b"\x02\x00\xff\xfe\x78\x56");
    assert_eq!(reader.string().unwrap().as_bytes(), b"\xff\xfe");
    assert_eq!(reader.u16().unwrap(), 0x5678);
}

// Test: Encode a directory entry into an exactly sized buffer or one that is a byte short.
// Expected: The exact wire vector is emitted atomically; insufficient capacity changes no bytes.
#[test]
fn directory_entry_encoding_is_atomic_at_the_capacity_boundary() {
    let qid = Qid {
        qid_type: 2,
        version: 0x04030201,
        path: 0x0807060504030201,
    };
    let expected = [
        2, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 10, 2, 0, b'a', b'b',
    ];
    let mut short = [0xcc; 25];
    assert!(!SliceWriter::new_raw(&mut short).dir_entry(
        "ab".as_ref(),
        &qid,
        0x0102030405060708,
        10
    ));
    assert_eq!(short, [0xcc; 25]);
    let mut exact = [0; 26];
    assert!(SliceWriter::new_raw(&mut exact).dir_entry(
        "ab".as_ref(),
        &qid,
        0x0102030405060708,
        10
    ));
    assert_eq!(exact, expected);
}
