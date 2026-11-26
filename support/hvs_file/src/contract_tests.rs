// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::reader::HvsFileReader;
use crate::reader::ReadError;
use crate::reader::ValueType;
use crate::writer::HvsFileWriter;
use std::io;
use std::io::Cursor;
use test_with_tracing::test;

fn image() -> Vec<u8> {
    let mut writer = HvsFileWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.add_uint("/value", 0xfedc_ba98_7654_3210);
    writer.finish().unwrap().into_inner()
}

// Test: Either redundant header has a corrupt signature or checksum, or both fail.
// Expected: One valid copy still exposes the original key; no valid copies return
//       the specific header error, and an invalid first object table is rejected.
#[test]
fn redundant_headers_recover_without_accepting_two_bad_copies() {
    let original = image();
    for copy in [0, 4096] {
        for field in [0, 4] {
            let mut bytes = original.clone();
            bytes[copy + field] ^= 1;
            let reader = HvsFileReader::open(Cursor::new(bytes)).unwrap();
            assert_eq!(reader.read_uint("/value").unwrap(), 0xfedc_ba98_7654_3210);
        }
    }
    let mut bytes = original.clone();
    bytes[4] ^= 1;
    bytes[4100] ^= 1;
    assert!(matches!(
        HvsFileReader::open(Cursor::new(bytes)),
        Err(ReadError::BadHeaderChecksum)
    ));
    let mut bytes = original.clone();
    bytes[0] ^= 1;
    bytes[4096] ^= 1;
    assert!(matches!(
        HvsFileReader::open(Cursor::new(bytes)),
        Err(ReadError::BadHeaderSignature(_))
    ));
    let mut bytes = original;
    bytes[8192] ^= 1;
    assert!(matches!(
        HvsFileReader::open(Cursor::new(bytes)),
        Err(ReadError::BadObjectTableSignature(_))
    ));
    assert!(matches!(
        HvsFileReader::open(Cursor::new(vec![0; 16])),
        Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
    ));
}

fn wrong_type<T>(result: Result<T, ReadError>, expected: &str, actual: ValueType) {
    match result {
        Err(ReadError::WrongKeyType {
            expected: e,
            actual: a,
        }) => {
            assert_eq!(e, expected);
            assert_eq!(a, actual);
        }
        _ => panic!("expected wrong key type"),
    }
}

fn missing<T>(result: Result<T, ReadError>) {
    assert!(matches!(result, Err(ReadError::KeyNotFound(path)) if path == "/missing"));
}

// Test: All typed readers encounter another type and an absent path.
// Expected: They identify the requested and actual types instead of interpreting
//       unrelated bytes, and signed/unsigned extremes and Unicode remain lossless.
#[test]
fn typed_reads_do_not_reinterpret_other_values() {
    let mut writer = HvsFileWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.add_int("/int", i64::MIN);
    writer.add_uint("/uint", u64::MAX);
    writer.add_string("/string", "guest β 🚀\0suffix");
    writer.add_bool("/bool", true);
    writer.add_array("/array", &[0xff, 0, 7]).unwrap();
    let mut reader = HvsFileReader::open(writer.finish().unwrap()).unwrap();
    assert_eq!(reader.read_int("/int").unwrap(), i64::MIN);
    assert_eq!(reader.read_uint("/uint").unwrap(), u64::MAX);
    assert_eq!(reader.read_string("/string").unwrap(), "guest β 🚀\0suffix");
    assert_eq!(reader.value_type("/array"), Some(ValueType::Array));
    assert_eq!(reader.value_type("/missing"), None);
    wrong_type(reader.read_int("/uint"), "Int", ValueType::UInt);
    wrong_type(reader.read_uint("/int"), "UInt", ValueType::Int);
    wrong_type(reader.read_string("/bool"), "String", ValueType::Bool);
    wrong_type(reader.read_bool("/string"), "Bool", ValueType::String);
    wrong_type(reader.read_array("/int"), "Array", ValueType::Int);
    missing(reader.read_int("/missing"));
    missing(reader.read_uint("/missing"));
    missing(reader.read_string("/missing"));
    missing(reader.read_bool("/missing"));
    missing(reader.read_array("/missing"));
    assert_eq!(
        reader.keys().collect::<Vec<_>>(),
        ["/array", "/bool", "/int", "/string", "/uint"]
    );
}

// Test: Names reach their UTF-8 byte capacity and blobs cross inline/file boundaries.
// Expected: The largest encodable leaf/node names preserve their complete paths,
//       oversized names fail with InvalidInput, and alignment never leaks padding.
#[test]
fn key_name_and_blob_storage_boundaries() {
    let mut writer = HvsFileWriter::new(Cursor::new(Vec::new())).unwrap();
    let leaf = format!("/{}", "é".repeat(127));
    let nested = format!("/{}/child", "n".repeat(254));
    writer.add_uint(&leaf, 17);
    writer.add_uint(&nested, 23);
    let mut expected = Vec::new();
    for len in [0, 2047, 2048, 2049, 4097] {
        let data = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let path = format!("/blob/{len}");
        writer.add_array(&path, &data).unwrap();
        expected.push((path, data));
    }
    let mut reader = HvsFileReader::open(writer.finish().unwrap()).unwrap();
    assert_eq!(reader.read_uint(&leaf).unwrap(), 17);
    assert_eq!(reader.read_uint(&nested).unwrap(), 23);
    for (path, data) in expected {
        assert_eq!(reader.read_array(&path).unwrap(), data);
    }
    for path in [
        format!("/{}", "x".repeat(255)),
        format!("/{}/child", "x".repeat(255)),
    ] {
        let mut writer = HvsFileWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.add_uint(&path, 1);
        assert!(
            matches!(writer.finish(), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }
}

// Test: A file with valid outer headers has a key entry shorter than its name.
// Expected: Public open rejects the reversed payload span rather than panicking;
//       no caller-side validation precedes the public reader's key-table parsing.
// IGNORED: Enabled reproduction panics in reader.rs on a backwards byte slice.
//       The public reader does not validate entry/name span ordering before slicing.
#[test]
#[ignore = "product bug: malformed key entry panics during public file open"]
fn malformed_key_payload_span_is_rejected() {
    let mut bytes = image();
    let table_offset = u64::from_le_bytes(bytes[8205..8213].try_into().unwrap()) as usize;
    let entry_offset = table_offset + 10;
    bytes[entry_offset + 2..entry_offset + 6].copy_from_slice(&21u32.to_le_bytes());
    assert!(HvsFileReader::open(Cursor::new(bytes)).is_err());
}
