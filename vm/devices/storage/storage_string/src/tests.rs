// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Encode SCSI identity strings at empty, padded and exact-width boundaries.
// Expected: Padding is spaces, never NUL; leading/interior spaces survive
//       presentation, and oversized or disallowed characters have typed errors.
#[test]
fn fixed_width_identity_encoding() {
    for (text, expected, trimmed) in [
        ("", *b"        ", ""),
        ("Msft", *b"Msft    ", "Msft"),
        (" A B ", *b" A B    ", " A B"),
        ("12345678", *b"12345678", "12345678"),
        ("~\x7f", *b"~\x7f      ", "~\x7f"),
    ] {
        let identity = text.parse::<AsciiString<8>>().unwrap();
        let wire: [u8; 8] = identity.into();
        assert_eq!(wire, expected);
        assert_eq!(identity.as_str(), Some(trimmed));
    }
    assert!(matches!(
        AsciiString::<8>::new("123456789"),
        Err(InvalidAsciiString::TooLong)
    ));
    for text in ["\0", "\t", "\n", "\x1f", "é", "😀"] {
        assert!(matches!(
            AsciiString::<8>::new(text),
            Err(InvalidAsciiString::NonAscii)
        ));
    }
    assert_eq!(AsciiString::<0>::new("").unwrap().as_bytes(), &[]);
    assert!(matches!(
        AsciiString::<0>::new("x"),
        Err(InvalidAsciiString::TooLong)
    ));
}

// Test: Decode device-provided fixed-width bytes without assuming UTF-8 validity.
// Expected: Trailing ASCII spaces alone are removed; invalid bytes stay
//       available verbatim and cannot be exposed as an invalid Rust string.
#[test]
fn device_identity_bytes_and_utf8() {
    let bytes = *b" Model  ";
    let identity = AsciiString::<8>::read_from_bytes(&bytes).unwrap();
    assert_eq!(identity.as_str(), Some(" Model"));
    assert_eq!(identity.as_bytes(), &bytes);
    let invalid = AsciiString::from([b'A', 0xff, b' ', b' ']);
    assert_eq!(invalid.as_str(), None);
    let bytes: [u8; 4] = invalid.into();
    assert_eq!(bytes, [b'A', 0xff, b' ', b' ']);
    let utf8 = AsciiString::from([0xc3, 0xa9, b' ', b' ']);
    assert_eq!(utf8.as_str(), Some("é"));
    let raw = AsciiString::from(*b"A\t  ");
    assert_eq!(raw.as_str(), Some("A\t"));
}
