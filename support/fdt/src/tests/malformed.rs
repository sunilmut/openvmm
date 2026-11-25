// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Reject malformed fixed headers and block bounds before parsing the tree.
// Expected: Each failure names its invalid field; partial header sizing does not require the full blob.
#[test]
fn invalid_headers_report_the_failed_boundary() {
    let base = wire(&words(&[1, 0, 2, 9]), b"p\0");
    for (index, value, expected) in [
        (0, 0, "magic"),
        (1, base.as_bytes().len() as u32 + 4, "total size"),
        (5, 16, "version"),
        (6, 17, "version"),
        (4, u32::MAX, "Memory reservation block"),
        (4, base.as_bytes().len() as u32 - 8, "empty entry"),
        (2, 57, "aligned"),
        (2, u32::MAX - 3, "Structure block"),
        (9, u32::MAX, "Structure block"),
        (9, 0, "FDT end token"),
        (3, u32::MAX, "Strings block"),
        (8, u32::MAX, "Strings block"),
    ] {
        let mut blob = base.clone();
        field(&mut blob, index, value);
        assert!(
            parse_error(blob.as_bytes()).contains(expected),
            "header field {index}: {expected}"
        );
    }
    assert!(parse_error(&base.as_bytes()[1..]).contains("aligned"));
    assert!(parse_error(&base.as_bytes()[..36]).contains("fixed FDT header"));
    assert!(
        Parser::read_total_size(&base.as_bytes()[..36])
            .unwrap_err()
            .to_string()
            .contains("fixed FDT header")
    );
    let mut invalid = base.clone();
    field(&mut invalid, 0, 0);
    assert!(
        Parser::read_total_size(invalid.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("magic")
    );
}

// Test: Reject invalid root structure, tokens, property framing and node-name encodings.
// Expected: Malformed serialized input returns contextual errors instead of producing a partial valid tree.
#[test]
fn malformed_structure_tokens_return_contextual_errors() {
    let cases: &[(&[u32], &str)] = &[
        (&[9], "No root"),
        (&[1, 0, 2, 1, 0, 2, 9], "More than one"),
        (&[2, 9], "begin node 2"),
        (&[3, 0, 0, 9], "begin node 3"),
        (&[9, 9], "begin node 9"),
        (&[1, 0, 9, 2, 9], "node properties 9"),
        (&[1, 0, 1, 0, 9, 2, 2, 9], "children nodes 9"),
        (&[0xdead_beef, 9], "Unknown FDT token"),
        (&[1, 0, 3, 9], "property header"),
        (&[1, 0, 3, 8, 0, 2, 9], "property data"),
        (&[1, 0x6162_6364, 9], "No null terminator"),
        (&[1, 0xff00_0000, 2, 9], "utf8"),
    ];
    for (tokens, expected) in cases {
        let blob = wire(&words(tokens), b"p\0");
        let error = parse_error(blob.as_bytes());
        assert!(error.contains(expected), "{tokens:x?}: {error}");
    }
    for (mut structure, expected) in [
        (vec![0, 0, 0], "read token"),
        ([words(&[1]), vec![0]].concat(), "name alignment"),
    ] {
        structure.extend_from_slice(&9u32.to_be_bytes());
        let blob = wire(&structure, b"");
        assert!(parse_error(blob.as_bytes()).contains(expected));
    }
}

// Test: Read malformed names and values through a structurally valid node's public property API.
// Expected: Invalid string offsets/encodings, scalar lengths and indexes retain node/property context.
#[test]
fn malformed_property_names_and_values_are_rejected() {
    for (name_offset, strings, expected) in [
        (9, &b"p\0"[..], "Invalid string block offset"),
        (0, &b"p"[..], "No null terminator"),
        (0, &b"\xff\0"[..], "utf8"),
    ] {
        let blob = wire(&words(&[1, 0, 3, 0, name_offset, 2, 9]), strings);
        let parser = Parser::new(blob.as_bytes()).unwrap();
        let root = parser.root().unwrap();
        let error = match root.find_property("p") {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed property name accepted"),
        };
        assert!(error.contains("Property name string"));
        assert!(error.contains(expected), "{error}");
    }
    for (data, expected) in [
        (&b"abc"[..], "No null terminator"),
        (&b"\xff\0"[..], "utf8"),
    ] {
        let mut structure = words(&[1, 0, 3, data.len() as u32, 0]);
        structure.extend_from_slice(data);
        structure.resize((structure.len() + 3) & !3, 0);
        structure.extend_from_slice(&words(&[2, 9]));
        let blob = wire(&structure, b"p\0");
        let parser = Parser::new(blob.as_bytes()).unwrap();
        let root = parser.root().unwrap();
        let property = root.find_property("p").unwrap().unwrap();
        assert!(
            property
                .read_str()
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
        assert!(
            property
                .read_u32(0)
                .unwrap_err()
                .to_string()
                .contains("Property p data buffer len")
        );
        let error = match property.as_64_list() {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed u64 list accepted"),
        };
        assert!(error.contains("Property p data buffer len"));
    }
}
