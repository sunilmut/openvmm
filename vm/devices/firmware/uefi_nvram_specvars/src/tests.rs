// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod boot;
mod signatures;

const END: &[u8] = &[0x7f, 0xff, 4, 0];
const OWNER: guid::Guid = guid::guid!("00112233-4455-6677-8899-aabbccddeeff");
const OWNER_BYTES: [u8; 16] = [
    0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

// Encode a reference UEFI device node without using the parser's structures.
fn node(kind: u8, subtype: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, subtype];
    bytes.extend(u16::try_from(payload.len() + 4).unwrap().to_le_bytes());
    bytes.extend(payload);
    bytes
}

// Encode a load option with distinct attributes and a UCS-2 description.
fn load_option(paths: &[u8], optional: &[u8]) -> Vec<u8> {
    let mut bytes = 0x11223344u32.to_le_bytes().to_vec();
    bytes.extend(u16::try_from(paths.len()).unwrap().to_le_bytes());
    bytes.extend(b"D\0i\0s\0k\0\0\0");
    bytes.extend(paths);
    bytes.extend(optional);
    bytes
}

// Test: Dispatch recognized boot variables and leave unrelated names opaque.
// Expected: Boot values are parsed, while unknown names retain their original bytes.
#[test]
fn variable_dispatch_preserves_boot_and_unknown_values() {
    let ParsedNvramEntry::BootOrder(order) = parse_nvram_entry("BootOrder", &[2, 0, 1, 0]).unwrap()
    else {
        panic!("expected boot order");
    };
    assert_eq!(order, [2, 1]);
    let bytes = load_option(END, b"optional");
    let ParsedNvramEntry::Boot(option) = parse_nvram_entry("Boot0012", &bytes).unwrap() else {
        panic!("expected load option");
    };
    assert_eq!(option.attributes, 0x11223344);
    assert_eq!(option.description.as_bytes(), b"D\0i\0s\0k\0\0\0");
    assert!(option.device_paths.is_empty());
    assert_eq!(option.opt, Some(&b"optional"[..]));
    for name in ["Boot", "BootNext", "boot0001", "OtherVariable"] {
        let ParsedNvramEntry::Unknown(data) = parse_nvram_entry(name, &bytes).unwrap() else {
            panic!("expected opaque variable {name}");
        };
        assert_eq!(data, bytes);
    }
}

// Test: Dispatch malformed boot-order, load-option and secure-boot variables.
// Expected: Each failure keeps its parser-specific typed error and outer context.
#[test]
fn variable_dispatch_retains_typed_errors() {
    assert!(matches!(
        parse_nvram_entry("BootOrder", &[1]),
        Err(ParseError::BootOrder(boot_order::Error::InvalidLength))
    ));
    assert!(matches!(
        parse_nvram_entry("Boot0001", &[]),
        Err(ParseError::BootOrder(boot_order::Error::InvalidLength))
    ));
    assert!(matches!(
        parse_nvram_entry("db", &[1]),
        Err(ParseError::SignatureList(
            signature_list::ParseError::InvalidHeader
        ))
    ));
}

// IGNORED: The dispatcher accepts decimal digits of any length instead of four
//       hexadecimal digits. Boot000A is incorrectly returned as an opaque variable.
//
// Test: Parse Boot#### names containing hexadecimal letters, and reject short suffixes.
// Expected: Four hexadecimal digits select a load option; other names stay opaque.
#[test]
#[ignore = "product bug: boot-name dispatch requires decimal rather than four hex digits"]
fn boot_variable_names_use_four_hexadecimal_digits() {
    let bytes = load_option(END, &[]);
    for name in ["Boot000A", "BootABCD"] {
        assert!(matches!(
            parse_nvram_entry(name, &bytes).unwrap(),
            ParsedNvramEntry::Boot(_)
        ));
    }
    for name in ["Boot1", "Boot00000", "Boot000G"] {
        assert!(matches!(
            parse_nvram_entry(name, &bytes).unwrap(),
            ParsedNvramEntry::Unknown(_)
        ));
    }
}
