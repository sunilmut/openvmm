// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use test_with_tracing::test;

fn put16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn image() -> Vec<u8> {
    let mut image = vec![0; 0x320];
    // Original PE32+ fixture: one section, named type, numeric ID and language.
    for (offset, value) in [
        (0, 0x5a4d),
        (0x84, 0x8664),
        (0x86, 1),
        (0x94, 240),
        (0x96, 0x2022),
        (0x98, 0x20b),
        (0x20c, 1),
        (0x22e, 1),
        (0x24e, 1),
        (0x280, 4),
    ] {
        put16(&mut image, offset, value);
    }
    for (offset, value) in [
        (0x3c, 0x80),
        (0x80, 0x4550),
        (0x98 + 108, 16),
        (0x98 + 128, 0x1000),
        (0x98 + 132, 0x120),
        (0x188 + 8, 0x120),
        (0x188 + 12, 0x1000),
        (0x188 + 16, 0x120),
        (0x188 + 20, 0x200),
        (0x188 + 36, 0x4000_0040),
        (0x210, 0x8000_0080),
        (0x214, 0x8000_0020),
        (0x230, 13515),
        (0x234, 0x8000_0040),
        (0x250, 0x409),
        (0x254, 0x60),
        (0x260, 0x1100),
        (0x264, 0x20),
    ] {
        put32(&mut image, offset, value);
    }
    image[0x188..0x18d].copy_from_slice(b".rsrc");
    for (i, byte) in b"VMFW".iter().enumerate() {
        put16(&mut image, 0x282 + i * 2, u16::from(*byte));
    }
    for (i, byte) in image[0x300..].iter_mut().enumerate() {
        *byte = (i * 7) as u8;
    }
    image
}

fn parse(bytes: &[u8], descriptor: &DllResourceDescriptor) -> anyhow::Result<Option<(u64, usize)>> {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("original.dll");
    std::fs::write(&path, bytes).unwrap();
    try_find_resource_from_dll(&File::open(path).unwrap(), descriptor)
}

// Test: Locate a named firmware resource using its numeric ID.
// Expected: The reported file span contains exactly the payload, not the RVA or
//       PE headers; type and ID matching are both required.
#[test]
fn named_resource_returns_payload_file_span() {
    let bytes = image();
    let descriptor = DllResourceDescriptor::new(b"VMFW", 13515);
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("firmware.dll");
    std::fs::write(&path, &bytes).unwrap();
    let mut file = File::open(path).unwrap();
    let (offset, len) = try_find_resource_from_dll(&file, &descriptor)
        .unwrap()
        .unwrap();
    assert_eq!((offset, len), (0x300, 0x20));
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut payload = vec![0; len];
    file.read_exact(&mut payload).unwrap();
    assert_eq!(payload, bytes[0x300..]);
    assert!(
        parse(&bytes, &DllResourceDescriptor::new(b"BIOS", 13515))
            .unwrap_err()
            .to_string()
            .contains("resource type")
    );
    assert!(
        parse(&bytes, &DllResourceDescriptor::new(b"VMFW", 13516))
            .unwrap_err()
            .to_string()
            .contains("id")
    );
}

// Test: Distinguish raw ROM blobs from recognized but unusable PE resources.
// Expected: Raw/truncated headers permit caller fallback; recognized PE images
//       with absent resource directories or malformed resource trees return errors.
#[test]
fn raw_fallback_does_not_hide_resource_tree_errors() {
    let descriptor = DllResourceDescriptor::new(b"VMFW", 13515);
    for bytes in [&[][..], b"original raw ROM", b"MZ\0\0"] {
        assert_eq!(parse(bytes, &descriptor).unwrap(), None);
    }
    for (offset, value) in [
        (0x98 + 128, 0),
        (0x214, 0x60),
        (0x234, 0x60),
        (0x254, 0x8000_0060),
        (0x260, 0x2000),
    ] {
        let mut bytes = image();
        put32(&mut bytes, offset, value);
        assert!(parse(&bytes, &descriptor).is_err(), "offset {offset:#x}");
    }
}

// Test: Supply zero or multiple language entries for a resource ID.
// Expected: Ambiguous or absent language selection is rejected, rather than
//       silently selecting one language or falling back to the full DLL.
#[test]
fn language_selection_requires_exactly_one_entry() {
    let descriptor = DllResourceDescriptor::new(b"VMFW", 13515);
    for count in [0, 2] {
        let mut bytes = image();
        put16(&mut bytes, 0x24e, count);
        assert!(
            parse(&bytes, &descriptor).is_err(),
            "language count {count}"
        );
    }
}
