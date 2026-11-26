// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::RomFileLocation;
use crate::find_pcat_bios;
use crate::find_svga_bios;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use test_with_tracing::test;

fn verify_location(mut location: RomFileLocation, start: u64, expected: &[u8]) {
    assert_eq!(location.start, start);
    assert_eq!(location.len, expected.len());
    location.file.seek(SeekFrom::Start(location.start)).unwrap();
    let mut data = Vec::new();
    location
        .file
        .take(location.len as u64)
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, expected);
}

fn resource_dll(resource_type: &[u8; 4], id: u32, data: &[u8]) -> Vec<u8> {
    let mut image = vec![0; 0x300 + data.len()];
    let u16_at = |image: &mut [u8], offset, value: u16| {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    };
    let u32_at = |image: &mut [u8], offset, value: u32| {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    };
    // A PE32+ image with one resource section and type/id/language directories.
    u16_at(&mut image, 0, 0x5a4d);
    u32_at(&mut image, 0x3c, 0x80);
    u32_at(&mut image, 0x80, 0x4550);
    u16_at(&mut image, 0x84, 0x8664);
    u16_at(&mut image, 0x86, 1);
    u16_at(&mut image, 0x94, 240);
    u16_at(&mut image, 0x96, 0x2022);
    u16_at(&mut image, 0x98, 0x20b);
    u32_at(&mut image, 0x98 + 108, 16);
    u32_at(&mut image, 0x98 + 128, 0x1000);
    u32_at(&mut image, 0x98 + 132, (0x100 + data.len()) as u32);
    let section = 0x188;
    image[section..section + 5].copy_from_slice(b".rsrc");
    u32_at(&mut image, section + 8, (0x100 + data.len()) as u32);
    u32_at(&mut image, section + 12, 0x1000);
    u32_at(&mut image, section + 16, (0x100 + data.len()) as u32);
    u32_at(&mut image, section + 20, 0x200);
    u32_at(&mut image, section + 36, 0x4000_0040);
    u16_at(&mut image, 0x20c, 1);
    u32_at(&mut image, 0x210, 0x8000_0080);
    u32_at(&mut image, 0x214, 0x8000_0020);
    u16_at(&mut image, 0x22e, 1);
    u32_at(&mut image, 0x230, id);
    u32_at(&mut image, 0x234, 0x8000_0040);
    u16_at(&mut image, 0x24e, 1);
    u32_at(&mut image, 0x250, 0x409);
    u32_at(&mut image, 0x254, 0x60);
    u32_at(&mut image, 0x260, 0x1100);
    u32_at(&mut image, 0x264, data.len() as u32);
    u16_at(&mut image, 0x280, 4);
    for (i, byte) in resource_type.iter().enumerate() {
        u16_at(&mut image, 0x282 + i * 2, u16::from(*byte));
    }
    image[0x300..].copy_from_slice(data);
    image
}

// Test: Explicit raw BIOS/VGA files have normal sizes or a documented size warning.
// Expected: The opened ROM owns the original file bytes and exposes the whole blob,
//       including nonstandard length; a missing explicit file never falls back.
#[test]
fn explicit_raw_roms_and_missing_path() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    for len in [256 * 1024, 48 * 1024, 13] {
        let path = directory.path().join(format!("raw-{len}.bin"));
        let data = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&path, &data).unwrap();
        verify_location(find_pcat_bios(Some(&path)).unwrap(), 0, &data);
        verify_location(find_svga_bios(Some(&path)).unwrap(), 0, &data);
    }
    let missing = directory.path().join("missing.bin");
    for error in [
        find_pcat_bios(Some(&missing)).unwrap_err(),
        find_svga_bios(Some(&missing)).unwrap_err(),
    ] {
        assert!(error.to_string().contains("missing.bin"));
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        }));
    }
}

// Test: BIOS and VGA PE resources have independent type/ID descriptors.
// Expected: Each locator returns the resource byte range rather than PE headers;
//       a recognized DLL containing only the other resource is not treated as raw.
#[test]
fn explicit_dll_resources_are_not_whole_file_roms() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let bios_path = directory.path().join("original-bios.dll");
    let bios = vec![0xab; 256 * 1024];
    std::fs::write(&bios_path, resource_dll(b"VMFW", 13500, &bios)).unwrap();
    verify_location(find_pcat_bios(Some(&bios_path)).unwrap(), 0x300, &bios);
    assert!(find_svga_bios(Some(&bios_path)).is_err());

    let vga_path = directory.path().join("original-vga.dll");
    let vga = vec![0xcd; 48 * 1024];
    std::fs::write(&vga_path, resource_dll(b"BIOS", 13501, &vga)).unwrap();
    verify_location(find_svga_bios(Some(&vga_path)).unwrap(), 0x300, &vga);
    assert!(find_pcat_bios(Some(&vga_path)).is_err());
}
