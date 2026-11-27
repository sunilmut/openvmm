// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CPIO newc archive builder and merger.
//!
//! Provides tools to inject files into an existing gzip-compressed CPIO
//! initrd, or append files as a separate gzip-compressed CPIO layer.

use anyhow::Context;

/// The CPIO newc magic number.
const CPIO_NEWC_MAGIC: &[u8] = b"070701";

/// The CPIO trailer filename.
const CPIO_TRAILER: &[u8] = b"TRAILER!!!";

/// Append a file as a gzip-compressed CPIO layer without modifying existing
/// initrd layers. Linux extracts the appended layer after the existing layers.
pub fn append_to_initrd(
    initrd: &mut Vec<u8>,
    file_name: &str,
    file_data: &[u8],
    mode: u32,
) -> anyhow::Result<()> {
    let mut layer = Vec::new();
    write_cpio_entry(&mut layer, file_name, file_data, mode);
    write_cpio_entry(&mut layer, "TRAILER!!!", &[], 0);
    let compressed = compress_gz(&layer).context("failed to compress appended initrd layer")?;
    initrd.extend_from_slice(&compressed);
    Ok(())
}

/// Inject a file into a gzip-compressed CPIO initrd.
///
/// Decompresses the initrd, inserts the file entry before the TRAILER!!!
/// marker, and recompresses as a single gzip stream. Returns the new
/// gzip-compressed initrd bytes.
///
/// If `file_name` already exists in the archive, this does not remove the
/// existing entry; the new entry is appended just before the trailer. Because
/// the kernel's initramfs extractor applies entries in order and later entries
/// overwrite earlier ones, the injected file wins. The original bytes remain
/// in the archive but are inert.
pub fn inject_into_initrd(
    initrd_gz: &[u8],
    file_name: &str,
    file_data: &[u8],
    mode: u32,
) -> anyhow::Result<Vec<u8>> {
    // Decompress the original initrd
    let decompressed = decompress_gz(initrd_gz).context("failed to decompress initrd")?;

    // Find the TRAILER!!! entry and insert our file before it
    let trailer_offset =
        find_trailer_offset(&decompressed).context("could not find TRAILER!!! in CPIO archive")?;

    let mut merged = Vec::with_capacity(decompressed.len() + file_data.len() + 256);
    // Everything before the trailer
    merged.extend_from_slice(&decompressed[..trailer_offset]);
    // Our new file entry
    write_cpio_entry(&mut merged, file_name, file_data, mode);
    // The trailer and everything after it
    merged.extend_from_slice(&decompressed[trailer_offset..]);

    // Recompress
    compress_gz(&merged).context("failed to recompress initrd")
}

/// Find the byte offset of the TRAILER!!! entry in a raw CPIO newc stream.
fn find_trailer_offset(data: &[u8]) -> Option<usize> {
    // The trailer entry starts with the magic "070701" followed by fixed
    // fields, then the filename "TRAILER!!!\0". We search for the magic
    // followed by the trailer name at the expected offset (110 bytes into
    // the header is where the filename starts).
    let mut pos = 0;
    while pos + 110 + CPIO_TRAILER.len() < data.len() {
        if &data[pos..pos + 6] == CPIO_NEWC_MAGIC {
            // Parse namesize from the header (bytes 94..102, 8 hex chars)
            let namesize_hex = &data[pos + 94..pos + 102];
            if let Ok(namesize_str) = std::str::from_utf8(namesize_hex) {
                if let Ok(namesize) = u32::from_str_radix(namesize_str, 16) {
                    let name_start = pos + 110;
                    let name_end = name_start + namesize as usize - 1; // exclude NUL
                    if name_end <= data.len() && &data[name_start..name_end] == CPIO_TRAILER {
                        return Some(pos);
                    }
                    // Skip past this entry to the next one
                    let filesize_hex = &data[pos + 54..pos + 62];
                    if let Ok(fs_str) = std::str::from_utf8(filesize_hex) {
                        if let Ok(filesize) = u32::from_str_radix(fs_str, 16) {
                            let header_plus_name = 110 + namesize as usize;
                            let name_padded = header_plus_name + (4 - (header_plus_name % 4)) % 4;
                            let data_padded = filesize as usize + (4 - (filesize as usize % 4)) % 4;
                            pos = pos + name_padded + data_padded;
                            continue;
                        }
                    }
                }
            }
            // If parsing failed, advance by 1 and keep searching
            pos += 1;
        } else {
            pos += 1;
        }
    }
    None
}

/// Decompress gzip data.
fn decompress_gz(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .context("gzip decompression failed")?;
    Ok(buf)
}

/// Compress data with gzip.
fn compress_gz(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).context("gzip compression failed")?;
    encoder.finish().context("gzip finish failed")
}

/// Write a single CPIO newc entry (header + filename + data).
fn write_cpio_entry(buf: &mut Vec<u8>, name: &str, data: &[u8], mode: u32) {
    // newc header is exactly 110 bytes of ASCII hex fields
    let name_with_nul = name.len() + 1; // include NUL terminator
    let header = format!(
        "070701\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}",
        0u32,                                                          // ino
        mode,                                                          // mode
        0u32,                                                          // uid
        0u32,                                                          // gid
        1u32,                                                          // nlink
        0u32,                                                          // mtime
        u32::try_from(data.len()).expect("file too large for CPIO"),   // filesize
        0u32,                                                          // devmajor
        0u32,                                                          // devminor
        0u32,                                                          // rdevmajor
        0u32,                                                          // rdevminor
        u32::try_from(name_with_nul).expect("name too long for CPIO"), // namesize
        0u32,                                                          // check (unused in newc)
    );

    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.push(0); // NUL terminator

    // Pad name to 4-byte boundary (header + name must be 4-byte aligned)
    let header_plus_name = 110 + name_with_nul;
    let name_padding = (4 - (header_plus_name % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, name_padding));

    // File data
    buf.extend_from_slice(data);

    // Pad data to 4-byte boundary
    let data_padding = (4 - (data.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, data_padding));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_trailer_in_simple_archive() {
        let mut buf = Vec::new();
        write_cpio_entry(&mut buf, "hello", b"world", 0o100644);
        let trailer_pos = buf.len();
        write_cpio_entry(&mut buf, "TRAILER!!!", &[], 0);
        assert_eq!(find_trailer_offset(&buf), Some(trailer_pos));
    }

    #[test]
    fn inject_adds_file_before_trailer() {
        // Build a minimal uncompressed CPIO, gzip it, inject, decompress, verify
        let mut original = Vec::new();
        write_cpio_entry(&mut original, "existing", b"data", 0o100644);
        write_cpio_entry(&mut original, "TRAILER!!!", &[], 0);

        let gz = compress_gz(&original).unwrap();
        let merged_gz = inject_into_initrd(&gz, "pipette", b"binary", 0o100755).unwrap();
        let merged = decompress_gz(&merged_gz).unwrap();

        let s = String::from_utf8_lossy(&merged);
        // Both files should be present
        assert!(s.contains("existing"));
        assert!(s.contains("pipette"));
        assert!(s.contains("TRAILER!!!"));

        // pipette should appear before TRAILER
        let pipette_pos = s.find("pipette").unwrap();
        let trailer_pos = s.find("TRAILER!!!").unwrap();
        assert!(pipette_pos < trailer_pos);
    }

    fn read_entries(data: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let header = &data[offset..offset + 110];
            assert_eq!(&header[..6], b"070701");
            let field = |range| {
                u32::from_str_radix(std::str::from_utf8(&header[range]).unwrap(), 16).unwrap()
            };
            let mode = field(14..22);
            let size = field(54..62) as usize;
            let namesize = field(94..102) as usize;
            let name = &data[offset + 110..offset + 110 + namesize];
            assert_eq!(name.last(), Some(&0));
            let name = std::str::from_utf8(&name[..name.len() - 1])
                .unwrap()
                .to_owned();
            let payload = (offset + 110 + namesize).next_multiple_of(4);
            entries.push((name, mode, data[payload..payload + size].to_vec()));
            offset = (payload + size).next_multiple_of(4);
        }
        entries
    }

    // Test: Inject a duplicate executable name when a file contains a fake trailer.
    // Expected: The original payload is intact and the replacement's exact bytes
    //       and permissions appear last, before the real archive trailer.
    #[test]
    fn injection_preserves_payload_and_appends_replacement() {
        let mut fake_trailer = Vec::new();
        write_cpio_entry(&mut fake_trailer, "TRAILER!!!", &[], 0);
        let mut original = Vec::new();
        write_cpio_entry(&mut original, "nested/archive", &fake_trailer, 0o100644);
        write_cpio_entry(&mut original, "pipette", &[0xff, 0, 0x71], 0o100600);
        write_cpio_entry(&mut original, "TRAILER!!!", &[], 0);
        let merged = inject_into_initrd(
            &compress_gz(&original).unwrap(),
            "pipette",
            &[0x83, 0, 0xff, 0x19, 0x27],
            0o100755,
        )
        .unwrap();
        assert_eq!(
            read_entries(&decompress_gz(&merged).unwrap()),
            vec![
                ("nested/archive".into(), 0o100644, fake_trailer),
                ("pipette".into(), 0o100600, vec![0xff, 0, 0x71]),
                ("pipette".into(), 0o100755, vec![0x83, 0, 0xff, 0x19, 0x27]),
                ("TRAILER!!!".into(), 0, vec![]),
            ]
        );
    }

    // Test: Append independent gzip layers to an existing initrd.
    // Expected: The existing compressed bytes stay unchanged and each added member
    //       decodes to its own complete archive, with exact binary content and mode.
    #[test]
    fn appended_layers_preserve_existing_compressed_bytes() {
        use flate2::read::MultiGzDecoder;
        use std::io::Read;

        let mut original = Vec::new();
        write_cpio_entry(&mut original, "init", b"original", 0o100755);
        write_cpio_entry(&mut original, "TRAILER!!!", &[], 0);
        let prefix = compress_gz(&original).unwrap();
        let mut initrd = prefix.clone();
        append_to_initrd(&mut initrd, "bin/a", &[0, 0x91, 0xff], 0o100700).unwrap();
        let first_end = initrd.len();
        append_to_initrd(&mut initrd, "empty", &[], 0o100644).unwrap();
        assert_eq!(&initrd[..prefix.len()], prefix);
        assert_eq!(
            read_entries(&decompress_gz(&initrd[prefix.len()..first_end]).unwrap()),
            vec![
                ("bin/a".into(), 0o100700, vec![0, 0x91, 0xff]),
                ("TRAILER!!!".into(), 0, vec![]),
            ]
        );
        assert_eq!(
            read_entries(&decompress_gz(&initrd[first_end..]).unwrap()),
            vec![
                ("empty".into(), 0o100644, vec![]),
                ("TRAILER!!!".into(), 0, vec![]),
            ]
        );
        let mut all = Vec::new();
        MultiGzDecoder::new(initrd.as_slice())
            .read_to_end(&mut all)
            .unwrap();
        let entries = read_entries(&all);
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0], ("init".into(), 0o100755, b"original".to_vec()));
        assert_eq!(entries[2], ("bin/a".into(), 0o100700, vec![0, 0x91, 0xff]));
        assert_eq!(entries[4], ("empty".into(), 0o100644, vec![]));
    }

    // Test: Attempt injection into invalid gzip or a valid archive without a trailer.
    // Expected: Both unsupported inputs return errors, not a fabricated initrd.
    #[test]
    fn injection_rejects_invalid_gzip_and_missing_trailer() {
        assert!(inject_into_initrd(b"not gzip", "init", b"data", 0o100755).is_err());
        let mut original = Vec::new();
        write_cpio_entry(&mut original, "init", b"data", 0o100755);
        assert!(
            inject_into_initrd(&compress_gz(&original).unwrap(), "other", b"data", 0o100644)
                .is_err()
        );
    }
}
