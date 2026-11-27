// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build a bootable OpenTMK UEFI disk image for the flowey `build-opentmk` path.
//! [`build_opentmk_vhd`] builds as-is; [`build_opentmk_vhd_with_config`] patches [`opentmk_protocol::TestConfig`].

use anyhow::Context;
use guid::Guid;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::ops::Range;

const SECTOR_SIZE: u64 = 512;
const IMAGE_SIZE: u64 = 64 * 1024 * 1024;

/// EFI System Partition type GUID.
const EFI_SYSTEM_PARTITION_GUID: Guid = guid::guid!("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");

/// Target architecture for the boot image, selecting the removable-media path.
#[derive(Debug, Clone, Copy)]
pub enum Arch {
    /// x86_64 (`EFI/BOOT/BOOTX64.EFI`).
    X86_64,
    /// aarch64 (`EFI/BOOT/BOOTAA64.EFI`).
    Aarch64,
}

/// Build a fixed VHD that boots the given OpenTMK `.efi` as-is.
pub fn build_opentmk_vhd(efi: &[u8], arch: Arch) -> anyhow::Result<tempfile::NamedTempFile> {
    build_image(efi, arch)
}

/// Build a fixed VHD that boots a copy of `efi` with `config_json` patched into
/// its embedded config region, selecting which test to run.
pub fn build_opentmk_vhd_with_config(
    efi: &[u8],
    arch: Arch,
    config_json: &[u8],
) -> anyhow::Result<tempfile::NamedTempFile> {
    let mut efi = efi.to_vec();
    opentmk_protocol::patch_opentmk_config(&mut efi, config_json)
        .context("failed to patch opentmk test config")?;
    build_image(&efi, arch)
}

fn build_image(efi: &[u8], arch: Arch) -> anyhow::Result<tempfile::NamedTempFile> {
    let boot_path = match arch {
        Arch::X86_64 => "EFI/BOOT/BOOTX64.EFI",
        Arch::Aarch64 => "EFI/BOOT/BOOTAA64.EFI",
    };
    let mut image_file = tempfile::Builder::new().suffix(".vhd").tempfile()?;
    image_file
        .as_file()
        .set_len(IMAGE_SIZE)
        .context("failed to set file size")?;

    build_fat32_disk_image(&mut image_file, "ESP", b"ESP        ", &[(boot_path, efi)])?;

    disk_vhd1::Vhd1Disk::make_fixed(image_file.as_file())
        .context("failed to make vhd for uefi boot image")?;
    Ok(image_file)
}

fn build_fat32_disk_image(
    file: &mut (impl Read + Write + Seek),
    gpt_name: &str,
    volume_label: &[u8; 11],
    files: &[(&str, &[u8])],
) -> anyhow::Result<()> {
    let range = build_gpt(file, gpt_name).context("failed to construct partition table")?;
    build_fat32(
        &mut fscommon::StreamSlice::new(file, range.start, range.end)?,
        volume_label,
        files,
    )
    .context("failed to format volume")
}

fn build_gpt(file: &mut (impl Read + Write + Seek), name: &str) -> anyhow::Result<Range<u64>> {
    let mut gpt = gptman::GPT::new_from(file, SECTOR_SIZE, Guid::new_random().into())?;
    gptman::GPT::write_protective_mbr_into(file, SECTOR_SIZE)?;
    gpt[1] = gptman::GPTPartitionEntry {
        partition_type_guid: EFI_SYSTEM_PARTITION_GUID.into(),
        unique_partition_guid: Guid::new_random().into(),
        starting_lba: gpt.header.first_usable_lba,
        ending_lba: gpt.header.last_usable_lba,
        attribute_bits: 0,
        partition_name: name.into(),
    };
    gpt.write_into(file)?;
    let start = gpt[1].starting_lba * SECTOR_SIZE;
    // GPT LBAs are inclusive, so the sector count spans `end - start + 1`.
    let bytes = (gpt[1].ending_lba - gpt[1].starting_lba + 1) * SECTOR_SIZE;
    Ok(start..start + bytes)
}

fn build_fat32(
    file: &mut (impl Read + Write + Seek),
    volume_label: &[u8; 11],
    files: &[(&str, &[u8])],
) -> anyhow::Result<()> {
    fatfs::format_volume(
        &mut *file,
        fatfs::FormatVolumeOptions::new()
            .volume_label(*volume_label)
            .fat_type(fatfs::FatType::Fat32),
    )
    .context("failed to format volume")?;
    let fs = fatfs::FileSystem::new(file, fatfs::FsOptions::new()).context("failed to open fs")?;
    for (path, data) in files {
        // Create parent directories (e.g. `EFI/BOOT`), since fatfs does not.
        let mut dir = fs.root_dir();
        let mut components = path.split('/').peekable();
        let mut file_name = *path;
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                file_name = component;
                break;
            }
            if component.is_empty() {
                continue;
            }
            dir = match dir.open_dir(component) {
                Ok(existing) => existing,
                Err(_) => dir
                    .create_dir(component)
                    .context("failed to create directory")?,
            };
        }
        let mut dest = dir
            .create_file(file_name)
            .context("failed to create file")?;
        dest.write_all(data).context("failed to write file")?;
        dest.flush().context("failed to flush file")?;
    }
    fs.unmount().context("failed to unmount fs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentmk_protocol::OPENTMK_CONFIG_JSON_SIZE;
    use opentmk_protocol::OPENTMK_CONFIG_MAGIC;
    use std::io::Cursor;
    use test_with_tracing::test;

    /// A minimal PE image with one `.tmkcfg` section holding an empty config.
    fn pe_with_config_region() -> Vec<u8> {
        let mut section = OPENTMK_CONFIG_MAGIC.to_vec();
        section.extend_from_slice(&0u32.to_le_bytes());
        section.extend_from_slice(&[0; OPENTMK_CONFIG_JSON_SIZE]);
        let (pe, coff) = (64usize, 68usize);
        let sh = coff + 20;
        let raw = sh + 40;
        let mut image = vec![0u8; raw];
        image[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        image[pe..pe + 4].copy_from_slice(b"PE\0\0");
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[sh..sh + 8].copy_from_slice(b".tmkcfg\0");
        image[sh + 16..sh + 20].copy_from_slice(&(section.len() as u32).to_le_bytes());
        image[sh + 20..sh + 24].copy_from_slice(&(raw as u32).to_le_bytes());
        image.extend_from_slice(&section);
        image
    }

    /// Opens the image's GPT and ESP filesystem, returning the partition entry
    /// and the requested file's contents if it exists.
    fn inspect(
        file: &mut std::fs::File,
        path: &str,
    ) -> (gptman::GPTPartitionEntry, String, Option<Vec<u8>>) {
        let gpt = gptman::GPT::read_from(file, SECTOR_SIZE).unwrap();
        let entry = gpt[1].clone();
        let start = entry.starting_lba * SECTOR_SIZE;
        let end = (entry.ending_lba + 1) * SECTOR_SIZE;
        let slice = fscommon::StreamSlice::new(file, start, end).unwrap();
        let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new()).unwrap();
        let label = fs.volume_label();
        let data = fs.root_dir().open_file(path).ok().map(|mut f| {
            let mut out = Vec::new();
            f.read_to_end(&mut out).unwrap();
            out
        });
        (entry, label, data)
    }

    // Test: Build boot images for both architectures from an owned payload.
    // Expected: Each image is a 64 MiB fixed VHD (with footer) holding one
    //       EFI System Partition over all usable sectors, a FAT32 volume
    //       labelled ESP, and the exact payload at the architecture's
    //       removable-media path only.
    #[test]
    fn boot_images_place_payload_at_architecture_path() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        for (arch, path, other) in [
            (
                Arch::X86_64,
                "EFI/BOOT/BOOTX64.EFI",
                "EFI/BOOT/BOOTAA64.EFI",
            ),
            (
                Arch::Aarch64,
                "EFI/BOOT/BOOTAA64.EFI",
                "EFI/BOOT/BOOTX64.EFI",
            ),
        ] {
            let image = build_opentmk_vhd(&payload, arch).unwrap();
            let mut file = image.reopen().unwrap();
            let len = file.metadata().unwrap().len();
            assert_eq!(len, IMAGE_SIZE + 512);
            let mut footer = [0u8; 8];
            file.seek(std::io::SeekFrom::Start(IMAGE_SIZE)).unwrap();
            file.read_exact(&mut footer).unwrap();
            assert_eq!(&footer, b"conectix");

            let gpt = gptman::GPT::read_from(&mut file, SECTOR_SIZE).unwrap();
            assert_eq!(gpt.iter().filter(|(_, p)| p.is_used()).count(), 1);
            let (entry, label, data) = inspect(&mut file, path);
            assert_eq!(
                entry.partition_type_guid,
                <[u8; 16]>::from(EFI_SYSTEM_PARTITION_GUID)
            );
            assert_eq!(entry.partition_name.as_str(), "ESP");
            assert_eq!(
                (entry.starting_lba, entry.ending_lba),
                (gpt.header.first_usable_lba, gpt.header.last_usable_lba)
            );
            assert_eq!(label, "ESP");
            assert_eq!(data.as_deref(), Some(&payload[..]));
            assert!(inspect(&mut file, other).2.is_none());
        }
    }

    // Test: Build a configured image from a PE with a config region, and from
    //       inputs whose config JSON or PE structure is invalid.
    // Expected: The booted payload carries the exact JSON in its config region
    //       while the caller's buffer is untouched; invalid inputs fail with the
    //       patching context and no image.
    #[test]
    fn configured_images_patch_a_copy_or_fail() {
        let efi = pe_with_config_region();
        let json = br#"{"backend":"hyperv","test":"hv_processor","params":{"n":1}}"#;
        let image = build_opentmk_vhd_with_config(&efi, Arch::X86_64, json).unwrap();
        let (_, _, data) = inspect(&mut image.reopen().unwrap(), "EFI/BOOT/BOOTX64.EFI");
        let data = data.unwrap();
        let magic = data
            .windows(16)
            .position(|w| w == OPENTMK_CONFIG_MAGIC)
            .unwrap();
        let len = u32::from_le_bytes(data[magic + 16..magic + 20].try_into().unwrap()) as usize;
        assert_eq!(&data[magic + 20..magic + 20 + len], json);
        assert_eq!(efi, pe_with_config_region());

        for (efi, json) in [
            (&efi[..], &b"{not json"[..]),
            (&b"MZ not a pe"[..], &json[..]),
        ] {
            let error = build_opentmk_vhd_with_config(efi, Arch::Aarch64, json).unwrap_err();
            assert!(
                format!("{error:#}").starts_with("failed to patch opentmk test config: "),
                "{error:#}"
            );
        }
    }

    // Test: Format an in-memory disk with nested, shared-parent, leading-slash
    //       and doubled-slash file paths.
    // Expected: Missing parent directories are created once and reused, empty
    //       path components are ignored, and every file holds its exact bytes.
    #[test]
    fn fat_volume_creates_nested_directories_for_each_file() {
        let mut disk = Cursor::new(vec![0u8; 40 * 1024 * 1024]);
        let files: &[(&str, &[u8])] = &[
            ("a/b/one.txt", b"1"),
            ("a/b/two.txt", b"22"),
            ("/root.txt", b"r"),
            ("c//d.txt", b"d"),
        ];
        build_fat32_disk_image(&mut disk, "TEST", b"TESTVOLUME ", files).unwrap();
        let gpt = gptman::GPT::read_from(&mut disk, SECTOR_SIZE).unwrap();
        let (start, end) = (
            gpt[1].starting_lba * SECTOR_SIZE,
            (gpt[1].ending_lba + 1) * SECTOR_SIZE,
        );
        let fs = fatfs::FileSystem::new(
            fscommon::StreamSlice::new(&mut disk, start, end).unwrap(),
            fatfs::FsOptions::new(),
        )
        .unwrap();
        assert_eq!(fs.volume_label(), "TESTVOLUME");
        for (path, data) in files {
            let mut out = Vec::new();
            fs.root_dir()
                .open_file(path.trim_start_matches('/').replace("//", "/").as_str())
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(&out, data, "{path}");
        }
        let names: Vec<_> = fs
            .root_dir()
            .open_dir("a/b")
            .unwrap()
            .iter()
            .map(|e| e.unwrap().file_name())
            .filter(|n| !n.starts_with('.'))
            .collect();
        assert_eq!(names, ["one.txt", "two.txt"]);
    }
}
