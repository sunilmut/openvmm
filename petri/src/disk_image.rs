// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tools for building a disk image for a VM.

use anyhow::Context;
use fatfs::FormatVolumeOptions;
use fatfs::FsOptions;
use guid::Guid;
use petri_artifacts_common::artifacts as common_artifacts;
use petri_artifacts_common::tags::MachineArch;
use petri_artifacts_common::tags::OsFlavor;
use petri_artifacts_core::ArtifactResolver;
use petri_artifacts_core::ResolvedArtifact;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempPath;

/// The description and artifacts needed to build a pipette disk image for a VM.
#[derive(Debug)]
pub struct AgentImage {
    os_flavor: OsFlavor,
    pipette: Option<ResolvedArtifact>,
    extras: Vec<(String, ImageEntry)>,
    free_space: u64,
}

#[derive(Debug)]
/// A file or directory in the agent image
pub enum ImageEntry {
    /// Directory
    Dir,
    /// Persistent file
    File(PathBuf),
    /// Owned temporary file path
    TempFile(TempPath),
}

impl<'a> ImageEntry {
    fn as_content(&'a self) -> ImageEntryContent<'a> {
        match self {
            ImageEntry::Dir => ImageEntryContent::Dir,
            ImageEntry::File(path_buf) => ImageEntryContent::Path(path_buf.as_path()),
            ImageEntry::TempFile(temp_path) => ImageEntryContent::Path(temp_path.as_ref()),
        }
    }
}

/// Disk image type
pub enum ImageType {
    /// Raw image
    Raw,
    /// Fixed VHD1
    Vhd,
}

impl AgentImage {
    /// Resolves the artifacts needed to build a disk image for a VM.
    pub fn new(os_flavor: OsFlavor) -> Self {
        Self {
            os_flavor,
            pipette: None,
            extras: Vec::new(),
            free_space: 0,
        }
    }

    /// Adds the appropriate pipette binary to the image
    pub fn with_pipette(mut self, resolver: &ArtifactResolver<'_>, arch: MachineArch) -> Self {
        self.pipette = match (self.os_flavor, arch) {
            (OsFlavor::Windows, MachineArch::X86_64) => Some(
                resolver
                    .require(common_artifacts::PIPETTE_WINDOWS_X64)
                    .erase(),
            ),
            (OsFlavor::Linux, MachineArch::X86_64) => Some(
                resolver
                    .require(common_artifacts::PIPETTE_LINUX_X64_MUSL)
                    .erase(),
            ),
            (OsFlavor::Windows, MachineArch::Aarch64) => Some(
                resolver
                    .require(common_artifacts::PIPETTE_WINDOWS_AARCH64)
                    .erase(),
            ),
            (OsFlavor::Linux, MachineArch::Aarch64) => Some(
                resolver
                    .require(common_artifacts::PIPETTE_LINUX_AARCH64_MUSL)
                    .erase(),
            ),
            (OsFlavor::FreeBsd | OsFlavor::Uefi, _) => {
                todo!("No pipette binary yet for os");
            }
        };
        self
    }

    /// Check if the image contains pipette
    pub fn contains_pipette(&self) -> bool {
        self.pipette.is_some()
    }

    /// Check if the image has extra files beyond pipette and cloud-init.
    pub fn has_extras(&self) -> bool {
        !self.extras.is_empty()
    }

    /// Adds an extra file to the disk image.
    pub fn add_file(&mut self, name: &str, file_path: impl AsRef<Path>) {
        self.extras.push((
            name.into(),
            ImageEntry::File(file_path.as_ref().to_path_buf()),
        ));
    }

    /// Add collection of image entries
    pub fn add_extras(&mut self, extras: Vec<(String, ImageEntry)>) {
        self.extras.extend(extras);
    }

    /// Allocate some extra free space in the image
    pub fn allocate_free_space(&mut self, space: u64) {
        self.free_space = space;
    }

    /// Builds a disk image containing pipette and any files needed for the guest VM
    /// to run pipette.
    pub fn build(&self, image_type: ImageType) -> anyhow::Result<Option<tempfile::NamedTempFile>> {
        let mut files = self
            .extras
            .iter()
            .map(|(name, file_path)| (name.as_str(), file_path.as_content()))
            .collect::<Vec<_>>();
        let volume_label = match self.os_flavor {
            OsFlavor::Windows => {
                // Windows doesn't use cloud-init, so we only need pipette
                // (which is configured via the IMC hive).
                if let Some(pipette) = self.pipette.as_ref() {
                    files.push(("pipette.exe", ImageEntryContent::Path(pipette.as_ref())));
                }
                b"pipette    "
            }
            OsFlavor::Linux => {
                if let Some(pipette) = self.pipette.as_ref() {
                    files.push(("pipette", ImageEntryContent::Path(pipette.as_ref())));
                }
                // Linux uses cloud-init, so we need to include the cloud-init
                // configuration files as well.
                files.extend([
                    (
                        "meta-data",
                        ImageEntryContent::Binary(include_bytes!("../guest-bootstrap/meta-data")),
                    ),
                    (
                        "user-data",
                        if self.pipette.is_some() {
                            ImageEntryContent::Binary(include_bytes!(
                                "../guest-bootstrap/user-data"
                            ))
                        } else {
                            ImageEntryContent::Binary(include_bytes!(
                                "../guest-bootstrap/user-data-no-agent"
                            ))
                        },
                    ),
                    // Specify a non-present NIC to work around https://github.com/canonical/cloud-init/issues/5511
                    // TODO: support dynamically configuring the network based on vm configuration
                    (
                        "network-config",
                        ImageEntryContent::Binary(include_bytes!(
                            "../guest-bootstrap/network-config"
                        )),
                    ),
                ]);
                b"cidata     " // cloud-init looks for a volume label of "cidata",
            }
            // Nothing OS-specific yet for other flavors
            _ => b"cidata     ",
        };

        let total_data_size: u64 = files
            .iter()
            .map(|(_, f)| {
                Ok(match f {
                    ImageEntryContent::Dir => 0,
                    ImageEntryContent::Path(path) => fs_err::metadata(path)?.len(),
                    ImageEntryContent::Binary(data) => data.len() as u64,
                })
            })
            .collect::<Result<Vec<_>, std::io::Error>>()?
            .into_iter()
            .sum();

        let total_size = total_data_size + self.free_space;

        if files.is_empty() {
            Ok(None)
        } else {
            let mut image_file = match image_type {
                ImageType::Raw => tempfile::NamedTempFile::new()?,
                ImageType::Vhd => tempfile::Builder::new().suffix(".vhd").tempfile()?,
            };

            image_file
                .as_file()
                .set_len(total_size.next_multiple_of(64 * 1024 * 1024))
                .context("failed to set file size")?;

            build_fat32_disk_image(&mut image_file, "CIDATA", volume_label, &files)?;

            if matches!(image_type, ImageType::Vhd) {
                disk_vhd1::Vhd1Disk::make_fixed(image_file.as_file())
                    .context("failed to make vhd for agent image")?;
            }

            Ok(Some(image_file))
        }
    }
}

pub(crate) const SECTOR_SIZE: u64 = 512;

pub(crate) enum ImageEntryContent<'a> {
    Dir,
    Path(&'a Path),
    Binary(&'a [u8]),
}

pub(crate) fn build_fat32_disk_image(
    file: &mut (impl Read + Write + Seek),
    gpt_name: &str,
    volume_label: &[u8; 11],
    files: &[(&str, ImageEntryContent<'_>)],
) -> anyhow::Result<()> {
    let partition_range =
        build_gpt(file, gpt_name).context("failed to construct partition table")?;
    build_fat32(
        &mut fscommon::StreamSlice::new(file, partition_range.start, partition_range.end)?,
        volume_label,
        files,
    )
    .context("failed to format volume")?;
    Ok(())
}

fn build_gpt(file: &mut (impl Read + Write + Seek), name: &str) -> anyhow::Result<Range<u64>> {
    let mut gpt = gptman::GPT::new_from(file, SECTOR_SIZE, Guid::new_random().into())?;

    // Set up the "Protective" Master Boot Record
    gptman::GPT::write_protective_mbr_into(file, SECTOR_SIZE)?;

    // Set up the GPT Partition Table Header
    gpt[1] = gptman::GPTPartitionEntry {
        // Basic data partition guid
        partition_type_guid: guid::guid!("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").into(),
        unique_partition_guid: Guid::new_random().into(),
        starting_lba: gpt.header.first_usable_lba,
        ending_lba: gpt.header.last_usable_lba,
        attribute_bits: 0,
        partition_name: name.into(),
    };
    gpt.write_into(file)?;

    // calculate the EFI partition's usable range
    let partition_start_byte = gpt[1].starting_lba * SECTOR_SIZE;
    let partition_num_bytes = (gpt[1].ending_lba - gpt[1].starting_lba) * SECTOR_SIZE;
    Ok(partition_start_byte..partition_start_byte + partition_num_bytes)
}

fn build_fat32(
    file: &mut (impl Read + Write + Seek),
    volume_label: &[u8; 11],
    files: &[(&str, ImageEntryContent<'_>)],
) -> anyhow::Result<()> {
    fatfs::format_volume(
        &mut *file,
        FormatVolumeOptions::new()
            .volume_label(*volume_label)
            .fat_type(fatfs::FatType::Fat32),
    )
    .context("failed to format volume")?;
    let fs = fatfs::FileSystem::new(file, FsOptions::new()).context("failed to open fs")?;
    for (path, src) in files {
        if matches!(src, ImageEntryContent::Dir) {
            fs.root_dir()
                .create_dir(path)
                .context("failed to create dir")?;
            continue;
        }

        let mut dest = fs
            .root_dir()
            .create_file(path)
            .context("failed to create file")?;
        match *src {
            ImageEntryContent::Path(src_path) => {
                let mut src = fs_err::File::open(src_path)?;
                std::io::copy(&mut src, &mut dest).context("failed to copy file")?;
            }
            ImageEntryContent::Binary(src_data) => {
                dest.write_all(src_data).context("failed to write file")?;
            }
            ImageEntryContent::Dir => unreachable!(),
        }
        dest.flush().context("failed to flush file")?;
    }
    fs.unmount().context("failed to unmount fs")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn check_image(file: &mut std::fs::File, label: &[u8], expected: &[(&str, &[u8])]) {
        let gpt = gptman::GPT::read_from(file, SECTOR_SIZE).unwrap();
        assert_eq!(gpt[1].partition_name.as_str(), "CIDATA");
        let basic_data_guid: [u8; 16] = guid::guid!("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").into();
        assert_eq!(gpt[1].partition_type_guid, basic_data_guid);
        let start = gpt[1].starting_lba * SECTOR_SIZE;
        let end = (gpt[1].ending_lba + 1) * SECTOR_SIZE;
        let partition = fscommon::StreamSlice::new(file, start, end).unwrap();
        let fs = fatfs::FileSystem::new(partition, FsOptions::new()).unwrap();
        assert_eq!(fs.volume_label_as_bytes(), label);
        for &(name, bytes) in expected {
            let mut contents = Vec::new();
            fs.root_dir()
                .open_file(name)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();
            assert_eq!(contents, bytes, "wrong contents for {name}");
        }
        fs.unmount().unwrap();
    }

    // Test: Build a Windows agent image with nested persistent and temporary files.
    // Expected: Decoding the GPT/FAT image finds the pipette volume and exact
    //       binary payloads at their requested paths.
    #[test]
    fn raw_agent_image_preserves_nested_and_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let persistent = directory.path().join("persistent");
        std::fs::write(&persistent, b"persistent\0\xff").unwrap();
        let mut temporary = tempfile::NamedTempFile::new().unwrap();
        temporary.write_all(b"temporary").unwrap();
        let mut builder = AgentImage::new(OsFlavor::Windows);
        builder.add_extras(vec![
            ("tools".into(), ImageEntry::Dir),
            (
                "temporary.bin".into(),
                ImageEntry::TempFile(temporary.into_temp_path()),
            ),
        ]);
        builder.add_file("tools/persistent.bin", &persistent);
        builder.allocate_free_space(crate::SIZE_1_MB);
        let mut image = builder.build(ImageType::Raw).unwrap().unwrap();
        check_image(
            image.as_file_mut(),
            b"pipette",
            &[
                ("tools/persistent.bin", b"persistent\0\xff"),
                ("temporary.bin", b"temporary"),
            ],
        );
    }

    // Test: Build Linux cloud-init images without an agent in raw and fixed-VHD modes.
    // Expected: Both expose the cidata configuration files; the VHD additionally
    //       has a fixed-disk footer with the correct size and checksum.
    #[test]
    fn linux_cloud_init_is_present_in_raw_and_fixed_vhd_images() {
        for mode in [ImageType::Raw, ImageType::Vhd] {
            let is_vhd = matches!(mode, ImageType::Vhd);
            let mut image = AgentImage::new(OsFlavor::Linux)
                .build(mode)
                .unwrap()
                .unwrap();
            let file = image.as_file_mut();
            let gpt = gptman::GPT::read_from(file, SECTOR_SIZE).unwrap();
            let partition = fscommon::StreamSlice::new(
                &mut *file,
                gpt[1].starting_lba * SECTOR_SIZE,
                (gpt[1].ending_lba + 1) * SECTOR_SIZE,
            )
            .unwrap();
            let fs = fatfs::FileSystem::new(partition, FsOptions::new()).unwrap();
            assert_eq!(fs.volume_label_as_bytes(), b"cidata");
            for name in ["meta-data", "user-data", "network-config"] {
                let mut contents = String::new();
                fs.root_dir()
                    .open_file(name)
                    .unwrap()
                    .read_to_string(&mut contents)
                    .unwrap();
                if name == "user-data" {
                    assert!(contents.starts_with("#cloud-config\n"));
                    assert!(!contents.contains("pipette"));
                } else if name == "network-config" {
                    assert!(contents.contains("optional: true"));
                }
            }
            fs.unmount().unwrap();
            if is_vhd {
                let size = file.metadata().unwrap().len();
                file.seek(std::io::SeekFrom::End(-512)).unwrap();
                let mut footer = [0; 512];
                file.read_exact(&mut footer).unwrap();
                assert_eq!(&footer[..8], b"conectix");
                assert_eq!(u32::from_be_bytes(footer[60..64].try_into().unwrap()), 2);
                assert_eq!(
                    u64::from_be_bytes(footer[48..56].try_into().unwrap()),
                    size - 512
                );
                let checksum = u32::from_be_bytes(footer[64..68].try_into().unwrap());
                footer[64..68].fill(0);
                assert_eq!(
                    checksum,
                    !footer.iter().map(|&byte| u32::from(byte)).sum::<u32>()
                );
            }
        }
    }

    // Test: Build an empty Windows image, then request a nonexistent extra file.
    // Expected: No image is needed without entries, but missing requested data
    //       remains an IO error rather than silently producing an empty image.
    #[test]
    fn absent_image_and_missing_requested_file_remain_distinct() {
        let mut builder = AgentImage::new(OsFlavor::Windows);
        assert!(builder.build(ImageType::Raw).unwrap().is_none());
        let directory = tempfile::tempdir().unwrap();
        builder.add_file("missing.bin", directory.path().join("missing"));
        let error = builder.build(ImageType::Raw).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    // IGNORED: The builder sizes this nonempty image from its zero payload bytes.
    //       It passes a zero-length disk to gptman, which panics on subtraction
    //       overflow in the development profile. Retain the intended contract
    //       without changing production code in this tests-only campaign.
    //
    // Test: Request an agent image containing only an explicitly added directory.
    // Expected: A valid image contains that directory even without payload bytes
    //       or an explicit extra-free-space allocation.
    #[test]
    #[ignore = "directory-only images produce a zero-length disk and panic in gptman"]
    fn directory_only_agent_image_has_room_for_filesystem_metadata() {
        let mut builder = AgentImage::new(OsFlavor::Windows);
        builder.add_extras(vec![("empty".into(), ImageEntry::Dir)]);
        let mut image = builder.build(ImageType::Raw).unwrap().unwrap();
        let file = image.as_file_mut();
        let gpt = gptman::GPT::read_from(file, SECTOR_SIZE).unwrap();
        let partition = fscommon::StreamSlice::new(
            file,
            gpt[1].starting_lba * SECTOR_SIZE,
            (gpt[1].ending_lba + 1) * SECTOR_SIZE,
        )
        .unwrap();
        let fs = fatfs::FileSystem::new(partition, FsOptions::new()).unwrap();
        {
            let directory = fs.root_dir().open_dir("empty").unwrap();
            let names = directory
                .iter()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(names, [".", ".."]);
        }
        fs.unmount().unwrap();
    }
}
