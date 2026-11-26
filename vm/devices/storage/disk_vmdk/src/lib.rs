// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VMDK disk format support.

#![deny(unsafe_code)]

mod errors;
mod flat;
#[cfg(target_os = "linux")]
mod io_uring;

pub use errors::OpenError;
pub use errors::ParseError;
pub use flat::FlatVmdkResolver;
pub use flat::ResolveFlatVmdkError;

use std::path::Path;
use vm_resource::Resource;
use vm_resource::kind::DiskHandleKind;

// Reject VMDK descriptor files larger than 1 MiB.
pub(crate) const MAX_DESCRIPTOR_SIZE: u64 = 1 << 20;

/// Opens and validates a VMDK descriptor and its extent files.
pub fn open_vmdk(path: &Path, read_only: bool) -> Result<Resource<DiskHandleKind>, OpenError> {
    Ok(Resource::new(flat::open_flat_vmdk(path, read_only)?))
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use disk_backend::DiskError;
    use disk_backend::resolve::ResolveDiskParameters;
    use disk_backend::resolve::ResolvedDisk;
    use disk_backend_resources::FlatVmdkDiskHandle;
    use disk_backend_resources::FlatVmdkExtent;
    use disk_backend_resources::VmdkExtentAccess;
    use guestmem::GuestMemory;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use scsi_buffers::OwnedRequestBuffers;
    use test_with_tracing::test;
    use vm_resource::AsyncResolveResource;
    use vm_resource::ResourceResolver;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    // Test: Transport an opened descriptor resource before resolving the disk.
    // Expected: Open source ownership outlives path replacement; repeated-file
    //       extents retain descriptor order, sector offsets and final padding.
    #[async_test]
    async fn transported_descriptor_retains_opened_source_identity(driver: DefaultDriver) {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let source_path = directory.path().join("source.bin");
        let descriptor_path = directory.path().join("disk.vmdk");
        let mut source = vec![0x21; 512];
        source.extend_from_slice(&[0x76; 512]);
        source.extend_from_slice(&[0x80, 0x00, 0xff, 0x45, 0x11, 0x73, 0x22]);
        std::fs::write(&source_path, &source).unwrap();
        std::fs::write(
            &descriptor_path,
            concat!(
                "# Disk DescriptorFile\nversion=1\ncreateType=\"twoGbMaxExtentFlat\"\n",
                "RW 1 FLAT \"source.bin\" 1\n",
                "RDONLY 1 FLAT \"source.bin\" 2\n",
                "RW 1 FLAT \"source.bin\" 0\n",
            ),
        )
        .unwrap();
        let handle = open_vmdk(&descriptor_path, true).unwrap();
        let (bytes, resources) = mesh::Message::new(handle).serialize();
        let transferred: Resource<DiskHandleKind> = mesh::Message::serialized(&bytes, resources)
            .parse()
            .unwrap();
        std::fs::rename(&source_path, directory.path().join("original.bin")).unwrap();
        std::fs::write(&source_path, [0xee; 1536]).unwrap();
        std::fs::remove_file(descriptor_path).unwrap();
        let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        let mut resolver = ResourceResolver::new();
        resolver.add_async_resolver(FlatVmdkResolver);
        let disk: ResolvedDisk = resolver
            .resolve(
                transferred,
                ResolveDiskParameters {
                    read_only: true,
                    driver_source: &driver_source,
                },
            )
            .await
            .unwrap();
        let memory = GuestMemory::allocate(1536);
        memory.fill_at(0, 0xcc, 1536).unwrap();
        let buffers = OwnedRequestBuffers::linear(0, 1536, true);
        disk.0
            .read_vectored(&buffers.buffer(&memory), 0)
            .await
            .unwrap();
        let mut actual = vec![0; 1536];
        memory.read_at(0, &mut actual).unwrap();
        let mut expected = vec![0x76; 512];
        expected.extend_from_slice(&source[1024..]);
        expected.resize(1024, 0);
        expected.extend_from_slice(&source[..512]);
        assert_eq!(actual, expected);
        assert!(matches!(
            disk.0
                .write_vectored(&buffers.buffer(&memory), 0, false)
                .await,
            Err(DiskError::ReadOnly)
        ));
        assert_eq!(std::fs::read(source_path).unwrap(), [0xee; 1536]);
    }

    // Test: Resolve transported extent records with an absent source-table entry.
    // Expected: Unsupported writable mode and invalid source references return
    //       typed resolver errors before a disk can expose guest I/O.
    #[async_test]
    async fn resolver_revalidates_transported_source_indices(driver: DefaultDriver) {
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        for read_only in [false, true] {
            let resource = FlatVmdkDiskHandle {
                files: Vec::new(),
                extents: vec![FlatVmdkExtent {
                    file_index: 0,
                    access: VmdkExtentAccess::ReadOnly,
                    sector_count: 1,
                    source_start_sector: 0,
                }],
            };
            let result = FlatVmdkResolver
                .resolve(
                    &ResourceResolver::new(),
                    resource,
                    ResolveDiskParameters {
                        read_only,
                        driver_source: &source,
                    },
                )
                .await;
            if read_only {
                assert!(matches!(
                    result,
                    Err(ResolveFlatVmdkError::Open(OpenError::InvalidExtentMap(_)))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(ResolveFlatVmdkError::ReadWriteUnsupported)
                ));
            }
        }
    }
}
