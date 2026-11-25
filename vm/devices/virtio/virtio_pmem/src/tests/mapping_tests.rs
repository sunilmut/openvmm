// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use sparse_mmap::AsMappableRef;
use sparse_mmap::SparseMapping;
use std::io;
use test_with_tracing::test;

struct Region {
    mapping: SparseMapping,
    calls: Mutex<Vec<(usize, u64, usize, bool)>>,
    fail_on: Option<usize>,
}

impl Region {
    fn new(fail_on: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            mapping: SparseMapping::new(0x20_0000).unwrap(),
            calls: Mutex::new(Vec::new()),
            fail_on,
        })
    }
}

impl guestmem::MappedMemoryRegion for Region {
    fn map(
        &self,
        offset: usize,
        section: &dyn AsMappableRef,
        file_offset: u64,
        len: usize,
        writable: bool,
    ) -> io::Result<()> {
        let mut calls = self.calls.lock();
        let index = calls.len();
        calls.push((offset, file_offset, len, writable));
        if self.fail_on == Some(index) {
            return Err(io::Error::other("injected mapping failure"));
        }
        self.mapping
            .map_file(offset, len, section, file_offset, writable)
    }

    fn unmap(&self, offset: usize, len: usize) -> io::Result<()> {
        self.mapping.unmap(offset, len)
    }
}

// Test: Map a short PMEM file into a real sparse region in writable and read-only modes, then access both the file-backed prefix and aligned tail.
// Expected: Mapping ranges/permissions match the advertised extent, file bytes and zero padding are readable, writable memory updates backing bytes, and read-only file/padding mappings reject writes without changing the source.
#[async_test]
async fn shared_memory_maps_real_file_bytes_padding_and_permissions(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    for writable in [false, true] {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        file.write_all(&[0x91; 64]).unwrap();
        let mut device = Device::new(&driver_source, file.try_clone().unwrap(), writable).unwrap();
        let region = Region::new(None);
        let interface: Arc<dyn guestmem::MappedMemoryRegion> = region.clone();
        device.set_shared_memory_region(&interface).unwrap();
        let expected = if writable {
            vec![(0, 0, 0x20_0000, true)]
        } else {
            vec![(0, 0, 4096, false), (4096, 0, 0x20_0000 - 4096, false)]
        };
        assert_eq!(*region.calls.lock(), expected);
        let mut bytes = [0; 64];
        region.mapping.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x91; 64]);
        region.mapping.read_at(4096, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 64]);
        if writable {
            region.mapping.write_at(0, &[0x27; 64]).unwrap();
            region.mapping.write_at(4096, &[0x72; 64]).unwrap();
        } else {
            assert!(region.mapping.write_at(0, &[0x27; 64]).is_err());
            assert!(region.mapping.write_at(4096, &[0x72; 64]).is_err());
        }
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [if writable { 0x27 } else { 0x91 }; 64]);
        assert_eq!(
            file.metadata().unwrap().len(),
            if writable { 0x20_0000 } else { 4096 }
        );
    }
}

// Test: Fail mapping the file or the separate read-only padding, then retry mapping the same device into a fresh functioning region.
// Expected: The correct mapping stage is reported with its source error; retry maps the full region successfully with readable zero padding and no backing-file extension.
#[async_test]
async fn shared_memory_mapping_errors_identify_stage_and_allow_retry(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    for (index, expected) in [
        (0, "failed to map persistent memory file"),
        (1, "failed to map persistent memory padding"),
    ] {
        let file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        let mut device = Device::new(&driver_source, file.try_clone().unwrap(), false).unwrap();
        let failed = Region::new(Some(index));
        let interface: Arc<dyn guestmem::MappedMemoryRegion> = failed;
        let error = device.set_shared_memory_region(&interface).unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.root_cause().to_string(), "injected mapping failure");
        let retry = Region::new(None);
        let interface: Arc<dyn guestmem::MappedMemoryRegion> = retry.clone();
        device.set_shared_memory_region(&interface).unwrap();
        let mut bytes = [0xff; 64];
        retry.mapping.read_at(4096, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 64]);
        assert_eq!(file.metadata().unwrap().len(), 4096);
    }
}

// Test: Resolve PMEM resources by path under read-only/writable policy and access the resolved device through its dynamic shared-memory interface; also resolve missing and empty files.
// Expected: Resolution preserves file bytes and read-only length/permissions, writable resolution extends and maps a usable aligned range, and missing/empty sources fail without implicit creation.
#[async_test]
async fn resolver_backing_path_policy_reaches_a_working_mapped_device(driver: DefaultDriver) {
    use crate::resolver::VirtioPmemResolver;
    use virtio::resolve::VirtioResolveInput;
    use virtio_resources::pmem::VirtioPmemHandle;
    use vm_resource::ResolveResource;

    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    for read_only in [true, false] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(4096).unwrap();
        file.write_all(&[0x91; 64]).unwrap();
        let mut device = VirtioPmemResolver
            .resolve(
                VirtioPmemHandle {
                    path: file.path().to_str().unwrap().into(),
                    read_only,
                },
                VirtioResolveInput {
                    driver_source: &driver_source,
                },
            )
            .unwrap();
        assert_eq!(device.0.traits().shared_memory.size, 0x20_0000);
        let region = Region::new(None);
        let interface: Arc<dyn guestmem::MappedMemoryRegion> = region.clone();
        device.0.set_shared_memory_region(&interface).unwrap();
        let mut bytes = [0; 64];
        region.mapping.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x91; 64]);
        assert!(region.calls.lock().iter().all(|call| call.3 != read_only));
        assert_eq!(
            file.as_file().metadata().unwrap().len(),
            if read_only { 4096 } else { 0x20_0000 }
        );
        assert_eq!(region.mapping.write_at(0, &[0x27; 64]).is_ok(), !read_only);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [if read_only { 0x91 } else { 0x27 }; 64]);
    }
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pmem");
    for read_only in [true, false] {
        assert!(
            VirtioPmemResolver
                .resolve(
                    VirtioPmemHandle {
                        path: missing.to_str().unwrap().into(),
                        read_only
                    },
                    VirtioResolveInput {
                        driver_source: &driver_source
                    },
                )
                .is_err()
        );
        assert!(!missing.exists());
    }
    let empty = tempfile::NamedTempFile::new().unwrap();
    let error = VirtioPmemResolver
        .resolve(
            VirtioPmemHandle {
                path: empty.path().to_str().unwrap().into(),
                read_only: true,
            },
            VirtioResolveInput {
                driver_source: &driver_source,
            },
        )
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "persistent memory file must not be empty"
    );
}
