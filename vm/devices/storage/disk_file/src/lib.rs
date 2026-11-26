// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

mod readwriteat;

use self::readwriteat::ReadWriteAt;
use blocking::unblock;
use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::resolve::ResolveDiskParameters;
use disk_backend::resolve::ResolvedDisk;
use disk_backend_resources::FileDiskHandle;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use inspect::Inspect;
use scsi_buffers::RequestBuffers;
use std::fs;
use std::sync::Arc;
use thiserror::Error;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::DiskHandleKind;

pub struct FileDiskResolver;
declare_static_resolver!(FileDiskResolver, (DiskHandleKind, FileDiskHandle));

#[derive(Debug, Error)]
pub enum ResolveFileDiskError {
    #[error("i/o error")]
    Io(#[source] std::io::Error),
    #[error("invalid disk")]
    InvalidDisk(#[source] disk_backend::InvalidDisk),
}

impl ResolveResource<DiskHandleKind, FileDiskHandle> for FileDiskResolver {
    type Output = ResolvedDisk;
    type Error = ResolveFileDiskError;

    fn resolve(
        &self,
        rsrc: FileDiskHandle,
        input: ResolveDiskParameters<'_>,
    ) -> Result<Self::Output, Self::Error> {
        ResolvedDisk::new(
            FileDisk::open(rsrc.0, input.read_only).map_err(ResolveFileDiskError::Io)?,
        )
        .map_err(ResolveFileDiskError::InvalidDisk)
    }
}

#[derive(Debug, Inspect)]
pub struct FileDisk {
    file: Arc<fs::File>,
    metadata: Metadata,
    sector_shift: u32,
}

#[derive(Debug, Inspect)]
pub struct Metadata {
    pub disk_size: u64,
    pub sector_size: u32,
    pub physical_sector_size: u32,
    pub read_only: bool,
}

#[cfg(windows)]
impl std::os::windows::io::AsHandle for FileDisk {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

impl FileDisk {
    pub fn open(file: fs::File, read_only: bool) -> Result<Self, std::io::Error> {
        let metadata = Metadata {
            disk_size: file.metadata()?.len(),
            sector_size: 512,
            physical_sector_size: 4096,
            read_only,
        };
        Ok(Self::with_metadata(file, metadata))
    }

    /// Opens the disk using the specified metadata.
    ///
    /// This ensures that no metadata queries are made to the file, which may be
    /// appropriate if this is wrapped in another disk implementation that
    /// retrieves metadata in another way.
    pub fn with_metadata(file: fs::File, metadata: Metadata) -> Self {
        assert!(metadata.sector_size.is_power_of_two());
        assert!(metadata.sector_size >= 512);
        let sector_shift = metadata.sector_size.trailing_zeros();
        FileDisk {
            file: Arc::new(file),
            metadata,
            sector_shift,
        }
    }

    pub fn into_inner(self) -> fs::File {
        Arc::try_unwrap(self.file).expect("no outstanding IOs")
    }
}

impl FileDisk {
    pub async fn read(&self, buffers: &RequestBuffers<'_>, sector: u64) -> Result<(), DiskError> {
        if ((sector << self.sector_shift) + buffers.len() as u64) > self.metadata.disk_size {
            return Err(DiskError::IllegalBlock);
        }
        let mut buffer = vec![0; buffers.len()];
        let file = self.file.clone();
        let offset = sector << self.sector_shift;
        let buffer = unblock(move || -> Result<_, std::io::Error> {
            let count = file.read_at(&mut buffer, offset)?;
            if count != buffer.len() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short disk read",
                ))
            } else {
                Ok(buffer)
            }
        })
        .await
        .map_err(DiskError::Io)?;
        buffers.writer().write(&buffer)?;
        Ok(())
    }

    pub async fn write(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        _fua: bool,
    ) -> Result<(), DiskError> {
        if ((sector << self.sector_shift) + buffers.len() as u64) > self.metadata.disk_size {
            return Err(DiskError::IllegalBlock);
        }
        let mut buffer = vec![0; buffers.len()];
        let file = self.file.clone();
        buffers.reader().read(&mut buffer)?;
        let offset = sector << self.sector_shift;
        unblock(move || -> Result<(), std::io::Error> {
            let count = file.write_at(&buffer, offset)?;
            if count != buffer.len() {
                Err(std::io::Error::other("short disk write"))
            } else {
                Ok(())
            }
        })
        .await
        .map_err(DiskError::Io)?;
        Ok(())
    }

    pub async fn flush(&self) -> Result<(), DiskError> {
        let file = self.file.clone();
        unblock(move || file.sync_all())
            .await
            .map_err(DiskError::Io)?;
        Ok(())
    }
}

impl DiskIo for FileDisk {
    fn disk_type(&self) -> &str {
        "file"
    }

    fn sector_count(&self) -> u64 {
        self.metadata.disk_size >> self.sector_shift
    }

    fn sector_size(&self) -> u32 {
        self.metadata.sector_size
    }

    fn is_read_only(&self) -> bool {
        self.metadata.read_only
    }

    fn disk_id(&self) -> Option<[u8; 16]> {
        None
    }

    fn physical_sector_size(&self) -> u32 {
        self.metadata.physical_sector_size
    }

    fn is_fua_respected(&self) -> bool {
        false
    }

    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        self.read(buffers, sector).await
    }

    async fn write_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        fua: bool,
    ) -> Result<(), DiskError> {
        self.write(buffers, sector, fua).await
    }

    async fn sync_cache(&self) -> Result<(), DiskError> {
        self.flush().await
    }

    async fn unmap(
        &self,
        _sector: u64,
        _count: u64,
        _block_level_only: bool,
    ) -> Result<(), DiskError> {
        Ok(())
    }

    fn unmap_behavior(&self) -> disk_backend::UnmapBehavior {
        disk_backend::UnmapBehavior::Ignored
    }
}

#[cfg(test)]
mod tests {
    use super::FileDisk;
    use disk_backend::Disk;
    use disk_backend::DiskError;
    use guestmem::GuestMemory;
    use pal_async::async_test;
    use scsi_buffers::OwnedRequestBuffers;

    const SECTOR_SIZE: usize = 512;
    const DISK_SIZE: u64 = 1024 * 1024;

    fn file_disk() -> Disk {
        let file = tempfile::tempfile().unwrap();
        file.set_len(DISK_SIZE).unwrap();
        Disk::new(FileDisk::open(file, false).unwrap()).unwrap()
    }

    #[async_test]
    async fn short_read_returns_error() {
        let file = tempfile::tempfile().unwrap();
        file.set_len(DISK_SIZE).unwrap();
        let disk = FileDisk::open(file.try_clone().unwrap(), false).unwrap();
        file.set_len((SECTOR_SIZE + SECTOR_SIZE / 2) as u64)
            .unwrap();

        let mem = GuestMemory::allocate(SECTOR_SIZE);
        mem.write_at(0, &[0xcd; SECTOR_SIZE]).unwrap();
        let buffers = OwnedRequestBuffers::linear(0, SECTOR_SIZE, true);
        let result = disk.read(&buffers.buffer(&mem), 1).await;

        assert!(
            matches!(result, Err(DiskError::Io(ref error)) if error.kind() == std::io::ErrorKind::UnexpectedEof),
            "{result:?}"
        );
        let mut contents = [0; SECTOR_SIZE];
        mem.read_at(0, &mut contents).unwrap();
        assert_eq!(contents, [0xcd; SECTOR_SIZE]);
    }

    #[async_test]
    async fn sector_range_conformance() {
        storage_tests::sector_range::test_disk_sector_range_conformance(&file_disk()).await;
    }

    /// The range check here is in byte units, computing `sector << sector_shift`.
    /// A left shift discards high bits without panicking, so a large enough
    /// sector wraps to a small byte offset and passes the check.
    ///
    /// This is the one defect in this area whose symptom was silent wrong data
    /// rather than a panic, so the test asserts both that the request is
    /// rejected and that it did not return the contents of sector 0.
    #[async_test]
    async fn sector_does_not_wrap_when_shifted() {
        let disk = file_disk();
        let mem = GuestMemory::allocate(SECTOR_SIZE);

        mem.write_at(0, &[0xcd; SECTOR_SIZE]).unwrap();
        disk.write_vectored(
            &OwnedRequestBuffers::linear(0, SECTOR_SIZE, false).buffer(&mem),
            0,
            false,
        )
        .await
        .unwrap();
        mem.write_at(0, &[0; SECTOR_SIZE]).unwrap();

        // `1 << 55` shifted left by 9 (512-byte sectors) is `1 << 64`, which
        // truncates to a byte offset of zero.
        let r = disk
            .read_vectored(
                &OwnedRequestBuffers::linear(0, SECTOR_SIZE, true).buffer(&mem),
                1 << 55,
            )
            .await;

        let mut buf = [0; SECTOR_SIZE];
        mem.read_at(0, &mut buf).unwrap();
        assert_ne!(buf, [0xcd; SECTOR_SIZE], "read returned sector 0");
        assert!(matches!(r, Err(DiskError::IllegalBlock)), "{r:?}");
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use guestmem::GuestMemory;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use scsi_buffers::OwnedRequestBuffers;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use test_with_tracing::test;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    // Test: Scatter/gather two 4K sectors inside a metadata-bounded disk image.
    // Expected: Sector scaling, buffer order and flush preserve exact file
    //       data, adjacent sectors and an excluded footer; unmap is a no-op.
    #[async_test]
    async fn scatter_gather_respects_metadata_and_preserves_footer() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut file = tempfile::tempfile_in(directory.path()).unwrap();
        let mut expected = vec![0x6d; 0x4200];
        file.write_all(&expected).unwrap();
        let disk = FileDisk::with_metadata(
            file,
            Metadata {
                disk_size: 0x4000,
                sector_size: 4096,
                physical_sector_size: 4096,
                read_only: false,
            },
        );
        let memory = GuestMemory::allocate(0x3000);
        memory.write_at(0x2000, &[0x19; 4096]).unwrap();
        memory.write_at(0, &[0xb3; 4096]).unwrap();
        let buffers = OwnedRequestBuffers::new(&[2, 0]);
        disk.write_vectored(&buffers.buffer(&memory), 1, true)
            .await
            .unwrap();
        disk.sync_cache().await.unwrap();
        disk.unmap(1, 2, false).await.unwrap();
        memory.fill_at(0, 0x88, 0x3000).unwrap();
        disk.read_vectored(&buffers.buffer(&memory), 1)
            .await
            .unwrap();
        let mut observed = vec![0; 0x3000];
        memory.read_at(0, &mut observed).unwrap();
        assert_eq!(&observed[..4096], &[0xb3; 4096]);
        assert_eq!(&observed[4096..8192], &[0x88; 4096]);
        assert_eq!(&observed[8192..], &[0x19; 4096]);
        let footer_request = OwnedRequestBuffers::linear(0, 4096, false);
        assert!(matches!(
            disk.write_vectored(&footer_request.buffer(&memory), 4, false)
                .await,
            Err(DiskError::IllegalBlock)
        ));
        assert!(matches!(
            disk.read_vectored(&footer_request.buffer(&memory), 4).await,
            Err(DiskError::IllegalBlock)
        ));
        expected[0x1000..0x2000].fill(0x19);
        expected[0x2000..0x3000].fill(0xb3);
        let mut file = disk.into_inner();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }

    // Test: Resolve a read-only file resource and issue reads and discard.
    // Expected: File bytes remain readable while the resolved read-only policy
    //       rejects discard without altering the underlying file.
    #[async_test]
    async fn resolver_preserves_read_only_policy(driver: DefaultDriver) {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut file = tempfile::tempfile_in(directory.path()).unwrap();
        file.write_all(&[0x93; 1024]).unwrap();
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        let disk = FileDiskResolver
            .resolve(
                FileDiskHandle(file),
                ResolveDiskParameters {
                    read_only: true,
                    driver_source: &source,
                },
            )
            .unwrap()
            .0;
        let memory = GuestMemory::allocate(512);
        disk.read_vectored(
            &OwnedRequestBuffers::linear(0, 512, true).buffer(&memory),
            1,
        )
        .await
        .unwrap();
        let mut bytes = [0; 512];
        memory.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x93; 512]);
        assert!(matches!(
            disk.unmap(0, 1, false).await,
            Err(DiskError::ReadOnly)
        ));
        disk.read_vectored(
            &OwnedRequestBuffers::linear(0, 512, true).buffer(&memory),
            0,
        )
        .await
        .unwrap();
        memory.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x93; 512]);
    }

    // Test: Write through an OS read-only descriptor and an inaccessible guest buffer.
    // Expected: Both failures propagate rather than reporting successful I/O,
    //       and neither can modify the backing file.
    #[async_test]
    async fn backing_and_guest_access_errors_propagate() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = directory.path().join("disk");
        fs::write(&path, [0x32; 1024]).unwrap();
        let disk = FileDisk::open(fs::File::open(&path).unwrap(), true).unwrap();
        let memory = GuestMemory::allocate(512);
        let buffers = OwnedRequestBuffers::linear(0, 512, false);
        assert!(matches!(
            disk.write(&buffers.buffer(&memory), 0, false).await,
            Err(DiskError::Io(_))
        ));
        let writable = FileDisk::open(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            false,
        )
        .unwrap();
        let inaccessible = OwnedRequestBuffers::linear(0x2000, 512, false);
        assert!(
            writable
                .write(&inaccessible.buffer(&memory), 0, false)
                .await
                .is_err()
        );
        assert!(
            writable
                .read(&inaccessible.buffer(&memory), 0)
                .await
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), [0x32; 1024]);
    }
}
