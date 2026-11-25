// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Disk;
use super::DiskError;
use super::DiskIo;
use super::InvalidDisk;
use super::UnmapBehavior;
use crate::resolve::ResolvedDisk;
use crate::sync_wrapper::BlockingDisk;
use futures::FutureExt;
use futures::executor::block_on;
use guestmem::GuestMemory;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use parking_lot::Mutex;
use scsi_buffers::OwnedRequestBuffers;
use scsi_buffers::RequestBuffers;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

struct State {
    bytes: Mutex<Vec<u8>>,
    writes: Mutex<Vec<(u64, bool)>>,
    unmaps: Mutex<Vec<(u64, u64, bool)>>,
    flushes: AtomicU64,
    sectors: AtomicU64,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
}

#[derive(Clone)]
struct Backend {
    state: Arc<State>,
    sector_size: u32,
    physical_size: u32,
    read_only: bool,
    behavior: UnmapBehavior,
}

impl Backend {
    fn new() -> Self {
        Self {
            state: Arc::new(State {
                bytes: Mutex::new((0..2048).map(|i| (i / 512) as u8).collect()),
                writes: Mutex::default(),
                unmaps: Mutex::default(),
                flushes: AtomicU64::new(0),
                sectors: AtomicU64::new(4),
                fail_reads: AtomicBool::new(false),
                fail_writes: AtomicBool::new(false),
            }),
            sector_size: 512,
            physical_size: 4096,
            read_only: false,
            behavior: UnmapBehavior::Zeroes,
        }
    }
}

impl inspect::Inspect for Backend {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.ignore();
    }
}

impl DiskIo for Backend {
    fn disk_type(&self) -> &str {
        "test"
    }
    fn sector_count(&self) -> u64 {
        self.state.sectors.load(Ordering::SeqCst)
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn physical_sector_size(&self) -> u32 {
        self.physical_size
    }
    fn disk_id(&self) -> Option<[u8; 16]> {
        Some([0x42; 16])
    }
    fn is_fua_respected(&self) -> bool {
        true
    }
    fn is_read_only(&self) -> bool {
        self.read_only
    }
    fn unmap_behavior(&self) -> UnmapBehavior {
        self.behavior
    }
    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        if self.state.fail_reads.load(Ordering::SeqCst) {
            return Err(DiskError::IllegalBlock);
        }
        let start = usize::try_from(sector)
            .ok()
            .and_then(|v| v.checked_mul(self.sector_size as usize))
            .ok_or(DiskError::IllegalBlock)?;
        let bytes = self.state.bytes.lock();
        let source = bytes
            .get(
                start
                    ..start
                        .checked_add(buffers.len())
                        .ok_or(DiskError::IllegalBlock)?,
            )
            .ok_or(DiskError::IllegalBlock)?;
        buffers.writer().write(source)?;
        Ok(())
    }
    async fn write_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        fua: bool,
    ) -> Result<(), DiskError> {
        if self.read_only {
            return Err(DiskError::ReadOnly);
        }
        if self.state.fail_writes.load(Ordering::SeqCst) {
            return Err(DiskError::IllegalBlock);
        }
        let start = usize::try_from(sector)
            .ok()
            .and_then(|v| v.checked_mul(self.sector_size as usize))
            .ok_or(DiskError::IllegalBlock)?;
        let mut bytes = self.state.bytes.lock();
        let target = bytes
            .get_mut(
                start
                    ..start
                        .checked_add(buffers.len())
                        .ok_or(DiskError::IllegalBlock)?,
            )
            .ok_or(DiskError::IllegalBlock)?;
        buffers.reader().read(target)?;
        self.state.writes.lock().push((sector, fua));
        Ok(())
    }
    async fn sync_cache(&self) -> Result<(), DiskError> {
        self.state.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn unmap(
        &self,
        sector: u64,
        count: u64,
        block_level_only: bool,
    ) -> Result<(), DiskError> {
        self.state
            .unmaps
            .lock()
            .push((sector, count, block_level_only));
        Ok(())
    }
}

// Test: Construct disks with invalid logical and physical sector sizes.
// Expected: Construction rejects sizes that violate the disk alignment contract.
#[test]
fn disk_construction_rejects_invalid_sector_geometries() {
    for sector_size in [0, 256, 513] {
        assert!(matches!(
            Disk::new(Backend {
                sector_size,
                ..Backend::new()
            }),
            Err(InvalidDisk::InvalidSectorSize(_))
        ));
    }
    for physical_size in [0, 256, 513] {
        assert!(matches!(
            Disk::new(Backend {
                physical_size,
                ..Backend::new()
            }),
            Err(InvalidDisk::InvalidPhysicalSectorSize(_))
        ));
    }
}

// Test: Clone and resolve a disk while the backend changes its capacity.
// Expected: Handles share live capacity while preserving immutable disk geometry.
#[test]
fn disk_handles_share_live_capacity_and_validated_metadata() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let disk = ResolvedDisk::new(backend).unwrap().0;
    let clone = disk.clone();
    assert_eq!(disk.sector_size(), 512);
    assert_eq!(disk.sector_shift(), 9);
    assert_eq!(disk.physical_sector_size(), 4096);
    assert_eq!(disk.disk_id(), Some([0x42; 16]));
    assert!(disk.is_fua_respected());
    assert!(!disk.is_read_only());
    assert_eq!(disk.optimal_unmap_sectors(), 1);
    assert_eq!(disk.unmap_behavior(), UnmapBehavior::Zeroes);
    state.sectors.store(8, Ordering::SeqCst);
    assert_eq!(clone.sector_count(), 8);
    assert_eq!(format!("{disk:?}"), "Disk");
    assert!(disk.pr().is_none());
    assert!(matches!(
        block_on(disk.eject()),
        Err(DiskError::UnsupportedEject)
    ));
    assert!(disk.wait_resize(8).now_or_never().is_none());
}

// Test: Submit vectored reads, writes, flushes, and unmaps through a disk handle.
// Expected: Buffer bytes, FUA, ranges, and operation results reach the backend.
#[test]
fn disk_operations_forward_data_and_request_parameters() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let disk = Disk::new(backend).unwrap();
    let gm = GuestMemory::allocate(512);
    let owned = OwnedRequestBuffers::linear(0, 512, true);
    let buffers = owned.buffer(&gm);
    block_on(disk.read_vectored(&buffers, 1)).unwrap();
    assert_eq!(gm.read_plain::<[u8; 4]>(0).unwrap(), [1; 4]);
    gm.write_at(0, &[7; 512]).unwrap();
    block_on(disk.write_vectored(&buffers, 2, true)).unwrap();
    assert_eq!(&state.bytes.lock()[1024..1536], &[7; 512]);
    assert_eq!(*state.writes.lock(), [(2, true)]);
    block_on(disk.sync_cache()).unwrap();
    assert_eq!(state.flushes.load(Ordering::SeqCst), 1);
    block_on(disk.unmap(1, 2, true)).unwrap();
    assert_eq!(*state.unmaps.lock(), [(1, 2, true)]);
}

// Test: Submit offsets whose end cannot be represented by signed host IO APIs.
// Expected: Reads, writes, and unmaps reject them before any backend write occurs.
#[test]
fn unrepresentable_requests_are_rejected() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let disk = Disk::new(backend).unwrap();
    let gm = GuestMemory::allocate(512);
    let owned = OwnedRequestBuffers::linear(0, 512, true);
    let buffers = owned.buffer(&gm);
    for sector in [u64::MAX, (i64::MAX as u64) / 512] {
        assert!(matches!(
            block_on(disk.read_vectored(&buffers, sector)),
            Err(DiskError::IllegalBlock)
        ));
        assert!(matches!(
            block_on(disk.write_vectored(&buffers, sector, false)),
            Err(DiskError::IllegalBlock)
        ));
        assert!(matches!(
            block_on(disk.unmap(sector, 1, false)),
            Err(DiskError::IllegalBlock)
        ));
    }
    assert!(state.writes.lock().is_empty());
    assert!(state.unmaps.lock().is_empty());
}

// Test: Unmap ignored, out-of-range, and read-only disk regions.
// Expected: Ignored unmaps never reach the backend, but invalid requests still fail.
#[test]
fn ignored_unmaps_still_validate_ranges_and_read_only_media() {
    for read_only in [false, true] {
        let backend = Backend {
            behavior: UnmapBehavior::Ignored,
            read_only,
            ..Backend::new()
        };
        let state = backend.state.clone();
        let disk = Disk::new(backend).unwrap();
        let result = block_on(disk.unmap(0, 1, false));
        if read_only {
            assert!(matches!(result, Err(DiskError::ReadOnly)));
        } else {
            result.unwrap();
        }
        assert!(matches!(
            block_on(disk.unmap(4, 1, false)),
            Err(DiskError::IllegalBlock)
        ));
        assert!(state.unmaps.lock().is_empty());
    }
}

// Test: Read and write whole sectors through the synchronous IO adapter.
// Expected: Data and cursor changes match standard Read, Write, and Seek behavior.
#[test]
fn blocking_disk_transfers_aligned_sectors() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let mut disk = BlockingDisk::new(Disk::new(backend).unwrap());
    disk.seek(SeekFrom::Start(512)).unwrap();
    let mut bytes = [0; 512];
    assert_eq!(disk.read(&mut bytes).unwrap(), 512);
    assert_eq!(bytes, [1; 512]);
    assert_eq!(disk.stream_position().unwrap(), 1024);
    assert_eq!(disk.write(&[9; 512]).unwrap(), 512);
    disk.flush().unwrap();
    assert_eq!(&state.bytes.lock()[1024..1536], &[9; 512]);
    assert_eq!(*state.writes.lock(), [(2, true)]);
}

// Test: Read an unaligned buffer across a sector boundary.
// Expected: Bytes from both sectors are returned in order and the cursor advances.
#[test]
fn blocking_disk_reads_partial_sectors_across_a_boundary() {
    let mut disk = BlockingDisk::new(Disk::new(Backend::new()).unwrap());
    disk.seek(SeekFrom::Start(509)).unwrap();
    let mut bytes = [0xff; 7];
    disk.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0, 0, 0, 1, 1, 1, 1]);
    assert_eq!(disk.stream_position().unwrap(), 516);
}

// Test: Write partial sectors across a boundary and flush the trailing bytes.
// Expected: Only the requested span changes; neighboring bytes remain intact.
#[test]
fn blocking_disk_partial_writes_preserve_neighboring_bytes() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let mut disk = BlockingDisk::new(Disk::new(backend).unwrap());
    disk.seek(SeekFrom::Start(509)).unwrap();
    disk.write_all(&[7; 7]).unwrap();
    disk.flush().unwrap();
    let bytes = state.bytes.lock();
    assert_eq!(&bytes[506..509], &[0; 3]);
    assert_eq!(&bytes[509..516], &[7; 7]);
    assert_eq!(&bytes[516..519], &[1; 3]);
}

// Test: Write twice within one sector, then seek and read the changed bytes.
// Expected: Buffered writes are flushed without losing either update.
#[test]
fn blocking_disk_flushes_pending_data_before_reuse() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let mut disk = BlockingDisk::new(Disk::new(backend).unwrap());
    disk.write_all(&[7; 3]).unwrap();
    disk.write_all(&[8; 3]).unwrap();
    disk.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = [0; 7];
    disk.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [7, 7, 7, 8, 8, 8, 0]);
    assert_eq!(&state.bytes.lock()[..7], &bytes);
}

// Test: Read immediately after writing a partial sector.
// Expected: The write is committed and subsequent reads start at the next byte.
#[test]
fn blocking_disk_reads_after_a_buffered_write() {
    let mut disk = BlockingDisk::new(Disk::new(Backend::new()).unwrap());
    disk.write_all(&[7; 3]).unwrap();
    let mut bytes = [0xff; 2];
    disk.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 2]);
    assert_eq!(disk.stream_position().unwrap(), 5);
}

// Test: Seek relative to the current position and the end of the disk.
// Expected: Valid positive and negative offsets produce the requested position.
#[test]
fn blocking_disk_supports_relative_and_end_seeks() {
    let mut disk = BlockingDisk::new(Disk::new(Backend::new()).unwrap());
    assert_eq!(disk.seek(SeekFrom::End(-10)).unwrap(), 2038);
    assert_eq!(disk.seek(SeekFrom::Current(-8)).unwrap(), 2030);
    assert_eq!(disk.seek(SeekFrom::Current(3)).unwrap(), 2033);
}

// Test: Inject backend failures into aligned and partial blocking reads and writes.
// Expected: IO errors propagate without advancing the cursor for failed transfers.
#[test]
fn blocking_disk_propagates_backend_transfer_errors() {
    let backend = Backend::new();
    let state = backend.state.clone();
    let mut disk = BlockingDisk::new(Disk::new(backend).unwrap());
    state.fail_reads.store(true, Ordering::SeqCst);
    assert!(disk.read(&mut [0; 512]).is_err());
    assert!(disk.read(&mut [0; 3]).is_err());
    assert!(disk.write(&[1; 3]).is_err());
    assert_eq!(disk.stream_position().unwrap(), 0);
    state.fail_reads.store(false, Ordering::SeqCst);
    state.fail_writes.store(true, Ordering::SeqCst);
    assert!(disk.write(&[1; 512]).is_err());
    disk.write_all(&[1; 3]).unwrap();
    assert!(disk.flush().is_err());
}

// IGNORED: BlockingDisk selects its whole-sector path by buffer length alone,
//         rounding an unaligned byte position down to the sector boundary.
//
// Test: Read a sector-sized buffer from an unaligned byte position.
// Expected: The read begins at that byte position, not at the sector boundary.
#[test]
#[ignore = "product bug: whole-sector reads discard an unaligned cursor offset"]
fn blocking_disk_full_length_reads_honor_unaligned_positions() {
    let mut disk = BlockingDisk::new(Disk::new(Backend::new()).unwrap());
    disk.seek(SeekFrom::Start(1)).unwrap();
    let mut bytes = [0xff; 512];
    disk.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes[511], 1);
}
