// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A disk device wrapper that provides configurable storage delay on Read/Write I/O operations to a disk.

#![forbid(unsafe_code)]

/// Provides a disk with a delay on every I/O operation.
pub mod resolver;

use disk_backend::Disk;
use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::UnmapBehavior;
use inspect::Inspect;
use mesh::Cell;
use pal_async::timer::PolledTimer;
use scsi_buffers::RequestBuffers;
use std::time::Duration;
use vmcore::vm_task::VmTaskDriver;
use vmcore::vm_task::VmTaskDriverSource;

/// A disk with delay on every I/O operation.
#[derive(Inspect)]
pub struct DelayDisk {
    #[inspect(with = "|x| x.get()")]
    delay: Cell<Duration>,
    inner: Disk,
    driver: VmTaskDriver,
}

impl DelayDisk {
    /// Creates a new disk with a specified delay on I/O operations.
    pub fn new(delay: Cell<Duration>, inner: Disk, driver_source: &VmTaskDriverSource) -> Self {
        Self {
            delay,
            inner,
            driver: driver_source.current(),
        }
    }
}

impl DiskIo for DelayDisk {
    fn disk_type(&self) -> &str {
        "delay"
    }

    /// Passthrough
    fn sector_count(&self) -> u64 {
        self.inner.sector_count()
    }

    /// Passthrough
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }

    /// Passthrough
    fn disk_id(&self) -> Option<[u8; 16]> {
        self.inner.disk_id()
    }

    /// Passthrough
    fn physical_sector_size(&self) -> u32 {
        self.inner.physical_sector_size()
    }

    /// Passthrough
    fn is_fua_respected(&self) -> bool {
        self.inner.is_fua_respected()
    }

    /// Passthrough
    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    /// Passthrough
    fn pr(&self) -> Option<&dyn disk_backend::pr::PersistentReservation> {
        self.inner.pr()
    }

    /// Delay and then Passthrough
    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        PolledTimer::new(&self.driver).sleep(self.delay.get()).await;
        self.inner.read_vectored(buffers, sector).await
    }

    /// Delay and then Passthrough
    async fn write_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        fua: bool,
    ) -> Result<(), DiskError> {
        PolledTimer::new(&self.driver).sleep(self.delay.get()).await;
        self.inner.write_vectored(buffers, sector, fua).await
    }

    /// Passthrough
    async fn sync_cache(&self) -> Result<(), DiskError> {
        self.inner.sync_cache().await
    }

    /// Passthrough
    async fn wait_resize(&self, sector_count: u64) -> u64 {
        self.inner.wait_resize(sector_count).await
    }

    /// Passthrough
    fn unmap(
        &self,
        sector: u64,
        count: u64,
        block_level_only: bool,
    ) -> impl Future<Output = Result<(), DiskError>> + Send {
        self.inner.unmap(sector, count, block_level_only)
    }

    /// Passthrough
    fn unmap_behavior(&self) -> UnmapBehavior {
        self.inner.unmap_behavior()
    }

    /// Passthrough
    fn optimal_unmap_sectors(&self) -> u32 {
        self.inner.optimal_unmap_sectors()
    }
}

#[cfg(test)]
mod tests {
    use crate::DelayDisk;
    use disk_backend::Disk;
    use guestmem::GuestMemory;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use scsi_buffers::OwnedRequestBuffers;
    use std::future::Future;
    use std::pin::pin;
    use std::task::Context;
    use std::task::Waker;
    use std::time::Duration;
    use test_with_tracing::test;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    #[async_test]
    async fn sector_range_conformance(driver: DefaultDriver) {
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        // A zero delay keeps the test fast. The delay is never updated, so the
        // updater can be dropped immediately; the cell keeps its initial value.
        let cell = mesh::CellUpdater::new(Duration::ZERO).cell();
        let inner = disklayer_ram::ram_disk(1024 * 1024, false).unwrap();
        let disk = Disk::new(DelayDisk::new(cell, inner, &source)).unwrap();
        storage_tests::sector_range::test_disk_sector_range_conformance(&disk).await;
    }

    // Test: Cancel reads and writes while delayed, then remove the delay at runtime.
    // Expected: Pending I/O has no disk or guest-memory effects; cache sync bypasses
    //       the read/write delay, and subsequent zero-delay I/O transfers exact data.
    #[async_test]
    async fn cancellation_and_live_delay_update(driver: DefaultDriver) {
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        let (mut updater, delay) = mesh::cell(Duration::from_secs(3600));
        let backing = disklayer_ram::ram_disk(4096, false).unwrap();
        let disk = Disk::new(DelayDisk::new(delay, backing.clone(), &source)).unwrap();
        let memory = GuestMemory::allocate(4096);
        let range = OwnedRequestBuffers::new_unaligned(&[0], 0, 512);
        let buffers = range.buffer(&memory);
        memory.write_at(0, &[0x96; 512]).unwrap();
        let mut cx = Context::from_waker(Waker::noop());

        {
            let mut write = pin!(disk.write_vectored(&buffers, 3, true));
            assert!(write.as_mut().poll(&mut cx).is_pending());
        }
        backing.read_vectored(&buffers, 3).await.unwrap();
        let mut actual = [0xff; 512];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0; 512], "cancelled write reached the backing disk");

        memory.write_at(0, &[0x96; 512]).unwrap();
        backing.write_vectored(&buffers, 3, false).await.unwrap();
        memory.write_at(0, &[0x35; 512]).unwrap();
        {
            let mut read = pin!(disk.read_vectored(&buffers, 3));
            assert!(read.as_mut().poll(&mut cx).is_pending());
        }
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0x35; 512], "cancelled read changed guest memory");

        {
            let mut sync = pin!(disk.sync_cache());
            let std::task::Poll::Ready(result) = sync.as_mut().poll(&mut cx) else {
                panic!("cache sync acquired the read/write delay");
            };
            result.unwrap();
        }
        updater.set(Duration::ZERO).await;
        disk.read_vectored(&buffers, 3).await.unwrap();
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0x96; 512]);
        memory.write_at(0, &[0xa7; 512]).unwrap();
        disk.write_vectored(&buffers, 5, true).await.unwrap();
        memory.write_at(0, &[0; 512]).unwrap();
        backing.read_vectored(&buffers, 5).await.unwrap();
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0xa7; 512]);
        backing.read_vectored(&buffers, 3).await.unwrap();
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, [0x96; 512], "write changed an unrelated sector");
    }
}
