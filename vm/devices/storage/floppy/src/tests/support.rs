// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::UnmapBehavior;
use guestmem::MemoryRead;
use guestmem::MemoryWrite;
use parking_lot::Mutex;
use std::sync::atomic::AtomicBool;
use vmcore::isa_dma_channel::IsaDmaBuffer;
use vmcore::line_interrupt::LineSetTarget;

pub(super) const IMAGE_SIZE: usize = 1_474_560;
pub(super) const DMA_ADDRESS: u64 = 0x1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Fault {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Request {
    Read(u64, usize),
    Write(u64, usize),
    Flush,
}

pub(super) struct MediaState {
    pub bytes: Vec<u8>,
    pub requests: Vec<Request>,
    pub fault: Option<Fault>,
}

#[derive(Clone, Inspect)]
pub(super) struct TestDisk {
    #[inspect(skip)]
    pub state: Arc<Mutex<MediaState>>,
    read_only: bool,
}

impl TestDisk {
    pub fn new(size: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(MediaState {
                bytes: vec![0x5a; size],
                requests: Vec::new(),
                fault: None,
            })),
            read_only: false,
        }
    }

    pub fn read_only(size: usize) -> Self {
        Self {
            read_only: true,
            ..Self::new(size)
        }
    }
}

fn injected_error() -> DiskError {
    DiskError::Io(std::io::Error::other("injected floppy backend failure"))
}

impl DiskIo for TestDisk {
    fn disk_type(&self) -> &str {
        "floppy-test"
    }
    fn sector_count(&self) -> u64 {
        self.state.lock().bytes.len() as u64 / 512
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn disk_id(&self) -> Option<[u8; 16]> {
        None
    }
    fn physical_sector_size(&self) -> u32 {
        512
    }
    fn is_fua_respected(&self) -> bool {
        false
    }
    fn is_read_only(&self) -> bool {
        self.read_only
    }
    fn unmap_behavior(&self) -> UnmapBehavior {
        UnmapBehavior::Ignored
    }
    async fn unmap(
        &self,
        _sector: u64,
        _count: u64,
        _block_level_only: bool,
    ) -> Result<(), DiskError> {
        panic!("floppy controller must not issue unmap")
    }
    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        let mut state = self.state.lock();
        state.requests.push(Request::Read(sector, buffers.len()));
        if state.fault == Some(Fault::Read) {
            return Err(injected_error());
        }
        let start = sector as usize * 512;
        let bytes = state
            .bytes
            .get(start..start + buffers.len())
            .ok_or(DiskError::IllegalBlock)?;
        buffers.writer().write(bytes)?;
        Ok(())
    }
    async fn write_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        _fua: bool,
    ) -> Result<(), DiskError> {
        let mut state = self.state.lock();
        state.requests.push(Request::Write(sector, buffers.len()));
        if state.fault == Some(Fault::Write) {
            return Err(injected_error());
        }
        if self.read_only {
            return Err(DiskError::ReadOnly);
        }
        let start = sector as usize * 512;
        let bytes = state
            .bytes
            .get_mut(start..start + buffers.len())
            .ok_or(DiskError::IllegalBlock)?;
        buffers.reader().read(bytes)?;
        Ok(())
    }
    async fn sync_cache(&self) -> Result<(), DiskError> {
        let mut state = self.state.lock();
        state.requests.push(Request::Flush);
        if state.fault == Some(Fault::Flush) {
            return Err(injected_error());
        }
        Ok(())
    }
}

pub(super) struct DmaState {
    pub buffer: Option<IsaDmaBuffer>,
    pub size_hint: u16,
    pub requests: Vec<IsaDmaDirection>,
    pub completions: usize,
}

struct TestDma(Arc<Mutex<DmaState>>);

impl IsaDmaChannel for TestDma {
    fn check_transfer_size(&mut self) -> u16 {
        self.0.lock().size_hint
    }
    fn request(&mut self, direction: IsaDmaDirection) -> Option<IsaDmaBuffer> {
        let mut state = self.0.lock();
        state.requests.push(direction);
        state.buffer
    }
    fn complete(&mut self) {
        self.0.lock().completions += 1;
    }
}

#[derive(Default)]
pub(super) struct Interrupt(pub AtomicBool);

impl LineSetTarget for Interrupt {
    fn set_irq(&self, vector: u32, high: bool) {
        assert_eq!(vector, 6);
        self.0.store(high, Ordering::SeqCst);
    }
}

pub(super) struct Rig {
    pub device: FloppyDiskController,
    pub memory: GuestMemory,
    pub dma: Arc<Mutex<DmaState>>,
    pub interrupt: Arc<Interrupt>,
}

impl Rig {
    pub fn with_disk(disk: TestDisk) -> Self {
        Self::with_drive(DriveRibbon::Single(Disk::new(disk).unwrap()))
    }

    pub fn without_disk() -> Self {
        Self::with_drive(DriveRibbon::None)
    }

    fn with_drive(drive: DriveRibbon) -> Self {
        let memory = GuestMemory::allocate(0x20000);
        let dma = Arc::new(Mutex::new(DmaState {
            buffer: Some(IsaDmaBuffer {
                address: DMA_ADDRESS,
                size: 512,
            }),
            size_hint: 512,
            requests: Vec::new(),
            completions: 0,
        }));
        let interrupt = Arc::new(Interrupt::default());
        let device = FloppyDiskController::new(
            memory.clone(),
            LineInterrupt::new_with_target("floppy", interrupt.clone(), 6),
            &mut ExternallyManagedPortIoIntercepts,
            0x3f0,
            drive,
            Box::new(TestDma(dma.clone())),
        )
        .unwrap();
        let mut rig = Self {
            device,
            memory,
            dma,
            interrupt,
        };
        rig.write(0x3f2, 0x0c);
        for _ in 0..4 {
            rig.issue(&[0x08]);
            rig.read(0x3f5);
            rig.read(0x3f5);
        }
        rig
    }

    pub fn read(&mut self, port: u16) -> u8 {
        read(&mut self.device, port)
    }
    pub fn write(&mut self, port: u16, value: u8) {
        write(&mut self.device, port, value);
    }
    pub fn issue(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write(0x3f5, *byte);
        }
    }
    pub fn transfer(&mut self, opcode: u8, cylinder: u8, head: u8, sector: u8) {
        self.issue(&[opcode, head << 2, cylinder, head, sector, 2, 18, 0x1b, 0xff]);
    }
    pub fn poll(&mut self) {
        self.device
            .supports_poll_device()
            .unwrap()
            .poll_device(&mut Context::from_waker(Waker::noop()));
    }
    pub fn result(&mut self) -> [u8; 7] {
        assert_eq!(self.read(0x3f4) & 0xd0, 0xd0);
        let bytes = core::array::from_fn(|_| self.read(0x3f5));
        assert_eq!(self.read(0x3f4), 0x80);
        bytes
    }
}
