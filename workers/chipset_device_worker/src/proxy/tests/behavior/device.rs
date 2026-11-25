// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::deferred::DeferredRead;
use chipset_device::io::deferred::DeferredWrite;
use chipset_device::io::deferred::defer_read;
use chipset_device::io::deferred::defer_write;

#[derive(Clone, Copy, MeshPayload)]
pub(super) enum Mode {
    Plain,
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, MeshPayload)]
pub(super) enum Space {
    Mmio,
    Pio,
    Pci,
}

#[derive(Debug, PartialEq, Eq, MeshPayload)]
pub(super) enum Event {
    Read(Space, u64, usize, Option<u8>),
    Write(Space, u64, Vec<u8>, Option<u8>),
    Start,
    Stop,
    Reset,
    Teardown,
}

#[derive(MeshPayload)]
pub(super) enum Completion {
    Read(usize, Result<Vec<u8>, IoError>),
    Write(usize, Result<(), IoError>),
}

#[derive(MeshPayload)]
pub(super) struct IoHandle {
    pub mode: Mode,
    pub events: mesh::Sender<Event>,
    pub completions: mesh::Receiver<Completion>,
}

impl ResourceId<ChipsetDeviceHandleKind> for IoHandle {
    const ID: &'static str = "test_remote_io";
}

#[derive(InspectMut)]
struct IoDevice {
    #[inspect(skip)]
    mode: Mode,
    #[inspect(skip)]
    events: mesh::Sender<Event>,
    #[inspect(skip)]
    completions: mesh::Receiver<Completion>,
    #[inspect(skip)]
    reads: Vec<Option<DeferredRead>>,
    #[inspect(skip)]
    writes: Vec<Option<DeferredWrite>>,
}

impl IoDevice {
    fn read(&mut self, space: Space, address: u64, data: &mut [u8], mask: Option<u8>) -> IoResult {
        self.events
            .send(Event::Read(space, address, data.len(), mask));
        match address & 0xf {
            4 => IoResult::Err(IoError::InvalidRegister),
            8 => {
                let (read, token) = defer_read();
                self.reads.push(Some(read));
                IoResult::Defer(token)
            }
            _ => {
                data.copy_from_slice(&address.to_le_bytes()[..data.len()]);
                IoResult::Ok
            }
        }
    }

    fn write(&mut self, space: Space, address: u64, data: &[u8], mask: Option<u8>) -> IoResult {
        self.events
            .send(Event::Write(space, address, data.to_vec(), mask));
        match address & 0xf {
            4 => IoResult::Err(IoError::InvalidAccessSize),
            8 => {
                let (write, token) = defer_write();
                self.writes.push(Some(write));
                IoResult::Defer(token)
            }
            _ => IoResult::Ok,
        }
    }
}

impl ChipsetDevice for IoDevice {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        matches!(self.mode, Mode::Io).then_some(self)
    }

    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        matches!(self.mode, Mode::Io).then_some(self)
    }

    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        matches!(self.mode, Mode::Io).then_some(self)
    }

    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        Some(self)
    }
}

impl MmioIntercept for IoDevice {
    fn mmio_read(&mut self, address: u64, data: &mut [u8]) -> IoResult {
        self.read(Space::Mmio, address, data, None)
    }

    fn mmio_write(&mut self, address: u64, data: &[u8]) -> IoResult {
        self.write(Space::Mmio, address, data, None)
    }

    fn get_static_regions(&mut self) -> &[(&str, std::ops::RangeInclusive<u64>)] {
        &[("mmio-registers", 0x1_0000_1200..=0x1_0000_12ff)]
    }
}

impl PortIoIntercept for IoDevice {
    fn io_read(&mut self, port: u16, data: &mut [u8]) -> IoResult {
        self.read(Space::Pio, port.into(), data, None)
    }

    fn io_write(&mut self, port: u16, data: &[u8]) -> IoResult {
        self.write(Space::Pio, port.into(), data, None)
    }

    fn get_static_regions(&mut self) -> &[(&str, std::ops::RangeInclusive<u16>)] {
        &[("pio-registers", 0x3f0..=0x3ff)]
    }
}

impl PciConfigSpace for IoDevice {
    fn pci_cfg_read(&mut self, offset: u16, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
        let result = self.read(
            Space::Pci,
            offset.into(),
            &mut [0; 4],
            Some(value.byte_enable().bits()),
        );
        if matches!(result, IoResult::Ok) {
            value.set(0x4433_2211);
        }
        result
    }

    fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> IoResult {
        self.write(
            Space::Pci,
            offset.into(),
            &value.extract().to_ne_bytes(),
            Some(value.byte_enable().bits()),
        )
    }

    fn suggested_bdf(&mut self) -> Option<(u8, u8, u8)> {
        Some((2, 3, 1))
    }
}

impl PollDevice for IoDevice {
    fn poll_device(&mut self, cx: &mut std::task::Context<'_>) {
        while let Poll::Ready(Ok(completion)) = self.completions.poll_recv(cx) {
            match completion {
                Completion::Read(index, result) => {
                    let read = self.reads[index].take().unwrap();
                    match result {
                        Ok(data) => read.complete(&data),
                        Err(error) => read.complete_error(error),
                    }
                }
                Completion::Write(index, result) => {
                    let write = self.writes[index].take().unwrap();
                    match result {
                        Ok(()) => write.complete(),
                        Err(error) => write.complete_error(error),
                    }
                }
            }
        }
    }
}

impl ChangeDeviceState for IoDevice {
    fn start(&mut self) {
        self.events.send(Event::Start);
    }

    async fn stop(&mut self) {
        self.events.send(Event::Stop);
    }

    async fn reset(&mut self) {
        self.reads.clear();
        self.writes.clear();
        self.events.send(Event::Reset);
    }

    async fn teardown(self) {
        self.events.send(Event::Teardown);
    }
}

impl AsyncSaveRestore for IoDevice {
    type SavedState = TestSavedState;

    async fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Ok(TestSavedState { value: 0 })
    }

    async fn restore(&mut self, _: Self::SavedState) -> Result<(), RestoreError> {
        Ok(())
    }
}

struct IoResolver;

impl ResolveResource<ChipsetDeviceHandleKind, IoHandle> for IoResolver {
    type Output = ResolvedChipsetDevice;
    type Error = Infallible;

    fn resolve(
        &self,
        handle: IoHandle,
        _: ResolveChipsetDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        Ok(IoDevice {
            mode: handle.mode,
            events: handle.events,
            completions: handle.completions,
            reads: Vec::new(),
            writes: Vec::new(),
        }
        .into())
    }
}

#[derive(Clone, MeshPayload)]
pub(super) struct IoResolvers;

impl RemoteDynamicResolvers for IoResolvers {
    const WORKER_ID_STR: &'static str = "test_remote_io_worker";

    async fn register_remote_dynamic_resolvers(
        self,
        resolver: &mut ResourceResolver,
    ) -> anyhow::Result<()> {
        resolver.add_resolver(IoResolver);
        Ok(())
    }
}
