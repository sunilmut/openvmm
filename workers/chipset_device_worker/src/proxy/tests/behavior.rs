// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::io::deferred::DeferredToken;
use chipset_device::mmio::ControlMmioIntercept;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigByteEnable;
use chipset_device::pci::PciConfigSpace;
use chipset_device::pio::ControlPortIoIntercept;
use chipset_device::pio::PortIoIntercept;
use chipset_device::pio::RegisterPortIoIntercept;
use chipset_device::poll_device::PollDevice;
use chipset_device_resources::ConfigureChipsetDevice;
use futures::StreamExt;
use std::future::poll_fn;
use std::sync::Arc;
use test_with_tracing::test;

mod device;
use device::*;

// Record registrations through the platform callbacks, not proxy internals.
struct MmioRegistration(Arc<parking_lot::Mutex<Vec<(String, u64, u64)>>>);

struct MmioRegion {
    name: String,
    len: u64,
    address: Option<u64>,
    registrations: Arc<parking_lot::Mutex<Vec<(String, u64, u64)>>>,
}

impl RegisterMmioIntercept for MmioRegistration {
    fn new_io_region(&mut self, name: &str, len: u64) -> Box<dyn ControlMmioIntercept> {
        Box::new(MmioRegion {
            name: name.into(),
            len,
            address: None,
            registrations: self.0.clone(),
        })
    }
}

impl ControlMmioIntercept for MmioRegion {
    fn region_name(&self) -> &str {
        &self.name
    }
    fn map(&mut self, address: u64) {
        self.address = Some(address);
        self.registrations
            .lock()
            .push((self.name.clone(), address, self.len));
    }
    fn unmap(&mut self) {
        self.address = None;
    }
    fn addr(&self) -> Option<u64> {
        self.address
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn offset_of(&self, address: u64) -> Option<u64> {
        address
            .checked_sub(self.address?)
            .filter(|offset| *offset < self.len)
    }
}

struct PioRegistration(Arc<parking_lot::Mutex<Vec<(String, u16, u16)>>>);

struct PioRegion {
    name: String,
    len: u16,
    address: Option<u16>,
    registrations: Arc<parking_lot::Mutex<Vec<(String, u16, u16)>>>,
}

impl RegisterPortIoIntercept for PioRegistration {
    fn new_io_region(&mut self, name: &str, len: u16) -> Box<dyn ControlPortIoIntercept> {
        Box::new(PioRegion {
            name: name.into(),
            len,
            address: None,
            registrations: self.0.clone(),
        })
    }
}

impl ControlPortIoIntercept for PioRegion {
    fn region_name(&self) -> &str {
        &self.name
    }
    fn map(&mut self, address: u16) {
        self.address = Some(address);
        self.registrations
            .lock()
            .push((self.name.clone(), address, self.len));
    }
    fn unmap(&mut self) {
        self.address = None;
    }
    fn addr(&self) -> Option<u16> {
        self.address
    }
    fn len(&self) -> u16 {
        self.len
    }
    fn offset_of(&self, address: u16) -> Option<u16> {
        address
            .checked_sub(self.address?)
            .filter(|offset| *offset < self.len)
    }
}

struct NoLines;

impl ConfigureChipsetDevice for NoLines {
    fn new_line(
        &mut self,
        _: chipset_device_resources::LineSetId,
        _: &str,
        _: u32,
    ) -> vmcore::line_interrupt::LineInterrupt {
        panic!("test device has no line outputs")
    }
    fn add_line_target(
        &mut self,
        _: chipset_device_resources::LineSetId,
        _: std::ops::RangeInclusive<u32>,
        _: u32,
    ) {
        panic!("test device has no line inputs")
    }
    fn omit_saved_state(&mut self) {
        panic!("test device has saved state")
    }
}

struct Fixture {
    proxy: ChipsetDeviceProxy,
    events: mesh::Receiver<Event>,
    completions: mesh::Sender<Completion>,
    mmio: Arc<parking_lot::Mutex<Vec<(String, u64, u64)>>>,
    pio: Arc<parking_lot::Mutex<Vec<(String, u16, u16)>>>,
}

impl Fixture {
    async fn new(mode: Mode, driver: &DefaultDriver, vmtime: &VmTimeKeeper) -> Self {
        let (req_send, req_recv) = mesh::channel();
        let (resp_send, resp_recv) = mesh::channel();
        let (cap_send, cap_recv) = mesh::oneshot();
        let (events_send, events) = mesh::channel();
        let (completions, completion_recv) = mesh::channel();
        let gm = GuestMemory::allocate(4096);
        let (task, guest_memory, encrypted_guest_memory) =
            GuestMemoryTask::new(gm.clone(), gm.clone());
        let mut memory_task = TaskControl::new(task);
        memory_task.insert(driver, "test-io-memory", ());
        memory_task.start();
        let worker = mesh_worker::launch_local_worker::<RemoteChipsetDeviceWorker<IoResolvers>>(
            RemoteChipsetDeviceWorkerParameters {
                device: IoHandle {
                    mode,
                    events: events_send,
                    completions: completion_recv,
                }
                .into_resource(),
                dyn_resolvers: IoResolvers,
                inputs: RemoteChipsetDeviceHandleParams {
                    device_name: "test-io".into(),
                    is_restoring: false,
                    vmtime: vmtime.builder().clone(),
                    guest_memory,
                    encrypted_guest_memory,
                },
                req_recv,
                resp_send,
                cap_send,
            },
        )
        .await
        .unwrap();
        let mmio = Arc::default();
        let pio = Arc::default();
        let source = vmcore::vm_task::VmTaskDriverSource::new(
            vmcore::vm_task::thread::ThreadDriverBackend::new(driver.clone()),
        );
        let proxy = ChipsetDeviceProxy::new(
            req_send,
            resp_recv,
            cap_recv,
            worker,
            memory_task,
            ResolveChipsetDeviceHandleParams {
                device_name: "test-io",
                is_restoring: false,
                guest_memory: &gm,
                encrypted_guest_memory: &gm,
                vmtime: &vmtime.builder().build(driver).await.unwrap(),
                task_driver_source: &source,
                configure: &mut NoLines,
                register_mmio: &mut MmioRegistration(Arc::clone(&mmio)),
                register_pio: &mut PioRegistration(Arc::clone(&pio)),
            },
        )
        .await
        .unwrap();
        Self {
            proxy,
            events,
            completions,
            mmio,
            pio,
        }
    }

    async fn event(&mut self, expected: Event) {
        assert_eq!(self.events.recv().await.unwrap(), expected);
    }

    async fn shutdown(mut self) {
        self.proxy.stop().await;
        self.event(Event::Stop).await;
        self.proxy.teardown().await;
        assert_eq!(self.events.recv().await.unwrap(), Event::Teardown);
    }
}

fn token(result: IoResult) -> DeferredToken {
    let IoResult::Defer(token) = result else {
        panic!("proxy must defer remote IO: {result:?}")
    };
    token
}

async fn read(
    proxy: &mut ChipsetDeviceProxy,
    mut token: DeferredToken,
    size: usize,
) -> Result<Vec<u8>, IoError> {
    let mut data = vec![0; size];
    poll_fn(|cx| {
        proxy.poll_device(cx);
        token.poll_read(cx, &mut data)
    })
    .await?;
    Ok(data)
}

async fn write(proxy: &mut ChipsetDeviceProxy, mut token: DeferredToken) -> Result<(), IoError> {
    poll_fn(|cx| {
        proxy.poll_device(cx);
        token.poll_write(cx)
    })
    .await
}

fn begin_read(
    proxy: &mut ChipsetDeviceProxy,
    space: Space,
    address: u64,
    size: usize,
) -> DeferredToken {
    token(match space {
        Space::Mmio => proxy
            .supports_mmio()
            .unwrap()
            .mmio_read(address, &mut vec![0; size]),
        Space::Pio => proxy
            .supports_pio()
            .unwrap()
            .io_read(address.try_into().unwrap(), &mut vec![0; size]),
        Space::Pci => panic!("PCI uses byte-enabled access"),
    })
}

fn begin_write(
    proxy: &mut ChipsetDeviceProxy,
    space: Space,
    address: u64,
    data: &[u8],
) -> DeferredToken {
    token(match space {
        Space::Mmio => proxy.supports_mmio().unwrap().mmio_write(address, data),
        Space::Pio => proxy
            .supports_pio()
            .unwrap()
            .io_write(address.try_into().unwrap(), data),
        Space::Pci => panic!("PCI uses byte-enabled access"),
    })
}

// Test: Forward immediate MMIO and port operations, including device-reported errors.
// Expected: Addresses, sizes and payloads survive the channel; errors reach the original caller.
#[async_test]
async fn mmio_and_pio_preserve_requests_results_and_errors(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut f = Fixture::new(Mode::Io, &driver, &time).await;
    for (space, address, size) in [(Space::Mmio, 0x1_0000_1230u64, 8), (Space::Pio, 0x3f0, 2)] {
        let pending = begin_read(&mut f.proxy, space, address, size);
        assert_eq!(
            read(&mut f.proxy, pending, size).await.unwrap(),
            address.to_le_bytes()[..size]
        );
        f.event(Event::Read(space, address, size, None)).await;
        let pending = begin_write(&mut f.proxy, space, address, &[1, 3, 5, 7]);
        write(&mut f.proxy, pending).await.unwrap();
        f.event(Event::Write(space, address, vec![1, 3, 5, 7], None))
            .await;
        let pending = begin_read(&mut f.proxy, space, address + 4, size);
        assert!(matches!(
            read(&mut f.proxy, pending, size).await,
            Err(IoError::InvalidRegister)
        ));
        f.event(Event::Read(space, address + 4, size, None)).await;
        let pending = begin_write(&mut f.proxy, space, address + 4, &[9, 8]);
        assert!(matches!(
            write(&mut f.proxy, pending).await,
            Err(IoError::InvalidAccessSize)
        ));
        f.event(Event::Write(space, address + 4, vec![9, 8], None))
            .await;
    }
    f.shutdown().await;
}

// Test: Advertise and initialize devices with and without remote IO capabilities.
// Expected: Trait availability matches the device, static mappings are exact and PCI retains its BDF.
#[async_test]
async fn advertised_capabilities_register_static_regions(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    for mode in [Mode::Plain, Mode::Io] {
        let mut f = Fixture::new(mode, &driver, &time).await;
        let io = matches!(mode, Mode::Io);
        assert_eq!(f.proxy.supports_mmio().is_some(), io);
        assert_eq!(f.proxy.supports_pio().is_some(), io);
        assert_eq!(f.proxy.supports_pci().is_some(), io);
        assert!(f.proxy.supports_poll_device().is_some());
        if io {
            assert_eq!(
                f.proxy.supports_pci().unwrap().suggested_bdf(),
                Some((2, 3, 1))
            );
            assert_eq!(
                *f.mmio.lock(),
                [("mmio-registers".into(), 0x1_0000_1200, 0x100)]
            );
            assert_eq!(*f.pio.lock(), [("pio-registers".into(), 0x3f0, 0x10)]);
        } else {
            assert!(f.mmio.lock().is_empty());
            assert!(f.pio.lock().is_empty());
        }
        f.shutdown().await;
    }
}

// Test: Forward PCI DWORD operations with every nonempty byte-lane mask.
// Expected: The backend sees the exact offset/mask and only enabled data bytes cross the boundary.
#[async_test]
async fn pci_accesses_preserve_byte_enables(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut f = Fixture::new(Mode::Io, &driver, &time).await;
    for bits in 1..16 {
        let mask = PciConfigByteEnable::new(bits).unwrap();
        let mut initial = 0;
        let pending = token(
            f.proxy
                .supports_pci()
                .unwrap()
                .pci_cfg_read(0x40, ByteEnabledDwordRead::new(&mut initial, mask)),
        );
        let data = read(&mut f.proxy, pending, 4).await.unwrap();
        assert_eq!(
            u32::from_ne_bytes(data.try_into().unwrap()),
            mask.extract(0x4433_2211)
        );
        f.event(Event::Read(Space::Pci, 0x40, 4, Some(bits))).await;
        let pending = token(
            f.proxy
                .supports_pci()
                .unwrap()
                .pci_cfg_write(0x80, ByteEnabledDwordWrite::new(0x8877_6655, mask)),
        );
        write(&mut f.proxy, pending).await.unwrap();
        f.event(Event::Write(
            Space::Pci,
            0x80,
            mask.extract(0x8877_6655).to_ne_bytes().to_vec(),
            Some(bits),
        ))
        .await;
    }
    f.shutdown().await;
}

// Test: Complete concurrent remote reads and writes in reverse order, with mixed outcomes.
// Expected: Pending operations stay pending and each completion reaches its own token with exact data/error.
#[async_test]
async fn deferred_completions_are_routed_out_of_order(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut f = Fixture::new(Mode::Io, &driver, &time).await;
    f.proxy.start();
    f.event(Event::Start).await;
    let mut first = begin_read(&mut f.proxy, Space::Mmio, 0x1_0000_1238, 4);
    f.event(Event::Read(Space::Mmio, 0x1_0000_1238, 4, None))
        .await;
    let second = begin_read(&mut f.proxy, Space::Pio, 0x3f8, 2);
    f.event(Event::Read(Space::Pio, 0x3f8, 2, None)).await;
    let first_write = begin_write(&mut f.proxy, Space::Mmio, 0x1_0000_1238, &[9, 8]);
    f.event(Event::Write(Space::Mmio, 0x1_0000_1238, vec![9, 8], None))
        .await;
    let second_write = begin_write(&mut f.proxy, Space::Pio, 0x3f8, &[7]);
    f.event(Event::Write(Space::Pio, 0x3f8, vec![7], None))
        .await;

    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(first.poll_read(&mut cx, &mut [0; 4]).is_pending());
    f.completions
        .send(Completion::Read(1, Ok(vec![0xab, 0xcd])));
    assert_eq!(read(&mut f.proxy, second, 2).await.unwrap(), [0xab, 0xcd]);
    assert!(first.poll_read(&mut cx, &mut [0; 4]).is_pending());
    f.completions
        .send(Completion::Write(1, Err(IoError::UnalignedAccess)));
    assert!(matches!(
        write(&mut f.proxy, second_write).await,
        Err(IoError::UnalignedAccess)
    ));
    f.completions
        .send(Completion::Read(0, Err(IoError::NoResponse)));
    assert!(matches!(
        read(&mut f.proxy, first, 4).await,
        Err(IoError::NoResponse)
    ));
    f.completions.send(Completion::Write(0, Ok(())));
    write(&mut f.proxy, first_write).await.unwrap();
    f.shutdown().await;
}

// Test: Reset with both queued immediate replies and unfinished device IO.
// Expected: Old tokens fail without a response, stale replies are discarded and new IO remains usable.
#[async_test]
async fn reset_discards_old_responses_and_cancels_pending_io(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut f = Fixture::new(Mode::Io, &driver, &time).await;
    let immediate = begin_read(&mut f.proxy, Space::Mmio, 0x1_0000_1230, 4);
    f.event(Event::Read(Space::Mmio, 0x1_0000_1230, 4, None))
        .await;
    let pending = begin_write(&mut f.proxy, Space::Pio, 0x3f8, &[9]);
    f.event(Event::Write(Space::Pio, 0x3f8, vec![9], None))
        .await;
    let deferred = begin_read(&mut f.proxy, Space::Mmio, 0x1_0000_1238, 4);
    f.event(Event::Read(Space::Mmio, 0x1_0000_1238, 4, None))
        .await;
    f.proxy.reset().await;
    f.event(Event::Reset).await;
    assert!(matches!(
        immediate.read_future(&mut [0; 4]).await,
        Err(IoError::NoResponse)
    ));
    assert!(matches!(
        pending.write_future().await,
        Err(IoError::NoResponse)
    ));
    assert!(matches!(
        deferred.read_future(&mut [0; 4]).await,
        Err(IoError::NoResponse)
    ));
    let next = begin_read(&mut f.proxy, Space::Pio, 0x3f0, 2);
    assert_eq!(read(&mut f.proxy, next, 2).await.unwrap(), [0xf0, 3]);
    f.event(Event::Read(Space::Pio, 0x3f0, 2, None)).await;
    f.shutdown().await;
}

mesh_worker::runnable_workers! {
    RestartWorkers { RemoteChipsetDeviceWorker<TestResolvers> }
}

// Test: Request worker migration even though the remote chipset worker cannot restart.
// Expected: A clear restart error is reported and the original device remains usable.
#[async_test]
async fn rejected_restart_preserves_the_original_device(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut proxy = new_proxy(&time, &driver).await;
    proxy.restore(state(37)).await.unwrap();
    let (host, runner) = mesh_worker::worker_host();
    let thread = std::thread::spawn(|| pal_async::local::block_on(runner.run(RestartWorkers)));
    proxy.worker.restart(&host);
    let mesh_worker::WorkerEvent::RestartFailed(error) = proxy.worker.next().await.unwrap() else {
        panic!("restart must fail explicitly");
    };
    assert!(format!("{error:#}").contains("not supported"));
    assert_eq!(
        proxy
            .save()
            .await
            .unwrap()
            .parse::<TestSavedState>()
            .unwrap()
            .value,
        37
    );
    proxy.teardown().await;
    drop(host);
    thread.join().unwrap();
}

// Test: Stop the worker itself while device polling is still running.
// Expected: Shutdown joins successfully and further requests report a closed channel.
#[async_test]
async fn worker_stop_shuts_down_a_running_device(driver: DefaultDriver) {
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let mut proxy = new_proxy(&time, &driver).await;
    proxy.start();
    // Saving is a barrier: Start must reach the worker before its prioritized stop RPC.
    proxy.save().await.unwrap();
    stop_worker(&mut proxy).await;
    assert!(proxy.save().await.is_err());
}
