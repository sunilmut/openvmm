// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use config::*;
use futures::FutureExt;
use memory_range::MemoryRange;
use pal_async::{DefaultDriver, async_test};
use parking_lot::Mutex;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use test_with_tracing::test;
use vm_topology::memory::MemoryRangeWithNode;
use vm_topology::processor::TopologyBuilder;
use vmcore::line_interrupt::LineInterrupt;
use vmcore::save_restore::SaveRestore;
use vmcore::vmtime::{VmTime, VmTimeKeeper};

fn config() -> PcatBiosConfig {
    let low = MemoryRange::new(0xe000_0000..0x1_0000_0000);
    let high = MemoryRange::new(0x2_0000_0000..0x2_4000_0000);
    PcatBiosConfig {
        processor_topology: TopologyBuilder::new_x86()
            .apic_id_offset(4)
            .build(2)
            .unwrap(),
        mem_layout: MemoryLayout::new_from_ranges(
            &[
                MemoryRangeWithNode {
                    range: MemoryRange::new(0..0x2000_0000),
                    vnode: 0,
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(0x1_0000_0000..0x1_1000_0000),
                    vnode: 0,
                },
                MemoryRangeWithNode {
                    range: MemoryRange::new(0x2_4000_0000..0x2_4800_0000),
                    vnode: 0,
                },
            ],
            &[low, high],
        )
        .unwrap(),
        chipset_low_mmio: low,
        chipset_high_mmio: high,
        srat: (1..=12).collect(),
        initial_generation_id: [0x42; 16],
        hibernation_enabled: true,
        num_lock_enabled: true,
        boot_order: [
            BootDevice::Floppy,
            BootDevice::Optical,
            BootDevice::HardDrive,
            BootDevice::Network,
        ]
        .map(|kind| BootDeviceStatus {
            kind,
            attached: true,
        }),
        smbios: SmbiosConstants {
            bios_guid: guid::Guid::from_slice(&[0x12; 16]),
            system_serial_number: b"serial".to_vec(),
            base_board_serial_number: b"board".to_vec(),
            chassis_serial_number: b"chassis".to_vec(),
            chassis_asset_tag: b"asset".to_vec(),
            bios_lock_string: b"locked".to_vec(),
            processor_manufacturer: b"Maker".to_vec(),
            processor_version: b"Version\0".to_vec(),
            cpu_info_bundle: Some(SmbiosProcessorInfoBundle {
                processor_family: 0xb3,
                voltage: 0x81,
                external_clock: 100,
                max_speed: 3200,
                current_speed: 2800,
            }),
        },
    }
}

#[derive(Default)]
struct Observer {
    events: Mutex<Vec<&'static str>>,
    replays: AtomicUsize,
    rom_maps: Mutex<Vec<(u64, u64, u64)>>,
    rom_unmaps: Mutex<Vec<u64>>,
}

struct Logger(Arc<Observer>);
impl PcatLogger for Logger {
    fn log_event(&self, event: PcatEvent) {
        self.0.events.lock().push(match event {
            PcatEvent::BootFailure => "failure",
            PcatEvent::BootAttempt => "attempt",
        });
    }
}

struct Registrar;
impl RegisterPortIoIntercept for Registrar {
    fn new_io_region(&mut self, _: &str, _: u16) -> Box<dyn ControlPortIoIntercept> {
        Box::new(())
    }
}

struct Fixture {
    device: PcatBiosDevice,
    gm: GuestMemory,
    observer: Arc<Observer>,
    keeper: VmTimeKeeper,
}

impl Fixture {
    async fn new(driver: &DefaultDriver) -> Self {
        Self::with_config(driver, config(), None).await.unwrap()
    }
    async fn with_config(
        driver: &DefaultDriver,
        config: PcatBiosConfig,
        rom: Option<Box<dyn MapRom>>,
    ) -> Result<Self, PcatBiosDeviceInitError> {
        let keeper = VmTimeKeeper::new(driver, VmTime::from_100ns(0));
        let time = keeper.builder().build(driver).await.unwrap();
        let gm = GuestMemory::allocate(0x10000);
        let observer = Arc::new(Observer::default());
        let replay_observer = observer.clone();
        let (_, generation_id_recv) = mesh::channel();
        let device = PcatBiosDevice::new(
            PcatBiosRuntimeDeps {
                gm: gm.clone(),
                logger: Box::new(Logger(observer.clone())),
                generation_id_deps: generation_id::GenerationIdRuntimeDeps {
                    gm: gm.clone(),
                    generation_id_recv,
                    notify_interrupt: LineInterrupt::detached(),
                },
                vmtime: &time,
                rom,
                register_pio: &mut Registrar,
                replay_mtrrs: Box::new(move || {
                    replay_observer.replays.fetch_add(1, Ordering::SeqCst);
                }),
            },
            config,
        )?;
        Ok(Self {
            device,
            gm,
            observer,
            keeper,
        })
    }
    fn select(&mut self, address: PcatAddress) {
        self.device
            .io_write(0x28, &address.0.to_le_bytes())
            .unwrap();
    }
    fn next(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.device.io_read(0x2c, &mut bytes).unwrap();
        u32::from_le_bytes(bytes)
    }
    fn read(&mut self, address: PcatAddress) -> u32 {
        self.select(address);
        self.next()
    }
    fn write(&mut self, address: PcatAddress, value: u32) {
        self.select(address);
        self.device.io_write(0x2c, &value.to_le_bytes()).unwrap();
    }
}

// Test: Read memory layout, processor counts, flags, and boot order through BIOS ports.
// Expected: The protocol reports configured machine values and unknown reads return all ones.
#[async_test]
async fn configuration_queries_report_machine_topology(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    for (address, expected) in [
        (PcatAddress::FIRST_MEMORY_BLOCK_SIZE, 512 * 1024),
        (PcatAddress::NUM_LOCK_ENABLED, 1),
        (PcatAddress::BOOT_DEVICE_ORDER, 0x7654_3210),
        (PcatAddress::BIOS_PROCESSOR_COUNT, 2),
        (PcatAddress::SRAT_SIZE, 12),
        (PcatAddress::MEMORY_AMOUNT_ABOVE_4GB, 384),
        (PcatAddress::SLEEP_STATES, 8),
        (PcatAddress::PCI_IO_GAP_START, 0xe000_0000),
        (PcatAddress::MEMORY_ABOVE_HIGH_MMIO, 128),
        (PcatAddress::HIGH_MMIO_GAP_BASE_IN_MB, 8192),
        (PcatAddress::HIGH_MMIO_GAP_LENGTH_IN_MB, 1023),
        (PcatAddress::INITIAL_MEGABYTES_BELOW_GAP, 512),
        (PcatAddress(u32::MAX), u32::MAX),
    ] {
        assert_eq!(f.read(address), expected, "{address:?}");
    }
    f.select(PcatAddress::PROCESSOR_LOCAL_APIC_ID);
    assert_eq!([f.next(), f.next(), f.next()], [4, 5, u32::MAX]);
    f.select(PcatAddress::PROCESSOR_STA_ENABLE);
    assert_eq!([f.next(), f.next(), f.next()], [1, 1, 0]);
    f.write(PcatAddress::PROCESSOR_STA_ENABLE, 1);
    assert_eq!([f.next(), f.next()], [1, 0]);
    f.write(PcatAddress::BIOS_PROCESSOR_COUNT, 12);
    assert_eq!(f.read(PcatAddress::BIOS_PROCESSOR_COUNT), 2);
}

// Test: Read padded SMBIOS strings and GUID chunks, including their wraparound.
// Expected: Each selection restarts its FIFO and strings pad missing bytes with spaces.
#[async_test]
async fn configuration_strings_are_chunked_padded_and_repeatable(driver: DefaultDriver) {
    let mut c = config();
    c.smbios.bios_guid =
        guid::Guid::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let mut f = Fixture::with_config(&driver, c, None).await.unwrap();
    for (address, text) in [
        (PcatAddress::BIOS_SYSTEM_SERIAL_NUMBER, b"serial".as_slice()),
        (PcatAddress::BIOS_BASE_SERIAL_NUMBER, b"board".as_slice()),
        (
            PcatAddress::BIOS_CHASSIS_SERIAL_NUMBER,
            b"chassis".as_slice(),
        ),
        (PcatAddress::BIOS_CHASSIS_ASSET_TAG, b"asset".as_slice()),
        (PcatAddress::BIOS_LOCK_STRING, b"locked".as_slice()),
    ] {
        let mut expected = [b' '; 32];
        expected[..text.len()].copy_from_slice(text);
        f.select(address);
        let mut actual = Vec::new();
        for _ in 0..8 {
            actual.extend_from_slice(&f.next().to_le_bytes());
        }
        assert_eq!(actual, expected);
        assert_eq!(f.next().to_le_bytes(), expected[..4]);
    }
    f.select(PcatAddress::BIOS_GUID);
    assert_eq!(
        [f.next(), f.next(), f.next(), f.next(), f.next()],
        [
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x0302_0100
        ]
    );
    assert_eq!(f.read(PcatAddress::BIOS_GUID), 0x0302_0100);
    let mut address = [0; 4];
    f.device.io_read(0x28, &mut address).unwrap();
    assert_eq!(u32::from_le_bytes(address), PcatAddress::BIOS_GUID.0);
}

// Test: Fetch SRAT chunks at valid and invalid offsets and copy the table into RAM.
// Expected: Valid chunks match the table; missing chunks return zero without corrupting RAM.
#[async_test]
async fn srat_fifo_offsets_and_guest_memory_delivery(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.write(PcatAddress::SRAT_SIZE, 12);
    f.write(PcatAddress::SRAT_OFFSET, 4);
    f.select(PcatAddress::SRAT_DATA);
    assert_eq!(f.next().to_le_bytes(), [5, 6, 7, 8]);
    assert_eq!(f.next().to_le_bytes(), [9, 10, 11, 12]);
    assert_eq!(f.next(), 0);
    f.write(PcatAddress::SRAT_SIZE, 1);
    f.write(PcatAddress::SRAT_OFFSET, 99);
    assert_eq!(f.read(PcatAddress::SRAT_DATA), 0);
    f.gm.write_at(0xffc, &[0xa5; 20]).unwrap();
    f.write(PcatAddress::SRAT_DATA, 0x1000);
    assert_eq!(
        f.gm.read_plain::<[u8; 12]>(0x1000).unwrap(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );
    assert_eq!(f.gm.read_plain::<[u8; 4]>(0xffc).unwrap(), [0xa5; 4]);
    assert_eq!(f.gm.read_plain::<[u8; 4]>(0x100c).unwrap(), [0xa5; 4]);
    let before = f.gm.read_plain::<[u8; 20]>(0xffc).unwrap();
    f.write(PcatAddress::SRAT_DATA, u32::MAX);
    assert_eq!(f.gm.read_plain::<[u8; 20]>(0xffc).unwrap(), before);
    f.write(PcatAddress(0xffff), 0);
    f.write(PcatAddress::BOOT_FINALIZE, 0);
    assert_eq!(f.observer.replays.load(Ordering::SeqCst), 1);
}

// Test: Enumerate the BIOS E820 extension across additional RAM blocks and invalid entries.
// Expected: Returned lengths, continuation flags, and 64-bit addresses describe RAM.
#[async_test]
async fn e820_fifo_reports_extra_memory_ranges(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.write(PcatAddress::E820_ENTRY, 0);
    assert_eq!(
        [f.next(), f.next(), f.next(), f.next()],
        [(256 << 3) | 5, 0, 1, 0]
    );
    f.write(PcatAddress::E820_ENTRY, 1);
    assert_eq!(
        [f.next(), f.next(), f.next()],
        [(128 << 3) | 1, 0x4000_0000, 2]
    );
    f.write(PcatAddress::E820_ENTRY, 7);
    assert_eq!(f.next(), 0);
    let mut c = config();
    c.mem_layout = MemoryLayout::new_from_ranges(
        &[MemoryRangeWithNode {
            range: MemoryRange::new(0..0x2000_0000),
            vnode: 0,
        }],
        &[],
    )
    .unwrap();
    c.hibernation_enabled = false;
    let mut f = Fixture::with_config(&driver, c, None).await.unwrap();
    assert_eq!(f.read(PcatAddress::E820_ENTRY), 0);
    assert_eq!(f.read(PcatAddress::SLEEP_STATES), 0);
}

// Test: Deliver CPU SMBIOS records with explicit and missing processor information.
// Expected: Complete records include formatted fields, string padding and terminators;
//       adjacent RAM is untouched and absent CPU information uses unknown defaults.
#[async_test]
async fn processor_tables_are_written_in_the_guest_smbios_format(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.gm.write_at(0x1ffc, &[0xa5; 131]).unwrap();
    f.write(PcatAddress::PROCESSOR_DMTF_TABLE, 0x2000);
    let bytes = f.gm.read_plain::<[u8; 123]>(0x2000).unwrap();
    let mut expected = [b' '; 123];
    expected[..35].copy_from_slice(&[
        4, 35, 0, 0, 1, 3, 0xb3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0x81, 100, 0, 0x80, 0x0c, 0xf0,
        0x0a, 0x41, 6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 1, 1,
    ]);
    expected[35..54].copy_from_slice(b"None\0Maker\0Version\0");
    expected[121..].fill(0);
    assert_eq!(bytes, expected);
    assert_eq!(f.gm.read_plain::<[u8; 4]>(0x1ffc).unwrap(), [0xa5; 4]);
    assert_eq!(f.gm.read_plain::<[u8; 4]>(0x207b).unwrap(), [0xa5; 4]);
    f.write(PcatAddress::PROCESSOR_DMTF_TABLE, u32::MAX);
    assert_eq!(f.gm.read_plain::<[u8; 123]>(0x2000).unwrap(), expected);
    let mut c = config();
    c.smbios.cpu_info_bundle = None;
    c.smbios.processor_manufacturer.clear();
    c.smbios.processor_version.clear();
    let mut f = Fixture::with_config(&driver, c, None).await.unwrap();
    f.write(PcatAddress::PROCESSOR_DMTF_TABLE, 0);
    let bytes = f.gm.read_plain::<[u8; 123]>(0).unwrap();
    expected[6] = 2;
    expected[17] = 1;
    expected[18..24].fill(0);
    expected[35..121].fill(b' ');
    expected[35..50].copy_from_slice(b"None\0None\0None\0");
    assert_eq!(bytes, expected);
}

// Test: Write the entropy table twice and set the generation-ID pointer in two halves.
// Expected: Entropy is delivered once, and the complete pointer receives the initial ID.
#[async_test]
async fn entropy_is_one_shot_and_generation_id_reaches_guest_ram(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.write(PcatAddress::ENTROPY_TABLE, 0x1000);
    f.gm.write_at(0x2000, &[0x77; 64]).unwrap();
    f.write(PcatAddress::ENTROPY_TABLE, 0x2000);
    assert_eq!(f.gm.read_plain::<[u8; 64]>(0x2000).unwrap(), [0x77; 64]);
    f.write(PcatAddress::GENERATION_ID_PTR_LOW, 0x3000);
    assert_eq!(f.gm.read_plain::<[u8; 16]>(0x3000).unwrap(), [0; 16]);
    f.write(PcatAddress::GENERATION_ID_PTR_HIGH, 0);
    assert_eq!(f.gm.read_plain::<[u8; 16]>(0x3000).unwrap(), [0x42; 16]);
    f.device.reset().await;
    f.write(PcatAddress::ENTROPY_TABLE, 0);
    let bytes = f.gm.read_plain::<[u8; 64]>(0).unwrap();
    f.write(PcatAddress::ENTROPY_TABLE, 0x2000);
    assert_eq!(f.gm.read_plain::<[u8; 64]>(0x2000).unwrap(), [0x77; 64]);
    f.write(PcatAddress::ENTROPY_TABLE, 0);
    assert_eq!(f.gm.read_plain::<[u8; 64]>(0).unwrap(), bytes);
}

// Test: Report boot events and POST completion through the firmware interfaces.
// Expected: Logging and POST readback work, and pre-boot legacy ports stop responding.
#[async_test]
async fn boot_notifications_release_legacy_ports(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    let mut byte = [0];
    f.device.io_read(0x279, &mut byte).unwrap();
    assert_eq!(byte, [0xff]);
    f.device.io_write(0x279, &[0]).unwrap();
    f.select(PcatAddress::REPORT_BOOT_ATTEMPT);
    f.select(PcatAddress::REPORT_BOOT_FAILURE);
    assert_eq!(*f.observer.events.lock(), ["attempt", "failure"]);
    assert!(matches!(
        f.device.io_read(0x279, &mut byte),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    let mut f = Fixture::new(&driver).await;
    f.device.io_write(0x80, &0x50ac_u16.to_le_bytes()).unwrap();
    let mut post = [0; 2];
    f.device.io_read(0x80, &mut post).unwrap();
    assert_eq!(post, 0x50ac_u16.to_le_bytes());
    assert!(matches!(
        f.device.io_read(0x279, &mut byte),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
}

// Test: Save and restore midway through a BIOS string read and POST update.
// Expected: Read position and guest-visible POST bytes survive the round trip.
#[async_test]
async fn save_restore_preserves_protocol_continuation(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.device.io_write(0x80, &[0x55]).unwrap();
    f.select(PcatAddress::BIOS_SYSTEM_SERIAL_NUMBER);
    assert_eq!(f.next().to_le_bytes(), *b"seri");
    let saved = f.device.save().unwrap();
    let mut restored = Fixture::new(&driver).await;
    restored.device.restore(saved).unwrap();
    assert_eq!(restored.next().to_le_bytes(), *b"al  ");
    let mut byte = [0];
    restored.device.io_read(0x80, &mut byte).unwrap();
    assert_eq!(byte, [0x55]);
}

// Test: Request each BIOS wait command while VM time is stopped, then start time.
// Expected: IO remains pending initially and completes through device polling.
#[async_test]
async fn wait_commands_defer_until_vm_time_reaches_the_deadline(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    for address in [
        PcatAddress::WAIT1_MILLISECOND,
        PcatAddress::WAIT2_MILLISECOND,
        PcatAddress::WAIT10_MILLISECONDS,
        PcatAddress::WAIT_NANO100,
    ] {
        let result = if address == PcatAddress::WAIT_NANO100 {
            f.select(address);
            f.device.io_write(0x2c, &100_u32.to_le_bytes())
        } else {
            f.device.io_write(0x28, &address.0.to_le_bytes())
        };
        let IoResult::Defer(mut token) = result else {
            panic!("wait must defer")
        };
        assert!(
            poll_fn(|cx| {
                f.device.poll_device(cx);
                token.poll_write(cx)
            })
            .now_or_never()
            .is_none()
        );
        f.keeper.start().await;
        poll_fn(|cx| {
            f.device.poll_device(cx);
            token.poll_write(cx)
        })
        .await
        .unwrap();
        f.keeper.stop().await;
    }
}

// Test: Probe wrong-sized and unknown IO accesses and the firmware ROM aperture.
// Expected: Invalid port requests fail; tolerated ROM accesses leave read buffers untouched.
#[async_test]
async fn bus_interfaces_reject_bad_ports_and_tolerate_rom_accesses(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    assert!(f.device.supports_pio().is_some());
    assert!(f.device.supports_mmio().is_some());
    assert!(f.device.supports_poll_device().is_some());
    assert_eq!(
        PortIoIntercept::get_static_regions(&mut f.device),
        &[("pcat_bios", 0x28..=0x2d), ("post", 0x80..=0x80)]
    );
    assert_eq!(
        MmioIntercept::get_static_regions(&mut f.device),
        &[
            ("rom-low", 0xf0000..=0xfffff),
            ("rom-high", 0xfffc_0000..=0xffff_ffff),
        ]
    );
    assert!(matches!(
        f.device.io_read(0x28, &mut [0; 2]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        f.device.io_write(0x28, &[0; 2]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        f.device.io_read(0x29, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        f.device.io_write(0x29, &[0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    let mut bytes = [0x77; 4];
    f.device.mmio_read(0xf0000, &mut bytes).unwrap();
    assert_eq!(bytes, [0x77; 4]);
    for addr in [0xf5bea, 0xf5bfa, 0xf0000] {
        f.device.mmio_write(addr, &[0]).unwrap();
    }
}

struct Rom {
    len: u64,
    fail_at: Option<u64>,
    observer: Arc<Observer>,
}
struct Mapping {
    gpa: u64,
    observer: Arc<Observer>,
}
impl Drop for Mapping {
    fn drop(&mut self) {
        self.observer.rom_unmaps.lock().push(self.gpa);
    }
}
impl UnmapRom for Mapping {
    fn unmap_rom(self) {}
}
impl MapRom for Rom {
    fn len(&self) -> u64 {
        self.len
    }
    fn map_rom(&self, gpa: u64, offset: u64, len: u64) -> std::io::Result<Box<dyn UnmapRom>> {
        if self.fail_at == Some(gpa) {
            return Err(std::io::Error::other("test ROM mapping failure"));
        }
        self.observer.rom_maps.lock().push((gpa, offset, len));
        Ok(Box::new(Mapping {
            gpa,
            observer: self.observer.clone(),
        }))
    }
}

// Test: Supply invalid SMBIOS, MMIO, and ROM configurations and a valid BIOS ROM.
// Expected: Construction reports explicit errors or maps both required ROM aliases.
#[async_test]
async fn construction_validates_configuration_and_maps_rom_aliases(driver: DefaultDriver) {
    let mut c = config();
    c.smbios.system_serial_number = vec![b'x'; 33];
    assert!(matches!(
        Fixture::with_config(&driver, c, None).await,
        Err(PcatBiosDeviceInitError::SmbiosStringTooLong {
            field: "system serial number",
            len: 33,
            max: 32,
        })
    ));
    let mut c = config();
    c.chipset_low_mmio = MemoryRange::new(0..0);
    assert!(matches!(
        Fixture::with_config(&driver, c, None).await,
        Err(PcatBiosDeviceInitError::IncorrectMmioHoles)
    ));
    for (len, fail) in [(1, false), (0x40000, true)] {
        let rom = Rom {
            len,
            fail_at: fail.then_some(0xfffc0000),
            observer: Arc::default(),
        };
        let result = Fixture::with_config(&driver, config(), Some(Box::new(rom))).await;
        if fail {
            assert!(matches!(result, Err(PcatBiosDeviceInitError::Rom(_))));
        } else {
            assert!(matches!(
                result,
                Err(PcatBiosDeviceInitError::InvalidRomSize(1))
            ));
        }
    }
    let mut c = config();
    c.smbios.system_serial_number = b"0123456789abcdefghijklmnopqrstuv".to_vec();
    let observer = Arc::new(Observer::default());
    let rom = Rom {
        len: 0x40000,
        fail_at: None,
        observer: observer.clone(),
    };
    let mut f = Fixture::with_config(&driver, c, Some(Box::new(rom)))
        .await
        .unwrap();
    assert_eq!(
        *observer.rom_maps.lock(),
        [(0xfffc0000, 0, 0x40000), (0xf0000, 0x30000, 0x10000)]
    );
    assert!(observer.rom_unmaps.lock().is_empty());
    f.select(PcatAddress::BIOS_SYSTEM_SERIAL_NUMBER);
    let mut serial = Vec::new();
    for _ in 0..8 {
        serial.extend_from_slice(&f.next().to_le_bytes());
    }
    assert_eq!(serial, b"0123456789abcdefghijklmnopqrstuv");
    drop(f);
    let mut unmapped = observer.rom_unmaps.lock().clone();
    unmapped.sort_unstable();
    assert_eq!(unmapped, [0xf0000, 0xfffc0000]);
}

// Test: Fail the second ROM alias mapping while another BIOS device remains live.
// Expected: The first alias is released on failure, preserving the original error
//       and the peer's live mappings until the peer itself is dropped.
#[async_test]
async fn rom_mapping_failure_releases_only_its_own_alias(driver: DefaultDriver) {
    let peer_observer = Arc::new(Observer::default());
    let peer = Fixture::with_config(
        &driver,
        config(),
        Some(Box::new(Rom {
            len: 0x40000,
            fail_at: None,
            observer: peer_observer.clone(),
        })),
    )
    .await
    .unwrap();
    let observer = Arc::new(Observer::default());
    let result = Fixture::with_config(
        &driver,
        config(),
        Some(Box::new(Rom {
            len: 0x40000,
            fail_at: Some(0xf0000),
            observer: observer.clone(),
        })),
    )
    .await;
    let Err(PcatBiosDeviceInitError::Rom(error)) = result else {
        panic!("second ROM mapping must fail");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(error.to_string(), "test ROM mapping failure");
    assert_eq!(*observer.rom_maps.lock(), [(0xfffc0000, 0, 0x40000)]);
    assert_eq!(*observer.rom_unmaps.lock(), [0xfffc0000]);
    assert!(peer_observer.rom_unmaps.lock().is_empty());
    drop(peer);
    let mut unmapped = peer_observer.rom_unmaps.lock().clone();
    unmapped.sort_unstable();
    assert_eq!(unmapped, [0xf0000, 0xfffc0000]);
}

// Test: Save entropy after a failed destination write, then restore into fresh RAM.
// Expected: The restored device delivers the source bytes once, preserves neighboring
//       RAM and cannot write another entropy table after saving the placed state.
#[async_test]
async fn entropy_retry_and_migration_preserve_guest_delivery(driver: DefaultDriver) {
    let mut source = Fixture::new(&driver).await;
    source.write(PcatAddress::ENTROPY_TABLE, u32::MAX);
    let saved = source.device.save().unwrap();
    source.write(PcatAddress::ENTROPY_TABLE, 0x1000);
    let entropy = source.gm.read_plain::<[u8; 64]>(0x1000).unwrap();

    let mut restored = Fixture::new(&driver).await;
    restored.gm.write_at(0x1ffc, &[0xa5; 72]).unwrap();
    restored.device.restore(saved).unwrap();
    restored.write(PcatAddress::ENTROPY_TABLE, 0x2000);
    assert_eq!(restored.gm.read_plain::<[u8; 64]>(0x2000).unwrap(), entropy);
    assert_eq!(
        restored.gm.read_plain::<[u8; 4]>(0x1ffc).unwrap(),
        [0xa5; 4]
    );
    assert_eq!(
        restored.gm.read_plain::<[u8; 4]>(0x2040).unwrap(),
        [0xa5; 4]
    );
    assert_eq!(source.gm.read_plain::<[u8; 64]>(0x1000).unwrap(), entropy);
    assert_eq!(source.gm.read_plain::<[u8; 64]>(0x2000).unwrap(), [0; 64]);

    let placed = restored.device.save().unwrap();
    let mut destination = Fixture::new(&driver).await;
    destination.gm.write_at(0x3000, &[0x77; 64]).unwrap();
    destination.device.restore(placed).unwrap();
    destination.write(PcatAddress::ENTROPY_TABLE, 0x3000);
    assert_eq!(
        destination.gm.read_plain::<[u8; 64]>(0x3000).unwrap(),
        [0x77; 64]
    );
    assert_eq!(restored.gm.read_plain::<[u8; 64]>(0x2000).unwrap(), entropy);
}

// Test: Save and restore after reading part of a nonzero E820 descriptor.
// Expected: The remaining high address word and end marker resume in order.
#[async_test]
async fn e820_descriptor_continuation_survives_save_restore(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.write(PcatAddress::E820_ENTRY, 1);
    assert_eq!(f.next(), (128 << 3) | 1);
    assert_eq!(f.next(), 0x4000_0000);
    let saved = f.device.save().unwrap();

    let mut restored = Fixture::new(&driver).await;
    restored.device.restore(saved).unwrap();
    assert_eq!(restored.next(), 2);
    assert_eq!(restored.next(), 0);
    restored.write(PcatAddress::E820_ENTRY, 0);
    assert_eq!(
        [restored.next(), restored.next(), restored.next()],
        [(256 << 3) | 5, 0, 1]
    );
}

// IGNORED: Adding one to the eight-bit E820 index overflows before the missing
//       range can be rejected; checked builds panic on a guest port read.
//
// Test: Select the maximum E820 descriptor index through the BIOS ports.
// Expected: The missing entry returns zero rather than wrapping or panicking.
#[async_test]
#[ignore = "product bug: maximum E820 index overflows before range validation"]
async fn e820_maximum_index_reports_a_missing_entry(driver: DefaultDriver) {
    let mut f = Fixture::new(&driver).await;
    f.write(PcatAddress::E820_ENTRY, u32::from(u8::MAX));
    assert_eq!(f.next(), 0);
}
