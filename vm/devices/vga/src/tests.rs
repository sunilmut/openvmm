// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::io::IoError;
use chipset_device::pci::PciConfigByteEnable;
use framebuffer::FRAMEBUFFER_SIZE;
use framebuffer::FramebufferDevice;
use guestmem::GuestMemory;
use guestmem::MappableGuestMemory;
use guestmem::MappedMemoryRegion;
use guestmem::MemoryMapper;
use parking_lot::Mutex;
use sparse_mmap::AsMappableRef;
use sparse_mmap::SparseMapping;
use std::io;
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mapping {
    Map { gpa: u64, len: usize },
    Unmap,
}

struct TestMemory {
    events: Arc<Mutex<Vec<Mapping>>>,
    len: usize,
}

impl MappableGuestMemory for TestMemory {
    fn map_to_guest(&mut self, gpa: u64, writable: bool) -> io::Result<()> {
        assert!(writable);
        self.events.lock().push(Mapping::Map { gpa, len: self.len });
        Ok(())
    }

    fn unmap_from_guest(&mut self) {
        self.events.lock().push(Mapping::Unmap);
    }
}

struct TestRegion(SparseMapping);

impl MappedMemoryRegion for TestRegion {
    fn map(
        &self,
        offset: usize,
        section: &dyn AsMappableRef,
        file_offset: u64,
        len: usize,
        writable: bool,
    ) -> io::Result<()> {
        self.0.map_file(offset, len, section, file_offset, writable)
    }

    fn unmap(&self, offset: usize, len: usize) -> io::Result<()> {
        self.0.unmap(offset, len)
    }
}

struct TestMapper(Arc<Mutex<Vec<Mapping>>>);

impl MemoryMapper for TestMapper {
    fn new_region(
        &self,
        len: usize,
        _debug_name: String,
    ) -> io::Result<(Box<dyn MappableGuestMemory>, Arc<dyn MappedMemoryRegion>)> {
        Ok((
            Box::new(TestMemory {
                events: self.0.clone(),
                len,
            }),
            Arc::new(TestRegion(SparseMapping::new(len)?)),
        ))
    }
}

pub(crate) struct Fixture {
    pub(crate) device: VgaDevice,
    pub(crate) vram: GuestMemory,
    pub(crate) view: framebuffer::View,
    pub(crate) mappings: Arc<Mutex<Vec<Mapping>>>,
    pub(crate) pool: pal_async::DefaultPool,
    _keeper: VmTimeKeeper,
}

impl Fixture {
    // Build the real device and framebuffer with a recording guest-memory mapper.
    pub(crate) fn new() -> Self {
        Self::with_optional_rom(None)
    }

    // Include a ROM provider when exercising PCI expansion-ROM mapping.
    fn with_optional_rom(rom: Option<Box<dyn MapRom>>) -> Self {
        let mut pool = pal_async::DefaultPool::new();
        let driver = pool.driver();
        let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(1000));
        let time = pool.run_until(keeper.builder().build(&driver)).unwrap();
        let driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver)).simple();
        let memory = sparse_mmap::alloc_shared_memory(FRAMEBUFFER_SIZE, "vga-test").unwrap();
        let (fb, access) = framebuffer::framebuffer(memory, FRAMEBUFFER_SIZE, 0).unwrap();
        let mappings = Arc::new(Mutex::new(Vec::new()));
        let framebuffer =
            FramebufferDevice::new(Box::new(TestMapper(mappings.clone())), fb, None).unwrap();
        let control = framebuffer.control();
        let vram = control.memory().unwrap();
        let device = VgaDevice::new(&driver, &time, control, rom).unwrap();
        Self {
            device,
            vram,
            view: access.view().unwrap(),
            mappings,
            pool,
            _keeper: keeper,
        }
    }

    // Write one byte through the chipset's guest-visible port interface.
    pub(crate) fn out(&mut self, port: u16, value: u8) {
        self.device.io_write(port, &[value]).unwrap();
    }

    // Read one byte through the chipset's guest-visible port interface.
    pub(crate) fn input(&mut self, port: u16) -> u8 {
        let mut value = [0];
        self.device.io_read(port, &mut value).unwrap();
        value[0]
    }

    // Write an indexed register using the BIOS's combined index/data operation.
    pub(crate) fn indexed(&mut self, port: u16, index: u8, value: u8) {
        self.device.io_write(port, &[index, value]).unwrap();
    }

    // Read an indexed register without consulting emulator internals.
    fn read_indexed(&mut self, port: u16, index: u8) -> u8 {
        self.out(port, index);
        self.input(port + 1)
    }

    // Reset the attribute flip-flop before selecting and writing its data register.
    pub(crate) fn attribute(&mut self, index: u8, value: u8) {
        self.input(0x3da);
        self.out(0x3c0, index);
        self.out(0x3c0, value);
    }

    // Select ordinary planar addressing with the 64 KiB graphics aperture.
    fn planar(&mut self) {
        self.indexed(0x3c4, 4, 4);
        self.indexed(0x3ce, 6, 5);
    }

    // Read a DWORD from PCI configuration space.
    fn pci_read(&mut self, offset: u16) -> u32 {
        let mut value = 0;
        self.device
            .pci_cfg_read(
                offset,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
            )
            .unwrap();
        value
    }

    // Write a DWORD to PCI configuration space.
    fn pci_write(&mut self, offset: u16, value: u32) {
        self.device
            .pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(value))
            .unwrap();
    }

    // Read guest-visible VGA aperture bytes.
    fn read_memory(&mut self, address: u64, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        self.device.mmio_read(address, &mut data).unwrap();
        data
    }
}

// Test: Enumerate the adapter and probe its PCI registers and unimplemented BARs.
// Expected: IDs/class are stable, writable bits are masked, and absent registers fail.
#[test]
fn pci_enumeration_masks_writes_and_rejects_absent_registers() {
    let mut f = Fixture::new();
    assert_eq!(f.device.suggested_bdf(), Some((0, 8, 0)));
    assert!(f.device.supports_pio().is_some());
    assert!(f.device.supports_mmio().is_some());
    assert!(f.device.supports_pci().is_some());
    assert_eq!(f.pci_read(0), 0x53531414);
    assert_eq!(f.pci_read(8), 0x03000000);
    assert_eq!(f.pci_read(0xc), 0);
    assert_eq!(f.pci_read(0x2c), 0);
    f.pci_write(4, u32::MAX);
    assert_eq!(f.pci_read(4), 0x7ff);
    f.device
        .pci_cfg_write(
            4,
            ByteEnabledDwordWrite::new(0x1200, PciConfigByteEnable::new(2).unwrap()),
        )
        .unwrap();
    assert_eq!(f.pci_read(4), 0x2ff);
    f.pci_write(0x10, u32::MAX);
    assert_eq!(f.pci_read(0x10), 0xfc000000);
    f.pci_write(0x3c, 0xdeadbe37);
    assert_eq!(f.pci_read(0x3c), 0x137);
    f.pci_write(0x30, u32::MAX);
    assert_eq!(f.pci_read(0x30), 0);
    for offset in [0x14, 0x18, 0x1c, 0x20, 0x24, 0x40] {
        let mut value = 0;
        assert!(matches!(
            f.device.pci_cfg_read(
                offset,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
            ),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            f.device
                .pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(1)),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert!(matches!(
        f.device
            .pci_cfg_write(0xc, ByteEnabledDwordWrite::with_all_bytes_enabled(1)),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Use separate and combined index/data accesses, including reserved index bits.
// Expected: Address aliases select the same register while index readback is preserved.
#[test]
fn indexed_registers_preserve_guest_readback() {
    let mut f = Fixture::new();
    for (port, index, value) in [(0x3c4, 0xe2, 0xa5), (0x3ce, 0xf0, 0xb9)] {
        f.indexed(port, index, value);
        assert_eq!(f.input(port), index);
        assert_eq!(f.input(port + 1), value);
        f.out(port + 1, 0x5a);
        assert_eq!(f.input(port + 1), 0x5a);
    }
    f.indexed(0x3b4, 0x0f, 0x67);
    assert_eq!(f.input(0x3b4), 0x0f);
    assert_eq!(f.read_indexed(0x3d4, 0x0f), 0x67);
    f.attribute(0x13, 5);
    assert_eq!(f.input(0x3c0), 0x13);
    assert_eq!(f.input(0x3c1), 5);
    f.out(0x3c1, 0xff);
    assert_eq!(f.input(0x3c1), 5);
    f.attribute(0x16, 0xff);
    assert_eq!(f.input(0x3c1), 0xef);
}

// Test: Lock legacy timing registers and attempt to overwrite read-only S3 identity.
// Expected: Locked timing is preserved, overflow bit 4 remains writable, IDs persist.
#[test]
fn crt_locking_and_read_only_identity_are_enforced() {
    let mut f = Fixture::new();
    f.indexed(0x3d4, 0, 0x37);
    f.indexed(0x3d4, 7, 0x02);
    f.indexed(0x3d4, 0x11, 0x80);
    f.indexed(0x3d4, 0, 0x54);
    f.indexed(0x3d4, 7, 0xff);
    assert_eq!(f.read_indexed(0x3d4, 0), 0x37);
    assert_eq!(f.read_indexed(0x3d4, 7), 0x12);
    f.indexed(0x3d4, 0x11, 0);
    f.indexed(0x3d4, 0, 0x54);
    assert_eq!(f.read_indexed(0x3d4, 0), 0x54);
    for (reg, expected) in [(0x2d, 0x53), (0x2e, 0x53), (0x2f, 0), (0x30, 0)] {
        f.indexed(0x3d4, reg, expected ^ 0xff);
        assert_eq!(f.read_indexed(0x3d4, reg), expected);
    }
    f.indexed(0x3d4, 0x36, 0xff);
    assert_eq!(f.read_indexed(0x3d4, 0x36), 0xfe);
    f.indexed(0x3d4, 0x5c, 0xff);
    assert_eq!(f.read_indexed(0x3d4, 0x5c), 0xf0);
    f.indexed(0x3d4, 0x61, 0xff);
    assert_eq!(f.read_indexed(0x3d4, 0x61), 0x60);
    for reg in [0x69, 0x6a] {
        f.indexed(0x3d4, reg, 0xff);
        assert_eq!(f.read_indexed(0x3d4, reg), 0xff);
    }
}

// Test: Program DAC colors across index 255 and read them back component by component.
// Expected: RGB access wraps to entry zero and reads do not disturb the write index.
#[test]
fn dac_component_indices_wrap_independently() {
    let mut f = Fixture::new();
    f.out(0x3c8, 255);
    for value in [63, 32, 1, 2, 3, 4] {
        f.out(0x3c9, value);
    }
    assert_eq!(f.input(0x3c8), 1);
    f.out(0x3c7, 255);
    for expected in [63, 32, 1, 2, 3, 4] {
        assert_eq!(f.input(0x3c9), expected);
    }
    assert_eq!(f.input(0x3c8), 1);
    f.out(0x3c6, 0x7e);
    assert_eq!(f.input(0x3c6), 0x7e);
    assert_eq!(f.input(0x3c7), 0);
}

// Test: Write distinct planar data and use each graphics write mode and raster op.
// Expected: Latches, per-plane masks, rotated data, and pixel masks compose correctly.
#[test]
fn planar_write_modes_apply_latches_masks_and_raster_operations() {
    let mut f = Fixture::new();
    f.planar();
    let latched = [0x55u8, 0xaa, 0x0f, 0xf0];
    for mode in 0..4 {
        for operation in 0..4 {
            f.vram.write_at(0, &latched).unwrap();
            f.vram.write_at(4, &[0x33; 4]).unwrap();
            f.indexed(0x3ce, 5, mode);
            f.indexed(0x3ce, 3, operation << 3 | 1);
            f.indexed(0x3ce, 0, 0x0a);
            f.indexed(0x3ce, 1, 0x05);
            f.indexed(0x3ce, 8, 0x3c);
            f.indexed(0x3c4, 2, 0x07);
            f.read_memory(0xa0000, 1);
            f.device.mmio_write(0xa0001, &[0x96]).unwrap();
            let actual: [u8; 4] = f.vram.read_plain(4).unwrap();
            let mut expected = [0x33; 4];
            for plane in 0..3 {
                if mode == 1 {
                    expected[plane] = latched[plane];
                    continue;
                }
                let bit = 1 << plane;
                let set_reset = if 0x0a & bit != 0 { 0xff } else { 0 };
                let (data, mask) = match mode {
                    0 => (if 0x05 & bit != 0 { set_reset } else { 0x4b }, 0x3c),
                    2 => (if 0x96 & bit != 0 { 0xff } else { 0 }, 0x3c),
                    3 => (set_reset, 0x3c & 0x4b),
                    _ => unreachable!(),
                };
                let data = match operation {
                    0 => data,
                    1 => data & latched[plane],
                    2 => data | latched[plane],
                    3 => data ^ latched[plane],
                    _ => unreachable!(),
                };
                expected[plane] = data & mask | latched[plane] & !mask;
            }
            assert_eq!(actual, expected, "mode {mode}, operation {operation}");
        }
    }
}

// Test: Read selected planes and compare pixel colors while ignoring one plane.
// Expected: Read mode zero selects one plane; mode one returns matching pixel bits.
#[test]
fn planar_reads_select_planes_and_compare_colors() {
    let mut f = Fixture::new();
    f.planar();
    let planes = [0x55, 0xaa, 0x0f, 0xf0];
    f.vram.write_at(0, &planes).unwrap();
    for (plane, expected) in planes.into_iter().enumerate() {
        f.indexed(0x3ce, 4, plane as u8);
        assert_eq!(f.read_memory(0xa0000, 1), [expected]);
    }
    f.indexed(0x3ce, 5, 8);
    f.indexed(0x3ce, 2, 5);
    f.indexed(0x3ce, 7, 7);
    assert_eq!(f.read_memory(0xa0000, 1), [0x05]);
}

// Test: Switch between chain-four and odd/even host addressing.
// Expected: Chain-four selects individual planes; odd/even selects paired planes.
#[test]
fn host_addressing_modes_route_writes_to_the_expected_planes() {
    let mut f = Fixture::new();
    f.planar();
    f.indexed(0x3c4, 4, 0x0c);
    f.device.mmio_write(0xa0000, &[1, 2, 3, 4]).unwrap();
    assert_eq!(f.vram.read_plain::<[u8; 4]>(0).unwrap(), [1, 2, 3, 4]);
    assert_eq!(f.read_memory(0xa0000, 4), [1, 2, 3, 4]);
    f.indexed(0x3c4, 4, 0);
    f.device.mmio_write(0xa0000, &[0x12, 0x34]).unwrap();
    assert_eq!(
        f.vram.read_plain::<[u8; 4]>(0).unwrap(),
        [0x12, 0x34, 0x12, 0x34]
    );
    assert_eq!(f.read_memory(0xa0000, 2), [0x12, 0x34]);
}

// Test: Relocate the legacy aperture and select an inaccessible video-memory bank.
// Expected: Only the selected aperture responds, and out-of-VRAM accesses are inert.
#[test]
fn aperture_selection_and_out_of_range_banks_are_isolated() {
    let mut f = Fixture::new();
    f.planar();
    for (mode, start, end) in [
        (0, 0xa0000, 0xc0000),
        (1, 0xa0000, 0xb0000),
        (2, 0xb0000, 0xb8000),
        (3, 0xb8000, 0xc0000),
    ] {
        f.indexed(0x3ce, 6, mode << 2 | 1);
        f.device.mmio_write(start, &[0x56]).unwrap();
        assert_eq!(f.read_memory(start, 1), [0x56]);
        assert_eq!(f.read_memory(start - 1, 1), [0xff]);
        assert_eq!(f.read_memory(end, 1), [0xff]);
        f.device.mmio_write(end, &[0x99]).unwrap();
        assert_eq!(f.read_memory(start, 1), [0x56]);
    }
    f.indexed(0x3d4, 0x38, 0x48);
    f.indexed(0x3d4, 0x35, 0x0f);
    f.indexed(0x3d4, 0x51, 0x0c);
    let mut before = vec![0; FRAMEBUFFER_SIZE];
    f.vram.read_at(0, &mut before).unwrap();
    for mode in 0..4 {
        f.indexed(0x3ce, 5, mode);
        f.device.mmio_write(0xb8000, &[0x99]).unwrap();
        assert_eq!(f.read_memory(0xb8000, 1), [0xff]);
    }
    f.indexed(0x3ce, 5, 8);
    assert_eq!(f.read_memory(0xb8000, 1), [0xff]);
    let mut after = vec![0; FRAMEBUFFER_SIZE];
    f.vram.read_at(0, &mut after).unwrap();
    let changed = before
        .iter()
        .zip(&after)
        .enumerate()
        .find(|(_, (before, after))| before != after);
    assert_eq!(
        changed, None,
        "out-of-range writes changed framebuffer data"
    );
    f.indexed(0x3d4, 0x35, 0);
    f.indexed(0x3d4, 0x51, 0);
    f.indexed(0x3ce, 5, 0);
    assert_eq!(f.read_memory(0xb8000, 1), [0x56]);
}

// Test: Move the linear framebuffer through PCI and S3 registers and disable it.
// Expected: Mapping sizes and alignment follow the selected window; reset unmaps it.
#[test]
fn linear_framebuffer_mapping_obeys_size_alignment_and_reset() {
    let mut f = Fixture::new();
    f.pci_write(0x10, 0xe0000000);
    let mut expected = Vec::new();
    for (code, len) in [(0, 0x10000), (1, 0x100000), (2, 0x200000), (3, 0x400000)] {
        f.indexed(0x3d4, 0x58, code | 0x10);
        if code != 0 {
            expected.push(Mapping::Unmap);
        }
        expected.push(Mapping::Map {
            gpa: 0xe0000000,
            len,
        });
        assert_eq!(*f.mappings.lock(), expected);
    }
    f.indexed(0x3d4, 0x59, 0xd1);
    f.indexed(0x3d4, 0x5a, 0x23);
    for _ in 0..2 {
        expected.extend([
            Mapping::Unmap,
            Mapping::Map {
                gpa: 0xd1000000,
                len: 0x400000,
            },
        ]);
    }
    assert_eq!(*f.mappings.lock(), expected);
    f.indexed(0x3d4, 0x58, 0);
    expected.push(Mapping::Unmap);
    assert_eq!(*f.mappings.lock(), expected);
    f.indexed(0x3d4, 0x58, 0x10);
    f.pool.run_until(f.device.reset());
    expected.extend([
        Mapping::Map {
            gpa: 0xd1230000,
            len: 0x10000,
        },
        Mapping::Unmap,
    ]);
    assert_eq!(*f.mappings.lock(), expected);
    assert_eq!(f.pci_read(4), 0);
    assert_eq!(f.read_indexed(0x3d4, 0x58), 0);
}

// Test: Invoke the BIOS clear-screen extension repeatedly and send an unknown opcode.
// Expected: Clear removes all VRAM bytes each time; unknown operations preserve data.
#[test]
fn bios_clear_screen_clears_the_entire_framebuffer_each_time() {
    let mut f = Fixture::new();
    for _ in 0..2 {
        f.vram.fill_at(0, 0xa5, FRAMEBUFFER_SIZE).unwrap();
        f.indexed(0x3d4, 0x73, 0x53);
        let mut bytes = vec![1; FRAMEBUFFER_SIZE];
        f.vram.read_at(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
    f.vram.write_at(0, &[0x77]).unwrap();
    f.indexed(0x3d4, 0x73, 0);
    assert_eq!(f.vram.read_plain::<u8>(0).unwrap(), 0x77);
}

// Test: Poll status, legacy compatibility ports, and an unmapped port.
// Expected: Fixed status bits persist, horizontal retrace progresses, unknowns float.
#[test]
fn status_and_legacy_ports_report_compatible_values() {
    let mut f = Fixture::new();
    let initial = f.input(0x3da);
    assert_eq!(initial & 0xf4, 0xf4);
    for _ in 0..11 {
        f.input(0x3da);
    }
    // VM time stays frozen, so only horizontal retrace changes.
    assert_eq!(f.input(0x3da), initial ^ 1);
    for (port, expected) in [
        (0x3c3, 0x80),
        (0x3ca, 0),
        (0x3d8, 0x50),
        (0x3d3, 0x80),
        (0x3d6, 0x80),
        (0x3d7, 0x80),
        (0x3db, 0x80),
        (0x3dc, 0x80),
        (0x3dd, 0x80),
        (0x3de, 0x80),
        (0x3df, 0x80),
        (0x3d0, 0xff),
        (0x3cd, 0xff),
        (0x1234, 0xff),
    ] {
        f.out(port, 0x5a);
        assert_eq!(f.input(port), expected, "port {port:x}");
    }
    f.out(0x3c2, 0x67);
    assert_eq!(f.input(0x3cc), 0x67);
}

struct TestRom {
    mappings: Arc<Mutex<Vec<(u64, u64, u64)>>>,
    active: Arc<std::sync::atomic::AtomicUsize>,
}

struct RomMapping(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for RomMapping {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl guestmem::UnmapRom for RomMapping {
    fn unmap_rom(self) {}
}

impl MapRom for TestRom {
    fn map_rom(&self, gpa: u64, offset: u64, len: u64) -> io::Result<Box<dyn guestmem::UnmapRom>> {
        self.mappings.lock().push((gpa, offset, len));
        if gpa == 0xdead0000 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(RomMapping(self.active.clone())))
    }

    fn len(&self) -> u64 {
        0x10000
    }
}

// Test: Enable, relocate, disable, and fail mapping a PCI expansion ROM.
// Expected: Only one mapping stays active; old mappings drop and later writes recover.
#[test]
fn expansion_rom_mapping_releases_previous_mappings_and_recovers() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    let mappings = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let mut f = Fixture::with_optional_rom(Some(Box::new(TestRom {
        mappings: mappings.clone(),
        active: active.clone(),
    })));
    f.pci_write(0x30, 0xc123fefe);
    assert_eq!(f.pci_read(0x30), 0xc1230000);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    for base in [0xc1230000, 0xc1230000, 0xc1240000] {
        f.pci_write(0x30, base | 1);
        assert_eq!(active.load(Ordering::SeqCst), 1);
    }
    assert_eq!(
        *mappings.lock(),
        [(0xc1230000, 0, 0x10000), (0xc1240000, 0, 0x10000)]
    );
    f.pci_write(0x30, 0xdead0001);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    f.pci_write(0x30, 0xc1230001);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    f.pci_write(0x30, 0xc1230000);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    f.pci_write(0x30, 0xc1230001);
    f.pool.run_until(f.device.reset());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(f.pci_read(0x30), 0);
}

// Test: Change CPU bank offsets in legacy and enhanced memory modes.
// Expected: Banked writes reach separate VRAM locations; locked bank writes do not.
#[test]
fn bank_selection_is_locked_until_unlocked_and_isolated_between_modes() {
    let mut f = Fixture::new();
    f.planar();
    f.indexed(0x3d4, 0x35, 1);
    assert_eq!(f.read_indexed(0x3d4, 0x35), 0);
    f.indexed(0x3d4, 0x38, 0x48);
    f.indexed(0x3d4, 0x35, 1);
    f.device.mmio_write(0xa0000, &[0x42]).unwrap();
    assert_eq!(f.vram.read_plain::<[u8; 4]>(0x40000).unwrap(), [0x42; 4]);
    assert_eq!(f.vram.read_plain::<[u8; 4]>(0).unwrap(), [0; 4]);
    f.indexed(0x3d4, 0x31, 8);
    f.indexed(0x3d4, 0x6a, 2);
    f.device.mmio_write(0xa0000, &[0x53]).unwrap();
    assert_eq!(f.vram.read_plain::<[u8; 4]>(0x20000).unwrap(), [0x53; 4]);
    f.indexed(0x3d4, 0x31, 0);
    assert_eq!(f.read_memory(0xa0000, 1), [0x42]);
}

// Test: Use a wide MMIO read to latch the lowest-addressed pixel before a copy.
// Expected: Write mode one copies the low-addressed latch, not the last array byte.
#[test]
fn multi_byte_reads_leave_the_low_address_in_the_latches() {
    let mut f = Fixture::new();
    f.planar();
    f.vram.write_at(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(f.read_memory(0xa0000, 2), [1, 5]);
    f.indexed(0x3ce, 5, 1);
    f.device.mmio_write(0xa0002, &[0]).unwrap();
    assert_eq!(f.vram.read_plain::<[u8; 4]>(8).unwrap(), [1, 2, 3, 4]);
}

// Test: Set enhanced mode using either the S3 CRT alias or the 16-bit AFC port.
// Expected: The shared enable bit stays synchronized without erasing unrelated bits.
#[test]
fn enhanced_mode_register_aliases_preserve_unrelated_bits() {
    let mut f = Fixture::new();
    f.indexed(0x3d4, 0x66, 0xfc);
    f.device.io_write(0x4ae8, &[0x23, 1]).unwrap();
    assert_eq!(f.read_indexed(0x3d4, 0x66), 0xfd);
    f.indexed(0x3d4, 0x66, 0xfc);
    let mut value = [0; 2];
    f.device.io_read(0x4ae8, &mut value).unwrap();
    assert_eq!(value, [0x22, 1]);
}

// Test: Move frozen VM time into and out of the vertical-retrace interval.
// Expected: Both VGA status ports report the same retrace phase after time changes.
#[test]
fn vertical_retrace_follows_vm_time_not_host_time() {
    let mut f = Fixture::new();
    for (time, retracing) in [(0, true), (1000, false), (16670, true)] {
        f.pool
            .run_until(f._keeper.restore(vmcore::vmtime::SavedState::from_vmtime(
                VmTime::from_100ns(time),
            )));
        assert_eq!(f.input(0x3c2) & 0x80 != 0, retracing);
        assert_eq!(f.input(0x3da) & 8 != 0, retracing);
    }
}

// IGNORED: The blue-screen loader retains consumed register bytes instead of
// advancing past them; attribute programming then indexes an empty slice.
//
// Test: Request the documented synthetic blue-screen mode using the guest port.
// Expected: The operation completes without panicking and selects 32-bit color.
#[test]
#[ignore = "product bug: blue-screen register loading panics on an empty slice"]
fn blue_screen_extension_selects_direct_color_without_panicking() {
    let mut f = Fixture::new();
    f.pci_write(0x10, 0xe0000000);
    f.indexed(0x3d4, 0x73, 0xbd);
    assert_eq!(f.read_indexed(0x3d4, 0x67) & 0xf0, 0xd0);
    assert_eq!(f.input(0x4ae8) & 1, 1);
}

mod consumers;
