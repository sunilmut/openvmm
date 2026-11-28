// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::root::GenericPcieRootComplex;
use crate::test_helpers::{TestPciDevice, TestPciePioRegistration};
use crate::{GenericPciePortDefinition, PciePortSettings};
use chipset_device::ChipsetDevice;
use chipset_device::io::{IoError, IoResult};
use chipset_device::mmio::{ControlMmioIntercept, MmioIntercept, RegisterMmioIntercept};
use chipset_device::pci::{
    ByteEnabledDwordRead, ByteEnabledDwordWrite, PciConfigAccessType, PciConfigAddress,
    PciConfigSpace,
};
use chipset_device::pio::PortIoIntercept;
use cxl_spec::pci_registers::flex_bus_port_dvsec::CxlFlexBusPortDvsecCapability;
use memory_range::MemoryRange;
use pci_core::bus_range::AssignedBusRange;
use pci_core::msi::{MsiConnection, SignalMsi};
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::SaveRestore;

struct MmioRegistration;

struct MmioRegion {
    name: String,
    base: Option<u64>,
    len: u64,
}

impl RegisterMmioIntercept for MmioRegistration {
    fn new_io_region(&mut self, name: &str, len: u64) -> Box<dyn ControlMmioIntercept> {
        Box::new(MmioRegion {
            name: name.into(),
            base: None,
            len,
        })
    }
}

impl ControlMmioIntercept for MmioRegion {
    fn map(&mut self, address: u64) {
        self.base = Some(address);
    }
    fn unmap(&mut self) {
        self.base = None;
    }
    fn addr(&self) -> Option<u64> {
        self.base
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn offset_of(&self, address: u64) -> Option<u64> {
        address
            .checked_sub(self.base?)
            .filter(|offset| *offset < self.len)
    }
    fn region_name(&self) -> &str {
        &self.name
    }
}

fn root(cxl: bool, hotplug: bool, pio: bool, connection: &MsiConnection) -> GenericPcieRootComplex {
    let mut mmio = MmioRegistration;
    let mut pio_registration = TestPciePioRegistration;
    let range = AssignedBusRange::new();
    range.set_bus_range(0, 3);
    GenericPcieRootComplex::builder(
        &mut mmio,
        &mut pio_registration,
        0..=3,
        MemoryRange::new(0..0x400000),
    )
    .root_ports(
        vec![GenericPciePortDefinition {
            name: "port".into(),
            devfn: None,
            hotplug,
            settings: PciePortSettings {
                cxl_flex_bus_port_capability: cxl
                    .then(|| CxlFlexBusPortDvsecCapability::new().with_mem_capable(true)),
                ..Default::default()
            },
        }],
        &connection.msi_target(range, 0),
    )
    .legacy_pci_config_io(pio)
    .chbcr_range(cxl.then(|| MemoryRange::new(0x10000000..0x10010000)))
    .build()
    .unwrap()
}

fn read32(root: &mut GenericPcieRootComplex, address: u64) -> u32 {
    let mut bytes = [0; 4];
    root.mmio_read(address, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

fn capability(root: &mut GenericPcieRootComplex, id: u8) -> u64 {
    let mut offset = (read32(root, 0x34) & 0xff) as u64;
    for _ in 0..48 {
        assert_ne!(offset, 0, "missing capability {id}");
        let header = read32(root, offset);
        if header as u8 == id {
            return offset;
        }
        offset = ((header >> 8) & 0xff) as u64;
    }
    panic!("capability list cycle");
}

fn switch() -> crate::switch::GenericPcieSwitch {
    crate::switch::GenericPcieSwitch::new(crate::switch::GenericPcieSwitchDefinition {
        name: "switch".into(),
        downstream_ports: [0, 8]
            .into_iter()
            .map(|devfn| GenericPciePortDefinition {
                name: format!("port-{devfn}").into(),
                devfn: Some(devfn),
                hotplug: false,
                settings: Default::default(),
            })
            .collect(),
        msi_target: pci_core::msi::MsiTarget::disconnected(),
    })
    .unwrap()
}

fn config_write(
    device: &mut dyn PciConfigSpace,
    kind: PciConfigAccessType,
    bus: u8,
    devfn: u8,
    offset: u16,
    value: u32,
) {
    device
        .pci_cfg_write_with_routing(
            kind,
            PciConfigAddress::new(bus, devfn, offset / 4).unwrap(),
            ByteEnabledDwordWrite::with_all_bytes_enabled(value),
        )
        .unwrap();
}

fn config_read(
    device: &mut dyn PciConfigSpace,
    kind: PciConfigAccessType,
    bus: u8,
    devfn: u8,
    offset: u16,
) -> u32 {
    let mut value = 0;
    device
        .pci_cfg_read_with_routing(
            kind,
            PciConfigAddress::new(bus, devfn, offset / 4).unwrap(),
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
        )
        .unwrap();
    value
}

// Test: Route config writes through initialized, missing and out-of-range switch ports.
// Expected: Only the addressed bridge changes, absent targets read all ones, and
//       reset returns both upstream and downstream bus registers to zero.
#[pal_async::async_test]
async fn switch_routing_ignores_absent_targets_and_reset_restores_bus_defaults() {
    use PciConfigAccessType::{Type0, Type1};
    let mut device = switch();
    config_write(&mut device, Type1, 1, 0, 0x18, 0x00020201);
    config_write(&mut device, Type0, 0, 8, 0x18, 0x00040400);
    assert_eq!(config_read(&mut device, Type0, 0, 0, 0x18), 0);
    config_write(&mut device, Type0, 0, 0, 0x18, 0x00050100);
    config_write(&mut device, Type1, 6, 0, 0x18, 0x00020201);
    config_write(&mut device, Type1, 1, 16, 0x18, 0x00020201);
    config_write(&mut device, Type1, 4, 0, 0x18, 0x00020201);
    config_write(&mut device, Type1, 1, 0, 0x18, 0x00020201);
    device
        .add_pcie_device(0, "endpoint", Box::new(TestPciDevice))
        .unwrap();
    config_write(&mut device, Type1, 2, 0, 0x4, 0);
    config_write(&mut device, Type1, 3, 0, 0x4, 0);
    assert_eq!(config_read(&mut device, Type1, 1, 0, 0x18), 0x00020201);
    assert_eq!(config_read(&mut device, Type1, 1, 8, 0x18), 0);
    assert_eq!(config_read(&mut device, Type1, 1, 16, 0), u32::MAX);
    device.start();
    device.stop().await;
    device.reset().await;
    assert_eq!(config_read(&mut device, Type0, 0, 0, 0x18), 0);
    config_write(&mut device, Type0, 0, 0, 0x18, 0x00050100);
    for devfn in [0, 8] {
        assert_eq!(config_read(&mut device, Type1, 1, devfn, 0x18), 0);
    }
}

// Test: Restore snapshots containing duplicate or unknown downstream switch ports.
// Expected: Malformed topology is rejected rather than silently dropping a port.
#[test]
fn switch_restore_rejects_duplicate_and_unknown_ports() {
    let mut device = switch();
    let mut state = device.save().unwrap();
    state.downstream_ports[1].devfn = state.downstream_ports[0].devfn;
    assert!(format!("{:?}", device.restore(state).unwrap_err()).contains("duplicate"));
    let mut state = device.save().unwrap();
    state.downstream_ports[1].devfn = 16;
    assert!(format!("{:?}", device.restore(state).unwrap_err()).contains("not found"));
}

// Test: Restore a missing root port and incompatible host-bridge CXL snapshots.
// Expected: Restore rejects each incompatible snapshot through its public result.
#[test]
fn root_restore_rejects_unknown_port_and_host_bridge_mode_mismatch() {
    let connection = MsiConnection::new();
    let mut plain = root(false, false, false, &connection);
    let mut state = plain.save().unwrap();
    state.ports[0].devfn = 8;
    assert!(format!("{:?}", plain.restore(state).unwrap_err()).contains("not found"));
    let mut cxl = root(true, false, false, &connection);
    let mut state = cxl.save().unwrap();
    state.cxl_component_registers = None;
    assert!(format!("{:?}", cxl.restore(state).unwrap_err()).contains("CXL mode mismatch"));
    let mut state = plain.save().unwrap();
    state.cxl_component_registers = cxl.save().unwrap().cxl_component_registers;
    assert!(format!("{:?}", plain.restore(state).unwrap_err()).contains("CXL mode mismatch"));
}

// Test: Program a CXL root-port BAR using guest config writes and access its registers.
// Expected: Header bytes are visible at the programmed address, reserved space reads
//       as zero, and malformed MMIO accesses return alignment or size errors.
#[test]
fn cxl_port_bar_mmio_obeys_guest_mapping_and_access_rules() {
    let mut rc = root(true, false, false, &MsiConnection::new());
    rc.mmio_write(0x10, &0x20000000_u32.to_le_bytes()).unwrap();
    rc.mmio_write(0x4, &2_u16.to_le_bytes()).unwrap();
    assert_eq!(read32(&mut rc, 0x20001000), 0x00110001);
    let mut reserved = [0xff; 8];
    rc.mmio_read(0x20000800, &mut reserved).unwrap();
    assert_eq!(reserved, [0; 8]);
    rc.mmio_write(0x20000800, &[0x5a; 4]).unwrap();
    assert_eq!(read32(&mut rc, 0x20000800), 0);
    rc.mmio_write(0x20000800, &[0x5a; 8]).unwrap();
    for len in [0, 3, 16] {
        assert!(matches!(
            rc.mmio_read(0x20001000, &mut vec![0; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert!(matches!(
            rc.mmio_write(0x20001000, &vec![0; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    for len in [1, 2] {
        assert!(matches!(
            rc.mmio_read(0x20001000, &mut vec![0; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert!(matches!(
            rc.mmio_write(0x20001000, &vec![0; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    assert!(matches!(
        rc.mmio_read(0x20001001, &mut [0; 4]),
        IoResult::Err(IoError::UnalignedAccess)
    ));
    assert!(matches!(
        rc.mmio_write(0x20001001, &[0; 4]),
        IoResult::Err(IoError::UnalignedAccess)
    ));
    rc.mmio_write(0x4, &0_u16.to_le_bytes()).unwrap();
    assert!(matches!(
        rc.mmio_read(0x20001000, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Access legacy PCI config ports with disabled decode, invalid sizes and reset.
// Expected: Disabled data reads return all ones, invalid accesses fail, and reset
//       clears the programmed address without changing configuration identity.
#[pal_async::async_test]
async fn legacy_config_ports_validate_access_and_reset_decode() {
    let mut rc = root(false, false, true, &MsiConnection::new());
    assert!(rc.supports_pio().is_some());
    let mut bytes = [0; 4];
    rc.io_read(0xcfc, &mut bytes).unwrap();
    assert_eq!(bytes, [0xff; 4]);
    rc.io_write(0xcfc, &[0x5a; 4]).unwrap();
    for port in [0xcf0, 0xd00] {
        assert!(matches!(
            rc.io_read(port, &mut bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            rc.io_write(port, &bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert!(matches!(
        rc.io_read(0xcf8, &mut [0; 3]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        rc.io_write(0xcf8, &[0; 3]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    rc.io_write(0xcf8, &0x80000000_u32.to_le_bytes()).unwrap();
    rc.io_read(0xcfc, &mut bytes).unwrap();
    assert_eq!(
        u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        crate::VENDOR_ID
    );
    rc.start();
    rc.stop().await;
    rc.reset().await;
    rc.io_read(0xcf8, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 4]);
    let mut no_pio = root(false, false, false, &MsiConnection::new());
    assert!(no_pio.supports_pio().is_none());
    assert!(matches!(
        no_pio.io_read(0xcf8, &mut bytes),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        no_pio.io_write(0xcf8, &bytes),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

#[derive(Default)]
struct MsiObserver(parking_lot::Mutex<Vec<(Option<u32>, u64, u32)>>);

impl SignalMsi for MsiObserver {
    fn signal_msi(&self, devid: Option<u32>, address: u64, data: u32) {
        self.0.lock().push((devid, address, data));
    }
}

// Test: Enable hotplug interrupts in PCI capabilities and add/remove an endpoint.
// Expected: Presence status follows attachment, MSI reaches the configured address,
//       and occupied, empty, missing and non-hotplug ports reject invalid operations.
#[test]
fn hotplug_changes_guest_presence_and_delivers_programmed_msi() {
    let connection = MsiConnection::new();
    let observer = Arc::new(MsiObserver::default());
    connection.connect(observer.clone());
    let mut rc = root(false, true, false, &connection);
    let express = capability(&mut rc, 0x10);
    let msi = capability(&mut rc, 5);
    let control = (read32(&mut rc, msi) >> 16) as u16;
    rc.mmio_write(msi + 4, &0xfee00000_u32.to_le_bytes())
        .unwrap();
    let data_offset = if control & 0x80 != 0 {
        rc.mmio_write(msi + 8, &[0; 4]).unwrap();
        12
    } else {
        8
    };
    rc.mmio_write(msi + data_offset, &0x45_u16.to_le_bytes())
        .unwrap();
    rc.mmio_write(msi + 2, &(control | 1).to_le_bytes())
        .unwrap();
    rc.mmio_write(express + 0x18, &0x20_u16.to_le_bytes())
        .unwrap();
    assert!(rc.hotplug_remove_device("port").is_err());
    rc.hotplug_add_device("port", "endpoint", Box::new(TestPciDevice))
        .unwrap();
    assert_ne!(read32(&mut rc, express + 0x18) & (0x40 << 16), 0);
    assert!(
        rc.hotplug_add_device("port", "duplicate", Box::new(TestPciDevice))
            .is_err()
    );
    rc.hotplug_remove_device("port").unwrap();
    assert_eq!(read32(&mut rc, express + 0x18) & (0x40 << 16), 0);
    let signals = observer.0.lock();
    assert_eq!(
        &*signals,
        &[(Some(0), 0xfee00000, 0x45), (Some(0), 0xfee00000, 0x45)]
    );
    drop(signals);
    assert!(
        rc.hotplug_add_device("missing", "endpoint", Box::new(TestPciDevice))
            .is_err()
    );
    assert!(rc.hotplug_remove_device("missing").is_err());
    let mut fixed = root(false, false, false, &connection);
    assert!(
        fixed
            .hotplug_add_device("port", "endpoint", Box::new(TestPciDevice))
            .is_err()
    );
    assert!(fixed.hotplug_remove_device("port").is_err());
}

// Test: Restore snapshots into root ports with incompatible CXL backing.
// Expected: Both directions of CXL topology mismatch are rejected.
#[test]
fn restore_rejects_mismatched_cxl_port_topology() {
    let connection = MsiConnection::new();
    let mut with_cxl = root(true, false, false, &connection);
    let mut without_cxl = root(false, false, false, &connection);
    assert!(without_cxl.restore(with_cxl.save().unwrap()).is_err());
    assert!(with_cxl.restore(without_cxl.save().unwrap()).is_err());
}

// Test: Translate MSI identities through the ITS wrapper.
// Expected: The segment replaces high identity bits, address/data are unchanged,
//       and a caller without an identity emits no interrupt.
#[test]
fn its_signal_wrapper_preserves_interrupt_payload() {
    let observer = Arc::new(MsiObserver::default());
    let its = crate::its::ItsSignalMsi::new(observer.clone(), 0x1234);
    its.signal_msi(None, 1, 2);
    its.signal_msi(Some(0xdead5678), 0xfee00000, 0x45);
    its.signal_msi(Some(0xffffffff), 0x12345678abcdef00, 0x89abcdef);
    assert_eq!(
        &*observer.0.lock(),
        &[
            (Some(0x12345678), 0xfee00000, 0x45),
            (Some(0x1234ffff), 0x12345678abcdef00, 0x89abcdef)
        ]
    );
}

struct IrqObserver {
    calls: Arc<parking_lot::Mutex<Vec<Option<(u64, u32, Option<u32>)>>>>,
    event: Arc<pal_event::Event>,
}

impl vmcore::irqfd::IrqFd for IrqObserver {
    fn new_irqfd_route(&self) -> anyhow::Result<Box<dyn vmcore::irqfd::IrqFdRoute>> {
        Ok(Box::new(Self {
            calls: self.calls.clone(),
            event: self.event.clone(),
        }))
    }
}

impl vmcore::irqfd::IrqFdRoute for IrqObserver {
    fn event(&self) -> &pal_event::Event {
        &self.event
    }
    fn enable(&self, address: u64, data: u32, devid: Option<u32>) {
        self.calls.lock().push(Some((address, data, devid)));
    }
    fn disable(&self) {
        self.calls.lock().push(None);
    }
}

// Test: Enable, signal and disable an ITS-aware irqfd route.
// Expected: The backend sees the translated device ID, the same event remains
//       usable, and disable is forwarded without a fabricated enable.
#[test]
fn its_irqfd_wrapper_forwards_route_operations() {
    use vmcore::irqfd::IrqFd;
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let event = Arc::new(pal_event::Event::new());
    let its = crate::its::ItsIrqFd::new(
        Arc::new(IrqObserver {
            calls: calls.clone(),
            event: event.clone(),
        }),
        7,
    );
    let route = its.new_irqfd_route().unwrap();
    route.enable(1, 2, None);
    route.enable(0xfee00000, 0x40, Some(0x12345678));
    route.event().signal();
    assert!(event.try_wait());
    route.disable();
    assert_eq!(
        &*calls.lock(),
        &[Some((0xfee00000, 0x40, Some(0x75678))), None]
    );
}

// Test: Acknowledge hotplug change events through guest Slot Status writes.
// Expected: Zero writes retain events, write-one clears only event bits, and
//       presence remains read-only across removal and reinsertion.
#[test]
fn hotplug_status_acknowledgement_preserves_live_presence() {
    let mut rc = root(false, true, false, &MsiConnection::new());
    let express = capability(&mut rc, 0x10);
    let status_address = express + 0x1a;
    let presence = 0x40_u16;
    let changed = 0x08_u16;
    let status = |rc: &mut GenericPcieRootComplex| {
        (read32(rc, express + 0x18) >> 16) as u16 & (presence | changed)
    };

    assert_eq!(status(&mut rc), 0);
    rc.hotplug_add_device("port", "first", Box::new(TestPciDevice))
        .unwrap();
    assert_eq!(status(&mut rc), presence | changed);
    rc.mmio_write(status_address, &0_u16.to_le_bytes()).unwrap();
    assert_eq!(status(&mut rc), presence | changed);
    rc.mmio_write(status_address, &presence.to_le_bytes())
        .unwrap();
    assert_eq!(status(&mut rc), presence | changed);
    rc.mmio_write(status_address, &changed.to_le_bytes())
        .unwrap();
    assert_eq!(status(&mut rc), presence);

    rc.hotplug_remove_device("port").unwrap();
    assert_eq!(status(&mut rc), changed);
    rc.mmio_write(status_address, &(presence | changed).to_le_bytes())
        .unwrap();
    assert_eq!(status(&mut rc), 0);
    rc.hotplug_add_device("port", "replacement", Box::new(TestPciDevice))
        .unwrap();
    assert_eq!(status(&mut rc), presence | changed);
}

struct RoutedEndpoint {
    bus: u8,
    devfn: u8,
    inner: Box<dyn pci_bus::GenericPciBusDevice>,
}

impl pci_bus::GenericPciBusDevice for RoutedEndpoint {
    fn pci_cfg_read(&mut self, offset: u16, value: ByteEnabledDwordRead<'_>) -> Option<IoResult> {
        self.inner.pci_cfg_read(offset, value)
    }

    fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> Option<IoResult> {
        self.inner.pci_cfg_write(offset, value)
    }

    fn pci_cfg_read_with_routing(
        &mut self,
        kind: PciConfigAccessType,
        address: PciConfigAddress,
        mut value: ByteEnabledDwordRead<'_>,
    ) -> Option<IoResult> {
        assert_eq!(kind, PciConfigAccessType::Type0);
        assert_eq!(address.bus, self.bus);
        if address.devfn == self.devfn {
            self.pci_cfg_read(address.byte_offset(), value)
        } else {
            value.set(u32::MAX);
            Some(IoResult::Ok)
        }
    }

    fn pci_cfg_write_with_routing(
        &mut self,
        kind: PciConfigAccessType,
        address: PciConfigAddress,
        value: ByteEnabledDwordWrite,
    ) -> Option<IoResult> {
        assert_eq!(kind, PciConfigAccessType::Type0);
        assert_eq!(address.bus, self.bus);
        if address.devfn == self.devfn {
            self.pci_cfg_write(address.byte_offset(), value)
        } else {
            Some(IoResult::Ok)
        }
    }
}

// Test: Access RCiEP config lanes on bus 255 at device 31 and its last dword.
// Expected: Writes merge only enabled bytes; adjacent registers/functions remain
//       intact, malformed lanes fail, and the ECAM aperture rejects outside access.
#[test]
fn ecam_byte_lanes_and_terminal_offsets_preserve_neighbors() {
    let mut mmio = MmioRegistration;
    let mut pio = TestPciePioRegistration;
    let base = 0x80000000;
    let mut rc = GenericPcieRootComplex::builder(
        &mut mmio,
        &mut pio,
        255..=255,
        MemoryRange::new(base..base + 0x100000),
    )
    .build()
    .unwrap();
    let registers = Arc::new(parking_lot::Mutex::new([
        0x11223344, 0x55667788, 0x99aabbcc,
    ]));
    let reads = registers.clone();
    let writes = registers.clone();
    let index = |offset| match offset {
        0x40 => 0,
        0x44 => 1,
        0xffc => 2,
        _ => panic!("unexpected endpoint offset {offset:#x}"),
    };
    rc.add_rciep(
        0xf8,
        "last-device",
        Box::new(RoutedEndpoint {
            bus: 255,
            devfn: 0xf8,
            inner: Box::new(crate::test_helpers::TestPcieEndpoint::new(
                move |offset, mut value| {
                    value.set(reads.lock()[index(offset)]);
                    Some(IoResult::Ok)
                },
                move |offset, value| {
                    value.merge_into(&mut writes.lock()[index(offset)]);
                    Some(IoResult::Ok)
                },
            )),
        }),
    )
    .unwrap();
    let function = base + 0xf8000;
    rc.mmio_write(function + 0x41, &[0xa5]).unwrap();
    assert_eq!(read32(&mut rc, function + 0x40), 0x1122a544);
    rc.mmio_write(function + 0x42, &[0xc3, 0xd4]).unwrap();
    assert_eq!(read32(&mut rc, function + 0x40), 0xd4c3a544);
    let mut bytes = [0; 2];
    rc.mmio_read(function + 0x42, &mut bytes).unwrap();
    assert_eq!(bytes, [0xc3, 0xd4]);
    for (lane, expected) in [0x44, 0xa5, 0xc3, 0xd4].into_iter().enumerate() {
        let mut byte = [0];
        rc.mmio_read(function + 0x40 + lane as u64, &mut byte)
            .unwrap();
        assert_eq!(byte, [expected]);
    }
    rc.mmio_write(function + 0xfff, &[0x7e]).unwrap();
    assert_eq!(read32(&mut rc, function + 0xffc), 0x7eaabbcc);
    assert_eq!(read32(&mut rc, function + 0x44), 0x55667788);
    assert_eq!(read32(&mut rc, function + 0x1000), u32::MAX);
    rc.mmio_write(function + 0x1000, &[0xff; 4]).unwrap();
    assert_eq!(read32(&mut rc, base + 0xffffc), u32::MAX);
    for (offset, len) in [(0x41, 2), (0x42, 4), (0xfff, 2)] {
        assert!(matches!(
            rc.mmio_read(function + offset, &mut vec![0; len]),
            IoResult::Err(IoError::UnalignedAccess)
        ));
        assert!(matches!(
            rc.mmio_write(function + offset, &vec![0xff; len]),
            IoResult::Err(IoError::UnalignedAccess)
        ));
    }
    for len in [0, 3, 8] {
        assert!(matches!(
            rc.mmio_read(function + 0x40, &mut vec![0; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert!(matches!(
            rc.mmio_write(function + 0x40, &vec![0xff; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    for address in [base - 4, base + 0x100000] {
        assert!(matches!(
            rc.mmio_read(address, &mut [0; 4]),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            rc.mmio_write(address, &[0xff; 4]),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert_eq!(*registers.lock(), [0xd4c3a544, 0x55667788, 0x7eaabbcc]);
}

// Test: Restore reversed sparse-port switch snapshots into a fresh topology.
// Expected: Bus numbers and commands follow devfn identity, not vector order,
//       and fresh endpoint links still answer on their independently restored buses.
#[test]
fn switch_fresh_restore_matches_sparse_devfns_not_snapshot_order() {
    use PciConfigAccessType::{Type0, Type1};
    let mut original = switch();
    config_write(&mut original, Type0, 0, 0, 0x18, 0x00050100);
    config_write(&mut original, Type0, 0, 0, 0x4, 6);
    for (devfn, buses, command) in [(0, 0x00030201, 2), (8, 0x00050401, 4)] {
        config_write(&mut original, Type1, 1, devfn, 0x18, buses);
        config_write(&mut original, Type1, 1, devfn, 0x4, command);
    }
    let mut saved = original.save().unwrap();
    saved.downstream_ports.reverse();
    let mut restored = switch();
    for (devfn, payload) in [(0, 0x1234abcd), (8, 0x8765dcba)] {
        restored
            .add_pcie_device(
                devfn,
                "fresh-endpoint",
                Box::new(crate::test_helpers::TestPcieEndpoint::new(
                    move |offset, mut value| {
                        assert_eq!(offset, 0);
                        value.set(payload);
                        Some(IoResult::Ok)
                    },
                    |_, _| Some(IoResult::Ok),
                )),
            )
            .unwrap();
    }
    assert_eq!(config_read(&mut restored, Type0, 0, 0, 0x18), 0);
    restored.restore(saved).unwrap();
    assert_eq!(config_read(&mut restored, Type0, 0, 0, 0x18), 0x00050100);
    assert_eq!(config_read(&mut restored, Type0, 0, 0, 0x4) & 0xffff, 6);
    for (devfn, buses, command) in [(0, 0x00030201, 2), (8, 0x00050401, 4)] {
        assert_eq!(config_read(&mut restored, Type1, 1, devfn, 0x18), buses);
        assert_eq!(
            config_read(&mut restored, Type1, 1, devfn, 0x4) & 0xffff,
            command
        );
    }
    assert_eq!(config_read(&mut restored, Type1, 2, 0, 0), 0x1234abcd);
    assert_eq!(config_read(&mut restored, Type1, 4, 0, 0), 0x8765dcba);
    config_write(&mut restored, Type1, 1, 0, 0x18, 0x00030301);
    assert_eq!(config_read(&mut restored, Type1, 2, 0, 0), u32::MAX);
    assert_eq!(config_read(&mut restored, Type1, 3, 0, 0), 0x1234abcd);
    assert_eq!(config_read(&mut restored, Type1, 4, 0, 0), 0x8765dcba);
    assert_eq!(config_read(&mut restored, Type1, 1, 8, 0x18), 0x00050401);
}

struct OwnedEndpoint {
    payload: u32,
    drops: Arc<parking_lot::Mutex<Vec<u32>>>,
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        self.drops.lock().push(self.payload);
    }
}

impl pci_bus::GenericPciBusDevice for OwnedEndpoint {
    fn pci_cfg_read(
        &mut self,
        offset: u16,
        mut value: ByteEnabledDwordRead<'_>,
    ) -> Option<IoResult> {
        assert_eq!(offset, 0);
        value.set(self.payload);
        Some(IoResult::Ok)
    }

    fn pci_cfg_write(&mut self, _offset: u16, _value: ByteEnabledDwordWrite) -> Option<IoResult> {
        Some(IoResult::Ok)
    }
}

// Test: Reject hot-add to occupied/missing ports, then remove and replace one peer.
// Expected: Rejected endpoints are released once, existing peers keep full payloads,
//       and removing/replacing one port neither detaches nor aliases the other.
#[test]
fn hotplug_rejection_and_replacement_preserve_peer_ownership() {
    let mut mmio = MmioRegistration;
    let mut pio = TestPciePioRegistration;
    let mut rc =
        GenericPcieRootComplex::builder(&mut mmio, &mut pio, 0..=2, MemoryRange::new(0..0x300000))
            .root_ports(
                [("left", 0), ("right", 8)]
                    .into_iter()
                    .map(|(name, devfn)| GenericPciePortDefinition {
                        name: name.into(),
                        devfn: Some(devfn),
                        hotplug: true,
                        settings: Default::default(),
                    })
                    .collect(),
                &pci_core::msi::MsiTarget::disconnected(),
            )
            .build()
            .unwrap();
    rc.mmio_write(0x18, &0x00010100_u32.to_le_bytes()).unwrap();
    rc.mmio_write(0x8018, &0x00020200_u32.to_le_bytes())
        .unwrap();
    let drops = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let endpoint = |payload| {
        Box::new(OwnedEndpoint {
            payload,
            drops: drops.clone(),
        })
    };
    rc.hotplug_add_device("left", "first", endpoint(0x1234abcd))
        .unwrap();
    rc.hotplug_add_device("right", "peer", endpoint(0x8765dcba))
        .unwrap();
    assert!(
        rc.hotplug_add_device("left", "duplicate", endpoint(0xaabbccdd))
            .is_err()
    );
    assert!(
        rc.hotplug_add_device("missing", "absent", endpoint(0xeeff0011))
            .is_err()
    );
    assert_eq!(&*drops.lock(), &[0xaabbccdd, 0xeeff0011]);
    assert_eq!(read32(&mut rc, 0x100000), 0x1234abcd);
    assert_eq!(read32(&mut rc, 0x200000), 0x8765dcba);
    rc.hotplug_remove_device("left").unwrap();
    assert_eq!(read32(&mut rc, 0x100000), u32::MAX);
    assert_eq!(read32(&mut rc, 0x200000), 0x8765dcba);
    assert!(rc.hotplug_remove_device("left").is_err());
    rc.hotplug_add_device("left", "replacement", endpoint(0x55667788))
        .unwrap();
    assert_eq!(read32(&mut rc, 0x100000), 0x55667788);
    assert_eq!(read32(&mut rc, 0x200000), 0x8765dcba);
    assert_eq!(&*drops.lock(), &[0xaabbccdd, 0xeeff0011, 0x1234abcd]);
    drop(rc);
    let mut released = drops.lock().clone();
    released.sort_unstable();
    assert_eq!(
        released,
        [0x1234abcd, 0x55667788, 0x8765dcba, 0xaabbccdd, 0xeeff0011]
    );
}
