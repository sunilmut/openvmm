// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{GenericPciBus, GenericPciBusDevice};
use chipset_device::ChipsetDevice;
use chipset_device::io::deferred::{DeferredRead, DeferredWrite, defer_read, defer_write};
use chipset_device::io::{IoError, IoResult};
use chipset_device::pci::{
    ByteEnabledDwordRead, ByteEnabledDwordWrite, PciConfigAccessType, PciConfigAddress,
    PciConfigByteEnable,
};
use chipset_device::pio::{ControlPortIoIntercept, PortIoIntercept, RegisterPortIoIntercept};
use futures::executor::block_on;
use parking_lot::Mutex;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::SaveRestore;

const ADDR: u16 = 0xcf8;
const DATA: u16 = 0xcfc;

struct Bus;
struct Region {
    name: String,
    address: Option<u16>,
    length: u16,
}

impl RegisterPortIoIntercept for Bus {
    fn new_io_region(&mut self, name: &str, length: u16) -> Box<dyn ControlPortIoIntercept> {
        Box::new(Region {
            name: name.into(),
            address: None,
            length,
        })
    }
}

impl ControlPortIoIntercept for Region {
    fn region_name(&self) -> &str {
        &self.name
    }
    fn map(&mut self, address: u16) {
        self.address = Some(address);
    }
    fn unmap(&mut self) {
        self.address = None;
    }
    fn addr(&self) -> Option<u16> {
        self.address
    }
    fn len(&self) -> u16 {
        self.length
    }
    fn offset_of(&self, address: u16) -> Option<u16> {
        address
            .checked_sub(self.address?)
            .filter(|offset| *offset < self.length)
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Online,
    Offline,
    Error(IoError),
    Deferred,
}

#[derive(Debug)]
struct Backing {
    value: u32,
    mode: Mode,
    reads: Vec<(u16, PciConfigByteEnable)>,
    writes: Vec<(u16, ByteEnabledDwordWrite)>,
    read: Option<DeferredRead>,
    write: Option<DeferredWrite>,
}

#[derive(Debug)]
struct Endpoint(Arc<Mutex<Backing>>);

impl GenericPciBusDevice for Endpoint {
    fn pci_cfg_read(
        &mut self,
        offset: u16,
        mut value: ByteEnabledDwordRead<'_>,
    ) -> Option<IoResult> {
        let mut backing = self.0.lock();
        backing.reads.push((offset, value.byte_enable()));
        Some(match backing.mode {
            Mode::Online => {
                value.set(backing.value);
                IoResult::Ok
            }
            Mode::Offline => return None,
            Mode::Error(error) => IoResult::Err(error),
            Mode::Deferred => {
                let (read, token) = defer_read();
                backing.read = Some(read);
                IoResult::Defer(token)
            }
        })
    }

    fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> Option<IoResult> {
        let mut backing = self.0.lock();
        backing.writes.push((offset, value));
        Some(match backing.mode {
            Mode::Online => {
                backing.value = value.merge(backing.value);
                IoResult::Ok
            }
            Mode::Offline => return None,
            Mode::Error(error) => IoResult::Err(error),
            Mode::Deferred => {
                let (write, token) = defer_write();
                backing.write = Some(write);
                IoResult::Defer(token)
            }
        })
    }
}

fn endpoint(value: u32) -> (Endpoint, Arc<Mutex<Backing>>) {
    let backing = Arc::new(Mutex::new(Backing {
        value,
        mode: Mode::Online,
        reads: Vec::new(),
        writes: Vec::new(),
        read: None,
        write: None,
    }));
    (Endpoint(backing.clone()), backing)
}

fn address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset)
}

fn read<const N: usize>(bus: &mut GenericPciBus, port: u16) -> [u8; N] {
    let mut bytes = [0xa5; N];
    bus.supports_pio()
        .unwrap()
        .io_read(port, &mut bytes)
        .unwrap();
    bytes
}

fn write(bus: &mut GenericPciBus, port: u16, bytes: &[u8]) {
    bus.supports_pio().unwrap().io_write(port, bytes).unwrap();
}

fn select(bus: &mut GenericPciBus, value: u32) {
    write(bus, ADDR, &value.to_le_bytes());
}

// Test: Program the configuration address through full, byte and word writes.
// Expected: Reserved and alignment bits read as zero; partial writes preserve
//       other lanes and reset clears the address without removing devices.
#[test]
fn address_register_masks_reserved_bits_and_merges_partial_writes() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    bus.start();
    assert_eq!(read::<4>(&mut bus, ADDR), [0; 4]);
    select(&mut bus, u32::MAX);
    assert_eq!(u32::from_le_bytes(read(&mut bus, ADDR)), 0x80ff_fffc);
    write(&mut bus, ADDR, &[0x27]);
    write(&mut bus, ADDR + 2, &[0x12, 0xff]);
    assert_eq!(u32::from_le_bytes(read(&mut bus, ADDR)), 0x8012_ff24);
    assert_eq!(read::<1>(&mut bus, ADDR + 1), [0xff]);
    assert_eq!(read::<2>(&mut bus, ADDR + 2), [0x12, 0x80]);
    block_on(bus.reset());
    assert_eq!(read::<4>(&mut bus, ADDR), [0; 4]);
    block_on(bus.stop());
}

// Test: Route full and partial accesses to a device at a nonzero BDF.
// Expected: The backend sees aligned offsets and exact byte enables; changing
//       another function, slot or bus cannot reach that device.
#[test]
fn configuration_accesses_route_bdf_offset_and_byte_lanes() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, backing) = endpoint(0x4433_2211);
    bus.add_pci_device(2, 3, 4, "endpoint", device).unwrap();
    select(&mut bus, address(2, 3, 4, 0x24));
    assert_eq!(read::<4>(&mut bus, DATA), 0x4433_2211u32.to_le_bytes());
    assert_eq!(read::<1>(&mut bus, DATA + 1), [0x22]);
    assert_eq!(read::<2>(&mut bus, DATA + 2), [0x33, 0x44]);
    assert_eq!(
        backing.lock().reads,
        [
            (0x24, PciConfigByteEnable::FULL),
            (0x24, PciConfigByteEnable::BYTE1),
            (0x24, PciConfigByteEnable::HIGH_WORD)
        ]
    );
    write(&mut bus, DATA + 1, &[0xaa]);
    write(&mut bus, DATA + 2, &[0xbb, 0xcc]);
    assert_eq!(read::<4>(&mut bus, DATA), [0x11, 0xaa, 0xbb, 0xcc]);
    let writes = backing.lock().writes.clone();
    assert_eq!(
        writes[0],
        (
            0x24,
            ByteEnabledDwordWrite::new(0xaa00, PciConfigByteEnable::BYTE1)
        )
    );
    assert_eq!(
        writes[1],
        (
            0x24,
            ByteEnabledDwordWrite::new(0xccbb_0000, PciConfigByteEnable::HIGH_WORD)
        )
    );
    for (target_bus, slot, function) in [(1, 3, 4), (2, 2, 4), (2, 3, 5)] {
        select(&mut bus, address(target_bus, slot, function, 0x24));
        assert_eq!(read::<4>(&mut bus, DATA), [0xff; 4]);
        write(&mut bus, DATA, &[0; 4]);
    }
    assert_eq!(backing.lock().writes, writes);
}

// Test: Access configuration data while decoding is disabled or no device exists.
// Expected: Reads return all ones and writes do not reach registered endpoints.
#[test]
fn disabled_and_absent_configuration_targets_are_open_bus() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, backing) = endpoint(7);
    bus.add_pci_device(0, 0, 0, "present", device).unwrap();
    assert_eq!(read::<4>(&mut bus, DATA), [0xff; 4]);
    write(&mut bus, DATA, &[0; 4]);
    assert!(backing.lock().reads.is_empty());
    assert!(backing.lock().writes.is_empty());
    select(&mut bus, address(0xff, 31, 7, 0xfc));
    assert_eq!(read::<4>(&mut bus, DATA), [0xff; 4]);
    write(&mut bus, DATA, &[0; 4]);
}

// Test: Register a second endpoint in an occupied slot and reuse its error value.
// Expected: The original endpoint stays reachable and the rejected endpoint is
//       returned intact for registration in another slot.
#[test]
fn duplicate_slots_preserve_both_endpoint_ownerships() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (first, _) = endpoint(11);
    let (second, _) = endpoint(22);
    bus.add_pci_device(0, 1, 0, "first", first).unwrap();
    let error = bus.add_pci_device(0, 1, 0, "second", second).unwrap_err();
    assert_eq!(&*error.existing_device_name, "first");
    assert!(error.to_string().contains("first"));
    bus.add_pci_device(0, 2, 0, "second", error.device).unwrap();
    for (slot, expected) in [(1, 11u32), (2, 22u32)] {
        select(&mut bus, address(0, slot, 0, 0));
        assert_eq!(read::<4>(&mut bus, DATA), expected.to_le_bytes());
    }
}

// Test: Make an endpoint disappear and later return, without unregistering it.
// Expected: Offline reads are all ones and writes are ignored; accesses resume
//       normally when the backend responds again.
#[test]
fn disappearing_endpoints_do_not_break_later_accesses() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, backing) = endpoint(0x1234);
    bus.add_pci_device(0, 0, 0, "endpoint", device).unwrap();
    select(&mut bus, address(0, 0, 0, 0x40));
    backing.lock().mode = Mode::Offline;
    assert_eq!(read::<4>(&mut bus, DATA), [0xff; 4]);
    write(&mut bus, DATA, &[0; 4]);
    backing.lock().mode = Mode::Online;
    assert_eq!(read::<4>(&mut bus, DATA), 0x1234u32.to_le_bytes());
}

// Test: Return each supported configuration error from the downstream endpoint.
// Expected: The bus's documented synchronous error policy returns zero-filled
//       reads and completes ignored writes without losing the selected address.
#[test]
fn synchronous_backend_errors_are_converted_to_bus_completion() {
    for error in [
        IoError::InvalidRegister,
        IoError::InvalidAccessSize,
        IoError::UnalignedAccess,
        IoError::NoResponse,
    ] {
        let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
        let (device, backing) = endpoint(0x1234);
        bus.add_pci_device(0, 0, 0, "endpoint", device).unwrap();
        select(&mut bus, address(0, 0, 0, 0x40));
        backing.lock().mode = Mode::Error(error);
        assert_eq!(read::<4>(&mut bus, DATA), [0; 4]);
        write(&mut bus, DATA, &[0; 4]);
        backing.lock().mode = Mode::Online;
        assert_eq!(read::<4>(&mut bus, DATA), 0x1234u32.to_le_bytes());
    }
}

// Test: Issue unsupported widths, unaligned accesses and unmapped port accesses.
// Expected: Invalid widths and alignments fail before reaching the endpoint;
//       unmapped reads fail and unmapped writes follow the ignored-write policy.
#[test]
fn invalid_port_accesses_are_rejected_without_backend_calls() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, backing) = endpoint(0);
    bus.add_pci_device(0, 0, 0, "endpoint", device).unwrap();
    select(&mut bus, address(0, 0, 0, 0));
    for (port, size) in [
        (DATA, 0),
        (DATA, 3),
        (DATA, 8),
        (DATA + 1, 2),
        (DATA + 2, 4),
    ] {
        let mut bytes = vec![0xa5; size];
        let expected_unaligned = size == 2 || size == 4;
        for result in [bus.io_read(port, &mut bytes), bus.io_write(port, &bytes)] {
            assert!(matches!(
                (expected_unaligned, result),
                (true, IoResult::Err(IoError::UnalignedAccess))
                    | (false, IoResult::Err(IoError::InvalidAccessSize))
            ));
        }
        assert_eq!(bytes, vec![0xa5; size]);
    }
    assert!(matches!(
        bus.io_read(ADDR - 4, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    bus.io_write(ADDR - 4, &[0; 4]).unwrap();
    assert!(backing.lock().reads.is_empty());
    assert!(backing.lock().writes.is_empty());
}

// Test: Defer a partial read and a write at an endpoint, completing them later.
// Expected: Guest tokens remain pending until bus polling forwards completion,
//       and partial-read completion selects only the requested byte lanes.
#[test]
fn deferred_reads_and_writes_complete_through_bus_polling() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, backing) = endpoint(0);
    bus.add_pci_device(0, 0, 0, "endpoint", device).unwrap();
    select(&mut bus, address(0, 0, 0, 0x40));
    backing.lock().mode = Mode::Deferred;
    let mut context = Context::from_waker(Waker::noop());
    let mut bytes = [0; 2];
    let IoResult::Defer(mut read_token) = bus.io_read(DATA + 2, &mut bytes) else {
        panic!("read was not deferred")
    };
    let IoResult::Defer(mut write_token) = bus.io_write(DATA, &[1, 2, 3, 4]) else {
        panic!("write was not deferred")
    };
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(read_token.poll_read(&mut context, &mut bytes).is_pending());
    assert!(write_token.poll_write(&mut context).is_pending());
    backing
        .lock()
        .read
        .take()
        .unwrap()
        .complete(&0x4433_2211u32.to_le_bytes());
    backing.lock().write.take().unwrap().complete();
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(matches!(
        read_token.poll_read(&mut context, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [0x33, 0x44]);
    assert!(matches!(
        write_token.poll_write(&mut context),
        Poll::Ready(Ok(()))
    ));
}

// Test: Restore a saved configuration address and malformed address payloads.
// Expected: A valid restore selects the same live device; reserved bits and
//       unaligned offsets are rejected before a later valid restore succeeds.
#[test]
fn snapshots_preserve_selection_and_reject_invalid_addresses() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (device, _) = endpoint(0x1234);
    bus.add_pci_device(3, 4, 5, "endpoint", device).unwrap();
    let selected = address(3, 4, 5, 0xfc);
    select(&mut bus, selected);
    let valid = bus.save().unwrap();
    block_on(bus.reset());
    bus.restore(valid).unwrap();
    assert_eq!(read::<4>(&mut bus, DATA), 0x1234u32.to_le_bytes());
    for bad in [selected | 0x0100_0000, selected | 3] {
        let valid = bus.save().unwrap();
        let mut snapshot = bus.save().unwrap();
        snapshot.pio_addr_reg = bad;
        assert!(bus.restore(snapshot).is_err());
        bus.restore(valid).unwrap();
    }
    assert_eq!(read::<4>(&mut bus, DATA), 0x1234u32.to_le_bytes());
}

// Test: Use a simple endpoint's default routing methods for local and forwarded
//       accesses, including a nonzero function and Type 1 configuration cycle.
// Expected: Only local Type 0 function-zero requests access endpoint storage;
//       other reads report no device and other writes are ignored.
#[test]
fn default_endpoint_routing_rejects_forwarded_and_other_function_accesses() {
    let (mut device, backing) = endpoint(0x1234);
    for (access, devfn, present) in [
        (PciConfigAccessType::Type0, 0, true),
        (PciConfigAccessType::Type0, 1, false),
        (PciConfigAccessType::Type1, 0, false),
    ] {
        let target = PciConfigAddress::new(0, devfn, 4).unwrap();
        let mut value = 0;
        device
            .pci_cfg_read_with_routing(
                access,
                target,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
            )
            .unwrap()
            .unwrap();
        assert_eq!(value, if present { 0x1234 } else { u32::MAX });
        device
            .pci_cfg_write_with_routing(
                access,
                target,
                ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234),
            )
            .unwrap()
            .unwrap();
    }
    assert_eq!(backing.lock().reads, [(16, PciConfigByteEnable::FULL)]);
    assert_eq!(backing.lock().writes.len(), 1);
}

// Test: Change and disable the address latch while a partial read is deferred.
// Expected: Completion retains its original device and byte lanes; accesses
//       to the second device stay independent and the latch is not restored.
#[test]
fn deferred_read_keeps_its_target_when_the_address_latch_changes() {
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (first, first_backing) = endpoint(0x1111_2222);
    let (second, _) = endpoint(0x4433_2211);
    bus.add_pci_device(0, 1, 0, "first", first).unwrap();
    bus.add_pci_device(0, 2, 0, "second", second).unwrap();
    select(&mut bus, address(0, 1, 0, 0x40));
    first_backing.lock().mode = Mode::Deferred;
    let mut bytes = [0xa5; 2];
    let IoResult::Defer(mut token) = bus.io_read(DATA + 2, &mut bytes) else {
        panic!("first device read was not deferred")
    };

    select(&mut bus, address(0, 2, 0, 0x24));
    assert_eq!(read::<4>(&mut bus, DATA), 0x4433_2211u32.to_le_bytes());
    write(&mut bus, DATA + 1, &[0xaa]);
    select(&mut bus, 0);
    let mut context = Context::from_waker(Waker::noop());
    assert!(token.poll_read(&mut context, &mut bytes).is_pending());
    first_backing
        .lock()
        .read
        .take()
        .unwrap()
        .complete(&0x8877_6655u32.to_le_bytes());
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(matches!(
        token.poll_read(&mut context, &mut bytes),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(bytes, [0x77, 0x88]);
    assert_eq!(read::<4>(&mut bus, ADDR), [0; 4]);
    assert_eq!(read::<4>(&mut bus, DATA), [0xff; 4]);
    select(&mut bus, address(0, 2, 0, 0x24));
    assert_eq!(read::<4>(&mut bus, DATA), [0x11, 0xaa, 0x33, 0x44]);
    first_backing.lock().mode = Mode::Online;
    select(&mut bus, address(0, 1, 0, 0x40));
    assert_eq!(read::<4>(&mut bus, DATA), 0x1111_2222u32.to_le_bytes());
}
