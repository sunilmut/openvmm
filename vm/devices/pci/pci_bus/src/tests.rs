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
use test_with_tracing::test;
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
//       other lanes and reset clears the address.
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
    for (port, size, expected) in [
        (DATA, 0, IoError::InvalidAccessSize),
        (DATA, 3, IoError::InvalidAccessSize),
        (DATA, 8, IoError::InvalidAccessSize),
        (DATA + 1, 2, IoError::UnalignedAccess),
        (DATA + 2, 4, IoError::UnalignedAccess),
        (DATA + 3, 2, IoError::UnalignedAccess),
        (ADDR + 3, 2, IoError::UnalignedAccess),
        (ADDR + 3, 4, IoError::UnalignedAccess),
    ] {
        let mut bytes = vec![0xa5; size];
        for result in [bus.io_read(port, &mut bytes), bus.io_write(port, &bytes)] {
            let IoResult::Err(error) = result else {
                panic!("invalid access was not rejected");
            };
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
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
    assert_eq!(read::<4>(&mut bus, ADDR), [0, 0, 0, 0x80]);
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
    let (mut device, backing) = endpoint(0x4433_2211);
    let local = PciConfigAddress::new(7, 0, 0x3ff).unwrap();
    let mut value = 0xa5a5_a5a5;
    device
        .pci_cfg_read_with_routing(
            PciConfigAccessType::Type0,
            local,
            ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::HIGH_WORD),
        )
        .unwrap()
        .unwrap();
    assert_eq!(value, 0x4433_a5a5);
    device
        .pci_cfg_write_with_routing(
            PciConfigAccessType::Type0,
            local,
            ByteEnabledDwordWrite::new(0xbbaa, PciConfigByteEnable::LOW_WORD),
        )
        .unwrap()
        .unwrap();
    for (access, devfn) in [
        (PciConfigAccessType::Type0, 1),
        (PciConfigAccessType::Type0, 0xf8),
        (PciConfigAccessType::Type1, 0),
        (PciConfigAccessType::Type1, 7),
    ] {
        let target = PciConfigAddress::new(7, devfn, 0x3ff).unwrap();
        let mut value = 0xa5a5_a5a5;
        device
            .pci_cfg_read_with_routing(
                access,
                target,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
            )
            .unwrap()
            .unwrap();
        assert_eq!(value, u32::MAX);
        device
            .pci_cfg_write_with_routing(
                access,
                target,
                ByteEnabledDwordWrite::with_all_bytes_enabled(0),
            )
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        backing.lock().reads,
        [(0xffc, PciConfigByteEnable::HIGH_WORD)]
    );
    assert_eq!(
        backing.lock().writes,
        [(
            0xffc,
            ByteEnabledDwordWrite::new(0xbbaa, PciConfigByteEnable::LOW_WORD)
        )]
    );
    let mut value = 0;
    device
        .pci_cfg_read_with_routing(
            PciConfigAccessType::Type0,
            local,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
        )
        .unwrap()
        .unwrap();
    assert_eq!(value, 0x4433_bbaa);
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

// Test: Access every legal lane at the last legacy configuration DWORD with
//       a live neighboring function, then access the first unmapped data port.
// Expected: Reads select exact bytes; writes preserve all other lanes and the
//       peer payload. The backend receives offset 0xfc and exact enables.
#[test]
fn last_configuration_dword_preserves_lanes_and_neighboring_function() {
    for (lane, payload, expected_read, expected_full, enable, backend_value) in [
        (
            0,
            vec![0xa1],
            vec![0x11],
            [0xa1, 0x22, 0x33, 0x44],
            PciConfigByteEnable::BYTE0,
            0xa1,
        ),
        (
            1,
            vec![0xa2],
            vec![0x22],
            [0x11, 0xa2, 0x33, 0x44],
            PciConfigByteEnable::BYTE1,
            0xa200,
        ),
        (
            2,
            vec![0xa3],
            vec![0x33],
            [0x11, 0x22, 0xa3, 0x44],
            PciConfigByteEnable::BYTE2,
            0xa3_0000,
        ),
        (
            3,
            vec![0xa4],
            vec![0x44],
            [0x11, 0x22, 0x33, 0xa4],
            PciConfigByteEnable::BYTE3,
            0xa400_0000,
        ),
        (
            0,
            vec![0xa1, 0xa2],
            vec![0x11, 0x22],
            [0xa1, 0xa2, 0x33, 0x44],
            PciConfigByteEnable::LOW_WORD,
            0xa2a1,
        ),
        (
            2,
            vec![0xa3, 0xa4],
            vec![0x33, 0x44],
            [0x11, 0x22, 0xa3, 0xa4],
            PciConfigByteEnable::HIGH_WORD,
            0xa4a3_0000,
        ),
        (
            0,
            vec![0xa1, 0xa2, 0xa3, 0xa4],
            vec![0x11, 0x22, 0x33, 0x44],
            [0xa1, 0xa2, 0xa3, 0xa4],
            PciConfigByteEnable::FULL,
            0xa4a3_a2a1,
        ),
    ] {
        let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
        let (device, backing) = endpoint(0x4433_2211);
        let (peer, peer_backing) = endpoint(0x8877_6655);
        bus.add_pci_device(0xff, 31, 7, "last", device).unwrap();
        bus.add_pci_device(0xff, 31, 6, "peer", peer).unwrap();
        select(&mut bus, 0x80ff_fffc);
        let mut bytes = vec![0xa5; payload.len()];
        bus.supports_pio()
            .unwrap()
            .io_read(DATA + lane, &mut bytes)
            .unwrap();
        assert_eq!(bytes, expected_read);
        write(&mut bus, DATA + lane, &payload);
        assert_eq!(backing.lock().reads, [(0xfc, enable)]);
        assert_eq!(
            backing.lock().writes,
            [(0xfc, ByteEnabledDwordWrite::new(backend_value, enable))]
        );
        assert!(peer_backing.lock().reads.is_empty());
        assert!(peer_backing.lock().writes.is_empty());
        assert_eq!(read::<4>(&mut bus, DATA), expected_full);
        let mut unmapped = [0xa5];
        assert!(matches!(
            bus.supports_pio().unwrap().io_read(DATA + 4, &mut unmapped),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert_eq!(unmapped, [0xa5]);
        write(&mut bus, DATA + 4, &[0]);
        assert_eq!(backing.lock().writes.len(), 1);
        assert_eq!(read::<4>(&mut bus, ADDR), [0xfc, 0xff, 0xff, 0x80]);
        assert_eq!(read::<4>(&mut bus, DATA), expected_full);
        select(&mut bus, 0x80ff_fefc);
        assert_eq!(read::<4>(&mut bus, DATA), [0x55, 0x66, 0x77, 0x88]);
        assert_eq!(
            peer_backing.lock().reads,
            [(0xfc, PciConfigByteEnable::FULL)]
        );
        assert!(peer_backing.lock().writes.is_empty());
    }
}

// Test: Restore a saved selection into a fresh bus with different endpoint
//       payloads, then reset and reselect both registered functions.
// Expected: Restore transfers only the latch, not devices or their contents;
//       reset disables decoding without unregistering or modifying either peer.
#[test]
fn fresh_restore_and_reset_preserve_destination_endpoint_ownership() {
    let mut source = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (old, _) = endpoint(0x4433_2211);
    source.add_pci_device(0xff, 31, 7, "source", old).unwrap();
    select(&mut source, 0x80ff_fffc);
    let saved = source.save().unwrap();
    block_on(source.reset());

    let mut destination = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (new, _) = endpoint(0x8877_6655);
    let (peer, _) = endpoint(0xccbb_aa99);
    destination
        .add_pci_device(0xff, 31, 7, "destination", new)
        .unwrap();
    destination
        .add_pci_device(0xff, 31, 6, "peer", peer)
        .unwrap();
    destination.restore(saved).unwrap();
    assert_eq!(read::<4>(&mut destination, ADDR), [0xfc, 0xff, 0xff, 0x80]);
    assert_eq!(read::<4>(&mut destination, DATA), [0x55, 0x66, 0x77, 0x88]);
    write(&mut destination, DATA + 3, &[0xdd]);
    block_on(destination.reset());
    assert_eq!(read::<4>(&mut destination, ADDR), [0; 4]);
    assert_eq!(read::<4>(&mut destination, DATA), [0xff; 4]);
    write(&mut destination, DATA, &[0; 4]);
    select(&mut destination, 0x80ff_fffc);
    assert_eq!(read::<4>(&mut destination, DATA), [0x55, 0x66, 0x77, 0xdd]);
    select(&mut destination, 0x80ff_fefc);
    assert_eq!(read::<4>(&mut destination, DATA), [0x99, 0xaa, 0xbb, 0xcc]);
    assert_eq!(read::<4>(&mut source, ADDR), [0; 4]);
    select(&mut source, 0x80ff_fffc);
    assert_eq!(read::<4>(&mut source, DATA), [0x11, 0x22, 0x33, 0x44]);
}

// Test: Defer read/write requests, change the latch to a live peer and finish
//       with a read error and dropped write completion.
// Expected: Polling is woken for new work and backend completion; errors reach
//       guest tokens without overwriting read bytes, changing peers or blocking
//       subsequent accesses to either endpoint.
#[test]
fn deferred_errors_wake_polling_and_leave_other_endpoint_accesses_independent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut bus = GenericPciBus::new(&mut Bus, ADDR, DATA);
    let (first, backing) = endpoint(0x4433_2211);
    let (peer, _) = endpoint(0x8877_6655);
    bus.add_pci_device(0, 1, 0, "first", first).unwrap();
    bus.add_pci_device(0, 2, 0, "peer", peer).unwrap();
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    let before_work = wake.0.load(Ordering::SeqCst);
    select(&mut bus, 0x8000_0840);
    backing.lock().mode = Mode::Deferred;
    let mut bytes = [0xa5; 2];
    let IoResult::Defer(mut read_token) = bus.io_read(DATA + 2, &mut bytes) else {
        panic!("read was not deferred");
    };
    let IoResult::Defer(mut write_token) = bus.io_write(DATA + 1, &[0xaa]) else {
        panic!("write was not deferred");
    };
    assert!(wake.0.load(Ordering::SeqCst) > before_work);
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(read_token.poll_read(&mut context, &mut bytes).is_pending());
    assert!(write_token.poll_write(&mut context).is_pending());
    assert_eq!(bytes, [0xa5; 2]);
    assert_eq!(
        backing.lock().reads,
        [(0x40, PciConfigByteEnable::HIGH_WORD)]
    );
    assert_eq!(
        backing.lock().writes,
        [(
            0x40,
            ByteEnabledDwordWrite::new(0xaa00, PciConfigByteEnable::BYTE1)
        )]
    );
    select(&mut bus, 0x8000_1024);
    assert_eq!(read::<4>(&mut bus, DATA), [0x55, 0x66, 0x77, 0x88]);
    write(&mut bus, DATA + 3, &[0xbb]);
    let before_completion = wake.0.load(Ordering::SeqCst);
    backing
        .lock()
        .read
        .take()
        .unwrap()
        .complete_error(IoError::InvalidRegister);
    drop(backing.lock().write.take().unwrap());
    assert!(wake.0.load(Ordering::SeqCst) > before_completion);
    bus.supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(matches!(
        read_token.poll_read(&mut context, &mut bytes),
        Poll::Ready(Err(IoError::InvalidRegister))
    ));
    assert_eq!(bytes, [0xa5; 2]);
    assert!(matches!(
        write_token.poll_write(&mut context),
        Poll::Ready(Err(IoError::NoResponse))
    ));
    assert_eq!(read::<4>(&mut bus, ADDR), [0x24, 0x10, 0, 0x80]);
    assert_eq!(read::<4>(&mut bus, DATA), [0x55, 0x66, 0x77, 0xbb]);
    backing.lock().mode = Mode::Online;
    select(&mut bus, 0x8000_0840);
    assert_eq!(read::<4>(&mut bus, DATA), [0x11, 0x22, 0x33, 0x44]);
    write(&mut bus, DATA + 1, &[0xdd]);
    assert_eq!(read::<4>(&mut bus, DATA), [0x11, 0xdd, 0x33, 0x44]);
}
