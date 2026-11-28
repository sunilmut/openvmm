// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::StubFloppyDiskController;
use chipset_device::ChipsetDevice;
use chipset_device::io::{IoError, IoResult};
use chipset_device::pio::{ControlPortIoIntercept, PortIoIntercept, RegisterPortIoIntercept};
use futures::executor::block_on;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vmcore::line_interrupt::{LineInterrupt, LineSetTarget};
use vmcore::save_restore::{RestoreError, SaveRestore};

const BASE: u16 = 0x3f0;

#[derive(Default)]
struct Irq(AtomicBool);

impl LineSetTarget for Irq {
    fn set_irq(&self, vector: u32, high: bool) {
        assert_eq!(vector, 6);
        self.0.store(high, Ordering::SeqCst);
    }
}

impl Irq {
    fn high(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct Bus {
    ports: Arc<Mutex<BTreeMap<u16, String>>>,
}

impl Bus {
    fn owner(&self, address: u16) -> Option<String> {
        self.ports.lock().get(&address).cloned()
    }
}

struct Region {
    name: String,
    address: Option<u16>,
    length: u16,
    ports: Arc<Mutex<BTreeMap<u16, String>>>,
}

impl RegisterPortIoIntercept for Bus {
    fn new_io_region(&mut self, name: &str, length: u16) -> Box<dyn ControlPortIoIntercept> {
        Box::new(Region {
            name: name.into(),
            address: None,
            length,
            ports: self.ports.clone(),
        })
    }
}

impl ControlPortIoIntercept for Region {
    fn region_name(&self) -> &str {
        &self.name
    }
    fn map(&mut self, address: u16) {
        self.unmap();
        let mut ports = self.ports.lock();
        for offset in 0..self.length {
            assert!(ports.insert(address + offset, self.name.clone()).is_none());
        }
        self.address = Some(address);
    }
    fn unmap(&mut self) {
        if let Some(address) = self.address.take() {
            let mut ports = self.ports.lock();
            for offset in 0..self.length {
                assert_eq!(
                    ports.remove(&(address + offset)).as_deref(),
                    Some(self.name.as_str())
                );
            }
        }
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

impl Drop for Region {
    fn drop(&mut self) {
        self.unmap();
    }
}

fn fixture() -> (StubFloppyDiskController, Arc<Irq>) {
    let irq = Arc::new(Irq::default());
    let line = LineInterrupt::new_with_target("floppy-test", irq.clone(), 6);
    let mut device = StubFloppyDiskController::new(line, &mut Bus::default(), BASE);
    block_on(ChangeDeviceState::reset(&mut device));
    device.start();
    (device, irq)
}

fn write(device: &mut StubFloppyDiskController, offset: u16, value: u8) {
    assert!(matches!(
        device
            .supports_pio()
            .unwrap()
            .io_write(BASE + offset, &[value]),
        IoResult::Ok
    ));
}

fn read(device: &mut StubFloppyDiskController, offset: u16) -> u8 {
    let mut data = [0];
    assert!(matches!(
        device
            .supports_pio()
            .unwrap()
            .io_read(BASE + offset, &mut data),
        IoResult::Ok
    ));
    data[0]
}

fn command(device: &mut StubFloppyDiskController, bytes: &[u8]) {
    for &byte in bytes {
        write(device, 5, byte);
    }
}

fn result<const N: usize>(device: &mut StubFloppyDiskController) -> [u8; N] {
    std::array::from_fn(|_| read(device, 5))
}

fn ready(device: &mut StubFloppyDiskController) {
    write(device, 2, 0x0c);
    for drive in 0..4 {
        command(device, &[0x08]);
        assert_eq!(result::<2>(device), [0xc0 | drive, 0]);
    }
}

// Test: Route every controller port through its registered ranges and exercise
//       unsupported ports and widths alongside the reset and motor registers.
// Expected: The IDE hole is unmapped, invalid accesses return explicit errors,
//       and documented status bits reflect controller and motor enablement.
#[test]
fn ports_access_widths_and_motor_status() {
    let (mut device, _) = fixture();
    for offset in 0..8 {
        assert_eq!(
            device.offset_of(BASE + offset),
            (offset != 6).then_some(offset)
        );
    }
    assert_eq!(device.offset_of(BASE - 1), None);
    assert_eq!(device.offset_of(BASE + 8), None);
    for width in [0, 2, 4] {
        let mut bytes = vec![0xa5; width];
        assert!(matches!(
            device.io_read(BASE + 5, &mut bytes),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert!(matches!(
            device.io_write(BASE + 5, &bytes),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(bytes, vec![0xa5; width]);
    }
    assert!(matches!(
        device.io_read(BASE + 6, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.io_write(BASE + 6, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(
        [
            read(&mut device, 0),
            read(&mut device, 1),
            read(&mut device, 3)
        ],
        [0xff, 0xfc, 0xff]
    );
    for offset in [0, 1, 3, 7] {
        write(&mut device, offset, 0xff);
    }
    assert_eq!(read(&mut device, 4), 0);
    assert_eq!(read(&mut device, 7), 0x7f);
    command(&mut device, &[0x0f, 0]);
    ready(&mut device);
    assert_eq!(read(&mut device, 4), 0x80);
    write(&mut device, 2, 0x1c);
    assert_eq!(read(&mut device, 2), 0x1c);
    assert_eq!(read(&mut device, 7), 0xff);
    device
        .supports_poll_device()
        .unwrap()
        .poll_device(&mut Context::from_waker(Waker::noop()));
    assert_eq!(read(&mut device, 2), 0x1c);
    assert_eq!(read(&mut device, 4), 0x80);
    block_on(device.stop());
    command(&mut device, &[0x10]);
    assert_eq!(read(&mut device, 5), 0x90);
    assert_eq!(read(&mut device, 4), 0x80);
}

// Test: Submit supported identification, configuration and FIFO commands.
// Expected: Commands consume exactly their input bytes, return documented
//       responses, and restore the data-register direction after the last byte.
#[test]
fn identification_configuration_and_result_handshake() {
    let (mut device, _) = fixture();
    ready(&mut device);
    for (bytes, reply) in [
        (&[0x10][..], Some(0x90)),
        (&[0x18][..], Some(1)),
        (&[0x94][..], Some(0x10)),
        (&[0x14][..], Some(0)),
        (&[0x03, 0, 0][..], None),
        (&[0x12, 0x55][..], None),
        (&[0x13, 0, 0x57, 0][..], None),
        (&[0xff][..], Some(0x80)),
    ] {
        for (index, &byte) in bytes.iter().enumerate() {
            write(&mut device, 5, byte);
            if index + 1 < bytes.len() {
                assert_eq!(read(&mut device, 4), 0x90);
                assert_eq!(read(&mut device, 5), 0x80);
            }
        }
        if let Some(reply) = reply {
            assert_eq!(read(&mut device, 4), 0xd0);
            assert_eq!(read(&mut device, 5), reply);
        }
        assert_eq!(read(&mut device, 4), 0x80);
    }
    command(&mut device, &[0x0e]);
    assert_eq!(result::<10>(&mut device), [0; 10]);
    assert_eq!(read(&mut device, 4), 0x80);
    assert_eq!(read(&mut device, 5), 0x80);
}

// Test: Leave reset, consume each drive's reset indication and request status
//       after all indications have been acknowledged.
// Expected: Four reset statuses identify drives 0-3, the interrupt clears on
//       acknowledgement, and a later sense command reports no pending event.
#[test]
fn reset_interrupts_have_four_acknowledgements() {
    let (mut device, irq) = fixture();
    assert!(!irq.high());
    write(&mut device, 2, 0x04);
    assert!(irq.high());
    for drive in 0..4 {
        command(&mut device, &[0x08]);
        assert!(!irq.high());
        assert_eq!(result::<2>(&mut device), [0xc0 | drive, 0]);
    }
    command(&mut device, &[0x08]);
    assert_eq!(result::<2>(&mut device), [0x80, 0]);
    assert_eq!(read(&mut device, 4), 0x80);
}

// Test: Seek with interrupts disabled, enable them, seek again and recalibrate.
// Expected: Interrupt masking preserves pending completion and sense commands
//       report the current cylinder and clear the externally connected IRQ.
#[test]
fn seeks_recalibration_and_interrupt_masking() {
    let (mut device, irq) = fixture();
    ready(&mut device);
    write(&mut device, 2, 0x04);
    command(&mut device, &[0x0f, 2, 7]);
    assert!(!irq.high());
    assert_eq!(read(&mut device, 4) & 0xf, 4);
    write(&mut device, 2, 0x0c);
    assert!(irq.high());
    command(&mut device, &[0x04, 7]);
    assert_eq!(read(&mut device, 5), 0x2f);
    command(&mut device, &[0x0f, 0, 8]);
    command(&mut device, &[0x08]);
    assert_eq!(result::<2>(&mut device), [0x20, 8]);
    assert!(!irq.high());
    command(&mut device, &[0x07, 0]);
    assert!(irq.high());
    write(&mut device, 2, 0x04);
    assert!(!irq.high());
    command(&mut device, &[0x08]);
    assert_eq!(result::<2>(&mut device), [0x20, 0]);
    command(&mut device, &[0x04, 3]);
    assert_eq!(read(&mut device, 5), 0x3b);
}

// Test: Interrupt a pending command with DOR reset and with software reset.
// Expected: Reset discards partial input, clears the IRQ and restores command
//       handling; software reset generates fresh reset acknowledgements.
#[test]
fn hardware_and_software_resets_discard_pending_work() {
    let (mut device, irq) = fixture();
    ready(&mut device);
    command(&mut device, &[0x0f, 0]);
    assert_eq!(read(&mut device, 4), 0x90);
    write(&mut device, 2, 0);
    assert!(!irq.high());
    assert_eq!(read(&mut device, 4), 0);
    ready(&mut device);
    command(&mut device, &[0x10]);
    assert_eq!(read(&mut device, 5), 0x90);
    write(&mut device, 4, 0);
    assert!(!irq.high());
    write(&mut device, 4, 0x80);
    assert!(irq.high());
    assert_eq!(read(&mut device, 2), 0x0c);
    command(&mut device, &[0x08]);
    assert_eq!(result::<2>(&mut device), [0xc0, 0]);
    block_on(ChangeDeviceState::reset(&mut device));
    assert_eq!(read(&mut device, 2), 0);
    assert!(!irq.high());
}

// Test: Restore a controller while reset acknowledgements or seek completion
//       are pending, then acknowledge through the normal data port.
// Expected: The restored IRQ level and subsequent guest replies match the
//       source controller, including reset-drive ordering, seek cylinder and
//       deassertion when replacing an interrupting receiver with a quiet source.
#[test]
fn snapshots_preserve_pending_interrupt_replies() {
    let (mut source, _) = fixture();
    write(&mut source, 2, 0x0c);
    let (mut restored, irq) = fixture();
    restored.restore(source.save().unwrap()).unwrap();
    assert!(irq.high());
    for drive in 0..4 {
        for device in [&mut source, &mut restored] {
            command(device, &[0x08]);
            assert_eq!(result::<2>(device), [0xc0 | drive, 0]);
            assert_eq!(read(device, 4), 0x80);
        }
        assert!(!irq.high());
    }
    command(&mut source, &[0x0f, 0, 11]);
    restored.restore(source.save().unwrap()).unwrap();
    assert!(irq.high());
    command(&mut restored, &[0x08]);
    assert_eq!(result::<2>(&mut restored), [0x20, 11]);
    assert!(!irq.high());
    command(&mut source, &[0x08]);
    assert_eq!(result::<2>(&mut source), [0x20, 11]);
    assert_eq!(read(&mut source, 4), 0x80);
    write(&mut restored, 2, 0);
    write(&mut restored, 2, 0x0c);
    assert!(irq.high());
    restored.restore(source.save().unwrap()).unwrap();
    assert!(!irq.high());
    command(&mut restored, &[0x04, 0]);
    assert_eq!(read(&mut restored, 5), 0x28);
    command(&mut restored, &[0x08]);
    assert_eq!(result::<2>(&mut restored), [0x80, 11]);
}

// Test: Save during partial command input and again during partial reply output.
// Expected: Restoring resumes from the next guest byte without repeating input,
//       losing the cylinder byte, or leaving the data direction stuck; a fresh
//       receiver and the source progress independently.
#[test]
fn snapshots_resume_partial_command_and_reply_transfers() {
    let (mut source, _) = fixture();
    ready(&mut source);
    command(&mut source, &[0x0f, 0]);
    let (mut restored, _) = fixture();
    restored.restore(source.save().unwrap()).unwrap();
    command(&mut restored, &[13]);
    command(&mut restored, &[0x08]);
    assert_eq!(read(&mut restored, 5), 0x20);
    assert_eq!(read(&mut restored, 4), 0xd0);
    let (mut fresh, irq) = fixture();
    fresh.restore(restored.save().unwrap()).unwrap();
    assert!(!irq.high());
    for device in [&mut restored, &mut fresh] {
        assert_eq!(read(device, 5), 13);
        assert_eq!(read(device, 4), 0x80);
        command(device, &[0x10]);
        assert_eq!(read(device, 5), 0x90);
        assert_eq!(read(device, 4), 0x80);
    }
    command(&mut source, &[29]);
    command(&mut source, &[0x08]);
    assert_eq!(result::<2>(&mut source), [0x20, 29]);
}

// Test: Supply snapshot payloads with oversized command or response FIFOs.
// Expected: Restore rejects both malformed payloads explicitly and a later
//       valid restore still accepts ordinary controller commands. Rejection
//       preserves the pending seek completion and its connected IRQ.
#[test]
fn oversized_snapshot_fifos_are_rejected() {
    let (mut source, irq) = fixture();
    ready(&mut source);
    command(&mut source, &[0x0f, 0, 31]);
    let valid = source.save().unwrap();
    for input in [true, false] {
        let mut snapshot = source.save().unwrap();
        snapshot.digital_output = 0;
        snapshot.main_status = 0;
        snapshot.interrupt_level = false;
        snapshot.floppies[0].cur_cylinder = 99;
        if input {
            snapshot.input_bytes = vec![0; 17];
        } else {
            snapshot.output_bytes = vec![0; 17];
        }
        assert!(matches!(
            source.restore(snapshot),
            Err(RestoreError::InvalidSavedState(_))
        ));
        assert!(irq.high());
        assert_eq!(read(&mut source, 2), 0x0c);
        assert_eq!(read(&mut source, 4), 0x81);
        command(&mut source, &[0x08]);
        assert_eq!(result::<2>(&mut source), [0x20, 31]);
        assert!(!irq.high());
        command(&mut source, &[0x0f, 0, 31]);
    }
    source.restore(valid).unwrap();
    command(&mut source, &[0x08]);
    assert_eq!(result::<2>(&mut source), [0x20, 31]);
    assert!(!irq.high());
    command(&mut source, &[0x10]);
    assert_eq!(read(&mut source, 5), 0x90);
}

// IGNORED: DUMP_REGISTERS queues its bytes in guest order but emits them from
//       the back of the FIFO, reversing the entire result.
//
// Test: Dump registers after programming timing bytes and seeking a cylinder.
// Expected: Drive cylinders precede timing bytes in the controller's documented
//       ten-byte result order.
#[test]
#[ignore = "product bug: register-dump response bytes are reversed"]
fn register_dump_returns_cylinders_before_timing_bytes() {
    let (mut device, _) = fixture();
    ready(&mut device);
    command(&mut device, &[0x03, 0x12, 0x34]);
    command(&mut device, &[0x0f, 0, 7]);
    command(&mut device, &[0x08]);
    assert_eq!(result::<2>(&mut device), [0x20, 7]);
    command(&mut device, &[0x0e]);
    assert_eq!(
        result::<10>(&mut device),
        [7, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0]
    );
}

// Test: Apply DOR or software reset halfway through a seek-status reply.
// Expected: The old cylinder byte is discarded, all four reset indications
//       are fresh, and a new command completes with normal FIFO direction.
#[test]
fn resets_discard_unread_result_bytes_before_new_commands() {
    for software in [false, true] {
        let (mut device, irq) = fixture();
        ready(&mut device);
        command(&mut device, &[0x0f, 0, 23]);
        command(&mut device, &[0x08]);
        assert_eq!(read(&mut device, 5), 0x20);
        assert_eq!(read(&mut device, 4) & 0xd0, 0xd0);
        if software {
            write(&mut device, 4, 0x80);
        } else {
            write(&mut device, 2, 0);
            write(&mut device, 2, 0x0c);
        }
        assert!(irq.high());
        assert_eq!(read(&mut device, 4), 0x80);
        for drive in 0..4 {
            command(&mut device, &[0x08]);
            assert_eq!(result::<2>(&mut device), [0xc0 | drive, 0]);
        }
        assert!(!irq.high());
        command(&mut device, &[0x10]);
        assert_eq!(read(&mut device, 5), 0x90);
        assert_eq!(read(&mut device, 4), 0x80);
    }
}

// Test: Register a floppy controller beside an IDE port and a shared IRQ peer,
//       then acknowledge, reset and drop the controller while the peer is active.
// Expected: Only floppy ports are claimed and released; the IDE mapping and
//       peer interrupt survive until their own owners release them.
#[test]
fn registered_resources_preserve_peer_ownership() {
    let mut bus = Bus::default();
    let mut ide = bus.new_io_region("ide alternate status", 1);
    ide.map(BASE + 6);
    let irq = Arc::new(Irq::default());
    let line = LineInterrupt::new_with_target("floppy-test", irq.clone(), 6);
    let peer = line.new_shared("secondary floppy").unwrap();
    let mut device = StubFloppyDiskController::new(line, &mut bus, BASE);
    block_on(ChangeDeviceState::reset(&mut device));
    for offset in 0..8 {
        let owner = match offset {
            0..=5 => "floppy base",
            6 => "ide alternate status",
            7 => "floppy control",
            _ => unreachable!(),
        };
        assert_eq!(bus.owner(BASE + offset).as_deref(), Some(owner));
        assert_eq!(
            device.offset_of(BASE + offset),
            (offset != 6).then_some(offset)
        );
    }
    peer.set_level(true);
    ready(&mut device);
    assert!(irq.high());
    peer.set_level(false);
    assert!(!irq.high());
    peer.set_level(true);
    block_on(ChangeDeviceState::reset(&mut device));
    assert!(irq.high());
    assert_eq!(read(&mut device, 4), 0);
    assert_eq!(bus.owner(BASE + 6).as_deref(), Some("ide alternate status"));
    write(&mut device, 2, 0x0c);
    peer.set_level(false);
    assert!(irq.high());
    peer.set_level(true);
    drop(device);
    for offset in 0..8 {
        assert_eq!(
            bus.owner(BASE + offset).as_deref(),
            (offset == 6).then_some("ide alternate status")
        );
    }
    assert_eq!(ide.offset_of(BASE + 6), Some(0));
    assert!(irq.high());
    peer.set_level(false);
    assert!(!irq.high());
    drop(ide);
    assert_eq!(bus.owner(BASE + 6), None);
}

// Test: Reject multi-byte accesses during partial command input and reply
//       output on a controller registered at the secondary floppy base.
// Expected: Rejected accesses preserve buffers, IRQ and transfer phase; the
//       base-independent port decoder completes the exact seek reply afterward.
#[test]
fn secondary_ports_reject_widths_without_consuming_pending_transfers() {
    const SECONDARY: u16 = 0x370;
    let irq = Arc::new(Irq::default());
    let line = LineInterrupt::new_with_target("secondary floppy", irq.clone(), 6);
    let mut device = StubFloppyDiskController::new(line, &mut Bus::default(), SECONDARY);
    block_on(ChangeDeviceState::reset(&mut device));
    let mut put = |offset, value| {
        assert!(matches!(
            device.io_write(SECONDARY + offset, &[value]),
            IoResult::Ok
        ));
    };
    put(2, 0x0c);
    put(5, 0x0f);
    put(5, 2);
    for phase in [0x90, 0xd0] {
        let mut status = [0];
        assert!(matches!(
            device.io_read(SECONDARY + 4, &mut status),
            IoResult::Ok
        ));
        assert_eq!(status, [phase]);
        assert_eq!(irq.high(), phase == 0x90);
        for width in [0, 2, 4] {
            let mut bytes = vec![0xa5; width];
            assert!(matches!(
                device.io_read(SECONDARY + 5, &mut bytes),
                IoResult::Err(IoError::InvalidAccessSize)
            ));
            assert_eq!(bytes, vec![0xa5; width]);
            assert!(matches!(
                device.io_write(SECONDARY + 5, &bytes),
                IoResult::Err(IoError::InvalidAccessSize)
            ));
            assert!(matches!(
                device.io_read(SECONDARY + 4, &mut status),
                IoResult::Ok
            ));
            assert_eq!(status, [phase]);
            assert_eq!(irq.high(), phase == 0x90);
        }
        if phase == 0x90 {
            assert!(matches!(
                device.io_write(SECONDARY + 5, &[0x5a]),
                IoResult::Ok
            ));
            assert!(irq.high());
            assert!(matches!(
                device.io_write(SECONDARY + 5, &[0x08]),
                IoResult::Ok
            ));
            let mut status0 = [0];
            assert!(matches!(
                device.io_read(SECONDARY + 5, &mut status0),
                IoResult::Ok
            ));
            assert_eq!(status0, [0x20]);
            assert!(!irq.high());
        } else {
            let mut cylinder = [0];
            assert!(matches!(
                device.io_read(SECONDARY + 5, &mut cylinder),
                IoResult::Ok
            ));
            assert_eq!(cylinder, [0x5a]);
        }
    }
    let mut status = [0];
    assert!(matches!(
        device.io_read(SECONDARY + 4, &mut status),
        IoResult::Ok
    ));
    assert_eq!(status, [0x80]);
    assert!(matches!(
        device.io_write(SECONDARY + 5, &[0x10]),
        IoResult::Ok
    ));
    let mut version = [0];
    assert!(matches!(
        device.io_read(SECONDARY + 5, &mut version),
        IoResult::Ok
    ));
    assert_eq!(version, [0x90]);
}
