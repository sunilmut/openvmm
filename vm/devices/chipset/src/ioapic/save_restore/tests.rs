// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::ioapic::IOAPIC_DEVICE_MMIO_REGION_BASE_ADDRESS as BASE;
use chipset_device::ChipsetDevice;
use chipset_device::interrupt::HandleEoi;
use chipset_device::interrupt::LineInterruptTarget;
use chipset_device::io::{IoError, IoResult};
use chipset_device::mmio::MmioIntercept;
use chipset_resources::ioapic::IoApicRouting;
use futures::executor::block_on;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::SaveRestore;

const ENTRY_COUNT: u8 = 2;
const IRQ: u8 = 1;
const VECTOR: u8 = 0x30;

#[derive(Clone, Default)]
struct RecordingRouting {
    assertions: Arc<Mutex<Vec<u8>>>,
    routes: Arc<Mutex<Vec<RouteCall>>>,
}

#[derive(Debug, PartialEq, Eq)]
struct RouteCall {
    irq: u8,
    request: Option<(u64, u32)>,
}

impl IoApicRouting for RecordingRouting {
    fn assert(&self, irq: u8) {
        self.assertions.lock().push(irq);
    }

    fn set_route(&self, irq: u8, request: Option<(u64, u32)>) {
        self.routes.lock().push(RouteCall { irq, request });
    }
}

fn device() -> (IoApicDevice, RecordingRouting) {
    let routing = RecordingRouting::default();
    (
        IoApicDevice::new(ENTRY_COUNT, Box::new(routing.clone())),
        routing,
    )
}

fn set_entry(device: &mut IoApicDevice, level: bool, masked: bool) {
    let entry = RedirectionEntry::new()
        .with_vector(VECTOR)
        .with_trigger_mode_level(level)
        .with_masked(masked);
    device.write_redirection_register(IRQ * 2, u64::from(entry) as u32);
}

fn mmio_set(device: &mut IoApicDevice, index: u8, value: u32) {
    device.mmio_write(BASE, &[index]).unwrap();
    device
        .supports_mmio()
        .unwrap()
        .mmio_write(BASE + 0x10, &value.to_le_bytes())
        .unwrap();
}

fn mmio_get(device: &mut IoApicDevice, index: u8) -> u32 {
    device.mmio_write(BASE, &[index]).unwrap();
    let mut value = [0; 4];
    device.mmio_read(BASE + 0x10, &mut value).unwrap();
    u32::from_le_bytes(value)
}

// Test: Read/write I/O APIC identity, version, arbitration, invalid, and absent-entry registers.
// Expected: Selected registers read correctly, read-only values stay fixed, and bad DATA sizes fail.
#[test]
fn mmio_register_window_preserves_read_only_values_and_rejects_bad_writes() {
    let (mut device, _) = device();
    assert_eq!(mmio_get(&mut device, 1), 0x00010011);
    mmio_set(&mut device, 0, 0x07000000);
    assert_eq!(mmio_get(&mut device, 0), 0x07000000);
    for (index, expected) in [(1, 0x00010011), (2, 0), (3, u32::MAX), (0x14, 0)] {
        mmio_set(&mut device, index, u32::MAX);
        assert_eq!(mmio_get(&mut device, index), expected);
    }
    device.mmio_write(BASE, &[1]).unwrap();
    for size in [1, 2, 4] {
        let mut bytes = vec![0xa5; size];
        device.mmio_read(BASE + 0x10, &mut bytes).unwrap();
        assert_eq!(bytes, 0x00010011u32.to_le_bytes()[..size]);
    }
    device.mmio_write(BASE, &[0]).unwrap();
    for size in [0, 1, 2, 8] {
        assert!(matches!(
            device.mmio_write(BASE + 0x10, &vec![0xff; size]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(mmio_get(&mut device, 0), 0x07000000);
    }
    assert!(matches!(
        device.mmio_read(BASE + 4, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.mmio_write(BASE + 4, &[0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    let mut index = [0xff];
    device.mmio_read(BASE, &mut index).unwrap();
    assert_eq!(index, [0]);
    assert_eq!(device.get_static_regions(), &[("mmio", BASE..=BASE + 0x1f)]);
}

// Test: Program a level-triggered route through MMIO, assert it, acknowledge it, mask, and reset.
// Expected: Routing uses the destination/vector, EOI reasserts only a live level, and reset masks all.
#[test]
fn mmio_redirection_programming_controls_routing_eoi_and_reset() {
    let (mut device, routing) = device();
    mmio_set(&mut device, 0x13, 0x07000000);
    mmio_set(&mut device, 0x12, 0x8030);
    assert_eq!(mmio_get(&mut device, 0x13), 0x07000000);
    assert_eq!(mmio_get(&mut device, 0x12), 0x8030);
    {
        let routes = routing.routes.lock();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].irq, IRQ);
        let (address, data) = routes[0].request.unwrap();
        assert_eq!(address, 0xfee07000);
        assert_eq!(data & 0xff, 0x30);
    }
    device
        .supports_line_interrupt_target()
        .unwrap()
        .set_irq(1, true);
    device.set_irq(1, true);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
    assert_ne!(mmio_get(&mut device, 0x12) & 0x4000, 0);
    device.supports_handle_eoi().unwrap().handle_eoi(0x31);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
    device.handle_eoi(0x30);
    assert_eq!(*routing.assertions.lock(), [IRQ, IRQ]);
    device.set_irq(1, false);
    device.handle_eoi(0x30);
    assert_eq!(*routing.assertions.lock(), [IRQ, IRQ]);
    assert_eq!(mmio_get(&mut device, 0x12) & 0x4000, 0);
    mmio_set(&mut device, 0x12, 0x18030);
    assert_eq!(routing.routes.lock().last().unwrap().request, None);
    block_on(device.reset());
    assert_eq!(mmio_get(&mut device, 0), 0);
    assert_eq!(mmio_get(&mut device, 0x12) & 0x100ff, 0x10000);
    assert_eq!(device.valid_lines(), &[0..=1]);
    assert_eq!(
        &routing.routes.lock()[2..],
        &[
            RouteCall {
                irq: 0,
                request: None
            },
            RouteCall {
                irq: 1,
                request: None
            }
        ]
    );
}

// Test: Restore a checkpoint missing a redirection entry over an already configured MMIO route.
// Expected: Restore rejects it and preserves the existing guest-visible route and routing callbacks.
#[test]
fn wrong_entry_count_checkpoint_preserves_the_active_mmio_route() {
    let (mut device, routing) = device();
    mmio_set(&mut device, 0x13, 0x07000000);
    mmio_set(&mut device, 0x12, 0x30);
    let calls = routing.routes.lock().len();
    let mut saved = device.save().unwrap();
    saved.redirection_entries.pop();
    assert!(device.restore(saved).is_err());
    assert_eq!(mmio_get(&mut device, 0x13), 0x07000000);
    assert_eq!(mmio_get(&mut device, 0x12), 0x30);
    assert_eq!(routing.routes.lock().len(), calls);
    device.set_irq(1, true);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

// Test: Known product bug: read eight bytes from the guest-visible I/O APIC DATA window.
// Expected: A guest access returns data or a typed error without panicking.
#[test]
#[ignore = "known product bug: MMIO reads larger than four bytes panic when copying the register"]
fn known_bug_eight_byte_mmio_read_does_not_panic() {
    let (mut device, _) = device();
    device.mmio_write(BASE, &[1]).unwrap();
    let _ = device.mmio_read(BASE + 0x10, &mut [0; 8]);
}

#[test]
fn restore_preserves_edge_history() {
    let (mut source, _) = device();
    set_entry(&mut source, false, false);
    source.set_irq(IRQ.into(), true);
    let state = source.save().expect("save succeeds");

    let (mut restored, routing) = device();
    restored.restore(state).expect("restore succeeds");
    restored.set_irq(IRQ.into(), true);
    assert!(routing.assertions.lock().is_empty());

    restored.set_irq(IRQ.into(), false);
    restored.set_irq(IRQ.into(), true);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

#[test]
fn restore_allows_new_rising_edge() {
    let (mut source, _) = device();
    set_entry(&mut source, false, false);
    let state = source.save().expect("save succeeds");

    let (mut restored, routing) = device();
    set_entry(&mut restored, false, false);
    restored.set_irq(IRQ.into(), true);
    routing.assertions.lock().clear();

    restored.restore(state).expect("restore succeeds");
    assert!(routing.assertions.lock().is_empty());
    restored.set_irq(IRQ.into(), true);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

#[test]
fn restore_preserves_asserted_level_until_unmasked() {
    let (mut source, _) = device();
    set_entry(&mut source, true, true);
    source.set_irq(IRQ.into(), true);
    let state = source.save().expect("save succeeds");

    let (mut restored, routing) = device();
    restored.restore(state).expect("restore succeeds");
    assert!(routing.assertions.lock().is_empty());
    set_entry(&mut restored, true, false);

    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

#[test]
fn restore_preserves_remote_irr_until_eoi() {
    let (mut source, _) = device();
    set_entry(&mut source, true, false);
    source.set_irq(IRQ.into(), true);
    let state = source.save().expect("save succeeds");

    let (mut restored, routing) = device();
    restored.restore(state).expect("restore succeeds");
    restored.set_irq(IRQ.into(), true);
    assert!(routing.assertions.lock().is_empty());

    restored.handle_eoi(VECTOR.into());
    assert_eq!(*routing.assertions.lock(), [IRQ]);
    restored.set_irq(IRQ.into(), false);
    restored.handle_eoi(VECTOR.into());
    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

#[test]
fn restore_does_not_evaluate_level_interrupts() {
    let (mut source, _) = device();
    set_entry(&mut source, true, true);
    source.set_irq(IRQ.into(), true);
    let mut state = source.save().expect("save succeeds");
    state.redirection_entries[IRQ as usize] =
        RedirectionEntry::from(state.redirection_entries[IRQ as usize])
            .with_masked(false)
            .into();

    let (mut restored, routing) = device();
    restored.restore(state).expect("restore succeeds");
    assert!(routing.assertions.lock().is_empty());

    restored.set_irq(IRQ.into(), true);
    assert_eq!(*routing.assertions.lock(), [IRQ]);
}

#[test]
fn restore_defaults_absent_line_levels_to_deasserted() {
    let (mut source, _) = device();
    set_entry(&mut source, true, true);
    source.set_irq(IRQ.into(), true);
    let mut state = source.save().expect("save succeeds");
    state.line_levels.clear();

    let (mut restored, routing) = device();
    restored.restore(state).expect("restore succeeds");
    set_entry(&mut restored, true, false);

    assert!(routing.assertions.lock().is_empty());
}

#[test]
fn restore_rejects_wrong_number_of_line_levels() {
    let (mut source, _) = device();
    let mut state = source.save().expect("save succeeds");
    state.line_levels.pop();

    let (mut restored, routing) = device();
    set_entry(&mut restored, false, false);
    let before = restored.save().expect("save succeeds");
    let error = restored.restore(state).expect_err("restore must fail");

    assert_eq!(error.to_string(), "wrong number of line levels");
    let after = restored.save().expect("save succeeds");
    assert_eq!(after.redirection_entries, before.redirection_entries);
    assert_eq!(after.line_levels, before.line_levels);
    assert!(routing.assertions.lock().is_empty());
}
