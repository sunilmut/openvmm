// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::Stream;
use futures::executor::block_on;
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use test_with_tracing::test;
use vmcore::line_interrupt::LineSetTarget;

struct TestInput {
    receiver: mesh::Receiver<KeyboardData>,
    active: Arc<AtomicBool>,
}

impl Stream for TestInput {
    type Item = KeyboardData;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl InputSource<KeyboardData> for TestInput {
    fn set_active(&mut self, active: bool) -> Pin<Box<dyn '_ + Future<Output = ()> + Send>> {
        Box::pin(async move { self.active.store(active, Ordering::SeqCst) })
    }
}

#[derive(Default)]
struct Irqs(Mutex<[bool; 16]>);

impl LineSetTarget for Irqs {
    fn set_irq(&self, vector: u32, high: bool) {
        self.0.lock()[vector as usize] = high;
    }
}

struct Fixture {
    device: I8042Device,
    input: mesh::Sender<KeyboardData>,
    irqs: Arc<Irqs>,
    resets: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let (input, receiver) = mesh::channel();
        let active = Arc::new(AtomicBool::new(false));
        let irqs = Arc::new(Irqs::default());
        let resets = Arc::new(AtomicUsize::new(0));
        let reset_count = resets.clone();
        let device = block_on(I8042Device::new(
            Box::new(move || {
                reset_count.fetch_add(1, Ordering::SeqCst);
            }),
            LineInterrupt::new_with_target("keyboard", irqs.clone(), 1),
            LineInterrupt::new_with_target("mouse", irqs.clone(), 12),
            Box::new(TestInput {
                receiver,
                active: active.clone(),
            }),
        ));
        assert!(active.load(Ordering::SeqCst));
        Self {
            device,
            input,
            irqs,
            resets,
        }
    }

    fn write(&mut self, port: u16, value: u8) {
        self.device.io_write(port, &[value]).unwrap();
    }

    fn read(&mut self, port: u16) -> u8 {
        let mut value = [0];
        self.device.io_read(port, &mut value).unwrap();
        value[0]
    }

    fn command_data(&mut self, command: u8, data: u8) {
        self.write(0x64, command);
        self.write(0x60, data);
    }

    fn poll(&mut self) {
        self.device
            .poll_device(&mut Context::from_waker(Waker::noop()));
    }

    fn expect_keyboard_bytes(&mut self, expected: &[u8]) {
        for &byte in expected {
            assert_eq!(self.read(0x64) & 0x21, 1);
            assert!(self.irqs.0.lock()[1]);
            assert_eq!(self.read(0x60), byte);
        }
        assert_eq!(self.read(0x64) & 1, 0);
        assert!(!self.irqs.0.lock()[1]);
    }
}

// Test: Write all spare controller RAM bytes and read them back through controller commands.
// Expected: Values remain independent, RAM reads assert IRQ1, and consuming output clears it.
#[test]
fn controller_ram_commands_preserve_all_slots_and_raise_keyboard_irqs() {
    let mut fixture = Fixture::new();
    for index in 1..=31u8 {
        fixture.command_data(0x60 | index, (index * 7) ^ 0x80);
    }
    for index in 1..=31u8 {
        fixture.write(0x64, 0x20 | index);
        assert_eq!(fixture.read(0x64) & 0x21, 1);
        assert!(fixture.irqs.0.lock()[1]);
        assert_eq!(fixture.read(0x60), (index * 7) ^ 0x80);
        assert!(!fixture.irqs.0.lock()[1]);
        assert_eq!(fixture.read(0x64) & 1, 0);
    }
}

// Test: Issue controller self/interface checks and keyboard/mouse enable-disable commands.
// Expected: BIOS replies match the protocol and command-byte flags reflect each command.
#[test]
fn controller_checks_and_interface_flags_round_trip_through_ports() {
    let mut fixture = Fixture::new();
    for (command, reply) in [
        (0xaa, 0x55),
        (0xa9, 0),
        (0xab, 0),
        (0xc0, 0x80),
        (0xa1, 0),
        (0xa4, 0xf1),
    ] {
        fixture.write(0x64, command);
        assert_eq!(fixture.read(0x64) & 0x21, 1);
        assert!(!fixture.irqs.0.lock()[1]);
        assert!(!fixture.irqs.0.lock()[12]);
        assert_eq!(fixture.read(0x60), reply);
    }
    for (command, expected) in [(0xa7, 0x67), (0xad, 0x77), (0xa8, 0x57), (0xae, 0x47)] {
        fixture.write(0x64, command);
        fixture.write(0x64, 0x20);
        assert_eq!(fixture.read(0x60), expected);
    }
    for command in [0xc1, 0xc2, 0x01] {
        fixture.write(0x64, command);
        assert_eq!(fixture.read(0x64) & 1, 0);
    }
}

// Test: Inject keyboard and auxiliary output, then mask interrupts before another byte arrives.
// Expected: Status and IRQ selection follow the source; masked bytes remain readable without IRQs.
#[test]
fn injected_output_selects_the_correct_irq_and_honors_interrupt_masks() {
    let mut fixture = Fixture::new();
    fixture.command_data(0xd2, 0xa5);
    assert_eq!(fixture.read(0x64) & 0x21, 1);
    assert!(fixture.irqs.0.lock()[1]);
    assert!(!fixture.irqs.0.lock()[12]);
    assert_eq!(fixture.read(0x60), 0xa5);
    assert!(!fixture.irqs.0.lock()[1]);
    fixture.command_data(0xd3, 0x5a);
    assert_eq!(fixture.read(0x64) & 0x21, 0x21);
    assert!(!fixture.irqs.0.lock()[1]);
    assert!(fixture.irqs.0.lock()[12]);
    assert_eq!(fixture.read(0x60), 0x5a);
    assert!(!fixture.irqs.0.lock()[12]);
    fixture.command_data(0x60, 0x40);
    fixture.command_data(0xd2, 0x81);
    assert_eq!(fixture.read(0x64) & 1, 1);
    assert!(!fixture.irqs.0.lock()[1]);
    assert_eq!(fixture.read(0x60), 0x81);
}

// Test: Pulse reset output and program the output port's reset/A20 bits.
// Expected: Only active-low reset requests invoke reset; A20 reads back and command data is staged.
#[test]
fn reset_and_a20_commands_have_distinct_observable_effects() {
    let mut fixture = Fixture::new();
    for command in [0xf1, 0xff] {
        fixture.write(0x64, command);
    }
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
    for command in [0xf0, 0xfe] {
        fixture.write(0x64, command);
    }
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 2);
    fixture.write(0x64, 0xd1);
    assert_ne!(fixture.read(0x64) & 8, 0);
    fixture.write(0x60, 1);
    assert_eq!(fixture.read(0x64) & 8, 0);
    fixture.write(0x64, 0xd0);
    assert_eq!(fixture.read(0x60), 0x45);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 2);
    fixture.command_data(0xd1, 3);
    fixture.write(0x64, 0xd0);
    assert_eq!(fixture.read(0x60), 0x47);
    fixture.command_data(0xd1, 0);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 3);
}

// Test: Send keyboard identify, echo/resend, parameterized commands, defaults, and reset.
// Expected: Replies contain exactly the protocol bytes and staged parameters do not become commands.
#[test]
fn keyboard_commands_return_ordered_replies_and_consume_parameters() {
    let mut fixture = Fixture::new();
    fixture.write(0x60, 0xee);
    fixture.expect_keyboard_bytes(&[0xee]);
    fixture.write(0x60, 0xfe);
    fixture.expect_keyboard_bytes(&[0xee]);
    fixture.write(0x60, 0xf2);
    fixture.expect_keyboard_bytes(&[0xfa, 0xab, 0x41]);
    fixture.write(0x60, 0xed);
    fixture.expect_keyboard_bytes(&[0xfa]);
    fixture.write(0x60, 0xed);
    fixture.expect_keyboard_bytes(&[0xfa]);
    fixture.write(0x60, 7);
    fixture.expect_keyboard_bytes(&[0xfa]);
    for (command, parameter) in [
        (0xf0, 2),
        (0xf3, 0x20),
        (0xfb, 0x1e),
        (0xfc, 0x1e),
        (0xfd, 0x1e),
    ] {
        fixture.write(0x60, command);
        fixture.expect_keyboard_bytes(&[0xfa]);
        fixture.write(0x60, parameter);
        fixture.expect_keyboard_bytes(&[0xfa]);
    }
    for command in [0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa] {
        fixture.write(0x60, command);
        fixture.expect_keyboard_bytes(&[0xfa]);
    }
    fixture.write(0x60, 0xff);
    fixture.expect_keyboard_bytes(&[0xfa, 0xaa]);
    fixture.write(0x60, 0x01);
    fixture.expect_keyboard_bytes(&[0xfe]);
}

// Test: Queue more extended make/break scan codes than fit in the keyboard buffer.
// Expected: Repeated polls/refills preserve every prefix, scan-code byte, and key-up bit in order.
#[test]
fn keyboard_input_preserves_extended_scan_codes_across_buffer_refills() {
    let mut fixture = Fixture::new();
    let mut expected = Vec::new();
    for index in 0..30u16 {
        let code = if index % 3 == 0 {
            0x1e
        } else {
            0xe000 | (0x10 + index)
        };
        let make = index % 2 == 0;
        fixture.input.send(KeyboardData { code, make });
        if code > 0xff {
            expected.push(0xe0);
        }
        expected.push(code as u8 | if make { 0 } else { 0x80 });
    }
    for byte in expected {
        fixture.poll();
        assert_eq!(fixture.read(0x64) & 0x21, 1);
        assert!(fixture.irqs.0.lock()[1]);
        assert_eq!(fixture.read(0x60), byte);
    }
    fixture.poll();
    assert_eq!(fixture.read(0x64) & 1, 0);
    assert!(!fixture.irqs.0.lock()[1]);
}

// Test: Snapshot queued mouse/keyboard replies, reset the controller, and restore.
// Expected: Queued replies and source IRQs recover in order without losing or duplicating bytes.
#[test]
fn checkpoint_restores_device_reply_queues_and_interrupt_sources() {
    use vmcore::save_restore::SaveRestore;
    let mut fixture = Fixture::new();
    fixture.command_data(0xd4, 0xff);
    fixture.write(0x60, 0xf2);
    let saved = fixture.device.save().unwrap();
    block_on(fixture.device.reset());
    assert_eq!(fixture.read(0x64) & 1, 0);
    assert!(!fixture.irqs.0.lock()[1]);
    assert!(!fixture.irqs.0.lock()[12]);
    fixture.device.restore(saved).unwrap();
    for (index, byte) in [0xfa, 0xaa, 0, 0xfa, 0xab, 0x41].into_iter().enumerate() {
        let mouse = index < 3;
        assert_eq!(fixture.read(0x64) & 0x21, if mouse { 0x21 } else { 1 });
        assert_eq!(fixture.irqs.0.lock()[12], mouse);
        assert_eq!(fixture.irqs.0.lock()[1], !mouse);
        assert_eq!(fixture.read(0x60), byte);
    }
    assert_eq!(fixture.read(0x64) & 1, 0);
}

// Test: Snapshot each output source while a controller data command awaits its parameter.
// Expected: Restore recovers the output byte, IRQ source, RAM contents, and pending A20 command.
#[test]
fn checkpoint_restores_controller_output_ram_and_staged_data_command() {
    use vmcore::save_restore::SaveRestore;
    for (command, byte, irq) in [
        (0xd2, 0xa5, Some(1)),
        (0xd3, 0x5a, Some(12)),
        (0xaa, 0x55, None),
    ] {
        let mut fixture = Fixture::new();
        fixture.command_data(0x61, 0x91);
        if command == 0xaa {
            fixture.write(0x64, command);
        } else {
            fixture.command_data(command, byte);
        }
        fixture.write(0x64, 0xd1);
        let saved = fixture.device.save().unwrap();
        block_on(fixture.device.reset());
        fixture.device.restore(saved).unwrap();
        assert_eq!(fixture.irqs.0.lock()[1], irq == Some(1));
        assert_eq!(fixture.irqs.0.lock()[12], irq == Some(12));
        assert_eq!(fixture.read(0x60), byte);
        fixture.write(0x60, 1);
        fixture.write(0x64, 0xd0);
        assert_eq!(fixture.read(0x60) & 3, 1);
        fixture.write(0x64, 0x21);
        assert_eq!(fixture.read(0x60), 0x91);
    }
}

// Test: Snapshot a keyboard parameter phase or a pending auxiliary-device command.
// Expected: Restore preserves the destination and pending command, yielding the correct reply bytes.
#[test]
fn checkpoint_restores_pending_keyboard_and_mouse_parameter_phases() {
    use vmcore::save_restore::SaveRestore;
    for (port, command, parameter, expected) in [
        (0x60, 0xed, 7, &[0xfa][..]),
        (0x64, 0xd4, 0xff, &[0xfa, 0xaa, 0][..]),
    ] {
        let mut fixture = Fixture::new();
        fixture.write(port, command);
        if port == 0x60 {
            fixture.expect_keyboard_bytes(&[0xfa]);
        }
        let saved = fixture.device.save().unwrap();
        block_on(fixture.device.reset());
        fixture.device.restore(saved).unwrap();
        fixture.write(0x60, parameter);
        for &byte in expected {
            assert_eq!(
                fixture.read(0x64) & 0x21,
                if port == 0x64 { 0x21 } else { 1 }
            );
            assert_eq!(fixture.read(0x60), byte);
        }
        assert_eq!(fixture.read(0x64) & 1, 0);
    }
}

// Test: Access invalid i8042 ports and unsupported transfer sizes around a staged command.
// Expected: Invalid accesses return typed errors without changing the sentinel or staged reply.
#[test]
fn invalid_accesses_preserve_buffers_and_controller_command_phase() {
    let mut fixture = Fixture::new();
    fixture.write(0x64, 0xd2);
    let mut sentinel = [0xa5];
    assert!(matches!(
        fixture.device.io_read(0x61, &mut sentinel),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(sentinel, [0xa5]);
    assert!(matches!(
        fixture.device.io_write(0x61, &[0x81]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    for size in [0, 2, 4] {
        let mut data = vec![0x5a; size];
        assert!(matches!(
            fixture.device.io_read(0x60, &mut data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(data, vec![0x5a; size]);
        assert!(matches!(
            fixture.device.io_write(0x60, &data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    fixture.write(0x60, 0x81);
    fixture.expect_keyboard_bytes(&[0x81]);
}

// Test: Known product bug: mask keyboard interrupts while a keyboard byte is still pending.
// Expected: IRQ1 deasserts immediately while the unread byte remains available.
#[test]
#[ignore = "known product bug: command-byte writes do not resynchronize pending IRQs"]
fn known_bug_masking_interrupts_must_deassert_an_already_pending_keyboard_irq() {
    let mut fixture = Fixture::new();
    fixture.command_data(0xd2, 0xa5);
    assert!(fixture.irqs.0.lock()[1]);
    fixture.command_data(0x60, 0x40);
    assert!(!fixture.irqs.0.lock()[1]);
    assert_eq!(fixture.read(0x60), 0xa5);
}
