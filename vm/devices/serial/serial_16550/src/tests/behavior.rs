// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::MockBackend;
use super::poll_serial;
use crate::*;
use test_with_tracing::test;
use vmcore::line_interrupt::test_helpers::TestLineInterruptTarget;
use vmcore::save_restore::SaveRestore;

fn new_serial(backend: impl SerialIo + 'static) -> Serial16550 {
    Serial16550::new(
        "test".into(),
        MmioOrIoPort::IoPort(0x3f8),
        1,
        LineInterrupt::detached(),
        Box::new(backend),
        false,
        None,
    )
    .unwrap()
}

fn read(serial: &mut Serial16550, register: u16) -> u8 {
    let mut value = [0];
    serial
        .supports_pio()
        .unwrap()
        .io_read(0x3f8 + register, &mut value)
        .unwrap();
    value[0]
}

fn write(serial: &mut Serial16550, register: u16, value: u8) {
    serial
        .supports_pio()
        .unwrap()
        .io_write(0x3f8 + register, &[value])
        .unwrap();
}

// Test: Access MMIO scratch registers at every supported stride and at unaligned addresses.
// Expected: Only the low byte is significant; invalid accesses preserve the register.
#[test]
fn mmio_strides_zero_extend_and_reject_unaligned_access() {
    for width in [1, 2, 4, 8] {
        let mut serial = Serial16550::new(
            "mmio".into(),
            MmioOrIoPort::Mmio(0x1000),
            width,
            LineInterrupt::detached(),
            Box::new(serial_core::disconnected::Disconnected),
            false,
            None,
        )
        .unwrap();
        assert!(serial.supports_pio().is_none());
        let mmio = serial.supports_mmio().unwrap();
        assert_eq!(
            mmio.get_static_regions(),
            &[("registers", 0x1000..=0x1000 + u64::from(width) * 8 - 1)]
        );
        let address = 0x1000 + u64::from(width) * 7;
        mmio.mmio_write(address, &[0x5a; 8][..usize::from(width)])
            .unwrap();
        let mut bytes = vec![0xff; usize::from(width)];
        mmio.mmio_read(address, &mut bytes).unwrap();
        assert_eq!(bytes[0], 0x5a);
        assert!(bytes[1..].iter().all(|&byte| byte == 0));
        if width > 1 {
            assert!(matches!(
                mmio.mmio_read(address + 1, &mut bytes),
                IoResult::Err(IoError::UnalignedAccess)
            ));
            assert!(matches!(
                mmio.mmio_write(address + 1, &[0x33]),
                IoResult::Err(IoError::UnalignedAccess)
            ));
            mmio.mmio_read(address, &mut bytes).unwrap();
            assert_eq!(bytes[0], 0x5a);
        }
    }
}

// Test: Construct UARTs with unsupported register widths or misaligned register banks.
// Expected: Typed configuration errors identify the rejected width or base address.
#[test]
fn invalid_register_banks_report_configuration_errors() {
    for (base, width) in [
        (MmioOrIoPort::Mmio(0x1000), 0),
        (MmioOrIoPort::Mmio(0x1000), 3),
        (MmioOrIoPort::Mmio(0x1000), 16),
        (MmioOrIoPort::IoPort(0x3f8), 2),
    ] {
        let result = Serial16550::new(
            "invalid".into(),
            base,
            width,
            LineInterrupt::detached(),
            Box::new(serial_core::disconnected::Disconnected),
            false,
            None,
        );
        assert!(
            matches!(result, Err(ConfigurationError::InvalidRegisterWidth(actual)) if actual == width)
        );
    }
    for (base, address) in [
        (MmioOrIoPort::IoPort(0x3f9), 0x3f9),
        (MmioOrIoPort::Mmio(0x1001), 0x1001),
    ] {
        let result = Serial16550::new(
            "invalid".into(),
            base,
            1,
            LineInterrupt::detached(),
            Box::new(serial_core::disconnected::Disconnected),
            false,
            None,
        );
        assert!(
            matches!(result, Err(ConfigurationError::UnalignedBaseAddress(actual)) if actual == address)
        );
    }
}

// Test: Save banked registers and both pending byte streams, then restore to a new UART.
// Expected: The new guest and backend see the same settings, receive bytes and queued output.
#[pal_async::async_test]
async fn save_restore_preserves_registers_and_pending_streams() {
    let (backend, handle) = MockBackend::new();
    let mut serial = new_serial(backend);
    assert!(serial.supports_mmio().is_none());
    assert_eq!(
        serial.supports_pio().unwrap().get_static_regions(),
        &[("registers", 0x3f8..=0x3ff)]
    );
    handle.inject_rx(b"rx");
    poll_serial(&mut serial).await;
    for byte in b"tx" {
        write(&mut serial, 0, *byte);
    }
    write(&mut serial, 3, 0x83);
    write(&mut serial, 0, 0x34);
    write(&mut serial, 1, 0x12);
    write(&mut serial, 3, 0x03);
    write(&mut serial, 1, 0xf5);
    write(&mut serial, 4, 0x0b);
    write(&mut serial, 2, 0x81);
    write(&mut serial, 7, 0x56);
    let snapshot = serial.save().unwrap();
    let (backend, restored_handle) = MockBackend::new();
    let mut restored = new_serial(backend);
    restored.restore(snapshot).unwrap();
    assert_eq!(read(&mut restored, 3), 0x03);
    assert_eq!(read(&mut restored, 1), 0x05);
    assert_eq!(read(&mut restored, 4), 0x0b);
    assert_eq!(read(&mut restored, 7), 0x56);
    write(&mut restored, 3, 0x83);
    assert_eq!(read(&mut restored, 0), 0x34);
    assert_eq!(read(&mut restored, 1), 0x12);
    write(&mut restored, 3, 0x03);
    assert_eq!(read(&mut restored, 0), b'r');
    assert_eq!(read(&mut restored, 0), b'x');
    poll_serial(&mut restored).await;
    assert_eq!(restored_handle.state.lock().written, b"tx");

    let mut disconnected = new_serial(serial_core::disconnected::Disconnected);
    disconnected.restore(serial.save().unwrap()).unwrap();
    assert_eq!(read(&mut disconnected, 6) & 0xf0, 0);
    disconnected.start();
    disconnected.stop().await;
    disconnected.reset().await;
    for (register, expected) in [(0, 0), (1, 0), (3, 0), (4, 0), (5, 0x60), (7, 0xff)] {
        assert_eq!(read(&mut disconnected, register), expected);
    }
}

// Test: Write the software-reset register with unread input and programmed divisor latches.
// Expected: Control settings reset, while baud rate, scratch and unread input survive.
#[pal_async::async_test]
async fn software_reset_preserves_divisor_scratch_and_input() {
    let (backend, handle) = MockBackend::new();
    let mut serial = new_serial(backend);
    handle.inject_rx(b"R");
    poll_serial(&mut serial).await;
    write(&mut serial, 3, 0x80);
    write(&mut serial, 0, 0x78);
    write(&mut serial, 1, 0x56);
    write(&mut serial, 3, 3);
    write(&mut serial, 7, 0xab);
    write(&mut serial, 1, 0x0f);
    write(&mut serial, 4, 0x0b);
    write(&mut serial, 5, 0);
    assert_eq!(read(&mut serial, 3), 0);
    assert_eq!(read(&mut serial, 1), 0);
    assert_eq!(read(&mut serial, 4), 0);
    assert_eq!(read(&mut serial, 7), 0xab);
    write(&mut serial, 3, 0x80);
    assert_eq!(read(&mut serial, 0), 0x78);
    assert_eq!(read(&mut serial, 1), 0x56);
    write(&mut serial, 3, 0);
    assert_eq!(read(&mut serial, 0), b'R');
    poll_serial(&mut serial).await;
    assert_eq!(read(&mut serial, 5), 0x60);
    assert_eq!(read(&mut serial, 6) & 0xf0, 0xb0);
}

// IGNORED: Software reset lowers carrier before pending output drains. The next
//          poll drops the preserved transmit buffer even though the backend is connected.
// Test: Reset the UART registers while an output byte is waiting for the connected backend.
// Expected: Software reset preserves the queued byte, and the backend receives it exactly once.
#[pal_async::async_test]
#[ignore = "software reset drops pending output before reconnecting the backend"]
async fn software_reset_preserves_pending_output() {
    let (backend, handle) = MockBackend::new();
    let mut serial = new_serial(backend);
    write(&mut serial, 0, b'T');
    write(&mut serial, 5, 0);
    poll_serial(&mut serial).await;
    assert_eq!(handle.state.lock().written, b"T");
}

// Test: Combine loopback overrun, receive, transmitter-empty and modem interrupts.
// Expected: Interrupt priority, acknowledgement and OUT2 gating match guest-visible registers.
#[test]
fn interrupt_priority_acknowledgement_and_modem_loopback() {
    let target = TestLineInterruptTarget::new_arc();
    let (backend, _) = MockBackend::new();
    let mut serial = Serial16550::new(
        "irq".into(),
        MmioOrIoPort::IoPort(0x3f8),
        1,
        LineInterrupt::new_with_target("uart", target.clone(), 4),
        Box::new(backend),
        false,
        None,
    )
    .unwrap();
    write(&mut serial, 1, 2);
    assert!(!target.is_high(4));
    write(&mut serial, 4, 8);
    assert!(target.is_high(4));
    assert_eq!(read(&mut serial, 2), 2);
    assert!(!target.is_high(4));
    write(&mut serial, 4, 0x18);
    read(&mut serial, 6);
    write(&mut serial, 1, 0x0f);
    write(&mut serial, 0, b'A');
    write(&mut serial, 0, b'B');
    assert!(target.is_high(4));
    assert_eq!(read(&mut serial, 2), 6);
    assert_eq!(read(&mut serial, 5) & 3, 3);
    assert_eq!(read(&mut serial, 2), 4);
    assert_eq!(read(&mut serial, 0), b'A');
    write(&mut serial, 2, 3);
    assert_eq!(read(&mut serial, 2), 0xc2);
    assert_eq!(read(&mut serial, 2), 0xc1);
    assert!(!target.is_high(4));
    write(&mut serial, 4, 0x1f);
    assert!(target.is_high(4));
    assert_eq!(read(&mut serial, 2), 0xc0);
    assert_eq!(read(&mut serial, 6) & 0xf0, 0xf0);
    write(&mut serial, 4, 0x18);
    let status = read(&mut serial, 6);
    assert_eq!(status & 0xf0, 0x80);
    assert_ne!(status & 4, 0);
    assert_eq!(read(&mut serial, 6) & 0x0f, 0);
    assert!(!target.is_high(4));
}

// Test: Fill a loopback FIFO to each selectable receive-interrupt threshold.
// Expected: Subthreshold bytes report timeout, the threshold reports data, and clear removes it.
#[test]
fn fifo_thresholds_and_clear_are_observable_in_interrupt_identification() {
    for (selection, threshold) in [1, 4, 8, 14].into_iter().enumerate() {
        let (backend, _) = MockBackend::new();
        let mut serial = new_serial(backend);
        write(&mut serial, 4, 0x18);
        write(&mut serial, 1, 1);
        write(&mut serial, 2, 1 | (selection as u8) << 6);
        write(&mut serial, 0, 0x40);
        assert_eq!(
            read(&mut serial, 2),
            if threshold == 1 { 0xc4 } else { 0xcc }
        );
        for value in 1..threshold {
            write(&mut serial, 0, value);
        }
        assert_eq!(read(&mut serial, 2), 0xc4);
        write(&mut serial, 2, 7);
        assert_eq!(read(&mut serial, 2), 0xc1);
        assert_eq!(read(&mut serial, 5) & 1, 0);
        write(&mut serial, 2, 0);
        assert_eq!(read(&mut serial, 2), 1);
    }
}

// Test: Hold hardware flow control closed, then assert DTR and RTS together.
// Expected: Backend input is withheld until both lines are set and then arrives in order.
#[pal_async::async_test]
async fn receive_flow_control_requires_both_dtr_and_rts() {
    let (backend, handle) = MockBackend::new();
    let mut serial = Serial16550::new(
        "flow".into(),
        MmioOrIoPort::IoPort(0x3f8),
        1,
        LineInterrupt::detached(),
        Box::new(backend),
        true,
        None,
    )
    .unwrap();
    handle.inject_rx(b"hello");
    for modem_control in [0, 1, 2] {
        write(&mut serial, 4, modem_control);
        poll_serial(&mut serial).await;
        assert_eq!(read(&mut serial, 5) & 1, 0);
    }
    write(&mut serial, 4, 3);
    poll_serial(&mut serial).await;
    for byte in b"hello" {
        assert_eq!(read(&mut serial, 5) & 1, 1);
        assert_eq!(read(&mut serial, 0), *byte);
    }
    assert_eq!(read(&mut serial, 5) & 1, 0);
}

// Test: Mask a full receive FIFO, inspect status, then unmask and drain it
//       across the receive-data/timeout interrupt boundary.
// Expected: Masking and IIR/LSR reads preserve the bytes; unmasking reasserts
//       IRQ, which stays high until the last byte is consumed.
#[test]
fn receive_masking_and_status_reads_preserve_fifo_until_drained() {
    let target = TestLineInterruptTarget::new_arc();
    let (backend, _) = MockBackend::new();
    let mut serial = Serial16550::new(
        "rx".into(),
        MmioOrIoPort::IoPort(0x3f8),
        1,
        LineInterrupt::new_with_target("uart", target.clone(), 4),
        Box::new(backend),
        false,
        None,
    )
    .unwrap();
    write(&mut serial, 4, 0x18);
    write(&mut serial, 2, 0x41);
    write(&mut serial, 1, 1);
    let payload = [0, 0x7f, 0x80, 0xff];
    for &byte in &payload {
        write(&mut serial, 0, byte);
    }
    assert_eq!(read(&mut serial, 2), 0xc4);
    assert!(target.is_high(4));

    write(&mut serial, 1, 0);
    assert!(!target.is_high(4));
    assert_eq!(read(&mut serial, 2), 0xc1);
    assert_eq!(read(&mut serial, 5) & 1, 1);
    write(&mut serial, 1, 1);
    assert!(target.is_high(4));
    for (index, &byte) in payload.iter().enumerate() {
        let expected = if index == 0 { 0xc4 } else { 0xcc };
        assert_eq!(read(&mut serial, 2), expected);
        assert_eq!(read(&mut serial, 5) & 1, 1);
        assert_eq!(read(&mut serial, 2), expected);
        assert!(target.is_high(4));
        assert_eq!(read(&mut serial, 0), byte);
    }
    assert_eq!(read(&mut serial, 2), 0xc1);
    assert_eq!(read(&mut serial, 5) & 1, 0);
    assert!(!target.is_high(4));
}
