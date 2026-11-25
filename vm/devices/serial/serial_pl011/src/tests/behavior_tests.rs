// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vmcore::save_restore::SaveRestore;

// Test: Transfer one byte with FIFOs disabled and both RX and TX interrupts unmasked, then consume the returned byte and read the empty data register.
// Expected: A queued byte clears TX status; delivery asserts RX and TX, consuming it clears RX only, and the empty data register returns zero with both empty flags set.
#[test]
fn fifo_disabled_single_byte_transfer_acknowledges_receive_interrupt() {
    let mut backend = SerialIoMock::new();
    backend.pending_read_when_empty = true;
    let mut serial = SerialPl011::new(
        "single-byte-probe".into(),
        PL011_SERIAL0_BASE,
        LineInterrupt::detached(),
        Box::new(backend),
        None,
    )
    .unwrap();
    write(&mut serial, Register::UARTCR, 0x300);
    write(&mut serial, Register::UARTLCR_H, 0x60);
    write(&mut serial, Register::UARTIMSC, 0x30);
    write(&mut serial, Register::UARTCR, 0x301);
    write(&mut serial, Register::UARTDR, 0xa5);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0);
    serial.poll_device(&mut Context::from_waker(Waker::noop()));
    assert_eq!(read(&mut serial, Register::UARTMIS), 0x30);
    assert_eq!(read(&mut serial, Register::UARTDR), 0xa5);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0x20);
    assert_eq!(read(&mut serial, Register::UARTDR), 0);
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0x90);
}

// Test: Restore connected and disconnected snapshots against backends whose current connection state is the opposite.
// Expected: CTS/DSR/DCD flags describe the current backend, not stale snapshot state, and all three modem-change interrupt bits are visible to the guest.
#[test]
fn restore_reconciles_modem_flags_and_change_interrupts_with_current_backend() {
    for (saved_connected, current_connected) in [(true, false), (false, true)] {
        let make_serial = |connected| {
            let mut backend = SerialIoMock::new();
            backend.connected = connected;
            SerialPl011::new(
                "modem-restore-probe".into(),
                PL011_SERIAL0_BASE,
                LineInterrupt::detached(),
                Box::new(backend),
                None,
            )
            .unwrap()
        };
        let mut original = make_serial(saved_connected);
        write(&mut original, Register::UARTIMSC, 0x0e);
        write(&mut original, Register::UARTICR, 0x7ff);
        assert_eq!(read(&mut original, Register::UARTMIS), 0);
        assert_eq!(
            read(&mut original, Register::UARTFR) & 7,
            if saved_connected { 7 } else { 0 }
        );
        let snapshot = original.save().unwrap();
        let mut restored = make_serial(current_connected);
        restored.restore(snapshot).unwrap();
        assert_eq!(
            read(&mut restored, Register::UARTFR) & 7,
            if current_connected { 7 } else { 0 }
        );
        assert_eq!(read(&mut restored, Register::UARTMIS), 0x0e);
        write(&mut restored, Register::UARTICR, 0x0e);
        assert_eq!(read(&mut restored, Register::UARTMIS), 0);
    }
}

// Test: Prime an empty-space interrupt, queue bytes through each selected TX FIFO threshold, and drain through the host backend.
// Expected: TX status stays asserted through the threshold, clears one byte above it, reasserts after draining, and the backend echoes every queued byte in order.
#[test]
fn transmit_fifo_interrupts_follow_selected_occupancy_boundaries() {
    for (selection, threshold) in [4, 8, 16, 24, 28, 16, 16, 16].into_iter().enumerate() {
        let mut backend = SerialIoMock::new();
        backend.pending_read_when_empty = true;
        let mut serial = SerialPl011::new(
            "tx-threshold-probe".into(),
            PL011_SERIAL0_BASE,
            LineInterrupt::detached(),
            Box::new(backend),
            None,
        )
        .unwrap();
        write(&mut serial, Register::UARTCR, 0x300);
        write(&mut serial, Register::UARTLCR_H, 0x70);
        write(&mut serial, Register::UARTIFLS, selection as u16);
        write(&mut serial, Register::UARTIMSC, UARTINT_TX);
        write(&mut serial, Register::UARTCR, 0x301);
        write(&mut serial, Register::UARTDR, 0xa5);
        serial.poll_device(&mut Context::from_waker(Waker::noop()));
        assert_eq!(read(&mut serial, Register::UARTDR), 0xa5);
        for value in 0..threshold {
            assert_ne!(read(&mut serial, Register::UARTMIS) & UARTINT_TX, 0);
            write(&mut serial, Register::UARTDR, value);
        }
        assert_ne!(read(&mut serial, Register::UARTMIS) & UARTINT_TX, 0);
        write(&mut serial, Register::UARTDR, threshold);
        assert_eq!(read(&mut serial, Register::UARTMIS) & UARTINT_TX, 0);
        serial.poll_device(&mut Context::from_waker(Waker::noop()));
        assert_ne!(read(&mut serial, Register::UARTMIS) & UARTINT_TX, 0);
        for expected in 0..=threshold {
            assert_eq!(read(&mut serial, Register::UARTFR) & 0x10, 0);
            assert_eq!(read(&mut serial, Register::UARTDR), expected);
        }
        assert_ne!(read(&mut serial, Register::UARTFR) & 0x10, 0);
    }
}

// Test: Attempt to disable FIFO mode while the UART is enabled, then repeat after disabling the UART with RX and TX data queued.
// Expected: The enabled-UART write is ignored; the legal FIFO-disable transition clears both queues and exposes empty flags without replaying queued data.
#[test]
fn fifo_disable_requires_a_stopped_uart_and_discards_both_queues() {
    let mut serial = serial();
    write(&mut serial, Register::UARTCR, 0x300);
    write(&mut serial, Register::UARTLCR_H, 0x70);
    write(&mut serial, Register::UARTCR, 0x381);
    write(&mut serial, Register::UARTDR, 0x81);
    write(&mut serial, Register::UARTCR, 0x301);
    write(&mut serial, Register::UARTDR, 0xa5);
    write(&mut serial, Register::UARTLCR_H, 0x60);
    assert_eq!(read(&mut serial, Register::UARTLCR_H), 0x70);
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0);
    write(&mut serial, Register::UARTCR, 0x300);
    write(&mut serial, Register::UARTLCR_H, 0x60);
    assert_eq!(read(&mut serial, Register::UARTLCR_H), 0x60);
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0x90);
    write(&mut serial, Register::UARTCR, 0x301);
    serial.poll_device(&mut Context::from_waker(Waker::noop()));
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0x90);
}

// Test: Fail one host write, then send another batch after the backend recovers.
// Expected: Failed output is dropped with TX-empty notification, never appears as echoed input, and only the later successful batch returns in order.
#[test]
fn host_write_error_drops_only_the_failed_batch_and_allows_later_output() {
    let mut backend = SerialIoMock::with_write_error(ErrorKind::PermissionDenied);
    backend.pending_read_when_empty = true;
    let mut serial = SerialPl011::new(
        "write-failure-probe".into(),
        PL011_SERIAL0_BASE,
        LineInterrupt::detached(),
        Box::new(backend),
        None,
    )
    .unwrap();
    write(&mut serial, Register::UARTIMSC, UARTINT_TX);
    write(&mut serial, Register::UARTICR, 0x7ff);
    for byte in b"failed" {
        write(&mut serial, Register::UARTDR, u16::from(*byte));
    }
    serial.poll_device(&mut Context::from_waker(Waker::noop()));
    assert_ne!(read(&mut serial, Register::UARTMIS) & UARTINT_TX, 0);
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0x90);
    for byte in b"ok" {
        write(&mut serial, Register::UARTDR, u16::from(*byte));
    }
    serial.poll_device(&mut Context::from_waker(Waker::noop()));
    for expected in b"ok" {
        assert_eq!(read(&mut serial, Register::UARTFR) & 0x10, 0);
        assert_eq!(read(&mut serial, Register::UARTDR), u16::from(*expected));
    }
    assert_eq!(read(&mut serial, Register::UARTFR) & 0x90, 0x90);
}

fn serial() -> SerialPl011 {
    SerialPl011::new(
        "snapshot-probe".into(),
        PL011_SERIAL0_BASE,
        LineInterrupt::detached(),
        Box::new(SerialIoMock::new()),
        None,
    )
    .unwrap()
}

// Test: Select each receive FIFO interrupt threshold and fill loopback data to one byte below and then exactly at the boundary.
// Expected: Masked RX status asserts only at the selected threshold and clears after a guest read drops occupancy below it, preserving the first byte.
#[test]
fn receive_fifo_interrupts_follow_selected_occupancy_boundaries() {
    for (selection, threshold) in [4, 8, 16, 24, 28, 16, 16, 16].into_iter().enumerate() {
        let mut serial = serial();
        write(&mut serial, Register::UARTCR, 0x300);
        write(&mut serial, Register::UARTLCR_H, 0x70);
        write(&mut serial, Register::UARTIFLS, (selection as u16) << 3);
        write(&mut serial, Register::UARTIMSC, 0x10);
        write(&mut serial, Register::UARTICR, 0x7ff);
        write(&mut serial, Register::UARTCR, 0x381);
        for value in 0..threshold - 1 {
            write(&mut serial, Register::UARTDR, value);
            assert_eq!(read(&mut serial, Register::UARTMIS) & 0x10, 0);
        }
        write(&mut serial, Register::UARTDR, threshold - 1);
        assert_eq!(read(&mut serial, Register::UARTMIS) & 0x10, 0x10);
        assert_eq!(read(&mut serial, Register::UARTDR), 0);
        assert_eq!(read(&mut serial, Register::UARTMIS) & 0x10, 0);
    }
}

// Test: Save nondefault MMIO registers, pending baud changes, received loopback bytes, and unsent host output, then restore into a fresh UART.
// Expected: Committed and pending baud values remain distinct until LCR commits them, register values survive, and both FIFOs retain exact byte order.
#[test]
fn snapshot_preserves_registers_pending_baud_and_both_fifo_contents() {
    let mut original = serial();
    write(&mut original, Register::UARTCR, 0x300);
    for (register, value) in [
        (Register::UARTILPR, 0x7d),
        (Register::UARTIBRD, 0x1234),
        (Register::UARTFBRD, 0x2a),
        (Register::UARTLCR_H, 0x70),
        (Register::UARTIFLS, 0x13),
        (Register::UARTIMSC, 0x7ff),
        (Register::UARTDMACR, 3),
        (Register::UARTCR, 0x381),
    ] {
        write(&mut original, register, value);
    }
    for byte in [0, 0x81, 0xff] {
        write(&mut original, Register::UARTDR, byte);
    }
    write(&mut original, Register::UARTCR, 0x301);
    for byte in [10, 20, 30, 40] {
        write(&mut original, Register::UARTDR, byte);
    }
    write(&mut original, Register::UARTIBRD, 0x4321);
    write(&mut original, Register::UARTFBRD, 0x15);
    let snapshot = original.save().unwrap();
    drop(original);
    let mut restored = serial();
    restored.restore(snapshot).unwrap();
    for (register, expected) in [
        (Register::UARTILPR, 0x7d),
        (Register::UARTIBRD, 0x1234),
        (Register::UARTFBRD, 0x2a),
        (Register::UARTLCR_H, 0x70),
        (Register::UARTCR, 0x301),
        (Register::UARTIFLS, 0x13),
        (Register::UARTIMSC, 0x7ff),
        (Register::UARTDMACR, 3),
    ] {
        assert_eq!(read(&mut restored, register), expected, "{register:?}");
    }
    write(&mut restored, Register::UARTCR, 0x300);
    write(&mut restored, Register::UARTLCR_H, 0x70);
    write(&mut restored, Register::UARTCR, 0x301);
    assert_eq!(read(&mut restored, Register::UARTIBRD), 0x4321);
    assert_eq!(read(&mut restored, Register::UARTFBRD), 0x15);
    for expected in [0, 0x81, 0xff] {
        assert_eq!(read(&mut restored, Register::UARTFR) & 0x10, 0);
        assert_eq!(read(&mut restored, Register::UARTDR), expected);
    }
    assert_ne!(read(&mut restored, Register::UARTFR) & 0x10, 0);
    restored.poll_device(&mut Context::from_waker(Waker::noop()));
    for expected in [10, 20, 30, 40] {
        assert_eq!(read(&mut restored, Register::UARTFR) & 0x10, 0);
        assert_eq!(read(&mut restored, Register::UARTDR), expected);
    }
    assert_ne!(read(&mut restored, Register::UARTFR) & 0x10, 0);
}

// Test: Mask and unmask pending receive sources, selectively acknowledge RX, then consume the queued byte.
// Expected: Masking preserves raw status/data, another pending source holds IRQ high after acknowledgement, and draining data lowers IRQ.
#[test]
fn interrupt_masking_and_selective_acknowledgment_preserve_pending_receive_data() {
    let target = vmcore::line_interrupt::test_helpers::TestLineInterruptTarget::new_arc();
    let mut serial = SerialPl011::new(
        "interrupt-lifecycle".into(),
        PL011_SERIAL0_BASE,
        LineInterrupt::new_with_target("uart", target.clone(), 42),
        Box::new(SerialIoMock::new()),
        None,
    )
    .unwrap();
    write(&mut serial, Register::UARTCR, 0x300);
    write(&mut serial, Register::UARTLCR_H, 0x60);
    write(&mut serial, Register::UARTIMSC, 0);
    write(&mut serial, Register::UARTICR, 0x7ff);
    write(&mut serial, Register::UARTCR, 0x381);
    write(&mut serial, Register::UARTDR, 0x81);
    assert_eq!(read(&mut serial, Register::UARTRIS) & 0x50, 0x50);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0);
    assert!(!target.is_high(42));
    write(&mut serial, Register::UARTIMSC, 0x50);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0x50);
    assert!(target.is_high(42));
    write(&mut serial, Register::UARTICR, 0x10);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0x40);
    assert!(target.is_high(42));
    write(&mut serial, Register::UARTIMSC, 0);
    assert!(!target.is_high(42));
    assert_eq!(read(&mut serial, Register::UARTRIS) & 0x50, 0x40);
    write(&mut serial, Register::UARTIMSC, 0x40);
    assert!(target.is_high(42));
    assert_eq!(read(&mut serial, Register::UARTDR), 0x81);
    assert_eq!(read(&mut serial, Register::UARTMIS), 0);
    assert_eq!(read(&mut serial, Register::UARTRIS) & 0x50, 0);
    assert!(!target.is_high(42));
    assert_ne!(read(&mut serial, Register::UARTFR) & 0x10, 0);
}
