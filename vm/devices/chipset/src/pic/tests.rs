// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::pio::ExternallyManagedPortIoIntercepts;
use chipset_device::pio::PortIoIntercept;
use futures::executor::block_on;
use test_with_tracing::test;
use vmcore::line_interrupt::test_helpers::TestLineInterruptTarget;
use vmcore::save_restore::SaveRestore;

const IV_BASE: u8 = 0x30;

fn read_port(pic: &mut DualPic, port: u16) -> u8 {
    let mut value = [0];
    pic.supports_pio()
        .unwrap()
        .io_read(port, &mut value)
        .unwrap();
    value[0]
}

// Test: Apply the Hyper-V paired command write at either PIC's command port.
// Expected: The byte for each controller selects its own IRR/ISR register regardless of port order.
#[test]
fn paired_command_writes_preserve_primary_and_secondary_ordering() {
    for port in [0x20, 0xa0] {
        let (_, mut pic) = create_pic();
        pic.set_irq(1, true);
        pic.set_irq(9, true);
        let command = if port == 0x20 {
            [0x0a, 0x0b]
        } else {
            [0x0b, 0x0a]
        };
        pic.io_write(port, &command).unwrap();
        assert_eq!(read_port(&mut pic, 0x20), 0x06);
        assert_eq!(read_port(&mut pic, 0xa0), 0);
        assert_eq!(pic.acknowledge_interrupt(), Some(0x31));
        let command = if port == 0x20 {
            [0x0b, 0x0a]
        } else {
            [0x0a, 0x0b]
        };
        pic.io_write(port, &command).unwrap();
        assert_eq!(read_port(&mut pic, 0x20), 0x02);
        assert_eq!(read_port(&mut pic, 0xa0), 0x02);
    }
}

// Test: Checkpoint before initialization and after each primary-PIC initialization word.
// Expected: Restoring resumes the next word correctly and delivers the configured interrupt vector.
#[test]
fn checkpoint_resumes_every_initialization_phase() {
    let initialization = [(0x20, 0x11), (0x21, 0x50), (0x21, 0x04), (0x21, 0x01)];
    for completed in 0..=initialization.len() {
        let (ready, mut pic) = create_pic();
        block_on(pic.reset());
        for &(port, value) in &initialization[..completed] {
            pic.io_write(port, &[value]).unwrap();
        }
        let saved = pic.save().unwrap();
        block_on(pic.reset());
        pic.restore(saved).unwrap();
        for &(port, value) in &initialization[completed..] {
            pic.io_write(port, &[value]).unwrap();
        }
        pic.supports_line_interrupt_target()
            .unwrap()
            .set_irq(1, true);
        assert!(ready(), "initialization phase {completed}");
        assert_eq!(
            pic.supports_acknowledge_pic_interrupt()
                .unwrap()
                .acknowledge_interrupt(),
            Some(0x51)
        );
        assert!(!ready());
    }
}

// Test: Write distinct interrupt masks and ELCR values to both controllers before a checkpoint.
// Expected: Each port reads its own value, masked IRQs stay quiet, and unmasking delivers the request.
#[test]
fn mask_and_elcr_registers_restore_independently_for_both_banks() {
    let (ready, mut pic) = create_pic();
    let registers = [(0x21, 0x02), (0xa1, 0x40), (0x4d0, 0x80), (0x4d1, 0x08)];
    for (port, value) in registers {
        pic.io_write(port, &[value]).unwrap();
        assert_eq!(read_port(&mut pic, port), value);
    }
    let saved = pic.save().unwrap();
    block_on(pic.reset());
    pic.restore(saved).unwrap();
    for (port, value) in registers {
        assert_eq!(read_port(&mut pic, port), value);
    }
    pic.set_irq(1, true);
    assert!(!ready());
    pic.io_write(0x21, &[0]).unwrap();
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(0x31));
    assert_eq!(pic.valid_lines(), &[0..=1, 3..=15]);
}

// Test: Issue invalid PIC reads and writes while a valid interrupt is waiting.
// Expected: Typed access errors preserve destination buffers, masks, and the pending interrupt.
#[test]
fn invalid_accesses_do_not_consume_pending_interrupts_or_change_masks() {
    let (ready, mut pic) = create_pic();
    pic.set_irq(1, true);
    for size in [0, 2, 4, 8] {
        let mut bytes = vec![0xa5; size];
        assert!(matches!(
            pic.io_read(0x20, &mut bytes),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(bytes, vec![0xa5; size]);
        assert!(matches!(
            pic.io_write(0x21, &vec![0xff; size]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(read_port(&mut pic, 0x21), 0);
    }
    for port in [0, 0x22, 0xa2, 0x4d2, u16::MAX] {
        let mut value = [0xa5];
        assert!(matches!(
            pic.io_read(port, &mut value),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert_eq!(value, [0xa5]);
        assert!(matches!(
            pic.io_write(port, &[0xff]),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(0x31));
}

// Test: Read command ports without a read selector, then poll both controllers with no request.
// Expected: Unselected reads are zero and empty polls report the spurious line without raising ready.
#[test]
fn unselected_and_spurious_poll_reads_leave_ready_deasserted() {
    let (ready, mut pic) = create_pic();
    for port in [0x20, 0xa0] {
        assert_eq!(read_port(&mut pic, port), 0);
        pic.io_write(port, &[0x0c]).unwrap();
        assert_eq!(read_port(&mut pic, port), 7);
        assert!(!ready());
    }
    assert_eq!(pic.acknowledge_interrupt(), None);
}

#[test]
fn priority_masks_and_non_specific_eoi() {
    let mut pic = Pic::new(true);
    pic.lines = u8::MAX;
    pic.line_low_latch = u8::MAX;
    for isr in 0..=u8::MAX {
        pic.isr = isr;
        let first = (0..8).find(|&irq| isr & (1 << irq) != 0);
        let expected = ((1u16 << first.unwrap_or(8)) - 1) as u8;
        assert_eq!(pic.ready_vec(), expected, "ISR {isr:#x}");
        assert_eq!(pic.pending_line(), (expected != 0).then_some(0));

        pic.eoi(None);
        let serviced = first.map_or(0, |irq| 1 << irq);
        assert_eq!(pic.isr, isr & !serviced, "ISR {isr:#x}");
    }
}

pub(super) fn create_pic() -> (impl Fn() -> bool, DualPic) {
    let ready = TestLineInterruptTarget::new_arc();
    let mut pic = DualPic::new(
        LineInterrupt::new_with_target("ready", ready.clone(), 0),
        &mut ExternallyManagedPortIoIntercepts,
    );

    // Initialization sequence copied by logging what Linux Direct does:
    pic.io_write(0x20, &[0x11]).unwrap();
    pic.io_write(0x21, &[IV_BASE]).unwrap(); // Primary ICW2
    pic.io_write(0x21, &[0x04]).unwrap();
    pic.io_write(0x21, &[0x01]).unwrap();
    pic.io_write(0xa0, &[0x11]).unwrap();
    pic.io_write(0xa1, &[IV_BASE + 8]).unwrap(); // Secondary ICW2
    pic.io_write(0xa1, &[0x02]).unwrap();
    pic.io_write(0xa1, &[0x01]).unwrap();

    (move || ready.is_high(0), pic)
}

fn send_eoi(pic: &mut DualPic, consts: PicTestConstants) {
    let (v, _) = consts;
    match v {
        0..=7 => pic
            .io_write(
                PRIMARY_PIC_COMMAND_PORT,
                &[Ocw2::new().with_eoi(true).with_sl(true).with_level(v).0],
            )
            .unwrap(),
        8..=15 => {
            pic.io_write(
                PRIMARY_PIC_COMMAND_PORT,
                &[Ocw2::new()
                    .with_eoi(true)
                    .with_sl(true)
                    .with_level(PIC_CHAIN_COMMUNICATION_IRQ)
                    .0],
            )
            .unwrap();
            pic.io_write(
                SECONDARY_PIC_COMMAND_PORT,
                &[Ocw2::new().with_eoi(true).with_sl(true).with_level(v - 8).0],
            )
            .unwrap();
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_create_pic() {
    let (ready, pic) = create_pic();
    assert!(matches!(pic.pics[0].init, InitStage::Initialized));
    assert!(matches!(pic.pics[1].init, InitStage::Initialized));
    assert!(!ready());
}

#[test]
fn test_poll_read_primary_lowers_ready() {
    let (ready, mut pic) = create_pic();
    pic.set_irq(1, true);
    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    assert!(ready());

    let mut data = [0];
    pic.io_read(PRIMARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x81);
    assert_eq!(pic.pics[0].isr, 1 << 1);
    assert!(!pic.pics[0].interrupt_pending());
    assert!(!ready());
}

#[test]
fn test_poll_read_secondary_lowers_cascade() {
    let (ready, mut pic) = create_pic();
    let cascade = 1 << PIC_CHAIN_COMMUNICATION_IRQ;
    pic.set_irq(9, true);
    assert!(ready());

    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    let mut data = [0];
    pic.io_read(PRIMARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x80 | PIC_CHAIN_COMMUNICATION_IRQ);

    pic.io_write(SECONDARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    assert_ne!(pic.pics[0].lines & cascade, 0);
    assert_eq!(pic.pics[0].line_low_latch & cascade, 0);

    pic.io_read(SECONDARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x81);
    assert_eq!(pic.pics[1].isr, 1 << 1);
    assert!(!pic.pics[1].interrupt_pending());
    assert_eq!(pic.pics[0].lines & cascade, 0);
    assert_ne!(pic.pics[0].line_low_latch & cascade, 0);
    assert!(!ready());
}

// (Vector, pics index)
type PicTestConstants = (u8, usize);
const PRIMARY: PicTestConstants = (0, 0);
const SECONDARY: PicTestConstants = (8, 1);

#[test]
fn test_edge_interrupt_primary() {
    test_edge_interrupt(PRIMARY);
}

#[test]
fn test_edge_interrupt_secondary() {
    test_edge_interrupt(SECONDARY);
}

fn test_edge_interrupt(consts: PicTestConstants) {
    let (ready, mut pic) = create_pic();
    let (v, i) = consts;

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);
    pic.set_irq(v, false);
    assert!(pic.pics[i].irr() == 0b0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert!(pic.pics[i].irr() == 0);
    assert!(pic.pics[i].isr == 0b1);

    send_eoi(&mut pic, consts);

    assert!(pic.pics[i].irr() == 0);
    assert!(pic.pics[i].isr == 0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(pic.pics[i].irr() == 0b0);
    pic.set_irq(v, false);
    pic.set_irq(v, true);
    assert!(pic.pics[i].irr() == 0b1);
    assert!(ready());

    pic.set_irq(v, false);
    assert!(pic.pics[i].irr() == 0b0);
}

#[test]
fn test_level_interrupts_primary() {
    test_level_interrupts(PRIMARY);
}

#[test]
fn test_level_interrupts_secondary() {
    test_level_interrupts(SECONDARY);
}

fn test_level_interrupts(consts: PicTestConstants) {
    let (ready, mut pic) = create_pic();
    let (v, i) = consts;

    pic.io_write(
        match i {
            0 => PRIMARY_PIC_ELCR_PORT,
            1 => SECONDARY_PIC_ELCR_PORT,
            _ => unreachable!(),
        },
        &[0b1],
    )
    .unwrap();

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);
    pic.set_irq(v, false);
    assert!(pic.pics[i].irr() == 0b0);
    let pending = pic.acknowledge_interrupt();

    // No spurious interrupt is possible with the current interface.
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert!(pic.pics[i].irr() == 0b1);
    assert!(pic.pics[i].isr == 0b1);

    send_eoi(&mut pic, consts);
    assert!(pic.pics[i].irr() == 0b1);
    assert!(pic.pics[i].isr == 0);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    pic.set_irq(v, false);
    send_eoi(&mut pic, consts);
    assert!(pic.pics[i].irr() == 0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());
}

#[test]
fn test_multiple_edge_interrupt_primary() {
    test_multiple_edge_interrupt(PRIMARY);
}

#[test]
fn test_multiple_edge_interrupt_secondary() {
    test_multiple_edge_interrupt(SECONDARY);
}

fn test_multiple_edge_interrupt(consts: PicTestConstants) {
    let (ready, mut pic) = create_pic();
    let (v, i) = consts;

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);
    pic.set_irq(v, false);
    assert!(pic.pics[i].irr() == 0b0);

    pic.set_irq(v + 1, true);
    assert!(pic.pics[i].irr() == 0b10);
    pic.set_irq(v + 1, false);
    assert!(pic.pics[i].irr() == 0b00);

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert!(pic.pics[i].irr() == 0b1);
    pic.set_irq(v + 1, true);
    assert!(pic.pics[i].irr() == 0b11);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert!(pic.pics[i].irr() == 0b10);
    assert!(pic.pics[i].isr == 0b01);

    send_eoi(&mut pic, consts);
    assert!(pic.pics[i].irr() == 0b10);
    assert!(pic.pics[i].isr == 0b00);
    assert!(ready());
    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + 1 + v));
    assert!(!ready());
}

#[test]
fn test_non_specific_eois() {
    let (_, mut pic) = create_pic();

    pic.set_irq(5, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 5));

    pic.set_irq(3, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 3));

    pic.set_irq(1, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 1));

    assert_eq!(pic.pics[0].isr, 0b101010);

    pic.io_write(
        PRIMARY_PIC_COMMAND_PORT,
        &[Ocw2::new().with_eoi(true).with_sl(false).0],
    )
    .unwrap();

    assert_eq!(pic.pics[0].isr, 0b101000);
}

mod reference_tests;
