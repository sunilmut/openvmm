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

// Select and read a controller's guest-visible IRR or ISR without polling it.
pub(super) fn read_register(pic: &mut DualPic, controller: usize, isr: bool) -> u8 {
    let port = match controller {
        0 => PRIMARY_PIC_COMMAND_PORT,
        1 => SECONDARY_PIC_COMMAND_PORT,
        _ => unreachable!(),
    };
    pic.io_write(port, &[if isr { 0x0b } else { 0x0a }])
        .unwrap();
    read_port(pic, port)
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

// Test: Try every pending IRQ against each in-service combination, then issue EOI.
// Expected: Only higher-priority IRQs win; EOI releases the highest service level.
#[test]
fn priority_masks_and_non_specific_eoi() {
    let mut pic = Pic::new(true);
    pic.line_low_latch = u8::MAX;
    for isr in 0..=u8::MAX {
        let first = (0..8).find(|&irq| isr & (1 << irq) != 0);
        let serviced = first.map_or(0, |irq| 1 << irq);
        let remaining = isr & !serviced;
        let next = (0..8).find(|&irq| remaining & (1 << irq) != 0);
        for irq in 0..8 {
            pic.lines = 1 << irq;
            pic.isr = isr;
            assert_eq!(
                pic.pending_line(),
                (irq < first.unwrap_or(8)).then_some(irq),
                "ISR {isr:#x}, IRQ {irq}"
            );
            pic.eoi(None);
            assert_eq!(
                pic.pending_line(),
                (irq < next.unwrap_or(8)).then_some(irq),
                "EOI ISR {isr:#x}, IRQ {irq}"
            );
        }
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

// Test: Initialize both controllers and deliver a primary then a secondary IRQ.
// Expected: Ready starts low and each controller supplies its configured vector.
#[test]
fn test_create_pic() {
    let (ready, mut pic) = create_pic();
    assert!(!ready());
    pic.set_irq(1, true);
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 1));
    pic.set_irq(9, true);
    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x61]).unwrap();
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 9));
}

// Test: Poll an asserted primary IRQ through its command port.
// Expected: Poll returns the IRQ, sets ISR and consumes the pending request.
#[test]
fn test_poll_read_primary_lowers_ready() {
    let (ready, mut pic) = create_pic();
    pic.set_irq(1, true);
    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    assert!(ready());

    let mut data = [0];
    pic.io_read(PRIMARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x81);
    assert_eq!(read_register(&mut pic, 0, true), 1 << 1);
    assert_eq!(read_register(&mut pic, 0, false), 0);
    assert!(!ready());
}

// Test: Poll the cascade and secondary IRQ, acknowledge service, then reassert it.
// Expected: Both pending requests clear and a later edge reaches the cascade.
#[test]
fn test_poll_read_secondary_lowers_cascade() {
    let (ready, mut pic) = create_pic();
    pic.set_irq(9, true);
    assert!(ready());

    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    let mut data = [0];
    pic.io_read(PRIMARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x80 | PIC_CHAIN_COMMUNICATION_IRQ);

    assert_eq!(read_register(&mut pic, 1, false), 1 << 1);
    pic.io_write(SECONDARY_PIC_COMMAND_PORT, &[0x0c]).unwrap(); // OCW3: poll
    pic.io_read(SECONDARY_PIC_COMMAND_PORT, &mut data).unwrap();
    assert_eq!(data[0], 0x81);
    assert_eq!(read_register(&mut pic, 1, true), 1 << 1);
    assert_eq!(read_register(&mut pic, 1, false), 0);
    assert_eq!(read_register(&mut pic, 0, false), 0);
    assert!(!ready());
    pic.set_irq(9, false);
    pic.io_write(SECONDARY_PIC_COMMAND_PORT, &[0x61]).unwrap();
    pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x62]).unwrap();
    pic.set_irq(9, true);
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 9));
}

// (Vector, pics index)
type PicTestConstants = (u8, usize);
const PRIMARY: PicTestConstants = (0, 0);
const SECONDARY: PicTestConstants = (8, 1);

// Test: Assert, consume and retrigger a primary edge-sensitive IRQ.
// Expected: Port IRR/ISR and delivered vectors follow each edge and EOI.
#[test]
fn test_edge_interrupt_primary() {
    test_edge_interrupt(PRIMARY);
}

// Test: Assert, consume and retrigger a secondary edge-sensitive IRQ.
// Expected: Cascade delivery and port IRR/ISR follow each edge and EOI.
#[test]
fn test_edge_interrupt_secondary() {
    test_edge_interrupt(SECONDARY);
}

fn test_edge_interrupt(consts: PicTestConstants) {
    let (ready, mut pic) = create_pic();
    let (v, i) = consts;

    pic.set_irq(v, true);
    assert!(ready());
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    pic.set_irq(v, false);
    assert_eq!(read_register(&mut pic, i, false), 0b0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert_eq!(read_register(&mut pic, i, false), 0b1);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert_eq!(read_register(&mut pic, i, false), 0);
    assert_eq!(read_register(&mut pic, i, true), 0b1);

    send_eoi(&mut pic, consts);

    assert_eq!(read_register(&mut pic, i, false), 0);
    assert_eq!(read_register(&mut pic, i, true), 0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert_eq!(read_register(&mut pic, i, false), 0b0);
    pic.set_irq(v, false);
    pic.set_irq(v, true);
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    assert!(ready());

    pic.set_irq(v, false);
    assert_eq!(read_register(&mut pic, i, false), 0b0);
}

// Test: Hold a primary level-sensitive IRQ through acknowledgement and EOI.
// Expected: It redelivers while high and disappears after deassertion.
#[test]
fn test_level_interrupts_primary() {
    test_level_interrupts(PRIMARY);
}

// Test: Hold a secondary level-sensitive IRQ through acknowledgement and EOI.
// Expected: Cascade redelivery continues only while the source remains high.
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
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    pic.set_irq(v, false);
    assert_eq!(read_register(&mut pic, i, false), 0b0);
    let pending = pic.acknowledge_interrupt();

    // No spurious interrupt is possible with the current interface.
    assert!(pending.is_none());

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert_eq!(read_register(&mut pic, i, false), 0b1);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    assert_eq!(read_register(&mut pic, i, true), 0b1);

    send_eoi(&mut pic, consts);
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    assert_eq!(read_register(&mut pic, i, true), 0);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    pic.set_irq(v, false);
    send_eoi(&mut pic, consts);
    assert_eq!(read_register(&mut pic, i, false), 0);
    let pending = pic.acknowledge_interrupt();
    assert!(pending.is_none());
}

// Test: Queue two primary edges and acknowledge them around EOI.
// Expected: The higher-priority vector wins and the peer remains pending.
#[test]
fn test_multiple_edge_interrupt_primary() {
    test_multiple_edge_interrupt(PRIMARY);
}

// Test: Queue two secondary edges and acknowledge them around cascade EOI.
// Expected: Priority and the pending peer are preserved through both controllers.
#[test]
fn test_multiple_edge_interrupt_secondary() {
    test_multiple_edge_interrupt(SECONDARY);
}

fn test_multiple_edge_interrupt(consts: PicTestConstants) {
    let (ready, mut pic) = create_pic();
    let (v, i) = consts;

    pic.set_irq(v, true);
    assert!(ready());
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    pic.set_irq(v, false);
    assert_eq!(read_register(&mut pic, i, false), 0b0);

    pic.set_irq(v + 1, true);
    assert_eq!(read_register(&mut pic, i, false), 0b10);
    pic.set_irq(v + 1, false);
    assert_eq!(read_register(&mut pic, i, false), 0b00);

    assert!(!ready());

    pic.set_irq(v, true);
    assert!(ready());
    assert_eq!(read_register(&mut pic, i, false), 0b1);
    pic.set_irq(v + 1, true);
    assert_eq!(read_register(&mut pic, i, false), 0b11);

    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + v));
    assert_eq!(read_register(&mut pic, i, false), 0b10);
    assert_eq!(read_register(&mut pic, i, true), 0b01);

    send_eoi(&mut pic, consts);
    assert_eq!(read_register(&mut pic, i, false), 0b10);
    assert_eq!(read_register(&mut pic, i, true), 0b00);
    assert!(ready());
    let pending = pic.acknowledge_interrupt();
    assert_eq!(pending, Some(IV_BASE + 1 + v));
    assert!(!ready());
}

// Test: Nest three primary service levels and issue a non-specific EOI.
// Expected: Only the highest-priority ISR bit clears through the command port.
#[test]
fn test_non_specific_eois() {
    let (_, mut pic) = create_pic();

    pic.set_irq(5, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 5));

    pic.set_irq(3, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 3));

    pic.set_irq(1, true);
    assert_eq!(pic.acknowledge_interrupt(), Some(IV_BASE + 1));

    assert_eq!(read_register(&mut pic, 0, true), 0b101010);

    pic.io_write(
        PRIMARY_PIC_COMMAND_PORT,
        &[Ocw2::new().with_eoi(true).with_sl(false).0],
    )
    .unwrap();

    assert_eq!(read_register(&mut pic, 0, true), 0b101000);
}

mod reference_tests;
