// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::support::*;
use super::*;
use test_with_tracing::test;

// Test: Restore READ ID at every result-byte boundary onto a fresh controller.
// Expected: Only the unread suffix remains, IRQ is restored independently,
//       and draining the result allows VERSION to acknowledge that IRQ.
#[test]
fn restore_preserves_unread_result_bytes_at_each_checkpoint() {
    let expected = [4, 0, 0, 37, 1, 1, 2];
    for consumed in 0..=expected.len() {
        let mut source = Rig::without_disk();
        source.issue(&[0x0f, 4, 37]);
        source.issue(&[0x4a, 4]);
        for byte in &expected[..consumed] {
            assert_eq!(source.read(0x3f5), *byte);
        }
        let saved = source.device.save().unwrap();
        let mut destination = Rig::without_disk();
        destination.device.restore(saved).unwrap();
        assert!(destination.interrupt.0.load(Ordering::SeqCst));
        for byte in &expected[consumed..] {
            assert_eq!(destination.read(0x3f4) & 0xd0, 0xd0);
            assert_eq!(destination.read(0x3f5), *byte);
        }
        assert_eq!(destination.read(0x3f4), 0x80);
        destination.issue(&[0x10]);
        assert_eq!(destination.read(0x3f5), 0x90);
        assert_eq!(destination.read(0x3f4), 0x80);
        assert!(!destination.interrupt.0.load(Ordering::SeqCst));
        assert!(source.interrupt.0.load(Ordering::SeqCst));
    }
}

// Test: Save reset acknowledgement midway through a two-byte SENSE response.
// Expected: A fresh destination resumes the remaining byte and pending drives
//       without repeating acknowledged statuses or retaining result-phase state.
#[test]
fn restore_resumes_reset_sequence_after_partial_sense_result() {
    for acknowledged in 0..4 {
        let mut source = Rig::without_disk();
        source.write(0x3f2, 0);
        source.write(0x3f2, 0x1c);
        for drive in 0..acknowledged {
            source.issue(&[8]);
            assert_eq!(source.read(0x3f5), 0xc0 | drive);
            assert_eq!(source.read(0x3f5), 0);
        }
        source.issue(&[8]);
        assert_eq!(source.read(0x3f5), 0xc0 | acknowledged);
        let saved = source.device.save().unwrap();
        drop(source);
        let mut destination = Rig::without_disk();
        destination.device.restore(saved).unwrap();
        assert_eq!(destination.read(0x3f2), 0x1c);
        assert!(!destination.interrupt.0.load(Ordering::SeqCst));
        assert_eq!(destination.read(0x3f4), 0xd0);
        assert_eq!(destination.read(0x3f5), 0);
        assert_eq!(destination.read(0x3f4), 0x80);
        for drive in acknowledged + 1..4 {
            destination.issue(&[8]);
            assert_eq!(destination.read(0x3f5), 0xc0 | drive);
            assert_eq!(destination.read(0x3f5), 0);
            assert_eq!(destination.read(0x3f4), 0x80);
        }
        destination.issue(&[0x10]);
        assert_eq!(destination.read(0x3f5), 0x90);
        assert_eq!(destination.read(0x3f4), 0x80);
    }
}

// Test: Independently seek, acknowledge, reset, and drop controllers sharing IRQ6.
// Expected: Each action releases only its own contribution; the peer keeps
//       the interrupt asserted until its own SENSE acknowledgement.
#[test]
fn shared_irq_peers_survive_acknowledgement_reset_and_drop() {
    let interrupt = Arc::new(Interrupt::default());
    let primary_line = LineInterrupt::new_with_target("primary", interrupt.clone(), 6);
    let secondary_line = primary_line.new_shared("secondary").unwrap();
    let mut primary = Rig::without_disk_with_interrupt(primary_line, interrupt.clone());
    let mut secondary = Rig::without_disk_with_interrupt(secondary_line, interrupt.clone());
    primary.issue(&[0x0f, 0, 12]);
    secondary.issue(&[0x0f, 4, 37]);
    primary.issue(&[8]);
    assert_eq!(primary.read(0x3f5), 0x20);
    assert_eq!(primary.read(0x3f5), 12);
    assert!(interrupt.0.load(Ordering::SeqCst));
    primary.write(0x3f2, 0);
    assert!(interrupt.0.load(Ordering::SeqCst));
    primary.write(0x3f2, 0x0c);
    drop(primary);
    assert!(interrupt.0.load(Ordering::SeqCst));
    secondary.issue(&[8]);
    assert_eq!(secondary.read(0x3f5), 0x24);
    assert_eq!(secondary.read(0x3f5), 37);
    assert!(!interrupt.0.load(Ordering::SeqCst));
}

// Test: Lifecycle-reset a controller with pending IRQ and partial command input.
// Expected: Reset clears IRQ and disables guest commands; re-enabling reports
//       four reset statuses, then accepts a new VERSION rather than old input.
#[test]
fn lifecycle_reset_discards_partial_command_and_reinitializes_guest_protocol() {
    let mut rig = Rig::without_disk();
    rig.issue(&[0x0f, 4, 37]);
    rig.issue(&[0x4a]);
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    assert!(matches!(
        std::pin::pin!(ChangeDeviceState::reset(&mut rig.device))
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(())
    ));
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    assert_eq!(rig.read(0x3f2), 0);
    assert_eq!(rig.read(0x3f4), 0);
    rig.issue(&[0x10]);
    assert_eq!(rig.read(0x3f4), 0);
    rig.write(0x3f2, 0x0c);
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    for drive in 0..4 {
        rig.issue(&[8]);
        assert_eq!(rig.read(0x3f5), 0xc0 | drive);
        assert_eq!(rig.read(0x3f5), 0);
        assert_eq!(rig.read(0x3f4), 0x80);
    }
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    rig.issue(&[0x10]);
    assert_eq!(rig.read(0x3f5), 0x90);
    assert_eq!(rig.read(0x3f4), 0x80);
}
