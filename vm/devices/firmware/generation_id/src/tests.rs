// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use vmcore::line_interrupt::LineSet;
use vmcore::line_interrupt::LineSetTarget;
use vmcore::save_restore::SaveRestore;

struct Notifications {
    gm: GuestMemory,
    events: Mutex<Vec<(u32, bool, [u8; 16])>>,
}

impl LineSetTarget for Notifications {
    fn set_irq(&self, vector: u32, high: bool) {
        let mut bytes = [0; 16];
        self.gm.read_at(128, &mut bytes).unwrap();
        self.events.lock().push((vector, high, bytes));
    }
}

fn fixture() -> (GenerationId, mesh::Sender<[u8; 16]>, Arc<Notifications>) {
    let gm = GuestMemory::allocate(4096);
    gm.write_at(0, &[0xa5; 4096]).unwrap();
    let notifications = Arc::new(Notifications {
        gm: gm.clone(),
        events: Mutex::new(Vec::new()),
    });
    let lines = LineSet::new();
    lines.add_target(5..=5, 23, "genid test", notifications.clone());
    let (send, generation_id_recv) = mesh::channel();
    (
        GenerationId::new(
            [0x11; 16],
            GenerationIdRuntimeDeps {
                gm,
                generation_id_recv,
                notify_interrupt: lines.new_line(5, "genid").unwrap(),
            },
        ),
        send,
        notifications,
    )
}

fn poll(device: &mut GenerationId) {
    device.poll(&mut Context::from_waker(std::task::Waker::noop()));
}

fn memory(notifications: &Notifications) -> [u8; 4096] {
    let mut bytes = [0; 4096];
    notifications.gm.read_at(0, &mut bytes).unwrap();
    bytes
}

// Test: Program the pointer halves in either order and reset after receiving a new ID.
// Expected: Only complete pointers write exactly 16 bytes, programming/reset never pulse, and reset retains the latest ID while forgetting both halves.
#[test]
fn pointer_programming_and_reset_preserve_memory_boundaries() {
    for high_first in [false, true] {
        let (mut device, send, notifications) = fixture();
        assert_eq!(memory(&notifications), [0xa5; 4096]);
        if high_first {
            device.write_generation_id_high(0);
        } else {
            device.write_generation_id_low(128);
        }
        assert_eq!(memory(&notifications), [0xa5; 4096]);
        if high_first {
            device.write_generation_id_low(128);
        } else {
            device.write_generation_id_high(0);
        }
        let mut expected = [0xa5; 4096];
        expected[128..144].fill(0x11);
        assert_eq!(memory(&notifications), expected);
        assert!(notifications.events.lock().is_empty());
        send.send([0x22; 16]);
        poll(&mut device);
        expected[128..144].fill(0x22);
        assert_eq!(memory(&notifications), expected);
        notifications.events.lock().clear();
        device.reset();
        device.write_generation_id_low(256);
        assert_eq!(memory(&notifications), expected);
        device.write_generation_id_high(0);
        expected[256..272].fill(0x22);
        assert_eq!(memory(&notifications), expected);
        assert!(notifications.events.lock().is_empty());
    }
}

// Test: Queue several IDs, drain them, then close the input and poll repeatedly.
// Expected: Each queued value is visible before its rising/falling pulse, in order, and neither idle nor closed polling emits extra events.
#[test]
fn queued_updates_write_before_each_notification_and_drain_before_close() {
    let (mut device, send, notifications) = fixture();
    device.write_generation_id_high(0);
    device.write_generation_id_low(128);
    poll(&mut device);
    assert!(notifications.events.lock().is_empty());
    for marker in [0x81, 0x00, 0xff] {
        send.send([marker; 16]);
    }
    drop(send);
    poll(&mut device);
    assert_eq!(
        *notifications.events.lock(),
        [0x81, 0x00, 0xff]
            .into_iter()
            .flat_map(|marker| [(23, true, [marker; 16]), (23, false, [marker; 16])])
            .collect::<Vec<_>>()
    );
    let mut expected = [0xa5; 4096];
    expected[128..144].fill(0xff);
    assert_eq!(memory(&notifications), expected);
    poll(&mut device);
    assert_eq!(notifications.events.lock().len(), 6);
}

// Test: Receive IDs before pointer completion and while its high half points outside guest RAM, then repair the pointer.
// Expected: Updates still notify without corrupting mapped RAM, and completing a valid pointer publishes the latest ID without another pulse.
#[test]
fn missing_and_unmapped_pointers_recover_with_latest_id() {
    let (mut device, send, notifications) = fixture();
    send.send([0x33; 16]);
    poll(&mut device);
    assert_eq!(memory(&notifications), [0xa5; 4096]);
    device.write_generation_id_low(128);
    device.write_generation_id_high(1);
    send.send([0x44; 16]);
    poll(&mut device);
    assert_eq!(memory(&notifications), [0xa5; 4096]);
    assert_eq!(
        *notifications.events.lock(),
        [
            (23, true, [0xa5; 16]),
            (23, false, [0xa5; 16]),
            (23, true, [0xa5; 16]),
            (23, false, [0xa5; 16])
        ]
    );
    device.write_generation_id_high(0);
    let mut expected = [0xa5; 4096];
    expected[128..144].fill(0x44);
    assert_eq!(memory(&notifications), expected);
    assert_eq!(notifications.events.lock().len(), 4);
}

// Test: Save with only the low pointer half set, mutate ID/pointer/memory, and restore.
// Expected: Restore itself neither writes nor notifies; completing the restored pointer publishes the saved ID at the saved location.
#[test]
fn restoring_partial_pointer_and_id_has_no_unsolicited_side_effects() {
    let (mut device, send, notifications) = fixture();
    send.send([0x55; 16]);
    poll(&mut device);
    device.write_generation_id_low(128);
    let saved = device.save().unwrap();
    device.write_generation_id_high(0);
    send.send([0x66; 16]);
    poll(&mut device);
    device.reset();
    notifications.gm.write_at(0, &[0xa5; 4096]).unwrap();
    notifications.events.lock().clear();
    device.restore(saved).unwrap();
    assert_eq!(memory(&notifications), [0xa5; 4096]);
    assert!(notifications.events.lock().is_empty());
    device.write_generation_id_high(0);
    let mut expected = [0xa5; 4096];
    expected[128..144].fill(0x55);
    assert_eq!(memory(&notifications), expected);
    assert!(notifications.events.lock().is_empty());
}

// Test: Invoke the public force-update command with false, malformed and true values.
// Expected: Rejected/no-op commands leave guest bytes and IRQs unchanged; a true command writes its generated ID before one pulse and retains it across reset.
#[test]
fn force_update_command_publishes_before_interrupt_without_inspect_oracle() {
    let (mut device, _send, notifications) = fixture();
    device.write_generation_id_low(128);
    device.write_generation_id_high(0);
    let before = memory(&notifications);
    for value in ["false", "not-a-boolean"] {
        // Inspect is only the command transport; its returned value/state is not an oracle.
        drop(inspect::update("force_update", value, &mut device));
        assert_eq!(memory(&notifications), before);
        assert!(notifications.events.lock().is_empty());
    }
    drop(inspect::update("force_update", "true", &mut device));
    let bytes = memory(&notifications);
    let generated: [u8; 16] = bytes[128..144].try_into().unwrap();
    assert_eq!(&bytes[..128], &before[..128]);
    assert_eq!(&bytes[144..], &before[144..]);
    assert_eq!(
        *notifications.events.lock(),
        [(23, true, generated), (23, false, generated)]
    );
    device.reset();
    device.write_generation_id_low(256);
    assert_eq!(memory(&notifications), bytes);
    device.write_generation_id_high(0);
    let mut expected = bytes;
    expected[256..272].copy_from_slice(&generated);
    assert_eq!(memory(&notifications), expected);
    assert_eq!(notifications.events.lock().len(), 2);
}
