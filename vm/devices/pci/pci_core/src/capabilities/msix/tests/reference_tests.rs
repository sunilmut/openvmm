// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::MsiConnection;
use super::MsixEmulator;
use super::TestPciInterruptController;
use super::read_cap_u32;
use super::write_cap_u32;
use test_with_tracing::test;

// Test: Set the MSI-X function mask after proving that an unmasked vector delivers.
// Expected: Function masking suppresses delivery and clearing it replays one pending MSI.
#[test]
#[ignore = "known product bug: MSI-X function mask is ignored and interrupts still deliver"]
fn known_bug_function_mask_defers_unmasked_vector_until_cleared() {
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut table, mut capability) = MsixEmulator::new(2, 1, &connection.target());
    table.write_u32(0, 0xfee01000);
    table.write_u32(8, 0x61);
    table.write_u32(12, 0);
    write_cap_u32(&mut capability, 0, 0x80000000);
    let interrupt = table.interrupt(0).unwrap();
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0xfee01000, 0x61)));
    assert_eq!(controller.get_next_interrupt(), None);

    write_cap_u32(&mut capability, 0, 0xc0000000);
    interrupt.deliver();
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(read_cap_u32(&capability, 0) & 0xc0000000, 0xc0000000);
    assert_eq!(table.read_u32(16), 1);
    write_cap_u32(&mut capability, 0, 0x80000000);
    assert_eq!(controller.get_next_interrupt(), Some((0xfee01000, 0x61)));
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(16), 0);
}

// Test: Retarget a masked pending vector while reading its PBA and using another vector.
// Expected: PBA reads preserve the pending bit and unmasking replays only the new message.
#[test]
fn pending_retarget_preserves_vector_identity_and_latest_message() {
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut table, mut capability) = MsixEmulator::new(2, 2, &connection.target());
    table.write_u32(0, 0xfee01000);
    table.write_u32(4, 1);
    table.write_u32(8, 0x61);
    table.write_u32(12, 0);
    table.write_u32(16, 0xfee02000);
    table.write_u32(20, 2);
    table.write_u32(24, 0x62);
    write_cap_u32(&mut capability, 0, 0x80000000);
    let active = table.interrupt(0).unwrap();
    let masked = table.interrupt(1).unwrap();
    for _ in 0..3 {
        masked.deliver();
    }
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(32), 2);
    assert_eq!(table.read_u32(32), 2);
    table.write_u32(32, u32::MAX);
    assert_eq!(table.read_u32(32), 2);

    table.write_u32(16, 0xfee03000);
    table.write_u32(20, 3);
    table.write_u32(24, 0x73);
    active.deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0x1fee01000, 0x61)));
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(32), 2);

    table.write_u32(28, 0);
    assert_eq!(controller.get_next_interrupt(), Some((0x3fee03000, 0x73)));
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(32), 0);
    table.write_u32(28, 0);
    assert_eq!(controller.get_next_interrupt(), None);
    masked.deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0x3fee03000, 0x73)));
    assert_eq!(controller.get_next_interrupt(), None);
}
