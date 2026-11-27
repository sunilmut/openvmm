// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

use crate::msi::MsiConnection;
use crate::test_helpers::TestPciInterruptController;
use crate::test_helpers::read_cap_u32;
use crate::test_helpers::write_cap_u32;
use test_with_tracing::test;

// Test: Program a 64-bit MSI capability, enable two messages, and reset it.
// Expected: Capability bits remain fixed while address/data and enable reset.
#[test]
fn msi_check() {
    let msi_conn = MsiConnection::new();
    let addr_64bit = true;
    let per_vector_masking = false;
    let mut cap = MsiCapability::new(2, addr_64bit, per_vector_masking, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Check initial capabilities register
    // Capability ID (0x05) + MMC=2 (4 messages) + 64-bit capable
    assert_eq!(read_cap_u32(&cap, 0), 0x00840005); // 0x05 (ID) | (0x84 << 16) where 0x84 = MMC=2(<<1) + 64bit(<<7)

    // Check initial address registers
    assert_eq!(read_cap_u32(&cap, 4), 0); // Address low
    assert_eq!(read_cap_u32(&cap, 8), 0); // Address high
    assert_eq!(read_cap_u32(&cap, 12), 0); // Data

    // Write address and data
    write_cap_u32(&mut cap, 4, 0x12345678);
    write_cap_u32(&mut cap, 8, 0x9abcdef0);
    write_cap_u32(&mut cap, 12, 0x1234);

    assert_eq!(read_cap_u32(&cap, 4), 0x12345678);
    assert_eq!(read_cap_u32(&cap, 8), 0x9abcdef0);
    assert_eq!(read_cap_u32(&cap, 12), 0x1234);

    // Enable MSI with 2 messages (MME=1)
    write_cap_u32(&mut cap, 0, 0x00110005); // Enable + MME=1 (bits 0 and 4-6)
    assert_eq!(read_cap_u32(&cap, 0), 0x00950005); // Should show enabled with all capability bits

    // Test reset
    cap.reset();
    assert_eq!(read_cap_u32(&cap, 0), 0x00840005); // Back to disabled
    assert_eq!(read_cap_u32(&cap, 4), 0);
    assert_eq!(read_cap_u32(&cap, 8), 0);
    assert_eq!(read_cap_u32(&cap, 12), 0);
}

// Test: Program the address and data of a 32-bit MSI capability.
// Expected: The capability lacks the 64-bit flag and data uses offset eight.
#[test]
fn msi_32bit_check() {
    let msi_conn = MsiConnection::new();
    let addr_64bit = false;
    let per_vector_masking = false;
    let mut cap = MsiCapability::new(1, addr_64bit, per_vector_masking, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Check initial capabilities register (no 64-bit bit set)
    assert_eq!(read_cap_u32(&cap, 0), 0x00020005); // MMC=1 (2 messages) + Capability ID

    // For 32-bit, data is at offset 8, not 12
    write_cap_u32(&mut cap, 4, 0x12345678); // Address
    write_cap_u32(&mut cap, 8, 0x1234); // Data

    assert_eq!(read_cap_u32(&cap, 4), 0x12345678);
    assert_eq!(read_cap_u32(&cap, 8), 0x1234);
}

// Test: Save a configured 64-bit MSI capability, reset it, then restore.
// Expected: Both address halves, data and enabled message count are recovered.
#[test]
fn test_msi_save_restore() {
    use vmcore::save_restore::SaveRestore;

    let msi_conn = MsiConnection::new();
    let addr_64bit = true;
    let per_vector_masking = false;
    let mut cap = MsiCapability::new(2, addr_64bit, per_vector_masking, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Configure MSI capability with specific values
    write_cap_u32(&mut cap, 4, 0x12345678); // Address low
    write_cap_u32(&mut cap, 8, 0x9abcdef0); // Address high
    write_cap_u32(&mut cap, 12, 0x5678); // Data
    write_cap_u32(&mut cap, 0, 0x00110001); // Enable MSI with MME=1 (2 messages)

    // Verify initial state
    assert_eq!(read_cap_u32(&cap, 0), 0x00950005); // Enabled with capabilities
    assert_eq!(read_cap_u32(&cap, 4), 0x12345678);
    assert_eq!(read_cap_u32(&cap, 8), 0x9abcdef0);
    assert_eq!(read_cap_u32(&cap, 12), 0x5678);

    // Save the state
    let saved_state = cap.save().expect("save should succeed");

    // Reset the capability
    cap.reset();
    assert_eq!(read_cap_u32(&cap, 0), 0x00840005); // Back to disabled
    assert_eq!(read_cap_u32(&cap, 4), 0);
    assert_eq!(read_cap_u32(&cap, 8), 0);
    assert_eq!(read_cap_u32(&cap, 12), 0);

    // Restore the state
    cap.restore(saved_state).expect("restore should succeed");

    // Verify restored state
    assert_eq!(read_cap_u32(&cap, 0), 0x00950005); // Should be enabled again
    assert_eq!(read_cap_u32(&cap, 4), 0x12345678);
    assert_eq!(read_cap_u32(&cap, 8), 0x9abcdef0);
    assert_eq!(read_cap_u32(&cap, 12), 0x5678);
}

// Test: Save and restore supported fields of a 32-bit masking-capable MSI.
// Expected: Address, data, enable and message count survive later changes.
#[test]
fn test_msi_save_restore_32bit_with_masking() {
    use vmcore::save_restore::SaveRestore;

    let msi_conn = MsiConnection::new();
    let addr_64bit = false;
    let per_vector_masking = true;
    let mut cap = MsiCapability::new(3, addr_64bit, per_vector_masking, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Configure MSI capability with specific values
    write_cap_u32(&mut cap, 4, 0x87654321); // Address (32-bit)
    write_cap_u32(&mut cap, 8, 0x1234); // Data
    // This implementation does not expose the 32-bit mask offset.
    write_cap_u32(&mut cap, 12, 0xaaaabbbb);
    write_cap_u32(&mut cap, 0, 0x00210001); // Enable MSI with MME=2 (4 messages)

    // Verify initial state
    let control_reg = read_cap_u32(&cap, 0);
    let control_val = (control_reg >> 16) & 0xFFFF;
    assert!(control_val & 1 != 0); // MSI enabled
    assert_eq!((control_val >> 4) & 0x7, 2); // MME = 2
    assert_eq!(read_cap_u32(&cap, 4), 0x87654321);
    assert_eq!(read_cap_u32(&cap, 8), 0x1234);

    // Save the state
    let saved_state = cap.save().expect("save should succeed");

    // Modify state
    write_cap_u32(&mut cap, 4, 0x11111111);
    write_cap_u32(&mut cap, 8, 0x9999);
    write_cap_u32(&mut cap, 12, 0x0000);
    write_cap_u32(&mut cap, 0, 0x00000005); // Disable MSI

    // Verify changed state
    let control_reg = read_cap_u32(&cap, 0);
    let control_val = (control_reg >> 16) & 0xFFFF;
    assert_eq!(control_val & 1, 0); // MSI disabled
    assert_eq!(read_cap_u32(&cap, 4), 0x11111111);
    assert_eq!(read_cap_u32(&cap, 8), 0x9999);

    // Restore the state
    cap.restore(saved_state).expect("restore should succeed");

    // Verify restored state
    let control_reg = read_cap_u32(&cap, 0);
    let control_val = (control_reg >> 16) & 0xFFFF;
    assert!(control_val & 1 != 0); // MSI enabled
    assert_eq!((control_val >> 4) & 0x7, 2); // MME = 2
    assert_eq!(read_cap_u32(&cap, 4), 0x87654321);
    assert_eq!(read_cap_u32(&cap, 8), 0x1234);
}

// Test: Request more MSI messages than supported and checkpoint the result.
// Expected: The clamped message count, route data and enable survive restore.
#[test]
fn test_msi_save_restore_mme_clamping() {
    use vmcore::save_restore::SaveRestore;

    let msi_conn = MsiConnection::new();
    let addr_64bit = true;
    let per_vector_masking = false;
    let mut cap = MsiCapability::new(1, addr_64bit, per_vector_masking, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Configure with MME=3 (8 messages), but device only supports MMC=1 (2 messages)
    write_cap_u32(&mut cap, 4, 0x12345678); // Address low
    write_cap_u32(&mut cap, 8, 0x9abcdef0); // Address high
    write_cap_u32(&mut cap, 12, 0x5678); // Data
    write_cap_u32(&mut cap, 0, 0x00310001); // Enable MSI with MME=3

    // Verify MME was clamped to MMC (1)
    let control_reg = read_cap_u32(&cap, 0);
    let control_val = (control_reg >> 16) & 0xFFFF;
    let mme = (control_val >> 4) & 0x7;
    assert_eq!(mme, 1); // Should be clamped to MMC=1

    // Save the state (which should preserve the clamped MME)
    let saved_state = cap.save().expect("save should succeed");

    // Reset the capability
    cap.reset();

    // Restore the state
    cap.restore(saved_state).expect("restore should succeed");

    // Check that MME is still properly clamped after restore
    let control_reg = read_cap_u32(&cap, 0);
    let control_val = (control_reg >> 16) & 0xFFFF;
    let mme = (control_val >> 4) & 0x7;
    let enabled = control_val & 1 != 0;
    assert_eq!(mme, 1); // Should still be clamped to MMC=1
    assert!(enabled); // Should be enabled
    assert_eq!(read_cap_u32(&cap, 4), 0x12345678);
    assert_eq!(read_cap_u32(&cap, 8), 0x9abcdef0);
    assert_eq!(read_cap_u32(&cap, 12), 0x5678);
}

// Test: Reprogram active 32/64-bit MSI vectors and restore enabled/disabled states.
// Expected: Delivered addresses and data follow the active registers and checkpoint.
#[test]
fn live_reprogramming_and_restore_control_actual_msi_delivery() {
    use vmcore::save_restore::SaveRestore;
    for addr_64bit in [false, true] {
        let connection = MsiConnection::new();
        let controller = TestPciInterruptController::new();
        connection.connect(controller.signal_msi());
        let per_vector_masking = false;
        let mut capability =
            MsiCapability::new(0, addr_64bit, per_vector_masking, &connection.target());
        let data_offset = if addr_64bit { 12 } else { 8 };
        write_cap_u32(&mut capability, 4, 0xfee00000);
        write_cap_u32(&mut capability, data_offset, 0x41);
        write_cap_u32(&mut capability, 0, 0x00010000);
        let interrupt = capability.interrupt().unwrap();
        interrupt.deliver();
        assert_eq!(controller.get_next_interrupt(), Some((0xfee00000, 0x41)));
        write_cap_u32(&mut capability, 4, 0xfee01000);
        if addr_64bit {
            write_cap_u32(&mut capability, 8, 1);
        }
        write_cap_u32(&mut capability, data_offset, 0x51);
        let address = if addr_64bit { 0x1fee01000 } else { 0xfee01000 };
        interrupt.deliver();
        assert_eq!(controller.get_next_interrupt(), Some((address, 0x51)));
        let enabled = capability.save().unwrap();
        write_cap_u32(&mut capability, 0, 0);
        let disabled = capability.save().unwrap();
        capability.restore(enabled).unwrap();
        interrupt.deliver();
        assert_eq!(controller.get_next_interrupt(), Some((address, 0x51)));
        capability.restore(disabled).unwrap();
        interrupt.deliver();
        assert_eq!(controller.get_next_interrupt(), None);
        capability.reset();
        assert_eq!(read_cap_u32(&capability, 4), 0);
        assert_eq!(read_cap_u32(&capability, data_offset), 0);
        assert_eq!((read_cap_u32(&capability, 0) >> 16) & 1, 0);
    }
}

// Test: Restore an invalid multiple-message encoding over a working MSI vector.
// Expected: The checkpoint is rejected and the existing interrupt still routes correctly.
#[test]
fn invalid_checkpoint_preserves_existing_msi_route() {
    use vmcore::save_restore::SaveRestore;
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let addr_64bit = true;
    let per_vector_masking = false;
    let mut capability =
        MsiCapability::new(0, addr_64bit, per_vector_masking, &connection.target());
    write_cap_u32(&mut capability, 4, 0xfee02000);
    write_cap_u32(&mut capability, 12, 0x61);
    write_cap_u32(&mut capability, 0, 0x00010000);
    let mut saved = capability.save().unwrap();
    saved.multiple_message_enable = 6;
    assert!(matches!(
        capability.restore(saved),
        Err(vmcore::save_restore::RestoreError::InvalidSavedState(_))
    ));
    capability.interrupt().unwrap().deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0xfee02000, 0x61)));
    assert_eq!(controller.get_next_interrupt(), None);
}

// Test: Write and checkpoint a 64-bit MSI mask while attempting pending-bit writes.
// Expected: Mask bits survive restoration and pending bits remain read-only.
#[test]
fn mask_registers_preserve_writes_and_pending_bits_are_read_only() {
    use vmcore::save_restore::SaveRestore;
    let connection = MsiConnection::new();
    let addr_64bit = true;
    let per_vector_masking = true;
    let mut capability =
        MsiCapability::new(2, addr_64bit, per_vector_masking, &connection.target());
    assert_eq!(capability.len(), 24);
    assert_eq!(read_cap_u32(&capability, 16), u32::MAX);
    write_cap_u32(&mut capability, 16, 0xa5a55a5a);
    assert_eq!(read_cap_u32(&capability, 16), 0xa5a55a5a);
    write_cap_u32(&mut capability, 20, u32::MAX);
    assert_eq!(read_cap_u32(&capability, 20), 0);
    let saved = capability.save().unwrap();
    write_cap_u32(&mut capability, 16, 0);
    assert_eq!(read_cap_u32(&capability, 16), 0);
    capability.restore(saved).unwrap();
    assert_eq!(read_cap_u32(&capability, 16), 0xa5a55a5a);
    assert_eq!(read_cap_u32(&capability, 20), 0);
}
