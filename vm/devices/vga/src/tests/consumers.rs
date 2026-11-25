// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Fixture;
use test_with_tracing::test;

fn check_attribute_save_then_restore(misc_output: u8, status_port: u16) {
    let mut f = Fixture::new();
    f.out(0x3c2, misc_output);
    f.attribute(0x13, 2);
    f.attribute(0x14, 3);

    // Saving a register leaves the shared port waiting for data.
    f.input(status_port);
    f.out(0x3c0, 0x13 | 0x20);
    assert_eq!(f.input(0x3c1), 2);
    assert_eq!(f.input(0x3c1), 2);

    // The status read must restart index selection before another register.
    f.input(status_port);
    f.out(0x3c0, 0x14 | 0x20);
    f.out(0x3c0, 0x0a);
    assert_eq!(f.input(0x3c1), 0x0a);

    f.input(status_port);
    f.out(0x3c0, 0x13 | 0x20);
    assert_eq!(f.input(0x3c1), 2);
}

// Test: Interleave attribute save reads and restore writes using color status.
// Expected: Each status read resets index selection without changing the saved
//       register or confusing the palette-enable bit with the register index.
#[test]
fn color_status_restarts_attribute_selection_after_save_reads() {
    check_attribute_save_then_restore(1, 0x3da);
}

// Test: Perform the same attribute save/restore sequence in monochrome mode.
// Expected: The monochrome status port resets the shared attribute index/data
//       phase just like the color port, preserving both register values.
#[test]
fn monochrome_status_restarts_attribute_selection_after_save_reads() {
    check_attribute_save_then_restore(0, 0x3ba);
}
