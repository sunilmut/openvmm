// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tests::Fixture;
use crate::tests::Mapping;
use test_with_tracing::test;

// Read the programmed hardware register, not the emulator's cached state.
fn indexed(f: &mut Fixture, port: u16, index: u8) -> u8 {
    f.out(port, index);
    f.input(port + 1)
}

// Test: Run the crash-screen reset stage after programming nondefault S3 settings.
// Expected: Reset preserves shared bits, disables linear decoding, and resets AFC.
#[test]
fn controller_reset_preserves_shared_bits_and_unmaps_the_framebuffer() {
    for (misc, crt) in [(0, 0x3b4), (1, 0x3d4)] {
        let mut f = Fixture::new();
        f.out(0x3c2, misc);
        assert_eq!(f.device.emu.get_crt_port(), crt);
        for (reg, value) in [
            (0x38, 0x48),
            (0x31, 0xb0),
            (0x32, 0x55),
            (0x3a, 0x88),
            (0x40, 0xab),
            (0x42, 0x24),
            (0x59, 0xe0),
            (0x5a, 0),
            (0x58, 0x93),
        ] {
            f.indexed(crt, reg, value);
        }
        f.mappings.lock().clear();
        f.device.emu.reset_dcc(crt);
        for (reg, expected) in [
            (0x31, 0xb5),
            (0x32, 0x40),
            (0x3a, 0x8d),
            (0x40, 0xaa),
            (0x42, 4),
            (0x58, 0xc0),
            (0x65, 0),
        ] {
            assert_eq!(indexed(&mut f, crt, reg), expected, "register {reg:#x}");
        }
        assert!(f.mappings.lock().contains(&Mapping::Unmap));
        assert_eq!(f.input(0x4ae8) & 1, 0);
    }
}

// Test: Program the extended crash-screen stage over existing shared control bits.
// Expected: Shared fields survive, 640-pixel pitch is selected, and DAC depth is 32.
#[test]
fn extended_mode_programming_preserves_shared_controls_and_selects_pitch() {
    let mut f = Fixture::new();
    for (reg, value) in [(0x31, 0x40), (0x3a, 0x80), (0x40, 0x22), (0x67, 5)] {
        f.indexed(0x3d4, reg, value);
    }
    let registers = [
        4, 0x55, 0x66, 8, 0x15, 1, 0x70, 0x18, 0, 0x2f, 0x81, 0xe0, 0, 0, 0, 0, 0, 0x23, 0xff, 0,
    ];
    f.device.emu.program_ecrtc(0x3d4, &mut registers.as_slice());
    f.device.emu.setup_dac(0x3d4);
    for (reg, expected) in [
        (0x31, 0x48),
        (0x3a, 0x95),
        (0x40, 0x23),
        (0x13, 0x40),
        (0x51, 0x13),
        (0x67, 0xd5),
    ] {
        assert_eq!(indexed(&mut f, 0x3d4, reg), expected, "register {reg:#x}");
    }
    assert_eq!(indexed(&mut f, 0x3d4, 0x5c) & 0x40, 0);
}

// Test: Program scanline lengths across the split offset-field boundary.
// Expected: Pitch bits change without corrupting other fields; short pitch clears CR43.
#[test]
fn scanline_length_updates_only_its_split_register_fields() {
    let mut f = Fixture::new();
    for (pitch, low, high, extended_mode) in [
        (640, 0x40, 0xdf, 4),
        (128, 0x40, 0xcf, 0),
        (1024, 0, 0xef, 4),
    ] {
        f.indexed(0x3d4, 0x51, 0xcf);
        f.indexed(0x3d4, 0x43, 4);
        f.device.emu.minimal_set_scanline_length(0x3d4, pitch);
        assert_eq!(indexed(&mut f, 0x3d4, 0x13), low);
        assert_eq!(indexed(&mut f, 0x3d4, 0x51), high);
        assert_eq!(indexed(&mut f, 0x3d4, 0x43), extended_mode);
    }
}

// Test: Blank and unblank during BIOS mode programming with a nondefault dot clock.
// Expected: Only the blanking bit changes; unrelated clock and character bits remain.
#[test]
fn screen_blanking_preserves_the_programmed_clock_bits() {
    let mut f = Fixture::new();
    f.indexed(0x3c4, 1, 9);
    f.device.emu.turn_screen_on_off(false);
    assert_eq!(indexed(&mut f, 0x3c4, 1), 0x29);
    f.device.emu.turn_screen_on_off(true);
    assert_eq!(indexed(&mut f, 0x3c4, 1), 9);
}
