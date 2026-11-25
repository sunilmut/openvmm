// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tests::Fixture;
use pal_async::timer::PolledTimer;
use std::time::Duration;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;

// Render one complete frame synchronously, avoiding wall-clock timer dependencies.
fn render(f: &mut Fixture) {
    let state = f.device.renderer.state.lock().clone();
    f.device.renderer.task.task_mut().render(&state);
}

// Program a small graphics image with a 16-pixel source stride.
fn graphics(f: &mut Fixture) {
    f.attribute(0x10, 1);
    f.indexed(0x3d4, 0x15, 0xff);
    f.indexed(0x3d4, 1, 1);
    f.indexed(0x3d4, 0x12, 1);
    f.indexed(0x3d4, 0x13, 8);
}

// Program one six-bit RGB palette entry through the DAC.
fn palette(f: &mut Fixture, index: u8, rgb: [u8; 3]) {
    f.out(0x3c8, index);
    for component in rgb {
        f.out(0x3c9, component);
    }
}

// Read the first four pixels of the currently published framebuffer row.
fn pixels(f: &mut Fixture, row: u16) -> [u32; 4] {
    let mut bytes = [0; 16];
    f.view.read_line(row, &mut bytes);
    std::array::from_fn(|i| u32::from_ne_bytes(bytes[i * 4..][..4].try_into().unwrap()))
}

// Test: Render RGB565 source rows with a stride larger than the visible width.
// Expected: Components expand to full eight-bit colors and source rows stay separate.
#[test]
fn rgb565_rendering_expands_channels_and_respects_source_stride() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.out(0x4ae8, 1);
    f.indexed(0x3d4, 0x67, 0x50);
    f.vram
        .write_plain(0, &[0xf800u16, 0x07e0, 0x001f, 0xffff])
        .unwrap();
    f.vram
        .write_plain(32, &[0u16, 0xffff, 0x001f, 0x07e0])
        .unwrap();
    render(&mut f);
    assert_eq!(f.view.resolution(), (8, 2));
    assert_eq!(pixels(&mut f, 0), [0xff0000, 0x00ff00, 0x0000ff, 0xffffff]);
    assert_eq!(pixels(&mut f, 1), [0, 0xffffff, 0x0000ff, 0x00ff00]);
}

// Test: Publish a 32-bit image without blitting it into the render scratch buffer.
// Expected: Displayed pixels come directly from VRAM, using its programmed stride.
#[test]
fn direct_color_mode_publishes_the_original_vram() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.out(0x4ae8, 1);
    f.indexed(0x3d4, 0x67, 0xd0);
    let first = [0x12345678u32, 0x9abcdef0, 0x01020304, 0x50607080];
    let second = [0x11111111u32; 4];
    f.vram.write_plain(0, &first).unwrap();
    f.vram.write_plain(64, &second).unwrap();
    render(&mut f);
    assert_eq!(f.view.resolution(), (16, 2));
    assert_eq!(pixels(&mut f, 0), first);
    assert_eq!(pixels(&mut f, 1), second);
}

// Test: Render planar pixels, then change palette padding and intensity selection.
// Expected: Displayed colors follow DAC entries selected by the attribute controller.
#[test]
fn planar_rendering_tracks_palette_padding_and_plane_enables() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.attribute(0x12, 0x0f);
    f.attribute(1, 0x21);
    palette(&mut f, 0x21, [63, 0, 0]);
    palette(&mut f, 0x91, [0, 63, 0]);
    f.vram.write_at(0, &[0x80, 0, 0, 0]).unwrap();
    render(&mut f);
    assert_eq!(f.view.resolution(), (16, 2));
    assert_eq!(
        pixels(&mut f, 0),
        [0xffff0000, 0xff000000, 0xff000000, 0xff000000]
    );
    f.attribute(0x10, 0x81);
    f.attribute(0x14, 9);
    render(&mut f);
    assert_eq!(pixels(&mut f, 0)[0], 0xff00ff00);
    f.attribute(0x12, 0);
    render(&mut f);
    assert_eq!(pixels(&mut f, 0)[0], 0xff000000);
}

// Test: Select a graphics mode that the renderer does not yet support.
// Expected: The published image uses the visible unsupported-mode fill pattern.
#[test]
fn unsupported_graphics_depth_is_visibly_marked() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.indexed(0x3ce, 5, 0x40);
    render(&mut f);
    assert_eq!(f.view.resolution(), (16, 2));
    assert_eq!(pixels(&mut f, 0), [0xcccccccc; 4]);
    assert_eq!(pixels(&mut f, 1), [0xcccccccc; 4]);
}

// Test: Program a high-resolution text mode with an eight-line font and no cursor.
// Expected: The framebuffer displays the selected glyph and foreground/background.
#[test]
fn text_rendering_uses_programmed_font_and_palette() {
    let mut f = Fixture::new();
    f.indexed(0x3d4, 2, 80);
    f.indexed(0x3d4, 9, 7);
    f.indexed(0x3d4, 0x0a, 0x20);
    f.attribute(0x12, 15);
    f.attribute(1, 1);
    palette(&mut f, 1, [0, 0, 63]);
    f.vram.write_at(0, &[65, 1]).unwrap();
    f.vram.write_at(2 + 65 * 128, &[0x80]).unwrap();
    render(&mut f);
    assert_eq!(f.view.resolution(), (640, 400));
    assert_eq!(
        pixels(&mut f, 0),
        [0xff0000ff, 0xff000000, 0xff000000, 0xff000000]
    );
    assert_eq!(pixels(&mut f, 1), [0xff000000; 4]);
}

// Test: Start, render, and stop the real worker, then restart with a changed image.
// Expected: Each run publishes its new frame and cancellation completes cleanly.
#[test]
fn renderer_start_stop_is_restartable() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.out(0x4ae8, 1);
    f.indexed(0x3d4, 0x67, 0xd0);
    let mut timer = PolledTimer::new(&f.pool.driver());
    for height in [2, 3] {
        f.indexed(0x3d4, 0x12, height - 1);
        f.device.start();
        f.pool.run_until(async {
            for _ in 0..100 {
                if f.view.resolution() == (16, u16::from(height)) {
                    return;
                }
                timer.sleep(Duration::from_millis(5)).await;
            }
            panic!("renderer did not publish the new frame");
        });
        f.pool.run_until(f.device.stop());
    }
    assert_eq!(f.view.resolution(), (16, 3));
}

// Test: Change display overflow, blanking, pixel doubling, and interlace controls.
// Expected: Resolution follows timing and blank cutoff; oversized modes are ignored.
#[test]
fn monitor_timing_combines_overflow_doubling_and_interlace() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.indexed(0x3d4, 0x72, 0xff);
    f.out(0x4ae8, 1);
    f.indexed(0x3d4, 0x67, 0xd0);
    for (registers, expected) in [
        (vec![(0x15, 0xff), (0x12, 0xdf), (7, 0x0a)], (16, 480)),
        (vec![(7, 0x4a), (9, 0x20), (0x12, 0x57)], (16, 856)),
        (vec![(0x5e, 6)], (16, 1880)),
        (vec![(0x5d, 2)], (16, 1880)),
    ] {
        for (reg, value) in registers {
            f.indexed(0x3d4, reg, value);
        }
        render(&mut f);
        assert_eq!(f.view.resolution(), expected);
    }
    f.indexed(0x3d4, 0x5d, 0);
    f.indexed(0x3d4, 0x5e, 0);
    f.indexed(0x3d4, 7, 0);
    f.indexed(0x3d4, 9, 0);
    f.indexed(0x3d4, 0x12, 10);
    f.indexed(0x3d4, 0x15, 5);
    render(&mut f);
    assert_eq!(f.view.resolution(), (16, 5));
    f.indexed(0x3d4, 0x42, 0x20);
    render(&mut f);
    assert_eq!(f.view.resolution(), (16, 10));
    f.out(0x4ae8, 0);
    f.indexed(0x3c4, 1, 8);
    render(&mut f);
    assert_eq!(f.view.resolution(), (32, 10));
    f.indexed(0x3ce, 5, 0x20);
    render(&mut f);
    assert_eq!(f.view.resolution(), (32, 10));
}

// Test: Configure zero, legacy-extended, and newer extended source stride encodings.
// Expected: A direct-color row is read from the documented pixel-stride location.
#[test]
fn extended_stride_registers_select_the_correct_source_rows() {
    let mut f = Fixture::new();
    graphics(&mut f);
    f.out(0x4ae8, 1);
    f.indexed(0x3d4, 0x67, 0xd0);
    for (low, legacy, extended, stride) in [
        (0, 0, 0, 512),
        (3, 4, 0, 518),
        (3, 4, 0x10, 518),
        (3, 4, 0x20, 1030),
    ] {
        f.indexed(0x3d4, 0x13, low);
        f.indexed(0x3d4, 0x43, legacy);
        f.indexed(0x3d4, 0x51, extended);
        let color = 0xff000000 | stride;
        f.vram
            .write_plain(u64::from(stride) * 4, &[color; 4])
            .unwrap();
        render(&mut f);
        assert_eq!(f.view.resolution(), (16, 2));
        assert_eq!(pixels(&mut f, 1), [color; 4]);
    }
}

// Test: Change between 40/80-column text and select an alternate font bank.
// Expected: Glyph widths, selected font pixels, and published row height follow mode.
#[test]
fn text_mode_changes_update_glyph_width_font_bank_and_row_height() {
    let mut f = Fixture::new();
    f.indexed(0x3d4, 2, 40);
    f.indexed(0x3d4, 9, 7);
    f.indexed(0x3d4, 0x0a, 0x20);
    f.attribute(0x12, 15);
    f.attribute(2, 2);
    f.attribute(9, 9);
    palette(&mut f, 2, [0, 63, 0]);
    palette(&mut f, 9, [63, 0, 0]);
    f.vram.write_at(0, &[65, 0x29]).unwrap();
    f.vram.write_at(2 + 65 * 128, &[0x80]).unwrap();
    f.vram.write_at(0x8000 + 2 + 65 * 128, &[0x40]).unwrap();
    render(&mut f);
    assert_eq!(f.view.resolution(), (640, 400));
    assert_eq!(
        pixels(&mut f, 0),
        [0xffff0000, 0xffff0000, 0xff00ff00, 0xff00ff00]
    );
    f.indexed(0x3d4, 2, 80);
    render(&mut f);
    assert_eq!(
        pixels(&mut f, 0),
        [0xffff0000, 0xff00ff00, 0xff00ff00, 0xff00ff00]
    );
    f.indexed(0x3c4, 3, 0x20);
    f.attribute(0x10, 0x0a);
    render(&mut f);
    assert_eq!(
        pixels(&mut f, 0),
        [0xff00ff00, 0xffff0000, 0xff00ff00, 0xff00ff00]
    );
    f.indexed(0x3d4, 9, 31);
    render(&mut f);
    assert_eq!(f.view.resolution(), (640, 384));
}

// Test: Scroll text to a new page and place then hide its cursor on the second cell.
// Expected: Cursor location is page-relative and only its programmed scanline fills.
#[test]
fn text_cursor_tracks_page_relative_location_and_visibility() {
    let mut f = Fixture::new();
    f.indexed(0x3d4, 2, 80);
    f.indexed(0x3d4, 9, 7);
    f.attribute(0x12, 15);
    f.attribute(1, 1);
    f.attribute(2, 2);
    palette(&mut f, 1, [63, 0, 0]);
    palette(&mut f, 2, [0, 63, 0]);
    f.vram.write_at(8, &[0, 0x21]).unwrap();
    f.vram.write_at(16, &[0, 0x21]).unwrap();
    f.indexed(0x3d4, 0x0d, 1);
    f.indexed(0x3d4, 0x0f, 2);
    render(&mut f);
    assert_eq!(f.view.resolution(), (640, 400));
    let mut row = [0; 64];
    f.view.read_line(0, &mut row);
    let green = 0xff00ff00u32.to_ne_bytes();
    assert!(row.chunks_exact(4).all(|pixel| pixel == green));
    f.view.read_line(1, &mut row);
    let red = 0xffff0000u32.to_ne_bytes();
    assert!(row[..32].chunks_exact(4).all(|pixel| pixel == green));
    assert!(row[32..].chunks_exact(4).all(|pixel| pixel == red));
    f.indexed(0x3d4, 0x0a, 0x20);
    render(&mut f);
    f.view.read_line(1, &mut row);
    assert!(row.chunks_exact(4).all(|pixel| pixel == green));
}
