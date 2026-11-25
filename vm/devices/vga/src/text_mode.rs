// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::emu::TextModeState;
use crate::spec;
use guestmem::GuestMemory;
use std::cmp::min;

struct ExpandPixelsTable([[u32; 4]; 16]);

pub struct Parameters {
    pub column_left: i32,
    pub column_right: i32,
    pub clip_left: i32,
    pub clip_right: i32,
    pub row_number_top: i32,
    pub row_number_bottom: i32,
}

pub fn blit_text(
    vram: &GuestMemory,
    parameters: &Parameters,
    text_state: &TextModeState,
    colors: &[u32; 256],
    text_start: usize,
    dest_start: usize,
) {
    let (cursor_row, cursor_col);

    cursor_row = text_state.cursor_row;
    cursor_col = text_state.cursor_col;

    for row_iter in parameters.row_number_top..parameters.row_number_bottom {
        let mut old_color = 256; // this value will force the expand table to be updated first time.
        let mut expand_pixels_table = ExpandPixelsTable([[0; 4]; 16]);

        const TEXT_DOUBLE_TABLE: [u8; 16] = [
            0x00, 0x03, 0x0C, 0x0F, 0x30, 0x33, 0x3C, 0x3F, 0xC0, 0xC3, 0xCC, 0xCF, 0xF0, 0xF3,
            0xFC, 0xFF,
        ];

        let char_bit_map_base = text_state.char_set_1 as u64 * 0x8000 + 2;
        let ext_char_bit_map_base = text_state.char_set_2 as u64 * 0x8000 + 2;

        // calculate which text row we're going to be drawing.
        let text_row = (row_iter / text_state.text_char_height as i32) as u16;
        let char_row = (row_iter % text_state.text_char_height as i32) as u16;

        let is_cursor_row = text_state.draw_text_cursor
            && text_state.cursor_blink_state
            && (text_row == cursor_row);

        let char_width = if text_state.lo_res_text_mode {
            spec::VGA_LORES_CHARACTER_WIDTH
        } else {
            spec::VGA_HIRES_CHARACTER_WIDTH
        } as i32;

        // Try to clip to full characters.
        let mut left_col = (parameters.column_left & !(char_width - 1)).max(parameters.clip_left);
        let right_col = ((parameters.column_right + (char_width - 1)) & !(char_width - 1))
            .min(parameters.clip_right);

        while left_col < right_col {
            let cell =
                text_row * text_state.current_text_columns + (left_col as u16 / char_width as u16);

            // Read and translate the value.
            let text_data = vram
                .read_plain(text_start as u64 + cell as u64 * 8)
                .expect("BUGBUG");

            let mut text_data = u16::from_be_bytes(text_data);
            if text_state.blinking_enabled {
                if text_state.blinking_state && text_data & spec::CGA_CHARACTER_BLINKING_MASK != 0 {
                    text_data = (text_data & !spec::CGA_CHARACTER_FOREGROUND_COLOR_MASK)
                        | ((text_data
                            & spec::CGA_CHARACTER_BACKGROUND_COLOR_MASK
                            & !spec::CGA_CHARACTER_BLINKING_MASK)
                            >> 4);
                }
                text_data &= 0xff7f;
            }

            if old_color
                != (text_data
                    & (spec::CGA_CHARACTER_BACKGROUND_COLOR_MASK
                        | spec::CGA_CHARACTER_FOREGROUND_COLOR_MASK))
            {
                old_color = text_data
                    & (spec::CGA_CHARACTER_BACKGROUND_COLOR_MASK
                        | spec::CGA_CHARACTER_FOREGROUND_COLOR_MASK);

                let fore_color = text_data as usize & 15;
                let back_color = (text_data >> 4) as usize & 15;
                rebuild_expand_pixels_table(
                    &mut expand_pixels_table,
                    colors[fore_color],
                    colors[back_color],
                );
            }

            let char_data: u8 = if is_cursor_row
                && ((left_col / char_width) == cursor_col as i32)
                && (char_row >= text_state.cursor_first_scanline)
                && (char_row <= text_state.cursor_last_scanline)
            {
                0xFF
            } else {
                let mut current_char_bit_map =
                    char_bit_map_base + (((text_data as u64 >> 8) << 7) + 4 * char_row as u64);
                if text_state.character_set_512 {
                    if (text_data & 0x08) == 0 {
                        current_char_bit_map = ext_char_bit_map_base
                            + (((text_data as u64 >> 8) << 7) + 4 * char_row as u64);
                    }
                }

                vram.read_plain(current_char_bit_map).unwrap()
            };

            let mut char_data = char_data as u16;
            if text_state.lo_res_text_mode {
                // pixel expand.
                char_data = TEXT_DOUBLE_TABLE[char_data as usize & 0xF] as u16
                    | ((TEXT_DOUBLE_TABLE[char_data as usize >> 4] as u16) << 8);
            }

            let mut offset = (row_iter * 640 + left_col) * 4;
            let mut write_32bit = |n: u32| {
                vram.write_at((dest_start + offset as usize) as u64, &n.to_ne_bytes())
                    .unwrap();
                offset += 4;
            };

            // there are three possible cases here.
            // 1. We have a partial char
            // 3. We have a full, aligned char
            // 4. we have a full, misaligned char.
            if (left_col & (char_width - 1)) != 0 || (right_col - left_col < char_width) {
                let end_blit = min(right_col, (left_col + char_width) & !(char_width - 1));

                let fore_color = text_data as usize & 15;
                let fore_color = colors[fore_color];
                let back_color = (text_data as usize >> 4) & 15;
                let back_color = colors[back_color];

                while left_col < end_blit {
                    let test_bit = char_width - (left_col & (char_width - 1)) - 1;
                    if ((char_data >> test_bit) & 0x1) != 0 {
                        write_32bit(fore_color);
                    } else {
                        write_32bit(back_color);
                    }

                    left_col += 1;
                }
            } else if right_col - left_col >= char_width {
                left_col += char_width;

                let mut fill_char_data = if text_state.lo_res_text_mode {
                    char_data >> 8
                } else {
                    char_data
                } as u8;

                for _ in (0..char_width).step_by(spec::VGA_HIRES_CHARACTER_WIDTH.into()) {
                    write_32bit(expand_pixels_table.0[fill_char_data as usize >> 4][0]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize >> 4][1]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize >> 4][2]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize >> 4][3]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize & 0xF][0]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize & 0xF][1]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize & 0xF][2]);
                    write_32bit(expand_pixels_table.0[fill_char_data as usize & 0xF][3]);

                    // get the second half for a lo-res pixel.
                    fill_char_data = char_data as u8;
                }
            }
        }
    }
}

fn rebuild_expand_pixels_table(
    expand_table: &mut ExpandPixelsTable,
    fore_color: u32,
    back_color: u32,
) {
    for cur_entry in 0..16 {
        let color = |mask| {
            if cur_entry & mask != 0 {
                fore_color
            } else {
                back_color
            }
        };
        expand_table.0[cur_entry] = [color(8), color(4), color(2), color(1)];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Create a small text layout with independent font banks and a hidden cursor.
    fn text_state() -> TextModeState {
        TextModeState {
            current_text_columns: 80,
            lo_res_text_mode: false,
            mono_text_mode: false,
            character_set_512: false,
            char_set_1: 0,
            char_set_2: 1,
            text_char_width: 8,
            text_char_height: 2,
            text_rows: 1,
            blinking_enabled: false,
            blinking_state: false,
            draw_text_cursor: false,
            cursor_first_scanline: 0,
            cursor_last_scanline: 0,
            cursor_row: 0,
            cursor_col: 0,
            cursor_blink_state: true,
        }
    }

    // Test: Clip a text glyph on both sides while preserving the surrounding image.
    // Expected: Only the requested pixels change and character bits remain aligned.
    #[test]
    fn clipped_glyphs_preserve_neighboring_pixels() {
        let vram = GuestMemory::allocate(0x20000);
        vram.write_at(0, &[1, 0x21]).unwrap();
        vram.write_at(2 + 128, &[0xaa]).unwrap();
        vram.write_plain(0x10000, &[99u32; 8]).unwrap();
        let params = Parameters {
            column_left: 0,
            column_right: 8,
            clip_left: 2,
            clip_right: 5,
            row_number_top: 0,
            row_number_bottom: 1,
        };
        let colors = std::array::from_fn(|i| i as u32);
        blit_text(&vram, &params, &text_state(), &colors, 0, 0x10000);
        assert_eq!(
            vram.read_plain::<[u32; 8]>(0x10000).unwrap(),
            [99, 99, 1, 2, 1, 99, 99, 99]
        );
    }

    // Test: Expand a low-resolution glyph with different nibbles.
    // Expected: Every original glyph bit becomes two adjacent pixels in order.
    #[test]
    fn low_resolution_glyphs_double_each_pixel() {
        let vram = GuestMemory::allocate(0x20000);
        vram.write_at(0, &[1, 0x21]).unwrap();
        vram.write_at(2 + 128, &[0xa5]).unwrap();
        let mut state = text_state();
        state.lo_res_text_mode = true;
        state.current_text_columns = 40;
        state.text_char_width = 16;
        let params = Parameters {
            column_left: 0,
            column_right: 16,
            clip_left: 0,
            clip_right: 16,
            row_number_top: 0,
            row_number_bottom: 1,
        };
        let colors = std::array::from_fn(|i| i as u32);
        blit_text(&vram, &params, &state, &colors, 0, 0x10000);
        assert_eq!(
            vram.read_plain::<[u32; 16]>(0x10000).unwrap(),
            [1, 1, 2, 2, 1, 1, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1]
        );
    }

    // Test: Render a blinking glyph and overlay a visible cursor on one scanline.
    // Expected: Blink hides the glyph, while the cursor fills only its selected row.
    #[test]
    fn text_blink_and_cursor_have_independent_visibility() {
        let vram = GuestMemory::allocate(0x20000);
        vram.write_at(0, &[1, 0xa1]).unwrap();
        vram.write_at(2 + 128, &[0xff]).unwrap();
        let mut state = text_state();
        state.blinking_enabled = true;
        state.blinking_state = true;
        let params = Parameters {
            column_left: 0,
            column_right: 8,
            clip_left: 0,
            clip_right: 8,
            row_number_top: 0,
            row_number_bottom: 2,
        };
        let colors = std::array::from_fn(|i| i as u32);
        blit_text(&vram, &params, &state, &colors, 0, 0x10000);
        assert_eq!(vram.read_plain::<[u32; 8]>(0x10000).unwrap(), [2; 8]);
        state.blinking_state = false;
        state.draw_text_cursor = true;
        state.cursor_first_scanline = 1;
        state.cursor_last_scanline = 1;
        vram.write_at(2 + 128, &[0]).unwrap();
        blit_text(&vram, &params, &state, &colors, 0, 0x10000);
        assert_eq!(vram.read_plain::<[u32; 8]>(0x10000).unwrap(), [2; 8]);
        assert_eq!(
            vram.read_plain::<[u32; 8]>(0x10000 + 640 * 4).unwrap(),
            [1; 8]
        );
        state.cursor_blink_state = false;
        blit_text(&vram, &params, &state, &colors, 0, 0x10000);
        assert_eq!(
            vram.read_plain::<[u32; 8]>(0x10000 + 640 * 4).unwrap(),
            [2; 8]
        );
    }

    // Test: Select two font banks with the text attribute's intensity bit.
    // Expected: Each character uses the selected bank rather than the other glyph.
    #[test]
    fn extended_character_sets_select_the_requested_font_bank() {
        let vram = GuestMemory::allocate(0x20000);
        vram.write_at(0, &[1, 1]).unwrap();
        vram.write_at(8, &[1, 9]).unwrap();
        vram.write_at(2 + 128, &[0xff]).unwrap();
        vram.write_at(0x8000 + 2 + 128, &[0]).unwrap();
        let mut state = text_state();
        state.character_set_512 = true;
        let params = Parameters {
            column_left: 0,
            column_right: 16,
            clip_left: 0,
            clip_right: 16,
            row_number_top: 0,
            row_number_bottom: 1,
        };
        let colors = std::array::from_fn(|i| i as u32);
        blit_text(&vram, &params, &state, &colors, 0, 0x10000);
        assert_eq!(
            vram.read_plain::<[u32; 16]>(0x10000).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9]
        );
    }
}
