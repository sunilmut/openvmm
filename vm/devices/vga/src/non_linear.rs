// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Non-linear blitting routines.

use crate::text_mode::Parameters;
use guestmem::GuestMemory;
use std::cmp::max;
use std::cmp::min;

pub fn blit_non_linear4to32(
    vram: &GuestMemory,
    parameters: &Parameters,
    colors: &[u32; 256],
    pixel_pan: u8,
    double_horiz: bool,
    double_vert: bool,
    src_start: usize,
    line_offset_pixels: u16,
    dest_start: usize,
    dest_row_bytes: usize,
) {
    let horizontal_load_mask = if double_horiz { 0xF } else { 0x7 };
    let horizontal_advance_mask = double_horiz as i32;
    let horizontal_shift = if double_horiz { 4 } else { 3 };
    let vertical_shift = double_vert as u8;
    let source_row_bytes = line_offset_pixels;

    let pixel_pan = (pixel_pan as i32) << horizontal_advance_mask;

    for row_iter in parameters.row_number_top..parameters.row_number_bottom {
        let mut left_col = max(parameters.clip_left, parameters.column_left);
        let right_col = min(parameters.clip_right, parameters.column_right);

        if left_col >= right_col {
            continue;
        }

        let mut offset = (row_iter * dest_row_bytes as i32) + left_col * 4;
        let mut write_32_bit = |n: u32| {
            vram.write_at((dest_start + offset as usize) as u64, &n.to_ne_bytes())
                .unwrap();
            offset += 4;
        };

        let source_video_offset = source_row_bytes as i32 * (row_iter >> vertical_shift);

        let read_u32 = |offset: i32| -> u32 {
            vram.read_plain(src_start as u64 + (source_video_offset as u64 + offset as u64) * 4)
                .unwrap()
        };

        let mut non_linear_data = 0;
        if ((left_col + pixel_pan) & horizontal_load_mask) != 0 {
            let converted_source_address0 = read_u32((left_col + pixel_pan) >> horizontal_shift);
            non_linear_data = converted_source_address0;

            let shift_alignment =
                ((left_col + pixel_pan) & horizontal_load_mask) >> horizontal_advance_mask;

            non_linear_data <<= shift_alignment;
        }

        while left_col < right_col {
            if ((left_col + pixel_pan) & horizontal_load_mask) == 0 {
                let converted_source_address0 =
                    read_u32((left_col + pixel_pan) >> horizontal_shift);
                non_linear_data = converted_source_address0;
            }

            let index = ((non_linear_data >> 28) & 0x08)
                | ((non_linear_data >> 21) & 0x04)
                | ((non_linear_data >> 14) & 0x02)
                | ((non_linear_data >> 7) & 0x01);

            let source0 = colors[index as usize];
            write_32_bit(source0);

            left_col += 1;
            if ((left_col + pixel_pan) & horizontal_advance_mask) == 0 {
                non_linear_data <<= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Render eight pixels whose four VGA planes have distinct bit patterns.
    // Expected: Each output pixel uses the palette entry selected by all planes.
    #[test]
    fn planar_pixels_select_palette_colors() {
        let vram = GuestMemory::allocate(4096);
        vram.write_plain(0, &0x0ff0_ccaa_u32).unwrap();
        let colors = std::array::from_fn(|i| 0xff00_0000 | i as u32);
        let parameters = Parameters {
            column_left: 0,
            column_right: 8,
            clip_left: 0,
            clip_right: 8,
            row_number_top: 0,
            row_number_bottom: 1,
        };
        blit_non_linear4to32(&vram, &parameters, &colors, 0, false, false, 0, 1, 256, 32);
        let pixels: [u32; 8] = vram.read_plain(256).unwrap();
        assert_eq!(pixels, [7, 6, 5, 4, 11, 10, 9, 8].map(|i| colors[i]));
    }

    // Test: Pan a planar row and clip both sides of the destination.
    // Expected: Only clipped pixels change, starting at the panned source bit.
    #[test]
    fn panning_and_clipping_preserve_surrounding_pixels() {
        let vram = GuestMemory::allocate(4096);
        vram.write_plain(0, &0x0ff0_ccaa_u32).unwrap();
        vram.write_plain(256, &[0xdead_beef_u32; 8]).unwrap();
        let colors = std::array::from_fn(|i| i as u32);
        let parameters = Parameters {
            column_left: 0,
            column_right: 8,
            clip_left: 2,
            clip_right: 5,
            row_number_top: 0,
            row_number_bottom: 1,
        };
        blit_non_linear4to32(&vram, &parameters, &colors, 1, false, false, 0, 1, 256, 32);
        let pixels: [u32; 8] = vram.read_plain(256).unwrap();
        assert_eq!(
            pixels,
            [
                0xdead_beef,
                0xdead_beef,
                4,
                11,
                10,
                0xdead_beef,
                0xdead_beef,
                0xdead_beef
            ]
        );
    }

    // Test: Render a planar row with horizontal and vertical pixel doubling.
    // Expected: Each source pixel becomes a two-by-two block of its palette color.
    #[test]
    fn doubled_pixels_repeat_in_both_dimensions() {
        let vram = GuestMemory::allocate(4096);
        vram.write_plain(0, &0x0ff0_ccaa_u32).unwrap();
        let colors = std::array::from_fn(|i| i as u32);
        let parameters = Parameters {
            column_left: 0,
            column_right: 16,
            clip_left: 0,
            clip_right: 16,
            row_number_top: 0,
            row_number_bottom: 2,
        };
        blit_non_linear4to32(&vram, &parameters, &colors, 0, true, true, 0, 1, 256, 64);
        let expected = [7, 7, 6, 6, 5, 5, 4, 4, 11, 11, 10, 10, 9, 9, 8, 8];
        assert_eq!(vram.read_plain::<[u32; 16]>(256).unwrap(), expected);
        assert_eq!(vram.read_plain::<[u32; 16]>(320).unwrap(), expected);
    }
}
