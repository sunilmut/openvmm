// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Negotiate RGB332 and big-endian RGB565 over real RFB connections and request a red/green/blue/white framebuffer.
// Expected: The server accepts valid formats and emits exact channel values, byte order, rectangle dimensions, and payload lengths.
#[test]
fn negotiated_pixel_formats_produce_exact_rgb332_and_big_endian_rgb565_bytes() {
    for (bits, endian, maxima, shifts, expected) in [
        (8, 0, [7, 7, 3], [5, 2, 0], vec![0xe0, 0x1c, 0x03, 0xff]),
        (
            16,
            1,
            [31, 63, 31],
            [11, 5, 0],
            vec![0xf8, 0x00, 0x07, 0xe0, 0x00, 0x1f, 0xff, 0xff],
        ),
    ] {
        let framebuffer = SharedFramebuffer::new(4, 1, 0);
        for (x, color) in [
            pixel(255, 0, 0),
            pixel(0, 255, 0),
            pixel(0, 0, 255),
            pixel(255, 255, 255),
        ]
        .into_iter()
        .enumerate()
        {
            framebuffer.set(x as u16, 0, color);
        }
        let (result, events) = run_server_test(framebuffer, None, None, move |mut stream, _| {
            let init = handshake(&mut stream, rfb::PROTOCOL_VERSION_38);
            let mut request = rfb::SetPixelFormat::new_zeroed();
            request.message_type = rfb::CS_MESSAGE_SET_PIXEL_FORMAT;
            request.pixel_format = init.server_pixel_format;
            let format = &mut request.pixel_format;
            format.bits_per_pixel = bits;
            format.depth = bits;
            format.big_endian_flag = endian;
            format.red_max = maxima[0].into();
            format.green_max = maxima[1].into();
            format.blue_max = maxima[2].into();
            format.red_shift = shifts[0];
            format.green_shift = shifts[1];
            format.blue_shift = shifts[2];
            write_message(&mut stream, &request);
            send_framebuffer_update_request(&mut stream, false, 4, 1);
            let update: rfb::FramebufferUpdate = read_message(&mut stream);
            assert_eq!(update.message_type, rfb::SC_MESSAGE_TYPE_FRAMEBUFFER_UPDATE);
            assert_eq!(update.rectangle_count.get(), 1);
            let rectangle: rfb::Rectangle = read_message(&mut stream);
            assert_eq!(
                (
                    rectangle.x.get(),
                    rectangle.y.get(),
                    rectangle.width.get(),
                    rectangle.height.get()
                ),
                (0, 0, 4, 1)
            );
            assert_eq!(rectangle.encoding_type.get(), rfb::ENCODING_TYPE_RAW);
            let mut payload = vec![0xa5; expected.len()];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(payload, expected);
        });
        assert!(result.is_ok(), "{bits}-bit format: {result:?}");
        assert!(events.is_empty());
    }
}

// Test: Send unsupported pixel widths, indexed color, oversized channel values, and channel shifts overflowing the conversion width.
// Expected: Every malformed format closes cleanly with UnsupportedPixelFormat, without framebuffer bytes or guest input delivery.
#[test]
fn malformed_pixel_formats_return_typed_errors_without_input_or_framebuffer_output() {
    let cases: [(u8, fn(&mut rfb::PixelFormat)); 8] = [
        (24, |format| format.bits_per_pixel = 24),
        (32, |format| format.true_color_flag = 0),
        (32, |format| format.red_max = 0x1ff.into()),
        (32, |format| format.green_max = 0x1ff.into()),
        (32, |format| format.blue_max = 0x1ff.into()),
        (32, |format| format.red_shift = 31),
        (32, |format| format.green_shift = 31),
        (32, |format| format.blue_shift = 31),
    ];
    for (expected_bits, configure) in cases {
        let framebuffer = SharedFramebuffer::new(1, 1, pixel(255, 0, 0));
        let (result, events) = run_server_test(framebuffer, None, None, move |mut stream, _| {
            let init = handshake(&mut stream, rfb::PROTOCOL_VERSION_38);
            let mut request = rfb::SetPixelFormat::new_zeroed();
            request.message_type = rfb::CS_MESSAGE_SET_PIXEL_FORMAT;
            request.pixel_format = init.server_pixel_format;
            configure(&mut request.pixel_format);
            write_message(&mut stream, &request);
            let mut trailing = Vec::new();
            stream.read_to_end(&mut trailing).unwrap();
            assert!(trailing.is_empty());
        });
        assert!(
            matches!(result, Err(Error::UnsupportedPixelFormat(bits)) if bits == expected_bits),
            "{result:?}"
        );
        assert!(events.is_empty());
    }
}

// Test: Negotiate QEMU extended-key events, read the capability acknowledgement, and send an A-key make/break pair.
// Expected: The acknowledgement is one empty capability rectangle, and following raw scancodes reach guest input exactly once in order.
#[test]
fn qemu_key_capability_acknowledgement_preserves_following_raw_input() {
    let framebuffer = SharedFramebuffer::new(4, 1, 0);
    let (result, events) = run_server_test(framebuffer, None, None, |mut stream, _| {
        handshake(&mut stream, rfb::PROTOCOL_VERSION_38);
        send_set_encodings(
            &mut stream,
            &[
                rfb::ENCODING_TYPE_RAW,
                rfb::ENCODING_TYPE_QEMU_EXTENDED_KEY_EVENT,
            ],
        );
        let rectangles = read_framebuffer_update(&mut stream);
        assert_eq!(rectangles.len(), 1);
        let rectangle = &rectangles[0];
        assert_eq!(
            rectangle.header.encoding_type.get(),
            rfb::ENCODING_TYPE_QEMU_EXTENDED_KEY_EVENT
        );
        assert_eq!(
            (
                rectangle.header.x.get(),
                rectangle.header.y.get(),
                rectangle.header.width.get(),
                rectangle.header.height.get()
            ),
            (0, 0, 0, 0)
        );
        assert!(rectangle.payload.is_empty());
        send_qemu_key_event(&mut stream, true, 0x1e);
        send_qemu_key_event(&mut stream, false, 0x1e);
    });
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        events,
        [InputEvent::Key(0x1e, true), InputEvent::Key(0x1e, false)]
    );
}
