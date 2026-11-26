// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use futures::StreamExt;
use mesh_input::input_pair;
use test_with_tracing::test;

// Test: Activate independent keyboard sources and drain make/repeat/break events.
// Expected: Activation reaches only the matching sink; event order and fields
//       survive boxing, and sender closure does not discard queued keystrokes.
#[test]
fn keyboard_activation_and_queued_events() {
    futures::executor::block_on(async {
        let (source, mut sink) = input_pair::<KeyboardData>();
        let mut source = ResolvedInputSource::from(source).0;
        let (mut other_source, other_sink) = input_pair::<KeyboardData>();
        assert!(!sink.is_active());
        assert!(!other_sink.is_active());
        assert!(source.next().now_or_never().is_none());
        for active in [true, true, false, false, true] {
            source.set_active(active).await;
            assert_eq!(sink.is_active(), active);
            assert!(!other_sink.is_active());
        }
        other_source.set_active(true).await;
        source.set_active(false).await;
        assert!(!sink.is_active());
        assert!(other_sink.is_active());
        let events = [
            KeyboardData {
                code: 0x1e,
                make: true,
            },
            KeyboardData {
                code: 0x1e,
                make: true,
            },
            KeyboardData {
                code: 0x1e,
                make: false,
            },
            KeyboardData {
                code: 0xe01d,
                make: true,
            },
            KeyboardData {
                code: 0xe01d,
                make: false,
            },
        ];
        for event in events {
            sink.send(event);
        }
        drop(sink);
        for expected in events {
            let actual = source.next().await.unwrap();
            assert_eq!((actual.code, actual.make), (expected.code, expected.make));
        }
        assert!(source.next().await.is_none());
        assert!(other_source.next().now_or_never().is_none());
    });
}

// Test: Deliver absolute mouse positions and button transitions through a boxed source.
// Expected: Full-width coordinates and button combinations are preserved,
//       independent activation remains acknowledged and closure ends the stream.
#[test]
fn mouse_absolute_coordinates_and_buttons() {
    futures::executor::block_on(async {
        let (source, mut sink) = input_pair::<MouseData>();
        let mut source = ResolvedInputSource::from(source).0;
        source.set_active(true).await;
        assert!(sink.is_active());
        let events = [
            MouseData {
                button_mask: 0,
                x: 0,
                y: u16::MAX,
            },
            MouseData {
                button_mask: 5,
                x: u16::MAX,
                y: 0,
            },
            MouseData {
                button_mask: 0,
                x: 12345,
                y: 54321,
            },
        ];
        for event in events {
            sink.send(event);
        }
        for expected in events {
            let actual = source.next().await.unwrap();
            assert_eq!(
                (actual.button_mask, actual.x, actual.y),
                (expected.button_mask, expected.x, expected.y)
            );
        }
        source.set_active(false).await;
        assert!(!sink.is_active());
        drop(sink);
        assert!(source.next().await.is_none());
    });
}
