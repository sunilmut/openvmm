// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::OwnedMessage;
use pal_async::local::block_on;
use std::sync::mpsc;
use test_with_tracing::test;

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Map(u64),
    SetFormat(FramebufferFormat),
    Unmap,
}

struct RecordingFramebuffer {
    requests: mpsc::Sender<Request>,
}

#[async_trait::async_trait]
impl FramebufferControl for RecordingFramebuffer {
    async fn map(&mut self, gpa: u64) {
        self.requests
            .send(Request::Map(gpa))
            .expect("test receiver remains alive");
    }

    async fn unmap(&mut self) {
        self.requests
            .send(Request::Unmap)
            .expect("test receiver remains alive");
    }

    async fn set_format(&mut self, format: FramebufferFormat) {
        self.requests
            .send(Request::SetFormat(format))
            .expect("test receiver remains alive");
    }
}

// Test: Resolve a caller-supplied framebuffer and issue mapping and format requests.
// Expected: The original control receives the full GPA, padded format and unmap
//       request in order, without substituting another control or losing fields.
#[test]
fn resolved_framebuffer_preserves_control_requests() {
    let (requests, received) = mpsc::channel();
    let mut framebuffer = ResolvedFramebuffer::from(RecordingFramebuffer { requests });
    let gpa = 0x1_0000_2000;
    let format = FramebufferFormat {
        width: 3,
        height: 2,
        bytes_per_line: 16,
        offset: 0x3000,
    };

    block_on(async {
        framebuffer.0.map(gpa).await;
        framebuffer.0.set_format(format).await;
        framebuffer.0.unmap().await;
    });

    assert_eq!(
        received.try_iter().collect::<Vec<_>>(),
        vec![
            Request::Map(gpa),
            Request::SetFormat(format),
            Request::Unmap,
        ]
    );
}

// Test: Encode and decode a framebuffer format with row padding and a nonzero offset.
// Expected: The established field tags preserve independent geometry, stride and
//       offset values, including a multibyte offset, across the wire.
#[test]
fn framebuffer_format_preserves_wire_fields() -> Result<(), mesh::payload::Error> {
    let format = FramebufferFormat {
        width: 3,
        height: 2,
        bytes_per_line: 16,
        offset: 256,
    };
    let wire = [0x08, 3, 0x10, 2, 0x18, 16, 0x20, 0x80, 0x02];

    assert_eq!(mesh::payload::encode(format), wire);
    assert_eq!(mesh::payload::decode::<FramebufferFormat>(&wire)?, format);
    Ok(())
}

// Test: Transport dirty rectangles outside the viewport and at signed-coordinate limits.
// Expected: All four signed edges survive serialization unchanged; this resource
//       type does not clip coordinates or truncate them before consumer handling.
#[test]
fn dirty_rect_preserves_signed_edges() -> Result<(), mesh::payload::Error> {
    for edges in [
        (-17, -9, 3, 5),
        (i32::MIN, i32::MIN + 1, i32::MAX - 1, i32::MAX),
    ] {
        let rect = DirtyRect {
            left: edges.0,
            top: edges.1,
            right: edges.2,
            bottom: edges.3,
        };
        let restored: DirtyRect =
            OwnedMessage::serialized(OwnedMessage::new(rect).serialize()).parse()?;

        assert_eq!(
            (restored.left, restored.top, restored.right, restored.bottom),
            edges
        );
    }
    Ok(())
}
