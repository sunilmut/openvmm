// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::io::AllowStdIo;
use futures::io::Cursor;
use pal_async::async_test;

// Test: Write a request and independently read a literal response frame.
// Expected: Length and stream ID use big-endian wire order and payloads stay intact.
#[async_test]
async fn frames_preserve_literal_wire_format() {
    let mut output = Vec::new();
    write_message(&mut output, 0x12345678, MESSAGE_TYPE_REQUEST, b"abc")
        .await
        .unwrap();
    assert_eq!(
        output,
        [0, 0, 0, 3, 0x12, 0x34, 0x56, 0x78, 1, 0, b'a', b'b', b'c']
    );
    let mut input = Cursor::new([0, 0, 0, 3, 0x87, 0x65, 0x43, 0x21, 2, 0, b'x', b'y', b'z']);
    let frame = read_message(&mut input).await.unwrap().unwrap();
    assert_eq!(frame.stream_id, 0x87654321);
    assert_eq!(frame.message_type, MESSAGE_TYPE_RESPONSE);
    assert_eq!(frame.payload.unwrap(), b"xyz");
    assert!(read_message(&mut input).await.unwrap().is_none());
}

// Test: Read zero-length and maximum-length legal payloads.
// Expected: Both boundary sizes are accepted and every payload byte survives.
#[async_test]
async fn payload_size_boundaries_are_accepted() {
    for length in [0, MAX_MESSAGE_SIZE] {
        let mut bytes = vec![0x5a; 10 + length];
        bytes[..10].copy_from_slice(&[
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            0,
            0,
            0,
            7,
            1,
            0,
        ]);
        let frame = read_message(&mut Cursor::new(bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.stream_id, 7);
        let payload = frame.payload.unwrap();
        assert_eq!(payload.len(), length);
        assert!(payload.iter().all(|&byte| byte == 0x5a));
    }
}

// Test: Follow an oversized frame with a valid frame on the same stream.
// Expected: The oversized body is discarded and the following frame stays aligned.
#[async_test]
async fn oversized_frame_does_not_desynchronize_following_frame() {
    let mut bytes = vec![0; 10 + MAX_MESSAGE_SIZE + 1];
    bytes[..10].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 7, 1, 0]);
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 9, 2, 0, 42]);
    let mut input = Cursor::new(bytes);
    let rejected = read_message(&mut input).await.unwrap().unwrap();
    assert_eq!(rejected.stream_id, 7);
    assert!(
        rejected
            .payload
            .unwrap_err()
            .to_string()
            .contains("16777216")
    );
    let following = read_message(&mut input).await.unwrap().unwrap();
    assert_eq!(following.stream_id, 9);
    assert_eq!(following.message_type, MESSAGE_TYPE_RESPONSE);
    assert_eq!(following.payload.unwrap(), [42]);
    assert!(read_message(&mut input).await.unwrap().is_none());
}

// Test: Read a complete header whose declared payload is truncated.
// Expected: Missing payload bytes produce UnexpectedEof instead of a partial message.
#[async_test]
async fn truncated_payload_returns_eof_error() {
    let mut input = Cursor::new([0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 42]);
    assert_eq!(
        read_message(&mut input).await.err().unwrap().kind(),
        ErrorKind::UnexpectedEof
    );
}

struct FailingIo {
    remaining: usize,
}

impl std::io::Read for FailingIo {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(ErrorKind::ConnectionReset.into())
    }
}

impl std::io::Write for FailingIo {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(ErrorKind::BrokenPipe.into());
        }
        let count = bytes.len().min(self.remaining);
        self.remaining -= count;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Test: Fail header reads and writes at header and payload byte boundaries.
// Expected: The I/O kind survives and write errors identify the failed phase.
#[async_test]
async fn io_failures_preserve_error_kind_and_write_phase() {
    let mut input = AllowStdIo::new(FailingIo { remaining: 0 });
    assert_eq!(
        read_message(&mut input).await.err().unwrap().kind(),
        ErrorKind::ConnectionReset
    );
    for (remaining, expected) in [
        (0, "failed writing message header"),
        (5, "failed writing message header"),
        (10, "failed writing message payload"),
        (11, "failed writing message payload"),
    ] {
        let mut output = AllowStdIo::new(FailingIo { remaining });
        let error = write_message(&mut output, 7, MESSAGE_TYPE_REQUEST, b"abc")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            ErrorKind::BrokenPipe
        );
    }
}
