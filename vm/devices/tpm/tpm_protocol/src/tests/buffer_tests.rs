// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::tpm20proto::*;
use test_with_tracing::test;
use zerocopy::FromBytes;

// Test: Round-trip empty, small and maximum-sized 2B payloads, with nonzero trailing input and every truncation.
// Expected: Only the declared payload is serialized, unused backing bytes are zero, limits are enforced with precise lengths, and all incomplete encodings are rejected.
#[test]
fn sized_buffers_preserve_exact_payloads_and_enforce_capacity() {
    for len in [0, 1, 7, MAX_DIGEST_BUFFER_SIZE] {
        let payload: Vec<u8> = (0..len)
            .map(|index| (index.wrapping_mul(37)) as u8)
            .collect();
        let buffer = Tpm2bBuffer::new(&payload).unwrap();
        assert_eq!(buffer.size.get() as usize, len);
        assert_eq!(&buffer.buffer[..len], payload);
        assert!(buffer.buffer[len..].iter().all(|byte| *byte == 0));
        let mut expected = (len as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(buffer.serialize(), expected);
        assert_eq!(buffer.payload_size(), len + 2);
        for end in 0..expected.len() {
            assert!(Tpm2bBuffer::deserialize(&expected[..end]).is_none());
        }
        expected.extend_from_slice(&[0xa5; 3]);
        let decoded = Tpm2bBuffer::deserialize(&expected).unwrap();
        assert_eq!(decoded.size.get() as usize, len);
        assert_eq!(&decoded.buffer[..len], payload);
        assert!(decoded.buffer[len..].iter().all(|byte| *byte == 0));
        assert_eq!(decoded.serialize(), expected[..len + 2]);
    }
    assert!(
        matches!(Tpm2bBuffer::new(&[0;MAX_DIGEST_BUFFER_SIZE+1]),Err(InvalidInput::BufferSizeTooLarge(size,MAX_DIGEST_BUFFER_SIZE)) if size==MAX_DIGEST_BUFFER_SIZE+1)
    );
    assert!(Tpm2bBuffer::deserialize(&[4, 1]).is_none());
}

// Test: Validate common reply headers for successful/failed commands, minimum sizes and session tags.
// Expected: TPM failures use a no-sessions header, successful replies use the requested session tag, and typed size/tag errors preserve the success classification.
#[test]
fn reply_headers_enforce_session_and_size_invariants() {
    for code in [0u32, 0x101, 0xdeadbeef] {
        let success = code == 0;
        let tag = if success { 0x8002u16 } else { 0x8001 };
        let minimum = if success { 19u32 } else { 10 };
        let mut header = common::ReplyHeader {
            session_tag: tag.into(),
            size: minimum.into(),
            response_code: code.into(),
        };
        assert_eq!(
            header
                .base_validation(SessionTagEnum::Sessions.into(), 19)
                .unwrap(),
            success
        );
        header.size = (minimum + 7).into();
        assert_eq!(
            header
                .base_validation(SessionTagEnum::Sessions.into(), 19)
                .unwrap(),
            success
        );
        header.size = (minimum - 1).into();
        assert!(
            matches!(header.base_validation(SessionTagEnum::Sessions.into(),19),Err(ResponseValidationError::HeaderResponseSizeMismatch { size,expected_size,command_succeeded }) if size==minimum-1 && expected_size==minimum as usize && command_succeeded==success)
        );
        header.size = minimum.into();
        header.session_tag = 0x8000.into();
        assert!(
            matches!(header.base_validation(SessionTagEnum::Sessions.into(),19),Err(ResponseValidationError::HeaderSessionTagMismatch {response_session_tag:0x8000,command_succeeded,..}) if command_succeeded==success)
        );
    }
    assert!(matches!(
        StartupCmd::base_validate_reply(&[], SessionTagEnum::NoSessions),
        Err(ResponseValidationError::ResponseSizeTooSmall)
    ));
    let reply = [0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0];
    let (decoded, success) =
        StartupCmd::base_validate_reply(&reply, SessionTagEnum::NoSessions).unwrap();
    assert!(success);
    assert_eq!(decoded.as_bytes(), reply);
}

// Test: Decode an NV read response that is shorter than its fixed header.
// Expected: Untrusted truncated bytes return None rather than causing a bounds-check panic.
#[test]
#[ignore = "Confirmed product bug: NV-read reply slices the fixed header before checking input length"]
fn known_bug_short_nv_read_reply_is_rejected_without_panicking() {
    for len in 0..10 {
        assert!(NvReadReply::deserialize(&vec![0; len]).is_none());
    }
}

// Test: Decode a session command's complete successful reply and its legal header-only TPM failure reply.
// Expected: The successful control validates with session data, while the short error reply preserves its TPM failure code without demanding success-only authorization bytes.
#[test]
#[ignore = "Confirmed product bug: typed session reply decoding rejects a legal header-only TPM failure as ResponseSizeTooSmall"]
fn known_bug_session_command_accepts_header_only_tpm_failure_reply() {
    let success = [0x80, 2, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let (_, succeeded) =
        ClearControlCmd::base_validate_reply(&success, SessionTagEnum::Sessions).unwrap();
    assert!(succeeded);
    let failure = [0x80, 1, 0, 0, 0, 10, 0, 0, 1, 1];
    let (reply, succeeded) =
        ClearControlCmd::base_validate_reply(&failure, SessionTagEnum::Sessions).unwrap();
    assert!(!succeeded);
    let header = common::ReplyHeader::read_from_prefix(reply.as_bytes())
        .unwrap()
        .0;
    assert_eq!(header.response_code.get(), 0x101);
    assert_eq!(header.size.get(), 10);
}

// Test: Provide every declared byte of over-capacity TPM2B payloads, with extra trailing input.
// Expected: Capacity rejection is independent of truncation and never copies or accepts the over-limit payload.
#[test]
fn sized_buffer_rejects_complete_oversized_wire_payloads() {
    for size in [MAX_DIGEST_BUFFER_SIZE + 1, u16::MAX as usize] {
        let mut wire = (size as u16).to_be_bytes().to_vec();
        wire.extend(std::iter::repeat_n(0xa5, size));
        wire.extend_from_slice(&[0x81, 0, 0xff, 0x27]);
        assert!(Tpm2bBuffer::deserialize(&wire).is_none());
    }
}
