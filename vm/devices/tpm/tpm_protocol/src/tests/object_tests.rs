// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::command_tests::{auth, expected_command};
use super::*;
use crate::tpm20proto::*;
use test_with_tracing::test;

const PUBLIC: &[u8] = &[
    0, 25, 0, 1, 0, 11, 0, 5, 4, 0x72, 0, 0, 0, 16, 0, 16, 8, 0, 0, 0, 0, 0, 0, 3, 0xaa, 0xbb, 0xcc,
];
const AUTH: &[u8] = &[0x40, 0, 0, 1, 0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0];

// Test: Serialize import/load commands from independently encoded RSA public data, duplicate and seed buffers; parse the no-inner-wrapper payload at every truncation.
// Expected: Complete commands have exact big-endian size/opcode/auth and parameter order, no-wrapper parsing preserves all object buffers while synthesizing only the omitted empty key/NULL algorithm, and incomplete fields fail.
#[test]
fn import_and_load_preserve_object_buffers_and_wire_order() {
    let public = Tpm2bPublic::deserialize(PUBLIC).unwrap();
    assert_eq!(public.serialize(), PUBLIC);
    let empty = Tpm2bBuffer::new(&[]).unwrap();
    let duplicate = Tpm2bBuffer::new(&[1, 2, 3]).unwrap();
    let seed = Tpm2bBuffer::new(&[9, 8, 7, 6]).unwrap();
    let symmetric = TpmtSymDefObject::new(AlgIdEnum::NULL.into(), None, None);
    let import = ImportCmd::new(
        SessionTagEnum::Sessions.into(),
        TPM20_RH_OWNER,
        auth(),
        &empty,
        &public,
        &duplicate,
        &seed,
        &symmetric,
    );
    let mut body = AUTH.to_vec();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(PUBLIC);
    body.extend_from_slice(&[0, 3, 1, 2, 3, 0, 4, 9, 8, 7, 6, 0, 16]);
    assert_eq!(import.serialize(), expected_command(0x156, &body));
    assert_eq!(import.payload_size(), body.len() + 10);
    let load = LoadCmd::new(
        SessionTagEnum::Sessions.into(),
        TPM20_RH_OWNER,
        auth(),
        &duplicate,
        &public,
    );
    let mut body = AUTH.to_vec();
    body.extend_from_slice(&[0, 3, 1, 2, 3]);
    body.extend_from_slice(PUBLIC);
    assert_eq!(load.serialize(), expected_command(0x157, &body));
    assert_eq!(load.payload_size(), body.len() + 10);
    let mut payload = PUBLIC.to_vec();
    payload.extend_from_slice(&[0, 3, 1, 2, 3, 0, 4, 9, 8, 7, 6]);
    for len in 0..payload.len() {
        assert!(ImportCmd::deserialize_no_wrapping_key(&payload[..len]).is_none());
    }
    payload.extend_from_slice(&[0; 7]);
    let decoded = ImportCmd::deserialize_no_wrapping_key(&payload).unwrap();
    assert_eq!(decoded.object_public.serialize(), PUBLIC);
    assert_eq!(decoded.duplicate.serialize(), [0, 3, 1, 2, 3]);
    assert_eq!(decoded.in_sym_seed.serialize(), [0, 4, 9, 8, 7, 6]);
    assert_eq!(decoded.encryption_key.serialize(), [0, 0]);
    assert_eq!(decoded.symmetric_alg.serialize(), [0, 16]);
}

fn reply(object: bool) -> Vec<u8> {
    let mut bytes = vec![0x80, 2, 0, 0, 0, 0, 0, 0, 0, 0];
    if object {
        bytes.extend_from_slice(&[0x80, 0x11, 0x22, 0x33]);
    }
    bytes.extend_from_slice(&[0, 0, 0, 5, 0, 3, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 0]);
    let length = bytes.len() as u32;
    bytes[2..6].copy_from_slice(&length.to_be_bytes());
    bytes
}

// Test: Decode import/load/NV-read success replies and failures, truncate all post-header fields, and corrupt import/load parameter/header lengths.
// Expected: Exact nonzero private/name/data bytes, handles and authorization flags survive; header-only failures produce empty result buffers, and inconsistent or incomplete replies are rejected.
#[test]
fn variable_replies_preserve_payloads_and_reject_inconsistent_lengths() {
    let import = reply(false);
    let decoded = ImportReply::deserialize(&import).unwrap();
    assert_eq!(decoded.out_private.serialize(), [0, 3, 0xaa, 0xbb, 0xcc]);
    assert_eq!(decoded.parameter_size.get(), 5);
    assert_eq!(decoded.auth.session, 1);
    assert!(
        decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
    let load = reply(true);
    let decoded = LoadReply::deserialize(&load).unwrap();
    assert_eq!(decoded.name.serialize(), [0, 3, 0xaa, 0xbb, 0xcc]);
    assert_eq!(0x80112233u32, decoded.object_handle);
    assert_eq!(decoded.parameter_size.get(), 5);
    assert_eq!(decoded.auth.session, 1);
    assert!(
        decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
    let decoded = NvReadReply::deserialize(&import).unwrap();
    assert_eq!(decoded.data.serialize(), [0, 3, 0xaa, 0xbb, 0xcc]);
    assert_eq!(decoded.parameter_size.get(), 5);
    assert_eq!(decoded.auth.session, 1);
    assert!(
        decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
    for len in 10..import.len() {
        assert!(ImportReply::deserialize(&import[..len]).is_none());
        assert!(NvReadReply::deserialize(&import[..len]).is_none());
    }
    for len in 10..load.len() {
        assert!(LoadReply::deserialize(&load[..len]).is_none());
    }
    for field in [5, 13] {
        let mut bad = import.clone();
        bad[field] += 1;
        assert!(ImportReply::deserialize(&bad).is_none());
    }
    for field in [5, 17] {
        let mut bad = load.clone();
        bad[field] += 1;
        assert!(LoadReply::deserialize(&bad).is_none());
    }
    let failure = [0x80, 1, 0, 0, 0, 10, 0, 0, 1, 1];
    let decoded = ImportReply::deserialize(&failure).unwrap();
    assert_eq!(decoded.out_private.size.get(), 0);
    assert!(
        !decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
    let decoded = LoadReply::deserialize(&failure).unwrap();
    assert_eq!(decoded.name.size.get(), 0);
    assert_eq!(0u32, decoded.object_handle);
    assert!(
        !decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
    let decoded = NvReadReply::deserialize(&failure).unwrap();
    assert_eq!(decoded.data.size.get(), 0);
    assert!(
        !decoded
            .base_validation(SessionTagEnum::Sessions.into())
            .unwrap()
    );
}

// Test: Update an NV write to a longer payload/offset, then attempt an oversized update.
// Expected: Header size, exact payload and offset change together, while an invalid update returns the typed bound error without changing the last valid command.
#[test]
fn nv_write_updates_are_atomic_on_invalid_input() {
    let mut command = NvWriteCmd::new(
        SessionTagEnum::Sessions.into(),
        TPM20_RH_OWNER,
        auth(),
        0,
        0x01400002,
        &[1],
        0,
    )
    .unwrap();
    command
        .update_write_data(&[0xaa, 0xbb, 0xcc], 0x1234)
        .unwrap();
    let mut body = AUTH[..4].to_vec();
    body.extend_from_slice(&[1, 0x40, 0, 2]);
    body.extend_from_slice(&AUTH[4..]);
    body.extend_from_slice(&[0, 3, 0xaa, 0xbb, 0xcc, 0x12, 0x34]);
    assert_eq!(command.serialize(), expected_command(0x137, &body));
    assert_eq!(command.payload_size(), 10 + body.len());
    let previous = command.serialize();
    assert!(
        matches!(command.update_write_data(&[0;MAX_DIGEST_BUFFER_SIZE+1],0xffff),Err(TpmProtoError::NvWriteData(InvalidInput::BufferSizeTooLarge(size,MAX_DIGEST_BUFFER_SIZE))) if size==MAX_DIGEST_BUFFER_SIZE+1)
    );
    assert_eq!(command.serialize(), previous);
}
