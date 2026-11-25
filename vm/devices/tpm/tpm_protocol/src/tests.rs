// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tpm20proto::protocol::*;
use test_with_tracing::test;
use zerocopy::IntoBytes;

mod buffer_tests;
mod code_tests;
mod command_tests;
mod object_tests;

// Test: Decode independent NV-read commands with variable authorization sizes and truncate each field boundary, then update the decoded range.
// Expected: The NV index, size and offset are exact big-endian values regardless of skipped auth bytes; incomplete or wrong-opcode commands are rejected, and range updates preserve the index.
#[test]
fn nv_read_command_decodes_authorization_boundaries_and_updates_range() {
    for auth_len in [0usize, 9, 13] {
        let mut wire = vec![
            0x80, 2, 0, 0, 0, 0, 0, 0, 1, 0x4e, 0x40, 0, 0, 1, 1, 0x40, 0, 2,
        ];
        wire.extend_from_slice(&(auth_len as u32).to_be_bytes());
        wire.extend_from_slice(&vec![0xa5; auth_len]);
        wire.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let len = wire.len() as u32;
        wire[2..6].copy_from_slice(&len.to_be_bytes());
        let mut command = NvReadCmd::deserialize(&wire).unwrap();
        assert_eq!(command.nv_index.get(), 0x01400002);
        assert_eq!(command.offset.get(), 0x5678);
        let bytes = command.as_bytes();
        assert_eq!(&bytes[bytes.len() - 4..], &[0x12, 0x34, 0x56, 0x78]);
        for end in 0..wire.len() {
            assert!(
                NvReadCmd::deserialize(&wire[..end]).is_none(),
                "accepted truncated command at {end}"
            );
        }
        command.update_read_parameters(0x9abc, 0xdef0);
        assert_eq!(command.nv_index.get(), 0x01400002);
        assert_eq!(command.offset.get(), 0xdef0);
        let bytes = command.as_bytes();
        assert_eq!(&bytes[bytes.len() - 4..], &[0x9a, 0xbc, 0xde, 0xf0]);
        wire[9] = 0x4f;
        assert!(NvReadCmd::deserialize(&wire).is_none());
    }
}
