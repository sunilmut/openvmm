// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::save_restore::*;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// Test: Encode and decode a saved x64 GP-register chunk followed by an epilog.
// Expected: All eighteen distinct register values occupy their wire slots;
//       the payload length excludes the header and the next chunk is intact.
#[test]
fn x64_saved_register_chunk_preserves_wire_order_and_stream_boundary() {
    let registers: [u64; 18] = [
        0x8000_0000_0000_0001,
        0x8000_0000_0000_0002,
        0x8000_0000_0000_0003,
        0x8000_0000_0000_0004,
        0x8000_0000_0000_0005,
        0x8000_0000_0000_0006,
        0x8000_0000_0000_0007,
        0x8000_0000_0000_0008,
        0x8000_0000_0000_0009,
        0x8000_0000_0000_000a,
        0x8000_0000_0000_000b,
        0x8000_0000_0000_000c,
        0x8000_0000_0000_000d,
        0x8000_0000_0000_000e,
        0x8000_0000_0000_000f,
        0x8000_0000_0000_0010,
        0xffff_f800_1234_5678,
        0x202,
    ];
    let chunk = VpX64SaveChunkGpRegisters {
        header: VmSaveChunkHeader {
            id: VmSaveChunkId::VP_GP_REGISTERS,
            data_length: 144,
            _padding: [0; 8],
        },
        rax: registers[0],
        rcx: registers[1],
        rdx: registers[2],
        rbx: registers[3],
        rsp: registers[4],
        rbp: registers[5],
        rsi: registers[6],
        rdi: registers[7],
        r8: registers[8],
        r9: registers[9],
        r10: registers[10],
        r11: registers[11],
        r12: registers[12],
        r13: registers[13],
        r14: registers[14],
        r15: registers[15],
        rip: registers[16],
        rflags: registers[17],
    };
    let mut wire = [0; 176];
    wire[..16].copy_from_slice(&[0, 0x50, 0, 0x30, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for (slot, value) in wire[16..160].chunks_exact_mut(8).zip(registers) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    wire[163] = 0xf0;
    assert_eq!(chunk.as_bytes(), &wire[..160]);

    let (decoded, remaining) = VpX64SaveChunkGpRegisters::read_from_prefix(&wire).unwrap();
    assert_eq!(decoded.header.data_length, 144);
    assert_eq!(decoded.rdx, 0x8000_0000_0000_0003);
    assert_eq!(decoded.rbx, 0x8000_0000_0000_0004);
    assert_eq!(decoded.rsp, 0x8000_0000_0000_0005);
    assert_eq!(decoded.rip, 0xffff_f800_1234_5678);
    assert_eq!(decoded.rflags, 0x202);
    assert_eq!(remaining, &wire[160..]);
    let epilog = ObSaveChunkEpilog::read_from_bytes(remaining).unwrap();
    assert_eq!(epilog.header.id, VmSaveChunkId::EPILOG);
    assert_eq!(epilog.header.data_length, 0);
    assert_eq!(epilog.header._padding, [0; 8]);
}
