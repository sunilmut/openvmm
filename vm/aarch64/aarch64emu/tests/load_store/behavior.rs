// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use aarch64defs::IssDataAbort;
use aarch64emu::Error;

fn syndrome(abort: IssDataAbort, il: bool) -> InterceptState {
    InterceptState {
        gpa: Some(0x8000),
        syndrome: aarch64defs::EsrEl2::from(abort.with_isv(true)).with_il(il),
        ..Default::default()
    }
}

fn cpu() -> (CpuState, SingleCellCpu) {
    let mut state = CpuState::default();
    state.update_pc(0x1000);
    state.update_x(1, 0x8000);
    let mut cpu = SingleCellCpu::new(state.clone());
    cpu.valid_gva = 0x8000;
    (state, cpu)
}

// Test: Emulate physical data-abort reads for all access widths and extensions.
// Expected: Architectural registers contain the correctly extended value, the
//       PC advances by the syndrome's instruction length, and no fetch is needed.
#[async_test]
async fn syndrome_loads_apply_width_sign_and_instruction_length() {
    for size in 0..4 {
        for signed in [false, true] {
            for wide in [false, true] {
                for il in [false, true] {
                    let (mut state, mut cpu) = cpu();
                    cpu.fail_instruction = true;
                    *cpu.mem_val.lock().await = 0xffff_ffff_ffff_ff80;
                    let intercept = syndrome(
                        IssDataAbort::new()
                            .with_srt(2)
                            .with_sas(size)
                            .with_sse(signed)
                            .with_sf(wide),
                        il,
                    );
                    Emulator::new(&mut cpu, &intercept).run().await.unwrap();
                    let mut expected = match size {
                        0 => 0x80,
                        1 => 0xff80,
                        2 => 0xffff_ff80,
                        3 => 0xffff_ffff_ffff_ff80,
                        _ => unreachable!(),
                    };
                    if signed {
                        expected = 0xffff_ffff_ffff_ff80;
                        if !wide {
                            expected &= 0xffff_ffff;
                        }
                    }
                    assert_eq!(state.x(2), expected);
                    assert_eq!(state.pc(), 0x1000 + if il { 4 } else { 2 });
                }
            }
        }
    }
}

// Test: Emulate syndrome stores from a general register or the zero register.
// Expected: Only the selected byte range changes, register 31 supplies zeros,
//       and storing through the syndrome path advances the PC exactly once.
#[async_test]
async fn syndrome_stores_preserve_neighbors_and_zero_register_semantics() {
    for size in 0..4 {
        for register in [0, 31] {
            let (mut state, mut cpu) = cpu();
            state.update_x(0, 0x1122_3344_5566_7788);
            *cpu.mem_val.lock().await = u128::MAX;
            let intercept = syndrome(
                IssDataAbort::new()
                    .with_srt(register)
                    .with_sas(size)
                    .with_wnr(true),
                true,
            );
            Emulator::new(&mut cpu, &intercept).run().await.unwrap();
            let mask = (1u128 << (8 * (1 << size))) - 1;
            let value = if register == 31 {
                0
            } else {
                0x1122_3344_5566_7788
            };
            assert_eq!(*cpu.mem_val.lock().await, !mask | (value & mask));
            assert_eq!(state.pc(), 0x1004);
        }
    }
}

// Test: Load the zero register through a valid data-abort syndrome.
// Expected: The access is discarded without reading memory or fetching code,
//       while the instruction still retires.
#[async_test]
async fn syndrome_zero_register_load_has_no_memory_side_effects() {
    let (mut state, mut cpu) = cpu();
    cpu.valid_gva = 0;
    cpu.fail_instruction = true;
    let intercept = syndrome(IssDataAbort::new().with_srt(31).with_sas(3), true);
    Emulator::new(&mut cpu, &intercept).run().await.unwrap();
    assert_eq!(state.pc(), 0x1004);
}

// Test: Fall back to instruction decoding when syndrome metadata cannot be used.
// Expected: Missing/invalid syndrome data and failed physical accesses all use
//       the supplied instruction, preserving its guest-visible load semantics.
#[async_test]
async fn unusable_syndromes_fall_back_to_instruction_emulation() {
    for case in 0..5 {
        let (mut state, mut cpu) = cpu();
        *cpu.mem_val.lock().await = 0x8877_6655_4433_2211;
        let mut intercept = syndrome(
            IssDataAbort::new()
                .with_srt(2)
                .with_sas(3)
                .with_wnr(case == 4),
            true,
        );
        intercept.instruction_byte_count = 4;
        intercept.instruction_bytes = 0xf940_0022u32.to_le_bytes(); // LDR X2, [X1].
        match case {
            0 => intercept.gpa = None,
            1 => {
                intercept.syndrome = intercept
                    .syndrome
                    .with_ec(aarch64defs::ExceptionClass::SYSTEM.0)
            }
            2 => intercept.syndrome = intercept.syndrome.with_d(false),
            3 | 4 => intercept.gpa = Some(0xdead_0000),
            _ => unreachable!(),
        }
        Emulator::new(&mut cpu, &intercept).run().await.unwrap();
        assert_eq!(state.x(2), 0x8877_6655_4433_2211);
        assert_eq!(state.pc(), 0x1004);
    }
}

// Test: Decode unsupported instruction encodings and incomplete intercept bytes.
// Expected: The emulator returns a typed error and does not advance the PC.
#[async_test]
async fn unsupported_instructions_do_not_retire() {
    for (opcode, byte_count) in [
        (0x0200_0000u32, 4),
        (0xd503_201f, 4),
        (0x0800_0000, 4),
        (0, 2),
    ] {
        let (mut state, mut cpu) = cpu();
        let intercept = InterceptState {
            instruction_bytes: opcode.to_le_bytes(),
            instruction_byte_count: byte_count,
            ..Default::default()
        };
        let error = Emulator::new(&mut cpu, &intercept).run().await.unwrap_err();
        match opcode {
            0x0200_0000 => {
                assert!(matches!(*error, Error::UnsupportedInstruction(value) if value == opcode))
            }
            0xd503_201f => assert!(
                matches!(*error, Error::UnsupportedInstructionGroup(_, value) if value == opcode)
            ),
            0x0800_0000 => assert!(
                matches!(*error, Error::UnsupportedLoadStoreInstruction(_, value) if value == opcode)
            ),
            _ => assert!(matches!(*error, Error::UnsupportedInstructionSet)),
        }
        assert_eq!(state.pc(), 0x1000);
    }
}

// Test: Fail instruction fetch, data read, data write and atomic compare/write.
// Expected: Each failure reaches the caller as a memory-access error and leaves
//       the faulting instruction's PC unchanged.
#[async_test]
async fn memory_failures_preserve_faulting_instruction_position() {
    for case in 0..4 {
        let (mut state, mut cpu) = cpu();
        cpu.fail_instruction = case == 0;
        cpu.fail_compare = case == 3;
        if case == 1 || case == 2 {
            cpu.valid_gva = 0x9000;
        }
        state.update_instruction(match case {
            0 | 1 => 0xf940_0022, // LDR X2, [X1].
            2 => 0xf900_0022,     // STR X2, [X1].
            3 => ldadd(3, false, false, 0, 1, 2),
            _ => unreachable!(),
        });
        let error = Emulator::new(&mut cpu, &InterceptState::default())
            .run()
            .await
            .unwrap_err();
        assert!(
            matches!(*error, Error::MemoryAccess(address, _, TestCpuError::BadAddress) if address == if case == 0 { 0x1000 } else { 0x8000 })
        );
        assert_eq!(state.pc(), 0x1000);
    }
}

// Test: Store scalar and SIMD registers through nested borrowed CPU adapters.
// Expected: Each architectural width writes exactly its low-order bytes and
//       preserves adjacent memory, including the complete 128-bit SIMD value.
#[async_test]
async fn borrowed_cpu_stores_preserve_scalar_and_simd_widths() {
    for (opcode, length, simd) in [
        (0x3900_0020u32, 1, false),
        (0x7900_0020, 2, false),
        (0xb900_0020, 4, false),
        (0xf900_0020, 8, false),
        (0x3d00_0020, 1, true),
        (0x7d00_0020, 2, true),
        (0xbd00_0020, 4, true),
        (0xfd00_0020, 8, true),
        (0x3d80_0020, 16, true),
    ] {
        let (mut state, mut cpu) = cpu();
        let value = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        state.update_x(0, value as u64);
        state.update_q(0, value);
        *cpu.mem_val.lock().await = u128::MAX;
        state.update_instruction(opcode);
        let mut borrowed = &mut cpu;
        Emulator::new(&mut borrowed, &InterceptState::default())
            .run()
            .await
            .unwrap();
        let mask = if length == 16 {
            u128::MAX
        } else {
            (1u128 << (8 * length)) - 1
        };
        let expected = if simd { value } else { value as u64 as u128 };
        assert_eq!(*cpu.mem_val.lock().await, !mask | (expected & mask));
        assert_eq!(state.pc(), 0x1004);
    }
}

// Test: Retry an atomic update after the host reports compare/exchange contention.
// Expected: The operation eventually returns the original memory value and
//       updates memory once, without incrementing the PC for failed attempts.
#[async_test]
async fn borrowed_cpu_atomic_retries_retire_once() {
    let (mut state, mut cpu) = cpu();
    cpu.compare_retries = 2;
    state.update_x(0, 7);
    state.update_instruction(ldadd(3, false, false, 0, 1, 2));
    *cpu.mem_val.lock().await = 11;
    Emulator::new(&mut cpu, &InterceptState::default())
        .run()
        .await
        .unwrap();
    assert_eq!(state.x(2), 11);
    assert_eq!(*cpu.mem_val.lock().await, 18);
    assert_eq!(state.pc(), 0x1004);
}

// Test: Execute literal SIMD loads and a prefetch through a borrowed CPU.
// Expected: The load updates its complete architectural vector and prefetch
//       retires without touching invalid guest memory.
#[async_test]
async fn literal_simd_and_prefetch_have_architectural_effects() {
    let (mut state, mut cpu) = cpu();
    *cpu.mem_val.lock().await = 0x1234_5678_9abc_def0_fedc_ba98_7654_3210;
    state.update_instruction(0x9c00_0000 | (0x1c00 << 5)); // LDR Q0, PC+0x7000.
    Emulator::new(&mut cpu, &InterceptState::default())
        .run()
        .await
        .unwrap();
    assert_eq!(state.q(0), *cpu.mem_val.lock().await);
    cpu.valid_gva = 0;
    state.update_instruction(0xd800_0000); // PRFM literal.
    Emulator::new(&mut cpu, &InterceptState::default())
        .run()
        .await
        .unwrap();
    assert_eq!(state.pc(), 0x1008);
}

// Test: Fault the first write of scalar and SIMD paired-store instructions.
// Expected: The memory error is returned without retiring the instruction or
//       changing any guest memory, including when either source is register 31.
#[async_test]
async fn paired_store_first_access_failures_preserve_guest_memory() {
    for opcode in [
        0x2900_0820u32,
        0xa900_0820,
        0x2d00_0820,
        0x6d00_0820,
        0xad00_0820,
    ] {
        for zero_first in [false, true] {
            for zero_second in [false, true] {
                let (mut state, mut cpu) = cpu();
                cpu.valid_gva = 0x9000;
                let original = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
                *cpu.mem_val.lock().await = original;
                state.update_x(0, 0x1111);
                state.update_x(2, 0x2222);
                state.update_q(0, 0x3333);
                state.update_q(2, 0x4444);
                let opcode = if zero_first { opcode | 31 } else { opcode };
                let opcode = if zero_second {
                    (opcode & !(31 << 10)) | (31 << 10)
                } else {
                    opcode
                };
                state.update_instruction(opcode);
                let error = Emulator::new(&mut cpu, &InterceptState::default())
                    .run()
                    .await
                    .unwrap_err();
                assert!(matches!(
                    *error,
                    Error::MemoryAccess(0x8000, _, TestCpuError::BadAddress)
                ));
                assert_eq!(*cpu.mem_val.lock().await, original);
                assert_eq!(state.pc(), 0x1000);
            }
        }
    }
}

// Test: Load SIMD scalar values and perform stack-pointer post-index writeback
//       through a borrowed CPU.
// Expected: Scalar loads clear unused vector bits, while the stack load updates
//       SP only after successfully reading the operand.
#[async_test]
async fn borrowed_cpu_loads_update_vectors_and_stack_pointer() {
    for (opcode, expected, vector) in [
        (0xbd40_0020u32, 0x7654_3210u128, true),
        (0xfd40_0020, 0xfedc_ba98_7654_3210, true),
        (0xf840_87e0, 0xfedc_ba98_7654_3210, false),
    ] {
        let (mut state, mut cpu) = cpu();
        state.update_sp(0x8000);
        state.update_q(0, u128::MAX);
        state.update_instruction(opcode);
        *cpu.mem_val.lock().await = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        Emulator::new(&mut cpu, &InterceptState::default())
            .run()
            .await
            .unwrap();
        if vector {
            assert_eq!(state.q(0), expected);
            assert_eq!(state.sp(), 0x8000);
        } else {
            assert_eq!(state.x(0), expected as u64);
            assert_eq!(state.sp(), 0x8008);
        }
        assert_eq!(state.pc(), 0x1004);
    }
}

// Test: Decode unallocated load/store and SIMD instruction combinations.
// Expected: Each encoding is rejected explicitly without changing guest
//       registers, memory or the faulting instruction position.
#[async_test]
async fn unallocated_instruction_fields_are_rejected_without_side_effects() {
    for opcode in [
        0x0c01_0000u32,
        0x0ca0_0000,
        0x0d01_0000,
        0x8c00_0000,
        0x9920_0000,
        0xdc00_0000,
        0xbd80_0020,
        0xe900_0820,
        0xf880_0420,
    ] {
        let (mut state, mut cpu) = cpu();
        state.update_x(0, 0x1234);
        state.update_instruction(opcode);
        *cpu.mem_val.lock().await = 0x5678;
        let error = Emulator::new(&mut cpu, &InterceptState::default())
            .run()
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::UnsupportedInstruction(value) if value == opcode));
        assert_eq!(state.x(0), 0x1234);
        assert_eq!(*cpu.mem_val.lock().await, 0x5678);
        assert_eq!(state.pc(), 0x1000);
    }
}

// IGNORED: Paired stores write both operands at the first address, overwriting
//       the first value and leaving the second destination unchanged.
//
// Test: Store two adjacent general-purpose registers with STP X0, X2, [X1].
// Expected: Both values appear at consecutive eight-byte addresses.
#[async_test]
#[ignore = "paired store writes its second operand to the first operand's address"]
async fn paired_store_writes_distinct_adjacent_addresses() {
    let (mut state, mut cpu) = cpu();
    state.update_x(0, 0x1111_2222_3333_4444);
    state.update_x(2, 0x5555_6666_7777_8888);
    state.update_instruction(0xa900_0820);
    Emulator::new(&mut cpu, &InterceptState::default())
        .run()
        .await
        .unwrap();
    assert_eq!(
        *cpu.mem_val.lock().await,
        0x5555_6666_7777_8888_1111_2222_3333_4444
    );
}
