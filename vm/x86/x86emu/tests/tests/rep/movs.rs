// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tests::common::run_wide_test;
use futures::FutureExt;
use iced_x86::code_asm::*;
use test_with_tracing::test;
use x86defs::RFlags;
use x86emu::Cpu;
use x86emu::Gp;

#[test]
fn movs() {
    const START_GVA: u64 = 0x100;

    let variations: [(&dyn Fn(&mut CodeAssembler) -> Result<(), IcedError>, _, u64); 3] = [
        (&CodeAssembler::movsd, vec![0xAA, 0xAA, 0xAA, 0xAA], 4),
        (&CodeAssembler::movsw, vec![0xAA, 0xAA], 2),
        (&CodeAssembler::movsb, vec![0xAA], 1),
    ];

    for (instruction, value, size) in variations.into_iter() {
        for direction in [false, true] {
            let mut cpu = run_wide_test(
                RFlags::new(),
                true,
                |asm| instruction(asm),
                |cpu| {
                    let mut rflags = cpu.rflags();
                    rflags.set_direction(direction);
                    cpu.set_rflags(rflags);
                    cpu.set_gp(Gp::RSI.into(), START_GVA);
                    cpu.set_gp(Gp::RDI.into(), START_GVA + size);
                    cpu.valid_gva = START_GVA;
                    cpu.write_memory(START_GVA, &value, false)
                        .now_or_never()
                        .unwrap()
                        .unwrap();
                },
            );

            // Most of the behavior being tested here is verified by how the fake cpu handles memory.
            assert_eq!(cpu.mem_val, value);
            assert_eq!(
                cpu.gp(Gp::RSI.into()),
                START_GVA.wrapping_add(if direction { size.wrapping_neg() } else { size })
            );
            assert_eq!(
                cpu.gp(Gp::RDI.into()),
                (START_GVA + size).wrapping_add(if direction { size.wrapping_neg() } else { size })
            );
        }
    }
}

// Test: Execute zero-count REP MOVSB with inaccessible source/destination addresses in both direction modes.
// Expected: The instruction completes without accessing memory, changing either pointer or altering flags; the guarded memory bytes are untouched.
#[test]
fn zero_count_rep_movs_does_not_access_either_operand() {
    const SOURCE: u64 = 0x0001_0000_0000_0000;
    const DESTINATION: u64 = 0x0002_0000_0000_0000;
    for direction in [false, true] {
        let mut cpu = run_wide_test(
            RFlags::new(),
            true,
            |asm| asm.rep().movsb(),
            |cpu| {
                cpu.valid_gva = 0x100;
                cpu.mem_val = vec![0x81, 0, 0xff, 0x27];
                cpu.set_gp(Gp::RSI.into(), SOURCE);
                cpu.set_gp(Gp::RDI.into(), DESTINATION);
                cpu.set_gp(Gp::RCX.into(), 0);
                let mut flags = cpu.rflags();
                flags.set_direction(direction);
                cpu.set_rflags(flags);
            },
        );
        assert_eq!(cpu.gp(Gp::RSI.into()), SOURCE);
        assert_eq!(cpu.gp(Gp::RDI.into()), DESTINATION);
        assert_eq!(cpu.gp(Gp::RCX.into()), 0);
        assert_eq!(cpu.mem_val, [0x81, 0, 0xff, 0x27]);
    }
}
