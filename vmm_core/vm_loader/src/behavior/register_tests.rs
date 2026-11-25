// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use loader::importer::{Aarch64Register, SegmentRegister, TableRegister};
use test_with_tracing::test;
use vm_topology::processor::aarch64::Aarch64VpInfo;
use vm_topology::processor::{VpIndex, VpInfo};

// Test: Convert x86 loader state including distinct segments, tables, scalar registers and MTRR slots.
// Expected: Each value reaches its architectural destination and unspecified reset state is retained.
#[test]
fn x86_loader_registers_preserve_destinations_and_unmentioned_reset_state() {
    let (caps, bsp) = x86_caps();
    let reset = virt::x86::X86InitialRegs::at_reset(&caps, &bsp);
    let segment = |selector, base| SegmentRegister {
        base,
        limit: 0x12345,
        selector,
        attributes: 0xc093,
    };
    let regs = [
        X86Register::Gdtr(TableRegister {
            base: 0x10000,
            limit: 0x123,
        }),
        X86Register::Idtr(TableRegister {
            base: 0x20000,
            limit: 0x456,
        }),
        X86Register::Ds(segment(8, 0x30000)),
        X86Register::Es(segment(16, 0x40000)),
        X86Register::Fs(segment(24, 0x50000)),
        X86Register::Gs(segment(32, 0x60000)),
        X86Register::Ss(segment(40, 0x70000)),
        X86Register::Cs(segment(48, 0x80000)),
        X86Register::Tr(segment(56, 0x90000)),
        X86Register::Cr0(1),
        X86Register::Cr3(0xa000),
        X86Register::Cr4(0x20),
        X86Register::Efer(0x500),
        X86Register::Pat(0x0007_0406_0007_0406),
        X86Register::Rbp(11),
        X86Register::Rip(12),
        X86Register::Rsi(13),
        X86Register::Rsp(14),
        X86Register::R8(15),
        X86Register::R9(16),
        X86Register::R10(17),
        X86Register::R11(18),
        X86Register::R12(19),
        X86Register::Rflags(0x202),
        X86Register::MtrrDefType(0x806),
        X86Register::MtrrPhysBase0(21),
        X86Register::MtrrPhysMask0(22),
        X86Register::MtrrPhysBase1(23),
        X86Register::MtrrPhysMask1(24),
        X86Register::MtrrPhysBase2(25),
        X86Register::MtrrPhysMask2(26),
        X86Register::MtrrPhysBase3(27),
        X86Register::MtrrPhysMask3(28),
        X86Register::MtrrPhysBase4(29),
        X86Register::MtrrPhysMask4(30),
        X86Register::MtrrFix64k00000(31),
        X86Register::MtrrFix16k80000(32),
        X86Register::MtrrFix4kE0000(33),
        X86Register::MtrrFix4kE8000(34),
        X86Register::MtrrFix4kF0000(35),
        X86Register::MtrrFix4kF8000(36),
    ];
    let actual = initial_regs::x86_initial_regs(&regs, &caps, &bsp);
    let out = &actual.registers;
    assert_eq!(
        (out.gdtr.base, out.gdtr.limit, out.idtr.base, out.idtr.limit),
        (0x10000, 0x123, 0x20000, 0x456)
    );
    for (index, out) in [
        &out.ds, &out.es, &out.fs, &out.gs, &out.ss, &out.cs, &out.tr,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            (out.selector, out.base, out.limit, out.attributes),
            (
                ((index + 1) * 8) as u16,
                ((index + 3) * 0x10000) as u64,
                0x12345,
                0xc093
            )
        );
    }
    assert_eq!(
        (out.cr0, out.cr3, out.cr4, out.efer),
        (1, 0xa000, 0x20, 0x500)
    );
    assert_eq!(actual.pat.value, 0x0007_0406_0007_0406);
    assert_eq!(
        [
            out.rbp, out.rip, out.rsi, out.rsp, out.r8, out.r9, out.r10, out.r11, out.r12,
            out.rflags
        ],
        [11, 12, 13, 14, 15, 16, 17, 18, 19, 0x202]
    );
    assert_eq!(actual.mtrrs.msr_mtrr_def_type, 0x806);
    assert_eq!(
        &actual.mtrrs.variable[..10],
        &[21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    );
    for (index, value) in [(0, 31), (1, 32), (7, 33), (8, 34), (9, 35), (10, 36)] {
        assert_eq!(actual.mtrrs.fixed[index], value);
    }
    assert_eq!(&actual.mtrrs.fixed[2..7], &reset.mtrrs.fixed[2..7]);
    assert_eq!(
        (out.rax, out.rdx, out.r13, out.ldtr),
        (
            reset.registers.rax,
            reset.registers.rdx,
            reset.registers.r13,
            reset.registers.ldtr
        )
    );
}

// Test: Convert all ARM64 loader registers on the host without creating a VM.
// Expected: General and system register values remain distinct and unspecified reset registers are unchanged.
#[test]
fn arm64_loader_registers_preserve_general_and_system_state() {
    let caps = virt::aarch64::Aarch64PartitionCapabilities {
        isolation: virt::IsolationType::None,
        supports_aarch32_el0: false,
        vendor: aarch64defs::Vendor::ARM,
    };
    let bsp = Aarch64VpInfo {
        base: VpInfo {
            vp_index: VpIndex::BSP,
            vnode: 0,
        },
        mpidr: 0.into(),
        gicr: None,
        pmu_gsiv: None,
    };
    let reset = virt::aarch64::Aarch64InitialRegs::at_reset(&caps, &bsp);
    let regs = [
        Aarch64Register::Pc(0x1000),
        Aarch64Register::X0(11),
        Aarch64Register::X1(12),
        Aarch64Register::X2(13),
        Aarch64Register::X3(14),
        Aarch64Register::X4(15),
        Aarch64Register::X5(16),
        Aarch64Register::X6(17),
        Aarch64Register::X7(18),
        Aarch64Register::Cpsr(0x3c5),
        Aarch64Register::Ttbr0El1(0x2000),
        Aarch64Register::MairEl1(0xff04),
        Aarch64Register::SctlrEl1(0x30d00800),
        Aarch64Register::TcrEl1(0x1234),
        Aarch64Register::VbarEl1(0x8000),
        Aarch64Register::Ttbr1El1(0x9000),
    ];
    let actual = initial_regs::aarch64_initial_regs(&regs, &caps, &bsp);
    let out = &actual.registers;
    assert_eq!((out.pc, out.cpsr), (0x1000, 0x3c5));
    assert_eq!(
        [
            out.x0, out.x1, out.x2, out.x3, out.x4, out.x5, out.x6, out.x7
        ],
        [11, 12, 13, 14, 15, 16, 17, 18]
    );
    let out = &actual.system_registers;
    assert_eq!(
        [
            out.ttbr0_el1,
            out.mair_el1,
            out.sctlr_el1,
            out.tcr_el1,
            out.vbar_el1,
            out.ttbr1_el1
        ],
        [0x2000, 0xff04, 0x30d00800, 0x1234, 0x8000, 0x9000]
    );
    assert_eq!(actual.registers.x8, reset.registers.x8);
}
