// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::gdb::arch::x86::reg::id::{X86_64CoreRegId, X86SegmentRegId};
use crate::gdb::arch::x86::reg::{X86_64CoreRegs, X86CoreRegs, X86SegmentRegs, X87FpuInternalRegs};
use crate::gdb::arch::x86::{I8086, X86_64_QEMU};
use crate::gdb::targets::{TargetArch, VmTarget};
use gdbstub::arch::{RegId, Registers};
use gdbstub::common::Tid;
use gdbstub::target::ext::base::multithread::MultiThreadBase;
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccess;
use gdbstub_arch::aarch64::{AArch64, reg::AArch64CoreRegs, reg::id::AArch64RegId};

fn serialize(regs: &impl Registers) -> Vec<u8> {
    let mut bytes = Vec::new();
    regs.gdb_serialize(|byte| bytes.push(byte.expect("register byte unexpectedly unavailable")));
    bytes
}

// Test: Decode and re-encode every byte of the x64 GDB register image and
//       enumerate the public register IDs used to address that image.
// Expected: Endianness and offsets round-trip, IDs cover exactly the wire size,
//       and all truncated images and out-of-range IDs are rejected.
#[test]
fn x64_register_wire_image_round_trips_and_rejects_truncation() {
    let bytes: Vec<_> = (0..608).map(|i| (i % 251) as u8).collect();
    let mut registers = X86_64CoreRegs::default();
    registers.gdb_deserialize(&bytes).unwrap();
    assert_eq!(serialize(&registers), bytes);
    assert_eq!(
        registers.pc(),
        u64::from_le_bytes(bytes[128..136].try_into().unwrap())
    );
    let size: usize = (0..66)
        .map(|id| X86_64CoreRegId::from_raw_id(id).unwrap().1.unwrap().get())
        .sum();
    assert_eq!(size, bytes.len());
    for id in [66, 255, usize::MAX] {
        assert!(X86_64CoreRegId::from_raw_id(id).is_none());
    }
    for end in 0..bytes.len() {
        assert!(
            X86_64CoreRegs::default()
                .gdb_deserialize(&bytes[..end])
                .is_err()
        );
    }
}

// Test: Serialize the early-boot x86 register file with nonzero integer,
//       segment, floating-point, and SIMD data.
// Expected: The wire image uses little-endian fields in the documented order
//       and truncated input is rejected.
#[test]
fn x86_register_serialization_preserves_field_order_and_rejects_short_input() {
    let registers = X86CoreRegs {
        eax: 0x1234_5678,
        ebx: 0x8765_4321,
        eip: 0x1020_3040,
        segments: X86SegmentRegs {
            cs: 8,
            ..Default::default()
        },
        st: [[0x5a; 10]; 8],
        xmm: [0x1122; 8],
        mxcsr: 0x1f80,
        ..Default::default()
    };
    let bytes = serialize(&registers);
    assert_eq!(bytes.len(), 308);
    assert_eq!(&bytes[..4], &registers.eax.to_le_bytes());
    assert_eq!(&bytes[12..16], &registers.ebx.to_le_bytes());
    assert_eq!(&bytes[32..36], &registers.eip.to_le_bytes());
    assert_eq!(&bytes[40..44], &8u32.to_le_bytes());
    assert_eq!(&bytes[64..144], &[0x5a; 80]);
    assert_eq!(&bytes[304..], &0x1f80u32.to_le_bytes());
    for length in [0, 100, 307] {
        assert!(
            X86CoreRegs::default()
                .gdb_deserialize(&bytes[..length])
                .is_err()
        );
    }
}

// Test: Round-trip x87 and segment sub-images, including invalid lengths.
// Expected: All wire bytes survive and incorrect lengths return an error.
#[test]
fn x87_and_segment_wire_images_validate_their_exact_lengths() {
    let mut fpu = X87FpuInternalRegs::default();
    let fpu_bytes: Vec<_> = (0..32).collect();
    fpu.gdb_deserialize(&fpu_bytes).unwrap();
    assert_eq!(serialize(&fpu), fpu_bytes);
    let mut segments = X86SegmentRegs::default();
    let segment_bytes: Vec<_> = (0..24).rev().collect();
    segments.gdb_deserialize(&segment_bytes).unwrap();
    assert_eq!(serialize(&segments), segment_bytes);
    for size in 0..40 {
        if size != 32 {
            assert!(fpu.gdb_deserialize(&vec![0; size]).is_err());
        }
        if size != 24 {
            assert!(segments.gdb_deserialize(&vec![0; size]).is_err());
        }
    }
}

// Test: Read x64 and early-boot register files through the GDB target boundary.
// Expected: VM RPC values are reordered into GDB order, segment selectors and
//       control registers are preserved, and early-boot registers truncate to 32 bits.
#[test]
fn bulk_register_reads_translate_vm_rpc_snapshots() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    let mut registers = X86_64CoreRegs::default();
    target
        .read_registers(&mut registers, Tid::new(2).unwrap())
        .success();
    assert!(matches!(event(&fixture.observed), Observed::Get(1)));
    let expected_order = [0, 3, 1, 2, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15];
    assert_eq!(
        registers.regs,
        expected_order.map(|i| (1u64 << 32) + 0x100 + i)
    );
    assert_eq!(registers.rip, 0x1234_5678_9abc_def0);
    assert_eq!(
        (
            registers.eflags,
            registers.segments.cs,
            registers.segments.gs
        ),
        (0x202, 8, 48)
    );
    assert_eq!((registers.fs_base, registers.k_gs_base), (0x1111, 0x3333));
    assert_eq!(
        (
            registers.cr0,
            registers.cr2,
            registers.cr3,
            registers.cr4,
            registers.cr8,
            registers.efer
        ),
        (0x10, 0x20, 0x30, 0x40, 0x80, 0xd01)
    );
    let mut target = VmTarget::<I8086>::new(fixture.proxy.as_mut().unwrap());
    let mut registers = X86CoreRegs::default();
    target
        .read_registers(&mut registers, Tid::new(2).unwrap())
        .success();
    assert_eq!(
        [
            registers.eax,
            registers.ecx,
            registers.edx,
            registers.ebx,
            registers.esp,
            registers.ebp,
            registers.esi,
            registers.edi
        ],
        [0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107]
    );
    assert_eq!(registers.eip, 0x9abc_def0);
}

// Test: Write a complete x64 GDB integer register file.
// Expected: SetVpState carries the requested VP, VM-order integer values, RIP,
//       and flags while retaining the other RPC snapshot values.
#[test]
fn bulk_register_writes_emit_vm_order_state_updates() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    let registers = X86_64CoreRegs {
        regs: std::array::from_fn(|i| 0x500 + i as u64),
        rip: 0x6789,
        eflags: 0x246,
        ..Default::default()
    };
    target
        .write_registers(&registers, Tid::new(2).unwrap())
        .success();
    assert!(matches!(event(&fixture.observed), Observed::Get(1)));
    let Observed::Set(vp, state) = event(&fixture.observed) else {
        panic!("expected state update")
    };
    let DebuggerVpState::X86_64(state) = *state else {
        panic!("wrong VM architecture")
    };
    assert_eq!(vp, 1);
    let order = [0, 2, 3, 1, 7, 6, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15];
    assert_eq!(state.gp, order.map(|i| 0x500 + i));
    assert_eq!(
        (state.rip, state.rflags, state.gs.base),
        (0x6789, 0x246, 0x2222)
    );
}

// Test: Read the supported single x64 registers and write RAX, RIP and flags.
// Expected: Reads return exact little-endian widths, unsupported reads fail,
//       and successful writes emit the requested values at the VM RPC boundary.
#[test]
fn x64_single_register_access_preserves_widths_and_emits_updates() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    for (id, expected) in [
        (
            X86_64CoreRegId::Segment(X86SegmentRegId::CS),
            8u64.to_le_bytes()[..4].to_vec(),
        ),
        (X86_64CoreRegId::Efer, 0xd01u64.to_le_bytes().to_vec()),
    ] {
        let mut bytes = [0xcc; 16];
        let length = target
            .read_register(Tid::new(1).unwrap(), id, &mut bytes)
            .success();
        assert_eq!(&bytes[..length], expected);
        assert!(bytes[length..].iter().all(|byte| *byte == 0xcc));
        assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    }
    assert!(
        target
            .read_register(Tid::new(1).unwrap(), X86_64CoreRegId::Rip, &mut [0; 8])
            .is_err()
    );
    assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    for id in [
        X86_64CoreRegId::Gpr(0),
        X86_64CoreRegId::Rip,
        X86_64CoreRegId::Eflags,
    ] {
        target
            .write_register(Tid::new(1).unwrap(), id, &[0x34, 0x12])
            .success();
        assert!(matches!(event(&fixture.observed), Observed::Get(0)));
        let Observed::Set(0, state) = event(&fixture.observed) else {
            panic!("expected VP zero update")
        };
        let DebuggerVpState::X86_64(state) = *state else {
            panic!("wrong VM architecture")
        };
        let value = match id {
            X86_64CoreRegId::Gpr(_) => state.gp[0],
            X86_64CoreRegId::Rip => state.rip,
            _ => state.rflags,
        };
        assert_eq!(value, 0x1234);
    }
}

// Test: Read ARM64 integer, stack, PC and status registers through GDB.
// Expected: The selected VP and architectural widths are respected, unsupported
//       system/SIMD registers and writes return explicit target errors.
#[test]
fn arm64_register_access_exposes_rpc_values_and_rejects_unsupported_operations() {
    let mut fixture = VmFixture::new(Architecture::Aarch64, false);
    let mut target = VmTarget::<AArch64>::new(fixture.proxy.as_mut().unwrap());
    let mut registers = AArch64CoreRegs::default();
    target
        .read_registers(&mut registers, Tid::new(2).unwrap())
        .success();
    assert_eq!(
        registers.x,
        std::array::from_fn(|i| (1u64 << 32) + 0x200 + i as u64)
    );
    assert_eq!(
        (registers.sp, registers.pc, registers.cpsr),
        (0x2000, 0x3000, 5)
    );
    assert!(matches!(event(&fixture.observed), Observed::Get(1)));
    for (id, value, width) in [
        (AArch64RegId::X(30), 0x21e, 8),
        (AArch64RegId::Sp, 0x2000, 8),
        (AArch64RegId::Pc, 0x3000, 8),
        (AArch64RegId::Pstate, 5, 4),
    ] {
        let mut bytes = [0; 8];
        assert_eq!(
            target
                .read_register(Tid::new(1).unwrap(), id, &mut bytes)
                .success(),
            width
        );
        assert_eq!(u64::from_le_bytes(bytes), value);
        assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    }
    for id in [AArch64RegId::System(0xffff), AArch64RegId::V(0)] {
        assert!(
            target
                .read_register(Tid::new(1).unwrap(), id, &mut [0; 16])
                .is_err()
        );
        assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    }
    assert!(
        target
            .write_registers(&registers, Tid::new(1).unwrap())
            .is_err()
    );
    assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    assert!(
        target
            .write_register(Tid::new(1).unwrap(), AArch64RegId::Pc, &[0; 8])
            .is_err()
    );
    assert!(matches!(event(&fixture.observed), Observed::Get(0)));
}

// Test: Translate an EL0 ARM64 RPC snapshot through bulk and single-register APIs.
// Expected: Both expose SP_EL0 rather than the exception-level-one stack.
#[test]
fn arm64_el0_reads_use_the_user_stack() {
    let mut state = snapshot(Architecture::Aarch64, 0);
    let DebuggerVpState::Aarch64(arm) = state.as_mut() else {
        unreachable!()
    };
    arm.cpsr = 0;
    let mut registers = AArch64CoreRegs::default();
    assert!(AArch64::registers(&state, &mut registers).is_ok());
    assert_eq!(registers.sp, 0x1000);
    let mut bytes = [0; 8];
    assert_eq!(
        AArch64::register(&state, AArch64RegId::Sp, &mut bytes).ok(),
        Some(8)
    );
    assert_eq!(u64::from_le_bytes(bytes), 0x1000);
}

// Test: Request x86 operations from an ARM64 backend and ARM64 operations from
//       an x86 backend, and request unsupported early-boot register writes.
// Expected: Architecture mismatch and unsupported operations return errors
//       without producing a SetVpState RPC.
#[test]
fn wrong_architecture_and_early_boot_writes_are_rejected() {
    for architecture in [Architecture::Aarch64, Architecture::X86_64] {
        let mut fixture = VmFixture::new(architecture, false);
        let proxy = fixture.proxy.as_mut().unwrap();
        if matches!(architecture, Architecture::Aarch64) {
            let mut target = VmTarget::<X86_64_QEMU>::new(proxy);
            assert!(
                target
                    .read_registers(&mut X86_64CoreRegs::default(), Tid::new(1).unwrap())
                    .is_err()
            );
            assert!(
                target
                    .read_register(Tid::new(1).unwrap(), X86_64CoreRegId::Efer, &mut [0; 8])
                    .is_err()
            );
            assert!(
                target
                    .write_registers(&X86_64CoreRegs::default(), Tid::new(1).unwrap())
                    .is_err()
            );
            assert!(
                target
                    .write_register(Tid::new(1).unwrap(), X86_64CoreRegId::Rip, &[0; 8])
                    .is_err()
            );
        } else {
            let mut target = VmTarget::<AArch64>::new(proxy);
            assert!(
                target
                    .read_registers(&mut AArch64CoreRegs::default(), Tid::new(1).unwrap())
                    .is_err()
            );
            assert!(
                target
                    .read_register(Tid::new(1).unwrap(), AArch64RegId::Pc, &mut [0; 8])
                    .is_err()
            );
        }
    }
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<I8086>::new(fixture.proxy.as_mut().unwrap());
    assert!(
        target
            .read_register(Tid::new(1).unwrap(), (), &mut [0; 4])
            .is_err()
    );
    assert!(
        target
            .write_register(Tid::new(1).unwrap(), (), &[0; 4])
            .is_err()
    );
    assert!(
        target
            .write_registers(&X86CoreRegs::default(), Tid::new(1).unwrap())
            .is_err()
    );
}

// IGNORED: The register reader copies FS.base into both FS and GS outputs.
//
// Test: Read a VM snapshot containing distinct FS and GS bases.
// Expected: GDB receives the GS base supplied by the VM backend.
#[test]
#[ignore = "product bug: GS base is read from FS base"]
fn x64_gs_base_is_not_replaced_by_fs_base() {
    let mut registers = X86_64CoreRegs::default();
    assert!(X86_64_QEMU::registers(&snapshot(Architecture::X86_64, 0), &mut registers).is_ok());
    assert_eq!(registers.gs_base, 0x2222);
}

// IGNORED: The x86 decoder requires 312 bytes although its serializer emits 308.
//
// Test: Deserialize the exact x86 register image emitted by the serializer.
// Expected: A complete, untruncated register image round-trips successfully.
#[test]
#[ignore = "product bug: decoder rejects the serializer's complete 308-byte image"]
fn x86_register_wire_image_round_trips_at_its_serialized_length() {
    let registers = X86CoreRegs {
        eax: 0x1234,
        ..Default::default()
    };
    let mut decoded = X86CoreRegs::default();
    decoded.gdb_deserialize(&serialize(&registers)).unwrap();
    assert_eq!(decoded, registers);
}

// IGNORED: Single GPR writes use GDB indices directly in VM-order storage.
//
// Test: Write GDB's RBX register through the target and observe the VM update.
// Expected: RBX changes without modifying RCX.
#[test]
#[ignore = "product bug: single GPR writes do not translate GDB register order"]
fn single_rbx_write_updates_rbx_not_rcx() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    target
        .write_register(
            Tid::new(1).unwrap(),
            X86_64CoreRegId::Gpr(1),
            &0xabcd_u64.to_le_bytes(),
        )
        .success();
    assert!(matches!(event(&fixture.observed), Observed::Get(0)));
    let Observed::Set(0, state) = event(&fixture.observed) else {
        panic!("expected VP zero update")
    };
    let DebuggerVpState::X86_64(state) = *state else {
        unreachable!()
    };
    assert_eq!(state.gp[3], 0xabcd);
    assert_eq!(state.gp[1], 0x101);
}
