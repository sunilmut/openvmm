// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::gdb::arch::x86::X86_64_QEMU;
use crate::gdb::arch::x86::reg::X86_64CoreRegs;
use crate::gdb::arch::x86::reg::id::X86_64CoreRegId;
use crate::gdb::targets::VmTarget;
use gdbstub::common::Tid;
use gdbstub::target::TargetError;
use gdbstub::target::ext::base::multithread::{
    MultiThreadBase, MultiThreadResume, MultiThreadSingleStep,
};
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccess;
use gdbstub::target::ext::breakpoints::{HwBreakpoint, HwWatchpoint};
use gdbstub::target::ext::target_description_xml_override::TargetDescriptionXmlOverride;
use vmm_core_defs::debug_rpc::{BreakpointSize, HardwareBreakpoint};

// Test: Read and write guest virtual memory for a selected thread.
// Expected: VM RPCs carry the correct VP/address/length and payload; returned
//       bytes match, while short backend buffers leave the output unchanged.
#[test]
fn memory_access_routes_addresses_payloads_and_short_buffer_errors() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    let mut bytes = [0xcc; 17];
    target
        .read_addrs(0x1234, &mut bytes, Tid::new(2).unwrap())
        .success();
    assert_eq!(bytes, std::array::from_fn(|i| i as u8));
    assert!(matches!(
        event(&fixture.observed),
        Observed::Read(GuestAddress::Gva { vp: 1, gva: 0x1234 }, 17)
    ));
    target
        .write_addrs(0x5678, b"debug bytes", Tid::new(1).unwrap())
        .success();
    let Observed::Write(GuestAddress::Gva { vp: 0, gva: 0x5678 }, bytes) = event(&fixture.observed)
    else {
        panic!("wrong memory write request")
    };
    assert_eq!(bytes, b"debug bytes");
    fixture.faults.store(16, Ordering::SeqCst);
    let mut bytes = [0xcc; 4];
    assert!(matches!(
        target.read_addrs(1, &mut bytes, Tid::new(1).unwrap()),
        Err(TargetError::Io(_))
    ));
    assert_eq!(bytes, [0xcc; 4]);
}

// Test: Inject VM RPC failures and invalid thread IDs into register/memory APIs.
// Expected: Backend failures become nonfatal IO errors, invalid threads are
//       fatal target errors, and no fabricated data is returned.
#[test]
fn backend_failures_and_invalid_threads_are_reported_explicitly() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    let tid = Tid::new(1).unwrap();
    fixture.faults.store(1, Ordering::SeqCst);
    assert!(matches!(
        target.read_registers(&mut X86_64CoreRegs::default(), tid),
        Err(TargetError::Io(_))
    ));
    assert!(matches!(
        target.write_registers(&X86_64CoreRegs::default(), tid),
        Err(TargetError::Io(_))
    ));
    assert!(matches!(
        target.read_register(tid, X86_64CoreRegId::Efer, &mut [0; 8]),
        Err(TargetError::Io(_))
    ));
    assert!(matches!(
        target.write_register(tid, X86_64CoreRegId::Rip, &[0; 8]),
        Err(TargetError::Io(_))
    ));
    fixture.faults.store(2, Ordering::SeqCst);
    assert!(matches!(
        target.write_registers(&X86_64CoreRegs::default(), tid),
        Err(TargetError::Io(_))
    ));
    assert!(matches!(
        target.write_register(tid, X86_64CoreRegId::Rip, &[0; 8]),
        Err(TargetError::Io(_))
    ));
    fixture.faults.store(4, Ordering::SeqCst);
    assert!(matches!(
        target.read_addrs(0, &mut [0; 1], tid),
        Err(TargetError::Io(_))
    ));
    fixture.faults.store(8, Ordering::SeqCst);
    assert!(matches!(
        target.write_addrs(0, &[1], tid),
        Err(TargetError::Io(_))
    ));
    let invalid = Tid::new(3).unwrap();
    assert!(matches!(
        target.read_registers(&mut X86_64CoreRegs::default(), invalid),
        Err(TargetError::Fatal(_))
    ));
    assert!(matches!(
        target.write_registers(&X86_64CoreRegs::default(), invalid),
        Err(TargetError::Fatal(_))
    ));
    assert!(matches!(
        target.read_register(invalid, X86_64CoreRegId::Rip, &mut [0; 8]),
        Err(TargetError::Fatal(_))
    ));
    assert!(matches!(
        target.write_register(invalid, X86_64CoreRegId::Rip, &[0; 8]),
        Err(TargetError::Fatal(_))
    ));
    assert!(matches!(
        target.read_addrs(0, &mut [0; 1], invalid),
        Err(TargetError::Fatal(_))
    ));
    assert!(matches!(
        target.write_addrs(0, &[1], invalid),
        Err(TargetError::Fatal(_))
    ));
    assert!(target.set_resume_action_continue(invalid, None).is_err());
    assert!(target.set_resume_action_step(invalid, None).is_err());
}

fn resume_events(
    events: &Receiver<Observed>,
    steps: [bool; 2],
    breakpoints: &[HardwareBreakpoint],
) -> mesh::OneshotSender<DebugStopReason> {
    for (vp, expected_step) in steps.into_iter().enumerate() {
        let Observed::Debug(index, state) = event(events) else {
            panic!("missing debug state")
        };
        assert_eq!(index, vp as u32);
        assert_eq!(state.single_step, expected_step);
        assert_eq!(
            state.breakpoints.into_iter().flatten().collect::<Vec<_>>(),
            breakpoints
        );
    }
    let Observed::Resume(response) = event(events) else {
        panic!("missing resume request")
    };
    response
}

// Test: Fill hardware breakpoint slots, remove/reuse a slot, and resume with
//       per-thread stepping before clearing the resume actions.
// Expected: Capacity/missing-breakpoint results are correct and each VM
//       SetDebugState RPC reflects only the requested thread's step action.
#[test]
fn breakpoint_capacity_and_step_actions_are_visible_in_resume_requests() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    let mut tids = Vec::new();
    target
        .list_active_threads(&mut |tid| tids.push(tid.get()))
        .unwrap();
    assert_eq!(tids, [1, 2]);
    for address in 0x100..0x104 {
        assert!(target.add_hw_breakpoint(address, 1).success());
    }
    assert!(!target.add_hw_breakpoint(0x200, 1).success());
    assert!(!target.remove_hw_breakpoint(0x999, 1).success());
    assert!(target.remove_hw_breakpoint(0x101, 1).success());
    assert!(target.add_hw_breakpoint(0x200, 1).success());
    target
        .set_resume_action_step(Tid::new(2).unwrap(), None)
        .unwrap();
    target
        .set_resume_action_continue(Tid::new(1).unwrap(), None)
        .unwrap();
    let expected = [0x100, 0x200, 0x102, 0x103].map(|address| HardwareBreakpoint {
        address,
        ty: BreakpointType::Execute,
        size: BreakpointSize::Byte,
    });
    target.resume().unwrap();
    resume_events(&fixture.observed, [false, true], &expected).send(DebugStopReason::Break);
    assert!(matches!(
        block_on(target.take_stop_chan().unwrap()).unwrap(),
        DebugStopReason::Break
    ));
    target.clear_resume_actions().unwrap();
    target.resume().unwrap();
    resume_events(&fixture.observed, [false, false], &expected).send(DebugStopReason::Reset);
    assert!(matches!(
        block_on(target.take_stop_chan().unwrap()).unwrap(),
        DebugStopReason::Reset
    ));
}

// Test: Install each supported watchpoint kind/length and reject invalid lengths.
// Expected: VM resume requests carry matching watchpoint types and sizes;
//       invalid removals and lengths do not consume a breakpoint slot.
#[test]
fn watchpoint_kinds_lengths_and_removal_reach_the_vm_boundary() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let mut target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    for (kind, ty) in [
        (WatchKind::Read, BreakpointType::ReadOrWrite),
        (WatchKind::Write, BreakpointType::Write),
        (WatchKind::ReadWrite, BreakpointType::ReadOrWrite),
    ] {
        for length in [1, 2, 4, 8] {
            assert!(target.add_hw_watchpoint(0x200, length, kind).success());
            target.resume().unwrap();
            let expected = HardwareBreakpoint {
                address: 0x200,
                ty,
                size: (length as usize).try_into().unwrap(),
            };
            resume_events(&fixture.observed, [false, false], &[expected])
                .send(DebugStopReason::Break);
            assert!(target.remove_hw_watchpoint(0x200, length, kind).success());
            assert!(!target.remove_hw_watchpoint(0x200, length, kind).success());
        }
    }
    assert!(
        target
            .add_hw_watchpoint(0x200, 3, WatchKind::Write)
            .is_err()
    );
    assert!(
        target
            .remove_hw_watchpoint(0x200, 3, WatchKind::Write)
            .is_err()
    );
}

// Test: Read QEMU-compatible target XML incrementally with bounded output buffers.
// Expected: Fragments reconstruct valid target descriptions, offsets past EOF
//       return no bytes, and unknown annex names are rejected.
#[test]
fn target_xml_supports_chunked_reads_and_unknown_annex_errors() {
    let mut fixture = VmFixture::new(Architecture::X86_64, false);
    let target = VmTarget::<X86_64_QEMU>::new(fixture.proxy.as_mut().unwrap());
    for annex in [b"target.xml".as_slice(), b"i386-64bit.xml"] {
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0xcc; 17];
            let count = target
                .target_description_xml(annex, bytes.len() as u64, 13, &mut buffer)
                .success();
            assert!(count <= 13);
            assert!(buffer[count..].iter().all(|byte| *byte == 0xcc));
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("<?xml"));
        assert_eq!(
            target
                .target_description_xml(annex, bytes.len() as u64 + 10, 100, &mut [0; 10])
                .success(),
            0
        );
    }
    assert!(
        target
            .target_description_xml(b"missing.xml", 0, 10, &mut [0; 10])
            .is_err()
    );
}
