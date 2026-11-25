// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;
use vmm_core_defs::debug_rpc::{
    Aarch64VpState, DebugState, DebuggerVpState, GuestAddress, X86VpState,
};

mod register_behavior;
mod target_behavior;
mod worker_behavior;

trait TargetSuccess<T> {
    fn success(self) -> T;
}

impl<T> TargetSuccess<T> for Result<T, gdbstub::target::TargetError<anyhow::Error>> {
    fn success(self) -> T {
        use gdbstub::target::TargetError;
        match self {
            Ok(value) => value,
            Err(TargetError::Fatal(error)) => panic!("fatal target error: {error:#}"),
            Err(TargetError::Io(error)) => panic!("target IO error: {error}"),
            Err(TargetError::Errno(errno)) => panic!("target errno: {errno}"),
            Err(_) => panic!("target rejected the operation"),
        }
    }
}

#[derive(Debug)]
enum Observed {
    Get(u32),
    Set(u32, Box<DebuggerVpState>),
    Read(GuestAddress, usize),
    Write(GuestAddress, Vec<u8>),
    Debug(u32, DebugState),
    Resume(mesh::OneshotSender<DebugStopReason>),
    InitialResume,
    Attach,
    Detach,
    Break,
}

fn snapshot(architecture: Architecture, vp: u32) -> Box<DebuggerVpState> {
    Box::new(match architecture {
        Architecture::X86_64 | Architecture::I8086 => {
            let mut state = X86VpState {
                gp: std::array::from_fn(|i| (u64::from(vp) << 32) + 0x100 + i as u64),
                rip: 0x1234_5678_9abc_def0,
                rflags: 0x202,
                cr0: 0x10,
                cr2: 0x20,
                cr3: 0x30,
                cr4: 0x40,
                cr8: 0x80,
                efer: 0xd01,
                kernel_gs_base: 0x3333,
                cs: Default::default(),
                ss: Default::default(),
                ds: Default::default(),
                es: Default::default(),
                fs: Default::default(),
                gs: Default::default(),
            };
            for (segment, selector, base) in [
                (&mut state.cs, 8, 0),
                (&mut state.ss, 16, 0),
                (&mut state.ds, 24, 0),
                (&mut state.es, 32, 0),
                (&mut state.fs, 40, 0x1111),
                (&mut state.gs, 48, 0x2222),
            ] {
                segment.selector = selector;
                segment.base = base;
            }
            DebuggerVpState::X86_64(state)
        }
        Architecture::Aarch64 => DebuggerVpState::Aarch64(Aarch64VpState {
            x: std::array::from_fn(|i| (u64::from(vp) << 32) + 0x200 + i as u64),
            sp_el0: 0x1000,
            sp_el1: 0x2000,
            pc: 0x3000,
            cpsr: 5,
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
        }),
    })
}

struct VmFixture {
    proxy: Option<VmProxy>,
    observed: Receiver<Observed>,
    faults: Arc<AtomicU8>,
    thread: Option<JoinHandle<()>>,
}

impl VmFixture {
    fn new(architecture: Architecture, initial_break: bool) -> Self {
        let (send, mut receive) = mesh::channel();
        let (events, observed) = mpsc::channel();
        let faults = Arc::new(AtomicU8::new(0));
        let injected = faults.clone();
        let thread = std::thread::spawn(move || {
            let mut first_resume = true;
            while let Ok(request) = block_on(receive.recv()) {
                match request {
                    DebugRequest::GetVpState(rpc) => {
                        let vp = *rpc.input();
                        events.send(Observed::Get(vp)).unwrap();
                        if injected.load(Ordering::SeqCst) & 1 != 0 {
                            rpc.fail(anyhow::anyhow!("injected read-register failure"));
                        } else {
                            rpc.complete(Ok(snapshot(architecture, vp)));
                        }
                    }
                    DebugRequest::SetVpState(rpc) => {
                        let ((vp, state), reply) = rpc.split();
                        events.send(Observed::Set(vp, state)).unwrap();
                        if injected.load(Ordering::SeqCst) & 2 != 0 {
                            reply.fail(anyhow::anyhow!("injected write-register failure"));
                        } else {
                            reply.complete(Ok(()));
                        }
                    }
                    DebugRequest::ReadMemory(rpc) => {
                        let ((address, length), reply) = rpc.split();
                        events.send(Observed::Read(address, length)).unwrap();
                        match injected.load(Ordering::SeqCst) {
                            4 => reply.fail(anyhow::anyhow!("injected memory-read failure")),
                            16 => reply.complete(Ok(vec![0; length.saturating_sub(1)])),
                            _ => reply.complete(Ok((0..length).map(|i| i as u8).collect())),
                        }
                    }
                    DebugRequest::WriteMemory(rpc) => {
                        let ((address, bytes), reply) = rpc.split();
                        events.send(Observed::Write(address, bytes)).unwrap();
                        if injected.load(Ordering::SeqCst) & 8 != 0 {
                            reply.fail(anyhow::anyhow!("injected memory-write failure"));
                        } else {
                            reply.complete(Ok(()));
                        }
                    }
                    DebugRequest::SetDebugState { vp, state } => {
                        events.send(Observed::Debug(vp, state)).unwrap();
                    }
                    DebugRequest::Resume { response } => {
                        if first_resume && initial_break {
                            events.send(Observed::InitialResume).unwrap();
                            if injected.load(Ordering::SeqCst) & 32 == 0 {
                                response.send(DebugStopReason::Break);
                            }
                        } else {
                            events.send(Observed::Resume(response)).unwrap();
                        }
                        first_resume = false;
                    }
                    DebugRequest::Attach => events.send(Observed::Attach).unwrap(),
                    DebugRequest::Detach => events.send(Observed::Detach).unwrap(),
                    DebugRequest::Break => events.send(Observed::Break).unwrap(),
                }
            }
        });
        Self {
            proxy: Some(VmProxy::new(send, 2)),
            observed,
            faults,
            thread: Some(thread),
        }
    }
}

fn event(receiver: &Receiver<Observed>) -> Observed {
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("VM RPC was not delivered")
}

impl Drop for VmFixture {
    fn drop(&mut self) {
        drop(self.proxy.take());
        self.thread.take().unwrap().join().unwrap();
    }
}
