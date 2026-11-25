// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::rpc::RpcSend;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

struct RunningWorker {
    control: Option<mesh::Sender<WorkerRpc<DebuggerParameters<TcpListener>>>>,
    thread: Option<JoinHandle<anyhow::Result<()>>>,
    address: SocketAddr,
    vm: VmFixture,
}

impl RunningWorker {
    fn new(architecture: Architecture) -> Self {
        let mut vm = VmFixture::new(architecture, true);
        let (req_chan, vp_count) = vm.proxy.take().unwrap().into_params();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let target_arch = match architecture {
            Architecture::X86_64 => debug_worker_defs::TargetArch::X86_64,
            Architecture::I8086 => debug_worker_defs::TargetArch::I8086,
            Architecture::Aarch64 => debug_worker_defs::TargetArch::Aarch64,
        };
        let parameters = DebuggerParameters {
            listener,
            req_chan,
            vp_count,
            target_arch,
        };
        let (control, receive) = mesh::channel();
        let thread = std::thread::spawn(move || DebuggerWorker::new(parameters)?.run(receive));
        Self {
            control: Some(control),
            thread: Some(thread),
            address,
            vm,
        }
    }

    fn connect(&self) -> RspClient {
        let socket = TcpStream::connect_timeout(&self.address, Duration::from_secs(3)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert!(matches!(event(&self.vm.observed), Observed::Attach));
        let initial = event(&self.vm.observed);
        match initial {
            Observed::InitialResume => {}
            Observed::Resume(response) => response.send(DebugStopReason::Break),
            other => panic!("missing initial resume: {other:?}"),
        }
        assert!(matches!(event(&self.vm.observed), Observed::Break));
        RspClient(socket)
    }

    fn restart(&mut self) {
        let parameters = block_on(
            self.control
                .as_ref()
                .unwrap()
                .call_failable(WorkerRpc::Restart, ()),
        )
        .unwrap();
        self.thread.take().unwrap().join().unwrap().unwrap();
        let (control, receive) = mesh::channel();
        self.thread = Some(std::thread::spawn(move || {
            DebuggerWorker::restart(parameters)?.run(receive)
        }));
        self.control = Some(control);
    }

    fn resume(&self) -> mesh::OneshotSender<DebugStopReason> {
        for vp in 0..2 {
            let Observed::Debug(index, _) = event(&self.vm.observed) else {
                panic!("missing debug configuration")
            };
            assert_eq!(index, vp);
        }
        let Observed::Resume(response) = event(&self.vm.observed) else {
            panic!("missing resume response")
        };
        response
    }
}

impl Drop for RunningWorker {
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            control.send(WorkerRpc::Stop);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap().unwrap();
        }
    }
}

struct RspClient(TcpStream);

impl RspClient {
    fn send(&mut self, command: &[u8]) {
        let checksum = command
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        self.0.write_all(b"$").unwrap();
        self.0.write_all(command).unwrap();
        write!(&mut self.0, "#{checksum:02x}").unwrap();
    }

    fn receive(&mut self) -> Vec<u8> {
        let mut byte = [0];
        loop {
            self.0.read_exact(&mut byte).unwrap();
            if byte[0] == b'$' {
                break;
            }
            assert!(matches!(byte[0], b'+' | b'-'), "unexpected RSP prefix");
        }
        let mut payload = Vec::new();
        loop {
            self.0.read_exact(&mut byte).unwrap();
            if byte[0] == b'#' {
                break;
            }
            payload.push(byte[0]);
        }
        let mut checksum = [0; 2];
        self.0.read_exact(&mut checksum).unwrap();
        let received = u8::from_str_radix(std::str::from_utf8(&checksum).unwrap(), 16).unwrap();
        assert_eq!(
            received,
            payload
                .iter()
                .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        );
        self.0.write_all(b"+").unwrap();
        payload
    }

    fn command(&mut self, command: &[u8]) -> Vec<u8> {
        tracing::debug!(command = %String::from_utf8_lossy(command), "sending RSP command");
        self.send(command);
        self.receive()
    }
}

// Test: Connect real RSP clients to each architecture's worker, enumerate threads,
//       read guest memory, and disconnect before another client attaches.
// Expected: Negotiation and replies are valid packets, guest RPC addresses are
//       preserved, and a disconnected session does not disable the listener.
#[test_with_tracing::test]
fn workers_serve_rsp_requests_and_accept_reconnections_for_all_architectures() {
    for architecture in [
        Architecture::X86_64,
        Architecture::I8086,
        Architecture::Aarch64,
    ] {
        let worker = RunningWorker::new(architecture);
        for _ in 0..2 {
            let mut client = worker.connect();
            let supported = client.command(b"qSupported:xmlRegisters=i386");
            assert!(
                std::str::from_utf8(&supported)
                    .unwrap()
                    .contains("PacketSize")
            );
            let threads = String::from_utf8(client.command(b"qfThreadInfo")).unwrap();
            let ids: Vec<_> = threads
                .strip_prefix('m')
                .unwrap()
                .split(',')
                .map(|id| usize::from_str_radix(id, 16).unwrap())
                .collect();
            assert_eq!(ids, [1, 2]);
            assert_eq!(client.command(b"qsThreadInfo"), b"l");
            assert_eq!(client.command(b"Hg2"), b"OK");
            assert_eq!(client.command(b"m1234,4"), b"00010203");
            assert!(matches!(
                event(&worker.vm.observed),
                Observed::Read(GuestAddress::Gva { vp: 1, gva: 0x1234 }, 4)
            ));
            assert_eq!(client.command(b"D"), b"OK");
        }
    }
}

fn signal(reply: &[u8]) -> u8 {
    assert!(matches!(reply[0], b'T' | b'S'));
    u8::from_str_radix(std::str::from_utf8(&reply[1..3]).unwrap(), 16).unwrap()
}

fn assert_closed(stream: &mut TcpStream) {
    match stream.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected the worker to close the connection, got {other:?}"),
    }
}

// Test: Resume guest execution and report each externally supported VM stop reason.
// Expected: RSP stop signals, watch addresses and thread IDs match the VM event;
//       reset and power-off produce distinct process-exit statuses.
#[test_with_tracing::test]
fn vm_stop_reasons_translate_to_rsp_signals_watchpoints_and_exits() {
    use vmm_core_defs::debug_rpc::{BreakpointSize, HardwareBreakpoint};
    let cases = [
        (DebugStopReason::Break, 2),
        (DebugStopReason::Watchdog, 6),
        (DebugStopReason::TripleFault { vp: 1 }, 11),
        (DebugStopReason::SingleStep { vp: 1 }, 5),
        (
            DebugStopReason::HwBreakpoint {
                vp: 1,
                breakpoint: HardwareBreakpoint {
                    address: 0x1234,
                    ty: BreakpointType::Execute,
                    size: BreakpointSize::Byte,
                },
            },
            5,
        ),
        (
            DebugStopReason::HwBreakpoint {
                vp: 1,
                breakpoint: HardwareBreakpoint {
                    address: 0x1234,
                    ty: BreakpointType::Write,
                    size: BreakpointSize::Byte,
                },
            },
            5,
        ),
        (
            DebugStopReason::HwBreakpoint {
                vp: 1,
                breakpoint: HardwareBreakpoint {
                    address: 0x1234,
                    ty: BreakpointType::ReadOrWrite,
                    size: BreakpointSize::Byte,
                },
            },
            5,
        ),
        (
            DebugStopReason::HwBreakpoint {
                vp: 1,
                breakpoint: HardwareBreakpoint {
                    address: 0x1234,
                    ty: BreakpointType::Invalid,
                    size: BreakpointSize::Byte,
                },
            },
            2,
        ),
    ];
    let worker = RunningWorker::new(Architecture::X86_64);
    let mut client = worker.connect();
    for (reason, expected_signal) in cases {
        let watch = match &reason {
            DebugStopReason::HwBreakpoint { breakpoint, .. } => match breakpoint.ty {
                BreakpointType::Write => Some("watch:"),
                BreakpointType::ReadOrWrite => Some("awatch:"),
                _ => None,
            },
            _ => None,
        };
        client.send(b"vCont;c");
        worker.resume().send(reason);
        let reply = client.receive();
        assert_eq!(signal(&reply), expected_signal);
        if let Some(prefix) = watch {
            let text = std::str::from_utf8(&reply).unwrap();
            let address = text
                .split(';')
                .find_map(|field| field.strip_prefix(prefix))
                .unwrap();
            assert_eq!(u64::from_str_radix(address, 16).unwrap(), 0x1234);
        }
    }
    assert_eq!(client.command(b"D"), b"OK");
    for (reason, expected) in [
        (DebugStopReason::PowerOff, b"W00"),
        (DebugStopReason::Reset, b"W01"),
    ] {
        let mut client = worker.connect();
        client.send(b"vCont;c");
        worker.resume().send(reason);
        assert_eq!(client.receive(), expected);
    }
}

// Test: Interrupt a running guest and report a breakpoint address too wide for
//       the early-boot target.
// Expected: Control-C requests a VM break and reports SIGINT; an unrepresentable
//       address also reports SIGINT rather than truncating the breakpoint.
#[test_with_tracing::test]
fn running_control_c_and_out_of_range_breakpoint_addresses_report_sigint() {
    use vmm_core_defs::debug_rpc::{BreakpointSize, HardwareBreakpoint};
    let worker = RunningWorker::new(Architecture::I8086);
    let mut client = worker.connect();
    client.send(b"vCont;c");
    let pending = worker.resume();
    client.0.write_all(&[3]).unwrap();
    assert!(matches!(event(&worker.vm.observed), Observed::Break));
    assert_eq!(signal(&client.receive()), 2);
    drop(pending);
    client.send(b"vCont;c");
    worker.resume().send(DebugStopReason::HwBreakpoint {
        vp: 0,
        breakpoint: HardwareBreakpoint {
            address: 1 << 40,
            ty: BreakpointType::Execute,
            size: BreakpointSize::Byte,
        },
    });
    assert_eq!(signal(&client.receive()), 2);
}

// Test: Restart each architecture's worker while listening and while connected.
// Expected: The listening address and register architecture survive, connected
//       clients are disconnected, and a new client can use the listener.
#[test_with_tracing::test]
fn worker_restart_preserves_listener_and_architecture_and_disconnects_old_clients() {
    for (architecture, register_bytes) in [
        (Architecture::X86_64, 608),
        (Architecture::I8086, 308),
        (Architecture::Aarch64, 788),
    ] {
        let mut worker = RunningWorker::new(architecture);
        worker.restart();
        let mut old = worker.connect();
        assert_eq!(old.command(b"g").len(), register_bytes * 2);
        assert!(matches!(event(&worker.vm.observed), Observed::Get(0)));
        worker.restart();
        assert_closed(&mut old.0);
        let mut client = worker.connect();
        assert_eq!(client.command(b"g").len(), register_bytes * 2);
        assert!(matches!(event(&worker.vm.observed), Observed::Get(0)));
        assert_eq!(client.command(b"D"), b"OK");
    }
}

// Test: Lose the VM's initial-break response, then lose a running stop response.
// Expected: Each affected client sees EOF and the worker accepts a fresh
//       debugging session instead of terminating its listener.
#[test_with_tracing::test]
fn closed_vm_stop_channels_disconnect_only_the_affected_session() {
    let worker = RunningWorker::new(Architecture::X86_64);
    worker.vm.faults.store(32, Ordering::SeqCst);
    let mut client = worker.connect();
    assert_eq!(client.0.read(&mut [0]).unwrap(), 0);
    worker.vm.faults.store(0, Ordering::SeqCst);
    let mut client = worker.connect();
    client.send(b"vCont;c");
    drop(worker.resume());
    let mut tail = Vec::new();
    client.0.read_to_end(&mut tail).unwrap();
    assert!(!tail.contains(&b'$'));
    let mut client = worker.connect();
    assert_eq!(client.command(b"qsThreadInfo"), b"l");
}

// Test: Kill a debugging session and close the worker's control channel.
// Expected: Kill closes only its client; closing the control channel then
//       terminates the worker cleanly without requiring a Stop RPC.
#[test_with_tracing::test]
fn kill_and_control_channel_closure_release_worker_connections() {
    let mut worker = RunningWorker::new(Architecture::X86_64);
    let mut client = worker.connect();
    client.send(b"k");
    let mut tail = Vec::new();
    client.0.read_to_end(&mut tail).unwrap();
    assert!(!tail.contains(&b'$'));
    let mut next = worker.connect();
    assert_eq!(next.command(b"qsThreadInfo"), b"l");
    drop(worker.control.take());
    worker.thread.take().unwrap().join().unwrap().unwrap();
    assert_closed(&mut next.0);
}
