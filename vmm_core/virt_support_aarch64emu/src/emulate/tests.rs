// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use aarch64defs::Cpsr64;
use aarch64emu::Cpu;
use hvdef::hypercall::TranslateGvaControlFlagsArm64;
use hvdef::hypercall::TranslateGvaResultCode as Code;
use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use test_with_tracing::test;

struct Monitor {
    writes: RefCell<Vec<(u64, Vec<u8>)>>,
}

impl EmulatorMonitorSupport for Monitor {
    fn check_read(&self, _gpa: u64, bytes: &mut [u8]) -> bool {
        bytes.fill(0x33);
        true
    }

    fn check_write(&self, gpa: u64, bytes: &[u8]) -> bool {
        self.writes.borrow_mut().push((gpa, bytes.to_vec()));
        true
    }
}

#[derive(Default)]
struct Support {
    xs: [u64; 31],
    qs: [u128; 32],
    pc: u64,
    sp: u64,
    commits: usize,
    mapped: bool,
    initial: Option<InitialTranslation>,
    translation_error: Option<Code>,
    translation_event: Option<EsrEl2>,
    overlay: bool,
    deny_execute: bool,
    interrupted: bool,
    events: Vec<HvAarch64PendingEvent>,
    monitor: Option<Monitor>,
}

macro_rules! vector_access {
    ($read:ident, $write:ident, $ty:ty) => {
        fn $read(&self, index: u8) -> $ty {
            self.qs[usize::from(index)] as $ty
        }
        fn $write(&mut self, index: u8, value: $ty) {
            self.qs[usize::from(index)] = u128::from(value);
        }
    };
}

impl AccessCpuState for Support {
    fn commit(&mut self) {
        self.commits += 1;
    }
    fn x(&mut self, index: u8) -> u64 {
        self.xs[usize::from(index)]
    }
    fn update_x(&mut self, index: u8, value: u64) {
        self.xs[usize::from(index)] = value;
    }
    vector_access!(q, update_q, u128);
    vector_access!(d, update_d, u64);
    vector_access!(h, update_h, u32);
    vector_access!(s, update_s, u16);
    vector_access!(b, update_b, u8);
    fn pc(&mut self) -> u64 {
        self.pc
    }
    fn update_pc(&mut self, value: u64) {
        self.pc = value;
    }
    fn sp(&mut self) -> u64 {
        self.sp
    }
    fn update_sp(&mut self, value: u64) {
        self.sp = value;
    }
    fn fp(&mut self) -> u64 {
        self.x(29)
    }
    fn update_fp(&mut self, value: u64) {
        self.update_x(29, value);
    }
    fn lr(&mut self) -> u64 {
        self.x(30)
    }
    fn update_lr(&mut self, value: u64) {
        self.update_x(30, value);
    }
    fn cpsr(&mut self) -> Cpsr64 {
        Cpsr64::new()
    }
}

impl EmulatorSupport for Support {
    fn vp_index(&self) -> VpIndex {
        VpIndex::new(0)
    }
    fn physical_address(&self) -> Option<u64> {
        Some(0x2000)
    }
    fn initial_gva_translation(&mut self) -> Option<InitialTranslation> {
        self.initial.take()
    }
    fn interruption_pending(&self) -> bool {
        self.interrupted
    }
    fn check_vtl_access(
        &mut self,
        _gpa: u64,
        mode: TranslateMode,
    ) -> Result<(), EmuCheckVtlAccessError> {
        if self.deny_execute && mode == TranslateMode::Execute {
            Err(EmuCheckVtlAccessError::AccessDenied {
                vtl: hvdef::Vtl::Vtl1,
                denied_flags: HvMapGpaFlags::new().with_kernel_executable(true),
            })
        } else {
            Ok(())
        }
    }
    fn translate_gva(
        &mut self,
        gva: u64,
        _mode: TranslateMode,
    ) -> Result<EmuTranslateResult, EmuTranslateError> {
        match self.translation_error {
            Some(code) => Err(EmuTranslateError {
                code,
                event_info: self.translation_event,
            }),
            None => Ok(EmuTranslateResult {
                gpa: gva,
                overlay_page: Some(self.overlay),
            }),
        }
    }
    fn inject_pending_event(&mut self, event: HvAarch64PendingEvent) {
        self.events.push(event);
    }
    fn monitor_support(&self) -> Option<&dyn EmulatorMonitorSupport> {
        self.monitor
            .as_ref()
            .map(|m| m as &dyn EmulatorMonitorSupport)
    }
    fn is_gpa_mapped(&self, _gpa: u64, _write: bool) -> bool {
        self.mapped
    }
}

#[derive(Default)]
struct Devices {
    read_byte: Option<u8>,
    reads: RefCell<Vec<(u64, usize)>>,
    writes: RefCell<Vec<(u64, Vec<u8>)>>,
    fatals: RefCell<Vec<String>>,
}

impl CpuIo for Devices {
    fn is_mmio(&self, _address: u64) -> bool {
        true
    }
    fn acknowledge_pic_interrupt(&self) -> Option<u8> {
        None
    }
    fn handle_eoi(&self, _irq: u32) {
        panic!("unexpected EOI")
    }
    async fn read_mmio(&self, _vp: VpIndex, address: u64, bytes: &mut [u8]) {
        self.reads.borrow_mut().push((address, bytes.len()));
        bytes.fill(self.read_byte.unwrap_or(0x44));
    }
    async fn write_mmio(&self, _vp: VpIndex, address: u64, bytes: &[u8]) {
        self.writes.borrow_mut().push((address, bytes.to_vec()));
    }
    async fn read_io(&self, _vp: VpIndex, _port: u16, _data: &mut [u8]) {
        panic!("unexpected PIO")
    }
    async fn write_io(&self, _vp: VpIndex, _port: u16, _data: &[u8]) {
        panic!("unexpected PIO")
    }
    fn fatal_error(&self, error: Box<dyn std::error::Error + Send + Sync>) -> VpHaltReason {
        self.fatals.borrow_mut().push(error.to_string());
        VpHaltReason::Reset
    }
}

fn finish<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test IO must complete synchronously"),
    }
}

fn run(
    opcode: u32,
    support: &mut Support,
    gm: &GuestMemory,
    devices: &Devices,
) -> Result<(), VpHaltReason> {
    finish(emulate(
        support,
        &InterceptState {
            instruction_bytes: opcode.to_le_bytes(),
            instruction_byte_count: 4,
            ..Default::default()
        },
        gm,
        devices,
    ))
}

fn assert_exception(event: &HvAarch64PendingEvent, syndrome: EsrEl2, address: u64) {
    let bytes = event.as_bytes();
    assert!(event.header.event_pending());
    assert_eq!(
        event.header.event_type(),
        HvAarch64PendingEventType::EXCEPTION
    );
    assert_eq!(event.header.reserved(), 0);
    assert_eq!(&bytes[1..8], &[0; 7]);
    assert_eq!(
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from(syndrome)
    );
    assert_eq!(
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        address
    );
    assert_eq!(&bytes[24..32], &[0; 8]);
}

// Test: Execute load and store instructions against ordinary guest RAM.
// Expected: Registers, RAM, and the next PC reflect the emulated instruction.
#[test]
fn instructions_transfer_data_to_and_from_guest_ram() {
    let gm = GuestMemory::allocate(0x4000);
    let devices = Devices::default();
    let mut support = Support {
        mapped: true,
        pc: 0x1000,
        ..Default::default()
    };
    support.xs[1] = 0x2000;
    gm.write_plain(0x2000, &0x1122334455667788u64).unwrap();
    run(0xf9400020, &mut support, &gm, &devices).unwrap(); // LDR X0, [X1]
    assert_eq!(support.xs[0], 0x1122334455667788);
    support.xs[0] = 0x8877665544332211;
    run(0xf9000020, &mut support, &gm, &devices).unwrap(); // STR X0, [X1]
    assert_eq!(gm.read_plain::<u64>(0x2000).unwrap(), support.xs[0]);
    assert_eq!(support.pc, 0x1008);
    assert_eq!(support.commits, 2);
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Execute load and store instructions against an unmapped guest address.
// Expected: The CPU IO interface receives the address and exact transfer bytes.
#[test]
fn instructions_route_unmapped_accesses_to_mmio() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support::default();
    support.xs[1] = 0x2000;
    run(0xf9400020, &mut support, &gm, &devices).unwrap();
    assert_eq!(support.xs[0], 0x4444444444444444);
    run(0xf9000020, &mut support, &gm, &devices).unwrap();
    assert_eq!(*devices.reads.borrow(), [(0x2000, 8)]);
    assert_eq!(*devices.writes.borrow(), [(0x2000, vec![0x44; 8])]);
}

// Test: Fetch an instruction from guest memory when intercept bytes are absent.
// Expected: Execute translation is used and the fetched load updates its register.
#[test]
fn missing_intercept_bytes_are_fetched_from_guest_memory() {
    let gm = GuestMemory::allocate(0x4000);
    gm.write_plain(0x1000, &0xf9400020u32).unwrap();
    gm.write_plain(0x2000, &91u64).unwrap();
    let mut support = Support {
        mapped: true,
        pc: 0x1000,
        ..Default::default()
    };
    support.xs[1] = 0x2000;
    finish(emulate(
        &mut support,
        &InterceptState::default(),
        &gm,
        &Devices::default(),
    ))
    .unwrap();
    assert_eq!(support.xs[0], 91);
    assert_eq!(support.pc, 0x1004);
}

// Test: Perform byte, word, DWORD, and QWORD atomic exchanges through the adapter.
// Expected: Only the requested RAM bytes change and a stale comparison fails.
#[test]
fn atomic_memory_operations_respect_size_and_comparison() {
    let gm = GuestMemory::allocate(0x4000);
    let devices = Devices::default();
    let mut support = Support {
        mapped: true,
        ..Default::default()
    };
    for len in [1, 2, 4, 8] {
        gm.write_at(0x2000, &[0x11; 8]).unwrap();
        let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
        let mut success = false;
        finish(cpu.compare_and_write_memory(
            0x2000,
            &vec![0x11; len],
            &vec![0x22; len],
            &mut success,
        ))
        .unwrap();
        assert!(success);
        finish(cpu.compare_and_write_memory(
            0x2000,
            &vec![0x11; len],
            &vec![0x33; len],
            &mut success,
        ))
        .unwrap();
        assert!(!success);
        let mut bytes = [0; 8];
        gm.read_at(0x2000, &mut bytes).unwrap();
        assert_eq!(&bytes[..len], vec![0x22; len]);
        assert_eq!(&bytes[len..], vec![0x11; 8 - len]);
    }
}

// Test: Perform a compare-and-write to MMIO instead of RAM.
// Expected: Comparison is bypassed and the device receives the write once.
#[test]
fn mmio_atomic_write_uses_the_device_io_contract() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support::default();
    let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
    let mut success = false;
    finish(cpu.compare_and_write_memory(0x2000, &[1, 2], &[3, 4], &mut success)).unwrap();
    assert!(success);
    assert_eq!(*devices.writes.borrow(), [(0x2000, vec![3, 4])]);
}

// Test: Read and atomically update a monitor page through the CPU interface.
// Expected: Monitor callbacks handle the access without RAM or device IO.
#[test]
fn monitor_accesses_bypass_ram_and_mmio() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support {
        monitor: Some(Monitor {
            writes: RefCell::default(),
        }),
        ..Default::default()
    };
    let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
    let mut bytes = [0; 4];
    finish(cpu.read_memory(0x2000, &mut bytes)).unwrap();
    assert_eq!(bytes, [0x33; 4]);
    let mut success = false;
    finish(cpu.compare_and_write_memory(0x2000, &[0; 4], &[7; 4], &mut success)).unwrap();
    assert!(success);
    assert_eq!(
        *support.monitor.as_ref().unwrap().writes.borrow(),
        [(0x2000, vec![7; 4])]
    );
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Use a valid intercept-provided translation when new translations fail.
// Expected: Access within that page succeeds, but a different page reports failure.
#[test]
fn intercept_translation_preserves_the_page_offset() {
    let gm = GuestMemory::allocate(0x4000);
    gm.write_at(0x2010, &[1, 2]).unwrap();
    let devices = Devices::default();
    let mut support = Support {
        mapped: true,
        initial: Some(InitialTranslation {
            gva: 0x8000,
            gpa: 0x2000,
            translate_mode: TranslateMode::Read,
        }),
        translation_error: Some(Code::GPA_UNMAPPED),
        ..Default::default()
    };
    let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
    let mut bytes = [0; 2];
    finish(cpu.read_memory(0x8010, &mut bytes)).unwrap();
    assert_eq!(bytes, [1, 2]);
    assert!(finish(cpu.read_memory(0x9000, &mut bytes)).is_err());
}

// Test: Reject every supported translation failure for reads and writes.
// Expected: No RAM or device transfer occurs after translation fails.
#[test]
fn translation_failures_prevent_memory_accesses() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    for code in [
        Code::INTERCEPT,
        Code::GPA_NO_READ_ACCESS,
        Code::GPA_NO_WRITE_ACCESS,
        Code::GPA_UNMAPPED,
        Code::GPA_ILLEGAL_OVERLAY_ACCESS,
        Code::GPA_UNACCEPTED,
        Code::PAGE_NOT_PRESENT,
        Code::PRIVILEGE_VIOLATION,
        Code::INVALID_PAGE_TABLE_FLAGS,
        Code(u32::MAX),
    ] {
        let mut support = Support {
            translation_error: Some(code),
            ..Default::default()
        };
        let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
        assert!(finish(cpu.read_memory(0x2000, &mut [0; 4])).is_err());
        assert!(finish(cpu.read_instruction(0x2000, &mut [0; 4])).is_err());
        assert!(finish(cpu.write_memory(0x2000, &[1; 4])).is_err());
        assert!(
            finish(cpu.compare_and_write_memory(0x2000, &[0; 4], &[1; 4], &mut false)).is_err()
        );
    }
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Read an overlay page and then attempt to write it.
// Expected: Reads are allowed but writes fail without reaching the device.
#[test]
fn overlay_pages_are_read_only() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support {
        overlay: true,
        ..Default::default()
    };
    let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
    let mut bytes = [0; 4];
    finish(cpu.read_memory(0x2000, &mut bytes)).unwrap();
    assert_eq!(bytes, [0x44; 4]);
    assert!(finish(cpu.write_memory(0x2000, &[1; 4])).is_err());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Access RAM that the host reports mapped but cannot actually read or write.
// Expected: Backing-memory failures propagate instead of falling back to MMIO.
#[test]
fn mapped_memory_failures_do_not_fall_back_to_devices() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support {
        mapped: true,
        ..Default::default()
    };
    let mut cpu = EmulatorCpu::new(&gm, &devices, &mut support, EsrEl2::new());
    assert!(finish(cpu.read_memory(0x2000, &mut [0; 4])).is_err());
    assert!(finish(cpu.write_memory(0x2000, &[1; 4])).is_err());
    assert!(finish(cpu.compare_and_write_memory(0x2000, &[0; 4], &[1; 4], &mut false)).is_err());
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Emulate a translation fault with a hypervisor-provided exception.
// Expected: The guest receives that exception at the faulting virtual address.
#[test]
fn translation_faults_inject_the_provided_guest_event() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let syndrome: EsrEl2 = IssInstructionAbort::new().into();
    let mut support = Support {
        translation_error: Some(Code::PAGE_NOT_PRESENT),
        translation_event: Some(syndrome),
        ..Default::default()
    };
    support.xs[1] = 0x2000;
    run(0xf9400020, &mut support, &gm, &devices).unwrap();
    assert_eq!(support.events.len(), 1);
    assert_exception(&support.events[0], syndrome, 0x2000);
    assert_eq!(support.pc, 0);
    assert!(devices.fatals.borrow().is_empty());
}

// Test: Fetch an instruction from an execute-protected address.
// Expected: A guest instruction-abort event is injected instead of fetching bytes.
#[test]
fn vtl_execute_denial_injects_an_instruction_abort() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support {
        deny_execute: true,
        pc: 0x1000,
        ..Default::default()
    };
    finish(emulate(
        &mut support,
        &InterceptState::default(),
        &gm,
        &devices,
    ))
    .unwrap();
    assert_eq!(support.events.len(), 1);
    let mut expected: EsrEl2 = IssInstructionAbort::new()
        .with_ifsc(FaultStatusCode::PERMISSION_FAULT_LEVEL2)
        .into();
    expected.set_il(false);
    assert_exception(&support.events[0], expected, 0x1000);
    assert!(devices.reads.borrow().is_empty());
}

// Test: Emulate an unsupported instruction and an interrupt-caused exit.
// Expected: Unsupported instructions inject an abort; interrupt exits halt safely.
#[test]
fn unsupported_instructions_and_interrupt_exits_are_distinguished() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    let mut support = Support {
        pc: 0x1000,
        ..Default::default()
    };
    run(0, &mut support, &gm, &devices).unwrap();
    assert_eq!(support.events.len(), 1);
    support.interrupted = true;
    assert!(matches!(
        run(0, &mut support, &gm, &devices),
        Err(VpHaltReason::Reset)
    ));
    assert_eq!(devices.fatals.borrow().len(), 1);
    assert_eq!(support.pc, 0x1000);
}

// Test: Emulate a memory fault with no injectable exception.
// Expected: The fatal-error policy handles the failure without advancing the PC.
#[test]
fn uninjectable_memory_faults_use_the_fatal_error_policy() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    for mapped in [false, true] {
        let mut support = Support {
            mapped,
            translation_error: (!mapped).then_some(Code::GPA_UNMAPPED),
            ..Default::default()
        };
        support.xs[1] = 0x2000;
        assert!(matches!(
            run(0xf9400020, &mut support, &gm, &devices),
            Err(VpHaltReason::Reset)
        ));
        assert!(support.events.is_empty());
        assert_eq!(support.pc, 0);
    }
    assert_eq!(devices.fatals.borrow().len(), 2);
}

// Test: Execute monitor fast-path stores at each width, including zero registers.
// Expected: The returned bitmask is width-limited, destination zeroed, and PC advanced.
#[test]
fn monitor_fast_path_masks_values_and_retires_the_instruction() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    for (size, expected) in [(0, 0xff), (1, 0xffff), (2, 0xffffffff), (3, u64::MAX)] {
        let mut support = Support::default();
        support.xs[2] = u64::MAX;
        support.xs[0] = 42;
        let opcode = (size << 30) | 0x38203000 | (2 << 16);
        assert_eq!(
            emulate_mnf_write_fast_path(opcode, &mut support, &gm, &devices),
            Some(expected)
        );
        assert_eq!(support.xs[0], 0);
        assert_eq!(support.pc, 4);
        assert_eq!(support.commits, 1);
    }
    let mut support = Support::default();
    assert_eq!(
        emulate_mnf_write_fast_path(0x383f301f, &mut support, &gm, &devices),
        Some(0)
    );
    assert_eq!(support.pc, 4);
}

// Test: Send interrupted and unsupported instructions to the monitor fast path.
// Expected: It declines without committing registers or advancing the guest PC.
#[test]
fn monitor_fast_path_declines_without_side_effects() {
    let gm = GuestMemory::allocate(0);
    let devices = Devices::default();
    for interrupted in [false, true] {
        let mut support = Support {
            interrupted,
            ..Default::default()
        };
        assert_eq!(
            emulate_mnf_write_fast_path(
                if interrupted { 0x38223000 } else { 0 },
                &mut support,
                &gm,
                &devices,
            ),
            None
        );
        assert_eq!(support.pc, 0);
        assert_eq!(support.commits, 0);
    }
}

// Test: Load and store SIMD registers at byte through quadword widths.
// Expected: Loads clear upper bits and stores preserve the exact low bytes.
#[test]
fn simd_instructions_transfer_data_without_changing_other_registers() {
    let gm = GuestMemory::allocate(0x4000);
    let devices = Devices::default();
    let data = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    for (load, store, width) in [
        (0x3d400023, 0x3d000023, 1),  // LDR/STR B3, [X1]
        (0x7d400023, 0x7d000023, 2),  // LDR/STR H3, [X1]
        (0xbd400023, 0xbd000023, 4),  // LDR/STR S3, [X1]
        (0xfd400023, 0xfd000023, 8),  // LDR/STR D3, [X1]
        (0x3dc00023, 0x3d800023, 16), // LDR/STR Q3, [X1]
    ] {
        let mut support = Support {
            mapped: true,
            ..Default::default()
        };
        support.xs[1] = 0x2000;
        support.qs.fill(u128::MAX);
        gm.write_at(0x2000, &data).unwrap();
        run(load, &mut support, &gm, &devices).unwrap();
        let mut expected = [0; 16];
        expected[..width].copy_from_slice(&data[..width]);
        assert_eq!(support.qs[3], u128::from_le_bytes(expected));
        assert!(
            support.qs[..3]
                .iter()
                .chain(&support.qs[4..])
                .all(|v| *v == u128::MAX)
        );
        gm.write_at(0x2000, &[0x55; 16]).unwrap();
        run(store, &mut support, &gm, &devices).unwrap();
        let mut stored = [0; 16];
        gm.read_at(0x2000, &mut stored).unwrap();
        assert_eq!(&stored[..width], &data[..width]);
        assert_eq!(&stored[width..], &vec![0x55; 16 - width]);
        assert_eq!(support.xs[1], 0x2000);
        assert_eq!(support.pc, 8);
        assert_eq!(support.commits, 2);
        assert!(support.events.is_empty());
    }
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Restore distinct frame/link values with a post-indexed stack pair load.
// Expected: Both registers load from consecutive RAM slots and SP advances once.
#[test]
fn stack_pair_load_preserves_frame_and_link_registers() {
    let gm = GuestMemory::allocate(0x4000);
    let devices = Devices::default();
    let mut support = Support {
        mapped: true,
        sp: 0x2010,
        ..Default::default()
    };
    gm.write_plain(0x2010, &0x1122334455667788u64).unwrap();
    gm.write_plain(0x2018, &0x8877665544332211u64).unwrap();
    run(0xa8c17bfd, &mut support, &gm, &devices).unwrap(); // LDP X29, X30, [SP], #16
    assert_eq!(support.xs[29..], [0x1122334455667788, 0x8877665544332211]);
    assert_eq!(support.sp, 0x2020);
    assert_eq!(support.pc, 4);
    assert_eq!(support.commits, 1);
    assert_eq!(gm.read_plain::<u64>(0x2010).unwrap(), 0x1122334455667788);
    assert_eq!(gm.read_plain::<u64>(0x2018).unwrap(), 0x8877665544332211);
    assert!(support.events.is_empty());
    assert!(devices.reads.borrow().is_empty());
    assert!(devices.writes.borrow().is_empty());
}

// Test: Execute a store with an intercept translation for each access mode.
// Expected: Only write permission can reuse the translation; other modes fault.
#[test]
fn intercept_translation_is_not_reused_for_a_different_access_mode() {
    let gm = GuestMemory::allocate(0x4000);
    for mode in [
        TranslateMode::Read,
        TranslateMode::Execute,
        TranslateMode::Write,
    ] {
        let devices = Devices::default();
        gm.write_plain(0x2010, &0x1122334455667788u64).unwrap();
        let syndrome = EsrEl2::new().with_ec(aarch64defs::ExceptionClass::DATA_ABORT.0);
        let mut support = Support {
            mapped: true,
            initial: Some(InitialTranslation {
                gva: 0x8000,
                gpa: 0x2000,
                translate_mode: mode,
            }),
            translation_error: Some(Code::PRIVILEGE_VIOLATION),
            translation_event: Some(syndrome),
            pc: 0x1000,
            ..Default::default()
        };
        support.xs[0] = 0x8877665544332211;
        support.xs[1] = 0x8010;
        run(0xf9000020, &mut support, &gm, &devices).unwrap();
        if mode == TranslateMode::Write {
            assert_eq!(gm.read_plain::<u64>(0x2010).unwrap(), 0x8877665544332211);
            assert_eq!(support.pc, 0x1004);
            assert!(support.events.is_empty());
        } else {
            assert_eq!(gm.read_plain::<u64>(0x2010).unwrap(), 0x1122334455667788);
            assert_eq!(support.pc, 0x1000);
            assert_eq!(support.events.len(), 1);
            assert_exception(&support.events[0], syndrome, 0x8010);
        }
        assert_eq!(support.xs[0], 0x8877665544332211);
        assert_eq!(support.xs[1], 0x8010);
        assert!(devices.reads.borrow().is_empty());
        assert!(devices.writes.borrow().is_empty());
        assert!(devices.fatals.borrow().is_empty());
    }
}

// Test: Convert hypervisor translation flags for each privilege-selection mode.
// Expected: Validation and page-bit-update requests preserve their public meaning.
#[test]
fn hypervisor_flags_select_the_expected_translation_policy() {
    use crate::translate::TranslateFlags;
    use crate::translate::TranslatePrivilegeCheck;
    for (user, supervisor, pan_clear) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (true, true, true),
    ] {
        let flags = TranslateFlags::from_hv_flags(
            TranslateGvaControlFlagsArm64::new()
                .with_user_access(user)
                .with_supervisor_access(supervisor)
                .with_pan_clear(pan_clear)
                .with_validate_read(true)
                .with_validate_write(true)
                .with_validate_execute(true)
                .with_set_page_table_bits(true),
        );
        assert!(
            flags.validate_read
                && flags.validate_write
                && flags.validate_execute
                && flags.set_page_table_bits
        );
        assert!(matches!(
            (flags.privilege_check, user, supervisor, pan_clear),
            (TranslatePrivilegeCheck::None, _, _, true)
                | (
                    TranslatePrivilegeCheck::CurrentPrivilegeLevel,
                    false,
                    false,
                    false
                )
                | (TranslatePrivilegeCheck::User, true, false, false)
                | (TranslatePrivilegeCheck::Supervisor, false, true, false)
                | (TranslatePrivilegeCheck::Both, true, true, false)
        ));
    }
}

struct TranslationSupport {
    memory: GuestMemory,
    registers: TranslationRegisters,
    fail_registers: bool,
    calls: Vec<&'static str>,
}

impl TranslateGvaSupport for TranslationSupport {
    type Error = &'static str;
    fn guest_memory(&self) -> &GuestMemory {
        &self.memory
    }
    fn acquire_tlb_lock(&mut self) {
        self.calls.push("lock");
    }
    fn registers(&mut self) -> Result<TranslationRegisters, Self::Error> {
        self.calls.push("registers");
        if self.fail_registers {
            Err("register access failed")
        } else {
            Ok(self.registers.clone())
        }
    }
}

fn translation_registers() -> TranslationRegisters {
    TranslationRegisters {
        cpsr: Cpsr64::new(),
        sctlr: aarch64defs::SctlrEl1::new().with_m(true),
        tcr: aarch64defs::TranslationControlEl1::new()
            .with_t0sz(34)
            .with_ips(aarch64defs::IntermPhysAddrSize::IPA_48_BITS_256_TB),
        ttbr0: 0,
        ttbr1: 0,
        syndrome: EsrEl2::new().with_il(true).into(),
        encryption_mode: crate::translate::EncryptionMode::None,
    }
}

fn read_flags() -> crate::translate::TranslateFlags {
    crate::translate::TranslateFlags {
        validate_read: true,
        validate_write: false,
        validate_execute: false,
        privilege_check: crate::translate::TranslatePrivilegeCheck::User,
        set_page_table_bits: false,
    }
}

fn page_tables() -> GuestMemory {
    let gm = GuestMemory::allocate(0x4000);
    let root = aarch64defs::Pte::new()
        .with_valid(true)
        .with_not_large_page(true)
        .with_pfn(1)
        .with_access_flag(true);
    let leaf = aarch64defs::Pte::new()
        .with_valid(true)
        .with_pfn(2)
        .with_access_flag(true)
        .with_ap_unprivileged(true);
    gm.write_plain(0, &u64::from(root)).unwrap();
    gm.write_plain(0x1000, &u64::from(leaf)).unwrap();
    gm
}

// Test: Translate with paging disabled and with unavailable processor registers.
// Expected: The TLB lock precedes register access; errors propagate to the caller.
#[test]
fn translation_wrapper_locks_before_reading_registers() {
    let mut support = TranslationSupport {
        memory: GuestMemory::allocate(0),
        registers: translation_registers(),
        fail_registers: false,
        calls: Vec::new(),
    };
    support.registers.sctlr.set_m(false);
    for mode in [
        TranslateMode::Read,
        TranslateMode::Write,
        TranslateMode::Execute,
    ] {
        let result = crate::translate::emulate_translate_gva(&mut support, 0x2345, mode)
            .unwrap()
            .unwrap();
        assert_eq!(result.gpa, 0x2345);
        assert_eq!(result.overlay_page, None);
    }
    assert_eq!(
        support.calls,
        [
            "lock",
            "registers",
            "lock",
            "registers",
            "lock",
            "registers"
        ]
    );
    support.fail_registers = true;
    assert!(matches!(
        crate::translate::emulate_translate_gva(&mut support, 0, TranslateMode::Read),
        Err("register access failed")
    ));
}

// Test: Translate malformed, unmapped, absent, and privilege-denied page tables.
// Expected: Hypervisor error codes and guest exception syndromes identify each fault.
#[test]
fn translation_wrapper_reports_walk_failures_as_guest_exceptions() {
    for kind in 0..5 {
        let mut support = TranslationSupport {
            memory: page_tables(),
            registers: translation_registers(),
            fail_registers: false,
            calls: Vec::new(),
        };
        let (expected, status) = match kind {
            0 => {
                support.registers.tcr.set_t0sz(0);
                (
                    Code::INVALID_PAGE_TABLE_FLAGS,
                    FaultStatusCode::ADDRESS_SIZE_FAULT_LEVEL0,
                )
            }
            1 => {
                support
                    .registers
                    .tcr
                    .set_tg0(aarch64defs::TranslationGranule0(3));
                (
                    Code::INVALID_PAGE_TABLE_FLAGS,
                    FaultStatusCode::TRANSLATION_FAULT_LEVEL0,
                )
            }
            2 => {
                support.registers.ttbr0 = 0x9000;
                (
                    Code::GPA_UNMAPPED,
                    FaultStatusCode::ACCESS_FLAG_FAULT_LEVEL1,
                )
            }
            3 => {
                support.memory.write_plain(0, &0u64).unwrap();
                (
                    Code::PAGE_NOT_PRESENT,
                    FaultStatusCode::ACCESS_FLAG_FAULT_LEVEL1,
                )
            }
            _ => {
                let mut leaf =
                    aarch64defs::Pte::from(support.memory.read_plain::<u64>(0x1000).unwrap());
                leaf.set_ap_unprivileged(false);
                support
                    .memory
                    .write_plain(0x1000, &u64::from(leaf))
                    .unwrap();
                (
                    Code::PRIVILEGE_VIOLATION,
                    FaultStatusCode::PERMISSION_FAULT_LEVEL2,
                )
            }
        };
        let error = crate::translate::emulate_translate_gva(&mut support, 0, TranslateMode::Read)
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(error.code, expected);
        let syndrome = error.event_info.unwrap();
        assert!(syndrome.il());
        assert_eq!(syndrome.ec(), aarch64defs::ExceptionClass::DATA_ABORT.0);
        assert_eq!(syndrome.lower_iss(), status.0);
        assert_eq!(support.calls, ["lock", "registers"]);
    }
}

// Test: Walk lower and upper address spaces with supported translation granules.
// Expected: TTBR selection and granule alignment produce the mapped guest address.
#[test]
fn page_walks_support_both_address_spaces_and_all_granules() {
    use aarch64defs::TranslationGranule0 as G0;
    use aarch64defs::TranslationGranule1 as G1;
    for (g0, g1, shift) in [
        (G0::TG_4KB, G1::TG_4KB, 12),
        (G0::TG_16KB, G1::TG_16KB, 14),
        (G0::TG_64KB, G1::TG_64KB, 16),
    ] {
        for upper in [false, true] {
            let gm = GuestMemory::allocate(0x20000);
            let mut registers = translation_registers();
            registers.tcr.set_t0sz(39);
            registers.tcr.set_t1sz(39);
            registers.tcr.set_tg0(g0);
            registers.tcr.set_tg1(g1);
            registers.ttbr1 = 0x10000;
            let gva = if upper {
                !((1u64 << 25) - 1) | 0x123
            } else {
                0x123
            };
            // A level-zero or block descriptor maps the aligned output base.
            let leaf = aarch64defs::Pte::new()
                .with_valid(true)
                .with_pfn(0x100)
                .with_ap_unprivileged(true)
                .with_access_flag(true);
            gm.write_plain(0, &u64::from(leaf)).unwrap();
            gm.write_plain(0x10000, &u64::from(leaf.with_pfn(0x200)))
                .unwrap();
            let result =
                crate::translate::translate_gva_to_gpa(&gm, gva, &registers, read_flags()).unwrap();
            assert_eq!(
                result,
                if upper { 0x200123 } else { 0x100123 },
                "granule shift {shift}, upper={upper}"
            );
        }
    }
}

// Test: Reject a virtual address outside the configured TTBR address widths.
// Expected: Invalid upper bits are rejected before any page-table access.
#[test]
fn page_walks_reject_invalid_virtual_address_bits() {
    let gm = GuestMemory::allocate(0);
    let mut registers = translation_registers();
    registers.tcr.set_t1sz(34);
    registers
        .tcr
        .set_tg1(aarch64defs::TranslationGranule1::TG_4KB);
    for address in [1u64 << 40, 0x0040000000000000] {
        assert!(matches!(
            crate::translate::translate_gva_to_gpa(&gm, address, &registers, read_flags()),
            Err(crate::translate::Error::InvalidAddressSize(_))
        ));
    }
    registers
        .tcr
        .set_tg1(aarch64defs::TranslationGranule1::TG_INVALID);
    assert!(matches!(
        crate::translate::translate_gva_to_gpa(&gm, u64::MAX, &registers, read_flags()),
        Err(crate::translate::Error::InvalidPageTableFlags(_))
    ));
}

// Test: Walk mappings under different physical address-size configurations.
// Expected: Supported widths retain offsets and reject representable out-of-range GPAs.
#[test]
fn page_walks_validate_the_configured_physical_address_size() {
    use aarch64defs::IntermPhysAddrSize as Size;
    let gm = page_tables();
    for (size, bits) in [
        (Size::IPA_32_BITS_4_GB, 32),
        (Size::IPA_36_BITS_64_GB, 36),
        (Size::IPA_40_BITS_1_TB, 40),
        (Size::IPA_42_BITS_4_TB, 42),
        (Size::IPA_44_BITS_16_TB, 44),
        (Size::IPA_48_BITS_256_TB, 48),
        (Size::IPA_52_BITS_4_PB, 52),
        (Size::IPA_56_BITS_64_PB, 56),
    ] {
        let mut registers = translation_registers();
        registers.tcr.set_ips(size);
        assert_eq!(
            crate::translate::translate_gva_to_gpa(&gm, 3, &registers, read_flags()).unwrap(),
            0x2003
        );
        // The descriptor's PFN field represents addresses only through bit 47.
        let last_page = (1u64 << bits.min(48)) - 0x1000;
        let leaf = aarch64defs::Pte::new()
            .with_valid(true)
            .with_access_flag(true)
            .with_ap_unprivileged(true)
            .with_pfn(last_page >> 12);
        gm.write_plain(0x1000, &u64::from(leaf)).unwrap();
        assert_eq!(
            crate::translate::translate_gva_to_gpa(&gm, 0xfff, &registers, read_flags()).unwrap(),
            last_page + 0xfff,
        );
        if bits < 48 {
            gm.write_plain(0x1000, &u64::from(leaf.with_pfn(1u64 << (bits - 12))))
                .unwrap();
            assert!(matches!(
                crate::translate::translate_gva_to_gpa(&gm, 3, &registers, read_flags()),
                Err(crate::translate::Error::InvalidPageTableFlags(2)),
            ));
        }
        gm.write_plain(0x1000, &u64::from(leaf.with_pfn(2)))
            .unwrap();
    }
}

// Test: Load negative subword MMIO values into both W and X registers.
// Expected: Signedness and destination width determine extension, not old bits.
#[test]
fn mmio_loads_extend_to_the_architectural_destination_width() {
    let gm = GuestMemory::allocate(0);
    for (opcode, width, expected) in [
        (0x39400020, 1, 0x80),               // LDRB W0, [X1]
        (0x39800020, 1, 0xffffffffffffff80), // LDRSB X0, [X1]
        (0x39c00020, 1, 0xffffff80),         // LDRSB W0, [X1]
        (0x79400020, 2, 0x8080),             // LDRH W0, [X1]
        (0x79800020, 2, 0xffffffffffff8080), // LDRSH X0, [X1]
        (0x79c00020, 2, 0xffff8080),         // LDRSH W0, [X1]
        (0xb9400020, 4, 0x80808080),         // LDR W0, [X1]
        (0xb9800020, 4, 0xffffffff80808080), // LDRSW X0, [X1]
    ] {
        let devices = Devices {
            read_byte: Some(0x80),
            ..Default::default()
        };
        let mut support = Support {
            pc: 0x1000,
            ..Default::default()
        };
        support.xs[0] = u64::MAX;
        support.xs[1] = 0x2000;

        run(opcode, &mut support, &gm, &devices).unwrap();

        assert_eq!(support.xs[0], expected, "opcode {opcode:#x}");
        assert_eq!(support.xs[1], 0x2000);
        assert_eq!(support.pc, 0x1004);
        assert_eq!(*devices.reads.borrow(), [(0x2000, width)]);
        assert!(devices.writes.borrow().is_empty());
        assert!(devices.fatals.borrow().is_empty());
        assert!(support.events.is_empty());
    }
}

// Test: Store a register with nonzero high bits through narrow MMIO accesses.
// Expected: Each callback receives only the low bytes, with no register changes.
#[test]
fn mmio_stores_send_only_the_requested_low_bytes() {
    let gm = GuestMemory::allocate(0);
    for (opcode, expected) in [
        (0x39000020, vec![0x80]),                   // STRB W0, [X1]
        (0x79000020, vec![0x80, 0x32]),             // STRH W0, [X1]
        (0xb9000020, vec![0x80, 0x32, 0x54, 0x76]), // STR W0, [X1]
    ] {
        let devices = Devices::default();
        let mut support = Support {
            pc: 0x1000,
            ..Default::default()
        };
        support.xs[0] = 0xfedcba9876543280;
        support.xs[1] = 0x2000;

        run(opcode, &mut support, &gm, &devices).unwrap();

        assert_eq!(*devices.writes.borrow(), [(0x2000, expected)]);
        assert!(devices.reads.borrow().is_empty());
        assert_eq!(support.xs[0], 0xfedcba9876543280);
        assert_eq!(support.xs[1], 0x2000);
        assert_eq!(support.pc, 0x1004);
        assert!(devices.fatals.borrow().is_empty());
        assert!(support.events.is_empty());
    }
}
