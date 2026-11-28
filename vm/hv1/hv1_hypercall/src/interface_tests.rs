// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::support::HypercallDispatch;
use crate::*;
use guestmem::GuestMemory;
use hv1_structs::ProcessorSet;
use hvdef::hypercall as defs;
use hvdef::{HvError, HvMessage, HvRegisterName, HvRegisterValue, HvResult, Vtl};
use std::cell::RefCell;
use test_with_tracing::test;
use zerocopy::{FromZeros, Immutable, IntoBytes};

#[derive(Debug, PartialEq)]
struct Call {
    name: &'static str,
    args: Vec<u64>,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Backend {
    registers: [u64; 18],
    xmm: [u128; 16],
    ip: u64,
    calls: RefCell<Vec<Call>>,
    error: Option<HvError>,
    apic_failure: Option<(HvError, usize)>,
}

impl Backend {
    fn record(&self, name: &'static str, args: &[u64], bytes: &[u8]) -> HvResult<()> {
        self.calls.borrow_mut().push(Call {
            name,
            args: args.to_vec(),
            bytes: bytes.to_vec(),
        });
        self.error.map_or(Ok(()), Err)
    }

    fn expect(&self, name: &'static str, args: &[u64], bytes: &[u8]) {
        assert_eq!(
            *self.calls.borrow(),
            [Call {
                name,
                args: args.to_vec(),
                bytes: bytes.to_vec(),
            }]
        );
        self.calls.borrow_mut().clear();
    }
}

impl X64RegisterState for Backend {
    fn rip(&mut self) -> u64 {
        self.ip
    }
    fn set_rip(&mut self, value: u64) {
        self.ip = value;
    }
    fn gp(&mut self, n: X64HypercallRegister) -> u64 {
        self.registers[n as usize]
    }
    fn set_gp(&mut self, n: X64HypercallRegister, value: u64) {
        self.registers[n as usize] = value;
    }
    fn xmm(&mut self, n: usize) -> u128 {
        self.xmm[n]
    }
    fn set_xmm(&mut self, n: usize, value: u128) {
        self.xmm[n] = value;
    }
}

fn invoke<C: HypercallDefinition>(
    backend: &mut Backend,
    input: &[u8],
    reps: usize,
    variable_words: usize,
) -> (defs::HypercallOutput, Vec<u8>)
where
    Backend: HypercallDispatch<C>,
{
    use X64HypercallRegister::{R8, Rax, Rcx, Rdx};
    let memory = GuestMemory::allocate(8192);
    memory.write_at(0, input).unwrap();
    memory.write_at(4096, &[0xa5; 4096]).unwrap();
    backend.set_gp(
        Rcx,
        defs::Control::new()
            .with_code(C::CODE.0)
            .with_rep_count(reps)
            .with_variable_header_size(variable_words)
            .into(),
    );
    backend.set_gp(Rdx, 0);
    backend.set_gp(R8, 4096);
    let previous_ip = backend.ip;
    let dispatcher =
        Dispatcher::<Backend>::new(|code| (code == C::CODE).then(HypercallHandler::new::<C>));
    dispatcher.dispatch(&memory, X64RegisterIo::new(&mut *backend, true, true));
    assert_eq!(backend.ip, previous_ip + 3);
    let result = backend.gp(Rax).into();
    let mut output = vec![0; 4096];
    memory.read_at(4096, &mut output).unwrap();
    (result, output)
}

fn simple<C: HypercallDefinition>(backend: &mut Backend, input: &[u8]) -> Vec<u8>
where
    Backend: HypercallDispatch<C>,
{
    let (result, output) = invoke::<C>(backend, input, 0, 0);
    assert_eq!(result.call_status(), Ok(()).into());
    output
}

fn rejected<C: HypercallDefinition>(
    backend: &mut Backend,
    input: &[u8],
    reps: usize,
    words: usize,
    expected: HvError,
) where
    Backend: HypercallDispatch<C>,
{
    let (result, _) = invoke::<C>(backend, input, reps, words);
    assert_eq!(result.call_status(), Err(expected).into());
    assert_eq!(result.elements_processed(), 0);
    assert!(backend.calls.borrow().is_empty());
}

fn rep<C: HypercallDefinition>(
    backend: &mut Backend,
    header: &[u8],
    elements: &[u8],
    count: usize,
) -> Vec<u8>
where
    Backend: HypercallDispatch<C>,
{
    let input = [header, elements].concat();
    let (result, output) = invoke::<C>(backend, &input, count, 0);
    assert_eq!(result.call_status(), Ok(()).into());
    assert_eq!(result.elements_processed(), count);
    output
}

impl PostMessage for Backend {
    fn post_message(&mut self, connection: u32, message: &[u8]) -> HvResult<()> {
        self.record("post", &[connection.into()], message)
    }
}
impl SignalEvent for Backend {
    fn signal_event(&mut self, connection: u32, flag: u16) -> HvResult<()> {
        self.record("signal", &[connection.into(), flag.into()], &[])
    }
}
impl PostMessageDirect for Backend {
    fn post_message_direct(
        &mut self,
        partition: u64,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        message: &HvMessage,
    ) -> HvResult<()> {
        self.record(
            "post-direct",
            &[partition, vtl as u64, vp.into(), sint.into()],
            message.as_bytes(),
        )
    }
}
impl SignalEventDirect for Backend {
    fn signal_event_direct(
        &mut self,
        partition: u64,
        vtl: Vtl,
        vp: u32,
        sint: u8,
        flag: u16,
    ) -> HvResult<defs::SignalEventDirectOutput> {
        self.record(
            "signal-direct",
            &[partition, vtl as u64, vp.into(), sint.into(), flag.into()],
            &[],
        )?;
        Ok(defs::SignalEventDirectOutput {
            newly_signaled: 1,
            rsvd: [0; 7],
        })
    }
}
impl RetargetDeviceInterrupt for Backend {
    fn retarget_interrupt(
        &mut self,
        device: u64,
        address: u64,
        data: u32,
        params: HvInterruptParameters<'_>,
    ) -> HvResult<()> {
        let mut args = vec![
            device,
            address,
            data.into(),
            params.vector.into(),
            u64::from(params.multicast),
        ];
        args.extend(params.target_processors.iter().map(u64::from));
        self.record("retarget", &args, &[])
    }
}
impl AssertVirtualInterrupt for Backend {
    fn assert_virtual_interrupt(
        &mut self,
        partition: u64,
        control: hvdef::HvInterruptControl,
        address: u64,
        vector: u32,
        vtl: Vtl,
    ) -> HvResult<()> {
        self.record(
            "interrupt",
            &[
                partition,
                control.into_bits(),
                address,
                vector.into(),
                vtl as u64,
            ],
            &[],
        )
    }
}
impl<T: IntoBytes + Immutable> StartVirtualProcessor<T> for Backend {
    fn start_virtual_processor(
        &mut self,
        partition: u64,
        vp: u32,
        vtl: Vtl,
        context: &T,
    ) -> HvResult<()> {
        self.record(
            "start",
            &[partition, vp.into(), vtl as u64],
            context.as_bytes(),
        )
    }
}
impl<T: IntoBytes + Immutable> EnableVpVtl<T> for Backend {
    fn enable_vp_vtl(&mut self, partition: u64, vp: u32, vtl: Vtl, context: &T) -> HvResult<()> {
        self.record(
            "enable-vp",
            &[partition, vp.into(), vtl as u64],
            context.as_bytes(),
        )
    }
}

macro_rules! translation_backend {
    ($trait:ident, $method:ident, $flags:ty, $output:ty, $name:literal) => {
        impl $trait for Backend {
            fn $method(
                &mut self,
                partition: u64,
                vp: u32,
                flags: $flags,
                page: u64,
            ) -> HvResult<$output> {
                self.record($name, &[partition, vp.into(), flags.into_bits(), page], &[])?;
                let mut output = <$output>::new_zeroed();
                output.gpa_page = 0x9876;
                Ok(output)
            }
        }
    };
}
translation_backend!(
    TranslateVirtualAddressX64,
    translate_virtual_address,
    defs::TranslateGvaControlFlagsX64,
    defs::TranslateVirtualAddressOutput,
    "translate"
);
translation_backend!(
    TranslateVirtualAddressExX64,
    translate_virtual_address_ex,
    defs::TranslateGvaControlFlagsX64,
    defs::TranslateVirtualAddressExOutputX64,
    "translate-x64-ex"
);
translation_backend!(
    TranslateVirtualAddressExAarch64,
    translate_virtual_address_ex,
    defs::TranslateGvaControlFlagsArm64,
    defs::TranslateVirtualAddressExOutputArm64,
    "translate-arm64-ex"
);

impl GetVpRegisters for Backend {
    fn get_vp_registers(
        &mut self,
        partition: u64,
        vp: u32,
        vtl: Option<Vtl>,
        registers: &[HvRegisterName],
        output: &mut [HvRegisterValue],
    ) -> HvRepResult {
        self.record(
            "get-registers",
            &[partition, vp.into(), vtl.map_or(0xff, |vtl| vtl as u64)],
            registers.as_bytes(),
        )
        .map_err(|error| (error, 0))?;
        for (index, value) in output.iter_mut().enumerate() {
            *value = HvRegisterValue::from(0x100_u64 + index as u64);
        }
        Ok(())
    }
}
impl SetVpRegisters for Backend {
    fn set_vp_registers(
        &mut self,
        partition: u64,
        vp: u32,
        vtl: Option<Vtl>,
        registers: &[defs::HvRegisterAssoc],
    ) -> HvRepResult {
        self.record(
            "set-registers",
            &[partition, vp.into(), vtl.map_or(0xff, |vtl| vtl as u64)],
            registers.as_bytes(),
        )
        .map_err(|error| (error, 0))
    }
}
impl InstallIntercept for Backend {
    fn install_intercept(
        &mut self,
        partition: u64,
        mask: u32,
        kind: defs::HvInterceptType,
        params: defs::HvInterceptParameters,
    ) -> HvResult<()> {
        self.record(
            "intercept",
            &[partition, mask.into(), kind.0.into()],
            params.as_bytes(),
        )
    }
}
impl ModifyVtlProtectionMask for Backend {
    fn modify_vtl_protection_mask(
        &mut self,
        partition: u64,
        flags: hvdef::HvMapGpaFlags,
        vtl: Option<Vtl>,
        pages: &[u64],
    ) -> HvRepResult {
        self.record(
            "protection",
            &[
                partition,
                flags.into_bits().into(),
                vtl.map_or(0xff, |vtl| vtl as u64),
            ],
            pages.as_bytes(),
        )
        .map_err(|error| (error, 0))
    }
}
impl GetVpIndexFromApicId for Backend {
    fn get_vp_index_from_apic_id(
        &mut self,
        partition: u64,
        vtl: Vtl,
        apics: &[u32],
        indices: &mut [u32],
    ) -> HvRepResult {
        self.record("apic", &[partition, vtl as u64], apics.as_bytes())
            .map_err(|error| (error, 0))?;
        let completed = self.apic_failure.map_or(apics.len(), |(_, count)| count);
        for (apic, index) in apics.iter().zip(indices).take(completed) {
            *index = *apic + 100;
        }
        self.apic_failure.map_or(Ok(()), Err)
    }
}
impl AcceptGpaPages for Backend {
    fn accept_gpa_pages(
        &mut self,
        partition: u64,
        attributes: defs::AcceptPagesAttributes,
        permissions: defs::VtlPermissionSet,
        base: u64,
        count: usize,
    ) -> HvRepResult {
        self.record(
            "accept",
            &[partition, attributes.into_bits().into(), base, count as u64],
            permissions.as_bytes(),
        )
        .map_err(|error| (error, 0))
    }
}
impl ModifySparseGpaPageHostVisibility for Backend {
    fn modify_gpa_visibility(
        &mut self,
        partition: u64,
        visibility: defs::HostVisibilityType,
        pages: &[u64],
    ) -> HvRepResult {
        self.record(
            "modify-visibility",
            &[partition, visibility.0.into()],
            pages.as_bytes(),
        )
        .map_err(|error| (error, 0))
    }
}
impl QuerySparseGpaPageHostVisibility for Backend {
    fn query_gpa_visibility(
        &mut self,
        partition: u64,
        pages: &[u64],
        visibility: &mut [defs::HostVisibilityType],
    ) -> HvRepResult {
        self.record("query-visibility", &[partition], pages.as_bytes())
            .map_err(|error| (error, 0))?;
        visibility.copy_from_slice(
            &[
                defs::HostVisibilityType::PRIVATE,
                defs::HostVisibilityType::SHARED,
            ][..pages.len()],
        );
        Ok(())
    }
}
impl EnablePartitionVtl for Backend {
    fn enable_partition_vtl(
        &mut self,
        partition: u64,
        vtl: Vtl,
        flags: defs::EnablePartitionVtlFlags,
    ) -> HvResult<()> {
        self.record(
            "enable-partition",
            &[partition, vtl as u64, flags.into_bits().into()],
            &[],
        )
    }
}

macro_rules! flush_backend {
    ($trait:ident, $method:ident, $name:literal, list) => {
        impl $trait for Backend {
            fn $method(
                &mut self,
                processors: ProcessorSet<'_>,
                flags: defs::HvFlushFlags,
                ranges: &[defs::HvGvaRange],
            ) -> HvRepResult {
                let mut args = vec![flags.into_bits()];
                args.extend(processors.iter().map(u64::from));
                self.record($name, &args, ranges.as_bytes())
                    .map_err(|error| (error, 0))
            }
        }
    };
    ($trait:ident, $method:ident, $name:literal, space) => {
        impl $trait for Backend {
            fn $method(
                &mut self,
                processors: ProcessorSet<'_>,
                flags: defs::HvFlushFlags,
            ) -> HvResult<()> {
                let mut args = vec![flags.into_bits()];
                args.extend(processors.iter().map(u64::from));
                self.record($name, &args, &[])
            }
        }
    };
}
flush_backend!(
    FlushVirtualAddressList,
    flush_virtual_address_list,
    "flush-list",
    list
);
flush_backend!(
    FlushVirtualAddressListEx,
    flush_virtual_address_list_ex,
    "flush-list-ex",
    list
);
flush_backend!(
    FlushVirtualAddressSpace,
    flush_virtual_address_space,
    "flush-space",
    space
);
flush_backend!(
    FlushVirtualAddressSpaceEx,
    flush_virtual_address_space_ex,
    "flush-space-ex",
    space
);

macro_rules! ipi_backend {
    ($trait:ident, $method:ident, $name:literal) => {
        impl $trait for Backend {
            fn $method(
                &mut self,
                vtl: Option<Vtl>,
                vector: u32,
                flags: u8,
                processors: ProcessorSet<'_>,
            ) -> HvResult<()> {
                let mut args = vec![
                    vtl.map_or(0xff, |vtl| vtl as u64),
                    vector.into(),
                    flags.into(),
                ];
                args.extend(processors.iter().map(u64::from));
                self.record($name, &args, &[])
            }
        }
    };
}
ipi_backend!(SendSyntheticClusterIpi, send_synthetic_cluster_ipi, "ipi");
ipi_backend!(
    SendSyntheticClusterIpiEx,
    send_synthetic_cluster_ipi_ex,
    "ipi-ex"
);

impl ExtendedQueryCapabilities for Backend {
    fn query_extended_capabilities(&mut self) -> HvResult<u64> {
        self.record("capabilities", &[], &[])?;
        Ok(0x123456789abcdef0)
    }
}
impl VbsVmCallReport for Backend {
    fn vbs_vm_call_report(&self, data: &[u8]) -> HvResult<defs::VbsVmCallReportOutput> {
        self.record("report", &[], data)?;
        Ok(defs::VbsVmCallReportOutput {
            report: [0x5a; defs::VBS_VM_MAX_REPORT_SIZE],
        })
    }
}
impl RestorePartitionTime for Backend {
    fn restore_partition_time(
        &mut self,
        partition: u64,
        sequence: u32,
        reference: u64,
        tsc: u64,
    ) -> HvResult<()> {
        self.record("time", &[partition, sequence.into(), reference, tsc], &[])
    }
}

// Test: Submit SynIC messages and signals, including invalid lengths and direct VTLs.
// Expected: The backend receives exactly the requested payload and routing fields;
//       malformed requests are rejected without invoking it.
#[test]
fn synic_payloads_and_direct_signal_outputs_follow_guest_requests() {
    let mut backend = Backend::default();
    let mut message = defs::PostMessage::new_zeroed();
    message.connection_id = 17;
    message.payload_size = 3;
    message.payload[..4].copy_from_slice(&[1, 2, 3, 0xff]);
    simple::<HvPostMessage>(&mut backend, message.as_bytes());
    backend.expect("post", &[17], &[1, 2, 3]);
    message.payload_size = 241;
    rejected::<HvPostMessage>(
        &mut backend,
        message.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
    let signal = defs::SignalEvent {
        connection_id: 29,
        flag_number: 31,
        rsvd: 0,
    };
    simple::<HvSignalEvent>(&mut backend, signal.as_bytes());
    backend.expect("signal", &[29, 31], &[]);
    let mut direct = defs::SignalEventDirect {
        target_partition: 41,
        target_vp: 7,
        target_vtl: 2,
        target_sint: 4,
        flag_number: 65,
    };
    let output = simple::<HvSignalEventDirect>(&mut backend, direct.as_bytes());
    assert_eq!(&output[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
    backend.expect("signal-direct", &[41, 2, 7, 4, 65], &[]);
    direct.target_vtl = 0xff;
    rejected::<HvSignalEventDirect>(
        &mut backend,
        direct.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
    let mut direct = defs::PostMessageDirect::new_zeroed();
    direct.partition_id = 43;
    direct.vp_index = 9;
    direct.vtl = 1;
    direct.sint = 3;
    simple::<HvPostMessageDirect>(&mut backend, direct.as_bytes());
    backend.expect(
        "post-direct",
        &[43, 1, 9, 3],
        HvMessage::new_zeroed().as_bytes(),
    );
    direct.vtl = 0xff;
    rejected::<HvPostMessageDirect>(
        &mut backend,
        direct.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Start VPs using both architecture-specific context layouts.
// Expected: Context bytes and target identity reach the backend unchanged, while
//       invalid x64 reserved fields and invalid VTL values reject the request.
#[test]
fn vp_start_preserves_architecture_contexts() {
    let mut backend = Backend::default();
    let mut x64 = defs::StartVirtualProcessorX64::new_zeroed();
    x64.partition_id = 11;
    x64.vp_index = 13;
    x64.target_vtl = 2;
    x64.vp_context.rip = 0x1234;
    x64.vp_context.cr3 = 0x9000;
    simple::<HvX64StartVirtualProcessor>(&mut backend, x64.as_bytes());
    backend.expect("start", &[11, 13, 2], x64.vp_context.as_bytes());
    for (rsvd0, rsvd1, vtl) in [(1, 0, 2), (0, 1, 2), (0, 0, 0xff)] {
        x64.rsvd0 = rsvd0;
        x64.rsvd1 = rsvd1;
        x64.target_vtl = vtl;
        rejected::<HvX64StartVirtualProcessor>(
            &mut backend,
            x64.as_bytes(),
            0,
            0,
            HvError::InvalidParameter,
        );
    }
    let mut arm = defs::StartVirtualProcessorArm64::new_zeroed();
    arm.partition_id = 17;
    arm.vp_index = 19;
    arm.target_vtl = 1;
    arm.vp_context.pc = 0x5678;
    arm.vp_context.ttbr0_el1 = 0x8000;
    simple::<HvArm64StartVirtualProcessor>(&mut backend, arm.as_bytes());
    backend.expect("start", &[17, 19, 1], arm.vp_context.as_bytes());
    arm.target_vtl = 0xff;
    rejected::<HvArm64StartVirtualProcessor>(
        &mut backend,
        arm.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Enable VP VTLs with x64 and arm64 initialization contexts.
// Expected: The backend receives each complete context and invalid VTL values
//       are rejected before it is called.
#[test]
fn vp_enable_preserves_architecture_contexts() {
    let mut backend = Backend::default();
    let mut x64 = defs::EnableVpVtlX64::new_zeroed();
    x64.partition_id = 23;
    x64.vp_index = 29;
    x64.target_vtl = 1;
    x64.vp_vtl_context.rsp = 0x7000;
    simple::<HvX64EnableVpVtl>(&mut backend, x64.as_bytes());
    backend.expect("enable-vp", &[23, 29, 1], x64.vp_vtl_context.as_bytes());
    x64.target_vtl = 0xff;
    rejected::<HvX64EnableVpVtl>(
        &mut backend,
        x64.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
    let mut arm = defs::EnableVpVtlArm64::new_zeroed();
    arm.partition_id = 31;
    arm.vp_index = 37;
    arm.target_vtl = 2;
    arm.vp_vtl_context.pc = 0x6000;
    simple::<HvArm64EnableVpVtl>(&mut backend, arm.as_bytes());
    backend.expect("enable-vp", &[31, 37, 2], arm.vp_vtl_context.as_bytes());
    arm.target_vtl = 0xff;
    rejected::<HvArm64EnableVpVtl>(
        &mut backend,
        arm.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Translate guest addresses through the standard and extended ABIs.
// Expected: Input flags and page numbers are forwarded and each reply contains
//       the backend's GPA at the architecture-defined wire offset.
#[test]
fn translation_replies_use_correct_architecture_layouts() {
    let mut backend = Backend::default();
    let mut x64 = defs::TranslateVirtualAddressX64::new_zeroed();
    x64.partition_id = 7;
    x64.vp_index = 11;
    x64.gva_page = 0x4321;
    x64.control_flags = defs::TranslateGvaControlFlagsX64::from_bits(3);
    let output = simple::<HvX64TranslateVirtualAddress>(&mut backend, x64.as_bytes());
    backend.expect("translate", &[7, 11, 3, 0x4321], &[]);
    assert_eq!(&output[8..16], &0x9876_u64.to_le_bytes());
    let output = simple::<HvX64TranslateVirtualAddressEx>(&mut backend, x64.as_bytes());
    backend.expect("translate-x64-ex", &[7, 11, 3, 0x4321], &[]);
    assert_eq!(&output[48..56], &0x9876_u64.to_le_bytes());
    let mut arm = defs::TranslateVirtualAddressArm64::new_zeroed();
    arm.partition_id = 13;
    arm.vp_index = 17;
    arm.gva_page = 0x2468;
    arm.control_flags = defs::TranslateGvaControlFlagsArm64::from_bits(5);
    let output = simple::<HvAarch64TranslateVirtualAddressEx>(&mut backend, arm.as_bytes());
    backend.expect("translate-arm64-ex", &[13, 17, 5, 0x2468], &[]);
    assert_eq!(&output[8..16], &0x9876_u64.to_le_bytes());
}

// Test: Read and write register lists and resolve APIC IDs with explicit VTLs.
// Expected: Element order, values, target VTL and completion counts survive the ABI;
//       invalid VTL encodings fail before any backend call.
#[test]
fn register_and_apic_lists_roundtrip_through_guest_memory() {
    let mut backend = Backend::default();
    let mut header = defs::GetSetVpRegisters::new_zeroed();
    header.partition_id = 3;
    header.vp_index = 5;
    header.target_vtl = Vtl::Vtl2.into();
    let names = [HvRegisterName(0x10), HvRegisterName(0x20)];
    let output = rep::<HvGetVpRegisters>(&mut backend, header.as_bytes(), names.as_bytes(), 2);
    backend.expect("get-registers", &[3, 5, 2], names.as_bytes());
    let values = [
        HvRegisterValue::from(0x100_u64),
        HvRegisterValue::from(0x101_u64),
    ];
    assert_eq!(&output[..32], values.as_bytes());
    let values = [
        defs::HvRegisterAssoc::from((names[0], 91_u64)),
        defs::HvRegisterAssoc::from((names[1], 97_u64)),
    ];
    rep::<HvSetVpRegisters>(&mut backend, header.as_bytes(), values.as_bytes(), 2);
    backend.expect("set-registers", &[3, 5, 2], values.as_bytes());
    header.target_vtl = defs::HvInputVtl::new().with_reserved(1);
    rejected::<HvGetVpRegisters>(
        &mut backend,
        &[header.as_bytes(), names.as_bytes()].concat(),
        2,
        0,
        HvError::InvalidParameter,
    );
    rejected::<HvSetVpRegisters>(
        &mut backend,
        &[header.as_bytes(), values.as_bytes()].concat(),
        2,
        0,
        HvError::InvalidParameter,
    );
    let mut header = defs::GetVpIndexFromApicId::new_zeroed();
    header.partition_id = 7;
    header.target_vtl = 1;
    let apics = [11_u32, 13];
    let output =
        rep::<HvGetVpIndexFromApicId>(&mut backend, header.as_bytes(), apics.as_bytes(), 2);
    backend.expect("apic", &[7, 1], apics.as_bytes());
    assert_eq!(&output[..8], [111_u32, 113].as_bytes());
    header.target_vtl = 0xff;
    rejected::<HvGetVpIndexFromApicId>(
        &mut backend,
        &[header.as_bytes(), apics.as_bytes()].concat(),
        2,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Accept pages, change VTL protections and modify/query host visibility.
// Expected: Page order, attributes and permissions reach the backend and visibility
//       replies retain element order and the full completion count.
#[test]
fn page_operations_preserve_targets_and_visibility_outputs() {
    let mut backend = Backend::default();
    let pages = [0x123_u64, 0x456];
    let mut accept = defs::AcceptGpaPages::new_zeroed();
    accept.partition_id = 11;
    accept.gpa_page_base = 0x900;
    accept.vtl_permission_set.vtl_permission_from_1 = [0x123, 0x456];
    accept.page_attributes =
        defs::AcceptPagesAttributes::new().with_host_visibility(defs::HostVisibilityType::SHARED);
    rep::<HvAcceptGpaPages>(&mut backend, accept.as_bytes(), pages.as_bytes(), 2);
    backend.expect(
        "accept",
        &[11, accept.page_attributes.into_bits().into(), 0x900, 2],
        accept.vtl_permission_set.as_bytes(),
    );
    let mut protect = defs::ModifyVtlProtectionMask::new_zeroed();
    protect.partition_id = 13;
    protect.map_flags = hvdef::HvMapGpaFlags::from_bits(3);
    protect.target_vtl = Vtl::Vtl1.into();
    rep::<HvModifyVtlProtectionMask>(&mut backend, protect.as_bytes(), pages.as_bytes(), 2);
    backend.expect("protection", &[13, 3, 1], pages.as_bytes());
    protect.target_vtl = defs::HvInputVtl::new().with_reserved(1);
    rejected::<HvModifyVtlProtectionMask>(
        &mut backend,
        &[protect.as_bytes(), pages.as_bytes()].concat(),
        2,
        0,
        HvError::InvalidParameter,
    );
    let mut modify = defs::ModifySparsePageVisibility::new_zeroed();
    modify.partition_id = 17;
    modify.host_visibility =
        defs::ModifyHostVisibility::new().with_host_visibility(defs::HostVisibilityType::SHARED);
    rep::<HvModifySparseGpaPageHostVisibility>(
        &mut backend,
        modify.as_bytes(),
        pages.as_bytes(),
        2,
    );
    backend.expect("modify-visibility", &[17, 3], pages.as_bytes());
    let query = defs::QuerySparsePageVisibility { partition_id: 19 };
    let output = rep::<HvQuerySparseGpaPageHostVisibility>(
        &mut backend,
        query.as_bytes(),
        pages.as_bytes(),
        2,
    );
    backend.expect("query-visibility", &[19], pages.as_bytes());
    assert_eq!(&output[..2], &[0, 3]);
}

// Test: Flush TLB ranges or whole spaces with legacy and sparse processor masks.
// Expected: Both ABIs select the same requested processors, and malformed sparse
//       formats or missing mask banks are rejected without invoking the backend.
#[test]
fn tlb_flushes_decode_legacy_and_sparse_processor_sets() {
    let mut backend = Backend::default();
    let mut header = defs::FlushVirtualAddressSpace::new_zeroed();
    header.processor_mask = 0x21;
    header.flags = defs::HvFlushFlags::from_bits(2);
    simple::<HvFlushVirtualAddressSpace>(&mut backend, header.as_bytes());
    backend.expect("flush-space", &[2, 0, 5], &[]);
    let ranges = [defs::HvGvaRange(0x12000), defs::HvGvaRange(0x34000)];
    rep::<HvFlushVirtualAddressList>(&mut backend, header.as_bytes(), ranges.as_bytes(), 2);
    backend.expect("flush-list", &[2, 0, 5], ranges.as_bytes());
    let mut header = defs::FlushVirtualAddressSpaceEx::new_zeroed();
    header.flags = defs::HvFlushFlags::from_bits(2);
    header.vp_set_valid_banks_mask = 5;
    let masks = [0x21_u64, 4];
    let input = [header.as_bytes(), masks.as_bytes()].concat();
    let (result, _) = invoke::<HvFlushVirtualAddressSpaceEx>(&mut backend, &input, 0, 2);
    assert_eq!(result.call_status(), Ok(()).into());
    backend.expect("flush-space-ex", &[2, 0, 5, 130], &[]);
    let input = [input.as_slice(), ranges.as_bytes()].concat();
    let (result, _) = invoke::<HvFlushVirtualAddressListEx>(&mut backend, &input, 2, 2);
    assert_eq!(result.elements_processed(), 2);
    assert_eq!(result.call_status(), Ok(()).into());
    backend.expect("flush-list-ex", &[2, 0, 5, 130], ranges.as_bytes());
    for (format, banks) in [(1, 5), (0, 7)] {
        header.vp_set_format = format;
        header.vp_set_valid_banks_mask = banks;
        let input = [header.as_bytes(), masks.as_bytes()].concat();
        rejected::<HvFlushVirtualAddressSpaceEx>(
            &mut backend,
            &input,
            0,
            2,
            HvError::InvalidParameter,
        );
        rejected::<HvFlushVirtualAddressListEx>(
            &mut backend,
            &[input.as_slice(), ranges.as_bytes()].concat(),
            2,
            2,
            HvError::InvalidParameter,
        );
    }
}

// Test: Send synthetic IPIs using legacy and extended sparse processor formats.
// Expected: Routing flags and sparse high-bank destinations survive decoding;
//       reserved bits, invalid VTLs, bad formats and missing banks are rejected.
#[test]
fn synthetic_ipis_validate_headers_and_decode_sparse_destinations() {
    let mut backend = Backend::default();
    let mut legacy = defs::SendSyntheticClusterIpi::new_zeroed();
    legacy.vector = 0x41;
    legacy.target_vtl = Vtl::Vtl1.into();
    legacy.flags = 3;
    legacy.processor_mask = 5;
    simple::<HvSendSyntheticClusterIpi>(&mut backend, legacy.as_bytes());
    backend.expect("ipi", &[1, 0x41, 3, 0, 2], &[]);
    legacy.reserved = 1;
    rejected::<HvSendSyntheticClusterIpi>(
        &mut backend,
        legacy.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
    legacy.reserved = 0;
    legacy.target_vtl = defs::HvInputVtl::new().with_reserved(1);
    rejected::<HvSendSyntheticClusterIpi>(
        &mut backend,
        legacy.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
    let mut extended = defs::SendSyntheticClusterIpiEx::new_zeroed();
    extended.vector = 0x45;
    extended.target_vtl = Vtl::Vtl2.into();
    extended.flags = 7;
    extended.vp_set_valid_banks_mask = 4;
    let mask = [4_u64];
    let input = [extended.as_bytes(), mask.as_bytes()].concat();
    let (result, _) = invoke::<HvSendSyntheticClusterIpiEx>(&mut backend, &input, 0, 1);
    assert_eq!(result.call_status(), Ok(()).into());
    backend.expect("ipi-ex", &[2, 0x45, 7, 130], &[]);
    for (reserved, format, banks, vtl) in [(1, 0, 4, 2), (0, 1, 4, 2), (0, 0, 5, 2), (0, 0, 4, 15)]
    {
        extended.reserved = reserved;
        extended.vp_set_format = format;
        extended.vp_set_valid_banks_mask = banks;
        extended.target_vtl = defs::HvInputVtl::new()
            .with_use_target_vtl(true)
            .with_target_vtl_value(vtl);
        rejected::<HvSendSyntheticClusterIpiEx>(
            &mut backend,
            &[extended.as_bytes(), mask.as_bytes()].concat(),
            0,
            1,
            HvError::InvalidParameter,
        );
    }
}

// Test: Retarget MSI interrupts through legacy masks and the variable sparse set.
// Expected: Device and MSI payloads are forwarded with decoded destinations;
//       reserved flags, non-MSI sources and malformed sets never reach the backend.
#[test]
fn interrupt_retargeting_validates_sources_and_processor_sets() {
    let mut backend = Backend::default();
    let mut header = defs::RetargetDeviceInterrupt::new_zeroed();
    header.device_id = 0x1234;
    header.entry.source = defs::HvInterruptSource::MSI;
    header.entry.data = [0xfee00000, 0x55];
    header.target_header.vector = 0x77;
    header.target_header.mask_or_format = 0x21;
    let (result, _) = invoke::<HvRetargetDeviceInterrupt>(&mut backend, header.as_bytes(), 0, 0);
    assert_eq!(result.call_status(), Ok(()).into());
    backend.expect("retarget", &[0x1234, 0xfee00000, 0x55, 0x77, 0, 0, 5], &[]);
    header.target_header.flags = defs::HvInterruptTargetFlags::new()
        .with_processor_set(true)
        .with_multicast(true);
    header.target_header.mask_or_format = 0;
    let masks = [4_u64, 8];
    let (result, _) = invoke::<HvRetargetDeviceInterrupt>(
        &mut backend,
        &[header.as_bytes(), masks.as_bytes()].concat(),
        0,
        2,
    );
    assert_eq!(result.call_status(), Ok(()).into());
    backend.expect("retarget", &[0x1234, 0xfee00000, 0x55, 0x77, 1, 131], &[]);
    header.target_header.flags.set_reserved(1);
    rejected::<HvRetargetDeviceInterrupt>(
        &mut backend,
        &[header.as_bytes(), masks.as_bytes()].concat(),
        0,
        2,
        HvError::InvalidParameter,
    );
    header.target_header.flags.set_reserved(0);
    header.entry.source = defs::HvInterruptSource::IO_APIC;
    rejected::<HvRetargetDeviceInterrupt>(
        &mut backend,
        &[header.as_bytes(), masks.as_bytes()].concat(),
        0,
        2,
        HvError::InvalidParameter,
    );
    header.entry.source = defs::HvInterruptSource::MSI;
    header.target_header.mask_or_format = 1;
    rejected::<HvRetargetDeviceInterrupt>(
        &mut backend,
        &[header.as_bytes(), masks.as_bytes()].concat(),
        0,
        2,
        HvError::InvalidParameter,
    );
}

// Test: Assert virtual interrupts with valid and malformed routing parameters.
// Expected: Valid routing reaches the backend; reserved fields and invalid VTLs
//       are rejected without a callback.
#[test]
fn virtual_interrupts_validate_reserved_fields_and_vtl() {
    let mut backend = Backend::default();
    let mut interrupt = defs::AssertVirtualInterrupt::new_zeroed();
    interrupt.partition_id = 31;
    interrupt.destination_address = 0x100;
    interrupt.requested_vector = 0x51;
    interrupt.target_vtl = 2;
    simple::<HvAssertVirtualInterrupt>(&mut backend, interrupt.as_bytes());
    backend.expect("interrupt", &[31, 0, 0x100, 0x51, 2], &[]);
    for (first, second, vtl) in [(1, 0, 2), (0, 1, 2), (0, 0, 15)] {
        interrupt.rsvd0 = first;
        interrupt.rsvd1 = second;
        interrupt.target_vtl = vtl;
        rejected::<HvAssertVirtualInterrupt>(
            &mut backend,
            interrupt.as_bytes(),
            0,
            0,
            HvError::InvalidParameter,
        );
    }
}

// Test: Install an intercept and enable a partition VTL.
// Expected: All callback parameters retain their values, and an invalid partition
//       VTL returns AccessDenied without invoking the backend.
#[test]
fn partition_administration_preserves_parameters() {
    let mut backend = Backend::default();
    let mut intercept = defs::InstallIntercept::new_zeroed();
    intercept.partition_id = 37;
    intercept.access_type_mask = 3;
    simple::<HvInstallIntercept>(&mut backend, intercept.as_bytes());
    backend.expect(
        "intercept",
        &[37, 3, 0],
        intercept.intercept_parameters.as_bytes(),
    );
    let mut enable = defs::EnablePartitionVtl::new_zeroed();
    enable.partition_id = 41;
    enable.target_vtl = 1;
    enable.flags = defs::EnablePartitionVtlFlags::new().with_enable_mbec(true);
    simple::<HvEnablePartitionVtl>(&mut backend, enable.as_bytes());
    backend.expect("enable-partition", &[41, 1, 1], &[]);
    enable.target_vtl = 0xff;
    rejected::<HvEnablePartitionVtl>(&mut backend, enable.as_bytes(), 0, 0, HvError::AccessDenied);
}

// Test: Query capabilities and request a VBS report, then reject a backend request.
// Expected: Guest output matches the complete backend replies, and a backend
//       AccessDenied result is returned to the guest.
#[test]
fn capability_and_report_outputs_preserve_backend_results() {
    let mut backend = Backend::default();
    let output = simple::<HvExtQueryCapabilities>(&mut backend, &[]);
    assert_eq!(&output[..8], &0x123456789abcdef0_u64.to_le_bytes());
    backend.expect("capabilities", &[], &[]);
    let report = defs::VbsVmCallReport {
        report_data: [0x37; 64],
    };
    let output = simple::<HvVbsVmCallReport>(&mut backend, report.as_bytes());
    assert_eq!(&output[..2048], &[0x5a; 2048]);
    backend.expect("report", &[], &report.report_data);
    backend.error = Some(HvError::AccessDenied);
    let (result, _) = invoke::<HvExtQueryCapabilities>(&mut backend, &[], 0, 0);
    assert_eq!(result.call_status(), Err(HvError::AccessDenied).into());
    backend.expect("capabilities", &[], &[]);
}

// Test: Restore partition time with valid and nonzero reserved fields.
// Expected: Time values reach the backend unchanged; reserved fields cause
//       InvalidParameter without a callback.
#[test]
fn partition_time_validates_reserved_fields() {
    let mut backend = Backend::default();
    let mut time = defs::RestorePartitionTime {
        partition_id: 43,
        tsc_sequence: 5,
        reserved: 0,
        reference_time_in_100_ns: 47,
        tsc: 53,
    };
    simple::<HvRestorePartitionTime>(&mut backend, time.as_bytes());
    backend.expect("time", &[43, 5, 47, 53], &[]);
    time.reserved = 1;
    rejected::<HvRestorePartitionTime>(
        &mut backend,
        time.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Post empty, near-limit and full SynIC payloads, then retry a backend error.
// Expected: Only declared bytes reach the connection, status is preserved, and
//       a subsequent full-payload request succeeds without writing output memory.
#[test]
fn post_message_payload_boundaries_and_retry_preserve_guest_contract() {
    let mut backend = Backend::default();
    let mut message = defs::PostMessage::new_zeroed();
    message.connection_id = 71;
    for (index, byte) in message.payload.iter_mut().enumerate() {
        *byte = index as u8;
    }
    for length in [0, 1, 239, 240] {
        message.payload_size = length;
        let output = simple::<HvPostMessage>(&mut backend, message.as_bytes());
        backend.expect("post", &[71], &message.payload[..length as usize]);
        assert_eq!(output, vec![0xa5; 4096]);
    }

    backend.error = Some(HvError::InvalidParameter);
    let (result, output) = invoke::<HvPostMessage>(&mut backend, message.as_bytes(), 0, 0);
    assert_eq!(result.call_status(), Err(HvError::InvalidParameter).into());
    backend.expect("post", &[71], &message.payload);
    assert_eq!(output, vec![0xa5; 4096]);
    backend.error = None;
    simple::<HvPostMessage>(&mut backend, message.as_bytes());
    backend.expect("post", &[71], &message.payload);

    message.payload_size = u32::MAX;
    rejected::<HvPostMessage>(
        &mut backend,
        message.as_bytes(),
        0,
        0,
        HvError::InvalidParameter,
    );
}

// Test: Dispatch a raw fast signal with nonzero upper halves in x86 registers.
// Expected: The 32-bit ABI uses only each low dword, the 64-bit ABI keeps its
//       payload, and completion changes only result registers and wraps the IP.
#[test]
fn raw_fast_signal_respects_register_width_and_preserves_non_targets() {
    use X64HypercallRegister::{R8, Rax, Rbx, Rcx, Rdi, Rdx, Rsi};

    for is_64bit in [false, true] {
        let mut backend = Backend {
            registers: std::array::from_fn(|i| 0xaabb_ccdd_1234_0000 + i as u64),
            xmm: std::array::from_fn(|i| u128::MAX - i as u128),
            ip: if is_64bit {
                u64::MAX - 1
            } else {
                u32::MAX as u64 - 1
            },
            ..Default::default()
        };
        if is_64bit {
            backend.set_gp(Rcx, 0x0001_005d);
            backend.set_gp(Rdx, 0x0000_91f3_89ab_cdef);
            backend.set_gp(R8, 0x1122_3344_5566_7788);
        } else {
            backend.set_gp(Rax, 0xfeed_face_0001_005d);
            backend.set_gp(Rdx, 0xdead_beef_0000_0000);
            backend.set_gp(Rbx, 0xcafe_babe_0000_91f3);
            backend.set_gp(Rcx, 0xface_feed_89ab_cdef);
            backend.set_gp(Rdi, 0x1234_5678_1122_3344);
            backend.set_gp(Rsi, 0x8765_4321_5566_7788);
        }
        let mut expected = backend.registers;
        let expected_xmm = backend.xmm;
        expected[Rax as usize] = 0;
        if !is_64bit {
            expected[Rdx as usize] = 0;
        }

        crate::dispatcher!(Backend, [HvSignalEvent]).dispatch(
            &GuestMemory::allocate(0),
            X64RegisterIo::new(&mut backend, is_64bit, true),
        );

        backend.expect("signal", &[0x89ab_cdef, 0x91f3], &[]);
        assert_eq!(backend.registers, expected);
        assert_eq!(backend.xmm, expected_xmm);
        assert_eq!(backend.ip, 1);
    }
}

impl Arm64RegisterState for Backend {
    fn pc(&mut self) -> u64 {
        self.ip
    }

    fn set_pc(&mut self, value: u64) {
        self.ip = value;
    }

    fn x(&mut self, n: u8) -> u64 {
        self.registers[n as usize]
    }

    fn set_x(&mut self, n: u8, value: u64) {
        self.registers[n as usize] = value;
    }
}

// Test: Query capabilities through raw Hyper-V and SMCCC fast-register layouts,
//       with and without a transport-advanced PC.
// Expected: Output occupies X15/X16 for Hyper-V or X2/X3 for SMCCC, status is
//       X0, other registers survive, and only an unadvanced PC advances.
#[test]
fn arm_fast_output_uses_convention_slots_and_transport_pc_policy() {
    for smccc in [false, true] {
        for pre_advanced in [false, true] {
            let mut backend = Backend {
                registers: std::array::from_fn(|i| 0xaabb_ccdd_9876_0000 + i as u64),
                ip: u64::MAX - 1,
                ..Default::default()
            };
            backend.registers[usize::from(smccc)] = 0x0001_8001;
            let mut expected = backend.registers;
            expected[0] = 0;
            let first_output = if smccc { 2 } else { 15 };
            expected[first_output] = 0x1234_5678_9abc_def0;
            expected[first_output + 1] = 0;

            crate::dispatcher!(Backend, [HvExtQueryCapabilities]).dispatch(
                &GuestMemory::allocate(0),
                Arm64RegisterIo::new(&mut backend, pre_advanced, smccc),
            );

            backend.expect("capabilities", &[], &[]);
            assert_eq!(backend.registers, expected);
            assert_eq!(backend.ip, if pre_advanced { u64::MAX - 1 } else { 2 });
        }
    }
}

// Test: Partially resolve APIC IDs, then resume the same request after a timeout
//       or an ordinary error using the guest-visible completed-element count.
// Expected: The resumed callback sees only the pending suffix, earlier output
//       and surrounding memory survive, and completion counts stay absolute.
#[test]
fn apic_partial_completion_resumes_without_replaying_completed_elements() {
    use X64HypercallRegister::{R8, Rax, Rcx, Rdx};

    for error in [HvError::Timeout, HvError::InvalidParameter] {
        let memory = GuestMemory::allocate(8192);
        let mut input = [0; 32];
        input[..8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        input[8] = 2;
        input[16..].copy_from_slice([11_u32, 13, 17, 19].as_bytes());
        memory.write_at(0, &input).unwrap();
        memory.write_at(4096, &[0xa5; 4096]).unwrap();
        let mut backend = Backend {
            ip: 0x1000,
            apic_failure: Some((error, 2)),
            ..Default::default()
        };
        backend.set_gp(Rcx, 0x0000_0004_0000_009a);
        backend.set_gp(Rdx, 0);
        backend.set_gp(R8, 4104);
        backend.set_gp(Rax, 0x9876_5432_10fe_dcba);
        let dispatcher = crate::dispatcher!(Backend, [HvGetVpIndexFromApicId]);
        dispatcher.dispatch(&memory, X64RegisterIo::new(&mut backend, true, true));
        backend.expect(
            "apic",
            &[0x1122_3344_5566_7788, 2],
            [11_u32, 13, 17, 19].as_bytes(),
        );
        if error == HvError::Timeout {
            assert_eq!(backend.ip, 0x1000);
            assert_eq!(backend.gp(Rax), 0x9876_5432_10fe_dcba);
            assert_eq!(backend.gp(Rcx), 0x0002_0004_0000_009a);
        } else {
            let result: defs::HypercallOutput = backend.gp(Rax).into();
            assert_eq!(result.call_status(), Err(error).into());
            assert_eq!(result.elements_processed(), 2);
            assert_eq!(backend.ip, 0x1003);
            backend.set_gp(Rcx, 0x0002_0004_0000_009a);
        }
        let mut expected = [0xa5; 4096];
        expected[8..16].copy_from_slice([111_u32, 113].as_bytes());
        let mut output = [0; 4096];
        memory.read_at(4096, &mut output).unwrap();
        assert_eq!(output, expected);

        backend.apic_failure = None;
        let resume_ip = backend.ip;
        dispatcher.dispatch(&memory, X64RegisterIo::new(&mut backend, true, true));
        backend.expect("apic", &[0x1122_3344_5566_7788, 2], [17_u32, 19].as_bytes());
        assert_eq!(backend.gp(Rax), 0x0000_0004_0000_0000);
        assert_eq!(backend.ip, resume_ip + 3);
        expected[16..24].copy_from_slice([117_u32, 119].as_bytes());
        memory.read_at(4096, &mut output).unwrap();
        assert_eq!(output, expected);
        let mut remaining_input = [0; 32];
        memory.read_at(0, &mut remaining_input).unwrap();
        assert_eq!(remaining_input, input);
    }
}
