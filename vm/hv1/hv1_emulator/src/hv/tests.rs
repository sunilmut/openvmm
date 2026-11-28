// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::RecordingProtection;
use test_with_tracing::test;
use vmcore::reference_time::{GetReferenceTime, ReferenceTimeResult};

#[cfg(guest_arch = "x86_64")]
const TEST_VENDOR: Vendor = Vendor::INTEL;
#[cfg(guest_arch = "aarch64")]
const TEST_VENDOR: Vendor = Vendor::ARM;

struct FixedTime;

impl GetReferenceTime for FixedTime {
    fn now(&self) -> ReferenceTimeResult {
        ReferenceTimeResult {
            ref_time: 0x1234_5678,
            system_time: None,
        }
    }
}

fn hypervisor(vendor: Vendor, backed_by_tsc: bool) -> GlobalHv<2> {
    GlobalHv::new(GlobalHvParams {
        max_vp_count: 2,
        vendor,
        tsc_frequency: 20_000_000,
        ref_time: ReferenceTimeSource::new(FixedTime),
        is_ref_time_backed_by_tsc: backed_by_tsc,
    })
}

// Test: Set a guest OS ID through one processor and observe another VP in the same VTL and a processor in another VTL.
// Expected: IDs are shared only within their VTL, read-only identity/time MSRs are exact, and global reset clears partition state.
#[test]
fn guest_identity_is_shared_per_vtl_and_read_only_msr_values_are_exact() {
    let global = hypervisor(TEST_VENDOR, true);
    let mut first = global.add_vp(VpIndex::new(0), Vtl::Vtl0);
    let peer = global.add_vp(VpIndex::new(1), Vtl::Vtl0);
    let other = global.add_vp(VpIndex::new(0), Vtl::Vtl1);
    let mut protection = RecordingProtection::new();
    first
        .msr_write(
            hvdef::HV_X64_MSR_GUEST_OS_ID,
            0x8123_4567_89ab_cdef,
            &mut protection,
        )
        .unwrap();
    assert_eq!(
        peer.msr_read(hvdef::HV_X64_MSR_GUEST_OS_ID).unwrap(),
        0x8123_4567_89ab_cdef
    );
    assert_eq!(
        u64::from(global.guest_os_id(Vtl::Vtl0)),
        0x8123_4567_89ab_cdef
    );
    assert_eq!(other.msr_read(hvdef::HV_X64_MSR_GUEST_OS_ID).unwrap(), 0);
    assert_eq!(peer.msr_read(hvdef::HV_X64_MSR_VP_INDEX).unwrap(), 1);
    assert_eq!(
        first.msr_read(hvdef::HV_X64_MSR_TSC_FREQUENCY).unwrap(),
        20_000_000
    );
    assert_eq!(
        first.msr_read(hvdef::HV_X64_MSR_TIME_REF_COUNT).unwrap(),
        0x1234_5678
    );
    assert_eq!(first.ref_time_now(), 0x1234_5678);
    assert_eq!(global.ref_time_source().now().ref_time, 0x1234_5678);
    for msr in [
        hvdef::HV_X64_MSR_VP_INDEX,
        hvdef::HV_X64_MSR_TIME_REF_COUNT,
        hvdef::HV_X64_MSR_TSC_FREQUENCY,
    ] {
        assert!(matches!(
            first.msr_write(msr, 99, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
    }
    assert!(matches!(
        first.msr_write(u32::MAX, 1, &mut protection),
        Err(MsrError::Unknown)
    ));
    assert!(matches!(first.msr_read(u32::MAX), Err(MsrError::Unknown)));
    first
        .msr_write(hvdef::HV_X64_MSR_SCONTROL, 0, &mut protection)
        .unwrap();
    assert_eq!(first.msr_read(hvdef::HV_X64_MSR_SCONTROL).unwrap(), 0);
    let mut other_protection = RecordingProtection::new();
    global.reset(VtlArray::from([
        &mut protection as &mut dyn VtlProtectAccess,
        &mut other_protection as &mut dyn VtlProtectAccess,
    ]));
    assert_eq!(peer.msr_read(hvdef::HV_X64_MSR_GUEST_OS_ID).unwrap(), 0);
    assert_eq!(other.msr_read(hvdef::HV_X64_MSR_GUEST_OS_ID).unwrap(), 0);
}

// Test: Enable, repeat, move, lock, and reset hypercall pages on Intel and AMD virtual processors.
// Expected: Guest bytes contain the vendor instruction/return stubs and INT3 padding, offsets match the ABI, mappings become read/execute-only, and locked writes fail.
#[cfg(guest_arch = "x86_64")]
#[test]
fn hypercall_pages_publish_vendor_stubs_permissions_offsets_and_locking() {
    for (vendor, instruction) in [
        (Vendor::INTEL, [0x0f, 0x01, 0xc1]),
        (Vendor::AMD, [0x0f, 0x01, 0xd9]),
    ] {
        let global = hypervisor(vendor, true);
        let mut processor = global.add_vp(VpIndex::new(0), Vtl::Vtl0);
        let mut protection = RecordingProtection::new();
        processor
            .msr_write(hvdef::HV_X64_MSR_HYPERCALL, 0x2001, &mut protection)
            .unwrap();
        processor
            .msr_write(hvdef::HV_X64_MSR_HYPERCALL, 0x2001, &mut protection)
            .unwrap();
        assert_eq!(protection.requested.len(), 1);
        let mut bytes = [0; 4096];
        protection.memory.read_at(0x2000, &mut bytes).unwrap();
        let [hc0, hc1, hc2] = instruction;
        // Normal entry, 32/64-bit VTL calls, then 32/64-bit VTL returns.
        let code = [
            hc0, hc1, hc2, 0xc3, 0x89, 0xc1, 0xb8, 0x11, 0, 0, 0, hc0, hc1, hc2, 0xc3, 0x48, 0x89,
            0xc8, 0xb9, 0x11, 0, 0, 0, hc0, hc1, hc2, 0xc3, 0x89, 0xc1, 0xb8, 0x12, 0, 0, 0, hc0,
            hc1, hc2, 0xc3, 0x48, 0x89, 0xc8, 0xb9, 0x12, 0, 0, 0, hc0, hc1, hc2, 0xc3,
        ];
        let mut expected = [0xcc; 4096];
        expected[..code.len()].copy_from_slice(&code);
        assert_eq!(bytes, expected);
        assert_eq!(processor.vsm_code_page_offsets(false).call_offset(), 4);
        assert_eq!(processor.vsm_code_page_offsets(false).return_offset(), 27);
        assert_eq!(processor.vsm_code_page_offsets(true).call_offset(), 15);
        assert_eq!(processor.vsm_code_page_offsets(true).return_offset(), 38);
        let checked = HvMapGpaFlags::new().with_readable(true).with_writable(true);
        let changed = Some(
            HvMapGpaFlags::new()
                .with_readable(true)
                .with_user_executable(true)
                .with_kernel_executable(true),
        );
        assert_eq!(protection.requested, [(2, checked, changed)]);
        assert!(matches!(
            processor.msr_write(hvdef::HV_X64_MSR_HYPERCALL, 0x2005, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
        processor
            .msr_write(hvdef::HV_X64_MSR_HYPERCALL, 0x3003, &mut protection)
            .unwrap();
        protection.memory.read_at(0x3000, &mut bytes).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(
            protection.requested,
            [(2, checked, changed), (3, checked, changed)]
        );
        assert_eq!(protection.unlocked, [2]);
        assert!(matches!(
            processor.msr_write(hvdef::HV_X64_MSR_HYPERCALL, 0, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
        assert_eq!(
            processor.msr_read(hvdef::HV_X64_MSR_HYPERCALL).unwrap(),
            0x3003
        );
        let mut other = RecordingProtection::new();
        global.reset(VtlArray::from([
            &mut protection as &mut dyn VtlProtectAccess,
            &mut other as &mut dyn VtlProtectAccess,
        ]));
        assert_eq!(processor.msr_read(hvdef::HV_X64_MSR_HYPERCALL).unwrap(), 0);
        assert_eq!(protection.unlocked, [2, 3]);
    }
}

// Test: Publish reference-TSC pages over stale guest data, repeat and move
//       their mappings, and disable them with and without TSC backing.
// Expected: Backed pages have complete wire data for a half-scale clock;
//       unbacked pages advertise an invalid sequence despite stale data.
//       Mappings are read-only/nonexecutable and survive failed replacements.
#[test]
fn reference_tsc_page_sequence_scale_and_permissions_match_clock_backing() {
    for backed in [false, true] {
        let global = hypervisor(TEST_VENDOR, backed);
        let mut processor = global.add_vp(VpIndex::new(0), Vtl::Vtl0);
        let mut protection = RecordingProtection::new();
        for (gpn, sequence) in [(2, 1u32), (3, 2)] {
            let register = (gpn << 12) | 1;
            protection
                .memory
                .write_at(gpn << 12, &[0xa5; 4096])
                .unwrap();
            processor
                .msr_write(hvdef::HV_X64_MSR_REFERENCE_TSC, register, &mut protection)
                .unwrap();
            processor
                .msr_write(hvdef::HV_X64_MSR_REFERENCE_TSC, register, &mut protection)
                .unwrap();
            let mut bytes = [0; 4096];
            protection.memory.read_at(gpn << 12, &mut bytes).unwrap();
            if backed {
                let mut expected = [0; 4096];
                expected[..4].copy_from_slice(&sequence.to_le_bytes());
                expected[8..16].copy_from_slice(&(1u64 << 63).to_le_bytes());
                assert_eq!(bytes, expected);
            } else {
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 0);
            }
            assert_eq!(
                processor.msr_read(hvdef::HV_X64_MSR_REFERENCE_TSC).unwrap(),
                register
            );
        }
        assert_eq!(
            protection.requested,
            [2, 3].map(|gpn| (
                gpn,
                HvMapGpaFlags::new().with_readable(true).with_writable(true),
                Some(HvMapGpaFlags::new().with_readable(true)),
            ))
        );
        assert!(matches!(
            processor.msr_write(hvdef::HV_X64_MSR_REFERENCE_TSC, 0x3003, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
        assert!(matches!(
            processor.msr_write(hvdef::HV_X64_MSR_REFERENCE_TSC, 0x100001, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
        assert_eq!(
            processor.msr_read(hvdef::HV_X64_MSR_REFERENCE_TSC).unwrap(),
            0x3001
        );
        assert_eq!(protection.unlocked, [2]);
        processor
            .msr_write(hvdef::HV_X64_MSR_REFERENCE_TSC, 0, &mut protection)
            .unwrap();
        assert_eq!(protection.unlocked, [2, 3]);
    }
}

// Test: Use a mapped VP-assist page for lazy EOI, return-register retrieval, and VINA assertion, then reset it.
// Expected: Public methods observe guest writes at ABI offsets, distinguish guest acknowledgment, reject reserved register bits, and release the mapping on reset.
#[test]
fn vp_assist_guest_interactions_and_reset_preserve_the_abi() {
    let global = hypervisor(TEST_VENDOR, true);
    let mut processor = global.add_vp(VpIndex::new(0), Vtl::Vtl0);
    let mut protection = RecordingProtection::new();
    assert!(!processor.set_lazy_eoi());
    processor
        .msr_write(hvdef::HV_X64_MSR_VP_ASSIST_PAGE, 0x4001, &mut protection)
        .unwrap();
    assert_eq!(processor.vp_assist_page(), 0x4001);
    assert_eq!(
        processor
            .msr_read(hvdef::HV_X64_MSR_VP_ASSIST_PAGE)
            .unwrap(),
        0x4001
    );
    assert!(processor.set_lazy_eoi());
    let offset = offset_of!(hvdef::HvVpAssistPage, apic_assist) as u64;
    let mut actual = [0; 4];
    protection
        .memory
        .read_at(0x4000 + offset, &mut actual)
        .unwrap();
    assert_eq!(actual, 1u32.to_le_bytes());
    assert!(!processor.clear_lazy_eoi());
    assert!(processor.set_lazy_eoi());
    protection
        .memory
        .write_at(0x4000 + offset, &0u32.to_le_bytes())
        .unwrap();
    assert!(processor.clear_lazy_eoi());
    let registers = [0x8123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let offset =
        offset_of!(hvdef::HvVpAssistPage, vtl_control) + offset_of!(HvVpVtlControl, registers);
    let bytes = [registers[0].to_le_bytes(), registers[1].to_le_bytes()].concat();
    protection
        .memory
        .write_at(0x4000 + offset as u64, &bytes)
        .unwrap();
    assert_eq!(processor.return_registers(), registers);
    assert!(!processor.vina_asserted());
    processor.set_vina_asserted(true);
    assert!(processor.vina_asserted());
    let offset =
        offset_of!(hvdef::HvVpAssistPage, vtl_control) + offset_of!(HvVpVtlControl, vina_status);
    protection
        .memory
        .write_at(0x4000 + offset as u64, &[0])
        .unwrap();
    assert!(!processor.vina_asserted());
    assert!(matches!(
        processor.msr_write(hvdef::HV_X64_MSR_VP_ASSIST_PAGE, 0x4003, &mut protection),
        Err(MsrError::InvalidAccess)
    ));
    assert_eq!(processor.vp_assist_page(), 0x4001);
    processor.reset(&mut protection);
    assert_eq!(processor.vp_assist_page(), 0);
    assert!(!processor.set_lazy_eoi());
    assert_eq!(processor.return_registers(), [0, 0]);
    assert!(!processor.vina_asserted());
    assert_eq!(protection.unlocked, [4]);
}
