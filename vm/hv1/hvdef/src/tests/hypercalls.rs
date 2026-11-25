// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use hypercall::*;
use test_with_tracing::test;

// Test: Set and replace target VTLs on x64 and ARM address-translation controls.
// Expected: The target occupies only the top byte and independent permission flags survive.
#[test]
fn translation_target_vtl_encoding_preserves_other_control_bits() {
    for (target, byte) in [
        (None, 0),
        (Some(Vtl::Vtl0), 0x10),
        (Some(Vtl::Vtl1), 0x11),
        (Some(Vtl::Vtl2), 0x12),
    ] {
        let input = HvInputVtl::from(target);
        assert_eq!(u8::from(input), byte);
        if let Some(target) = target {
            assert_eq!(u8::from(HvInputVtl::from(target)), byte);
        }
        let expected = 0x11 | (u64::from(byte) << 56);
        let mut x64 = TranslateGvaControlFlagsX64::from(0x11).with_input_vtl(input);
        let mut arm = TranslateGvaControlFlagsArm64::from(0x11).with_input_vtl(input);
        assert_eq!(u64::from(x64), expected);
        assert_eq!(u64::from(arm), expected);
        assert_eq!(x64.input_vtl().target_vtl(), Ok(target));
        assert_eq!(arm.input_vtl().target_vtl(), Ok(target));
        x64.set_input_vtl(HvInputVtl::CURRENT_VTL);
        arm.set_input_vtl(HvInputVtl::CURRENT_VTL);
        assert_eq!(u64::from(x64), 0x11);
        assert_eq!(u64::from(arm), 0x11);
    }
}

// Test: Decode Microsoft and open-source guest OS identifiers from their wire values.
// Expected: The vendor discriminator selects exactly one layout and all identity fields survive.
#[test]
fn guest_os_identifier_discriminates_layout_without_losing_identity_fields() {
    let microsoft = HvGuestOsId::from(0x0001040000000000);
    let os = microsoft.microsoft().unwrap();
    assert_eq!(os.vendor_id(), 1);
    assert_eq!(os.os_id(), 4);
    assert!(microsoft.open_source().is_none());
    assert_eq!(microsoft.as_u64().to_le_bytes(), [0, 0, 0, 0, 0, 4, 1, 0]);
    let linux = HvGuestOsId::from(0x8142010203041234);
    assert!(linux.microsoft().is_none());
    let os = linux.open_source().unwrap();
    assert_eq!(os.os_type(), 1);
    assert_eq!(os.os_id(), 0x42);
    assert_eq!(os.version(), 0x01020304);
    assert_eq!(os.build_no(), 0x1234);
    assert_eq!(
        linux.as_u64().to_le_bytes(),
        [0x34, 0x12, 4, 3, 2, 1, 0x42, 0x81]
    );
}

// Test: Serialize intercept parameters for port ranges, individual ports, exceptions, and CPUID.
// Expected: Endpoints and selectors occupy their TLFS-defined bits with no sign extension.
#[test]
fn install_intercept_parameter_layout_retains_range_endpoints_and_selector_width() {
    for (ports, bytes) in [
        (0x3f8..=0x3ff, [0xf8, 3, 0xff, 3, 0, 0, 0, 0]),
        (0..=u16::MAX, [0, 0, 0xff, 0xff, 0, 0, 0, 0]),
    ] {
        let parameters = HvInterceptParameters::new_io_port_range(ports.clone());
        assert_eq!(parameters.as_bytes(), &bytes);
        assert_eq!(
            HvInterceptParameters::read_from_bytes(&bytes)
                .unwrap()
                .io_port_range(),
            ports
        );
        let intercept = InstallIntercept {
            partition_id: 7,
            access_type_mask: 3,
            intercept_type: HvInterceptType::HvInterceptTypeX64IoPortRange,
            intercept_parameters: parameters,
        };
        assert_eq!(&intercept.as_bytes()[16..24], &bytes);
    }
    let port = HvInterceptParameters::new_io_port(0xcf8);
    assert_eq!(port.as_bytes(), &[0xf8, 0xc, 0, 0, 0, 0, 0, 0]);
    assert_eq!(port.io_port(), 0xcf8);
    let exception = HvInterceptParameters::new_exception(14);
    assert_eq!(exception.as_bytes(), &[14, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(exception.exception(), 14);
    let cpuid =
        HvInterceptParameters::read_from_bytes(&[2, 0, 0, 0x80, 0xff, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(cpuid.cpuid_index(), 0x80000002);
}

// Test: Interpret simple and extended 4-KiB flush entries for virtual and physical addresses.
// Expected: The count boundary and all address bits remain distinct in both formats.
#[test]
fn flush_page_ranges_decode_counts_without_corrupting_page_numbers() {
    let raw = 0x123456789abccfff;
    let virtual_range = HvGvaRange::from(raw);
    let physical_range = HvGpaRange(raw);
    assert_eq!(u64::from(virtual_range), raw);
    assert_eq!(virtual_range.as_simple().additional_pages(), 0xfff);
    assert_eq!(virtual_range.as_simple().gva_page_number(), 0x123456789abcc);
    assert_eq!(physical_range.as_simple().additional_pages(), 0xfff);
    assert_eq!(
        physical_range.as_simple().gpa_page_number(),
        0x123456789abcc
    );
    let raw = 0x123456789abcc7ff;
    let virtual_range = HvGvaRange::from(raw).as_extended();
    let physical_range = HvGpaRange(raw).as_extended();
    assert!(!virtual_range.large_page());
    assert!(!physical_range.large_page());
    assert_eq!(virtual_range.additional_pages(), 0x7ff);
    assert_eq!(physical_range.additional_pages(), 0x7ff);
    assert_eq!(virtual_range.gva_page_number(), 0x123456789abcc);
    assert_eq!(physical_range.gpa_page_number(), 0x123456789abcc);
}

// Test: Decode extended 2-MiB and 1-GiB flush entries for both address spaces.
// Expected: Page-size selection and counts do not leak into the large-page address.
#[test]
fn large_flush_ranges_keep_page_size_separate_from_address_and_count() {
    for (raw, is_gigabyte) in [(0x123480000805, false), (0x123480001805, true)] {
        let virtual_range = HvGvaRange::from(raw).as_extended_large_page();
        let physical_range = HvGpaRange(raw).as_extended_large_page();
        assert!(virtual_range.large_page());
        assert!(physical_range.large_page());
        assert_eq!(virtual_range.page_size(), is_gigabyte);
        assert_eq!(physical_range.page_size(), is_gigabyte);
        assert_eq!(virtual_range.additional_pages(), 5);
        assert_eq!(physical_range.additional_pages(), 5);
        assert_eq!(virtual_range.gva_large_page_number(), 0x123480000000 >> 21);
        assert_eq!(physical_range.gpa_large_page_number(), 0x123480000000 >> 21);
    }
}

// Test: Pack host visibility and VTL permissions in an accept-pages request header.
// Expected: Shared/private/future visibility encodings preserve independent memory and VTL fields.
#[test]
fn accepted_page_attributes_preserve_visibility_and_independent_permissions() {
    for (visibility, raw) in [
        (HostVisibilityType::PRIVATE, 0x501),
        (HostVisibilityType::SHARED, 0x5c1),
        (HostVisibilityType(1), 0x541),
        (HostVisibilityType(2), 0x581),
    ] {
        let attributes = AcceptPagesAttributes::new()
            .with_memory_type(1)
            .with_vtl_set(5)
            .with_host_visibility(visibility);
        assert_eq!(u32::from(attributes), raw);
        let decoded = AcceptPagesAttributes::read_from_bytes(&raw.to_le_bytes()).unwrap();
        assert_eq!(decoded.host_visibility(), visibility);
        assert_eq!(decoded.memory_type(), 1);
        assert_eq!(decoded.vtl_set(), 5);
    }
}

// Test: Pack interrupt delivery controls and per-VTL SNP injection modes.
// Expected: Interrupt tags round-trip, including unknown tags, without altering delivery flags.
#[test]
fn interrupt_control_and_snp_modes_preserve_independent_delivery_fields() {
    let mut control = HvInterruptControl::new()
        .with_interrupt_type(HvInterruptType::HvX64InterruptTypeNmi)
        .with_x86_level_triggered(true)
        .with_x86_logical_destination_mode(true);
    assert_eq!(u64::from(control), 0x0000000300000004);
    assert_eq!(
        control.interrupt_type(),
        HvInterruptType::HvX64InterruptTypeNmi
    );
    control.set_interrupt_type(HvInterruptType(0x80000001));
    assert_eq!(u64::from(control), 0x0000000380000001);
    assert_eq!(control.interrupt_type(), HvInterruptType(0x80000001));
    let mut vsm = HvRegisterGuestVsmPartitionConfig::new()
        .with_maximum_vtl(2)
        .with_vtl0_interrupt_injection(HvSnpInterruptInjection::HvSnpRestricted)
        .with_vtl1_interrupt_injection(HvSnpInterruptInjection::HvSnpSecureAvic);
    assert_eq!(u64::from(vsm), 0xc2);
    vsm.set_vtl0_interrupt_injection(HvSnpInterruptInjection::HvSnpAlternate);
    assert_eq!(u64::from(vsm), 0xe2);
    assert_eq!(
        vsm.vtl0_interrupt_injection(),
        HvSnpInterruptInjection::HvSnpAlternate
    );
    assert_eq!(
        vsm.vtl1_interrupt_injection(),
        HvSnpInterruptInjection::HvSnpSecureAvic
    );
}
