// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::spec::caps::pci_express::DevicePortType;
use crate::test_helpers::read_cap_u32;
use crate::test_helpers::write_cap_u32;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigByteEnable;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

#[derive(Debug)]
struct TestFlrHandler {
    flr_initiated: AtomicBool,
}

impl TestFlrHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            flr_initiated: AtomicBool::new(false),
        })
    }

    fn was_flr_initiated(&self) -> bool {
        self.flr_initiated.load(Ordering::Acquire)
    }

    fn reset(&self) {
        self.flr_initiated.store(false, Ordering::Release);
    }
}

impl FlrHandler for TestFlrHandler {
    fn initiate_flr(&self) {
        self.flr_initiated.store(true, Ordering::Release);
    }
}

impl Inspect for TestFlrHandler {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("flr_initiated", self.flr_initiated.load(Ordering::Acquire));
    }
}

// Test: Read ARI support on downstream ports, an upstream port and an endpoint.
// Expected: Only downstream-facing ports advertise ARI forwarding.
#[test]
fn test_ari_forwarding_supported_by_port_type() {
    // ARI Forwarding Supported (Device Capabilities 2, bit 5 / 0x20) must be
    // advertised on downstream-facing ports and never on endpoints/upstream ports.
    for (typ, expected) in [
        (DevicePortType::RootPort, true),
        (DevicePortType::DownstreamSwitchPort, true),
        (DevicePortType::UpstreamSwitchPort, false),
        (DevicePortType::Endpoint, false),
    ] {
        let name = format!("{typ:?}");
        let cap = PciExpressCapability::new(typ, None);
        let device_caps_2 = read_cap_u32(&cap, 0x24);
        let ari_supported = device_caps_2 & 0x20 != 0;
        assert_eq!(ari_supported, expected, "unexpected ARI support for {name}");
    }
}

// Test: Set and clear a root port's ARI forwarding control.
// Expected: Both the public accessor and register follow the guest writes.
#[test]
fn test_ari_forwarding_enable_is_guest_writable() {
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    // Enable bit starts cleared.
    assert!(!cap.ari_forwarding_enable());

    // Guest sets ARI Forwarding Enable (Device Control 2, bit 5 / 0x20).
    write_cap_u32(&mut cap, 0x28, 0x0020);
    assert!(cap.ari_forwarding_enable());
    assert_eq!(read_cap_u32(&cap, 0x28) & 0x0020, 0x0020);

    // Guest clears it again.
    write_cap_u32(&mut cap, 0x28, 0x0000);
    assert!(!cap.ari_forwarding_enable());
}

// Test: Advertise each supported maximum number of end-to-end TLP prefixes.
// Expected: Support bits and the prefix-count encoding match the configuration.
#[test]
fn test_tlp_prefixing_supported_max_prefixes() {
    for max_prefixes in [
        MaxEndEndTlpPrefixes::One,
        MaxEndEndTlpPrefixes::Two,
        MaxEndEndTlpPrefixes::Three,
        MaxEndEndTlpPrefixes::Four,
    ] {
        let cap = PciExpressCapability::new(DevicePortType::Endpoint, None)
            .with_tlp_prefixing_supported(max_prefixes);
        let device_caps_2 = pci_express::DeviceCapabilities2::from_bits(read_cap_u32(&cap, 0x24));

        assert!(device_caps_2.extended_fmt_field_supported());
        assert!(device_caps_2.end_end_tlp_prefix_supported());
        assert_eq!(
            device_caps_2.max_end_end_tlp_prefixes().into_bits(),
            max_prefixes.into_bits(),
            "unexpected max TLP prefix encoding for {max_prefixes:?}"
        );
    }
}

// Test: Read an endpoint capability with function-level reset support.
// Expected: Header identity, FLR support, control defaults and link agree.
#[test]
fn test_pci_express_capability_read_endpoint() {
    let flr_handler = TestFlrHandler::new();
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, Some(flr_handler));

    // Test PCIe Capabilities Register (offset 0x00)
    let caps_val = read_cap_u32(&cap, 0x00);
    assert_eq!(caps_val & 0xFF, 0x10); // Capability ID = 0x10
    assert_eq!((caps_val >> 8) & 0xFF, 0x00); // Next Pointer = 0x00
    assert_eq!((caps_val >> 16) & 0xFFFF, 0x0002); // PCIe Caps: Version 2, Device/Port Type 0

    // Test Device Capabilities Register (offset 0x04)
    let device_caps_val = read_cap_u32(&cap, 0x04);
    assert_eq!(
        device_caps_val & PCI_EXPRESS_DEVICE_CAPS_FLR_BIT_MASK,
        PCI_EXPRESS_DEVICE_CAPS_FLR_BIT_MASK
    ); // FLR bit should be set

    // Test the specification-defined Device Control reset value.
    let device_ctl_sts_val = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts_val, 0x2810);

    // Test Link Control/Status Register (offset 0x10) - should have link status initialized
    let link_ctl_sts_val = read_cap_u32(&cap, 0x10);
    let expected_link_status =
        (LinkSpeed::Speed32_0GtS.into_bits() as u16) | ((LinkWidth::X16.into_bits() as u16) << 4); // current_link_speed + negotiated_link_width
    assert_eq!(link_ctl_sts_val, (expected_link_status as u32) << 16); // Link status is in upper 16 bits
}

// Test: Read the header of a root-port PCIe capability.
// Expected: Its wire identity, version and port type identify a root port.
#[test]
fn test_pci_express_capability_read_root_port() {
    let cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    // Test PCIe Capabilities Register (offset 0x00)
    let caps_val = read_cap_u32(&cap, 0x00);
    assert_eq!(caps_val & 0xFF, 0x10); // Capability ID = 0x10
    assert_eq!((caps_val >> 8) & 0xFF, 0x00); // Next Pointer = 0x00
    assert_eq!((caps_val >> 16) & 0xFFFF, 0x0042); // PCIe Caps: Version 2, Device/Port Type 4
}

// Test: Encode reserved PCIe speeds, widths and an unknown device port type.
// Expected: Unknown wire values round-trip without coercion or panic.
#[test]
fn test_pcie_open_enums_preserve_reserved_values() {
    assert_eq!(LinkSpeed::from_bits(0).into_bits(), 0);
    assert_eq!(LinkWidth::from_bits(0b11_1111).into_bits(), 0b11_1111);
    assert_eq!(
        SupportedLinkSpeedsVector::from_bits(0b101_0101).into_bits(),
        0b101_0101
    );

    let unknown_port_type = DevicePortType(0b1111);
    let capabilities =
        pci_express::PciExpressCapabilities::new().with_device_port_type(unknown_port_type);
    assert_eq!(capabilities.device_port_type(), unknown_port_type);
}

// Test: Read an endpoint configured without a function-level reset handler.
// Expected: The device capability does not advertise FLR.
#[test]
fn test_pci_express_capability_read_no_flr() {
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    // Test Device Capabilities Register (offset 0x04) - FLR should not be set
    let device_caps_val = read_cap_u32(&cap, 0x04);
    assert_eq!(device_caps_val & PCI_EXPRESS_DEVICE_CAPS_FLR_BIT_MASK, 0);
}

// Test: Supply an FLR handler to a root port and write the reset bit.
// Expected: FLR remains unadvertised and the handler is not invoked.
#[test]
fn test_flr_is_only_advertised_by_endpoints() {
    let flr_handler = TestFlrHandler::new();
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, Some(flr_handler.clone()));

    assert_eq!(
        read_cap_u32(&cap, 0x04) & PCI_EXPRESS_DEVICE_CAPS_FLR_BIT_MASK,
        0
    );
    write_cap_u32(&mut cap, 0x08, 0x8000);
    assert!(!flr_handler.was_flr_initiated());
}

// Test: Attempt to overwrite each advertised read-only PCIe register.
// Expected: Neither all-ones nor zero writes change the original capability values.
#[test]
fn test_pci_express_capability_write_readonly_registers() {
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    for offset in [0x00, 0x04, 0x0c, 0x14, 0x20, 0x24, 0x2c, 0x34, 0x38] {
        let original = read_cap_u32(&cap, offset);
        for value in [u32::MAX, 0] {
            write_cap_u32(&mut cap, offset, value);
            assert_eq!(read_cap_u32(&cap, offset), original, "register {offset:#x}");
        }
    }
}

// Test: Deliver hotplug changes while the guest clears event latches.
// Expected: Real transitions latch both events; unchanged presence does not; RW1C preserves presence.
#[test]
fn hotplug_transitions_latch_events_and_guest_acknowledgement_preserves_presence() {
    let mut capability =
        PciExpressCapability::new(DevicePortType::RootPort, None).with_hotplug_support(3);
    assert!(capability.slot_capabilities().hot_plug_capable());
    assert!(!capability.hot_plug_interrupt_enabled());
    write_cap_u32(&mut capability, 0x18, 0x20);
    assert!(capability.hot_plug_interrupt_enabled());
    capability.set_hotplug_state(true);
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0x0148);
    assert_ne!(read_cap_u32(&capability, 0x10) & (1 << 29), 0);
    write_cap_u32(&mut capability, 0x18, 0x01080020);
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0x0040);
    capability.set_hotplug_state(true);
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0x0040);
    capability.set_hotplug_state(false);
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0x0108);
    assert_eq!(read_cap_u32(&capability, 0x10) & (1 << 29), 0);
    write_cap_u32(&mut capability, 0x18, 0x01080020);
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0);
    capability.set_hotplug_changed_bits();
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0x0108);
    capability.reset();
    assert_eq!((read_cap_u32(&capability, 0x18) >> 16) & 0x0148, 0);
    assert!(!capability.hot_plug_interrupt_enabled());
}

// Test: Send hotplug notifications to a port that does not advertise hotplug support.
// Expected: Slot/link status do not change and hotplug interrupts remain disabled.
#[test]
fn non_hotplug_ports_ignore_hotplug_notifications() {
    let capability = PciExpressCapability::new(DevicePortType::RootPort, None);
    let before = (
        read_cap_u32(&capability, 0x18),
        read_cap_u32(&capability, 0x10),
    );
    capability.set_hotplug_state(false);
    capability.set_hotplug_changed_bits();
    assert_eq!(
        (
            read_cap_u32(&capability, 0x18),
            read_cap_u32(&capability, 0x10)
        ),
        before
    );
    assert!(!capability.hot_plug_interrupt_enabled());
}

// Test: Write endpoint controls and repeatedly request function-level reset.
// Expected: Ordinary controls persist, each FLR invokes its handler and clears.
#[test]
fn test_pci_express_capability_write_device_control() {
    let flr_handler = TestFlrHandler::new();
    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, Some(flr_handler.clone()));

    // Initial state should have FLR clear and the defined control defaults.
    let initial_ctl_sts = read_cap_u32(&cap, 0x08);
    assert_eq!(initial_ctl_sts & 0xFFFF, 0x2810);

    // Test writing to Device Control Register (lower 16 bits of offset 0x08)
    // Set some control bits but not FLR initially
    write_cap_u32(&mut cap, 0x08, 0x0001); // Enable correctable error reporting (bit 0)
    let device_ctl_sts = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts & 0xFFFF, 0x0001); // Device Control should be set
    assert!(!flr_handler.was_flr_initiated()); // FLR should not be triggered

    // Test FLR initiation (bit 15 of Device Control)
    flr_handler.reset();
    write_cap_u32(&mut cap, 0x08, 0x8001); // Set FLR bit (bit 15) and other control bits
    let device_ctl_sts_after_flr = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts_after_flr & 0xFFFF, 0x0001); // FLR bit should be cleared, others remain
    assert!(flr_handler.was_flr_initiated()); // FLR should be triggered

    // Test that writing FLR bit when it's already been triggered behaves correctly
    flr_handler.reset();
    // After the previous FLR, device_control should have bit 0 set but FLR clear
    // So writing 0x8000 (only FLR bit) should trigger FLR again
    write_cap_u32(&mut cap, 0x08, 0x8000); // Set FLR bit only
    let device_ctl_sts_final = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts_final & 0xFFFF, 0x0000); // All bits should be cleared (FLR self-clears, bit 0 was overwritten)
    assert!(flr_handler.was_flr_initiated()); // Should trigger because FLR transitioned from 0 to 1
}

// Test: Write all ones to unimplemented PCIe status registers.
// Expected: Every unimplemented status field continues to read zero.
#[test]
fn test_unimplemented_status_registers_ignore_writes() {
    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    write_cap_u32(&mut cap, 0x08, 0xffff_0000);
    write_cap_u32(&mut cap, 0x20, 0xffff_ffff);
    write_cap_u32(&mut cap, 0x28, 0xffff_0000);
    write_cap_u32(&mut cap, 0x30, 0xffff_0000);
    write_cap_u32(&mut cap, 0x38, 0xffff_ffff);

    assert_eq!(read_cap_u32(&cap, 0x08) >> 16, 0);
    assert_eq!(read_cap_u32(&cap, 0x20), 0);
    assert_eq!(read_cap_u32(&cap, 0x28) >> 16, 0);
    assert_eq!(read_cap_u32(&cap, 0x30) >> 16, 0);
    assert_eq!(read_cap_u32(&cap, 0x38), 0);
}

// Test: Write all control bits on a root port and endpoint.
// Expected: Only each device type's supported control fields remain set.
#[test]
fn test_unsupported_control_fields_ignore_all_ones_write() {
    let mut root_port = PciExpressCapability::new(DevicePortType::RootPort, None);

    write_cap_u32(&mut root_port, 0x08, u32::MAX);
    write_cap_u32(&mut root_port, 0x10, u32::MAX);
    write_cap_u32(&mut root_port, 0x1c, u32::MAX);
    write_cap_u32(&mut root_port, 0x28, u32::MAX);
    write_cap_u32(&mut root_port, 0x30, u32::MAX);

    assert_eq!(read_cap_u32(&root_port, 0x08), 0x0000_78ff);
    assert_eq!(read_cap_u32(&root_port, 0x10) & 0xffff, 0x00c3);
    assert_eq!(read_cap_u32(&root_port, 0x1c), 0x0000_000f);
    assert_eq!(read_cap_u32(&root_port, 0x28), 0x0000_0020);
    assert_eq!(read_cap_u32(&root_port, 0x30), 0x0000_ffbf);

    let mut endpoint = PciExpressCapability::new(DevicePortType::Endpoint, None);
    write_cap_u32(&mut endpoint, 0x10, u32::MAX);
    write_cap_u32(&mut endpoint, 0x1c, u32::MAX);
    write_cap_u32(&mut endpoint, 0x28, u32::MAX);
    assert_eq!(read_cap_u32(&endpoint, 0x10) & 0xffff, 0x00cb);
    assert_eq!(read_cap_u32(&endpoint, 0x1c), 0);
    assert_eq!(read_cap_u32(&endpoint, 0x28), 0);
}

// Test: Write one enabled byte of endpoint device control.
// Expected: Disabled control bytes survive and status remains read-only.
#[test]
fn test_pci_express_capability_byte_write_control() {
    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    cap.write(
        0x08,
        ByteEnabledDwordWrite::new(
            0x0000_0001,
            PciConfigByteEnable::from_offset_len(0x08, 1).unwrap(),
        ),
    );

    let device_ctl_sts = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts & 0xffff, 0x2801);
    assert_eq!(device_ctl_sts & 0xffff_0000, 0);

    cap.write(
        0x08,
        ByteEnabledDwordWrite::new(
            0x0001_0000,
            PciConfigByteEnable::from_offset_len(0x08, 1).unwrap(),
        ),
    );

    let status_after = read_cap_u32(&cap, 0x08) & 0xffff_0000;
    assert_eq!(status_after, 0);
}

// Test: Write the link register while observing device control.
// Expected: The write does not corrupt the neighboring control register.
#[test]
fn test_pci_express_capability_write_unhandled_offset() {
    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    // Writing to unhandled offset should not panic
    write_cap_u32(&mut cap, 0x10, 0xFFFFFFFF);
    // Should not crash and should not affect other registers
    assert_eq!(read_cap_u32(&cap, 0x08), 0x2810);
}

// Test: Reset a modified root port that still has a physically present device.
// Expected: Guest controls reset without removing physical presence or link.
#[test]
fn test_pci_express_capability_reset() {
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None).with_hotplug_support(1);
    cap.set_presence_detect_state(true);

    // Set some state
    write_cap_u32(&mut cap, 0x08, 0x0001); // Set some device control bits

    // Verify state is set
    let device_ctl_sts = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts, 0x0001);
    let slot_status = pci_express::SlotStatus::from_bits((read_cap_u32(&cap, 0x18) >> 16) as u16);
    let link_status = pci_express::LinkStatus::from_bits((read_cap_u32(&cap, 0x10) >> 16) as u16);
    assert_eq!(slot_status.presence_detect_state(), 1);
    assert!(link_status.data_link_layer_link_active());

    // Reset the capability
    cap.reset();

    // Guest-controlled and event state resets, while externally managed
    // physical state remains unchanged.
    let device_ctl_sts_after_reset = read_cap_u32(&cap, 0x08);
    assert_eq!(device_ctl_sts_after_reset, 0x2810);
    let slot_status = pci_express::SlotStatus::from_bits((read_cap_u32(&cap, 0x18) >> 16) as u16);
    let link_status = pci_express::LinkStatus::from_bits((read_cap_u32(&cap, 0x10) >> 16) as u16);
    assert_eq!(slot_status.presence_detect_state(), 1);
    assert!(link_status.data_link_layer_link_active());
}

// Test: Read every extended PCIe register on a default endpoint.
// Expected: Link advertisements, target speed and unsupported fields agree.
#[test]
fn test_pci_express_capability_extended_registers() {
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    // Test that extended registers return proper default values and don't crash
    // Link Capabilities should have default speed (Speed32_0GtS) and width (X16)
    let expected_link_caps =
        LinkSpeed::Speed32_0GtS.into_bits() | (LinkWidth::X16.into_bits() << 4) | (1 << 22);
    assert_eq!(read_cap_u32(&cap, 0x0C), expected_link_caps); // Link Capabilities
    // Link Control/Status should have Link Status with current_link_speed=5 and negotiated_link_width=16
    let expected_link_ctl_sts =
        (LinkSpeed::Speed32_0GtS.into_bits() as u16) | ((LinkWidth::X16.into_bits() as u16) << 4); // current_link_speed (bits 0-3) + negotiated_link_width (bits 4-9) = 5 + (16 << 4) = 5 + 256 = 261
    assert_eq!(
        read_cap_u32(&cap, 0x10),
        (expected_link_ctl_sts as u32) << 16
    ); // Link Control/Status (status in upper 16 bits)
    assert_eq!(read_cap_u32(&cap, 0x14), 0); // Slot Capabilities
    assert_eq!(read_cap_u32(&cap, 0x18), 0); // Slot Control/Status
    assert_eq!(read_cap_u32(&cap, 0x1C), 0); // Root Control/Capabilities
    assert_eq!(read_cap_u32(&cap, 0x20), 0); // Root Status
    assert_eq!(read_cap_u32(&cap, 0x24), 0); // Device Capabilities 2
    assert_eq!(read_cap_u32(&cap, 0x28), 0); // Device Control/Status 2
    // Link Capabilities 2 has supported_link_speeds_vector set to UpToGen5
    let expected_link_caps_2 = SupportedLinkSpeedsVector::UpToGen5.into_bits() << 1; // supported_link_speeds_vector at bits 1-7 = 31 << 1 = 62
    assert_eq!(read_cap_u32(&cap, 0x2C), expected_link_caps_2); // Link Capabilities 2
    // Link Control/Status 2 - Link Control 2 should have target_link_speed set to Speed32_0GtS (5)
    let expected_link_ctl_sts_2 = LinkSpeed::Speed32_0GtS.into_bits() as u16; // target_link_speed in lower 4 bits = 5
    assert_eq!(read_cap_u32(&cap, 0x30), expected_link_ctl_sts_2 as u32); // Link Control/Status 2
    assert_eq!(read_cap_u32(&cap, 0x34), 0); // Slot Capabilities 2
    assert_eq!(read_cap_u32(&cap, 0x38), 0); // Slot Control/Status 2
}

// Test: Query the space occupied by a PCIe capability.
// Expected: The layout occupies sixty bytes for capability-chain placement.
#[test]
fn test_pci_express_capability_length() {
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, None);
    assert_eq!(cap.len(), 0x3C); // Should be 60 bytes (0x3C)
}

// Test: Query the PCIe capability's checkpoint identity label.
// Expected: Its stable label is pci-express.
#[test]
fn test_pci_express_capability_label() {
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, None);
    assert_eq!(cap.label(), "pci-express");
}

// Test: Enable hotplug on both supported downstream-facing port types.
// Expected: Guest-visible slot flags and numbers change only with hotplug.
#[test]
fn test_pci_express_capability_with_hotplug_support() {
    // Test with RootPort (should work)
    let cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    let cap_with_hotplug = cap.with_hotplug_support(1);

    // Verify that the method doesn't crash and returns the capability
    assert_eq!(cap_with_hotplug.label(), "pci-express");
    assert_eq!(cap_with_hotplug.len(), 0x3C);

    // Verify hotplug capabilities are set
    assert!(cap_with_hotplug.slot_capabilities().hot_plug_surprise());
    assert!(cap_with_hotplug.slot_capabilities().hot_plug_capable());
    assert_eq!(
        cap_with_hotplug.slot_capabilities().physical_slot_number(),
        1
    );

    // Verify that slot_implemented is set in PCIe capabilities
    assert!(
        read_cap_u32(&cap_with_hotplug, 0) & (1 << 24) != 0,
        "slot_implemented should be true when hotplug is enabled"
    );

    // Test with DownstreamSwitchPort (should work)
    let cap2 = PciExpressCapability::new(DevicePortType::DownstreamSwitchPort, None);
    let cap2_with_hotplug = cap2.with_hotplug_support(2);

    assert!(cap2_with_hotplug.slot_capabilities().hot_plug_surprise());
    assert!(cap2_with_hotplug.slot_capabilities().hot_plug_capable());
    assert_eq!(
        cap2_with_hotplug.slot_capabilities().physical_slot_number(),
        2
    );

    // Verify that slot_implemented is set for downstream switch port too
    assert!(
        read_cap_u32(&cap2_with_hotplug, 0) & (1 << 24) != 0,
        "slot_implemented should be true when hotplug is enabled"
    );

    // Test that non-hotplug capability doesn't have slot_implemented set
    let cap_no_hotplug = PciExpressCapability::new(DevicePortType::RootPort, None);
    assert!(
        read_cap_u32(&cap_no_hotplug, 0) & (1 << 24) == 0,
        "slot_implemented should be false when hotplug is not enabled"
    );
}

// Test: Request hotplug configuration on an endpoint.
// Expected: The internal configuration invariant rejects that unsupported mode.
#[test]
#[should_panic(expected = "Hotplug support is not valid for device port type Endpoint")]
fn test_pci_express_capability_with_hotplug_support_endpoint_panics() {
    let cap = PciExpressCapability::new(DevicePortType::Endpoint, None);
    cap.with_hotplug_support(1);
}

// Test: Request hotplug configuration on an upstream-facing switch port.
// Expected: The internal configuration invariant rejects that unsupported mode.
#[test]
#[should_panic(expected = "Hotplug support is not valid for device port type UpstreamSwitchPort")]
fn test_pci_express_capability_with_hotplug_support_upstream_panics() {
    let cap = PciExpressCapability::new(DevicePortType::UpstreamSwitchPort, None);
    cap.with_hotplug_support(1);
}

// Test: Set all slot controls on a normally configured hotplug root port.
// Expected: Advertised event controls work and unsupported hardware controls do not.
#[test]
fn test_slot_control_write_protection() {
    // Create a root port capability with hotplug support but limited slot capabilities
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap = cap.with_hotplug_support(1);

    // Try to write to slot control register with all bits set
    let slot_ctl_sts_offset = 0x18; // SLOT_CTL_STS offset
    let val_to_write = 0xFFFFFFFF; // All bits set in both control and status

    write_cap_u32(&mut cap, slot_ctl_sts_offset, val_to_write);

    // Read back the slot control register (lower 16 bits)
    let read_back = read_cap_u32(&cap, slot_ctl_sts_offset);
    let slot_control_value = read_back as u16;
    let slot_control = pci_express::SlotControl::from_bits(slot_control_value);

    // Verify that features not present in capabilities were not set in control register
    assert!(
        !slot_control.attention_button_pressed_enable(),
        "Attention button enable should be 0 when capability not present"
    );
    assert!(
        !slot_control.power_fault_detected_enable(),
        "Power fault enable should be 0 without a power controller"
    );
    assert!(
        !slot_control.power_controller_control(),
        "Power controller control should be 0 when capability not present"
    );
    assert!(
        !slot_control.mrl_sensor_changed_enable(),
        "MRL sensor changed enable should be 0 when capability not present"
    );
    assert_eq!(
        slot_control.attention_indicator_control(),
        0,
        "Attention indicator control should be 0 when capability not present"
    );
    assert_eq!(
        slot_control.power_indicator_control(),
        0,
        "Power indicator control should be 0 when capability not present"
    );
    assert!(
        !slot_control.electromechanical_interlock_control(),
        "Electromechanical interlock control should be 0 when capability not present"
    );
    assert!(
        !slot_control.command_completed_interrupt_enable(),
        "Command completed interrupt enable should be 0 when no command completed support"
    );
    assert!(!slot_control.auto_slot_power_limit_enable());
    assert!(!slot_control.in_band_pd_disable());

    // Native hotplug and DLL active reporting are advertised.
    assert!(slot_control.presence_detect_changed_enable());
    assert!(
        slot_control.hot_plug_interrupt_enable(),
        "Hotplug interrupt enable should be settable when hotplug capable"
    );
    assert!(slot_control.data_link_layer_state_changed_enable());
}

// Test: Request link retraining and then write a supported ASPM control.
// Expected: Retraining reads clear while the ordinary control remains writable.
#[test]
fn test_link_control_retrain_link_behavior() {
    // Test that retrain_link always reads as 0 regardless of what is written
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    let link_ctl_sts_offset = 0x10; // LINK_CTL_STS offset

    // Write a value with retrain_link bit set (bit 5)
    let write_val = 0x0020; // retrain_link bit (bit 5) = 1
    write_cap_u32(&mut cap, link_ctl_sts_offset, write_val);

    // Read back and verify retrain_link is always 0
    let read_back = read_cap_u32(&cap, link_ctl_sts_offset);
    let link_control = pci_express::LinkControl::from_bits(read_back as u16);

    assert!(
        !link_control.retrain_link(),
        "retrain_link should always read as 0"
    );

    // Verify other bits can still be set (except retrain_link)
    let write_val_2 = 0x0001; // aspm_control bit 0 = 1
    write_cap_u32(&mut cap, link_ctl_sts_offset, write_val_2);

    let read_back_2 = read_cap_u32(&cap, link_ctl_sts_offset);
    let link_control_2 = pci_express::LinkControl::from_bits(read_back_2 as u16);

    assert_eq!(
        link_control_2.aspm_control(),
        1,
        "Other control bits should be settable"
    );
    assert!(
        !link_control_2.retrain_link(),
        "retrain_link should still read as 0"
    );
}

// Test: Write Link Disable while a downstream device remains physically present.
// Expected: The intentionally read-only control cannot disable the active link.
#[test]
fn test_link_disable_is_read_only() {
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap.set_presence_detect_state(true);

    write_cap_u32(&mut cap, 0x10, 0x0010);

    let link_control = pci_express::LinkControl::from_bits(read_cap_u32(&cap, 0x10) as u16);
    assert!(!link_control.link_disable());
    assert!(
        pci_express::LinkStatus::from_bits((read_cap_u32(&cap, 0x10) >> 16) as u16)
            .data_link_layer_link_active()
    );
}

// Test: Compare link advertisements with and without hotplug support.
// Expected: Hotplug adds link-active reporting without changing speed or width.
#[test]
fn test_hotplug_link_capabilities() {
    // Test that Data Link Layer Link Active Reporting is enabled with hotplug
    let cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    let cap_with_hotplug = cap.with_hotplug_support(1);

    let link_caps_offset = 0x0C; // LINK_CAPS offset
    let link_caps = read_cap_u32(&cap_with_hotplug, link_caps_offset);
    let link_capabilities = pci_express::LinkCapabilities::from_bits(link_caps);

    // Verify that Data Link Layer Link Active Reporting is enabled
    assert!(
        link_capabilities.data_link_layer_link_active_reporting(),
        "Data Link Layer Link Active Reporting should be enabled for hotplug"
    );

    // Verify default speed and width are still correct
    assert_eq!(
        link_capabilities.max_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Max link speed should be Speed32_0GtS (PCIe 32.0 GT/s)"
    );
    assert_eq!(
        link_capabilities.max_link_width(),
        LinkWidth::X16,
        "Max link width should be X16 (x16)"
    );

    // Test that non-hotplug capability doesn't have Data Link Layer Link Active Reporting
    let cap_no_hotplug = PciExpressCapability::new(DevicePortType::RootPort, None);
    let link_caps_no_hotplug = read_cap_u32(&cap_no_hotplug, link_caps_offset);
    let link_capabilities_no_hotplug =
        pci_express::LinkCapabilities::from_bits(link_caps_no_hotplug);

    assert!(
        !link_capabilities_no_hotplug.data_link_layer_link_active_reporting(),
        "Data Link Layer Link Active Reporting should be disabled without hotplug"
    );
}

// Test: Write every link-status bit alongside a valid link-control change.
// Expected: Physical status survives while the writable control changes.
#[test]
fn test_link_status_read_only() {
    // Test that Link Status register is read-only and cannot be modified by writes
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None).with_hotplug_support(1);
    cap.set_presence_detect_state(true);

    let link_ctl_sts_offset = 0x10; // LINK_CTL_STS offset

    // Read initial values
    let initial_read = read_cap_u32(&cap, link_ctl_sts_offset);
    let initial_link_status = pci_express::LinkStatus::from_bits((initial_read >> 16) as u16);

    // Verify initial values are set
    assert_eq!(
        initial_link_status.current_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Initial link speed should be set"
    );
    assert_eq!(
        initial_link_status.negotiated_link_width(),
        LinkWidth::X16,
        "Initial link width should be set"
    );
    assert!(!initial_link_status.link_training());
    assert!(
        initial_link_status.data_link_layer_link_active(),
        "Initial DLL should be active"
    );

    // Try to write different values to Link Status (upper 16 bits) while also writing to Link Control
    let write_val = 0xFFFF0001; // Upper 16 bits all 1s (Link Status), lower 16 bits = 1 (Link Control)
    write_cap_u32(&mut cap, link_ctl_sts_offset, write_val);

    // Read back and verify Link Status hasn't changed
    let after_write = read_cap_u32(&cap, link_ctl_sts_offset);
    let final_link_status = pci_express::LinkStatus::from_bits((after_write >> 16) as u16);
    let final_link_control = pci_express::LinkControl::from_bits(after_write as u16);

    // Link Status should remain unchanged (read-only)
    assert_eq!(
        final_link_status.current_link_speed(),
        initial_link_status.current_link_speed(),
        "Link Status current_link_speed should be read-only"
    );
    assert_eq!(
        final_link_status.negotiated_link_width(),
        initial_link_status.negotiated_link_width(),
        "Link Status negotiated_link_width should be read-only"
    );
    assert!(!final_link_status.link_training());
    assert_eq!(
        final_link_status.data_link_layer_link_active(),
        initial_link_status.data_link_layer_link_active(),
        "Link Status data_link_layer_link_active should be read-only"
    );

    // But Link Control should be modifiable
    assert_eq!(
        final_link_control.aspm_control(),
        1,
        "Link Control should be writable"
    );
}

// Test: Acknowledge hotplug event latches independently through RW1C writes.
// Expected: Only selected events clear and physical presence remains unchanged.
#[test]
fn test_slot_status_rw1c_behavior() {
    // Create a root port capability with hotplug support
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap = cap.with_hotplug_support(1);

    let slot_ctl_sts_offset = 0x18; // SLOT_CTL_STS offset
    cap.set_hotplug_state(true);

    // Hotplug sets the two event latches this emulator implements.
    let initial_read = read_cap_u32(&cap, slot_ctl_sts_offset);
    let initial_status = pci_express::SlotStatus::from_bits((initial_read >> 16) as u16);
    assert!(initial_status.presence_detect_changed());
    assert!(initial_status.data_link_layer_state_changed());
    assert_eq!(initial_status.presence_detect_state(), 1);

    // Clear DLLSC while leaving PDC set.
    let clear_dllsc = pci_express::SlotStatus::new()
        .with_data_link_layer_state_changed(true)
        .into_bits();
    write_cap_u32(&mut cap, slot_ctl_sts_offset, u32::from(clear_dllsc) << 16);
    let status =
        pci_express::SlotStatus::from_bits((read_cap_u32(&cap, slot_ctl_sts_offset) >> 16) as u16);
    assert!(status.presence_detect_changed());
    assert!(!status.data_link_layer_state_changed());
    assert_eq!(status.presence_detect_state(), 1);

    // Clear PDC. The read-only physical presence bit remains set.
    let clear_pdc = pci_express::SlotStatus::new()
        .with_presence_detect_changed(true)
        .into_bits();
    write_cap_u32(&mut cap, slot_ctl_sts_offset, u32::from(clear_pdc) << 16);
    let status =
        pci_express::SlotStatus::from_bits((read_cap_u32(&cap, slot_ctl_sts_offset) >> 16) as u16);
    assert!(!status.presence_detect_changed());
    assert_eq!(status.presence_detect_state(), 1);

    // Re-applying the same physical state is not a new hotplug event.
    cap.set_hotplug_state(true);
    let status =
        pci_express::SlotStatus::from_bits((read_cap_u32(&cap, slot_ctl_sts_offset) >> 16) as u16);
    assert!(!status.presence_detect_changed());
    assert!(!status.data_link_layer_state_changed());
}

// Test: Write supported and unsupported target link-speed encodings.
// Expected: Target values persist without changing negotiated speed or width.
#[test]
fn test_link_control_2_target_speed_validation() {
    // Target Link Speed is guest control state. Current Link Speed reports
    // negotiated hardware state and does not change until link retraining.
    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    let link_ctl_sts_2_offset = 0x30; // LINK_CTL_STS_2 offset

    // Initially, target link speed should be Speed32_0GtS (5) and current link speed should match
    let initial_read = read_cap_u32(&cap, link_ctl_sts_2_offset);
    let initial_link_control_2 = pci_express::LinkControl2::from_bits(initial_read as u16);
    assert_eq!(
        initial_link_control_2.target_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Initial target link speed should be Speed32_0GtS"
    );

    // Check that link status reflects this speed
    let link_ctl_sts_offset = 0x10; // LINK_CTL_STS offset
    let link_ctl_sts = read_cap_u32(&cap, link_ctl_sts_offset);
    let link_status = pci_express::LinkStatus::from_bits((link_ctl_sts >> 16) as u16);
    assert_eq!(
        link_status.current_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Initial current link speed should match target speed"
    );
    assert_eq!(
        link_status.negotiated_link_width(),
        LinkWidth::X16,
        "Initial negotiated link width should be X16"
    );

    // Test writing a valid speed (Speed16_0GtS = 4) that's less than max speed (Speed32_0GtS = 5)
    let valid_speed = LinkSpeed::Speed16_0GtS;
    write_cap_u32(&mut cap, link_ctl_sts_2_offset, valid_speed.into_bits());

    // Verify target link speed was set correctly
    let after_valid_write = read_cap_u32(&cap, link_ctl_sts_2_offset);
    let link_control_2_after_valid = pci_express::LinkControl2::from_bits(after_valid_write as u16);
    assert_eq!(
        link_control_2_after_valid.target_link_speed(),
        valid_speed,
        "Target link speed should be set to requested valid speed"
    );

    // Writing Target Link Speed alone does not initiate retraining.
    let link_ctl_sts_after_valid = read_cap_u32(&cap, link_ctl_sts_offset);
    let link_status_after_valid =
        pci_express::LinkStatus::from_bits((link_ctl_sts_after_valid >> 16) as u16);
    assert_eq!(
        link_status_after_valid.current_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Target Link Speed must not directly change negotiated link speed"
    );

    // Unsupported Target Link Speed encodings have undefined behavior. The
    // register preserves the guest value rather than inventing a clamp.
    let invalid_speed = LinkSpeed::Speed64_0GtS;
    write_cap_u32(&mut cap, link_ctl_sts_2_offset, invalid_speed.into_bits());

    let after_invalid_write = read_cap_u32(&cap, link_ctl_sts_2_offset);
    let link_control_2_after_invalid =
        pci_express::LinkControl2::from_bits(after_invalid_write as u16);
    assert_eq!(
        link_control_2_after_invalid.target_link_speed(),
        invalid_speed,
        "Target link speed should preserve the guest value"
    );

    // The unsupported target still does not alter negotiated status.
    let link_ctl_sts_after_invalid = read_cap_u32(&cap, link_ctl_sts_offset);
    let link_status_after_invalid =
        pci_express::LinkStatus::from_bits((link_ctl_sts_after_invalid >> 16) as u16);
    assert_eq!(
        link_status_after_invalid.current_link_speed(),
        LinkSpeed::Speed32_0GtS,
        "Target Link Speed must not directly change negotiated link speed"
    );

    // Verify that link width remains unchanged throughout
    assert_eq!(
        link_status_after_valid.negotiated_link_width(),
        LinkWidth::X16,
        "Negotiated link width should remain unchanged"
    );
    assert_eq!(
        link_status_after_invalid.negotiated_link_width(),
        LinkWidth::X16,
        "Negotiated link width should remain unchanged"
    );
}

// Test: Configure hotplug slots numbered zero, five and 255 on supported ports.
// Expected: Each public slot capability reports its configured slot number.
#[test]
fn test_with_hotplug_support_slot_number() {
    // Test that slot numbers are properly set when enabling hotplug support

    // Test with slot number 5
    let cap1 = PciExpressCapability::new(DevicePortType::RootPort, None);
    let cap1_with_hotplug = cap1.with_hotplug_support(5);

    assert!(cap1_with_hotplug.slot_capabilities().hot_plug_capable());
    assert_eq!(
        cap1_with_hotplug.slot_capabilities().physical_slot_number(),
        5
    );

    // Test with slot number 0
    let cap2 = PciExpressCapability::new(DevicePortType::DownstreamSwitchPort, None);
    let cap2_with_hotplug = cap2.with_hotplug_support(0);

    assert!(cap2_with_hotplug.slot_capabilities().hot_plug_capable());
    assert_eq!(
        cap2_with_hotplug.slot_capabilities().physical_slot_number(),
        0
    );

    // Test with a larger slot number
    let cap3 = PciExpressCapability::new(DevicePortType::RootPort, None);
    let cap3_with_hotplug = cap3.with_hotplug_support(255);

    assert!(cap3_with_hotplug.slot_capabilities().hot_plug_capable());
    assert_eq!(
        cap3_with_hotplug.slot_capabilities().physical_slot_number(),
        255
    );
}

// Test: Read the Slot Implemented wire bit before and after enabling hotplug.
// Expected: Only the hotplug-capable configuration advertises an implemented slot.
#[test]
fn test_slot_implemented_flag_in_pcie_capabilities_register() {
    // Test that slot_implemented bit is correctly set in the PCIe Capabilities register
    // when hotplug support is enabled

    // Test without hotplug - slot_implemented should be false
    let cap_no_hotplug = PciExpressCapability::new(DevicePortType::RootPort, None);
    let caps_val_no_hotplug = read_cap_u32(&cap_no_hotplug, 0x00);
    let pcie_caps_no_hotplug = (caps_val_no_hotplug >> 16) as u16;
    let slot_implemented_bit = (pcie_caps_no_hotplug >> 8) & 0x1; // slot_implemented is bit 8 of PCIe capabilities
    assert_eq!(
        slot_implemented_bit, 0,
        "slot_implemented should be 0 when hotplug is not enabled"
    );

    // Test with hotplug - slot_implemented should be true
    let cap_with_hotplug = cap_no_hotplug.with_hotplug_support(1);
    let caps_val_with_hotplug = read_cap_u32(&cap_with_hotplug, 0x00);
    let pcie_caps_with_hotplug = (caps_val_with_hotplug >> 16) as u16;
    let slot_implemented_bit_hotplug = (pcie_caps_with_hotplug >> 8) & 0x1; // slot_implemented is bit 8 of PCIe capabilities
    assert_eq!(
        slot_implemented_bit_hotplug, 1,
        "slot_implemented should be 1 when hotplug is enabled"
    );
}

// Test: Mark a hotplug slot present and then absent through the public setter.
// Expected: Guest-visible physical presence follows both transitions.
#[test]
fn test_set_presence_detect_state() {
    // Test setting presence detect state on a hotplug-capable port
    let cap = PciExpressCapability::new(DevicePortType::RootPort, None).with_hotplug_support(1);

    // Initially, presence detect state should be 0 (no device present)
    let initial_slot_status = read_cap_u32(&cap, 0x18); // Slot Control + Slot Status
    let initial_presence_detect = (initial_slot_status >> 22) & 0x1; // presence_detect_state is bit 6 of slot status (upper 16 bits)
    assert_eq!(
        initial_presence_detect, 0,
        "Initial presence detect state should be 0"
    );

    // Set device as present
    cap.set_presence_detect_state(true);
    let present_slot_status = read_cap_u32(&cap, 0x18);
    let present_presence_detect = (present_slot_status >> 22) & 0x1;
    assert_eq!(
        present_presence_detect, 1,
        "Presence detect state should be 1 when device is present"
    );

    // Set device as not present
    cap.set_presence_detect_state(false);
    let absent_slot_status = read_cap_u32(&cap, 0x18);
    let absent_presence_detect = (absent_slot_status >> 22) & 0x1;
    assert_eq!(
        absent_presence_detect, 0,
        "Presence detect state should be 0 when device is not present"
    );
}

// Test: Change physical link state on a port without an implemented slot.
// Expected: Link activity follows presence while the slot-presence convention stays.
#[test]
fn test_set_presence_detect_state_without_slot_implemented() {
    let cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    let slot_status = pci_express::SlotStatus::from_bits((read_cap_u32(&cap, 0x18) >> 16) as u16);
    assert_eq!(slot_status.presence_detect_state(), 1);

    cap.set_presence_detect_state(true);
    assert!(
        pci_express::LinkStatus::from_bits((read_cap_u32(&cap, 0x10) >> 16) as u16,)
            .data_link_layer_link_active()
    );
    assert_eq!(
        pci_express::SlotStatus::from_bits((read_cap_u32(&cap, 0x18) >> 16) as u16)
            .presence_detect_state(),
        1
    );

    cap.set_presence_detect_state(false);
    assert!(
        !pci_express::LinkStatus::from_bits((read_cap_u32(&cap, 0x10) >> 16) as u16,)
            .data_link_layer_link_active()
    );
}

// Test: Save a newly created endpoint capability.
// Expected: The public checkpoint contains the defined control and event defaults.
#[test]
fn test_save_restore_default_state() {
    use vmcore::save_restore::SaveRestore;

    // Create a capability with default state
    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    // Save the default state
    let saved = cap.save().expect("save should succeed");

    // Verify default state values
    assert_eq!(saved.device_control, 0x2810);
    assert_eq!(saved.link_control, 0);
    assert_eq!(saved.slot_control, 0);
    assert_eq!(saved.slot_status_events, 0);
    assert_eq!(saved.root_control, 0);
    assert_eq!(saved.device_control_2, 0);
    // Link control 2 has default target_link_speed
    let expected_link_control_2 = LinkSpeed::Speed32_0GtS.into_bits() as u16;
    assert_eq!(saved.link_control_2, expected_link_control_2);
}

// Test: Save a root port after modifying supported control registers.
// Expected: The public checkpoint records each programmed control value.
#[test]
fn test_save_restore_modified_state() {
    use vmcore::save_restore::SaveRestore;

    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    // Modify state by writing to registers
    // Write to Device Control (offset 0x08, lower 16 bits)
    write_cap_u32(&mut cap, 0x08, 0x0005); // Set some device control bits

    // Write to Link Control (offset 0x10, lower 16 bits)
    write_cap_u32(&mut cap, 0x10, 0x0003); // Set ASPM control bits

    // Write to Device Control 2 (offset 0x28, lower 16 bits)
    write_cap_u32(&mut cap, 0x28, 0x0020); // Enable advertised ARI forwarding

    // Save the modified state
    let saved = cap.save().expect("save should succeed");

    // Verify the saved state reflects the modifications
    assert_eq!(saved.device_control, 0x0005);
    assert_eq!(saved.link_control, 0x0003);
    assert_eq!(saved.device_control_2, 0x0020);
}

// Test: Restore programmed root-port controls into a fresh capability.
// Expected: Device, link and second-generation controls round-trip through reads.
#[test]
fn test_save_restore_roundtrip() {
    use vmcore::save_restore::SaveRestore;

    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);

    // Modify various state registers
    write_cap_u32(&mut cap, 0x08, 0x000F); // Device Control
    write_cap_u32(&mut cap, 0x10, 0x0043); // Link Control
    write_cap_u32(&mut cap, 0x28, 0x0020); // Device Control 2
    write_cap_u32(&mut cap, 0x30, 0x0004); // Link Control 2 (target speed = 4)

    // Save the state
    let saved = cap.save().expect("save should succeed");

    // Create a new capability and restore the saved state
    let mut cap2 = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap2.restore(saved).expect("restore should succeed");

    // Verify restored state by reading registers
    let device_ctl_sts = read_cap_u32(&cap2, 0x08);
    assert_eq!(
        device_ctl_sts & 0xFFFF,
        0x000F,
        "Device control should be restored"
    );

    let link_ctl_sts = read_cap_u32(&cap2, 0x10);
    assert_eq!(
        link_ctl_sts & 0xFFFF,
        0x0043,
        "Link control should be restored"
    );

    let device_ctl_sts_2 = read_cap_u32(&cap2, 0x28);
    assert_eq!(
        device_ctl_sts_2 & 0xFFFF,
        0x0020,
        "Device control 2 should be restored"
    );

    let link_ctl_sts_2 = read_cap_u32(&cap2, 0x30);
    assert_eq!(
        link_ctl_sts_2 & 0xFFFF,
        0x0004,
        "Link control 2 should be restored"
    );
}

// Test: Checkpoint a real hotplug event and restore onto an empty destination.
// Expected: Event latches survive without importing source physical presence.
#[test]
fn test_save_restore_with_status_bits() {
    use vmcore::save_restore::SaveRestore;

    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap = cap.with_hotplug_support(1);

    cap.set_hotplug_state(true);

    // Save the state
    let saved = cap.save().expect("save should succeed");

    // Verify status bits are in saved state
    let saved_slot_status = pci_express::SlotStatus::from_bits(saved.slot_status_events);
    assert!(saved_slot_status.presence_detect_changed());
    assert_eq!(saved_slot_status.presence_detect_state(), 0);

    // Restore into a port with different physical state. The snapshot's
    // source-side presence must not overwrite destination topology.
    let mut cap2 = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap2 = cap2.with_hotplug_support(1);
    cap2.restore(saved).expect("restore should succeed");

    // Read back and verify the event latch was restored.
    let slot_ctl_sts = read_cap_u32(&cap2, 0x18);
    let restored_slot_status = pci_express::SlotStatus::from_bits((slot_ctl_sts >> 16) as u16);
    assert!(
        restored_slot_status.presence_detect_changed(),
        "Slot status should be restored"
    );
    assert_eq!(
        restored_slot_status.presence_detect_state(),
        0,
        "Presence detect state should be preserved independently of saved state"
    );
}

// Test: Restore a checkpoint with every supported and unsupported field set.
// Expected: A subsequent checkpoint contains only the supported register masks.
#[test]
fn test_restore_masks_unsupported_fields() {
    use vmcore::save_restore::SaveRestore;

    let mut cap = PciExpressCapability::new(DevicePortType::RootPort, None);
    let mut saved = cap.save().expect("save should succeed");
    saved.device_control = u16::MAX;
    saved.link_control = u16::MAX;
    saved.slot_control = u16::MAX;
    saved.slot_status_events = u16::MAX;
    saved.root_control = u16::MAX;
    saved.device_control_2 = u16::MAX;
    saved.link_control_2 = u16::MAX;

    let mut cap2 = PciExpressCapability::new(DevicePortType::RootPort, None);
    cap2.restore(saved).expect("restore should succeed");

    let saved2 = cap2.save().expect("second save should succeed");
    assert_eq!(saved2.device_control, 0x78ff);
    assert_eq!(saved2.link_control, 0x00c3);
    assert_eq!(saved2.slot_control, 0);
    assert_eq!(saved2.slot_status_events, 0);
    assert_eq!(saved2.root_control, 0x000f);
    assert_eq!(saved2.device_control_2, 0x0020);
    assert_eq!(saved2.link_control_2, 0xffbf);
}

// Test: Reset modified endpoint controls and then save a checkpoint.
// Expected: Serialized controls and event latches return to their defaults.
#[test]
fn test_save_after_reset() {
    use vmcore::save_restore::SaveRestore;

    let mut cap = PciExpressCapability::new(DevicePortType::Endpoint, None);

    // Modify state
    write_cap_u32(&mut cap, 0x08, 0x00FF);
    write_cap_u32(&mut cap, 0x10, 0x00FF);

    // Reset
    cap.reset();

    // Save after reset
    let saved = cap.save().expect("save should succeed");

    // Verify state is back to defaults
    assert_eq!(saved.device_control, 0x2810);
    assert_eq!(saved.link_control, 0);
    assert_eq!(saved.slot_status_events, 0);
}
