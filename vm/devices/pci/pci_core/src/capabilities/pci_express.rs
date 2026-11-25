// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PCI Express Capability with Function Level Reset (FLR) support.

use super::PciCapability;
use crate::spec::caps::CapabilityId;
use crate::spec::caps::pci_express;
use crate::spec::caps::pci_express::LinkSpeed;
use crate::spec::caps::pci_express::LinkWidth;
use crate::spec::caps::pci_express::MaxEndEndTlpPrefixes;
use crate::spec::caps::pci_express::PciExpressCapabilityHeader;
use crate::spec::caps::pci_express::SupportedLinkSpeedsVector;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use inspect::Inspect;
use parking_lot::Mutex;
use std::sync::Arc;

/// FLR bit is the 28th bit in the Device Capabilities register (0 indexed).
pub const PCI_EXPRESS_DEVICE_CAPS_FLR_BIT_MASK: u32 = 1 << 28;

/// Callback interface for handling Function Level Reset (FLR) events.
pub trait FlrHandler: Send + Sync + Inspect {
    /// Called when Function Level Reset is initiated.
    fn initiate_flr(&self);
}

#[derive(Debug, Inspect)]
struct PciExpressState {
    registers: PciExpressRegisters,
    presence_detect_state: bool,
}

#[derive(Debug, Inspect)]
struct PciExpressRegisters {
    device_control: pci_express::DeviceControl,
    link_control: pci_express::LinkControl,
    slot_control: pci_express::SlotControl,
    slot_status_events: pci_express::SlotStatus,
    root_control: pci_express::RootControl,
    device_control_2: pci_express::DeviceControl2,
    link_control_2: pci_express::LinkControl2,
}

impl PciExpressState {
    fn new() -> Self {
        Self {
            registers: PciExpressRegisters::new(),
            presence_detect_state: false,
        }
    }

    fn reset_registers(&mut self) {
        let Self {
            registers,
            presence_detect_state: _,
        } = self;
        *registers = PciExpressRegisters::new();
    }

    fn slot_status(
        &self,
        slot_implemented: bool,
        downstream_port: bool,
    ) -> pci_express::SlotStatus {
        self.registers
            .slot_status_events
            .with_mrl_sensor_state(0)
            .with_presence_detect_state(
                (if slot_implemented {
                    self.presence_detect_state
                } else {
                    downstream_port
                })
                .into(),
            )
            .with_electromechanical_interlock_status(0)
    }

    fn link_status(&self) -> pci_express::LinkStatus {
        pci_express::LinkStatus::new()
            .with_current_link_speed(LinkSpeed::Speed32_0GtS)
            .with_negotiated_link_width(LinkWidth::X16)
            .with_data_link_layer_link_active(self.presence_detect_state)
    }
}

impl PciExpressRegisters {
    fn new() -> Self {
        Self {
            device_control: pci_express::DeviceControl::new()
                .with_enable_relaxed_ordering(true)
                .with_enable_no_snoop(true)
                .with_max_read_request_size(0b010),
            link_control: pci_express::LinkControl::new(),
            slot_control: pci_express::SlotControl::new(),
            slot_status_events: pci_express::SlotStatus::new(),
            root_control: pci_express::RootControl::new(),
            device_control_2: pci_express::DeviceControl2::new(),
            link_control_2: pci_express::LinkControl2::new()
                .with_target_link_speed(LinkSpeed::Speed32_0GtS),
        }
    }
}

#[derive(Inspect)]
/// Configurable PCI Express capability.
pub struct PciExpressCapability {
    pcie_capabilities: pci_express::PciExpressCapabilities,
    device_capabilities: pci_express::DeviceCapabilities,
    link_capabilities: pci_express::LinkCapabilities,
    slot_capabilities: pci_express::SlotCapabilities,
    root_capabilities: pci_express::RootCapabilities,
    device_capabilities_2: pci_express::DeviceCapabilities2,
    link_capabilities_2: pci_express::LinkCapabilities2,
    slot_capabilities_2: pci_express::SlotCapabilities2,
    state: Arc<Mutex<PciExpressState>>,
    #[inspect(skip)]
    flr_handler: Option<Arc<dyn FlrHandler>>,
}

impl PciExpressCapability {
    /// Creates a new PCI Express capability with FLR support.
    ///
    /// # Arguments
    /// * `typ` - The spec-defined device or port type.
    /// * `flr_handler` - Optional handler to be called when FLR is initiated. This emulator will report that FLR is supported if flr_handler = Some(_)
    pub fn new(typ: pci_express::DevicePortType, flr_handler: Option<Arc<dyn FlrHandler>>) -> Self {
        // ARI Forwarding is only meaningful on downstream-facing ports (root port /
        // switch downstream port) which turn Type 1 config requests into Type 0
        // requests to the connected device. Advertising it as supported lets an
        // ARI-aware guest enable ARI Forwarding so that endpoint functions numbered
        // greater than 7 (e.g. SR-IOV VFs) enumerate correctly instead of being
        // aliased under multiple device numbers. See PCIe Base Spec 7.0 §6.13.
        let ari_forwarding_supported = matches!(
            typ,
            pci_express::DevicePortType::RootPort
                | pci_express::DevicePortType::DownstreamSwitchPort
        );
        let function_level_reset =
            typ == pci_express::DevicePortType::Endpoint && flr_handler.is_some();
        Self {
            pcie_capabilities: pci_express::PciExpressCapabilities::new()
                .with_capability_version(2)
                .with_device_port_type(typ),
            device_capabilities: pci_express::DeviceCapabilities::new()
                .with_role_based_error(true)
                .with_function_level_reset(function_level_reset),
            // TODO: Advertising 32 GT/s is not automatically PCIe spec compliant. PCIe 7.0
            // requires additional support, including 10-bit Tag Completer and the Secondary
            // PCI Express, Data Link Feature (for downstream ports), Physical Layer 16.0 GT/s,
            // and Physical Layer 32.0 GT/s Extended Capabilities.
            link_capabilities: pci_express::LinkCapabilities::new()
                .with_max_link_speed(LinkSpeed::Speed32_0GtS)
                .with_max_link_width(LinkWidth::X16)
                .with_aspm_optionality_compliance(true),
            slot_capabilities: pci_express::SlotCapabilities::new(),
            root_capabilities: pci_express::RootCapabilities::new(),
            device_capabilities_2: pci_express::DeviceCapabilities2::new()
                .with_ari_forwarding_supported(ari_forwarding_supported),
            link_capabilities_2: pci_express::LinkCapabilities2::new()
                .with_supported_link_speeds_vector(SupportedLinkSpeedsVector::UpToGen5), // Support speeds up to PCIe Gen 5 (32.0 GT/s)
            slot_capabilities_2: pci_express::SlotCapabilities2::new(),
            state: Arc::new(Mutex::new(PciExpressState::new())),
            flr_handler,
        }
    }

    fn handle_device_control_status_write(&mut self, val: ByteEnabledDwordWrite) {
        // Device Control (2 bytes) + Device Status (2 bytes)
        let mut state = self.state.lock();
        let new_control = pci_express::DeviceControl::from_bits(
            val.merge_low(state.registers.device_control.into_bits()),
        );

        if new_control.initiate_function_level_reset()
            && self.device_capabilities.function_level_reset()
        {
            if let Some(handler) = &self.flr_handler {
                handler.initiate_flr();
            }
        }

        state.registers.device_control = pci_express::DeviceControl::from_bits(
            new_control.into_bits() & self.device_control_writable_mask(),
        );
    }

    fn device_control_writable_mask(&self) -> u16 {
        pci_express::DeviceControl::new()
            .with_correctable_error_reporting_enable(true)
            .with_non_fatal_error_reporting_enable(true)
            .with_fatal_error_reporting_enable(true)
            .with_unsupported_request_reporting_enable(true)
            .with_enable_relaxed_ordering(true)
            .with_max_payload_size(0b111)
            .with_extended_tag_enable(self.device_capabilities.ext_tag_field())
            .with_phantom_functions_enable(self.device_capabilities.phantom_functions() != 0)
            .with_enable_no_snoop(true)
            .with_max_read_request_size(0b111)
            .into_bits()
    }

    fn handle_slot_control_status_write(&mut self, val: ByteEnabledDwordWrite) {
        // Slot Control (2 bytes) + Slot Status (2 bytes)
        let mut state = self.state.lock();

        let new_slot_control = pci_express::SlotControl::from_bits(
            val.merge_low(state.registers.slot_control.into_bits()),
        );

        state.registers.slot_control = pci_express::SlotControl::from_bits(
            new_slot_control.into_bits() & self.slot_control_writable_mask(),
        );

        let written_status = pci_express::SlotStatus::from_bits(val.extract_high());
        state.registers.slot_status_events = pci_express::SlotStatus::from_bits(
            state.registers.slot_status_events.into_bits()
                & !(written_status.into_bits() & self.slot_status_rw1c_mask()),
        );
    }

    fn slot_control_writable_mask(&self) -> u16 {
        let slot_implemented = self.pcie_capabilities.slot_implemented();
        let hotplug_capable = slot_implemented && self.slot_capabilities.hot_plug_capable();
        pci_express::SlotControl::new()
            .with_attention_button_pressed_enable(
                slot_implemented && self.slot_capabilities.attention_button_present(),
            )
            .with_power_fault_detected_enable(
                slot_implemented && self.slot_capabilities.power_controller_present(),
            )
            .with_mrl_sensor_changed_enable(
                slot_implemented && self.slot_capabilities.mrl_sensor_present(),
            )
            .with_presence_detect_changed_enable(hotplug_capable)
            .with_command_completed_interrupt_enable(
                hotplug_capable && !self.slot_capabilities.no_command_completed_support(),
            )
            .with_hot_plug_interrupt_enable(hotplug_capable)
            .with_attention_indicator_control(
                if slot_implemented && self.slot_capabilities.attention_indicator_present() {
                    0b11
                } else {
                    0
                },
            )
            .with_power_indicator_control(
                if slot_implemented && self.slot_capabilities.power_indicator_present() {
                    0b11
                } else {
                    0
                },
            )
            .with_power_controller_control(
                slot_implemented && self.slot_capabilities.power_controller_present(),
            )
            .with_data_link_layer_state_changed_enable(
                self.link_capabilities
                    .data_link_layer_link_active_reporting(),
            )
            .with_in_band_pd_disable(
                slot_implemented && self.slot_capabilities_2.in_band_pd_disable_supported(),
            )
            .into_bits()
    }

    fn slot_status_rw1c_mask(&self) -> u16 {
        let slot_implemented = self.pcie_capabilities.slot_implemented();
        let hotplug_capable = slot_implemented && self.slot_capabilities.hot_plug_capable();
        pci_express::SlotStatus::new()
            .with_attention_button_pressed(
                slot_implemented && self.slot_capabilities.attention_button_present(),
            )
            .with_power_fault_detected(
                slot_implemented && self.slot_capabilities.power_controller_present(),
            )
            .with_mrl_sensor_changed(
                slot_implemented && self.slot_capabilities.mrl_sensor_present(),
            )
            .with_presence_detect_changed(hotplug_capable)
            .with_command_completed(
                hotplug_capable && !self.slot_capabilities.no_command_completed_support(),
            )
            .with_data_link_layer_state_changed(
                self.link_capabilities
                    .data_link_layer_link_active_reporting(),
            )
            .into_bits()
    }

    fn handle_link_control_status_write(&mut self, val: ByteEnabledDwordWrite) {
        // Link Control (2 bytes) + Link Status (2 bytes)
        let mut state = self.state.lock();

        let new_link_control = pci_express::LinkControl::from_bits(
            val.merge_low(state.registers.link_control.into_bits()),
        );

        state.registers.link_control = pci_express::LinkControl::from_bits(
            new_link_control.into_bits() & self.link_control_writable_mask(),
        );
    }

    fn link_control_writable_mask(&self) -> u16 {
        let port_type = self.pcie_capabilities.device_port_type();
        let downstream_port = Self::is_downstream_port(port_type);
        // The PCIe spec requires Link Disable to be writable on downstream ports.
        // Keep it read-only because this emulator intentionally does not disable
        // downstream transaction forwarding when the bit is set.
        pci_express::LinkControl::new()
            .with_aspm_control(0b11)
            .with_read_completion_boundary(matches!(
                port_type,
                pci_express::DevicePortType::Endpoint
            ) as u16)
            .with_common_clock_configuration(true)
            .with_extended_synch(true)
            .with_enable_clock_power_management(
                matches!(
                    port_type,
                    pci_express::DevicePortType::Endpoint
                        | pci_express::DevicePortType::UpstreamSwitchPort
                ) && self.link_capabilities.clock_power_management(),
            )
            .with_link_bandwidth_management_interrupt_enable(
                downstream_port
                    && self
                        .link_capabilities
                        .link_bandwidth_notification_capability(),
            )
            .with_link_autonomous_bandwidth_interrupt_enable(
                downstream_port
                    && self
                        .link_capabilities
                        .link_bandwidth_notification_capability(),
            )
            .with_drs_signaling_control(
                if downstream_port && self.link_capabilities_2.drs_supported() {
                    0b11
                } else {
                    0
                },
            )
            .into_bits()
    }

    fn handle_link_control_2_write(&mut self, val: ByteEnabledDwordWrite) {
        // Link Control 2 (2 bytes) + Link Status 2 (2 bytes)
        let mut state = self.state.lock();

        let new_link_control_2 = pci_express::LinkControl2::from_bits(
            val.merge_low(state.registers.link_control_2.into_bits()),
        );

        state.registers.link_control_2 = pci_express::LinkControl2::from_bits(
            new_link_control_2.into_bits() & Self::link_control_2_writable_mask(),
        );
    }

    fn link_control_2_writable_mask() -> u16 {
        pci_express::LinkControl2::new()
            .with_target_link_speed(LinkSpeed::from_bits(0b1111))
            .with_enter_compliance(true)
            .with_hardware_autonomous_speed_disable(true)
            .with_transmit_margin(0b111)
            .with_enter_modified_compliance(true)
            .with_compliance_sos(true)
            .with_compliance_preset_de_emphasis(0b1111)
            .into_bits()
    }

    fn root_control_writable_mask(&self) -> u16 {
        let root_port =
            self.pcie_capabilities.device_port_type() == pci_express::DevicePortType::RootPort;
        pci_express::RootControl::new()
            .with_system_error_on_correctable_error_enable(root_port)
            .with_system_error_on_non_fatal_error_enable(root_port)
            .with_system_error_on_fatal_error_enable(root_port)
            .with_pme_interrupt_enable(root_port)
            .with_crs_software_visibility_enable(
                root_port && self.root_capabilities.crs_software_visibility(),
            )
            .into_bits()
    }

    fn device_control_2_writable_mask(&self) -> u16 {
        pci_express::DeviceControl2::new()
            .with_ari_forwarding_enable(self.device_capabilities_2.ari_forwarding_supported())
            .into_bits()
    }

    fn is_downstream_port(port_type: pci_express::DevicePortType) -> bool {
        matches!(
            port_type,
            pci_express::DevicePortType::RootPort
                | pci_express::DevicePortType::DownstreamSwitchPort
        )
    }

    /// Enable hotplug support for this PCIe capability.
    /// This configures the appropriate registers to support hotpluggable devices.
    /// Panics if called on device types other than RootPort or DownstreamSwitchPort.
    ///
    /// # Arguments
    /// * `slot_number` - The physical slot number to assign to this hotplug-capable port
    pub fn with_hotplug_support(mut self, slot_number: u32) -> Self {
        let port_type = self.pcie_capabilities.device_port_type();
        assert!(
            Self::is_downstream_port(port_type),
            "Hotplug support is not valid for device port type {port_type:?}. \
             Only RootPort and DownstreamSwitchPort support hotplug."
        );

        // Enable slot implemented in PCIe capabilities when hotplug is enabled
        self.pcie_capabilities = self.pcie_capabilities.with_slot_implemented(true);

        // Enable hotplug capabilities in slot capabilities register.
        //
        // We advertise no_command_completed_support because our emulation
        // applies Slot Control changes instantly (no hardware delay). This
        // tells the guest's pciehp driver to skip waiting for command_completed
        // after writing Slot Control (PCIe spec §7.5.3.9).
        //
        // Without this, a naive command_completed implementation that sets
        // the bit on every Slot Control write creates an interrupt storm:
        // the guest clears command_completed via RW1C (which is itself a
        // Slot Control write), re-triggering command_completed in a loop.
        // A correct implementation for ports with real delay would need to
        // diff old vs new Slot Control values and only signal completion
        // when control bits actually change, not on RW1C status clears.
        self.slot_capabilities = self
            .slot_capabilities
            .with_hot_plug_surprise(true)
            .with_hot_plug_capable(true)
            .with_no_command_completed_support(true)
            .with_physical_slot_number(slot_number);

        // Enable Data Link Layer Link Active Reporting when hotplug is enabled
        self.link_capabilities = self
            .link_capabilities
            .with_data_link_layer_link_active_reporting(true);

        self
    }

    /// Enable TLP prefixing support for this PCIe capability.
    ///
    /// This configures the appropriate registers to indicate that the function supports
    /// end-to-end TLP prefixes. We do not currently implement TLP prefixing in endpoint
    /// DMA APIs but this still may be required for ports upstream of passthrough devices
    /// that support TLP prefixing (ex. for guest controlled PASID with a virtual IOMMU).
    pub fn with_tlp_prefixing_supported(mut self, max_prefixes: MaxEndEndTlpPrefixes) -> Self {
        self.device_capabilities_2 = self
            .device_capabilities_2
            .with_extended_fmt_field_supported(true)
            .with_end_end_tlp_prefix_supported(true)
            .with_max_end_end_tlp_prefixes(max_prefixes);
        self
    }

    /// Set the physical presence state used to derive slot and link status.
    ///
    /// # Arguments
    /// * `present` - true if a device is present in the slot, false if the slot is empty
    pub fn set_presence_detect_state(&self, present: bool) {
        let mut state = self.state.lock();
        state.presence_detect_state = present;
    }

    /// Set the RW1C changed bits in Slot Status to signal a hotplug event.
    /// Call this only for runtime hotplug events, not build-time device attachment.
    pub fn set_hotplug_changed_bits(&self) {
        if !self.pcie_capabilities.slot_implemented() || !self.slot_capabilities.hot_plug_capable()
        {
            return;
        }

        let mut state = self.state.lock();
        state
            .registers
            .slot_status_events
            .set_presence_detect_changed(true);
        state
            .registers
            .slot_status_events
            .set_data_link_layer_state_changed(true);
    }

    /// Atomically update presence detect state, link active state, and
    /// changed bits for a hotplug event.
    pub fn set_hotplug_state(&self, present: bool) {
        if !self.pcie_capabilities.slot_implemented() || !self.slot_capabilities.hot_plug_capable()
        {
            return;
        }

        let mut state = self.state.lock();
        if state.presence_detect_state == present {
            return;
        }
        state.presence_detect_state = present;

        state
            .registers
            .slot_status_events
            .set_presence_detect_changed(true);
        state
            .registers
            .slot_status_events
            .set_data_link_layer_state_changed(true);
    }

    /// Returns whether the hot plug interrupt is enabled in Slot Control.
    pub fn hot_plug_interrupt_enabled(&self) -> bool {
        self.state
            .lock()
            .registers
            .slot_control
            .hot_plug_interrupt_enable()
    }

    /// Returns whether ARI Forwarding is enabled in Device Control 2.
    ///
    /// When set on a downstream-facing port, the port no longer enforces the
    /// requirement that the Device Number be 0 when turning a Type 1
    /// configuration request into a Type 0 request, allowing the full 8-bit
    /// ARI function number to reach the connected device. See PCIe Base Spec
    /// 7.0 §6.13.
    pub fn ari_forwarding_enable(&self) -> bool {
        self.state
            .lock()
            .registers
            .device_control_2
            .ari_forwarding_enable()
    }

    /// Returns a reference to the slot capabilities register.
    pub fn slot_capabilities(&self) -> &pci_express::SlotCapabilities {
        &self.slot_capabilities
    }
}

impl PciCapability for PciExpressCapability {
    fn label(&self) -> &str {
        "pci-express"
    }

    fn capability_id(&self) -> CapabilityId {
        CapabilityId::PCI_EXPRESS
    }

    fn len(&self) -> usize {
        // Implement the full PCI Express Capability structure (PCI Spec, Section 7.5.3):
        // 0x00: PCIe Capabilities (2 bytes) + Next Pointer (1 byte) + Capability ID (1 byte)
        // 0x04: Device Capabilities (4 bytes)
        // 0x08: Device Control (2 bytes) + Device Status (2 bytes)
        // 0x0C: Link Capabilities (4 bytes)
        // 0x10: Link Control (2 bytes) + Link Status (2 bytes)
        // 0x14: Slot Capabilities (4 bytes)
        // 0x18: Slot Control (2 bytes) + Slot Status (2 bytes)
        // 0x1C: Root Control (2 bytes) + Root Capabilities (2 bytes)
        // 0x20: Root Status (4 bytes)
        // 0x24: Device Capabilities 2 (4 bytes)
        // 0x28: Device Control 2 (2 bytes) + Device Status 2 (2 bytes)
        // 0x2C: Link Capabilities 2 (4 bytes)
        // 0x30: Link Control 2 (2 bytes) + Link Status 2 (2 bytes)
        // 0x34: Slot Capabilities 2 (4 bytes)
        // 0x38: Slot Control 2 (2 bytes) + Slot Status 2 (2 bytes)
        // Total: 60 bytes (0x3C)
        0x3C
    }

    fn read(&self, offset: u16, mut value: ByteEnabledDwordRead<'_>) {
        let state = self.state.lock();
        let label = self.label();
        match PciExpressCapabilityHeader(offset) {
            PciExpressCapabilityHeader::PCIE_CAPS => {
                // PCIe Capabilities Register (16 bits) + Next Pointer (8 bits) + Capability ID (8 bits)
                value.set_low_high(
                    CapabilityId::PCI_EXPRESS.0.into(),
                    self.pcie_capabilities.into_bits(),
                )
            }
            PciExpressCapabilityHeader::DEVICE_CAPS => {
                value.set(self.device_capabilities.into_bits())
            }
            PciExpressCapabilityHeader::DEVICE_CTL_STS => {
                // Device Control (2 bytes) + Device Status (2 bytes)
                value.set_low_high(state.registers.device_control.into_bits(), 0);
            }
            PciExpressCapabilityHeader::LINK_CAPS => value.set(self.link_capabilities.into_bits()),
            PciExpressCapabilityHeader::LINK_CTL_STS => {
                // Link Control (2 bytes) + Link Status (2 bytes)
                value.set_low_high(
                    state.registers.link_control.into_bits(),
                    state.link_status().into_bits(),
                );
            }
            PciExpressCapabilityHeader::SLOT_CAPS => value.set(self.slot_capabilities.into_bits()),
            PciExpressCapabilityHeader::SLOT_CTL_STS => {
                // Slot Control (2 bytes) + Slot Status (2 bytes)
                value.set_low_high(
                    state.registers.slot_control.into_bits(),
                    state
                        .slot_status(
                            self.pcie_capabilities.slot_implemented(),
                            Self::is_downstream_port(self.pcie_capabilities.device_port_type()),
                        )
                        .into_bits(),
                );
            }
            PciExpressCapabilityHeader::ROOT_CTL_CAPS => {
                // Root Control (2 bytes) + Root Capabilities (2 bytes)
                value.set_low_high(
                    state.registers.root_control.into_bits(),
                    self.root_capabilities.into_bits(),
                );
            }
            PciExpressCapabilityHeader::ROOT_STS => {
                value.set(0);
            }
            PciExpressCapabilityHeader::DEVICE_CAPS_2 => {
                value.set(self.device_capabilities_2.into_bits())
            }
            PciExpressCapabilityHeader::DEVICE_CTL_STS_2 => {
                // Device Control 2 (2 bytes) + Device Status 2 (2 bytes)
                value.set_low_high(state.registers.device_control_2.into_bits(), 0);
            }
            PciExpressCapabilityHeader::LINK_CAPS_2 => {
                value.set(self.link_capabilities_2.into_bits())
            }
            PciExpressCapabilityHeader::LINK_CTL_STS_2 => {
                // Link Control 2 (2 bytes) + Link Status 2 (2 bytes)
                value.set_low_high(state.registers.link_control_2.into_bits(), 0);
            }
            PciExpressCapabilityHeader::SLOT_CAPS_2 => {
                value.set(self.slot_capabilities_2.into_bits())
            }
            PciExpressCapabilityHeader::SLOT_CTL_STS_2 => {
                value.set(0);
            }
            _ => {
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    "unhandled pci express capability read"
                );
                value.set(0);
            }
        }
    }

    fn write(&mut self, offset: u16, val: ByteEnabledDwordWrite) {
        let label = self.label();
        match PciExpressCapabilityHeader(offset) {
            PciExpressCapabilityHeader::PCIE_CAPS => {
                // PCIe Capabilities register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only pcie capabilities"
                );
            }
            PciExpressCapabilityHeader::DEVICE_CAPS => {
                // Device Capabilities register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only device capabilities"
                );
            }
            PciExpressCapabilityHeader::DEVICE_CTL_STS => {
                self.handle_device_control_status_write(val);
            }
            PciExpressCapabilityHeader::LINK_CAPS => {
                // Link Capabilities register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only link capabilities"
                );
            }
            PciExpressCapabilityHeader::LINK_CTL_STS => {
                self.handle_link_control_status_write(val);
            }
            PciExpressCapabilityHeader::SLOT_CAPS => {
                // Slot Capabilities register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only slot capabilities"
                );
            }
            PciExpressCapabilityHeader::SLOT_CTL_STS => {
                self.handle_slot_control_status_write(val);
            }
            PciExpressCapabilityHeader::ROOT_CTL_CAPS => {
                // Root Control (2 bytes) + Root Capabilities (2 bytes)
                let mut state = self.state.lock();
                let new_control = pci_express::RootControl::from_bits(
                    val.merge_low(state.registers.root_control.into_bits()),
                );
                state.registers.root_control = pci_express::RootControl::from_bits(
                    new_control.into_bits() & self.root_control_writable_mask(),
                );
                // Root Capabilities upper 16 bits are read-only
            }
            PciExpressCapabilityHeader::ROOT_STS => {
                // Root Status is not modeled and remains hardwired to zero.
            }
            PciExpressCapabilityHeader::DEVICE_CAPS_2 => {
                // Device Capabilities 2 register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only device capabilities 2"
                );
            }
            PciExpressCapabilityHeader::DEVICE_CTL_STS_2 => {
                // Device Control 2 (2 bytes) + Device Status 2 (2 bytes)
                let mut state = self.state.lock();
                let new_control = pci_express::DeviceControl2::from_bits(
                    val.merge_low(state.registers.device_control_2.into_bits()),
                );
                state.registers.device_control_2 = pci_express::DeviceControl2::from_bits(
                    new_control.into_bits() & self.device_control_2_writable_mask(),
                );
            }
            PciExpressCapabilityHeader::LINK_CAPS_2 => {
                // Link Capabilities 2 register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only link capabilities 2"
                );
            }
            PciExpressCapabilityHeader::LINK_CTL_STS_2 => {
                self.handle_link_control_2_write(val);
            }
            PciExpressCapabilityHeader::SLOT_CAPS_2 => {
                // Slot Capabilities 2 register is read-only
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "write to read-only slot capabilities 2"
                );
            }
            PciExpressCapabilityHeader::SLOT_CTL_STS_2 => {
                // Slot Control 2 and Slot Status 2 are reserved and hardwired to zero.
            }
            _ => {
                tracelimit::warn_ratelimited!(
                    ?label,
                    offset,
                    ?val,
                    "unhandled pci express capability write"
                );
            }
        }
    }

    fn reset(&mut self) {
        let mut state = self.state.lock();
        state.reset_registers();
    }

    fn as_pci_express(&self) -> Option<&PciExpressCapability> {
        Some(self)
    }

    fn as_pci_express_mut(&mut self) -> Option<&mut PciExpressCapability> {
        Some(self)
    }
}

mod save_restore {
    use super::*;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        #[derive(Protobuf, SavedStateRoot)]
        #[mesh(package = "pci.capabilities.pci_express")]
        pub struct SavedState {
            #[mesh(1)]
            pub device_control: u16,
            #[mesh(2)]
            pub link_control: u16,
            #[mesh(3)]
            pub slot_control: u16,
            #[mesh(4)]
            pub slot_status_events: u16,
            #[mesh(5)]
            pub root_control: u16,
            #[mesh(6)]
            pub device_control_2: u16,
            #[mesh(7)]
            pub link_control_2: u16,
        }
    }

    impl SaveRestore for PciExpressCapability {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            let state = self.state.lock();
            let PciExpressState {
                registers,
                presence_detect_state: _,
            } = &*state;
            let PciExpressRegisters {
                device_control,
                link_control,
                slot_control,
                slot_status_events,
                root_control,
                device_control_2,
                link_control_2,
            } = registers;
            Ok(state::SavedState {
                device_control: device_control.into_bits(),
                link_control: link_control.into_bits(),
                slot_control: slot_control.into_bits(),
                slot_status_events: slot_status_events.into_bits(),
                root_control: root_control.into_bits(),
                device_control_2: device_control_2.into_bits(),
                link_control_2: link_control_2.into_bits(),
            })
        }

        fn restore(&mut self, saved: Self::SavedState) -> Result<(), RestoreError> {
            let state::SavedState {
                device_control,
                link_control,
                slot_control,
                slot_status_events,
                root_control,
                device_control_2,
                link_control_2,
            } = saved;
            let mut state = self.state.lock();
            let PciExpressState {
                registers,
                presence_detect_state: _,
            } = &mut *state;
            *registers = PciExpressRegisters {
                device_control: pci_express::DeviceControl::from_bits(
                    device_control & self.device_control_writable_mask(),
                ),
                link_control: pci_express::LinkControl::from_bits(
                    link_control & self.link_control_writable_mask(),
                ),
                slot_control: pci_express::SlotControl::from_bits(
                    slot_control & self.slot_control_writable_mask(),
                ),
                slot_status_events: pci_express::SlotStatus::from_bits(
                    slot_status_events & self.slot_status_rw1c_mask(),
                ),
                root_control: pci_express::RootControl::from_bits(
                    root_control & self.root_control_writable_mask(),
                ),
                device_control_2: pci_express::DeviceControl2::from_bits(
                    device_control_2 & self.device_control_2_writable_mask(),
                ),
                link_control_2: pci_express::LinkControl2::from_bits(
                    link_control_2 & Self::link_control_2_writable_mask(),
                ),
            };
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
