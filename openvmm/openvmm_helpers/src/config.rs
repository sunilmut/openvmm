// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for constructing VM configurations.

use openvmm_defs::config::LinuxDirectBootMode;
use openvmm_defs::config::LoadMode;

/// Whether this boot path exposes the host's ACPI power button to the guest.
///
/// IGVM images supply their own firmware tables, and device-tree-only Linux
/// boot has no ACPI button description. `None` carries no firmware information;
/// snapshot restore must reconstruct the original device configuration.
pub fn supports_acpi_power_button(load_mode: &LoadMode) -> bool {
    match load_mode {
        LoadMode::Linux { boot_mode, .. } => match boot_mode {
            LinuxDirectBootMode::Acpi => true,
            LinuxDirectBootMode::DeviceTree => false,
        },
        LoadMode::Uefi { .. } | LoadMode::Pcat { .. } => true,
        LoadMode::Igvm { .. } | LoadMode::None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvmm_defs::config::IgvmPersonality;
    use openvmm_defs::config::LinuxIsolationConfig;
    use openvmm_defs::config::Vtl2BaseAddressType;
    use test_with_tracing::test;

    // Test: Select ACPI or device-tree discovery for Linux direct boot.
    // Expected: Only the ACPI boot mode exposes the host ACPI power button.
    #[test]
    fn linux_discovery_mode_controls_acpi_button() {
        for (boot_mode, expected) in [
            (LinuxDirectBootMode::Acpi, true),
            (LinuxDirectBootMode::DeviceTree, false),
        ] {
            let mode = LoadMode::Linux {
                kernel: tempfile::tempfile().unwrap(),
                initrd: None,
                cmdline: String::new(),
                enable_serial: false,
                isolation: LinuxIsolationConfig::None,
                boot_mode,
                smbios: Default::default(),
            };
            assert_eq!(supports_acpi_power_button(&mode), expected);
        }
    }

    // Test: Compare UEFI, IGVM-supplied firmware and an unspecified restore boot mode.
    // Expected: UEFI exposes the button; IGVM and unspecified firmware do not.
    #[test]
    fn firmware_source_controls_acpi_button() {
        let uefi = LoadMode::Uefi {
            firmware: tempfile::tempfile().unwrap(),
            enable_debugging: false,
            enable_memory_protections: true,
            disable_frontpage: true,
            tpm_version: None,
            enable_battery: false,
            enable_serial: false,
            enable_vpci_boot: false,
            uefi_console_mode: None,
            default_boot_always_attempt: false,
            smbios: Default::default(),
            enable_vmbus: true,
            force_dma_bounce: false,
            enable_hv: false,
            hibernation_enabled: false,
            force_firmware_version: false,
        };
        assert!(supports_acpi_power_button(&uefi));
        for personality in [
            IgvmPersonality::Openhcl,
            IgvmPersonality::Uefi,
            IgvmPersonality::LinuxDirect,
        ] {
            let igvm = LoadMode::Igvm {
                file: tempfile::tempfile().unwrap(),
                cmdline: String::new(),
                vtl2_base_address: Vtl2BaseAddressType::File,
                com_serial: None,
                personality,
            };
            assert!(!supports_acpi_power_button(&igvm));
        }
        assert!(!supports_acpi_power_button(&LoadMode::None));
    }
}
