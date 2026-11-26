// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hypervisor backend implementations for OpenVMM.
//!
//! Each submodule provides a [`HypervisorProbe`](hypervisor_resources::HypervisorProbe)
//! implementation for the corresponding hypervisor backend.
//!
//! Probes are registered here via `register_hypervisor_probes!`. Resource
//! resolvers are registered separately in `openvmm_resources`.

#![forbid(unsafe_code)]

pub mod hvf;
pub mod kvm;
pub mod mshv;
pub mod whp;

// Register probes for auto-detection (checked in this order).
hypervisor_resources::register_hypervisor_probes! {
    #[cfg(all(target_os = "linux", feature = "virt_mshv", guest_is_native))]
    mshv::MshvProbe,

    #[cfg(all(target_os = "linux", feature = "virt_kvm", guest_is_native))]
    kvm::KvmProbe,

    #[cfg(all(target_os = "windows", feature = "virt_whp", guest_is_native))]
    whp::WhpProbe,

    #[cfg(all(target_os = "macos", guest_arch = "aarch64", guest_is_native, feature = "virt_hvf"))]
    hvf::HvfProbe,
}

/// Returns whether OpenVMM can create SEV-SNP partitions with MSHV on this
/// machine. See `virt_mshv::is_snp_available` for why this is a probe.
pub fn mshv_snp_available() -> bool {
    cfg_select! {
        all(
            target_os = "linux",
            feature = "virt_mshv",
            guest_is_native,
            guest_arch = "x86_64"
        ) => virt_mshv::is_snp_available(),
        _ => false,
    }
}

/// Returns whether KVM supports the nested-state ioctls on this machine.
pub fn kvm_nested_state_available() -> bool {
    #[cfg(all(
        target_os = "linux",
        feature = "virt_kvm",
        guest_is_native,
        guest_arch = "x86_64"
    ))]
    {
        virt_kvm::is_nested_state_available()
    }
    #[cfg(not(all(
        target_os = "linux",
        feature = "virt_kvm",
        guest_is_native,
        guest_arch = "x86_64"
    )))]
    {
        false
    }
}

/// Returns whether MSHV supports partition scrub on this machine.
/// TODO: Remove when dom0 Kernel ships with this IOCTL
pub fn mshv_partition_scrub_available() -> bool {
    #[cfg(all(target_os = "linux", feature = "virt_mshv", guest_is_native))]
    {
        virt_mshv::is_partition_scrub_available()
    }
    #[cfg(not(all(target_os = "linux", feature = "virt_mshv", guest_is_native)))]
    {
        false
    }
}

/// Returns whether WHP supports nested partition reset on this machine.
pub fn whp_nested_reset_available() -> bool {
    #[cfg(all(
        target_os = "windows",
        feature = "virt_whp",
        guest_is_native,
        guest_arch = "x86_64"
    ))]
    {
        virt_whp::is_nested_reset_available()
    }
    #[cfg(not(all(
        target_os = "windows",
        feature = "virt_whp",
        guest_is_native,
        guest_arch = "x86_64"
    )))]
    {
        false
    }
}

#[expect(clippy::allow_attributes, reason = "lots of conditions")]
#[allow(dead_code)]
pub(crate) fn parse_bool_param(key: &str, val: &str) -> anyhow::Result<bool> {
    match val {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => anyhow::bail!("invalid boolean value for {key}: {val}"),
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    guest_is_native,
    any(feature = "virt_kvm", feature = "virt_mshv")
))]
mod contract_tests {
    use hypervisor_resources::HypervisorProbe;
    use test_with_tracing::test;

    // Test: Supply unsupported KVM parameters through the public probe.
    // Expected: Parameter errors identify the rejected key before host device
    //       availability can mask an invalid backend configuration.
    #[cfg(feature = "virt_kvm")]
    #[test]
    fn kvm_rejects_foreign_parameters_before_opening_device() {
        for key in ["snp_disable_cpuid_offload", "user_mode_apic", ""] {
            let error = crate::kvm::KvmProbe
                .new_resource(&[(key, "true")])
                .unwrap_err();
            assert_eq!(error.to_string(), format!("unknown kvm parameter: {key}"));
        }
    }

    // Test: Validate complete MSHV option lists, including boolean spellings.
    // Expected: Every accepted boolean reaches validation of the following
    //       key; malformed values retain their own key and value in the error.
    #[cfg(feature = "virt_mshv")]
    #[test]
    fn mshv_validates_options_before_host_capabilities() {
        let key = "snp_disable_cpuid_offload";
        for value in ["true", "1", "yes", "false", "0", "no"] {
            let error = crate::mshv::MshvProbe
                .new_resource(&[(key, value), ("foreign_backend_option", "true")])
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "unknown mshv parameter: foreign_backend_option"
            );
        }
        for value in ["", "TRUE", "2", "true ", "λ"] {
            let error = crate::mshv::MshvProbe
                .new_resource(&[(key, value)])
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("invalid boolean value for {key}: {value}")
            );
        }
        let error = crate::mshv::MshvProbe
            .new_resource(&[(key, "true"), (key, "invalid")])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("invalid boolean value for {key}: invalid")
        );
    }
}
