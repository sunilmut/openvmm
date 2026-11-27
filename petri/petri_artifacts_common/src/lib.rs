// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `petri` test artifact declarations used by all petri-based tests, no matter
//! what VMM backend is being used.

/// Runtime capabilities that VMM tests can require.
pub mod capabilities {
    /// Software VPCI device emulation support.
    pub const VPCI: &str = "vpci";

    /// Support for resetting a partition running Windows.
    pub const WINDOWS_PARTITION_RESET: &str = "windows_partition_reset";

    /// Support for nested virtualization
    pub const NESTED_VIRT: &str = "nested_virt";

    /// Support for resetting a partition with nested virtualization enabled.
    pub const NESTED_RESET: &str = "nested_reset";

    /// All capability names known to petri, including those defined by
    /// tests.
    pub const KNOWN_CAPABILITIES: &[&str] = &[
        VPCI,
        WINDOWS_PARTITION_RESET,
        NESTED_VIRT,
        NESTED_RESET,
        "test_disk",
        "edu_initiator",
        "ivshmem_target",
    ];

    /// Returns `name` if it is a known capability name.
    pub fn known(name: &str) -> Option<&'static str> {
        KNOWN_CAPABILITIES
            .iter()
            .copied()
            .find(|capability| *capability == name)
    }

    /// Returns whether `name` is a known capability name.
    pub fn is_known_name(name: &str) -> bool {
        known(name).is_some()
    }
}

/// Artifact declarations
pub mod artifacts {
    use petri_artifacts_core::declare_artifacts;

    declare_artifacts! {
        /// Pipette windows x86_64 executable
        PIPETTE_WINDOWS_X64("pipette.exe", WINDOWS_X64),
        /// Pipette linux x86_64 musl executable
        PIPETTE_LINUX_X64_MUSL("pipette", LINUX_X64_MUSL),
        /// Pipette windows aarch64 executable
        PIPETTE_WINDOWS_AARCH64("pipette.exe", WINDOWS_AARCH64),
        /// Pipette linux aarch64 musl executable
        PIPETTE_LINUX_AARCH64_MUSL("pipette", LINUX_AARCH64_MUSL),
        /// Directory to put petri test logs in
        TEST_LOG_DIRECTORY("test_results", ANY),
    }
}

/// Artifact tag trait declarations
pub mod tags {
    use petri_artifacts_core::ArtifactId;

    /// A coarse-grained label used to differentiate between different OS
    /// environments.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[expect(missing_docs)] // Self-describing names.
    pub enum OsFlavor {
        Windows,
        Linux,
        FreeBsd,
        Uefi,
    }

    /// The machine architecture supported by the artifact or VM.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[expect(missing_docs)] // Self describing names
    pub enum MachineArch {
        X86_64,
        Aarch64,
    }

    impl MachineArch {
        /// Returns the host's architecture.
        pub fn host() -> Self {
            cfg_select! {
                // xtask-fmt allow-target-arch oneoff-petri-host-arch
                target_arch = "x86_64" => Self::X86_64,
                // xtask-fmt allow-target-arch oneoff-petri-host-arch
                target_arch = "aarch64" => Self::Aarch64,
                _ => panic!("unsupported host architecture"),
            }
        }
    }

    /// Quirks needed to boot a guest.
    #[derive(Default, Clone, Debug)]
    pub struct GuestQuirksInner {
        /// How long to wait after the shutdown IC reports ready before sending
        /// the shutdown command.
        ///
        /// This is necessary because some guests will ignore shutdown requests
        /// that arrive too early in the boot process.
        pub hyperv_shutdown_ic_sleep: Option<std::time::Duration>,
        /// Some guests reboot automatically soon after first boot.
        pub initial_reboot: Option<InitialRebootCondition>,
    }

    /// Some guests may automatically reboot only in certain configurations
    #[derive(Clone, Copy, Debug)]
    pub enum InitialRebootCondition {
        /// This guest always reboots on this VMM.
        Always,
        /// This guest only reboots when the TPM is enabled.
        WithTpm,
    }

    /// Quirks needed to boot a guest, allowing for differences based on backend
    #[derive(Default, Clone, Debug)]
    pub struct GuestQuirks {
        /// Quirks when running in OpenVMM
        pub openvmm: GuestQuirksInner,
        /// Quirks when running in Hyper-V
        pub hyperv: GuestQuirksInner,
    }

    impl GuestQuirks {
        /// Use the same quirks for all backends
        pub fn for_all_backends(quirks: GuestQuirksInner) -> GuestQuirks {
            GuestQuirks {
                openvmm: quirks.clone(),
                hyperv: quirks,
            }
        }
    }

    /// Artifact is a OpenHCL IGVM file
    pub trait IsOpenhclIgvm: IsLoadable + ArtifactId {}

    /// Artifact is a bootable test VHD file
    pub trait IsTestVhd: ArtifactId {
        /// What [`OsFlavor`] this image boots into.
        const OS_FLAVOR: OsFlavor;

        /// What [`MachineArch`] this image supports.
        const ARCH: MachineArch;

        /// Declare any "quirks" needed to boot the image.
        fn quirks() -> GuestQuirks {
            GuestQuirks::default()
        }
    }

    /// Artifact is a bootable test ISO file
    pub trait IsTestIso: ArtifactId {
        /// What [`OsFlavor`] this image boots into.
        const OS_FLAVOR: OsFlavor;

        /// What [`MachineArch`] this image supports.
        const ARCH: MachineArch;

        /// Declare any "quirks" needed to boot the image.
        fn quirks() -> GuestQuirks {
            GuestQuirks::default()
        }
    }

    /// Artifact is a binary that can be loaded into a VM
    pub trait IsLoadable: ArtifactId {
        /// What [`MachineArch`] this artifact supports.
        const ARCH: MachineArch;
    }

    /// Artifact is a test VMGS file
    pub trait IsTestVmgs: ArtifactId {}

    /// Artifact is a VmgsTool binary
    pub trait IsVmgsTool: ArtifactId {}
}

#[cfg(test)]
mod tests {
    use super::capabilities::*;
    use super::tags::*;
    use std::collections::BTreeSet;
    use test_with_tracing::test;

    // Test: Inspect every known capability name and look up known, unknown,
    //       differently cased and padded names.
    // Expected: Names are unique lowercase identifiers usable in
    //       `requires(...)`; only exact matches are known, and a lookup of an
    //       owned copy returns the registered name.
    #[test]
    fn capability_registry_has_unique_identifiers_and_exact_lookup() {
        let names: BTreeSet<_> = KNOWN_CAPABILITIES.iter().collect();
        assert_eq!(names.len(), KNOWN_CAPABILITIES.len());
        for &name in KNOWN_CAPABILITIES {
            assert!(
                !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit()),
                "{name}"
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
            let owned: String = name.chars().collect();
            let found = known(&owned).unwrap();
            assert_eq!(found, name);
            assert!(is_known_name(name));
        }
        for unknown in ["", "VPCI", " vpci", "vpci ", "nested", "test-disk"] {
            assert_eq!(known(unknown), None, "{unknown:?}");
            assert!(!is_known_name(unknown));
        }
    }

    petri_artifacts_core::declare_artifacts! {
        /// Fixture image that declares no boot quirks.
        PLAIN_IMAGE("plain.img", ANY),
    }

    impl IsTestVhd for PLAIN_IMAGE {
        const OS_FLAVOR: OsFlavor = OsFlavor::Linux;
        const ARCH: MachineArch = MachineArch::X86_64;
    }

    impl IsTestIso for PLAIN_IMAGE {
        const OS_FLAVOR: OsFlavor = OsFlavor::FreeBsd;
        const ARCH: MachineArch = MachineArch::Aarch64;
    }

    // Test: Query boot quirks for VHD and ISO images that declare none.
    // Expected: Both backends get no shutdown delay and no initial reboot,
    //       so undeclared images are booted without workarounds.
    #[test]
    fn images_without_declared_quirks_get_none() {
        for quirks in [
            <PLAIN_IMAGE as IsTestVhd>::quirks(),
            <PLAIN_IMAGE as IsTestIso>::quirks(),
        ] {
            for inner in [quirks.openvmm, quirks.hyperv] {
                assert!(inner.hyperv_shutdown_ic_sleep.is_none());
                assert!(inner.initial_reboot.is_none());
            }
        }
    }

    // Test: Expand backend-independent quirks, and query the host architecture.
    // Expected: OpenVMM and Hyper-V receive identical quirks, the default has
    //       none, and the host architecture matches this test binary's target.
    #[test]
    fn quirks_apply_to_all_backends_and_host_arch_matches_target() {
        let quirks = GuestQuirks::for_all_backends(GuestQuirksInner {
            hyperv_shutdown_ic_sleep: Some(std::time::Duration::from_millis(1500)),
            initial_reboot: Some(InitialRebootCondition::WithTpm),
        });
        assert_eq!(
            format!("{:?}", quirks.openvmm),
            format!("{:?}", quirks.hyperv)
        );
        assert_eq!(
            quirks.openvmm.hyperv_shutdown_ic_sleep,
            Some(std::time::Duration::from_millis(1500))
        );
        let default = GuestQuirks::default();
        assert!(
            default.openvmm.initial_reboot.is_none()
                && default.hyperv.hyperv_shutdown_ic_sleep.is_none()
        );
        let expected = if cfg!(target_arch = "x86_64") {
            MachineArch::X86_64
        } else {
            MachineArch::Aarch64
        };
        assert_eq!(MachineArch::host(), expected);
    }
}
