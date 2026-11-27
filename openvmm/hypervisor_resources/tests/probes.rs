// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exercises external probe registration and hypervisor-setting transport.

use hypervisor_resources::HypervisorKind;
use hypervisor_resources::HypervisorProbe;
use hypervisor_resources::WhpHandle;
use hypervisor_resources::probe_by_name;
use hypervisor_resources::probes;
use mesh::OwnedMessage;
use test_with_tracing::test;
use vm_resource::Resource;

struct FirstProbe;
struct SecondProbe;

impl HypervisorProbe for FirstProbe {
    fn name(&self) -> &str {
        "test-first"
    }

    fn try_new_resource(&self) -> anyhow::Result<Option<Resource<HypervisorKind>>> {
        Ok(None)
    }

    fn new_resource(&self, _params: &[(&str, &str)]) -> anyhow::Result<Resource<HypervisorKind>> {
        anyhow::bail!("test backend is unavailable")
    }
}

impl HypervisorProbe for SecondProbe {
    fn name(&self) -> &str {
        "test-second"
    }

    fn try_new_resource(&self) -> anyhow::Result<Option<Resource<HypervisorKind>>> {
        Ok(None)
    }

    fn new_resource(&self, _params: &[(&str, &str)]) -> anyhow::Result<Resource<HypervisorKind>> {
        anyhow::bail!("test backend is unavailable")
    }
}

hypervisor_resources::register_hypervisor_probes! { FirstProbe, SecondProbe }

/// Force wire transport rather than a lazy message's same-type unwrap.
fn transport(settings: WhpHandle) -> WhpHandle {
    OwnedMessage::serialized(OwnedMessage::new(settings).serialize())
        .parse()
        .unwrap()
}

// Test: Discover externally registered probes and select them by exact name.
// Expected: Both registrations are visible, null sentinels are skipped, and
//       unknown or differently cased names do not select a backend.
#[test]
fn registered_probes_are_discoverable_by_exact_name() {
    let mut names = probes().map(|probe| probe.name()).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["test-first", "test-second"]);
    for name in names {
        assert_eq!(probe_by_name(name).unwrap().name(), name);
    }
    for name in ["", "test-missing", "TEST-FIRST"] {
        assert!(probe_by_name(name).is_none());
    }
}

// Test: Register two backends in highest-priority-first order.
// Expected: Discovery preserves that order for deterministic auto-selection.
#[test]
fn probe_registration_preserves_priority_order() {
    assert_eq!(
        probes().map(|probe| probe.name()).collect::<Vec<_>>(),
        ["test-first", "test-second"]
    );
}

// Test: Transport default and explicitly overridden WHP settings.
// Expected: APIC and enlightenment choices remain independent across the wire.
#[test]
fn whp_settings_preserve_defaults_and_independent_overrides() {
    let default = transport(WhpHandle::default());
    assert!(!default.user_mode_apic);
    assert!(default.offload_enlightenments);
    for (apic, enlightenments) in [(true, false), (true, true), (false, false)] {
        let restored = transport(WhpHandle {
            user_mode_apic: apic,
            offload_enlightenments: enlightenments,
        });
        assert_eq!(restored.user_mode_apic, apic);
        assert_eq!(restored.offload_enlightenments, enlightenments);
    }
}
