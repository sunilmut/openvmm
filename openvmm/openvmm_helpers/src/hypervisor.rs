// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hypervisor resource construction and auto-detection for OpenVMM entry
//! points.

use hypervisor_resources::HypervisorKind;
use vm_resource::Resource;

/// Returns a [`Resource<HypervisorKind>`] for the first available hypervisor
/// backend.
///
/// Backends are checked in registration order (highest priority first).
pub fn choose_hypervisor() -> anyhow::Result<Resource<HypervisorKind>> {
    for probe in hypervisor_resources::probes() {
        if let Some(resource) = probe.try_new_resource()? {
            return Ok(resource);
        }
    }
    anyhow::bail!("no hypervisor available");
}

/// Parses a hypervisor specifier of the form `name` or `name:key=val,key,...`.
///
/// Returns `(name, params)` where `params` is a list of `(key, value)` pairs.
/// A bare key (no `=`) is treated as a boolean flag with value `"true"`.
fn parse_hypervisor_spec(spec: &str) -> anyhow::Result<(&str, Vec<(&str, &str)>)> {
    let (name, rest) = spec.split_once(':').unwrap_or((spec, ""));
    anyhow::ensure!(!name.is_empty(), "empty hypervisor name in spec: {spec}");
    let params = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',')
            .filter(|item| !item.is_empty())
            .map(|item| {
                let (key, val) = item.split_once('=').unwrap_or((item, "true"));
                anyhow::ensure!(!key.is_empty(), "empty parameter key in spec: {spec}");
                Ok((key, val))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    Ok((name, params))
}

/// Returns a [`Resource<HypervisorKind>`] for the named backend, with
/// optional parameters.
///
/// The specifier format is `name` or `name:key=val,key,...`.
/// Each backend validates its own parameters — see the probe
/// implementations for supported keys.
pub fn hypervisor_resource(spec: &str) -> anyhow::Result<Resource<HypervisorKind>> {
    let (name, params) = parse_hypervisor_spec(spec)?;
    let probe = hypervisor_resources::probe_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("unknown hypervisor: {name}"))?;
    probe.new_resource(&params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Parse backend names, flags, empty values and values containing equals signs.
    // Expected: Names and values survive unchanged; bare flags become true.
    #[test]
    fn hypervisor_spec_preserves_parameters() {
        for spec in ["backend", "backend:", "backend:,,"] {
            assert_eq!(parse_hypervisor_spec(spec).unwrap(), ("backend", vec![]));
        }
        assert_eq!(
            parse_hypervisor_spec("backend:mode=2,debug,,empty=,chain=a=b,").unwrap(),
            (
                "backend",
                vec![
                    ("mode", "2"),
                    ("debug", "true"),
                    ("empty", ""),
                    ("chain", "a=b"),
                ],
            )
        );
    }

    // Test: Request malformed backend specs and a well-formed unknown backend.
    // Expected: Syntax errors retain the spec; unknown-backend errors identify its name.
    #[test]
    fn hypervisor_resource_rejects_invalid_specs() {
        for spec in ["", ":flag"] {
            assert_eq!(
                hypervisor_resource(spec).unwrap_err().to_string(),
                format!("empty hypervisor name in spec: {spec}")
            );
        }
        for spec in ["backend:=value", "backend:flag,=value"] {
            assert_eq!(
                hypervisor_resource(spec).unwrap_err().to_string(),
                format!("empty parameter key in spec: {spec}")
            );
        }
        assert_eq!(
            hypervisor_resource("not-a-registered-hypervisor:mode=2")
                .unwrap_err()
                .to_string(),
            "unknown hypervisor: not-a-registered-hypervisor"
        );
    }
}
