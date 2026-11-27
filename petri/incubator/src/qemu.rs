// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! QEMU device provisioning.

use crate::profile::DeviceConfig;
use crate::profile::parse_size;
use anyhow::Context;
use std::collections::BTreeMap;

/// First PCI device number (`addr=`) used for extra-device root ports.
///
/// QEMU's built-in devices use low device numbers. We start at 16 (0x10)
/// to avoid collisions. The root port for the i-th extra device has
/// devfn = `(EXTRA_DEVICE_ADDR_BASE + i) << 3`.
const EXTRA_DEVICE_ADDR_BASE: usize = petri::qemu::EXTRA_DEVICE_ADDR_BASE;

pub(crate) fn petri_devices(
    devices: &[DeviceConfig],
) -> anyhow::Result<Vec<petri::qemu::devices::DeviceConfig>> {
    use petri::qemu::devices as p;
    devices
        .iter()
        .map(|device| {
            Ok(match device {
                DeviceConfig::VirtioBlk(c) => {
                    p::DeviceConfig::VirtioBlk(p::VirtioBlkDeviceConfig {
                        name: c.name.clone(),
                        size: parse_size(&c.size)?,
                        vfio: c.vfio,
                    })
                }
                DeviceConfig::Edu(c) => p::DeviceConfig::Edu(p::EduDeviceConfig {
                    name: c.name.clone(),
                    dma_mask: c
                        .dma_mask
                        .as_deref()
                        .map(|value| {
                            if let Some(hex) = value.strip_prefix("0x") {
                                u64::from_str_radix(hex, 16)
                            } else {
                                value.parse()
                            }
                            .context("invalid DMA mask")
                        })
                        .transpose()?,
                    vfio: c.vfio,
                }),
                DeviceConfig::IvshmemPlain(c) => {
                    p::DeviceConfig::IvshmemPlain(p::IvshmemPlainDeviceConfig {
                        name: c.name.clone(),
                        size: parse_size(&c.size)?,
                        vfio: c.vfio,
                    })
                }
            })
        })
        .collect()
}

/// Set up VFIO devices inside the incubator.
///
/// Each extra device in the profile sits behind its own PCIe root port
/// at a known PCI device number (see [`EXTRA_DEVICE_ADDR_BASE`]). This
/// function discovers the child device's BDF by finding the bridge at
/// that slot in sysfs, then unbinds the child from its driver and binds
/// it to vfio-pci.
///
/// Returns a map of environment variables to set for the guest command,
/// e.g., `INCUBATOR_VFIO_BDF_TEST_DISK=0000:01:00.0`. If any provisioned
/// device declares a `provides` capability, the returned map also includes
/// `PETRI_CAPABILITIES` listing those capabilities (comma-separated).
pub async fn setup_vfio_devices(
    client: &pipette_client::PipetteClient,
    devices: &[DeviceConfig],
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    let mut capabilities = Vec::new();

    // Collect (device_index, device) for devices that need VFIO binding.
    // VFIO binding is device-type-agnostic: any extra device behind its own
    // root port can be unbound from its driver and rebound to vfio-pci.
    let vfio_devices: Vec<_> = devices
        .iter()
        .enumerate()
        .filter(|(_, d)| d.vfio())
        .collect();

    if vfio_devices.is_empty() {
        return Ok(env);
    }

    tracing::info!("setting up {} VFIO device(s)", vfio_devices.len());

    for (device_index, device) in &vfio_devices {
        let name = device.name();
        let addr = EXTRA_DEVICE_ADDR_BASE + device_index;

        // The root port for this device is deterministically at
        // 0000:00:{addr:02x}.0 (see `build_qemu_command`). Read its
        // secondary bus number from sysfs; the assigned device sits at
        // slot 0, function 0 of that bus.
        let rp_bdf = format!("0000:00:{addr:02x}.0");
        let secondary_bus_path = format!("/sys/bus/pci/devices/{rp_bdf}/secondary_bus_number");
        let secondary_bus_raw = client
            .read_file(&secondary_bus_path)
            .await
            .with_context(|| {
                format!(
                    "failed to read secondary bus number for device '{name}' (root port {rp_bdf})"
                )
            })?;
        // sysfs reports the secondary bus number in decimal.
        let secondary_bus_str = String::from_utf8_lossy(&secondary_bus_raw);
        let secondary_bus: u8 = secondary_bus_str.trim().parse().with_context(|| {
            format!("unexpected secondary bus number {secondary_bus_str:?} for device '{name}'")
        })?;
        let bdf = format!("0000:{secondary_bus:02x}:00.0");

        // Confirm the child device actually exists before trying to rebind it.
        client
            .read_file(format!("/sys/bus/pci/devices/{bdf}/vendor"))
            .await
            .with_context(|| {
                format!(
                    "no device found behind root port {rp_bdf} (expected {bdf}) for device '{name}'"
                )
            })?;

        tracing::info!(%name, %bdf, %addr, "binding device to vfio-pci");

        // Unbind from current driver
        let _ = client
            .write_file(
                format!("/sys/bus/pci/devices/{bdf}/driver/unbind"),
                bdf.as_bytes(),
            )
            .await;

        // Set driver override to vfio-pci
        client
            .write_file(
                format!("/sys/bus/pci/devices/{bdf}/driver_override"),
                b"vfio-pci".as_slice(),
            )
            .await
            .context("failed to set driver_override")?;

        // Bind to vfio-pci
        client
            .write_file("/sys/bus/pci/drivers/vfio-pci/bind", bdf.as_bytes())
            .await
            .context("failed to bind to vfio-pci")?;

        // Export env var: name "test-disk" → INCUBATOR_VFIO_BDF_TEST_DISK
        let env_name = format!(
            "INCUBATOR_VFIO_BDF_{}",
            name.to_uppercase().replace('-', "_")
        );
        tracing::info!(%env_name, %bdf, "VFIO device ready");
        env.insert(env_name, bdf);

        // Advertise the capability this device provides (derived from its
        // name), now that it has been successfully provisioned. Tests gate on
        // this via `requires(...)`.
        capabilities.push(device.capability());
    }

    // Advertise all provisioned capabilities to the guest command via
    // PETRI_CAPABILITIES (comma-separated), which petri's requirement
    // evaluation reads. Augment any capabilities already present in the
    // incubator's environment rather than overwriting them, so that
    // host-provided capabilities are preserved.
    if !capabilities.is_empty() {
        let mut value = capabilities.join(",");
        if let Ok(existing) = std::env::var("PETRI_CAPABILITIES") {
            if !existing.is_empty() {
                value = format!("{existing},{value}");
            }
        }
        env.insert("PETRI_CAPABILITIES".to_string(), value);
    }

    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::EduDeviceConfig;
    use crate::profile::IvshmemPlainDeviceConfig;
    use crate::profile::VirtioBlkDeviceConfig;
    use test_with_tracing::test;

    fn edu(dma_mask: Option<&str>) -> DeviceConfig {
        DeviceConfig::Edu(EduDeviceConfig {
            name: "edu-initiator".into(),
            dma_mask: dma_mask.map(Into::into),
            vfio: true,
        })
    }

    // Test: Convert one device of each kind, including hex, decimal and absent
    //       edu DMA masks, into petri device configurations.
    // Expected: Order, names, VFIO flags and parsed sizes are preserved, and
    //       both DMA mask notations decode to the same value.
    #[test]
    fn devices_convert_in_order_with_parsed_sizes_and_masks() {
        use petri::qemu::devices as p;
        let devices = [
            DeviceConfig::VirtioBlk(VirtioBlkDeviceConfig {
                name: "disk".into(),
                size: "64M".into(),
                vfio: false,
            }),
            edu(Some("0xffffffffffff")),
            edu(Some("281474976710655")),
            edu(None),
            DeviceConfig::IvshmemPlain(IvshmemPlainDeviceConfig {
                name: "shm".into(),
                size: "4MB".into(),
                vfio: true,
            }),
        ];
        let converted = petri_devices(&devices).unwrap();
        assert_eq!(converted.len(), 5);
        match &converted[0] {
            p::DeviceConfig::VirtioBlk(c) => {
                assert_eq!((c.name.as_str(), c.size, c.vfio), ("disk", 64 << 20, false))
            }
            _ => panic!("wrong kind"),
        }
        for (i, mask) in [
            (1, Some(0xffff_ffff_ffff)),
            (2, Some(0xffff_ffff_ffff)),
            (3, None),
        ] {
            match &converted[i] {
                p::DeviceConfig::Edu(c) => assert_eq!(
                    (c.name.as_str(), c.dma_mask, c.vfio),
                    ("edu-initiator", mask, true)
                ),
                _ => panic!("wrong kind"),
            }
        }
        match &converted[4] {
            p::DeviceConfig::IvshmemPlain(c) => assert_eq!((c.size, c.vfio), (4 << 20, true)),
            _ => panic!("wrong kind"),
        }
    }

    // Test: Convert devices with malformed DMA masks or sizes.
    // Expected: The whole conversion fails with the specific field error rather
    //       than dropping or defaulting the bad device.
    #[test]
    fn invalid_device_fields_fail_conversion() {
        for mask in ["0xg", "0x", "-1", "ff"] {
            let error = petri_devices(&[edu(Some(mask))]).unwrap_err();
            assert_eq!(format!("{error}"), "invalid DMA mask", "{mask}");
        }
        let error = petri_devices(&[DeviceConfig::VirtioBlk(VirtioBlkDeviceConfig {
            name: "disk".into(),
            size: "64Q".into(),
            vfio: false,
        })])
        .unwrap_err();
        assert_eq!(format!("{error}"), "invalid size '64Q'");
    }
}
