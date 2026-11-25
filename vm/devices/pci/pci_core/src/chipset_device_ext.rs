// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extension trait to simplify probing PCI [`ChipsetDevice`] devices.

use crate::spec::hwid::ClassCode;
use crate::spec::hwid::HardwareIds;
use crate::spec::hwid::ProgrammingInterface;
use crate::spec::hwid::Subclass;
use chipset_device::ChipsetDevice;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigSpace;

/// An extension trait to simplify probing PCI [`ChipsetDevice`] devices.
pub trait PciChipsetDeviceExt: ChipsetDevice + PciConfigSpace {
    /// Probe the PCI device's BAR registers to retrieve the BAR masks.
    fn probe_bar_masks(&mut self) -> [u32; 6];

    /// Probe the PCI device's configuration space registers to obtain the
    /// device's hardware ID values.
    fn probe_hardware_ids(&mut self) -> HardwareIds;
}

impl<T: ?Sized> PciChipsetDeviceExt for T
where
    T: ChipsetDevice + PciConfigSpace,
{
    fn probe_bar_masks(&mut self) -> [u32; 6] {
        let mut masks = [0; 6];
        for (i, addr) in (0x10..=0x24).step_by(4).enumerate() {
            let mut buf_u32 = 0;
            let buf = ByteEnabledDwordRead::with_all_bytes_enabled(&mut buf_u32);
            let old = self
                .pci_cfg_read(addr, buf)
                .now_or_never()
                .map(|_| buf_u32)
                .unwrap_or(0);
            self.pci_cfg_write(addr, ByteEnabledDwordWrite::with_all_bytes_enabled(!0))
                .unwrap();
            let mut buf_u32 = 0;
            let buf = ByteEnabledDwordRead::with_all_bytes_enabled(&mut buf_u32);
            masks[i] = self
                .pci_cfg_read(addr, buf)
                .now_or_never()
                .map(|_| buf_u32)
                .unwrap_or(0);
            self.pci_cfg_write(addr, ByteEnabledDwordWrite::with_all_bytes_enabled(old))
                .unwrap();
        }
        masks
    }

    fn probe_hardware_ids(&mut self) -> HardwareIds {
        let mut p0 = 0;
        let mut p8 = 0;
        let mut p2c = 0;
        p0 = self
            .pci_cfg_read(0, ByteEnabledDwordRead::with_all_bytes_enabled(&mut p0))
            .now_or_never()
            .map(|_| p0)
            .unwrap_or(0);
        p8 = self
            .pci_cfg_read(8, ByteEnabledDwordRead::with_all_bytes_enabled(&mut p8))
            .now_or_never()
            .map(|_| p8)
            .unwrap_or(0);
        p2c = self
            .pci_cfg_read(0x2c, ByteEnabledDwordRead::with_all_bytes_enabled(&mut p2c))
            .now_or_never()
            .map(|_| p2c)
            .unwrap_or(0);
        HardwareIds {
            vendor_id: p0 as u16,
            device_id: (p0 >> 16) as u16,
            revision_id: p8 as u8,
            prog_if: ProgrammingInterface((p8 >> 8) as u8),
            sub_class: Subclass((p8 >> 16) as u8),
            base_class: ClassCode((p8 >> 24) as u8),
            type0_sub_vendor_id: p2c as u16,
            type0_sub_system_id: (p2c >> 16) as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chipset_device::io::{IoError, IoResult};
    use test_with_tracing::test;

    #[derive(Default)]
    struct ProbeDevice {
        registers: [u32; 12],
        masks: [u32; 6],
        accesses: Vec<(u16, Option<u32>)>,
        fail_reads: bool,
    }

    impl ChipsetDevice for ProbeDevice {}

    impl PciConfigSpace for ProbeDevice {
        fn pci_cfg_read(&mut self, offset: u16, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
            self.accesses.push((offset, None));
            if self.fail_reads {
                return IoResult::Err(IoError::NoResponse);
            }
            let register = self.registers[usize::from(offset / 4)];
            value.set(if (0x10..=0x24).contains(&offset) && register == u32::MAX {
                self.masks[usize::from((offset - 0x10) / 4)]
            } else {
                register
            });
            IoResult::Ok
        }

        fn pci_cfg_write(&mut self, offset: u16, value: ByteEnabledDwordWrite) -> IoResult {
            let register = &mut self.registers[usize::from(offset / 4)];
            value.merge_into(register);
            self.accesses.push((offset, Some(*register)));
            IoResult::Ok
        }
    }

    // Test: Probe mixed implemented/unimplemented BARs on a recording config-space device.
    // Expected: Masks match the device, and each original BAR is restored in probe order.
    #[test]
    fn bar_probe_returns_masks_and_restores_every_register() {
        let originals = [0x80000000, 0x90000004, 1, 0, 0xa0000000, 0];
        let masks = [0xfffff000, 0xffffe004, u32::MAX, 0, 0xffff0000, 0];
        let mut device = ProbeDevice {
            masks,
            ..Default::default()
        };
        device.registers[4..10].copy_from_slice(&originals);
        let before = device.registers;
        assert_eq!(device.probe_bar_masks(), masks);
        assert_eq!(device.registers, before);
        let expected: Vec<_> = originals
            .into_iter()
            .enumerate()
            .flat_map(|(index, original)| {
                let offset = 0x10 + index as u16 * 4;
                [
                    (offset, None),
                    (offset, Some(u32::MAX)),
                    (offset, None),
                    (offset, Some(original)),
                ]
            })
            .collect();
        assert_eq!(device.accesses, expected);
    }

    // Test: Probe hardware IDs with distinct values in every encoded byte and word.
    // Expected: All eight ID fields decode correctly without writes to configuration space.
    #[test]
    fn hardware_id_probe_decodes_all_fields_without_writes() {
        let mut device = ProbeDevice::default();
        device.registers[0] = 0x9abc1234;
        device.registers[2] = 0x02030405;
        device.registers[11] = 0xdef05678;
        let ids = device.probe_hardware_ids();
        assert_eq!(
            (ids.vendor_id, ids.device_id, ids.revision_id),
            (0x1234, 0x9abc, 5)
        );
        assert_eq!(
            (ids.prog_if.0, ids.sub_class.0, ids.base_class.0),
            (4, 3, 2)
        );
        assert_eq!(
            (ids.type0_sub_vendor_id, ids.type0_sub_system_id),
            (0x5678, 0xdef0)
        );
        assert_eq!(device.accesses, [(0, None), (8, None), (0x2c, None)]);
    }

    // Test: Probe a device that returns NoResponse for every configuration read.
    // Expected: Failed reads produce zero masks and zero hardware IDs rather than stale data.
    #[test]
    fn probe_read_errors_use_zero_fallbacks() {
        let mut device = ProbeDevice {
            fail_reads: true,
            ..Default::default()
        };
        assert_eq!(device.probe_bar_masks(), [0; 6]);
        let ids = device.probe_hardware_ids();
        assert_eq!((ids.vendor_id, ids.device_id, ids.revision_id), (0, 0, 0));
        assert_eq!(
            (ids.prog_if.0, ids.sub_class.0, ids.base_class.0),
            (0, 0, 0)
        );
        assert_eq!((ids.type0_sub_vendor_id, ids.type0_sub_system_id), (0, 0));
    }
}
