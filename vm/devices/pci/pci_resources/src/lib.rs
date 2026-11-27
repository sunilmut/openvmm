// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource definitions for PCI devices.

#![forbid(unsafe_code)]

use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device_resources::ErasedChipsetDevice;
use chipset_device_resources::ResolvedChipsetDevice;
use guestmem::DoorbellRegistration;
use guestmem::MemoryMapper;
use pci_core::dma::DmaTarget;
use std::sync::Arc;
use vm_resource::CanResolveTo;
use vm_resource::kind::PciDeviceHandleKind;
use vmcore::vm_task::VmTaskDriverSource;

impl CanResolveTo<ResolvedPciDevice> for PciDeviceHandleKind {
    type Input<'a> = ResolvePciDeviceHandleParams<'a>;
}

/// A resolved PCI device.
pub struct ResolvedPciDevice(pub ErasedChipsetDevice);

impl<T: Into<ResolvedChipsetDevice>> From<T> for ResolvedPciDevice {
    fn from(value: T) -> Self {
        Self(value.into().0)
    }
}

/// Parameters used when resolving a resource with kind [`PciDeviceHandleKind`].
pub struct ResolvePciDeviceHandleParams<'a> {
    /// DMA and MSI target for the device.
    pub dma_target: &'a DmaTarget,
    /// An object with which to register MMIO regions.
    pub register_mmio: &'a mut (dyn RegisterMmioIntercept + Send),
    /// The VM's task driver source.
    pub driver_source: &'a VmTaskDriverSource,
    /// An object with which to register doorbell regions.
    pub doorbell_registration: Option<Arc<dyn DoorbellRegistration>>,
    /// An object with which to register shared memory regions.
    pub shared_mem_mapper: Option<&'a dyn MemoryMapper>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chipset_device::ChipsetDevice;
    use chipset_device::io::IoError;
    use chipset_device::io::IoResult;
    use chipset_device::pci::ByteEnabledDwordRead;
    use chipset_device::pci::ByteEnabledDwordWrite;
    use chipset_device::pci::PciConfigSpace;
    use inspect::InspectMut;
    use test_with_tracing::test;
    use vmcore::device_state::ChangeDeviceState;
    use vmcore::save_restore::AsyncSaveRestore;
    use vmcore::save_restore::NoSavedState;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;

    #[derive(InspectMut)]
    struct IdentifiedPciDevice {
        #[inspect(skip)]
        vendor_device_id: u32,
    }

    impl ChipsetDevice for IdentifiedPciDevice {
        fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
            Some(self)
        }
    }

    impl PciConfigSpace for IdentifiedPciDevice {
        fn pci_cfg_read(&mut self, offset: u16, mut value: ByteEnabledDwordRead<'_>) -> IoResult {
            if offset != 0 {
                return IoResult::Err(IoError::InvalidRegister);
            }
            value.set(self.vendor_device_id);
            IoResult::Ok
        }

        fn pci_cfg_write(&mut self, _offset: u16, _value: ByteEnabledDwordWrite) -> IoResult {
            IoResult::Err(IoError::InvalidRegister)
        }
    }

    impl ChangeDeviceState for IdentifiedPciDevice {
        fn start(&mut self) {}
        async fn stop(&mut self) {}
        async fn reset(&mut self) {}
    }

    impl AsyncSaveRestore for IdentifiedPciDevice {
        type SavedState = NoSavedState;

        async fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            Ok(NoSavedState)
        }

        async fn restore(&mut self, _state: Self::SavedState) -> Result<(), RestoreError> {
            Ok(())
        }
    }

    // Test: Resolve concrete and already-erased devices with different PCI identities.
    // Expected: Each retains its PCI interface and returns its original identity.
    #[test]
    fn resource_conversion_preserves_original_pci_interface() {
        let concrete = ResolvedPciDevice::from(IdentifiedPciDevice {
            vendor_device_id: 0x1234_5678,
        });
        let erased = ResolvedPciDevice::from(ResolvedChipsetDevice::from(IdentifiedPciDevice {
            vendor_device_id: 0x8765_4321,
        }));
        for (mut resource, expected) in [(concrete, 0x1234_5678), (erased, 0x8765_4321)] {
            let pci = resource
                .0
                .supports_pci()
                .expect("the resolved device must retain its PCI interface");
            let mut identity = 0;
            assert!(matches!(
                pci.pci_cfg_read(
                    0,
                    ByteEnabledDwordRead::with_all_bytes_enabled(&mut identity)
                ),
                IoResult::Ok
            ));
            assert_eq!(identity, expected);
        }
    }
}
