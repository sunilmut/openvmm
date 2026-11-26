// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource definitions for chipset devices.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use chipset_device::ChipsetDevice;
use guestmem::GuestMemory;
use inspect::InspectMut;
use std::ops::RangeInclusive;
use vm_resource::CanResolveTo;
use vm_resource::kind::ChipsetDeviceHandleKind;
use vmcore::device_state::ChangeDeviceState;
use vmcore::line_interrupt::LineInterrupt;
use vmcore::save_restore::AsyncProtobufSaveRestore;
use vmcore::vm_task::VmTaskDriverSource;
use vmcore::vmtime::VmTimeSource;

/// A unique identifier for a line set.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineSetId(&'static str);

impl LineSetId {
    /// Returns the name of the line set.
    pub fn name(&self) -> &str {
        self.0
    }
}

/// Line set for device interrupts connected to the platform interrupt
/// controller.
pub const IRQ_LINE_SET: LineSetId = LineSetId("irq");
/// Line set for ACPI general purpose events.
pub const GPE0_LINE_SET: LineSetId = LineSetId("gpe0");
/// Line set for the BSP's local interrupts (LINT0/1) on x86.
pub const BSP_LINT_LINE_SET: LineSetId = LineSetId("bsp_lint");

impl CanResolveTo<ResolvedChipsetDevice> for ChipsetDeviceHandleKind {
    type Input<'a> = ResolveChipsetDeviceHandleParams<'a>;
}

/// Parameters used when resolving a resource with kind
/// [`ChipsetDeviceHandleKind`].
pub struct ResolveChipsetDeviceHandleParams<'a> {
    /// The name of the device.
    pub device_name: &'a str,
    /// Guest memory for device DMA operations for untrusted devices.
    pub guest_memory: &'a GuestMemory,
    /// Guest memory for device DMA operations for trusted devices, which can
    /// access encrypted memory on CVMs.
    ///
    /// For non-CVMs, this is the same as `guest_memory`.
    pub encrypted_guest_memory: &'a GuestMemory,
    /// The VM time source.
    pub vmtime: &'a VmTimeSource,
    /// Whether the VM is restoring from a saved state.
    ///
    /// FUTURE: remove this once devices have a state transition for "first
    /// boot". Device authors: try to avoid taking a dependency on this. If
    /// possible, delay any "first boot" initialization until it's really
    /// needed.
    pub is_restoring: bool,
    /// An object to confiure the chipset device's connection to the platform.
    pub configure: &'a mut dyn ConfigureChipsetDevice,
    /// The task driver source for the VM.
    pub task_driver_source: &'a VmTaskDriverSource,
    /// Object to register for MMIO intercepts.
    pub register_mmio: &'a mut (dyn chipset_device::mmio::RegisterMmioIntercept + Send),
    /// Object to register for PIO intercepts.
    pub register_pio: &'a mut (dyn chipset_device::pio::RegisterPortIoIntercept + Send),
}

/// A trait for configuring a chipset device's connection to the platform.
pub trait ConfigureChipsetDevice: Send {
    /// Creates a new line interrupt.
    fn new_line(&mut self, id: LineSetId, name: &str, vector: u32) -> LineInterrupt;

    /// Adds this device as a target for a range of line interrupts.
    fn add_line_target(
        &mut self,
        id: LineSetId,
        source_range: RangeInclusive<u32>,
        target_start: u32,
    );

    /// Tags this device so that its save/restore routines will not be called.
    fn omit_saved_state(&mut self);
}

#[async_trait]
trait DynChipsetDevice: ChipsetDevice + AsyncProtobufSaveRestore + InspectMut {
    fn start(&mut self);
    async fn stop(&mut self);
    async fn reset(&mut self);
    async fn teardown(self: Box<Self>);
}

#[async_trait]
impl<T: ChangeDeviceState + ChipsetDevice + AsyncProtobufSaveRestore + InspectMut> DynChipsetDevice
    for T
{
    fn start(&mut self) {
        self.start()
    }
    async fn stop(&mut self) {
        self.stop().await
    }
    async fn reset(&mut self) {
        self.reset().await
    }
    async fn teardown(self: Box<Self>) {
        (*self).teardown().await
    }
}

/// A resolved chipset device resource.
pub struct ResolvedChipsetDevice(pub ErasedChipsetDevice);

/// A type-erased [`ChipsetDevice`].
#[derive(InspectMut)]
#[inspect(transparent(mut))]
pub struct ErasedChipsetDevice(Box<dyn DynChipsetDevice>);

impl<T: ChangeDeviceState + ChipsetDevice + AsyncProtobufSaveRestore + InspectMut> From<T>
    for ResolvedChipsetDevice
{
    fn from(value: T) -> Self {
        Self(ErasedChipsetDevice(Box::new(value)))
    }
}

impl ChangeDeviceState for ErasedChipsetDevice {
    fn start(&mut self) {
        self.0.start()
    }

    async fn stop(&mut self) {
        self.0.stop().await
    }

    async fn reset(&mut self) {
        self.0.reset().await
    }

    async fn teardown(self) {
        self.0.teardown().await
    }
}

impl ChipsetDevice for ErasedChipsetDevice {
    fn supports_pio(&mut self) -> Option<&mut dyn chipset_device::pio::PortIoIntercept> {
        self.0.supports_pio()
    }

    fn supports_mmio(&mut self) -> Option<&mut dyn chipset_device::mmio::MmioIntercept> {
        self.0.supports_mmio()
    }

    fn supports_pci(&mut self) -> Option<&mut dyn chipset_device::pci::PciConfigSpace> {
        self.0.supports_pci()
    }

    fn supports_poll_device(&mut self) -> Option<&mut dyn chipset_device::poll_device::PollDevice> {
        self.0.supports_poll_device()
    }

    fn supports_line_interrupt_target(
        &mut self,
    ) -> Option<&mut dyn chipset_device::interrupt::LineInterruptTarget> {
        self.0.supports_line_interrupt_target()
    }

    fn supports_handle_eoi(&mut self) -> Option<&mut dyn chipset_device::interrupt::HandleEoi> {
        self.0.supports_handle_eoi()
    }

    fn supports_acknowledge_pic_interrupt(
        &mut self,
    ) -> Option<&mut dyn chipset_device::interrupt::AcknowledgePicInterrupt> {
        self.0.supports_acknowledge_pic_interrupt()
    }

    fn supports_tdisp_host(&mut self) -> Option<&mut dyn tdisp::TdispHostDeviceTarget> {
        self.0.supports_tdisp_host()
    }

    fn supports_tdisp_relay(&mut self) -> Option<&mut dyn tdisp::TdispRelayedDeviceTarget> {
        self.0.supports_tdisp_relay()
    }
}

#[async_trait]
impl AsyncProtobufSaveRestore for ErasedChipsetDevice {
    async fn save(
        &mut self,
    ) -> Result<vmcore::save_restore::SavedStateBlob, vmcore::save_restore::SaveError> {
        self.0.save().await
    }

    async fn restore(
        &mut self,
        state: vmcore::save_restore::SavedStateBlob,
    ) -> Result<(), vmcore::save_restore::RestoreError> {
        self.0.restore(state).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use test_with_tracing::test;
    use vmcore::save_restore::{AsyncSaveRestore, NoSavedState, RestoreError, SaveError};

    #[derive(InspectMut)]
    struct Device {
        #[inspect(skip)]
        events: Arc<Mutex<Vec<&'static str>>>,
        #[inspect(skip)]
        mmio_enabled: bool,
        #[inspect(skip)]
        fail_save: bool,
        #[inspect(skip)]
        fail_restore: bool,
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.events.lock().push("drop");
        }
    }

    impl ChipsetDevice for Device {
        fn supports_mmio(&mut self) -> Option<&mut dyn chipset_device::mmio::MmioIntercept> {
            self.mmio_enabled.then_some(self)
        }
    }

    impl chipset_device::mmio::MmioIntercept for Device {
        fn mmio_read(&mut self, addr: u64, data: &mut [u8]) -> chipset_device::io::IoResult {
            assert_eq!(addr, 0x1003);
            data.copy_from_slice(&[0x81, 0x00, 0xff, 0x27]);
            self.events.lock().push("mmio_read");
            chipset_device::io::IoResult::Ok
        }

        fn mmio_write(&mut self, addr: u64, data: &[u8]) -> chipset_device::io::IoResult {
            assert_eq!(addr, 0x1004);
            assert_eq!(data, &[0xab, 0x00, 0xcd]);
            self.events.lock().push("mmio_write");
            chipset_device::io::IoResult::Ok
        }
    }

    impl ChangeDeviceState for Device {
        fn start(&mut self) {
            self.events.lock().push("start");
        }

        async fn stop(&mut self) {
            self.events.lock().push("stop");
        }

        async fn reset(&mut self) {
            self.events.lock().push("reset");
        }

        async fn teardown(self) {
            self.events.lock().push("teardown");
        }
    }

    impl AsyncSaveRestore for Device {
        type SavedState = NoSavedState;

        async fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            self.events.lock().push("save");
            if self.fail_save {
                Err(SaveError::NotSupported)
            } else {
                Ok(NoSavedState)
            }
        }

        async fn restore(&mut self, _: Self::SavedState) -> Result<(), RestoreError> {
            self.events.lock().push("restore");
            if self.fail_restore {
                Err(RestoreError::SavedStateNotSupported)
            } else {
                Ok(())
            }
        }
    }

    // Test: Drive the concrete device lifecycle through the resolved type-erased resource.
    // Expected: The original device receives ordered start, stop, reset and teardown, and is dropped before teardown completes.
    #[test]
    fn erased_lifecycle_preserves_terminal_cleanup() {
        pal_async::local::block_on(async {
            let events = Arc::new(Mutex::new(Vec::new()));
            let ResolvedChipsetDevice(mut device) = Device {
                events: events.clone(),
                mmio_enabled: false,
                fail_save: false,
                fail_restore: false,
            }
            .into();
            ChangeDeviceState::start(&mut device);
            assert_eq!(*events.lock(), ["start"]);
            ChangeDeviceState::stop(&mut device).await;
            ChangeDeviceState::reset(&mut device).await;
            assert_eq!(*events.lock(), ["start", "stop", "reset"]);
            ChangeDeviceState::teardown(device).await;
            assert_eq!(
                *events.lock(),
                ["start", "stop", "reset", "teardown", "drop"]
            );
        });
    }

    // Test: Save and restore an erased device, then exercise concrete save/restore rejection results.
    // Expected: The saved blob retains its concrete type, both operations reach the device, and typed errors propagate unchanged.
    #[test]
    fn erased_save_restore_preserves_blob_type_and_errors() {
        pal_async::local::block_on(async {
            for fail in [false, true] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let ResolvedChipsetDevice(mut device) = Device {
                    events: events.clone(),
                    mmio_enabled: false,
                    fail_save: fail,
                    fail_restore: fail,
                }
                .into();
                let result = AsyncProtobufSaveRestore::save(&mut device).await;
                if fail {
                    assert!(matches!(result, Err(SaveError::NotSupported)));
                } else {
                    result.unwrap().parse::<NoSavedState>().unwrap();
                }
                let result = AsyncProtobufSaveRestore::restore(
                    &mut device,
                    vmcore::save_restore::SavedStateBlob::new(NoSavedState),
                )
                .await;
                if fail {
                    assert!(matches!(result, Err(RestoreError::SavedStateNotSupported)));
                } else {
                    result.unwrap();
                }
                assert_eq!(*events.lock(), ["save", "restore"]);
            }
        });
    }

    // Test: Query unsupported capabilities and perform MMIO through an enabled erased endpoint.
    // Expected: Absent interfaces stay absent; enabled MMIO retains exact addresses, binary payloads and surrounding buffer guards.
    #[test]
    fn erased_capabilities_preserve_absence_and_mmio_payloads() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let ResolvedChipsetDevice(mut absent) = Device {
            events: events.clone(),
            mmio_enabled: false,
            fail_save: false,
            fail_restore: false,
        }
        .into();
        assert!(absent.supports_pio().is_none());
        assert!(absent.supports_mmio().is_none());
        assert!(absent.supports_pci().is_none());
        assert!(absent.supports_poll_device().is_none());
        assert!(absent.supports_line_interrupt_target().is_none());
        assert!(absent.supports_handle_eoi().is_none());
        assert!(absent.supports_acknowledge_pic_interrupt().is_none());
        assert!(absent.supports_tdisp_host().is_none());
        assert!(absent.supports_tdisp_relay().is_none());
        let ResolvedChipsetDevice(mut enabled) = Device {
            events: events.clone(),
            mmio_enabled: true,
            fail_save: false,
            fail_restore: false,
        }
        .into();
        let endpoint = enabled.supports_mmio().unwrap();
        let mut bytes = [0xcc; 6];
        assert!(matches!(
            endpoint.mmio_read(0x1003, &mut bytes[1..5]),
            chipset_device::io::IoResult::Ok
        ));
        assert_eq!(bytes, [0xcc, 0x81, 0x00, 0xff, 0x27, 0xcc]);
        assert!(matches!(
            endpoint.mmio_write(0x1004, &[0xab, 0x00, 0xcd]),
            chipset_device::io::IoResult::Ok
        ));
        assert_eq!(*events.lock(), ["mmio_read", "mmio_write"]);
    }

    // Test: Use cloned IRQ/GPE/BSP-LINT identifiers as ordered routing-map keys.
    // Expected: Stable platform names select independent targets and cloned identifiers address the original entries.
    #[test]
    fn platform_line_sets_remain_distinct_routing_keys() {
        let routes = std::collections::BTreeMap::from([
            (IRQ_LINE_SET, 42),
            (GPE0_LINE_SET, 43),
            (BSP_LINT_LINE_SET, 44),
        ]);
        assert_eq!(routes[&IRQ_LINE_SET.clone()], 42);
        assert_eq!(routes[&GPE0_LINE_SET.clone()], 43);
        assert_eq!(routes[&BSP_LINT_LINE_SET.clone()], 44);
        assert_eq!(
            routes
                .iter()
                .map(|(id, target)| (id.name(), *target))
                .collect::<Vec<_>>(),
            [("bsp_lint", 44), ("gpe0", 43), ("irq", 42)]
        );
    }
}
