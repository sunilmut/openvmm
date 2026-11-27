// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(not(target_os = "linux"), expect(missing_docs))]
#![cfg(target_os = "linux")]

//! The [`vm_resource`] resources and [`mesh_worker`] workers that are available
//! in OpenVMM-HCL.

#![forbid(unsafe_code)]

// Resources.
#[cfg(guest_arch = "x86_64")]
vm_resource::register_static_resolvers! {
    // Chipset devices
    chipset::i8042::resolver::I8042Resolver,
    chipset_legacy::piix4_uhci::resolver::Piix4PciUsbUhciStubResolver,
    chipset_legacy::piix4_pci_isa_bridge::resolver::Piix4PciIsaBridgeResolver,
    chipset::dma::resolver::GenericIsaDmaResolver,
    chipset_legacy::piix4_pm::resolver::Piix4PowerManagementResolver,
    chipset_legacy::i440bx_host_pci_bridge::resolver::I440BxHostPciBridgeResolver,
    chipset::pit::resolver::PitResolver,
    chipset::pic::resolver::PicResolver,
    chipset::ioapic::resolver::GenericIoApicResolver,
    chipset::pm::resolver::HyperVPowerManagementResolver,
    serial_16550::resolver::Serial16550Resolver,
}

vm_resource::register_static_resolvers! {
    // Chipset devices
    chipset_resources::cmos_rtc_time_source::SystemTimeClockResolver,
    firmware_uefi::resolver::UefiDeviceResolver,
    missing_dev::resolver::MissingDevResolver,
    #[cfg(feature = "tpm")]
    tpm_device::resolver::TpmDeviceResolver,
    #[cfg(guest_arch = "aarch64")]
    serial_pl011::resolver::SerialPl011Resolver,
    chipset::battery::resolver::BatteryResolver,
    guest_watchdog::resolver::HyperVGuestWatchdogResolver,
    ipmi_kcs::resolver::IpmiKcsResolver,

    // Non-volatile stores
    vmcore::non_volatile_store::resources::EphemeralNonVolatileStoreResolver,
    vmgs_broker::resolver::VmgsFileResolver,

    // Serial ports
    serial_core::disconnected::resolver::DisconnectedSerialBackendResolver,
    serial_core::null::resolver::NullSerialBackendResolver,
    vmbus_serial_guest::VmbusSerialGuestResolver,

    // Disks.
    //
    // `BlockDevice` and `NvmeDisk` are registered dynamically since they have
    // runtime dependencies.
    disk_striped::StripedDiskResolver,

    // SCSI
    scsidisk::resolver::SimpleScsiResolver,

    // Vmbus devices
    hyperv_ic::resolver::ShutdownIcResolver,
    storvsp::resolver::StorvspResolver,
    storvsp::resolver::StorvspIdeResolver,
    #[cfg(feature = "uidevices")]
    uidevices::resolver::VmbusUiResolver,

    // VPCI devices
    #[cfg(feature = "nvme")]
    nvme::resolver::NvmeControllerResolver,
}

// Mesh workers.
mesh_worker::register_workers! {
    #[cfg(feature = "vnc_worker")]
    vnc_worker::VncWorker<vmsocket::VmListener>,
    #[cfg(feature = "debug_worker")]
    debug_worker::DebuggerWorker<vmsocket::VmListener>,
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;
    use vm_resource::{IntoResource, ResourceResolver};
    use vmcore::non_volatile_store::resources::EphemeralNonVolatileStoreHandle;

    // Test: Resolve stores through the linked OpenHCL resource catalog, without
    //       adding any resolvers dynamically.
    // Expected: The catalog supplies functional, independent stores and
    //       distinguishes unwritten storage from an explicitly empty value.
    #[test]
    fn linked_catalog_resolves_independent_stores() {
        futures::executor::block_on(async {
            let resolver = ResourceResolver::new();
            let mut first = resolver
                .resolve(EphemeralNonVolatileStoreHandle.into_resource(), &())
                .await
                .unwrap()
                .0;
            let mut second = resolver
                .resolve(EphemeralNonVolatileStoreHandle.into_resource(), &())
                .await
                .unwrap()
                .0;
            assert_eq!(first.restore().await.unwrap(), None);
            first.persist(vec![0, 255, 42]).await.unwrap();
            assert_eq!(second.restore().await.unwrap(), None);
            second.persist(vec![]).await.unwrap();
            assert_eq!(second.restore().await.unwrap(), Some(vec![]));
            assert_eq!(first.restore().await.unwrap(), Some(vec![0, 255, 42]));
        });
    }
}
