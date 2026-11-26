// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exports [`MissingDev`]: a "no-op" device that silently swallows all MMIO,
//! PIO, and PCI accesses that come its way.
//!
//! Useful for claiming known-unimplemented machine resources, in order to cut
//! down on missing-device logging.

#![forbid(unsafe_code)]

use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::ControlMmioIntercept;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigSpace;
use chipset_device::pio::ControlPortIoIntercept;
use chipset_device::pio::PortIoIntercept;
use chipset_device::pio::RegisterPortIoIntercept;
use inspect::Inspect;
use inspect::InspectMut;
use pci_core::spec::hwid::ProgrammingInterface;
use std::ops::RangeInclusive;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;

#[derive(Default, Inspect)]
struct MissingDevPciMetadata {
    #[inspect(debug)]
    bdf: (u8, u8, u8),
    #[inspect(hex)]
    vendor_id: u16,
    #[inspect(hex)]
    device_id: u16,
}

/// A device that swallows all MMIO, PIO, and PCI accesses that come its way.
#[derive(Default, InspectMut)]
pub struct MissingDev {
    #[inspect(with = "inspect_helpers::io_ranges")]
    pio: Vec<(Box<str>, RangeInclusive<u16>)>,
    #[inspect(with = "inspect_helpers::io_ranges")]
    mmio: Vec<(Box<str>, RangeInclusive<u64>)>,
    pci: Option<MissingDevPciMetadata>,

    #[inspect(skip)]
    _mmio_control: Box<[Box<dyn ControlMmioIntercept>]>,
    #[inspect(skip)]
    _pio_control: Box<[Box<dyn ControlPortIoIntercept>]>,
}

impl MissingDev {
    /// Convert a [`MissingDevManifest`] into a fully instantiated
    /// [`MissingDev`].
    pub fn from_manifest(
        manifest: MissingDevManifest,
        register_mmio: &mut dyn RegisterMmioIntercept,
        register_pio: &mut dyn RegisterPortIoIntercept,
    ) -> MissingDev {
        let MissingDevManifest { pio, mmio, pci } = manifest;

        let pio_control = pio
            .iter()
            .map(|(name, range)| {
                let mut control = register_pio.new_io_region(name, range.end() - range.start() + 1);
                control.map(*range.start());
                control
            })
            .collect();

        let mmio_control = mmio
            .iter()
            .map(|(name, range)| {
                let mut control =
                    register_mmio.new_io_region(name, range.end() - range.start() + 1);
                control.map(*range.start());
                control
            })
            .collect();

        MissingDev {
            pio,
            mmio,
            pci,

            _pio_control: pio_control,
            _mmio_control: mmio_control,
        }
    }
}

mod inspect_helpers {
    use super::*;

    pub(crate) fn io_ranges<T>(ranges: &[(Box<str>, RangeInclusive<T>)]) -> impl Inspect + '_
    where
        T: std::fmt::LowerHex,
    {
        inspect::adhoc(|req| {
            let mut res = req.respond();
            for (label, range) in ranges.iter() {
                let width = size_of::<T>() * 2 + 2;
                res.field(
                    &format!("{:#0width$x}-{:#0width$x}", range.start(), range.end()),
                    label,
                );
            }
        })
    }
}

impl ChangeDeviceState for MissingDev {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl ChipsetDevice for MissingDev {
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        Some(self)
    }

    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }

    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        // this is technically IDET abuse...
        if self.pci.is_some() { Some(self) } else { None }
    }
}

impl SaveRestore for MissingDev {
    // This device should be constructed with `omit_saved_state`.
    type SavedState = SavedStateNotSupported;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Err(SaveError::NotSupported)
    }

    fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
        match state {}
    }
}

impl MmioIntercept for MissingDev {
    fn mmio_read(&mut self, _addr: u64, data: &mut [u8]) -> IoResult {
        data.fill(!0);
        IoResult::Ok
    }

    fn mmio_write(&mut self, _addr: u64, _data: &[u8]) -> IoResult {
        IoResult::Ok
    }
}

impl PortIoIntercept for MissingDev {
    fn io_read(&mut self, _addr: u16, data: &mut [u8]) -> IoResult {
        data.fill(!0);
        IoResult::Ok
    }

    fn io_write(&mut self, _addr: u16, _data: &[u8]) -> IoResult {
        IoResult::Ok
    }
}

impl PciConfigSpace for MissingDev {
    fn pci_cfg_read(&mut self, offset: u16, value: ByteEnabledDwordRead<'_>) -> IoResult {
        let pci = self.pci.as_ref().unwrap();

        pci_core::cfg_space_emu::ConfigSpaceType0Emulator::new(
            pci_core::spec::hwid::HardwareIds {
                vendor_id: pci.vendor_id,
                device_id: pci.device_id,
                revision_id: 0,
                prog_if: ProgrammingInterface::NONE,
                sub_class: pci_core::spec::hwid::Subclass::NONE,
                base_class: pci_core::spec::hwid::ClassCode::UNCLASSIFIED,
                type0_sub_vendor_id: 0,
                type0_sub_system_id: 0,
            },
            vec![],
            vec![],
            pci_core::cfg_space_emu::DeviceBars::new(),
        )
        .read_byte_enabled(offset, value)
    }

    fn pci_cfg_write(&mut self, _offset: u16, _value: ByteEnabledDwordWrite) -> IoResult {
        IoResult::Ok
    }

    fn suggested_bdf(&mut self) -> Option<(u8, u8, u8)> {
        let pci = self.pci.as_ref().unwrap();
        Some(pci.bdf)
    }
}

/// A [`MissingDev`] builder.
#[derive(Default)]
pub struct MissingDevManifest {
    pio: Vec<(Box<str>, RangeInclusive<u16>)>,
    mmio: Vec<(Box<str>, RangeInclusive<u64>)>,
    pci: Option<MissingDevPciMetadata>,
}

impl MissingDevManifest {
    /// Create a new [`MissingDevManifest`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Claim the specified Port IO region.
    pub fn claim_pio(mut self, region_name: &str, range: RangeInclusive<u16>) -> Self {
        self.pio.push((region_name.into(), range));
        self
    }

    /// Claim the specified MMIO region.
    pub fn claim_mmio(mut self, region_name: &str, range: RangeInclusive<u64>) -> Self {
        self.mmio.push((region_name.into(), range));
        self
    }

    /// Claim the specified PCI slot.
    pub fn claim_pci(mut self, bdf: (u8, u8, u8), vendor_id: u16, device_id: u16) -> Self {
        self.pci = Some(MissingDevPciMetadata {
            bdf,
            vendor_id,
            device_id,
        });
        self
    }
}

pub mod resolver {
    //! A resolver for [`MissingDevHandle`] resources.

    use crate::MissingDev;
    use crate::MissingDevManifest;
    use chipset_device_resources::ResolveChipsetDeviceHandleParams;
    use chipset_device_resources::ResolvedChipsetDevice;
    use missing_dev_resources::MissingDevHandle;
    use std::convert::Infallible;
    use vm_resource::ResolveResource;
    use vm_resource::declare_static_resolver;
    use vm_resource::kind::ChipsetDeviceHandleKind;

    /// A resolver for [`MissingDevHandle`] resources.
    pub struct MissingDevResolver;

    declare_static_resolver!(
        MissingDevResolver,
        (ChipsetDeviceHandleKind, MissingDevHandle)
    );

    impl ResolveResource<ChipsetDeviceHandleKind, MissingDevHandle> for MissingDevResolver {
        type Output = ResolvedChipsetDevice;
        type Error = Infallible;

        fn resolve(
            &self,
            resource: MissingDevHandle,
            input: ResolveChipsetDeviceHandleParams<'_>,
        ) -> Result<Self::Output, Self::Error> {
            input.configure.omit_saved_state();
            let dev = MissingDev::from_manifest(
                MissingDevManifest {
                    pio: resource
                        .pio
                        .into_iter()
                        .map(|(name, start, end)| (name.into(), start..=end))
                        .collect(),
                    mmio: resource
                        .mmio
                        .into_iter()
                        .map(|(name, start, end)| (name.into(), start..=end))
                        .collect(),
                    pci: None,
                },
                input.register_mmio,
                input.register_pio,
            );
            Ok(dev.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chipset_device::pci::PciConfigByteEnable;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use test_with_tracing::test;

    #[derive(Debug, PartialEq, Eq)]
    enum Registration {
        Created(&'static str, String, u64),
        Mapped(&'static str, String, u64),
        Dropped(&'static str, String),
    }

    #[derive(Default)]
    struct Registrar(Arc<Mutex<Vec<Registration>>>);

    struct Control<Address> {
        kind: &'static str,
        name: String,
        length: Address,
        address: Option<Address>,
        log: Arc<Mutex<Vec<Registration>>>,
    }

    impl<Address> Drop for Control<Address> {
        fn drop(&mut self) {
            self.log
                .lock()
                .push(Registration::Dropped(self.kind, self.name.clone()));
        }
    }

    macro_rules! recording_registrar {
        ($register:ident, $control:ident, $address:ty, $kind:literal) => {
            impl $register for Registrar {
                fn new_io_region(&mut self, name: &str, length: $address) -> Box<dyn $control> {
                    self.0
                        .lock()
                        .push(Registration::Created($kind, name.into(), length.into()));
                    Box::new(Control::<$address> {
                        kind: $kind,
                        name: name.into(),
                        length,
                        address: None,
                        log: self.0.clone(),
                    })
                }
            }
            impl $control for Control<$address> {
                fn region_name(&self) -> &str {
                    &self.name
                }
                fn map(&mut self, address: $address) {
                    self.address = Some(address);
                    self.log.lock().push(Registration::Mapped(
                        $kind,
                        self.name.clone(),
                        address.into(),
                    ));
                }
                fn unmap(&mut self) {
                    self.address = None;
                }
                fn addr(&self) -> Option<$address> {
                    self.address
                }
                fn len(&self) -> $address {
                    self.length
                }
                fn offset_of(&self, address: $address) -> Option<$address> {
                    address
                        .checked_sub(self.address?)
                        .filter(|&offset| offset < self.length)
                }
            }
        };
    }
    recording_registrar!(RegisterMmioIntercept, ControlMmioIntercept, u64, "mmio");
    recording_registrar!(RegisterPortIoIntercept, ControlPortIoIntercept, u16, "pio");

    // Test: Read and write the default missing device at low and high MMIO/PIO addresses.
    // Expected: Reads return only 0xff, writes succeed without changing later reads, and PCI is unavailable.
    #[test]
    fn missing_io_reads_all_ones_and_ignores_writes() {
        let mut device = MissingDev::default();
        assert!(device.supports_mmio().is_some());
        assert!(device.supports_pio().is_some());
        assert!(device.supports_pci().is_none());
        for length in [0, 1, 2, 4, 8, 17] {
            for address in [0, 0x1234, u64::MAX] {
                let mut bytes = vec![0x27; length];
                assert!(matches!(device.mmio_write(address, &bytes), IoResult::Ok));
                assert!(matches!(
                    device.mmio_read(address, &mut bytes),
                    IoResult::Ok
                ));
                assert_eq!(bytes, vec![0xff; length]);
            }
            for address in [0, 0x1234, u16::MAX] {
                let mut bytes = vec![0x81; length];
                assert!(matches!(device.io_write(address, &bytes), IoResult::Ok));
                assert!(matches!(device.io_read(address, &mut bytes), IoResult::Ok));
                assert_eq!(bytes, vec![0xff; length]);
            }
        }
        assert!(matches!(device.save(), Err(SaveError::NotSupported)));
    }

    // Test: Instantiate named inclusive PIO/MMIO ranges, including one-byte and highest-address regions.
    // Expected: Each range registers exactly its inclusive length/base and every intercept remains alive until device drop.
    #[test]
    fn manifest_maps_inclusive_regions_and_retains_intercepts() {
        let mut registrar = Registrar::default();
        let mut pio = Registrar(registrar.0.clone());
        let device = MissingDev::from_manifest(
            MissingDevManifest::new()
                .claim_pio("single", 0x1234..=0x1234)
                .claim_pio("top ports", 0xfffe..=0xffff)
                .claim_mmio("low", 0..=0)
                .claim_mmio("top memory", (u64::MAX - 15)..=u64::MAX),
            &mut registrar,
            &mut pio,
        );
        let expected = vec![
            Registration::Created("pio", "single".into(), 1),
            Registration::Mapped("pio", "single".into(), 0x1234),
            Registration::Created("pio", "top ports".into(), 2),
            Registration::Mapped("pio", "top ports".into(), 0xfffe),
            Registration::Created("mmio", "low".into(), 1),
            Registration::Mapped("mmio", "low".into(), 0),
            Registration::Created("mmio", "top memory".into(), 16),
            Registration::Mapped("mmio", "top memory".into(), u64::MAX - 15),
        ];
        assert_eq!(*registrar.0.lock(), expected);
        drop(device);
        let log = registrar.0.lock();
        assert_eq!(&log[..expected.len()], expected);
        let dropped = &log[expected.len()..];
        assert_eq!(dropped.len(), 4);
        for event in [
            Registration::Dropped("mmio", "low".into()),
            Registration::Dropped("mmio", "top memory".into()),
            Registration::Dropped("pio", "single".into()),
            Registration::Dropped("pio", "top ports".into()),
        ] {
            assert!(dropped.contains(&event));
        }
    }

    // Test: Claim a PCI stub twice, read its identity and zero BARs, and write its configuration.
    // Expected: The final claim supplies the BDF/IDs, disabled byte lanes stay intact, and writes or lifecycle changes never alter the advertised configuration.
    #[test]
    fn pci_stub_preserves_identity_and_ignores_configuration_writes() {
        fn read(device: &mut MissingDev, offset: u16, enable: PciConfigByteEnable) -> u32 {
            let mut value = 0x1234_5678;
            assert!(matches!(
                device.pci_cfg_read(offset, ByteEnabledDwordRead::new(&mut value, enable)),
                IoResult::Ok
            ));
            value
        }
        let mut device = MissingDev::from_manifest(
            MissingDevManifest::new()
                .claim_pci((0, 0, 0), 1, 2)
                .claim_pci((7, 21, 3), 0x1234, 0xabcd),
            &mut chipset_device::mmio::ExternallyManagedMmioIntercepts,
            &mut chipset_device::pio::ExternallyManagedPortIoIntercepts,
        );
        assert!(device.supports_pci().is_some());
        assert_eq!(device.suggested_bdf(), Some((7, 21, 3)));
        assert_eq!(
            read(&mut device, 0, PciConfigByteEnable::HIGH_WORD),
            0xabcd_5678
        );
        for (offset, expected) in [(0, 0xabcd_1234), (8, 0), (0x10, 0), (0x2c, 0)] {
            assert_eq!(
                read(&mut device, offset, PciConfigByteEnable::FULL),
                expected
            );
            assert!(matches!(
                device.pci_cfg_write(
                    offset,
                    ByteEnabledDwordWrite::with_all_bytes_enabled(u32::MAX)
                ),
                IoResult::Ok
            ));
            assert_eq!(
                read(&mut device, offset, PciConfigByteEnable::FULL),
                expected
            );
        }
        fn finish(future: impl Future<Output = ()>) {
            let mut future = std::pin::pin!(future);
            assert!(
                future
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                    .is_ready()
            );
        }
        device.start();
        finish(device.stop());
        finish(device.reset());
        assert_eq!(device.suggested_bdf(), Some((7, 21, 3)));
        assert_eq!(read(&mut device, 0, PciConfigByteEnable::FULL), 0xabcd_1234);
    }

    // Test: Resolve a resource with inclusive port and memory ranges through the normal device resolver.
    // Expected: Resolution omits saved state exactly once, retains the requested mappings, and exposes only ignored MMIO/PIO accesses.
    #[pal_async::async_test]
    async fn resolver_preserves_ranges_and_omits_saved_state(driver: pal_async::DefaultDriver) {
        use chipset_device_resources::ConfigureChipsetDevice;
        use chipset_device_resources::LineSetId;
        use chipset_device_resources::ResolveChipsetDeviceHandleParams;
        use guestmem::GuestMemory;
        use missing_dev_resources::MissingDevHandle;
        use vm_resource::ResolveResource;
        use vmcore::line_interrupt::LineInterrupt;
        use vmcore::vm_task::SingleDriverBackend;
        use vmcore::vm_task::VmTaskDriverSource;
        use vmcore::vmtime::VmTime;
        use vmcore::vmtime::VmTimeKeeper;

        #[derive(Default)]
        struct Configuration(usize);
        impl ConfigureChipsetDevice for Configuration {
            fn new_line(&mut self, _id: LineSetId, _name: &str, _vector: u32) -> LineInterrupt {
                panic!("a missing device must not allocate interrupt lines");
            }
            fn add_line_target(
                &mut self,
                _id: LineSetId,
                _range: RangeInclusive<u32>,
                _start: u32,
            ) {
                panic!("a missing device must not register interrupt targets");
            }
            fn omit_saved_state(&mut self) {
                self.0 += 1;
            }
        }

        let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
        let vmtime = keeper.builder().build(&driver).await.unwrap();
        let task_driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        let memory = GuestMemory::allocate(4096);
        let mut configuration = Configuration::default();
        let mut mmio = Registrar::default();
        let mut pio = Registrar(mmio.0.clone());
        let mut resolved = resolver::MissingDevResolver
            .resolve(
                MissingDevHandle::new()
                    .claim_pio("ports", 0xfff0..=0xffff)
                    .claim_mmio("memory", 0x2000..=0x2001),
                ResolveChipsetDeviceHandleParams {
                    device_name: "missing",
                    guest_memory: &memory,
                    encrypted_guest_memory: &memory,
                    vmtime: &vmtime,
                    is_restoring: true,
                    configure: &mut configuration,
                    task_driver_source: &task_driver_source,
                    register_mmio: &mut mmio,
                    register_pio: &mut pio,
                },
            )
            .unwrap()
            .0;
        assert_eq!(configuration.0, 1);
        assert_eq!(
            *mmio.0.lock(),
            [
                Registration::Created("pio", "ports".into(), 16),
                Registration::Mapped("pio", "ports".into(), 0xfff0),
                Registration::Created("mmio", "memory".into(), 2),
                Registration::Mapped("mmio", "memory".into(), 0x2000),
            ]
        );
        assert!(resolved.supports_pci().is_none());
        let mut bytes = [0x27; 2];
        assert!(matches!(
            resolved
                .supports_mmio()
                .unwrap()
                .mmio_read(0x2000, &mut bytes),
            IoResult::Ok
        ));
        assert_eq!(bytes, [0xff; 2]);
        bytes.fill(0x81);
        assert!(matches!(
            resolved.supports_pio().unwrap().io_read(0xfffe, &mut bytes),
            IoResult::Ok
        ));
        assert_eq!(bytes, [0xff; 2]);
    }
}
