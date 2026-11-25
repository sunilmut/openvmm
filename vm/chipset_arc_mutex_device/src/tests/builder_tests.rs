// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::device::ArcMutexChipsetDeviceBuilder;
use crate::device::ArcMutexChipsetServicesFinalize;
use crate::services::*;
use chipset_device::pci::{ByteEnabledDwordRead, ByteEnabledDwordWrite, PciConfigSpace};
use chipset_device::pio::{ControlPortIoIntercept, PortIoIntercept, RegisterPortIoIntercept};
use chipset_device::poll_device::PollDevice;
use closeable_mutex::CloseableMutex;
use parking_lot::Mutex;
use std::cell::Cell;
use std::sync::Arc;
use test_with_tracing::test;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Region(String, u16),
    Map(u16),
    Pci(u8, u8, u8),
    Poll,
    Finalize(String),
}
type Calls = Arc<Mutex<Vec<Call>>>;

struct Services {
    calls: Calls,
    enabled: [bool; 3],
    used: [Cell<bool>; 3],
}
struct Meta;
impl ChipsetServicesMeta for Meta {
    type RegisterMmioIntercept = Unimplemented;
    type RegisterPortIoIntercept = PortRegistrar;
}
impl ChipsetServices for Services {
    type M = Meta;
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoInterceptServices<M = Meta>> {
        self.enabled[0].then_some(self)
    }
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpaceServices<M = Meta>> {
        self.enabled[1].then_some(self)
    }
    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDeviceServices<M = Meta>> {
        self.enabled[2].then_some(self)
    }
}
impl PortIoInterceptServices for Services {
    fn register_pio(&self) -> PortRegistrar {
        self.used[0].set(true);
        PortRegistrar(self.calls.clone())
    }
    fn is_being_used(&self) -> bool {
        self.used[0].get()
    }
}
impl PciConfigSpaceServices for Services {
    fn register_static_pci(&mut self, bus: u8, device: u8, function: u8) {
        self.used[1].set(true);
        self.calls.lock().push(Call::Pci(bus, device, function));
    }
    fn is_being_used(&self) -> bool {
        self.used[1].get()
    }
}
impl PollDeviceServices for Services {
    fn register_poll(&mut self) {
        self.used[2].set(true);
        self.calls.lock().push(Call::Poll);
    }
    fn is_being_used(&self) -> bool {
        self.used[2].get()
    }
}
impl<T> ArcMutexChipsetServicesFinalize<T> for Services {
    fn finalize(self, _device: &Arc<CloseableMutex<T>>, name: Arc<str>) {
        self.calls.lock().push(Call::Finalize(name.to_string()));
    }
}
struct PortRegistrar(Calls);
struct PortRegion {
    calls: Calls,
    label: String,
    len: u16,
    addr: Option<u16>,
}
impl RegisterPortIoIntercept for PortRegistrar {
    fn new_io_region(&mut self, label: &str, len: u16) -> Box<dyn ControlPortIoIntercept> {
        self.0.lock().push(Call::Region(label.to_owned(), len));
        Box::new(PortRegion {
            calls: self.0.clone(),
            label: label.to_owned(),
            len,
            addr: None,
        })
    }
}
impl ControlPortIoIntercept for PortRegion {
    fn region_name(&self) -> &str {
        &self.label
    }
    fn map(&mut self, addr: u16) {
        self.addr = Some(addr);
        self.calls.lock().push(Call::Map(addr));
    }
    fn unmap(&mut self) {
        self.addr = None;
    }
    fn addr(&self) -> Option<u16> {
        self.addr
    }
    fn len(&self) -> u16 {
        self.len
    }
    fn offset_of(&self, addr: u16) -> Option<u16> {
        addr.checked_sub(self.addr?)
            .filter(|offset| *offset < self.len)
    }
}
struct BusDevice {
    enabled: [bool; 3],
    suggested: Option<(u8, u8, u8)>,
}
impl ChipsetDevice for BusDevice {
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        self.enabled[0].then_some(self)
    }
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        self.enabled[1].then_some(self)
    }
    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        self.enabled[2].then_some(self)
    }
}
impl PortIoIntercept for BusDevice {
    fn io_read(&mut self, _addr: u16, _data: &mut [u8]) -> IoResult {
        IoResult::Ok
    }
    fn io_write(&mut self, _addr: u16, _data: &[u8]) -> IoResult {
        IoResult::Ok
    }
    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u16>)] {
        &[("ports", 0x80..=0x83)]
    }
}
impl PciConfigSpace for BusDevice {
    fn pci_cfg_read(&mut self, _offset: u16, _value: ByteEnabledDwordRead<'_>) -> IoResult {
        IoResult::Ok
    }
    fn pci_cfg_write(&mut self, _offset: u16, _value: ByteEnabledDwordWrite) -> IoResult {
        IoResult::Ok
    }
    fn suggested_bdf(&mut self) -> Option<(u8, u8, u8)> {
        self.suggested
    }
}
impl PollDevice for BusDevice {
    fn poll_device(&mut self, _cx: &mut std::task::Context<'_>) {}
}

fn builder(calls: Calls, enabled: [bool; 3]) -> ArcMutexChipsetDeviceBuilder<Services, BusDevice> {
    ArcMutexChipsetDeviceBuilder::new("bus-device".into(), |_device, _name| Services {
        calls,
        enabled,
        used: Default::default(),
    })
}

// Test: Build PCI devices with a suggested address, an explicit address, both, no address, or externally managed PCI.
// Expected: Explicit addresses override suggestions, exact BDFs are registered once, missing addresses fail without finalization, and external PCI bypasses unavailable chipset PCI registration while still finalizing the device.
#[test]
fn pci_address_policy_registers_only_the_selected_bdf() {
    for (suggested, override_bdf, expected) in [
        (Some((1, 2, 3)), None, (1, 2, 3)),
        (None, Some((4, 5, 6)), (4, 5, 6)),
        (Some((1, 2, 3)), Some((4, 5, 6)), (4, 5, 6)),
    ] {
        let calls = Calls::default();
        let mut builder = builder(calls.clone(), [false, true, false]);
        if let Some((bus, device, function)) = override_bdf {
            builder = builder.with_pci_addr(bus, device, function);
        }
        let _device = builder
            .add(|_| BusDevice {
                enabled: [false, true, false],
                suggested,
            })
            .unwrap();
        assert_eq!(
            *calls.lock(),
            [
                Call::Pci(expected.0, expected.1, expected.2),
                Call::Finalize("bus-device".into())
            ]
        );
    }
    let calls = Calls::default();
    let result = builder(calls.clone(), [false, true, false]).add(|_| BusDevice {
        enabled: [false, true, false],
        suggested: None,
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("missing PCI address accepted"),
    };
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "no pci bus address provided"
    );
    assert!(calls.lock().is_empty());
    let _device = builder(calls.clone(), [false; 3])
        .with_external_pci()
        .add(|_| BusDevice {
            enabled: [false, true, false],
            suggested: None,
        })
        .unwrap();
    assert_eq!(*calls.lock(), [Call::Finalize("bus-device".into())]);
}

// Test: Build a device advertising static PIO and polling support, then omit each required chipset service or request services without corresponding device support.
// Expected: The inclusive static port interval registers length four at its exact base, polling registers before finalization, and inconsistent capability declarations fail with device context and no finalization.
#[test]
fn service_registration_and_missing_support_are_validated() {
    let calls = Calls::default();
    let _device = builder(calls.clone(), [true, false, true])
        .add(|_| BusDevice {
            enabled: [true, false, true],
            suggested: None,
        })
        .unwrap();
    assert_eq!(
        *calls.lock(),
        [
            Call::Region("ports".into(), 4),
            Call::Map(0x80),
            Call::Poll,
            Call::Finalize("bus-device".into())
        ]
    );
    for index in 0..3 {
        let calls = Calls::default();
        let mut enabled = [false; 3];
        enabled[index] = true;
        let result = builder(calls.clone(), [false; 3]).add(|_| BusDevice {
            enabled,
            suggested: Some((0, 1, 0)),
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("missing service accepted"),
        };
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .to_string()
                .contains("chipset does not support")
        );
        assert!(calls.lock().is_empty());
        let result = builder(calls.clone(), enabled).add(|services| {
            match index {
                0 => {
                    let _registrar = services.register_pio();
                }
                1 => services.register_static_pci(0, 1, 0),
                2 => services.register_poll(),
                _ => unreachable!(),
            }
            BusDevice {
                enabled: [false; 3],
                suggested: None,
            }
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("unadvertised service accepted"),
        };
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .to_string()
                .contains("without overriding supports_")
        );
        assert!(
            !calls
                .lock()
                .iter()
                .any(|call| matches!(call, Call::Finalize(_)))
        );
    }
}
