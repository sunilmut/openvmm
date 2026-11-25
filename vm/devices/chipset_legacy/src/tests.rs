// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use chipset_device::ChipsetDevice;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigByteEnable;
use chipset_device::pci::PciConfigSpace;
use chipset_device::pio::ControlPortIoIntercept;
use chipset_device::pio::PortIoIntercept;
use chipset_device::pio::RegisterPortIoIntercept;
use parking_lot::Mutex;
use std::sync::Arc;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::SaveRestore;

fn pci_read(device: &mut dyn ChipsetDevice, offset: u16) -> u32 {
    let mut value = 0;
    device
        .supports_pci()
        .expect("device must expose PCI configuration to the chipset")
        .pci_cfg_read(
            offset,
            ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::FULL),
        )
        .unwrap();
    value
}

fn pci_write(device: &mut dyn ChipsetDevice, offset: u16, value: u32) {
    device
        .supports_pci()
        .expect("device must expose PCI configuration to the chipset")
        .pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(value))
        .unwrap();
}

pub(crate) fn read8(device: &mut dyn ChipsetDevice, port: u16) -> u8 {
    let mut value = [0];
    device
        .supports_pio()
        .expect("device must expose port I/O to the chipset")
        .io_read(port, &mut value)
        .unwrap();
    value[0]
}

pub(crate) fn write8(device: &mut dyn ChipsetDevice, port: u16, value: u8) {
    device
        .supports_pio()
        .expect("device must expose port I/O to the chipset")
        .io_write(port, &[value])
        .unwrap();
}

#[derive(Default)]
struct PioRegistrar {
    regions: Vec<Arc<Mutex<PioRegion>>>,
}

struct PioRegion {
    name: String,
    len: u16,
    base: Option<u16>,
}

struct PioControl(Arc<Mutex<PioRegion>>, String);

impl RegisterPortIoIntercept for PioRegistrar {
    fn new_io_region(&mut self, name: &str, len: u16) -> Box<dyn ControlPortIoIntercept> {
        let region = Arc::new(Mutex::new(PioRegion {
            name: name.into(),
            len,
            base: None,
        }));
        self.regions.push(region.clone());
        Box::new(PioControl(region, name.into()))
    }
}

impl PioRegistrar {
    fn base(&self, name: &str) -> Option<u16> {
        self.regions
            .iter()
            .find_map(|region| {
                let region = region.lock();
                (region.name == name).then_some(region.base)
            })
            .expect("region must have been registered")
    }
}

impl ControlPortIoIntercept for PioControl {
    fn region_name(&self) -> &str {
        &self.1
    }
    fn map(&mut self, addr: u16) {
        self.0.lock().base = Some(addr);
    }
    fn unmap(&mut self) {
        self.0.lock().base = None;
    }
    fn addr(&self) -> Option<u16> {
        self.0.lock().base
    }
    fn len(&self) -> u16 {
        self.0.lock().len
    }
    fn offset_of(&self, addr: u16) -> Option<u16> {
        let region = self.0.lock();
        addr.checked_sub(region.base?)
            .filter(|offset| *offset < region.len)
    }
}

mod bridges;
mod legacy_io;
mod power;
mod super_io;
