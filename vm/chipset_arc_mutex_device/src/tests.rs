// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::services::MmioInterceptServices;
use crate::test_chipset::TestChipset;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::mmio::ControlMmioIntercept;
use chipset_device::mmio::MmioIntercept;
use chipset_device::mmio::RegisterMmioIntercept;
use std::ops::RangeInclusive;
use test_with_tracing::test;

mod async_tests;
mod builder_tests;

struct Device {
    region: Option<Box<dyn ControlMmioIntercept>>,
    supported: bool,
    data: [u8; 4],
    writes: Vec<(u64, Vec<u8>)>,
}

impl Device {
    fn new(region: Option<Box<dyn ControlMmioIntercept>>, supported: bool) -> Self {
        Self {
            region,
            supported,
            data: [1, 2, 3, 4],
            writes: Vec::new(),
        }
    }
}

impl ChipsetDevice for Device {
    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        self.supported.then_some(self)
    }
}

impl MmioIntercept for Device {
    fn mmio_read(&mut self, _addr: u64, data: &mut [u8]) -> IoResult {
        if _addr == 12 {
            return IoResult::Err(chipset_device::io::IoError::InvalidRegister);
        }
        data.copy_from_slice(&self.data[..data.len()]);
        IoResult::Ok
    }
    fn mmio_write(&mut self, addr: u64, data: &[u8]) -> IoResult {
        self.writes.push((addr, data.to_vec()));
        if addr == 12 {
            return IoResult::Err(chipset_device::io::IoError::InvalidRegister);
        }
        self.data.copy_from_slice(data);
        IoResult::Ok
    }
    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u64>)] {
        &[("static", 10..=13)]
    }
}

// Test: Dispatch reads/writes through static and movable four-byte MMIO regions, then unmap or drop the device.
// Expected: Both inclusive endpoints route exact data, adjacent addresses remain untouched, remap removes the old route, writes reach the device with their address/data, and unmapping or dropping makes accesses unmapped.
#[test]
fn mmio_ranges_route_data_and_move_without_stale_dispatch() {
    let chipset = TestChipset::default();
    let device = chipset
        .device_builder("registers")
        .add(|services| {
            Device::new(
                Some(services.register_mmio().new_io_region("dynamic", 4)),
                true,
            )
        })
        .unwrap();
    for address in [10, 13] {
        let mut data = [0; 4];
        assert_eq!(chipset.mmio_read(address, &mut data), Some(()));
        assert_eq!(data, [1, 2, 3, 4]);
    }
    for address in [9, 14] {
        let mut data = [0xa7; 4];
        assert_eq!(chipset.mmio_read(address, &mut data), None);
        assert_eq!(data, [0xa7; 4]);
        assert_eq!(chipset.mmio_write(address, &[9; 4]), None);
    }
    {
        let mut device = device.lock();
        let region = device.region.as_mut().unwrap();
        assert_eq!(region.region_name(), "dynamic");
        assert_eq!(region.len(), 4);
        assert_eq!(region.addr(), None);
        assert_eq!(region.offset_of(100), None);
        region.map(100);
        assert_eq!(region.addr(), Some(100));
        assert_eq!(region.offset_of(99), None);
        assert_eq!(region.offset_of(100), Some(0));
        assert_eq!(region.offset_of(103), Some(3));
        assert_eq!(region.offset_of(104), None);
    }
    assert_eq!(chipset.mmio_write(103, &[0x91; 4]), Some(()));
    assert_eq!(device.lock().writes, [(103, vec![0x91; 4])]);
    device.lock().region.as_mut().unwrap().map(200);
    assert_eq!(chipset.mmio_read(100, &mut [0; 4]), None);
    let mut readback = [0; 4];
    assert_eq!(chipset.mmio_read(203, &mut readback), Some(()));
    assert_eq!(readback, [0x91; 4]);
    device.lock().region.as_mut().unwrap().unmap();
    assert_eq!(chipset.mmio_write(200, &[0; 4]), None);
    drop(device);
    assert_eq!(chipset.mmio_read(10, &mut [0; 4]), None);
}

// Test: Dispatch device-reported MMIO failures through a registered range.
// Expected: Read errors replace every requested byte with ff; write errors remain handled bus accesses but do not change the device's register bytes, and later valid accesses still succeed.
#[test]
fn mmio_failures_return_open_bus_bytes_and_preserve_registers() {
    let chipset = TestChipset::default();
    let device = chipset
        .device_builder("failing-register")
        .add(|_| Device::new(None, true))
        .unwrap();
    let mut readback = [0xa7; 4];
    assert_eq!(chipset.mmio_read(12, &mut readback), Some(()));
    assert_eq!(readback, [0xff; 4]);
    assert_eq!(chipset.mmio_write(12, &[0x91; 4]), Some(()));
    assert_eq!(device.lock().writes, [(12, vec![0x91; 4])]);
    assert_eq!(chipset.mmio_read(10, &mut readback), Some(()));
    assert_eq!(readback, [1, 2, 3, 4]);
}

// Test: Build a device that requests MMIO without advertising MMIO support and a device whose constructor fails.
// Expected: Neither device is attached; the public error identifies its device name and retains the specific mismatch or constructor source.
#[test]
fn builder_errors_keep_device_context_and_do_not_attach() {
    use std::error::Error;
    let chipset = TestChipset::default();
    let result = chipset.device_builder("missing-mmio").add(|services| {
        Device::new(
            Some(services.register_mmio().new_io_region("unused", 4)),
            false,
        )
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unsupported MMIO was accepted"),
    };
    assert_eq!(error.to_string(), "could not initialize missing-mmio");
    assert!(
        error
            .source()
            .unwrap()
            .to_string()
            .contains("without overriding supports_mmio")
    );
    let result = chipset
        .device_builder::<Device>("constructor")
        .try_add(|_| Err(std::io::Error::other("fixture construction failed")));
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("failed constructor was accepted"),
    };
    assert_eq!(error.to_string(), "could not initialize constructor");
    assert_eq!(
        error.source().unwrap().source().unwrap().to_string(),
        "fixture construction failed"
    );
    assert_eq!(chipset.mmio_read(10, &mut [0; 4]), None);
}
