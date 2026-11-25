// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::test::CxlTestDevice;
use chipset_device::ChipsetDevice;
use chipset_device::io::{IoError, IoResult};
use chipset_device::mmio::{ControlMmioIntercept, MmioIntercept, RegisterMmioIntercept};
use chipset_device::pci::{ByteEnabledDwordRead, ByteEnabledDwordWrite, PciConfigSpace};
use cxl_spec::component_registers::hdm_decoder::*;
use futures::executor::block_on;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::{SaveError, SaveRestore};

const BAR: u64 = 0x1000_0000;
const HDM: u64 = 0x1_0000_0000;
const SIZE: u64 = 256 * 1024 * 1024;

struct Registrar;
struct Region {
    name: String,
    len: u64,
    address: Option<u64>,
}

impl RegisterMmioIntercept for Registrar {
    fn new_io_region(&mut self, name: &str, len: u64) -> Box<dyn ControlMmioIntercept> {
        Box::new(Region {
            name: name.into(),
            len,
            address: None,
        })
    }
}

impl ControlMmioIntercept for Region {
    fn region_name(&self) -> &str {
        &self.name
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn addr(&self) -> Option<u64> {
        self.address
    }
    fn map(&mut self, addr: u64) {
        self.address = Some(addr);
    }
    fn unmap(&mut self) {
        self.address = None;
    }
    fn offset_of(&self, addr: u64) -> Option<u64> {
        addr.checked_sub(self.address?)
            .filter(|&offset| offset < self.len)
    }
}

fn config_write(device: &mut CxlTestDevice, offset: u16, value: u32) {
    assert!(matches!(
        device.pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(value)),
        IoResult::Ok
    ));
}

fn config_read(device: &mut CxlTestDevice, offset: u16) -> u32 {
    let mut value = 0;
    assert!(matches!(
        device.pci_cfg_read(
            offset,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        IoResult::Ok
    ));
    value
}

fn write_register(device: &mut CxlTestDevice, offset: u16, value: u32) {
    assert!(matches!(
        device.mmio_write(BAR + u64::from(offset), &value.to_le_bytes()),
        IoResult::Ok
    ));
}

fn read_register(device: &mut CxlTestDevice, offset: u16) -> u32 {
    let mut bytes = [0; 4];
    assert!(matches!(
        device.mmio_read(BAR + u64::from(offset), &mut bytes),
        IoResult::Ok
    ));
    u32::from_le_bytes(bytes)
}

fn map_bar(device: &mut CxlTestDevice) {
    config_write(device, 0x10, BAR as u32);
    config_write(device, 0x04, 2);
}

fn find_hdm(device: &mut CxlTestDevice) -> u16 {
    // Locate the HDM block through the guest-visible capability directory.
    let directory = cxl_spec::CXL_COMPONENT_REG_RANGE_CACHEMEM_PRIMARY_OFFSET as u16;
    let header = read_register(device, directory);
    let count = (header >> 24) as u16;
    for index in 1..=count {
        let entry = read_register(device, directory + index * 4);
        if entry as u16 == CXL_HDM_DECODER_CAPABILITY_ID {
            return directory + ((entry >> 20) as u16) * 4;
        }
    }
    panic!("HDM capability missing from guest-visible directory");
}

fn program_decoder(device: &mut CxlTestDevice, cap: u16, size: u64) {
    let decoder = cap + CXL_HDM_DECODER_BASE_OFFSET;
    write_register(device, decoder + CxlHdmDecoderRegisterOffset::BASE_LOW, 0);
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::BASE_HIGH,
        (HDM >> 32) as u32,
    );
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::SIZE_LOW,
        CxlHdmDecoderSizeLowRegister::new()
            .with_memory_size_low((size >> 28) as u8)
            .into_bits(),
    );
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::SIZE_HIGH,
        (size >> 32) as u32,
    );
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::DPA_SKIP_LOW,
        0,
    );
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::DPA_SKIP_HIGH,
        0,
    );
    write_register(
        device,
        decoder + CxlHdmDecoderRegisterOffset::CONTROL,
        CxlHdmDecoderControlRegister::new()
            .with_commit(true)
            .into_bits(),
    );
}

// Test: Construct endpoints with zero, unaligned, and excessive memory sizes.
// Expected: Invalid requests fail before registering any MMIO region.
#[test]
fn endpoint_rejects_invalid_memory_sizes() {
    struct RejectRegistration;
    impl RegisterMmioIntercept for RejectRegistration {
        fn new_io_region(&mut self, _: &str, _: u64) -> Box<dyn ControlMmioIntercept> {
            panic!("invalid construction must not register memory")
        }
    }
    for size in [0, 1, SIZE - 1, 5 * 1024 * 1024 * 1024] {
        assert!(CxlTestDevice::new(&mut RejectRegistration, size).is_err());
    }
}

// Test: Configure endpoint memory through PCI and MMIO, then stop and reset it.
// Expected: Only committed, enabled ranges serve data; reset unmaps and clears RAM.
#[test]
fn endpoint_memory_obeys_decoder_enable_bounds_and_reset() {
    let mut device = CxlTestDevice::new(&mut Registrar, SIZE).unwrap();
    assert!(device.supports_mmio().is_some());
    assert!(device.supports_pci().is_some());
    assert_eq!(config_read(&mut device, 0), 0xc102_1414);
    assert!(matches!(device.save(), Err(SaveError::NotSupported)));
    device.start();
    map_bar(&mut device);
    let cap = find_hdm(&mut device);
    assert!(matches!(
        device.mmio_read(HDM, &mut [0; 1]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    write_register(
        &mut device,
        cap + CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET,
        CxlHdmDecoderGlobalControlRegister::new()
            .with_hdm_decoder_enable(true)
            .into_bits(),
    );
    program_decoder(&mut device, cap, SIZE);
    let mut bytes = [0xff; 4];
    assert!(matches!(device.mmio_read(HDM, &mut bytes), IoResult::Ok));
    assert_eq!(bytes, [0; 4]);
    assert!(matches!(
        device.mmio_write(HDM + 7, &[1, 2, 3, 4]),
        IoResult::Ok
    ));
    assert!(matches!(
        device.mmio_read(HDM + 7, &mut bytes),
        IoResult::Ok
    ));
    assert_eq!(bytes, [1, 2, 3, 4]);
    for address in [HDM - 1, HDM + SIZE - 2, u64::MAX] {
        assert!(matches!(
            device.mmio_read(address, &mut bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            device.mmio_write(address, &bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    write_register(&mut device, cap + CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET, 0);
    assert!(matches!(
        device.mmio_read(HDM, &mut bytes),
        IoResult::Err(IoError::InvalidRegister)
    ));
    block_on(device.stop());
    block_on(device.reset());
    map_bar(&mut device);
    assert!(matches!(
        device.mmio_read(HDM, &mut bytes),
        IoResult::Err(IoError::InvalidRegister)
    ));
    write_register(
        &mut device,
        cap + CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET,
        CxlHdmDecoderGlobalControlRegister::new()
            .with_hdm_decoder_enable(true)
            .into_bits(),
    );
    assert!(matches!(
        device.mmio_read(HDM + 7, &mut bytes),
        IoResult::Ok
    ));
    assert_eq!(bytes, [0; 4]);
}

// Test: Access holes in the component aperture and commit an oversized decoder.
// Expected: Holes read zero and ignore writes; oversized memory remains unmapped.
#[test]
fn endpoint_ignores_register_holes_and_rejects_oversized_decodes() {
    let mut device = CxlTestDevice::new(&mut Registrar, SIZE).unwrap();
    map_bar(&mut device);
    assert_eq!(read_register(&mut device, 0x100), 0);
    write_register(&mut device, 0x100, u32::MAX);
    assert_eq!(read_register(&mut device, 0x100), 0);
    let cap = find_hdm(&mut device);
    program_decoder(&mut device, cap, 2 * SIZE);
    write_register(
        &mut device,
        cap + CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET,
        CxlHdmDecoderGlobalControlRegister::new()
            .with_hdm_decoder_enable(true)
            .into_bits(),
    );
    assert!(matches!(
        device.mmio_read(HDM, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Program a decoder's address and DPA registers through its public aperture.
// Expected: Readback preserves the values and rejects unaligned or missing registers.
#[test]
fn decoder_register_readback_and_invalid_accesses() {
    use crate::CxlComponentRegister;
    use crate::component_registers::CxlHdmDecoderCapability;
    let mut cap = CxlHdmDecoderCapability::new().unwrap();
    cap.with_decoder_slot(
        CxlHdmDecoderInterleaveGranularity::Bytes256,
        CxlHdmDecoderInterleaveWays::Way1,
    )
    .unwrap();
    for (offset, value) in [
        (CxlHdmDecoderRegisterOffset::BASE_LOW, 0x3000_0000),
        (CxlHdmDecoderRegisterOffset::BASE_HIGH, 7),
        (CxlHdmDecoderRegisterOffset::SIZE_LOW, 0x1000_0000),
        (CxlHdmDecoderRegisterOffset::SIZE_HIGH, 1),
        (CxlHdmDecoderRegisterOffset::DPA_SKIP_LOW, 0x2000_0000),
        (CxlHdmDecoderRegisterOffset::DPA_SKIP_HIGH, 2),
    ] {
        assert!(cap.write_u32(CXL_HDM_DECODER_BASE_OFFSET + offset, value));
        assert_eq!(
            cap.read_u32(CXL_HDM_DECODER_BASE_OFFSET + offset),
            Some(value)
        );
    }
    for offset in [1, cap.len(), CXL_HDM_DECODER_BASE_OFFSET + 0x1c] {
        assert_eq!(cap.read_u32(offset), None);
        assert!(!cap.write_u32(offset, u32::MAX));
    }
    assert_eq!(cap.find_enabled_decoder_for_access(u64::MAX, 1), None);
    assert!(cap.write_u32(CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET, 2));
    assert_eq!(cap.find_enabled_decoder_for_access(0, 4), None);
    assert_eq!(cap.find_enabled_decoder_for_access(u64::MAX, 1), None);
}

// Test: Write every advertised register-locator DWORD through the PCI interface.
// Expected: Locator entries remain read-only and preserve their full 64-bit offset.
#[test]
fn register_locator_is_read_only_through_the_pci_interface() {
    use crate::CxlRegisterLocatorDvsecExtendedCapability;
    use cxl_spec::pci_registers::register_locator_dvsec::{
        CxlRegisterLocatorRegisterBir, CxlRegisterLocatorRegisterBlockIdentifier,
    };
    use pci_core::capabilities::PciExtendedCapability;
    let mut cap = CxlRegisterLocatorDvsecExtendedCapability::new()
        .with_register_block(
            CxlRegisterLocatorRegisterBir::BAR_10H,
            CxlRegisterLocatorRegisterBlockIdentifier::COMPONENT_REGISTERS,
            0x1234_5678_0000,
        )
        .unwrap();
    for offset in (0..cap.len() as u16 + 8).step_by(4) {
        let mut before = 0;
        cap.read(
            offset,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut before),
        );
        cap.write(
            offset,
            ByteEnabledDwordWrite::with_all_bytes_enabled(!before),
        );
        let mut after = 0;
        cap.read(
            offset,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut after),
        );
        assert_eq!(after, before);
    }
    cap.reset();
    let mut high = 0;
    cap.read(
        0x10,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut high),
    );
    assert_eq!(high, 0x1234);
}

// Test: Disable and re-enable a committed decoder after writing endpoint memory.
// Expected: Disabled accesses fail without changing data or the committed mapping.
#[test]
fn endpoint_decoder_disable_preserves_memory_across_reenable() {
    let mut device = CxlTestDevice::new(&mut Registrar, SIZE).unwrap();
    map_bar(&mut device);
    let cap = find_hdm(&mut device);
    let global_control = cap + CXL_HDM_DECODER_GLOBAL_CONTROL_OFFSET;
    let enabled = CxlHdmDecoderGlobalControlRegister::new()
        .with_hdm_decoder_enable(true)
        .into_bits();
    program_decoder(&mut device, cap, SIZE);
    write_register(&mut device, global_control, enabled);
    let address = HDM + SIZE - 4;
    let expected = [0x12, 0x34, 0x56, 0x78];
    assert!(matches!(
        device.mmio_write(address, &expected),
        IoResult::Ok
    ));

    write_register(&mut device, global_control, 0);
    let mut bytes = [0xa5; 4];
    assert!(matches!(
        device.mmio_read(address, &mut bytes),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert_eq!(bytes, [0xa5; 4]);
    assert!(matches!(
        device.mmio_write(address, &[0xff; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));

    write_register(&mut device, global_control, enabled);
    assert!(matches!(
        device.mmio_read(address, &mut bytes),
        IoResult::Ok
    ));
    assert_eq!(bytes, expected);
}
