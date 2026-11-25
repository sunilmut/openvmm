// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::capabilities::extended::acs::AcsExtendedCapability;
use crate::capabilities::pci_express::PciExpressCapability;
use crate::capabilities::read_only::ReadOnlyCapability;
use crate::spec::caps::pci_express::DevicePortType;
use crate::spec::hwid::ClassCode;
use crate::spec::hwid::ProgrammingInterface;
use crate::spec::hwid::Subclass;
use crate::test_helpers::TestCfgAccess;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigByteEnable;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use test_with_tracing::test;
use vmcore::save_restore::SaveRestore;

fn create_type0_emulator(caps: Vec<Box<dyn PciCapability>>) -> ConfigSpaceType0Emulator {
    create_type0_with_extended(caps, vec![])
}

fn create_type0_with_extended(
    caps: Vec<Box<dyn PciCapability>>,
    extended: Vec<Box<dyn PciExtendedCapability>>,
) -> ConfigSpaceType0Emulator {
    ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0x3333,
            type0_sub_system_id: 0x4444,
        },
        caps,
        extended,
        DeviceBars::new(),
    )
}

fn create_type1_emulator(caps: Vec<Box<dyn PciCapability>>) -> ConfigSpaceType1Emulator {
    create_type1_with_extended(caps, vec![])
}

fn create_type1_with_extended(
    caps: Vec<Box<dyn PciCapability>>,
    extended: Vec<Box<dyn PciExtendedCapability>>,
) -> ConfigSpaceType1Emulator {
    ConfigSpaceType1Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::BRIDGE_PCI_TO_PCI,
            base_class: ClassCode::BRIDGE,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        caps,
        extended,
    )
}

#[test]
fn test_type1_probe() {
    let emu = create_type1_emulator(vec![]);
    assert_eq!(emu.read_u32(0), 0x2222_1111);
    assert_eq!(emu.read_u32(4) & 0x10_0000, 0); // Capabilities pointer

    let emu = create_type1_emulator(vec![Box::new(ReadOnlyCapability::new("foo", 0))]);
    assert_eq!(emu.read_u32(0), 0x2222_1111);
    assert_eq!(emu.read_u32(4) & 0x10_0000, 0x10_0000); // Capabilities pointer
}

#[test]
fn test_type1_bus_number_assignment() {
    let mut emu = create_type1_emulator(vec![]);

    // The bus number (and latency timer) registers are
    // all default 0.
    assert_eq!(emu.read_u32(0x18), 0);
    assert_eq!(emu.assigned_bus_range(), 0..=0);

    // The bus numbers can be programmed one by one,
    // and the range may not be valid during the middle
    // of allocation.
    emu.write_u32(0x18, 0x0000_1000);
    assert_eq!(emu.read_u32(0x18), 0x0000_1000);
    assert_eq!(emu.assigned_bus_range(), 0..=0);
    emu.write_u32(0x18, 0x0012_1000);
    assert_eq!(emu.read_u32(0x18), 0x0012_1000);
    assert_eq!(emu.assigned_bus_range(), 0x10..=0x12);

    // The primary bus number register is read/write for compatability
    // but unused.
    emu.write_u32(0x18, 0x0012_1033);
    assert_eq!(emu.read_u32(0x18), 0x0012_1033);
    assert_eq!(emu.assigned_bus_range(), 0x10..=0x12);

    // Software can also just write the entire 4byte value at once
    emu.write_u32(0x18, 0x0047_4411);
    assert_eq!(emu.read_u32(0x18), 0x0047_4411);
    assert_eq!(emu.assigned_bus_range(), 0x44..=0x47);

    // The subordinate bus number can equal the secondary bus number...
    emu.write_u32(0x18, 0x0088_8800);
    assert_eq!(emu.assigned_bus_range(), 0x88..=0x88);

    // ... but it cannot be less, that's a confused guest OS.
    emu.write_u32(0x18, 0x0087_8800);
    assert_eq!(emu.assigned_bus_range(), 0..=0);
}

#[test]
fn test_type1_bus_number_byte_writes() {
    let mut emu = create_type1_emulator(vec![]);

    emu.write(
        PciConfigAddress::new(0, 0, 0x18 / 4).unwrap(),
        ByteEnabledDwordWrite::new(
            0x0000_0011,
            PciConfigByteEnable::from_offset_len(0x18, 1).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(emu.read_u32(0x18), 0x0000_0011);
    assert_eq!(emu.assigned_bus_range(), 0..=0);

    emu.write(
        PciConfigAddress::new(0, 0, 0x18 / 4).unwrap(),
        ByteEnabledDwordWrite::new(
            0x0000_2200,
            PciConfigByteEnable::from_offset_len(0x19, 1).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(emu.read_u32(0x18), 0x0000_2211);
    assert_eq!(emu.assigned_bus_range(), 0..=0);

    emu.write(
        PciConfigAddress::new(0, 0, 0x18 / 4).unwrap(),
        ByteEnabledDwordWrite::new(
            0x0033_0000,
            PciConfigByteEnable::from_offset_len(0x1a, 1).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(emu.read_u32(0x18), 0x0033_2211);
    assert_eq!(emu.assigned_bus_range(), 0x22..=0x33);

    emu.write(
        PciConfigAddress::new(0, 0, 0x18 / 4).unwrap(),
        ByteEnabledDwordWrite::new(
            0xff00_0000,
            PciConfigByteEnable::from_offset_len(0x1b, 1).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(emu.read_u32(0x18), 0x0033_2211);
    assert_eq!(emu.assigned_bus_range(), 0x22..=0x33);
}

#[test]
fn test_type1_memory_assignment() {
    const MMIO_ENABLED: u32 = 0x0000_0002;
    const MMIO_DISABLED: u32 = 0x0000_0000;

    let mut emu = create_type1_emulator(vec![]);
    assert!(emu.assigned_memory_range().is_none());

    // The guest can write whatever it wants while MMIO
    // is disabled.
    emu.write_u32(0x20, 0xDEAD_BEEF);
    assert!(emu.assigned_memory_range().is_none());

    // The guest can program a valid resource assignment...
    emu.write_u32(0x20, 0xFFF0_FF00);
    assert!(emu.assigned_memory_range().is_none());
    // ... enable memory decoding...
    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(emu.assigned_memory_range(), Some(0xFF00_0000..=0xFFFF_FFFF));
    // ... then disable memory decoding it.
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_memory_range().is_none());

    // Setting memory base equal to memory limit is a valid 1MB range.
    emu.write_u32(0x20, 0xBBB0_BBB0);
    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(emu.assigned_memory_range(), Some(0xBBB0_0000..=0xBBBF_FFFF));
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_memory_range().is_none());

    // The guest can try to program an invalid assignment (base > limit), we
    // just won't decode it.
    emu.write_u32(0x20, 0xAA00_BB00);
    assert!(emu.assigned_memory_range().is_none());
    emu.write_u32(0x4, MMIO_ENABLED);
    assert!(emu.assigned_memory_range().is_none());
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_memory_range().is_none());
}

#[test]
fn test_type1_memory_range_register_masks_reserved_bits() {
    const MMIO_ENABLED: u32 = 0x0000_0002;

    let mut emu = create_type1_emulator(vec![]);

    emu.write_u32(0x20, 0x567f_123f);
    assert_eq!(emu.read_u32(0x20), 0x5670_1230);

    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(emu.assigned_memory_range(), Some(0x1230_0000..=0x567f_ffff));
}

#[test]
fn test_type1_prefetch_assignment() {
    const MMIO_ENABLED: u32 = 0x0000_0002;
    const MMIO_DISABLED: u32 = 0x0000_0000;

    let mut emu = create_type1_emulator(vec![]);
    assert!(emu.assigned_prefetch_range().is_none());

    // The guest can program a valid prefetch range...
    emu.write_u32(0x24, 0xFFF0_FF00); // limit + base
    emu.write_u32(0x28, 0x00AA_BBCC); // base upper
    emu.write_u32(0x2C, 0x00DD_EEFF); // limit upper
    assert!(emu.assigned_prefetch_range().is_none());
    // ... enable memory decoding...
    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(
        emu.assigned_prefetch_range(),
        Some(0x00AA_BBCC_FF00_0000..=0x00DD_EEFF_FFFF_FFFF)
    );
    // ... then disable memory decoding it.
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_prefetch_range().is_none());

    // The validity of the assignment is determined using the combined 64-bit
    // address, not the lower bits or the upper bits in isolation.

    // Lower bits of the limit are greater than the lower bits of the
    // base, but the upper bits make that valid.
    emu.write_u32(0x24, 0xFF00_FFF0); // limit + base
    emu.write_u32(0x28, 0x00AA_BBCC); // base upper
    emu.write_u32(0x2C, 0x00DD_EEFF); // limit upper
    assert!(emu.assigned_prefetch_range().is_none());
    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(
        emu.assigned_prefetch_range(),
        Some(0x00AA_BBCC_FFF0_0000..=0x00DD_EEFF_FF0F_FFFF)
    );
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_prefetch_range().is_none());

    // The base can equal the limit, which is a valid 1MB range.
    emu.write_u32(0x24, 0xDD00_DD00); // limit + base
    emu.write_u32(0x28, 0x00AA_BBCC); // base upper
    emu.write_u32(0x2C, 0x00AA_BBCC); // limit upper
    assert!(emu.assigned_prefetch_range().is_none());
    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(
        emu.assigned_prefetch_range(),
        Some(0x00AA_BBCC_DD00_0000..=0x00AA_BBCC_DD0F_FFFF)
    );
    emu.write_u32(0x4, MMIO_DISABLED);
    assert!(emu.assigned_prefetch_range().is_none());
}

#[test]
fn test_type1_prefetch_range_register_masks_reserved_bits_and_reports_64_bit() {
    const MMIO_ENABLED: u32 = 0x0000_0002;

    let mut emu = create_type1_emulator(vec![]);

    emu.write_u32(0x24, 0x567e_123e);
    assert_eq!(emu.read_u32(0x24), 0x5671_1231);

    emu.write_u32(0x4, MMIO_ENABLED);
    assert_eq!(
        emu.assigned_prefetch_range(),
        Some(0x1230_0000..=0x567f_ffff)
    );
}

#[test]
fn test_type1_restore_masks_bridge_memory_range_reserved_bits() {
    const MMIO_ENABLED: u32 = 0x0000_0002;

    let mut source = create_type1_emulator(vec![]);
    source.write_u32(0x4, MMIO_ENABLED);
    source.state.memory_base = 0x123f;
    source.state.memory_limit = 0x567f;
    source.state.prefetch_base = 0x234e;
    source.state.prefetch_limit = 0x678e;

    let saved_state = source.save().expect("save should succeed");

    let mut emu = create_type1_emulator(vec![]);
    emu.restore(saved_state).expect("restore should succeed");

    assert_eq!(emu.read_u32(0x20), 0x5670_1230);
    assert_eq!(emu.read_u32(0x24), 0x6781_2341);
    assert_eq!(emu.assigned_memory_range(), Some(0x1230_0000..=0x567f_ffff));
    assert_eq!(
        emu.assigned_prefetch_range(),
        Some(0x2340_0000..=0x678f_ffff)
    );
}

#[test]
fn test_type1_is_pcie_device() {
    // Test Type 1 device without PCIe capability
    let emu = create_type1_emulator(vec![Box::new(ReadOnlyCapability::new("foo", 0))]);
    assert!(!emu.is_pcie_device());

    // Test Type 1 device with PCIe capability
    let emu = create_type1_emulator(vec![Box::new(PciExpressCapability::new(
        DevicePortType::RootPort,
        None,
    ))]);
    assert!(emu.is_pcie_device());

    // Test Type 1 device with multiple capabilities including PCIe
    let emu = create_type1_emulator(vec![
        Box::new(ReadOnlyCapability::new("foo", 0)),
        Box::new(PciExpressCapability::new(DevicePortType::Endpoint, None)),
        Box::new(ReadOnlyCapability::new("bar", 0)),
    ]);
    assert!(emu.is_pcie_device());
}

#[test]
fn test_type0_is_pcie_device() {
    // Test Type 0 device without PCIe capability
    let emu = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(ReadOnlyCapability::new("foo", 0))],
        vec![],
        DeviceBars::new(),
    );
    assert!(!emu.is_pcie_device());

    // Test Type 0 device with PCIe capability
    let emu = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(PciExpressCapability::new(
            DevicePortType::Endpoint,
            None,
        ))],
        vec![],
        DeviceBars::new(),
    );
    assert!(emu.is_pcie_device());

    // Test Type 0 device with multiple capabilities including PCIe
    let emu = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![
            Box::new(ReadOnlyCapability::new("foo", 0)),
            Box::new(PciExpressCapability::new(DevicePortType::Endpoint, None)),
            Box::new(ReadOnlyCapability::new("bar", 0)),
        ],
        vec![],
        DeviceBars::new(),
    );
    assert!(emu.is_pcie_device());

    // Test Type 0 device with no capabilities
    let emu = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        DeviceBars::new(),
    );
    assert!(!emu.is_pcie_device());
}

#[test]
fn test_capability_ids() {
    // Test that capabilities return the correct capability IDs
    let pcie_cap = PciExpressCapability::new(DevicePortType::Endpoint, None);
    assert_eq!(pcie_cap.capability_id(), CapabilityId::PCI_EXPRESS);

    let read_only_cap = ReadOnlyCapability::new("test", 0u32);
    assert_eq!(read_only_cap.capability_id(), CapabilityId::VENDOR_SPECIFIC);
}

#[test]
fn test_common_header_emulator_type0() {
    // Test the common header emulator with Type 0 configuration (6 BARs)
    let hardware_ids = HardwareIds {
        vendor_id: 0x1111,
        device_id: 0x2222,
        revision_id: 1,
        prog_if: ProgrammingInterface::NONE,
        sub_class: Subclass::NONE,
        base_class: ClassCode::UNCLASSIFIED,
        type0_sub_vendor_id: 0,
        type0_sub_system_id: 0,
    };

    let bars = DeviceBars::new().bar0(4096, BarMemoryKind::Dummy);

    let common_emu: ConfigSpaceCommonHeaderEmulatorType0 =
        ConfigSpaceCommonHeaderEmulator::new(hardware_ids, vec![], vec![], bars);

    assert_eq!(common_emu.hardware_ids().vendor_id, 0x1111);
    assert_eq!(common_emu.hardware_ids().device_id, 0x2222);
    assert!(!common_emu.multi_function_bit());
    assert!(!common_emu.is_pcie_device());
    assert_ne!(common_emu.bar_masks()[0], 0); // Should have a mask for BAR0
}

#[test]
fn test_common_header_emulator_type1() {
    // Test the common header emulator with Type 1 configuration (2 BARs)
    let hardware_ids = HardwareIds {
        vendor_id: 0x3333,
        device_id: 0x4444,
        revision_id: 1,
        prog_if: ProgrammingInterface::NONE,
        sub_class: Subclass::BRIDGE_PCI_TO_PCI,
        base_class: ClassCode::BRIDGE,
        type0_sub_vendor_id: 0,
        type0_sub_system_id: 0,
    };

    let bars = DeviceBars::new().bar0(4096, BarMemoryKind::Dummy);

    let mut common_emu: ConfigSpaceCommonHeaderEmulatorType1 =
        ConfigSpaceCommonHeaderEmulator::new(
            hardware_ids,
            vec![Box::new(PciExpressCapability::new(
                DevicePortType::RootPort,
                None,
            ))],
            vec![],
            bars,
        )
        .with_multi_function_bit(true);

    assert_eq!(common_emu.hardware_ids().vendor_id, 0x3333);
    assert_eq!(common_emu.hardware_ids().device_id, 0x4444);
    assert!(common_emu.multi_function_bit());
    assert!(common_emu.is_pcie_device());
    assert_ne!(common_emu.bar_masks()[0], 0); // Should have a mask for BAR0
    assert_eq!(common_emu.bar_masks().len(), 2);

    // Test reset functionality
    common_emu.reset();
    assert_eq!(common_emu.capabilities().len(), 1); // capabilities should still be there
}

#[test]
fn test_common_header_emulator_no_bars() {
    // Test the common header emulator with no BARs configured
    let hardware_ids = HardwareIds {
        vendor_id: 0x5555,
        device_id: 0x6666,
        revision_id: 1,
        prog_if: ProgrammingInterface::NONE,
        sub_class: Subclass::NONE,
        base_class: ClassCode::UNCLASSIFIED,
        type0_sub_vendor_id: 0,
        type0_sub_system_id: 0,
    };

    // Create bars with no BARs configured
    let bars = DeviceBars::new();

    let common_emu: ConfigSpaceCommonHeaderEmulatorType0 =
        ConfigSpaceCommonHeaderEmulator::new(hardware_ids, vec![], vec![], bars);

    assert_eq!(common_emu.hardware_ids().vendor_id, 0x5555);
    assert_eq!(common_emu.hardware_ids().device_id, 0x6666);

    // All BAR masks should be 0 when no BARs are configured
    for &mask in common_emu.bar_masks() {
        assert_eq!(mask, 0);
    }
}

#[test]
fn test_common_header_emulator_type1_ignores_extra_bars() {
    // Test that Type 1 emulator ignores BARs beyond index 1 (only supports 2 BARs)
    let hardware_ids = HardwareIds {
        vendor_id: 0x7777,
        device_id: 0x8888,
        revision_id: 1,
        prog_if: ProgrammingInterface::NONE,
        sub_class: Subclass::BRIDGE_PCI_TO_PCI,
        base_class: ClassCode::BRIDGE,
        type0_sub_vendor_id: 0,
        type0_sub_system_id: 0,
    };

    // Configure BARs 0, 2, and 4 - Type 1 should only use BAR0 (and BAR1 as upper 32 bits)
    let bars = DeviceBars::new()
        .bar0(4096, BarMemoryKind::Dummy)
        .bar2(8192, BarMemoryKind::Dummy)
        .bar4(16384, BarMemoryKind::Dummy);

    let common_emu: ConfigSpaceCommonHeaderEmulatorType1 =
        ConfigSpaceCommonHeaderEmulator::new(hardware_ids, vec![], vec![], bars);

    assert_eq!(common_emu.hardware_ids().vendor_id, 0x7777);
    assert_eq!(common_emu.hardware_ids().device_id, 0x8888);

    // Should have a mask for BAR0, and BAR1 should be the upper 32 bits (64-bit BAR)
    assert_ne!(common_emu.bar_masks()[0], 0); // BAR0 should be configured
    assert_ne!(common_emu.bar_masks()[1], 0); // BAR1 should be upper 32 bits of BAR0
    assert_eq!(common_emu.bar_masks().len(), 2); // Type 1 only has 2 BARs

    // BAR2 and higher should be ignored (not accessible in Type 1 with N=2)
    // This demonstrates that extra BARs in DeviceBars are properly ignored
}

#[test]
fn test_common_header_extended_capabilities() {
    // Test common header emulator extended capabilities
    let mut common_emu_no_pcie = ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(ReadOnlyCapability::new("foo", 0))],
        vec![],
        DeviceBars::new(),
    );
    assert!(!common_emu_no_pcie.is_pcie_device());

    let mut common_emu_pcie = ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(PciExpressCapability::new(
            DevicePortType::Endpoint,
            None,
        ))],
        vec![],
        DeviceBars::new(),
    );
    assert!(common_emu_pcie.is_pcie_device());

    // A non-PCIe device has no extended configuration space, but the
    // function is present: in-range reads return 0 (no extended caps),
    // not all-ones.
    let mut value = 0xdead_beef;
    assert!(matches!(
        common_emu_no_pcie.read_extended_capabilities(
            EXT_CAP_START,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(value, 0);

    // A PCIe device with no extended capabilities returns an all-zero
    // header, terminating the list.
    let mut value = 0xdead_beef;
    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            EXT_CAP_START,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(value, 0);

    // Writes to the (unimplemented) extended region on a non-PCIe device
    // are dropped silently rather than faulting.
    assert!(matches!(
        common_emu_no_pcie.write_extended_capabilities(
            EXT_CAP_START,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234)
        ),
        CommonHeaderResult::Handled
    ));

    // Test writing extended capabilities - PCIe device should accept writes
    assert!(matches!(
        common_emu_pcie.write_extended_capabilities(
            EXT_CAP_START,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234)
        ),
        CommonHeaderResult::Handled
    ));

    // Test invalid offset ranges
    let mut value = 0;
    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            0x99,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Failed(IoError::InvalidRegister)
    ));
    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            EXT_CAP_END,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Failed(IoError::InvalidRegister)
    ));
}

#[test]
fn test_unimplemented_capability_region_reads_zero() {
    // Unimplemented registers in the standard capability region of a
    // present function read as 0.
    let mut common_emu = ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        // A single small capability at the start of the region; everything
        // past it is unimplemented.
        vec![Box::new(ReadOnlyCapability::new("foo", 0))],
        vec![],
        DeviceBars::new(),
    );

    // An offset well past the implemented capability reads as 0.
    let mut value = 0xdead_beef;
    assert!(matches!(
        common_emu.read_capabilities(
            0x90,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(value, 0);

    // Writes to the unimplemented region are dropped silently.
    assert!(matches!(
        common_emu.write_capabilities(0x90, ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234)),
        CommonHeaderResult::Handled
    ));
}

#[test]
fn test_type1_acs_extended_capability() {
    let mut common_emu_pcie = ConfigSpaceCommonHeaderEmulatorType1::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::BRIDGE_PCI_TO_PCI,
            base_class: ClassCode::BRIDGE,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(PciExpressCapability::new(
            DevicePortType::RootPort,
            None,
        ))],
        vec![Box::new(AcsExtendedCapability::new())],
        DeviceBars::new(),
    );

    let mut value = 0;
    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            EXT_CAP_START,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(value, 0x0001_000d);

    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            0x104,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(value as u16, 0x005f);
    assert_eq!((value >> 16) as u16, 0x0000);

    assert!(matches!(
        common_emu_pcie.write_extended_capabilities(
            0x104,
            ByteEnabledDwordWrite::with_all_bytes_enabled(0xffff_0000),
        ),
        CommonHeaderResult::Handled
    ));
    assert!(matches!(
        common_emu_pcie.read_extended_capabilities(
            0x104,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut value)
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!((value >> 16) as u16, 0x005f);
}

#[test]
fn test_type0_emulator_save_restore() {
    // Test Type 0 emulator save/restore
    let mut emu = create_type0_emulator(vec![]);

    // Modify some state by writing to command register
    emu.write_u32(0x04, 0x0007); // Enable some command bits

    // Read back and verify
    assert_eq!(emu.read_u32(0x04) & 0x0007, 0x0007);

    // Write to latency timer / interrupt register
    emu.write_u32(0x3C, 0x0040_0000); // Set latency_timer

    // Save the state
    let saved_state = emu.save().expect("save should succeed");

    // Reset the emulator
    emu.reset();

    // Verify state is reset
    assert_eq!(emu.read_u32(0x04) & 0x0007, 0x0000); // Should be reset

    // Restore the state
    emu.restore(saved_state).expect("restore should succeed");

    // Verify state is restored
    assert_eq!(emu.read_u32(0x04) & 0x0007, 0x0007); // Should be restored
}

#[test]
fn test_type1_emulator_save_restore() {
    // Test Type 1 emulator save/restore
    let mut emu = create_type1_emulator(vec![]);

    // Modify some state
    emu.write_u32(0x04, 0x0003); // Enable command bits
    emu.write_u32(0x18, 0x0012_1000); // Set bus numbers
    emu.write_u32(0x20, 0xFFF0_FF00); // Set memory range
    emu.write_u32(0x24, 0xFFF0_FF00); // Set prefetch range
    emu.write_u32(0x28, 0x00AA_BBCC); // Set prefetch base upper
    emu.write_u32(0x2C, 0x00DD_EEFF); // Set prefetch limit upper
    emu.write_u32(0x3C, 0x0001_0000); // Set bridge control

    // Verify values
    assert_eq!(emu.read_u32(0x04) & 0x0003, 0x0003);
    assert_eq!(emu.read_u32(0x18), 0x0012_1000);
    assert_eq!(emu.read_u32(0x20), 0xFFF0_FF00);
    assert_eq!(emu.read_u32(0x28), 0x00AA_BBCC);
    assert_eq!(emu.read_u32(0x2C), 0x00DD_EEFF);
    assert_eq!(emu.read_u32(0x3C) >> 16, 0x0001); // bridge_control

    // Save the state
    let saved_state = emu.save().expect("save should succeed");

    // Reset the emulator
    emu.reset();

    // Verify state is reset
    let test_val = emu.read_u32(0x04);
    assert_eq!(test_val & 0x0003, 0x0000);
    let test_val = emu.read_u32(0x18);
    assert_eq!(test_val, 0x0000_0000);

    // Restore the state
    emu.restore(saved_state).expect("restore should succeed");

    // Verify state is restored
    assert_eq!(emu.read_u32(0x04) & 0x0003, 0x0003);
    assert_eq!(emu.read_u32(0x18), 0x0012_1000);
    assert_eq!(emu.read_u32(0x20), 0xFFF0_FF00);
    assert_eq!(emu.read_u32(0x28), 0x00AA_BBCC);
    assert_eq!(emu.read_u32(0x2C), 0x00DD_EEFF);
    assert_eq!(emu.read_u32(0x3C) >> 16, 0x0001); // bridge_control
}

#[test]
fn test_type1_emulator_save_restore_with_extended_capabilities() {
    let mut emu = ConfigSpaceType1Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::BRIDGE_PCI_TO_PCI,
            base_class: ClassCode::BRIDGE,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![Box::new(PciExpressCapability::new(
            DevicePortType::RootPort,
            None,
        ))],
        vec![Box::new(AcsExtendedCapability::new())],
    );

    // Enable all supported ACS control bits.
    emu.write_u32(0x104, 0xffff_0000);

    assert_eq!((emu.read_u32(0x104) >> 16) as u16, 0x005f);

    let saved_state = emu.save().expect("save should succeed");

    emu.reset();
    assert_eq!((emu.read_u32(0x104) >> 16) as u16, 0);

    emu.restore(saved_state).expect("restore should succeed");
    assert_eq!((emu.read_u32(0x104) >> 16) as u16, 0x005f);
}

#[test]
fn test_config_space_type1_set_presence_detect_state() {
    // Test that ConfigSpaceType1Emulator can set presence detect state
    // when it has a PCIe Express capability with hotplug support

    // Create a PCIe Express capability with hotplug support
    let pcie_cap =
        PciExpressCapability::new(DevicePortType::RootPort, None).with_hotplug_support(1);

    let mut emulator = create_type1_emulator(vec![Box::new(pcie_cap)]);

    // Initially, presence detect state should be 0
    let slot_status_val = emulator.read_u32(COMMON_HEADER_END + 0x18); // COMMON_HEADER_END (cap start) + 0x18 (slot control/status)
    let initial_presence_detect = (slot_status_val >> 22) & 0x1; // presence_detect_state is bit 6 of slot status
    assert_eq!(
        initial_presence_detect, 0,
        "Initial presence detect state should be 0"
    );

    // Set device as present
    emulator.set_presence_detect_state(true);
    let slot_status_val = emulator.read_u32(0x58);
    let present_presence_detect = (slot_status_val >> 22) & 0x1;
    assert_eq!(
        present_presence_detect, 1,
        "Presence detect state should be 1 when device is present"
    );

    // Set device as not present
    emulator.set_presence_detect_state(false);
    let slot_status_val = emulator.read_u32(0x58);
    let absent_presence_detect = (slot_status_val >> 22) & 0x1;
    assert_eq!(
        absent_presence_detect, 0,
        "Presence detect state should be 0 when device is not present"
    );
}

#[test]
fn test_config_space_type1_set_presence_detect_state_without_pcie() {
    // Test that ConfigSpaceType1Emulator silently ignores set_presence_detect_state
    // when there is no PCIe Express capability

    let mut emulator = create_type1_emulator(vec![]); // No capabilities

    // Should not panic and should be silently ignored
    emulator.set_presence_detect_state(true);
    emulator.set_presence_detect_state(false);
}

#[test]
fn test_interrupt_pin_register() {
    use vmcore::line_interrupt::LineInterrupt;

    // Test Type 0 device with interrupt pin configured
    let mut emu = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        DeviceBars::new(),
    );

    // Initially, no interrupt pin should be configured
    assert_eq!(emu.read_u32(0x3C) & 0xFF00, 0); // Interrupt pin should be 0

    // Configure interrupt pin A
    let line_interrupt = LineInterrupt::detached();
    emu.set_interrupt_pin(PciInterruptPin::IntA, line_interrupt);

    // Read the register again
    assert_eq!((emu.read_u32(0x3C) >> 8) & 0xFF, 1); // Interrupt pin should be 1 (INTA)

    // Set interrupt line to 0x42 and verify both pin and line are correct
    emu.write_u32(0x3C, 0x00110042); // Latency=0x11, pin=ignored, line=0x42
    let val = emu.read_u32(0x3C);
    assert_eq!(val & 0xFF, 0x42); // Interrupt line should be 0x42
    assert_eq!((val >> 8) & 0xFF, 1); // Interrupt pin should still be 1 (writes ignored)
    assert_eq!((val >> 16) & 0xFF, 0x11); // Latency timer should be 0x11

    // Test with interrupt pin D
    let mut emu_d = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        DeviceBars::new(),
    );

    let line_interrupt_d = LineInterrupt::detached();
    emu_d.set_interrupt_pin(PciInterruptPin::IntD, line_interrupt_d);

    assert_eq!((emu_d.read_u32(0x3C) >> 8) & 0xFF, 4); // Interrupt pin should be 4 (INTD)
}

#[test]
fn test_header_type_functionality() {
    // Test HeaderType enum values
    assert_eq!(HeaderType::Type0.bar_count(), 6);
    assert_eq!(HeaderType::Type1.bar_count(), 2);
    assert_eq!(usize::from(HeaderType::Type0), 6);
    assert_eq!(usize::from(HeaderType::Type1), 2);

    // Test constant values
    assert_eq!(header_type_consts::TYPE0_BAR_COUNT, 6);
    assert_eq!(header_type_consts::TYPE1_BAR_COUNT, 2);

    // Test Type 0 emulator
    let emu_type0 = create_type0_emulator(vec![]);
    assert_eq!(emu_type0.common.bar_count(), 6);
    assert_eq!(emu_type0.common.header_type(), HeaderType::Type0);
    assert!(emu_type0.common.validate_header_type(HeaderType::Type0));
    assert!(!emu_type0.common.validate_header_type(HeaderType::Type1));

    // Test Type 1 emulator
    let emu_type1 = create_type1_emulator(vec![]);
    assert_eq!(emu_type1.common.bar_count(), 2);
    assert_eq!(emu_type1.common.header_type(), HeaderType::Type1);
    assert!(emu_type1.common.validate_header_type(HeaderType::Type1));
    assert!(!emu_type1.common.validate_header_type(HeaderType::Type0));
}

/// Ensure that `find_bar` correctly returns a full `u64` offset for BARs
/// larger than 64KiB, guarding against truncation back to `u16`.
#[test]
fn find_bar_returns_full_u64_offset_for_large_bar() {
    use crate::bar_mapping::BarMappings;

    // Set up a 64-bit BAR0 at base address 0x1_0000_0000 with size
    // 0x2_0000 (128KiB). The mask encodes the size via the complement:
    //   mask = !(size - 1) = !(0x1_FFFF) = 0xFFFF_FFFE_0000
    // Split across two 32-bit BAR registers (BAR0 low + BAR1 high).
    let bar_base: u64 = 0x1_0000_0000;
    let bar_size: u64 = 0x2_0000; // 128KiB — larger than u16::MAX
    let mask64 = !(bar_size - 1); // 0xFFFF_FFFE_0000

    let mut base_addresses = [0u32; 6];
    let mut bar_masks = [0u32; 6];

    // BAR0 low: set the 64-bit type bit in the mask and the base address.
    bar_masks[0] = cfg_space::BarEncodingBits::from_bits(mask64 as u32)
        .with_type_64_bit(true)
        .into_bits();
    bar_masks[1] = (mask64 >> 32) as u32;
    base_addresses[0] = bar_base as u32;
    base_addresses[1] = (bar_base >> 32) as u32;

    let bar_mappings = BarMappings::parse(&base_addresses, &bar_masks);

    // Query an address whose offset within BAR0 exceeds 0xFFFF.
    let expected_offset: u64 = 0x1_2345;
    let address: u64 = bar_base + expected_offset;

    let (found_bar, offset) = bar_mappings
        .find(address)
        .expect("address should resolve to BAR 0");
    assert_eq!(found_bar, 0);
    assert_eq!(offset, expected_offset);
}

#[test]
fn test_odd_index_64bit_bar_preserves_attrs_only_on_lower_dword() {
    let mut bars = DeviceBars::new();
    bars.bars[1] = Some((4096, BarMemoryKind::Dummy));

    let mut common_emu = ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        bars,
    );

    // BAR1 is the lower dword of a 64-bit BAR and should preserve
    // encoding bits (type + prefetchable).
    assert!(matches!(
        common_emu.write(
            PciConfigAddress::new(0, 0, 0x14 / 4).unwrap(),
            ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234_5000),
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(common_emu.base_addresses()[1] & 0xF, 0xC);

    // BAR2 is the upper dword and must not be treated as encoding bits.
    assert!(matches!(
        common_emu.write(
            PciConfigAddress::new(0, 0, 0x18 / 4).unwrap(),
            ByteEnabledDwordWrite::with_all_bytes_enabled(0x89ab_cde5),
        ),
        CommonHeaderResult::Handled
    ));
    assert_eq!(common_emu.base_addresses()[2] & 0xF, 0x5);
}

#[test]
fn test_32bit_bar_preserves_attr_bits_without_clobbering_address_bits() {
    let mut common_emu = ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        DeviceBars::new(),
    );

    // Force BAR0 to behave like a 32-bit mapped BAR with the prefetchable
    // bit set. This validates low-nibble preservation independent of
    // current DeviceBars construction defaults.
    common_emu.bar_masks[0] = 0xffff_fff0 | 0x8;
    common_emu.mapped_memory[0] = Some(BarMemoryKind::Dummy);

    assert!(matches!(
        common_emu.write(
            PciConfigAddress::new(0, 0, 0x10 / 4).unwrap(),
            ByteEnabledDwordWrite::with_all_bytes_enabled(0x1234_5670),
        ),
        CommonHeaderResult::Handled
    ));

    // Low nibble should retain BAR attribute bits from the mask while
    // higher address bits should come from the guest write and BAR mask.
    assert_eq!(common_emu.base_addresses()[0], 0x1234_5678);
}

// A `ControlMmioIntercept` test double that records map/unmap. Like some
// real intercept implementations (e.g. the PCIe test intercept), its
// `unmap()` panics if called while not mapped -- so these tests also verify
// that teardown never unmaps a BAR that was never mapped.
struct TrackingBar {
    len: u64,
    addr: Option<u64>,
    mapped: Arc<AtomicBool>,
}

impl ControlMmioIntercept for TrackingBar {
    fn region_name(&self) -> &str {
        "bar0"
    }
    fn map(&mut self, addr: u64) {
        self.addr = Some(addr);
        self.mapped.store(true, Ordering::SeqCst);
    }
    fn unmap(&mut self) {
        assert!(self.addr.is_some(), "unmap called while not mapped");
        self.addr = None;
        self.mapped.store(false, Ordering::SeqCst);
    }
    fn addr(&self) -> Option<u64> {
        self.addr
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn offset_of(&self, addr: u64) -> Option<u64> {
        let base = self.addr?;
        (base..base + self.len).contains(&addr).then(|| addr - base)
    }
}

fn config_space_with_intercept_bar(
    mapped: Arc<AtomicBool>,
) -> ConfigSpaceCommonHeaderEmulatorType0 {
    let bars = DeviceBars::new().bar0(
        0x1000,
        BarMemoryKind::Intercept(Box::new(TrackingBar {
            len: 0x1000,
            addr: None,
            mapped,
        })),
    );
    ConfigSpaceCommonHeaderEmulatorType0::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0,
            type0_sub_system_id: 0,
        },
        vec![],
        vec![],
        bars,
    )
}

// Regression test for a PCIe hot-add-after-remove failure: when a device's
// config space is dropped (e.g. a hot-removed controller being torn down),
// its BAR intercept registrations must be released. Otherwise the stale
// range stays in the chipset's shared range map and a subsequent device
// that reuses the same GPA fails to install its intercept, leaving its BAR
// undispatched (guest reads all-1s -> stornvme FindAdapter reads CAP=~0).
#[test]
fn dropping_config_space_unmaps_bar_intercepts() {
    let mapped = Arc::new(AtomicBool::new(false));
    let mut common_emu = config_space_with_intercept_bar(mapped.clone());

    // Program BAR0's base address and enable memory space so the BAR
    // intercept is mapped into the chipset's range map.
    common_emu.set_base_addresses(&[0x2000_0000, 0, 0, 0, 0, 0]);
    common_emu.update_mmio_enabled(true);
    assert!(
        mapped.load(Ordering::SeqCst),
        "BAR intercept should be mapped once memory space is enabled"
    );

    // Dropping the config space (device teardown / hot-remove) must unmap
    // the BAR intercept so its range is released.
    drop(common_emu);
    assert!(
        !mapped.load(Ordering::SeqCst),
        "dropping config space must unmap its BAR intercepts"
    );
}

// A device can be torn down before the guest ever enables memory space (so
// the BAR was never mapped). Dropping its config space must not attempt to
// unmap the never-mapped intercept -- which would panic for intercept impls
// whose `unmap()` is not idempotent (as `TrackingBar::unmap` asserts here).
#[test]
fn dropping_config_space_without_mmio_enabled_does_not_unmap() {
    let mapped = Arc::new(AtomicBool::new(false));
    let common_emu = config_space_with_intercept_bar(mapped.clone());

    // Never enabled memory space -> BAR never mapped. Dropping must be a
    // no-op for the intercept and must not panic.
    drop(common_emu);
    assert!(!mapped.load(Ordering::SeqCst));
}

#[test]
fn test_type1_bdf_capturing() {
    // Test that the type1 config space emulator captures
    // the BDF of accesses it receives.
    let mut type1_emulator = create_type1_emulator(vec![]);

    // Initially, the captured BDF should be 0.
    assert_eq!(type1_emulator.captured_bus_number(), 0);
    assert_eq!(type1_emulator.captured_devfn(), 0);

    // Reads do not capture the BDF.
    let mut read_value = 0;
    let _ = type1_emulator.read(
        PciConfigAddress::new(1, 1, 0).unwrap(),
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut read_value),
    );
    assert_eq!(type1_emulator.captured_bus_number(), 0);
    assert_eq!(type1_emulator.captured_devfn(), 0);

    // Writes capture the BDF.
    let _ = type1_emulator.write(
        PciConfigAddress::new(1, 1, 0).unwrap(),
        ByteEnabledDwordWrite::with_all_bytes_enabled(0xdead_beef),
    );
    assert_eq!(type1_emulator.captured_bus_number(), 1);
    assert_eq!(type1_emulator.captured_devfn(), 1);

    // And writing a new BDF overwrites the old.
    let _ = type1_emulator.write(
        PciConfigAddress::new(4, 1, 0).unwrap(),
        ByteEnabledDwordWrite::with_all_bytes_enabled(0xdead_beef),
    );
    assert_eq!(type1_emulator.captured_bus_number(), 4);
    assert_eq!(type1_emulator.captured_devfn(), 1);

    // Save state with BDF captured.
    let saved_state = type1_emulator.save().expect("save should succeed");

    // Captured BDF should be cleared on reset.
    type1_emulator.reset();
    assert_eq!(type1_emulator.captured_bus_number(), 0);
    assert_eq!(type1_emulator.captured_devfn(), 0);

    // Restore the state, captured BDF should be restored.
    type1_emulator
        .restore(saved_state)
        .expect("restore should succeed");
    assert_eq!(type1_emulator.captured_bus_number(), 4);
    assert_eq!(type1_emulator.captured_devfn(), 1);
}

#[test]
fn test_type0_bdf_capturing() {
    // Test that the type0 config space emulator captures
    // the BDF of accesses it receives.
    let mut type0_emulator = create_type0_emulator(vec![]);

    // Initially, the captured BDF should be 0.
    assert_eq!(type0_emulator.captured_bus_number(), 0);
    assert_eq!(type0_emulator.captured_devfn(), 0);

    // Reads do not capture the BDF.
    let mut read_value = 0;
    let _ = type0_emulator.read(
        PciConfigAddress::new(1, 1, 0).unwrap(),
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut read_value),
    );
    assert_eq!(type0_emulator.captured_bus_number(), 0);
    assert_eq!(type0_emulator.captured_devfn(), 0);

    // Writes capture the BDF.
    let _ = type0_emulator.write(
        PciConfigAddress::new(1, 1, 0).unwrap(),
        ByteEnabledDwordWrite::with_all_bytes_enabled(0xdead_beef),
    );
    assert_eq!(type0_emulator.captured_bus_number(), 1);
    assert_eq!(type0_emulator.captured_devfn(), 1);

    // And writing a new BDF overwrites the old.
    let _ = type0_emulator.write(
        PciConfigAddress::new(4, 1, 0).unwrap(),
        ByteEnabledDwordWrite::with_all_bytes_enabled(0xdead_beef),
    );
    assert_eq!(type0_emulator.captured_bus_number(), 4);
    assert_eq!(type0_emulator.captured_devfn(), 1);

    // Save state with BDF captured.
    let saved_state = type0_emulator.save().expect("save should succeed");

    // Captured BDF should be cleared on reset.
    type0_emulator.reset();
    assert_eq!(type0_emulator.captured_bus_number(), 0);
    assert_eq!(type0_emulator.captured_devfn(), 0);

    // Restore the state, captured BDF should be restored.
    type0_emulator
        .restore(saved_state)
        .expect("restore should succeed");
    assert_eq!(type0_emulator.captured_bus_number(), 4);
    assert_eq!(type0_emulator.captured_devfn(), 1);
}

fn assert_capability_checkpoint<T>(
    create: impl FnOnce(Vec<Box<dyn PciCapability>>, Vec<Box<dyn PciExtendedCapability>>) -> T,
    reset: fn(&mut T),
) where
    T: TestCfgAccess
        + SaveRestore<SavedState = <ConfigSpaceType0Emulator as SaveRestore>::SavedState>,
{
    use crate::capabilities::msi_cap::MsiCapability;
    use crate::msi::MsiConnection;
    use crate::test_helpers::TestPciInterruptController;
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let msi = MsiCapability::new(0, true, false, &connection.target());
    let interrupt = msi.interrupt().unwrap();
    let mut emulator = create(
        vec![
            Box::new(msi),
            Box::new(ReadOnlyCapability::new("vendor", 0u32)),
            Box::new(PciExpressCapability::new(DevicePortType::RootPort, None)),
        ],
        vec![Box::new(AcsExtendedCapability::new())],
    );
    emulator.write_u32(0x44, 0xfee03000);
    emulator.write_u32(0x48, 1);
    emulator.write_u32(0x4c, 0x71);
    emulator.write_u32(0x40, 0x00010000);
    emulator.write_u32(0x104, 0x005f0000);
    assert_eq!(emulator.read_u32(0x104) >> 16, 0x005f);
    let mut saved = emulator.save().unwrap();
    saved.capabilities.reverse();
    reset(&mut emulator);
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(emulator.read_u32(0x104) >> 16, 0);
    emulator.restore(saved).unwrap();
    assert_eq!(emulator.read_u32(0x44), 0xfee03000);
    assert_eq!(emulator.read_u32(0x48), 1);
    assert_eq!(emulator.read_u32(0x4c), 0x71);
    assert_eq!(emulator.read_u32(0x104) >> 16, 0x005f);
    assert_eq!(controller.get_next_interrupt(), Some((0x1fee03000, 0x71)));
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0x1fee03000, 0x71)));
    assert_eq!(controller.get_next_interrupt(), None);
}

// Test: Restore reordered standard and extended capability checkpoints on a device.
// Expected: Reset stops delivery; restoration recovers ACS controls and the MSI route by label.
#[test]
fn type0_checkpoint_restores_capabilities_by_label_and_actual_delivery() {
    assert_capability_checkpoint(create_type0_with_extended, ConfigSpaceType0Emulator::reset);
}

// Test: Restore reordered standard and extended capability checkpoints on a bridge.
// Expected: Reset stops delivery; restoration recovers ACS controls and the MSI route by label.
#[test]
fn type1_checkpoint_restores_capabilities_by_label_and_actual_delivery() {
    assert_capability_checkpoint(create_type1_with_extended, ConfigSpaceType1Emulator::reset);
}

fn assert_invalid_checkpoints<T>(mut emulator: T)
where
    T: SaveRestore<SavedState = <ConfigSpaceType0Emulator as SaveRestore>::SavedState>,
{
    for kind in 0..3 {
        let mut saved = emulator.save().unwrap();
        if kind == 2 {
            saved.command = u16::MAX;
        } else {
            let mut capability = ReadOnlyCapability::new("absent", 0u32);
            let blob = vmcore::save_restore::ProtobufSaveRestore::save(&mut capability).unwrap();
            let entries = if kind == 0 {
                &mut saved.capabilities
            } else {
                &mut saved.extended_capabilities
            };
            entries.push(("absent".into(), blob));
        }
        let error = emulator.restore(saved).unwrap_err();
        let vmcore::save_restore::RestoreError::InvalidSavedState(error) = error else {
            panic!("expected invalid saved state, got {error:?}");
        };
        if kind < 2 {
            assert!(error.to_string().contains("absent"), "{error}");
        }
    }
}

// Test: Restore device checkpoints with unknown capabilities or unsupported command bits.
// Expected: Every invalid checkpoint is rejected and unknown capability errors name the label.
#[test]
fn type0_rejects_unknown_capabilities_and_invalid_commands() {
    assert_invalid_checkpoints(create_type0_emulator(vec![]));
}

// Test: Restore bridge checkpoints with unknown capabilities or unsupported command bits.
// Expected: Every invalid checkpoint is rejected and unknown capability errors name the label.
#[test]
fn type1_rejects_unknown_capabilities_and_invalid_commands() {
    assert_invalid_checkpoints(create_type1_emulator(vec![]));
}

fn assert_byte_enabled_entry_points<T: TestCfgAccess>(
    mut emulator: T,
    read: fn(&T, u16, ByteEnabledDwordRead<'_>) -> IoResult,
    write: fn(&mut T, u16, ByteEnabledDwordWrite) -> IoResult,
) {
    write(
        &mut emulator,
        4,
        ByteEnabledDwordWrite::new(2, PciConfigByteEnable::from_offset_len(4, 1).unwrap()),
    )
    .unwrap();
    write(
        &mut emulator,
        4,
        ByteEnabledDwordWrite::new(0, PciConfigByteEnable::from_offset_len(5, 1).unwrap()),
    )
    .unwrap();
    let mut value = 0;
    read(
        &emulator,
        4,
        ByteEnabledDwordRead::with_all_bytes_enabled(&mut value),
    )
    .unwrap();
    assert_eq!(value & 0xffff, 2);
    for offset in [1, 0x1000, 0xfffc] {
        let mut unchanged = 0xdeadbeef;
        let read_result = read(
            &emulator,
            offset,
            ByteEnabledDwordRead::with_all_bytes_enabled(&mut unchanged),
        );
        let write_result = write(
            &mut emulator,
            offset,
            ByteEnabledDwordWrite::with_all_bytes_enabled(u32::MAX),
        );
        for result in [read_result, write_result] {
            if offset == 1 {
                assert!(matches!(result, IoResult::Err(IoError::UnalignedAccess)));
            } else {
                assert!(matches!(result, IoResult::Err(IoError::InvalidRegister)));
            }
        }
        assert_eq!(unchanged, 0xdeadbeef);
        assert_eq!(emulator.read_u32(4) & 0xffff, 2);
    }
}

// Test: Use a multifunction device's byte-enabled entry points with valid and invalid offsets.
// Expected: Header identity and byte masks are preserved; bad accesses fail without mutation.
#[test]
fn type0_byte_enabled_access_preserves_masks_and_rejects_invalid_offsets() {
    let emulator = create_type0_emulator(vec![]).with_multi_function_bit(true);
    assert_eq!(emulator.read_u32(0x0c) & 0x00ff0000, 0x00800000);
    assert_byte_enabled_entry_points(
        emulator,
        ConfigSpaceType0Emulator::read_byte_enabled,
        ConfigSpaceType0Emulator::write_byte_enabled,
    );
}

// Test: Use a multifunction bridge's byte-enabled entry points with valid and invalid offsets.
// Expected: Header identity and byte masks are preserved; bad accesses fail without mutation.
#[test]
fn type1_byte_enabled_access_preserves_masks_and_rejects_invalid_offsets() {
    let emulator = create_type1_emulator(vec![]).with_multi_function_bit(true);
    assert_eq!(emulator.read_u32(0x0c) & 0x00ff0000, 0x00810000);
    assert_byte_enabled_entry_points(
        emulator,
        ConfigSpaceType1Emulator::read_byte_enabled,
        ConfigSpaceType1Emulator::write_byte_enabled,
    );
}

#[derive(Debug, PartialEq, Eq)]
enum SharedBarCall {
    Map(u64, bool),
    Unmap,
}

struct TrackingSharedBar {
    calls: Arc<parking_lot::Mutex<Vec<SharedBarCall>>>,
    fail_mapping: bool,
}

impl MappableGuestMemory for TrackingSharedBar {
    fn map_to_guest(&mut self, gpa: u64, writable: bool) -> std::io::Result<()> {
        self.calls.lock().push(SharedBarCall::Map(gpa, writable));
        if self.fail_mapping {
            Err(std::io::Error::other("injected BAR mapping failure"))
        } else {
            Ok(())
        }
    }

    fn unmap_from_guest(&mut self) {
        self.calls.lock().push(SharedBarCall::Unmap);
    }
}

fn assert_bar_lifecycle(fail_mapping: bool) {
    let intercepted = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let bars = DeviceBars::new()
        .bar0(
            0x1000,
            BarMemoryKind::Intercept(Box::new(TrackingBar {
                len: 0x1000,
                addr: None,
                mapped: intercepted.clone(),
            })),
        )
        .bar2(
            0x2000,
            BarMemoryKind::SharedMem(Box::new(TrackingSharedBar {
                calls: calls.clone(),
                fail_mapping,
            })),
        )
        .bar4(0x4000, BarMemoryKind::Dummy);
    let mut emulator = ConfigSpaceType0Emulator::new(
        HardwareIds {
            vendor_id: 0x1111,
            device_id: 0x2222,
            revision_id: 1,
            prog_if: ProgrammingInterface::NONE,
            sub_class: Subclass::NONE,
            base_class: ClassCode::UNCLASSIFIED,
            type0_sub_vendor_id: 0x3333,
            type0_sub_system_id: 0x4444,
        },
        vec![],
        vec![],
        bars,
    );
    for (offset, value) in [
        (0x10, 0x80000000),
        (0x18, 0x90000000),
        (0x1c, 1),
        (0x20, 0xa0000000),
        (0x24, 2),
    ] {
        emulator.write_u32(offset, value);
    }
    assert_eq!(emulator.bar_address(0), None);
    assert_eq!(emulator.find_bar(0x80000000), None);
    emulator.write_u32(4, 2);
    assert!(intercepted.load(Ordering::SeqCst));
    assert_eq!(*calls.lock(), [SharedBarCall::Map(0x190000000, true)]);
    for (bar, base, len) in [
        (0, 0x80000000, 0x1000),
        (2, 0x190000000, 0x2000),
        (4, 0x2a0000000, 0x4000),
    ] {
        assert_eq!(emulator.bar_address(bar), Some(base));
        assert_eq!(emulator.find_bar(base), Some((bar, 0)));
        assert_eq!(emulator.find_bar(base + len - 1), Some((bar, len - 1)));
        assert_eq!(emulator.find_bar(base + len), None);
    }
    assert_eq!(emulator.bar_address(1), None);
    emulator.write_u32(0x10, 0x81000000);
    assert_eq!(emulator.read_u32(0x10) & !0xf, 0x80000000);
    emulator.write_u32(4, 0);
    assert!(!intercepted.load(Ordering::SeqCst));
    assert_eq!(
        *calls.lock(),
        [SharedBarCall::Map(0x190000000, true), SharedBarCall::Unmap]
    );
    assert_eq!(emulator.find_bar(0x80000000), None);
    assert_eq!(emulator.bar_address(0), None);
    emulator.write_u32(0x10, 0x81000000);
    emulator.write_u32(4, 2);
    assert_eq!(emulator.bar_address(0), Some(0x81000000));
    assert!(intercepted.load(Ordering::SeqCst));
    emulator.reset();
    assert!(!intercepted.load(Ordering::SeqCst));
    assert_eq!(emulator.bar_address(0), None);
}

// Test: Enable, disable, reprogram, and reset intercept/shared/dummy BARs.
// Expected: Mapping calls and boundary lookups follow decoding; enabled BAR writes are ignored.
#[test]
fn bar_mapping_lifecycle_tracks_decoding_and_reprogramming() {
    assert_bar_lifecycle(false);
}

// Test: Enable a device whose shared-memory BAR fails to map beside other BARs.
// Expected: The map failure does not abort intercept mapping, decoding updates, or reset cleanup.
#[test]
fn failed_shared_bar_mapping_does_not_abort_other_bar_lifecycle() {
    assert_bar_lifecycle(true);
}

// Test: Read chained capability headers with all bytes, only the pointer, and only the ID enabled.
// Expected: Next pointers follow the chain and all disabled bytes retain the caller's sentinel.
#[test]
fn capability_chain_pointers_preserve_disabled_byte_lanes() {
    let emulator = create_type0_emulator(vec![
        Box::new(ReadOnlyCapability::new("first", 0xaabb0009u32)),
        Box::new(ReadOnlyCapability::new("last", 0x11220009u32)),
    ]);
    assert_eq!(emulator.read_u32(0x34), 0x40);
    assert_eq!(emulator.read_u32(0x40), 0xaabb4409);
    assert_eq!(emulator.read_u32(0x44), 0x11220009);
    for (offset, mask, expected) in [
        (0x40, PciConfigByteEnable::BYTE1, 0xdead44ef),
        (0x44, PciConfigByteEnable::BYTE1, 0xdead00ef),
        (0x40, PciConfigByteEnable::BYTE0, 0xdeadbe09),
        (0x40, PciConfigByteEnable::HIGH_WORD, 0xaabbbeef),
    ] {
        let mut value = 0xdeadbeef;
        emulator
            .read_byte_enabled(offset, ByteEnabledDwordRead::new(&mut value, mask))
            .unwrap();
        assert_eq!(value, expected);
    }
}

// Test: Write read-only Type 0 header fields after programming latency and interrupt line.
// Expected: Subsystem IDs, reserved fields, header type, and latency remain correctly encoded.
#[test]
fn type0_header_identity_and_reserved_registers_ignore_writes() {
    let mut emulator = create_type0_emulator(vec![]);
    emulator.write_u32(0x3c, 0x00550042);
    for (offset, expected) in [
        (0x0c, 0x5500),
        (0x28, 0),
        (0x2c, 0x44443333),
        (0x30, 0),
        (0x38, 0),
    ] {
        assert_eq!(emulator.read_u32(offset), expected);
        emulator.write_u32(offset, u32::MAX);
        assert_eq!(emulator.read_u32(offset), expected);
    }
    assert_eq!(emulator.read_u32(0x3c), 0x00550042);
}

// Test: Observe a bridge's shared bus range across guest writes, reset, restore, and inversion.
// Expected: The existing handle follows every update and an inverted range contains no buses.
#[test]
fn bridge_bus_range_handle_tracks_writes_reset_and_restore() {
    let mut emulator = create_type1_emulator(vec![]);
    let handle = emulator.bus_range();
    emulator.write_u32(0x18, 0x00341200);
    assert_eq!(handle.bus_range(), (0x12, 0x34));
    assert!(handle.contains_bus(0x12));
    assert!(handle.contains_bus(0x34));
    assert!(!handle.contains_bus(0x35));
    let saved = emulator.save().unwrap();
    emulator.reset();
    assert_eq!(handle.bus_range(), (0, 0));
    emulator.restore(saved).unwrap();
    assert_eq!(handle.bus_range(), (0x12, 0x34));
    emulator.write_u32(0x18, 0x00102000);
    assert_eq!(handle.bus_range(), (0x20, 0x10));
    for bus in 0x10..=0x20 {
        assert!(!handle.contains_bus(bus));
    }
}
