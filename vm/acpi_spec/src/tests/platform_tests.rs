// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::madt::*;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Serialize x86 interrupt controller defaults and all polarity/trigger combinations.
// Expected: Type/length/reserved/default fields follow ACPI, and interrupt overrides encode polarity in bits 1:0 and trigger in bits 3:2 without changing source/GSI.
#[test]
fn x86_interrupt_records_encode_defaults_and_override_flags() {
    assert_eq!(MadtApic::new().as_bytes(), &[0, 8, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        MadtX2Apic::new().as_bytes(),
        &[9, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        MadtIoApic::new().as_bytes(),
        &[1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(MadtLocalNmiSource::new().as_bytes(), &[4, 6, 1, 0, 0, 1]);
    for polarity in 0..3 {
        for trigger in 0..3 {
            let entry = MadtInterruptSourceOverride::new(
                9,
                0x44332211,
                match polarity {
                    0 => None,
                    1 => Some(InterruptPolarity::ActiveHigh),
                    _ => Some(InterruptPolarity::ActiveLow),
                },
                match trigger {
                    0 => None,
                    1 => Some(InterruptTriggerMode::Edge),
                    _ => Some(InterruptTriggerMode::Level),
                },
            );
            let flags = [0, 1, 3][polarity] | ([0, 1, 3][trigger] << 2);
            assert_eq!(
                entry.as_bytes(),
                &[2, 10, 0, 9, 0x11, 0x22, 0x33, 0x44, flags, 0]
            );
        }
    }
}

// Test: Build ARM GIC distributor, MSI frame, ITS and CPU records with distinctive IDs, addresses and SPI ranges.
// Expected: Entire serialized records have the ACPI type/length, exact non-overlapping fields and zero reserved bytes, including the enabled CPU bit.
#[test]
fn arm_interrupt_records_match_wire_layout() {
    let address = 0x8877665544332211;
    assert_eq!(
        MadtGicd::new(0x44332211, address, 3).as_bytes(),
        &[
            12, 24, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0, 0, 0, 0, 3, 0, 0, 0
        ]
    );
    assert_eq!(
        MadtGicMsiFrame::new(0x44332211, address, 0x6655, 0xaa99).as_bytes(),
        &[
            13, 24, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            1, 0, 0, 0, 0x99, 0xaa, 0x55, 0x66
        ]
    );
    assert_eq!(
        MadtGicIts::new(0x44332211, address).as_bytes(),
        &[
            15, 20, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0, 0, 0, 0
        ]
    );
    let mut expected = [0; 80];
    expected[0] = 11;
    expected[1] = 80;
    expected[8..12].copy_from_slice(&0x44332211u32.to_le_bytes());
    expected[12] = 1;
    expected[68..76].copy_from_slice(&address.to_le_bytes());
    assert_eq!(MadtGicc::new(0x44332211, address).as_bytes(), expected);
}

// Test: Assemble a DMAR remapping unit with one PCI scope/path and modify an IVHD unit's flags/length alongside an IOAPIC entry.
// Expected: Advertised lengths include actual children, PCI addresses and MMIO bases retain exact wire bytes, and builders do not overwrite unrelated fields.
#[test]
fn remapping_records_describe_device_scopes_and_special_devices() {
    use crate::dmar::*;
    use crate::ivrs::*;
    assert_eq!(
        Dmar::new(47, 5).as_bytes(),
        &[47, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    let drhd = DmarDrhd::new(1, 0x6655, 0x8877665544332211).with_length(24);
    let scope = DmarDeviceScope::new(1, 0x22);
    let path = DmarDevicePath {
        device: 0x1f,
        function: 7,
    };
    let mut bytes = drhd.as_bytes().to_vec();
    bytes.extend_from_slice(scope.as_bytes());
    bytes.extend_from_slice(path.as_bytes());
    assert_eq!(
        bytes,
        &[
            0, 0, 24, 0, 1, 0, 0x55, 0x66, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 8, 0,
            0, 0, 0x22, 0x1f, 7
        ]
    );
    let original = IvhdType11::new(0x1234, 0x5678, 0x8877665544332211, 9, 0x1122334455667788);
    let mut expected = original.as_bytes().to_vec();
    expected[1] = 0xa5;
    expected[2..4].copy_from_slice(&48u16.to_le_bytes());
    let changed = original.with_length(48).with_flags(0xa5);
    let special = IvhdSpecialDeviceEntry8::ioapic(0x3344, 0x55);
    assert_eq!(special.as_bytes(), &[0x48, 0, 0, 0, 0x55, 0x44, 0x33, 1]);
    let mut table = changed.as_bytes().to_vec();
    table.extend_from_slice(special.as_bytes());
    expected.extend_from_slice(&[0x48, 0, 0, 0, 0x55, 0x44, 0x33, 1]);
    assert_eq!(table, expected);
    assert_eq!(table.len(), 48);
}

// Test: Serialize PPTT processor nodes with trailing resource references, cache defaults and a two-node SLIT matrix.
// Expected: The processor length/count includes the references, cache defaults retain zero invalid fields, and the SLIT count precedes the complete row-major matrix.
#[test]
fn topology_records_account_for_trailing_resources_and_distances() {
    use crate::pptt::*;
    for count in [0, 2] {
        let processor = PpttProcessor::new(count);
        let mut expected = [0; 20];
        expected[1] = 20 + 4 * count;
        expected[16] = count;
        assert_eq!(processor.as_bytes(), expected);
        let mut bytes = processor.as_bytes().to_vec();
        for index in 0..count {
            bytes.extend_from_slice(&(0x100u32 + index as u32 * 28).to_le_bytes());
        }
        assert_eq!(bytes.len(), 20 + 4 * count as usize);
    }
    let mut expected = [0; 28];
    expected[0] = 1;
    expected[1] = 28;
    assert_eq!(PpttCache::new().as_bytes(), expected);
    let mut slit = crate::slit::SlitHeader::new(2).as_bytes().to_vec();
    slit.extend_from_slice(&[10, 20, 20, 10]);
    assert_eq!(slit, &[2, 0, 0, 0, 0, 0, 0, 0, 10, 20, 20, 10]);
}
