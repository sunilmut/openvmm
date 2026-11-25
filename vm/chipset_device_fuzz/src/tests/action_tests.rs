// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Generate actions from deterministic entropy spanning all selector values on a chipset with every transport registered, then execute each action.
// Expected: Every action kind is reachable, addresses/BDFs and widths are supported, PCI offsets are aligned, write payloads retain input bytes, and generated routes are executable.
#[test]
fn generated_actions_respect_registered_routes_widths_and_payload_entropy() {
    let (chipset, _) = chipset(false);
    let mut seen = 0;
    for seed in 0..=u8::MAX {
        let input = [seed; 64];
        let action = chipset
            .get_arbitrary_action(&mut arbitrary::Unstructured::new(&input))
            .unwrap();
        let kind = match &action {
            ChipsetAction::MmioRead { addr, len } => {
                assert!((0x1000..=0x100f).contains(addr));
                assert!([1, 2, 4, 8].contains(len));
                0
            }
            ChipsetAction::MmioWrite { addr, val } => {
                assert!((0x1000..=0x100f).contains(addr));
                assert!([1, 2, 4, 8].contains(&val.len()));
                assert!(val.iter().all(|byte| *byte == seed));
                1
            }
            ChipsetAction::PortIoRead { addr, len } => {
                assert!((0x200..=0x207).contains(addr));
                assert!([1, 2, 4].contains(len));
                2
            }
            ChipsetAction::PortIoWrite { addr, val } => {
                assert!((0x200..=0x207).contains(addr));
                assert!([1, 2, 4].contains(&val.len()));
                assert!(val.iter().all(|byte| *byte == seed));
                3
            }
            ChipsetAction::PciRead { bdf, offset } => {
                assert_eq!(*bdf, (2, 3, 1));
                assert_eq!(offset & 3, 0);
                assert!(*offset <= 0xffc);
                4
            }
            ChipsetAction::PciWrite { bdf, offset, val } => {
                assert_eq!(*bdf, (2, 3, 1));
                assert_eq!(offset & 3, 0);
                assert!(*offset <= 0xffc);
                assert_eq!(*val, u32::from_ne_bytes([seed; 4]));
                5
            }
            ChipsetAction::Poll { index } => {
                assert_eq!(*index, 0);
                6
            }
        };
        seen |= 1 << kind;
        assert_eq!(chipset.exec_action(action), Some(()));
    }
    assert_eq!(seen, 0x7f, "all transport kinds must be generated");
}

// Test: Ask an empty chipset for actions using each deterministic entropy selector.
// Expected: Generation reports insufficient choices rather than fabricating an unmapped address, missing PCI device, or invalid poll index.
#[test]
fn empty_chipset_cannot_generate_an_unregistered_action() {
    let chipset = FuzzChipset::default();
    for seed in 0..=u8::MAX {
        let input = [seed; 64];
        assert!(
            chipset
                .get_arbitrary_action(&mut arbitrary::Unstructured::new(&input))
                .is_err()
        );
    }
}
