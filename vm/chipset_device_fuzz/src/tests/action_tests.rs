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

// Test: Map a device's dynamic MMIO window, move it, then unmap it while issuing accesses at old and new addresses.
// Expected: Only the current window dispatches exact addresses/data once; retired windows are unclaimed and preserve read buffers.
#[test]
fn dynamic_mmio_remapping_retires_old_routes_and_preserves_device_payloads() {
    let mut chipset = FuzzChipset::new(4);
    let accesses = Arc::new(Mutex::new(Vec::new()));
    let mut region = None;
    let device = chipset
        .device_builder("remapping-device")
        .add(|services| {
            region = Some(services.register_mmio().new_io_region("moving-window", 16));
            RecordingDevice {
                accesses: accesses.clone(),
                fail: false,
                defer_polls: None,
                remaining: 0,
                pending: None,
            }
        })
        .unwrap();
    drop(device);
    let mut region = region.unwrap();
    region.map(0x6000);
    let mut byte = [0x5a];
    assert_eq!(chipset.mmio_read(0x600f, &mut byte), Some(()));
    assert_eq!(byte, [0xa0]);
    region.map(0x7000);
    byte.fill(0x5a);
    assert_eq!(chipset.mmio_read(0x600f, &mut byte), None);
    assert_eq!(byte, [0x5a]);
    assert_eq!(chipset.mmio_write(0x7003, &[0x81, 0xff]), Some(()));
    region.unmap();
    assert_eq!(chipset.mmio_read(0x700f, &mut byte), None);
    assert_eq!(byte, [0x5a]);
    assert_eq!(chipset.mmio_write(0x7003, &[0]), None);
    assert_eq!(
        *accesses.lock(),
        [
            Access::MmioRead(0x600f, 1),
            Access::MmioWrite(0x7003, vec![0x81, 0xff])
        ]
    );
}
