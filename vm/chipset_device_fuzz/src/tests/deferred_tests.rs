// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Dispatch PCI reads/writes through registered and absent BDFs using successful and failed devices.
// Expected: Full byte enables and exact offsets/values reach the device; reads retain the full DWORD or become zero on error, and absent routes leave data untouched.
#[test]
fn pci_dispatch_preserves_full_dwords_and_zeroes_failed_reads() {
    for fail in [false, true] {
        let (chipset, accesses) = chipset(fail);
        let mut data = [0xa5; 4];
        assert_eq!(chipset.pci_read((2, 3, 1), 0xffc, &mut data), Some(()));
        assert_eq!(
            data,
            if fail {
                [0; 4]
            } else {
                [0x11, 0x22, 0x33, 0x44]
            }
        );
        assert_eq!(
            chipset.exec_action(ChipsetAction::PciWrite {
                bdf: (2, 3, 1),
                offset: 0x44,
                val: 0x89abcdef
            }),
            Some(())
        );
        assert_eq!(
            *accesses.lock(),
            [
                Access::PciRead(0xffc, 0xf),
                Access::PciWrite(0x44, 0x89abcdef, 0xf)
            ]
        );
        data.fill(0xa5);
        assert_eq!(chipset.pci_read((2, 3, 2), 0, &mut data), None);
        assert_eq!(chipset.pci_write((2, 3, 2), 0, 0), None);
        assert_eq!(data, [0xa5; 4]);
    }
}

// Test: Complete deferred MMIO/PIO reads and all write transports after one poll and exactly at the configured budget.
// Expected: Operations finish without premature timeout, return complete payloads or open-bus error bytes, and forward each write exactly once.
#[test]
fn deferred_io_completes_at_poll_budget_and_preserves_read_results() {
    for delay in [1, 4] {
        for fail in [false, true] {
            let (chipset, accesses) = configured_chipset(fail, Some(delay), 4);
            let mut mmio = [0; 4];
            assert_eq!(chipset.mmio_read(0x1000, &mut mmio), Some(()));
            assert_eq!(mmio, if fail { [0xff; 4] } else { [0xa0; 4] });
            let mut pio = [0; 2];
            assert_eq!(chipset.pio_read(0x200, &mut pio), Some(()));
            assert_eq!(pio, if fail { [0xff; 2] } else { [0x91; 2] });
            assert_eq!(chipset.mmio_write(0x1002, &[1, 2]), Some(()));
            assert_eq!(chipset.pio_write(0x202, &[3, 4]), Some(()));
            assert_eq!(chipset.pci_write((2, 3, 1), 0x20, 0x12345678), Some(()));
            let operations: Vec<_> = accesses
                .lock()
                .iter()
                .filter(|access| !matches!(access, Access::Poll))
                .cloned()
                .collect();
            assert_eq!(
                operations,
                [
                    Access::MmioRead(0x1000, 4),
                    Access::PioRead(0x200, 2),
                    Access::MmioWrite(0x1002, vec![1, 2]),
                    Access::PioWrite(0x202, vec![3, 4]),
                    Access::PciWrite(0x20, 0x12345678, 0xf)
                ]
            );
        }
    }
}

// Test: Complete a deferred PCI read with a nonzero device-provided DWORD.
// Expected: The caller receives the deferred bytes rather than the untouched synchronous read scratch value.
#[test]
#[ignore = "known product bug: deferred PCI read payload is overwritten by synchronous scratch value"]
fn known_bug_deferred_pci_read_preserves_completed_device_payload() {
    let (chipset, _) = configured_chipset(false, Some(2), 4);
    let mut data = [0xa5; 4];
    assert_eq!(chipset.pci_read((2, 3, 1), 0x40, &mut data), Some(()));
    assert_eq!(data, [0x11, 0x22, 0x33, 0x44]);
}
