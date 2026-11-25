// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod device_tests;
mod dma_tests;

// Test: Write through the payload subrange and DMA allocation and observe their shared full guest-memory backing, including exact half-range allocation capacity.
// Expected: Payload offsets start halfway through the guest range, DMA PFNs stay in the first half, all accessors see identical bytes, and allocation cannot consume the payload half.
#[test]
fn guest_payload_and_dma_views_share_bytes_without_crossing_halves() {
    for allow_dma in [false, true] {
        let memory = DeviceTestMemory::new(8, allow_dma, "shared-view-test");
        let guest = memory.guest_memory();
        let payload = memory.payload_mem();
        assert_eq!(guest.iova(PAGE_SIZE64), allow_dma.then_some(PAGE_SIZE64));
        assert_eq!(payload.iova(17), allow_dma.then_some(4 * PAGE_SIZE64 + 17));
        payload.write_plain(0, &0x91827364u32).unwrap();
        assert_eq!(
            guest.read_plain::<u32>(4 * PAGE_SIZE64).unwrap(),
            0x91827364
        );
        guest
            .write_plain(4 * PAGE_SIZE64 + PAGE_SIZE64 - 2, &0x12345678u32)
            .unwrap();
        assert_eq!(
            payload.read_plain::<u32>(PAGE_SIZE64 - 2).unwrap(),
            0x12345678
        );
        assert!(payload.read_plain::<u32>(4 * PAGE_SIZE64).is_err());
        let client = memory.dma_client();
        let allocation = client
            .allocate_dma_buffer(4 * PAGE_SIZE64 as usize)
            .unwrap();
        assert_eq!(allocation.len(), 4 * PAGE_SIZE64 as usize);
        assert_eq!(allocation.pfns().len(), 4);
        assert!(allocation.pfns().iter().all(|pfn| *pfn < 4));
        allocation.write_at(0, &[0, 0x91, 0xff, 0x20]);
        let address = allocation.pfns()[0] * PAGE_SIZE64;
        assert_eq!(
            guest.read_plain::<[u8; 4]>(address).unwrap(),
            [0, 0x91, 0xff, 0x20]
        );
        guest.write_plain(address + 1, &0x44u8).unwrap();
        let mut output = [0; 4];
        allocation.read_at(0, &mut output);
        assert_eq!(output, [0, 0x44, 0xff, 0x20]);
        assert!(client.allocate_dma_buffer(PAGE_SIZE64 as usize).is_err());
        assert_eq!(payload.read_plain::<u32>(0).unwrap(), 0x91827364);
    }
}
