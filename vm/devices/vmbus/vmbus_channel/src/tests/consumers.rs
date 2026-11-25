// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Copy ring data across a page boundary and the end of a multi-page
//       GPADL whose physical pages are deliberately out of address order.
// Expected: Logical packet order follows the GPADL, wraps only through data
//       pages, and never modifies the control page or unrelated guest memory.
#[test]
fn discontiguous_ring_pages_preserve_packet_order_and_control_isolation() {
    let memory = GuestMemory::allocate(12 * 4096);
    memory.fill_at(0, 0xa5, 12 * 4096).unwrap();
    let map = GpadlMap::new();
    map.add(
        GpadlId(7),
        MultiPagedRangeBuf::from_range_buffer(1, vec![4 * 4096, 9, 5, 2, 7]).unwrap(),
    );
    let aligned = AlignedGpadlView::new(map.view().map(GpadlId(7)).unwrap()).unwrap();
    let ring = GpadlRingMem::new(aligned, &memory).unwrap();
    let payload: [u8; 24] = std::array::from_fn(|i| 0x80 + i as u8);

    for (offset, tail_page, head_page) in [(4088, 5, 2), (12280, 7, 5)] {
        ring.write_aligned(offset, &payload);
        assert_eq!(
            memory
                .read_plain::<[u8; 8]>(tail_page * 4096 + 4088)
                .unwrap(),
            payload[..8],
        );
        assert_eq!(
            memory.read_plain::<[u8; 16]>(head_page * 4096).unwrap(),
            payload[8..],
        );
        let mut aligned = [0; 24];
        ring.read_aligned(offset, &mut aligned);
        assert_eq!(aligned, payload);
        let mut unaligned = [0; 22];
        ring.read_at(offset + 1, &mut unaligned);
        assert_eq!(unaligned, payload[1..23]);
    }
    assert_eq!(memory.read_plain::<[u8; 16]>(9 * 4096).unwrap(), [0xa5; 16]);
    assert_eq!(memory.read_plain::<[u8; 16]>(0).unwrap(), [0xa5; 16]);
}
