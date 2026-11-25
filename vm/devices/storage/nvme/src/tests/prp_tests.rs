// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::PAGE_SIZE;
use crate::PAGE_SIZE64;
use crate::error::CommandResult;
use crate::prp::PrpRange;
use crate::spec;
use guestmem::GuestMemory;
use test_with_tracing::test;

// Test: Transfer data through a PRP list that chains into a second list page,
//       with data pages deliberately arranged out of physical-address order.
// Expected: Reads follow logical PRP order; writes and zeroing reach the named
//       pages without overwriting bytes outside the transfer.
#[test]
fn chained_prp_lists_preserve_logical_data_order() {
    const PAGES: usize = 515;
    const BASE: u64 = 0x10000;
    let mem = GuestMemory::allocate(BASE as usize + PAGES * PAGE_SIZE);
    let address = |i: usize| BASE + ((i * 17) % PAGES) as u64 * PAGE_SIZE64;
    let mut list = [0u64; 512];
    for (i, entry) in list[..511].iter_mut().enumerate() {
        *entry = address(i + 1);
    }
    list[511] = 0x2000;
    mem.write_plain(0x1000, &list).unwrap();
    mem.write_plain(0x2000, &[address(512), address(513), address(514)])
        .unwrap();
    for i in 0..PAGES {
        mem.fill_at(address(i), (i % 251 + 1) as u8, PAGE_SIZE)
            .unwrap();
    }
    mem.fill_at(BASE - PAGE_SIZE64, 0x35, PAGE_SIZE).unwrap();
    let range = PrpRange::parse(&mem, PAGES * PAGE_SIZE, [address(0), 0x1000]).unwrap();
    let mut bytes = vec![0; PAGES * PAGE_SIZE];
    range.read(&mem, &mut bytes).unwrap();
    for (i, page) in bytes.chunks_exact(PAGE_SIZE).enumerate() {
        assert!(page.iter().all(|&b| b == (i % 251 + 1) as u8));
    }
    bytes.fill(0x6a);
    range.write(&mem, &bytes).unwrap();
    let mut page = [0; PAGE_SIZE];
    mem.read_at(address(514), &mut page).unwrap();
    assert_eq!(page, [0x6a; PAGE_SIZE]);
    range.zero(&mem, bytes.len()).unwrap();
    for i in [0, 511, 512, 514] {
        mem.read_at(address(i), &mut page).unwrap();
        assert_eq!(page, [0; PAGE_SIZE]);
    }
    mem.read_at(BASE - PAGE_SIZE64, &mut page).unwrap();
    assert_eq!(page, [0x35; PAGE_SIZE]);
}

// Test: Parse a multi-page transfer whose PRP list itself is outside guest RAM.
// Expected: The caller receives Data Transfer Error with its memory-error
//       source, rather than a partial or successfully parsed transfer.
#[test]
fn inaccessible_prp_list_reports_data_transfer_error() {
    let mem = GuestMemory::allocate(4 * PAGE_SIZE);
    let err = PrpRange::parse(&mem, 3 * PAGE_SIZE, [0, 4 * PAGE_SIZE64])
        .err()
        .unwrap();
    assert!(std::error::Error::source(&err).is_some());
    assert_eq!(
        CommandResult::from(err).status,
        spec::Status::DATA_TRANSFER_ERROR
    );
}
