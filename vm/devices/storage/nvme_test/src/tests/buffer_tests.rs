// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::command_match::{CommandMatchBuilder, match_command_pattern};
use crate::prp::PrpRange;
use crate::spec;
use guestmem::GuestMemory;
use test_with_tracing::test;
use zerocopy::{FromZeros, IntoBytes};

// Test: Transfer data through a PRP list that chains to a second list page.
// Expected: The unaligned first page and all later pages are transferred without touching list metadata.
#[test]
fn chained_prp_lists_preserve_data_order_and_the_initial_offset() {
    let data_base = 0x10000u64;
    let page_count = 515;
    let memory = GuestMemory::allocate(data_base as usize + page_count * 4096);
    let expected: Vec<u8> = (0..page_count)
        .flat_map(|i| std::iter::repeat_n((i % 251) as u8, 4096))
        .collect();
    memory.write_at(data_base, &expected).unwrap();
    let mut first = [0u64; 512];
    for (i, entry) in first[..511].iter_mut().enumerate() {
        *entry = data_base + (i as u64 + 1) * 4096;
    }
    first[511] = 0x2000;
    let second = [
        data_base + 512 * 4096,
        data_base + 513 * 4096,
        data_base + 514 * 4096,
    ];
    memory.write_at(0x1000, first.as_bytes()).unwrap();
    memory.write_at(0x2000, second.as_bytes()).unwrap();
    let range = PrpRange::parse(&memory, expected.len() - 37, [data_base + 37, 0x1000]).unwrap();
    let mut actual = vec![0; expected.len() - 37];
    range.read(&memory, &mut actual).unwrap();
    assert_eq!(actual, expected[37..]);

    range.write(&memory, &vec![0xc8; actual.len()]).unwrap();
    let mut prefix = [0xff; 37];
    memory.read_at(data_base, &mut prefix).unwrap();
    assert_eq!(prefix, [0; 37]);
    memory.read_at(data_base + 37, &mut actual).unwrap();
    assert!(actual.iter().all(|&b| b == 0xc8));
    let mut metadata = [0u64; 512];
    memory.read_at(0x1000, metadata.as_mut_bytes()).unwrap();
    assert_eq!(metadata, first);
}

// Test: Parse a PRP list outside guest memory and apply partial command-field masks.
// Expected: Invalid memory yields a transfer error; only selected CID/CDW10 bits affect matching.
#[test]
fn invalid_prp_memory_and_partial_command_masks_have_precise_results() {
    let memory = GuestMemory::allocate(4096);
    let error = PrpRange::parse(&memory, 3 * 4096, [0, 0x10000])
        .err()
        .unwrap();
    assert_eq!(
        crate::error::CommandResult::from(error).status,
        spec::Status::DATA_TRANSFER_ERROR
    );
    let mut command = spec::Command::new_zeroed();
    command.cdw0 = spec::Cdw0::new().with_cid(0x1234).with_opcode(7);
    command.cdw10 = 0xa5a5_1234;
    let pattern = CommandMatchBuilder::new()
        .match_cdw0(u32::from(command.cdw0), 0xffff_0000)
        .match_cdw10(0x1234, 0xffff)
        .build();
    assert!(match_command_pattern(&pattern, &command));
    command.cdw0.set_opcode(0xff);
    command.cdw10 ^= 0xffff_0000;
    assert!(match_command_pattern(&pattern, &command));
    command.cdw10 ^= 1;
    assert!(!match_command_pattern(&pattern, &command));
    command.cdw10 ^= 1;
    command.cdw0.set_cid(0x1235);
    assert!(!match_command_pattern(&pattern, &command));
}
