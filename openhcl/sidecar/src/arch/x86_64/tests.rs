// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::CommandErrorWriter;
use super::addr_space;
use core::fmt::Write;
use std::collections::BTreeSet;
use test_with_tracing::test;
use x86defs::Pte;

// Test: Build an AP page table from high physical addresses over stale mappings.
// Expected: Boot-layout slots and stack pages are writable, non-executable data;
//       unused mappings are cleared and the next unallocated page is retained.
#[test]
fn ap_page_table_preserves_layout_permissions_and_allocation_boundary() {
    let stack_pages = sidecar_defs::STACK_PAGES;
    let frames: Vec<_> = (0..stack_pages + 4)
        .map(|i| 0x12_0000_0000 + i as u64 * 0x1000)
        .collect();
    let spare = 0x13_0000_0000;
    let mut memory = frames.iter().copied().chain([spare]);
    let mut table = [Pte::new().with_address(0xdead_0000).with_present(true); 512];
    let globals = addr_space::init_ap(
        &mut table,
        0x14_0000_0000,
        0x15_0000_0000,
        0x16_0000_0000,
        0x17_0000_0000,
        &mut memory,
    );

    // These slots are consumed by the sidecar's fixed virtual-address layout.
    let expected = [
        0x14_0000_0000,
        frames[stack_pages + 2],
        frames[stack_pages + 3],
        0x16_0000_0000,
        frames[stack_pages],
        frames[stack_pages + 1],
        0x15_0000_0000,
        0x17_0000_0000,
    ];
    for (pte, address) in table[..8].iter().zip(expected) {
        assert_eq!(pte.address(), address);
        assert!(pte.present() && pte.read_write() && pte.no_execute());
    }
    for (pte, &address) in table[512 - stack_pages..]
        .iter()
        .zip(&frames[..stack_pages])
    {
        assert_eq!(pte.address(), address);
        assert!(pte.present() && pte.read_write() && pte.no_execute());
    }
    for &pte in &table[8..512 - stack_pages] {
        let raw: u64 = pte.into();
        assert_eq!(raw, 0, "stale mapping survived AP initialization");
    }
    assert_eq!(globals, expected[4]);
    assert_eq!(memory.next(), Some(spare));
}

// Test: Allocate two APs from one frame iterator with a shared node control page.
// Expected: Only the control page aliases; stacks, globals, hypercall buffers
//       and command/register/page-table mappings remain private to each AP.
#[test]
fn ap_page_tables_share_only_the_node_control_page() {
    let frames_per_ap = sidecar_defs::STACK_PAGES + 4;
    let mut memory = (0..2 * frames_per_ap).map(|i| 0x20_0000_0000 + i as u64 * 0x1000);
    let control = 0x30_0000_0000;
    let mut private_mappings = Vec::new();
    for cpu in 0..2 {
        let base = 0x40_0000_0000 + cpu as u64 * 0x10000;
        let mut table = [Pte::new(); 512];
        let globals = addr_space::init_ap(
            &mut table,
            base,
            control,
            base + 0x1000,
            base + 0x2000,
            &mut memory,
        );
        assert_eq!(table[6].address(), control);
        assert_eq!(
            globals,
            0x20_0000_0000 + (cpu * frames_per_ap + sidecar_defs::STACK_PAGES) as u64 * 0x1000
        );
        private_mappings.push(
            table
                .iter()
                .enumerate()
                .filter(|&(index, pte)| index != 6 && pte.present())
                .map(|(_, pte)| pte.address())
                .collect::<BTreeSet<_>>(),
        );
    }
    assert!(private_mappings[0].is_disjoint(&private_mappings[1]));
}

// Test: Append a multibyte UTF-8 prefix and over-capacity diagnostic fragments.
// Expected: Byte lengths and append order are preserved, truncation retains
//       the accepted prefix, and writes after capacity cannot overflow.
#[test]
fn command_error_writer_preserves_prefix_and_bounds_fragmented_output() {
    let mut error = sidecar_defs::CommandError {
        len: 0,
        buf: [0xa5; 255],
    };
    CommandErrorWriter(&mut error).write_str("\u{e9}:").unwrap();
    assert_eq!(error.len, 3);
    assert_eq!(&error.buf[..3], b"\xc3\xa9:");
    assert!(error.buf[3..].iter().all(|&byte| byte == 0xa5));
    CommandErrorWriter(&mut error)
        .write_str(&"x".repeat(300))
        .unwrap();
    let mut expected = [b'x'; 255];
    expected[..3].copy_from_slice(b"\xc3\xa9:");
    assert_eq!(error.len, 255);
    assert_eq!(error.buf, expected);
    CommandErrorWriter(&mut error).write_str("").unwrap();
    CommandErrorWriter(&mut error)
        .write_str("discarded")
        .unwrap();
    assert_eq!(error.len, 255);
    assert_eq!(error.buf, expected);
}

// IGNORED: entry310-bug1. The writer cuts at byte 255 even inside a character.
//       The client uses lossy decoding, so this corrupts diagnostics rather
//       than demonstrating a client crash.
//
// Test: Truncate a valid multibyte diagnostic one byte beyond buffer capacity.
// Expected: The UTF-8 command-error ABI retains the longest complete prefix,
//       rather than publishing an incomplete final character.
#[test]
#[ignore = "entry310-bug1: command-error truncation can publish invalid UTF-8"]
fn command_error_truncation_preserves_valid_utf8() {
    let mut error = sidecar_defs::CommandError {
        len: 0,
        buf: [0; 255],
    };
    CommandErrorWriter(&mut error)
        .write_str(&"\u{e9}".repeat(128))
        .unwrap();
    let bytes = &error.buf[..usize::from(error.len)];
    assert!(
        core::str::from_utf8(bytes).is_ok(),
        "truncated diagnostic violated the UTF-8 command-error ABI"
    );
    assert_eq!(bytes, "\u{e9}".repeat(127).as_bytes());
}
