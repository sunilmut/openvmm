// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::RecordingProtection;
use test_with_tracing::test;

// Test: Map a logical overlay, write through guest memory, remap it, unmap it, and map it again.
// Expected: Logical bytes survive each move, same-GPN synchronization is a no-op, permissions are read/write, and only replaced mappings are unlocked.
#[test]
fn overlay_remap_and_unmap_preserve_guest_written_bytes() {
    let mut protection = RecordingProtection::new();
    let mut overlay = OverlayPage::default();
    let mut initial = [0x5a; 4096];
    initial[0] = 0x11;
    initial[4095] = 0xee;
    overlay.restore_page(&initial);
    overlay.sync(true, 2, &mut protection).unwrap();
    overlay.sync(true, 2, &mut protection).unwrap();
    let mut actual = [0; 4096];
    protection.memory.read_at(2 * 4096, &mut actual).unwrap();
    assert_eq!(actual, initial);
    protection
        .memory
        .write_at(2 * 4096 + 37, b"guest-write")
        .unwrap();
    initial[37..48].copy_from_slice(b"guest-write");
    overlay.sync(true, 3, &mut protection).unwrap();
    protection.memory.read_at(3 * 4096, &mut actual).unwrap();
    assert_eq!(actual, initial);
    overlay.sync(false, 99, &mut protection).unwrap();
    assert_eq!(overlay.save_page(), initial);
    overlay.sync(true, 4, &mut protection).unwrap();
    protection.memory.read_at(4 * 4096, &mut actual).unwrap();
    assert_eq!(actual, initial);
    assert_eq!(
        protection
            .requested
            .iter()
            .map(|request| request.0)
            .collect::<Vec<_>>(),
        [2, 3, 4]
    );
    for (_, checked, changed) in &protection.requested {
        assert!(checked.readable());
        assert!(checked.writable());
        assert!(changed.is_none());
    }
    assert_eq!(protection.unlocked, [2, 3]);
    overlay.reset(&mut protection);
    assert_eq!(overlay.save_page(), [0; 4096]);
    assert_eq!(protection.unlocked, [2, 3, 4]);
}
