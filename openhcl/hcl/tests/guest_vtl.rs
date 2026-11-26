// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest target validation at the paravisor VTL boundary.

#![cfg(target_os = "linux")]

use hcl::GuestVtl;
use hvdef::Vtl;
use hvdef::hypercall::HvInputVtl;
use test_with_tracing::test;

// Test: Narrow every byte selector and typed VTL into a guest hypercall target.
// Expected: Only VTL0/VTL1 are accepted, always explicitly targeted; paravisor
//       VTL2 and all unknown bytes are rejected without truncating error values.
#[test]
fn guest_targets_exclude_paravisor_and_unknown_vtls() {
    for raw in 0..=u8::MAX {
        if raw <= 1 {
            let guest = GuestVtl::try_from(raw).unwrap();
            let expected = if raw == 0 {
                GuestVtl::Vtl0
            } else {
                GuestVtl::Vtl1
            };
            assert_eq!(guest, expected);
            assert_eq!(u8::from(guest), raw);
            let full = Vtl::from(guest);
            assert_eq!(GuestVtl::try_from(full).unwrap(), expected);
            let target = HvInputVtl::from(guest);
            assert_eq!(target.target_vtl().unwrap(), Some(full));
        } else {
            assert_eq!(GuestVtl::try_from(raw).unwrap_err().0, raw);
        }
    }
    assert_eq!(GuestVtl::try_from(Vtl::Vtl2).unwrap_err().0, 2);
}
