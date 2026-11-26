// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromZeros;

// Test: Translate all six reservation access modes independently in both directions.
// Expected: Each wire type preserves its access policy; reserved and future
//       types are rejected rather than granting a different reservation.
#[test]
fn reservation_type_access_policies() {
    let policies = [
        pr::ReservationType::WriteExclusive,
        pr::ReservationType::ExclusiveAccess,
        pr::ReservationType::WriteExclusiveRegistrantsOnly,
        pr::ReservationType::ExclusiveAccessRegistrantsOnly,
        pr::ReservationType::WriteExclusiveAllRegistrants,
        pr::ReservationType::ExclusiveAccessAllRegistrants,
    ];
    for (index, policy) in policies.into_iter().enumerate() {
        let wire = nvm::ReservationType(index as u8 + 1);
        assert_eq!(to_nvme_reservation_type(policy), wire);
        assert_eq!(from_nvme_reservation_type(wire).unwrap(), policy);
    }
    for value in (0..=u8::MAX).filter(|value| !(1..=6).contains(value)) {
        assert!(from_nvme_reservation_type(nvm::ReservationType(value)).is_err());
    }
}

// Test: Decode every combination of reservation capability bits.
// Expected: Independent capabilities retain their meaning, and the reserved
//       high bit cannot enable any supported reservation policy.
#[test]
fn reservation_capability_bits_are_independent() {
    for bits in 0..=u8::MAX {
        let actual = from_nvme_reservation_capabilities(bits.into());
        assert_eq!(
            [
                actual.persist_through_power_loss,
                actual.write_exclusive,
                actual.exclusive_access,
                actual.write_exclusive_registrants_only,
                actual.exclusive_access_registrants_only,
                actual.write_exclusive_all_registrants,
                actual.exclusive_access_all_registrants,
            ],
            core::array::from_fn(|bit| bits & (1 << bit) != 0),
        );
    }
}

// Test: Decode extended reports containing ordinary and SAS-form host identifiers.
// Expected: Keys, ownership, generation and persistence survive translation;
//       only the exact SAS prefix is stripped and absent/invalid types differ.
#[test]
fn extended_report_identity_and_reservation() {
    let mut header = nvm::ReservationReport::new_zeroed();
    let empty = from_nvme_reservation_report(&header, &[]).unwrap();
    assert_eq!(empty.reservation_type, None);
    assert!(empty.controllers.is_empty());
    assert!(!empty.persist_through_power_loss);

    header.generation = 0xfedc_ba98;
    header.rtype = nvm::ReservationType::EXCLUSIVE_ACCESS_ALL_REGISTRANTS;
    header.regctl = 3u16.into();
    header.ptpls = 1;
    let mut first = nvm::RegisteredControllerExtended::new_zeroed();
    first.cntlid = 0xabcd;
    first.rkey = 0xfedc_ba98_7654_3210;
    first.rcsts = 1u8.into();
    first.hostid = [6, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0];
    let mut second = nvm::RegisteredControllerExtended::new_zeroed();
    second.cntlid = 19;
    second.rkey = 123;
    second.hostid = [6, 0, 0, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0];
    let mut third = nvm::RegisteredControllerExtended::new_zeroed();
    third.cntlid = 20;
    third.rkey = 456;
    third.hostid = [0x5a; 16];
    let input = [first, second, third];
    let report = from_nvme_reservation_report(&header, &input).unwrap();
    assert_eq!(report.generation, 0xfedc_ba98);
    assert_eq!(
        report.reservation_type,
        Some(pr::ReservationType::ExclusiveAccessAllRegistrants)
    );
    assert!(report.persist_through_power_loss);
    assert_eq!(report.controllers.len(), 3);
    let owner = &report.controllers[0];
    assert_eq!(owner.controller_id, 0xabcd);
    assert_eq!(owner.key, 0xfedc_ba98_7654_3210);
    assert!(owner.holds_reservation);
    assert_eq!(
        owner.host_id,
        [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    for (actual, expected) in report.controllers[1..].iter().zip(&input[1..]) {
        assert_eq!(actual.controller_id, expected.cntlid);
        assert_eq!(actual.key, expected.rkey);
        assert!(!actual.holds_reservation);
        assert_eq!(actual.host_id, expected.hostid);
    }
    header.rtype = nvm::ReservationType(7);
    assert!(from_nvme_reservation_report(&header, &input).is_err());
}
