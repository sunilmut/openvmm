// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::RecordingProtection;
use hvdef::HvSynicSint;
use test_with_tracing::test;
use zerocopy::FromBytes;

// Test: Acknowledge one of two occupied SINT slots by clearing only its message type.
// Expected: Stale pending flags/payload do not block reuse or release the other slot.
#[test]
fn type_only_acknowledgment_releases_only_the_acknowledged_sint() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = RecordingProtection::new();
    processor.set_simp(0x3001, &mut protection).unwrap();
    for (sint, vector) in [(2, 0x62), (5, 0x65)] {
        processor.set_sint(sint, HvSynicSint::new().with_vector(vector).into());
    }
    let mask = (1 << 2) | (1 << 5);
    let mut interrupts = Vec::new();
    let mut interrupt = |vector, auto_eoi| interrupts.push((vector, auto_eoi));
    processor.request_sint_readiness(mask);
    assert_eq!(processor.scan(0, &mut interrupt), (mask, None));
    let first = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 17, &[0x5a; 24]);
    let second = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 29, &[0xa5; 8]);
    for sint in [2, 5] {
        processor
            .post_message(sint, &first, &mut interrupt)
            .unwrap();
    }
    processor.request_sint_readiness(mask);
    assert_eq!(processor.scan(0, &mut interrupt), (0, None));
    let address = 0x3000 + 2 * HV_MESSAGE_SIZE as u64;
    let other_address = 0x3000 + 5 * HV_MESSAGE_SIZE as u64;
    let mut occupied = [0; HV_MESSAGE_SIZE];
    protection.memory.read_at(address, &mut occupied).unwrap();
    assert!(
        HvMessageHeader::read_from_prefix(&occupied)
            .unwrap()
            .0
            .flags
            .message_pending()
    );
    let mut other = [0; HV_MESSAGE_SIZE];
    protection
        .memory
        .read_at(other_address, &mut other)
        .unwrap();
    protection
        .memory
        .write_at(address, &0u32.to_le_bytes())
        .unwrap();
    processor.set_eom(0);
    assert_eq!(processor.scan(0, &mut interrupt), (1 << 2, None));
    assert_eq!(
        processor.post_message(5, &second, &mut interrupt),
        Err(HvError::ObjectInUse)
    );
    processor.post_message(2, &second, &mut interrupt).unwrap();
    let mut actual = [0; HV_MESSAGE_SIZE];
    protection.memory.read_at(address, &mut actual).unwrap();
    assert_eq!(actual.as_slice(), second.as_bytes());
    protection
        .memory
        .read_at(other_address, &mut actual)
        .unwrap();
    assert_eq!(actual, other);
    assert_eq!(processor.scan(0, &mut interrupt), (0, None));
    assert_eq!(interrupts, [(0x62, false), (0x65, false), (0x62, false)]);
}
