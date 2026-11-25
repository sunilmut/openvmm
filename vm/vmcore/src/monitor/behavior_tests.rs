// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Signal the first/last pending bit of every monitor group, surrounding reserved bits, and a dropped/reused registration.
// Expected: Only registered pending bits return their exact connection ID; armed/reserved/out-of-range bits do not signal; dropping a guard unregisters its ID.
#[test]
fn direct_bit_signaling_respects_group_boundaries_and_registration_lifetime() {
    let monitor = MonitorPage::new();
    let offset = offset_of!(HvMonitorPage, trigger_group) as u32 * 8;
    let mut registrations = Vec::new();
    for group in 0..4u32 {
        for trigger in [0, 31] {
            let index = group * 32 + trigger;
            registrations.push(monitor.register_monitor(MonitorId(index as u8), 1000 + index));
            assert_eq!(
                monitor.write_bit(offset + group * 64 + trigger),
                Some(1000 + index)
            );
        }
        assert_eq!(monitor.write_bit(offset + group * 64 + 32), None);
        assert_eq!(monitor.write_bit(offset + group * 64 + 63), None);
    }
    assert_eq!(monitor.write_bit(offset - 1), None);
    assert_eq!(monitor.write_bit(offset + 4 * 64), None);
    assert_eq!(monitor.write_bit(offset + 5), None);
    drop(registrations);
    assert_eq!(monitor.write_bit(offset), None);
    let _reused = monitor.register_monitor(MonitorId(0), 42);
    assert_eq!(monitor.write_bit(offset), Some(42));
}

// Test: Read a configured monitor page and neighboring pages, and write to unused or overlong ranges within the page.
// Expected: Matching reads are zero-filled, nonmatching buffers stay untouched, and unused writes are handled without signaling a monitor.
#[test]
fn monitor_read_and_unused_write_ranges_preserve_handling_boundaries() {
    let monitor = MonitorPage::new();
    monitor.set_gpa(Some(0x2000));
    assert_eq!(monitor.gpa(), Some(0x2000));
    let _guard = monitor.register_monitor(MonitorId(0), 7);
    let mut bytes = [0xa5; 16];
    assert!(!monitor.check_read(0x1000, &mut bytes));
    assert_eq!(bytes, [0xa5; 16]);
    assert!(monitor.check_read(0x2020, &mut bytes));
    assert_eq!(bytes, [0; 16]);
    let end = 0x2000 + size_of::<HvMonitorPageSmall>() as u64;
    assert!(monitor.check_write(end, &[0xff], |_| panic!("unused bytes signaled a monitor")));
    assert!(monitor.check_write(end - 1, &[0xff; 2], |_| panic!(
        "overlong bytes signaled a monitor"
    )));
    assert!(!monitor.check_write(0x3000, &[0xff], |_| panic!(
        "neighboring page signaled a monitor"
    )));
    assert_eq!(monitor.set_gpa(None), Some(0x2000));
    bytes.fill(0xa5);
    assert!(!monitor.check_read(0x2000, &mut bytes));
    assert_eq!(bytes, [0xa5; 16]);
}
