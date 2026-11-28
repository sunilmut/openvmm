// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::new_test_rtc;
use crate::tests::read8;
use crate::tests::write8;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::pio::PortIoIntercept;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::SaveRestore;

// Test: Save extended CMOS through one alias, then restore and use its mirrored ports.
// Expected: The masked address latch and CMOS contents survive; unknown ports are rejected.
#[test]
fn extended_cmos_restore_preserves_address_latch_and_mirrored_data() {
    let (mut pool, _time, mut rtc) = new_test_rtc();
    write8(&mut rtc, 0x72, 0xe7);
    assert_eq!(read8(&mut rtc, 0x72), 0x67);
    assert_eq!(read8(&mut rtc, 0x76), 0x67);
    write8(&mut rtc, 0x77, 0xa5);
    assert_eq!(read8(&mut rtc, 0x73), 0xa5);
    let saved = rtc.save().unwrap();
    write8(&mut rtc, 0x73, 0x5a);
    write8(&mut rtc, 0x76, 3);
    pool.run_until(rtc.reset());
    let (_restored_pool, _restored_time, mut rtc) = new_test_rtc();
    rtc.restore(saved).unwrap();
    assert_eq!(read8(&mut rtc, 0x76), 0x67);
    assert_eq!(read8(&mut rtc, 0x77), 0xa5);
    assert!(matches!(
        rtc.io_read(0x78, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        rtc.io_write(0x78, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Interleave standard and extended CMOS accesses through mirrored ports,
//       changing one bank's index while the other bank remains selected.
// Expected: The two banks retain independent address latches and storage;
//       writes never alias the same offset in the other bank.
#[test]
fn interleaved_cmos_banks_keep_independent_addresses_and_data() {
    let (_pool, _time, mut rtc) = new_test_rtc();
    write8(&mut rtc, 0x70, 0x21);
    write8(&mut rtc, 0x72, 0xa1);
    write8(&mut rtc, 0x71, 0xa5);
    write8(&mut rtc, 0x73, 0x5a);

    write8(&mut rtc, 0x74, 0x22);
    write8(&mut rtc, 0x75, 0xa6);
    write8(&mut rtc, 0x77, 0x6b);
    write8(&mut rtc, 0x76, 0xa2);
    write8(&mut rtc, 0x75, 0xa7);
    write8(&mut rtc, 0x77, 0x6c);

    for (offset, standard, extended) in [(0x21, 0xa5, 0x6b), (0x22, 0xa7, 0x6c)] {
        write8(&mut rtc, 0x70, offset);
        assert_eq!(read8(&mut rtc, 0x71), standard);
        write8(&mut rtc, 0x72, offset | 0x80);
        assert_eq!(read8(&mut rtc, 0x73), extended);
    }
}
