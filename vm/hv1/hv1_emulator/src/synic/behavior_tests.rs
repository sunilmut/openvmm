// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_support::RecordingProtection;
use hvdef::HvSynicSint;
use test_with_tracing::test;

// Test: Post intercepts without a prior readiness scan, fill the slot, then acknowledge it in guest memory.
// Expected: The dedicated intercept slot carries exact bytes, full slots reject overwrites, guest acknowledgment permits another delivery, and polling suppresses local interrupts.
#[test]
fn intercept_delivery_checks_guest_slot_readiness_and_honors_polling() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = RecordingProtection::new();
    processor.set_simp(0x3001, &mut protection).unwrap();
    let index = hvdef::HV_SYNIC_INTERCEPTION_SINT_INDEX;
    processor.set_sint(
        index as usize,
        HvSynicSint::new()
            .with_vector(0x77)
            .with_polling(true)
            .into(),
    );
    let message = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 17, &[0x35; 24]);
    let mut interrupts = Vec::new();
    processor
        .post_intercept_message(&message, &mut |vector, auto_eoi| {
            interrupts.push((vector, auto_eoi))
        })
        .unwrap();
    let mut bytes = [0; HV_MESSAGE_SIZE];
    let address = 0x3000 + u64::from(index) * HV_MESSAGE_SIZE as u64;
    protection.memory.read_at(address, &mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), message.as_bytes());
    assert_eq!(
        processor.post_intercept_message(&message, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Err(HvError::ObjectInUse)
    );
    protection
        .memory
        .write_at(address, &[0; HV_MESSAGE_SIZE])
        .unwrap();
    processor
        .post_intercept_message(&message, &mut |vector, auto_eoi| {
            interrupts.push((vector, auto_eoi))
        })
        .unwrap();
    protection.memory.read_at(address, &mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), message.as_bytes());
    assert!(interrupts.is_empty());
}

// Test: Access the same SynIC state through architectural register names and x64 MSR numbers.
// Expected: SINT/timer slots and control/page/EOM aliases share exact values in both directions without slot swaps.
#[test]
fn architectural_registers_alias_the_correct_msr_slots() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = DeniedProtection::default();
    let mut aliases = vec![
        (
            HvAllArchRegisterName::Scontrol.0,
            hvdef::HV_X64_MSR_SCONTROL,
            1,
        ),
        (
            HvAllArchRegisterName::Sifp.0,
            hvdef::HV_X64_MSR_SIEFP,
            0x5000,
        ),
        (
            HvAllArchRegisterName::Sipp.0,
            hvdef::HV_X64_MSR_SIMP,
            0x6000,
        ),
        (HvAllArchRegisterName::Eom.0, hvdef::HV_X64_MSR_EOM, 0),
    ];
    for index in 0..16u32 {
        aliases.push((
            HvAllArchRegisterName::Sint0.0 + index,
            hvdef::HV_X64_MSR_SINT0 + index,
            0x50 + u64::from(index),
        ));
    }
    for index in 0..8u32 {
        aliases.push((
            HvAllArchRegisterName::Stimer0Config.0 + index,
            hvdef::HV_X64_MSR_STIMER0_CONFIG + index,
            if index % 2 == 0 {
                2
            } else {
                0x1000 + u64::from(index)
            },
        ));
    }
    for (register, msr, value) in aliases {
        let register = HvRegisterName(register);
        processor
            .write_reg(register, value.into(), &mut protection)
            .unwrap();
        assert_eq!(processor.read_msr(msr).unwrap(), value);
        processor.write_msr(msr, 0, &mut protection).unwrap();
        assert_eq!(processor.read_reg(register).unwrap().as_u64(), 0);
    }
    assert_eq!(
        processor
            .read_reg(HvRegisterName(HvAllArchRegisterName::Sversion.0))
            .unwrap()
            .as_u64(),
        1
    );
    assert!(protection.requested.is_empty());
}

// Test: Program a valid nonzero VINA value, then attempt reserved-bit, read-only, unknown-register, and denied-overlay writes.
// Expected: VINA survives invalid writes, public error codes distinguish unknown names from invalid parameters, and failed overlays retain their register value.
#[test]
fn architectural_register_errors_preserve_vina_and_overlay_state() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = DeniedProtection::default();
    let register = HvRegisterName(HvAllArchRegisterName::VsmVina.0);
    let vina = HvRegisterVsmVina::new()
        .with_vector(0x66)
        .with_enabled(true)
        .with_auto_reset(true)
        .with_auto_eoi(true);
    processor
        .write_reg(register, vina.into_bits().into(), &mut protection)
        .unwrap();
    assert_eq!(
        processor.read_reg(register).unwrap().as_u64(),
        vina.into_bits()
    );
    assert_eq!(processor.vina().into_bits(), vina.into_bits());
    assert_eq!(
        processor.write_reg(register, u64::MAX.into(), &mut protection),
        Err(HvError::InvalidParameter)
    );
    assert_eq!(
        processor.read_reg(register).unwrap().as_u64(),
        vina.into_bits()
    );
    assert_eq!(
        processor.write_reg(
            HvRegisterName(HvAllArchRegisterName::Sversion.0),
            0u64.into(),
            &mut protection
        ),
        Err(HvError::InvalidParameter)
    );
    assert!(matches!(
        processor.read_reg(HvRegisterName(u32::MAX)),
        Err(HvError::UnknownRegisterName)
    ));
    assert_eq!(
        processor.write_reg(HvRegisterName(u32::MAX), 0u64.into(), &mut protection),
        Err(HvError::UnknownRegisterName)
    );
    assert_eq!(
        processor.write_reg(
            HvRegisterName(HvAllArchRegisterName::Sifp.0),
            0x5001u64.into(),
            &mut protection
        ),
        Err(HvError::InvalidParameter)
    );
    assert_eq!(processor.siefp(), 0);
    assert_eq!(protection.requested, [5]);
}

// Test: Fill a message slot, request readiness while full, then acknowledge it in guest memory.
// Expected: Full slots are never overwritten, pending is marked, acknowledgment makes the slot ready again, and delivered payloads/interrupts are exact.
#[test]
fn message_slot_backpressure_and_guest_acknowledgment_preserve_payloads() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = RecordingProtection::new();
    processor.set_simp(0x3001, &mut protection).unwrap();
    processor.set_sint(2, HvSynicSint::new().with_vector(0x66).into());
    let message = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 17, &[0x5a; 24]);
    let mut interrupts = Vec::new();
    processor.request_sint_readiness(1 << 2);
    assert_eq!(
        processor.scan(0, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (1 << 2, None)
    );
    processor
        .post_message(2, &message, &mut |vector, auto_eoi| {
            interrupts.push((vector, auto_eoi))
        })
        .unwrap();
    let mut bytes = [0; HV_MESSAGE_SIZE];
    protection
        .memory
        .read_at(0x3000 + 2 * HV_MESSAGE_SIZE as u64, &mut bytes)
        .unwrap();
    assert_eq!(bytes.as_slice(), message.as_bytes());
    assert_eq!(
        processor.post_message(2, &message, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Err(HvError::ObjectInUse)
    );
    processor.request_sint_readiness(1 << 2);
    assert_eq!(
        processor.scan(0, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, None)
    );
    protection
        .memory
        .read_at(0x3000 + 2 * HV_MESSAGE_SIZE as u64, &mut bytes)
        .unwrap();
    let mut pending = message;
    pending.header.flags.set_message_pending(true);
    assert_eq!(bytes.as_slice(), pending.as_bytes());
    protection
        .memory
        .write_at(0x3000 + 2 * HV_MESSAGE_SIZE as u64, &[0; HV_MESSAGE_SIZE])
        .unwrap();
    assert_eq!(
        processor.scan(0, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (1 << 2, None)
    );
    let second = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 29, &[0xa5; 24]);
    processor
        .post_message(2, &second, &mut |vector, auto_eoi| {
            interrupts.push((vector, auto_eoi))
        })
        .unwrap();
    protection
        .memory
        .read_at(0x3000 + 2 * HV_MESSAGE_SIZE as u64, &mut bytes)
        .unwrap();
    assert_eq!(bytes.as_slice(), second.as_bytes());
    assert_eq!(interrupts, [(0x66, false), (0x66, false)]);
    processor.reset(&mut protection);
    assert_eq!(processor.simp(), 0);
    assert_eq!(processor.siefp(), 0);
    assert_eq!(processor.scontrol(), 1);
    assert_eq!(processor.proxied_sints(), 0);
    assert_eq!(protection.unlocked, [3]);
    assert_eq!(
        processor.post_message(2, &message, &mut |_, _| {}),
        Err(HvError::InvalidSynicState)
    );
    assert_eq!(
        processor.post_message(16, &message, &mut |_, _| {}),
        Err(HvError::InvalidSynicState)
    );
}

// Test: Arm two direct one-shot timers whose deadline order differs from timer-slot order.
// Expected: Scanning returns the earliest deadline, only due timers interrupt, and each expired one-shot disables itself exactly once.
#[test]
fn direct_timer_scan_orders_deadlines_and_disables_expired_oneshots() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    for (index, vector, deadline) in [(0, 0x70, 2000), (1, 0x71, 1000)] {
        processor.set_stimer_config(
            index,
            HvSynicStimerConfig::new()
                .with_auto_enable(true)
                .with_direct_mode(true)
                .with_apic_vector(vector)
                .into(),
        );
        processor.set_stimer_count_at(index, deadline, 900);
    }
    let mut interrupts = Vec::new();
    assert_eq!(
        processor.scan(999, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, Some(1000))
    );
    assert!(interrupts.is_empty());
    assert_eq!(
        processor.scan(1000, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, Some(2000))
    );
    assert_eq!(interrupts, [(0x71, false)]);
    assert!(!HvSynicStimerConfig::from(processor.stimer_config(1)).enabled());
    assert!(HvSynicStimerConfig::from(processor.stimer_config(0)).enabled());
    assert_eq!(
        processor.scan(2000, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, None)
    );
    assert_eq!(
        processor.scan(3000, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, None)
    );
    assert_eq!(interrupts, [(0x71, false), (0x70, false)]);
}

// Test: Run a direct periodic timer across ordinary and wrapping reference-clock deadlines.
// Expected: No early interrupt occurs, each expiration schedules the next period, and a zero count cancels further delivery.
#[test]
fn periodic_timer_deadlines_and_cancellation_survive_clock_wrap() {
    for reference in [100, u64::MAX - 2] {
        let global = GlobalSynic::new(1);
        let mut processor = global.add_vp(VpIndex::new(0));
        processor.set_stimer_config(
            0,
            HvSynicStimerConfig::new()
                .with_auto_enable(true)
                .with_periodic(true)
                .with_direct_mode(true)
                .with_apic_vector(0x72)
                .into(),
        );
        processor.set_stimer_count_at(0, 5, reference);
        let deadline = reference.wrapping_add(5);
        let mut interrupts = Vec::new();
        assert_eq!(
            processor.scan(deadline.wrapping_sub(1), &mut |vector, auto_eoi| interrupts
                .push((vector, auto_eoi))),
            (0, Some(deadline))
        );
        assert!(interrupts.is_empty());
        assert_eq!(
            processor.scan(deadline, &mut |vector, auto_eoi| interrupts
                .push((vector, auto_eoi))),
            (0, Some(deadline.wrapping_add(5)))
        );
        assert_eq!(interrupts, [(0x72, false)]);
        processor.set_stimer_count(0, 0);
        assert_eq!(
            processor.scan(deadline.wrapping_add(10), &mut |vector, auto_eoi| {
                interrupts.push((vector, auto_eoi))
            }),
            (0, None)
        );
        assert_eq!(interrupts, [(0x72, false)]);
    }
}

// Test: Deliver a non-direct timer expiration to an enabled SINT message slot.
// Expected: The timer message contains its exact index, programmed expiration and observed delivery time, and the SINT interrupt uses its configured vector.
#[test]
fn message_timer_delivers_architectural_expiration_payload() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = RecordingProtection::new();
    processor.set_simp(0x3001, &mut protection).unwrap();
    processor.set_sint(2, HvSynicSint::new().with_vector(0x65).into());
    processor.set_stimer_config(
        1,
        HvSynicStimerConfig::new()
            .with_auto_enable(true)
            .with_sint(2)
            .into(),
    );
    processor.set_stimer_count_at(1, 1000, 900);
    let mut interrupts = Vec::new();
    assert_eq!(
        processor.scan(1007, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        (0, None)
    );
    let mut bytes = [0; HV_MESSAGE_SIZE];
    protection
        .memory
        .read_at(0x3000 + 2 * HV_MESSAGE_SIZE as u64, &mut bytes)
        .unwrap();
    let payload = [
        1u32.to_le_bytes().as_slice(),
        0u32.to_le_bytes().as_slice(),
        1000u64.to_le_bytes().as_slice(),
        1007u64.to_le_bytes().as_slice(),
    ]
    .concat();
    let expected = HvMessage::new(HvMessageType::HvMessageTypeTimerExpired, 0, &payload);
    assert_eq!(bytes.as_slice(), expected.as_bytes());
    assert_eq!(interrupts, [(0x65, false)]);
    assert!(!HvSynicStimerConfig::from(processor.stimer_config(1)).enabled());
}

// Test: Signal the same high-numbered event twice, clear its guest bit, and signal it again.
// Expected: The exact SINT/flag byte changes, duplicate signals do not interrupt, and guest acknowledgment permits another vector/auto-EOI notification.
#[test]
fn event_delivery_sets_exact_guest_bit_and_deduplicates_interrupts() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = RecordingProtection::new();
    processor.set_siefp(0x2001, &mut protection).unwrap();
    processor.set_scontrol(1);
    processor.set_sint(
        3,
        HvSynicSint::new()
            .with_vector(0x71)
            .with_auto_eoi(true)
            .into(),
    );
    let mut interrupts = Vec::new();
    assert!(matches!(
        global.signal_event(VpIndex::new(0), 3, 2003, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Ok(true)
    ));
    assert!(matches!(
        global.signal_event(VpIndex::new(0), 3, 2003, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Ok(false)
    ));
    let mut page = [0; 4096];
    protection.memory.read_at(0x2000, &mut page).unwrap();
    let mut expected = [0; 4096];
    expected[3 * 256 + 2003 / 8] = 1 << (2003 % 8);
    assert_eq!(page, expected);
    assert_eq!(interrupts, [(0x71, true)]);
    protection
        .memory
        .write_at(0x2000 + 3 * 256 + 2003 / 8, &[0])
        .unwrap();
    assert!(matches!(
        global.signal_event(VpIndex::new(0), 3, 2003, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Ok(true)
    ));
    assert_eq!(interrupts, [(0x71, true), (0x71, true)]);
}

// Test: Signal invalid VP/SINT/flag addresses, masked/disabled SINTs, and a proxied SINT.
// Expected: Invalid or disabled requests are ignored, proxy forwarding is explicit, and no local interrupt is delivered.
#[test]
fn event_rejection_and_proxy_forwarding_do_not_inject_local_interrupts() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut interrupts = Vec::new();
    for (vp, sint, flag) in [(7, 0, 0), (0, 16, 0), (0, 0, 2048), (0, 0, 0)] {
        assert!(matches!(
            global.signal_event(VpIndex::new(vp), sint, flag, &mut |vector, auto_eoi| {
                interrupts.push((vector, auto_eoi))
            }),
            Ok(false)
        ));
    }
    processor.set_sint(0, HvSynicSint::new().with_vector(0x60).into());
    processor.set_scontrol(0);
    assert!(matches!(
        global.signal_event(VpIndex::new(0), 0, 0, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Ok(false)
    ));
    processor.set_sint(0, HvSynicSint::new().with_proxy(true).into());
    assert!(matches!(
        global.signal_event(VpIndex::new(0), 0, 0, &mut |vector, auto_eoi| interrupts
            .push((vector, auto_eoi))),
        Err(SintProxied)
    ));
    assert!(interrupts.is_empty());
    assert_eq!(processor.proxied_sints(), 1);
}

#[derive(Default)]
struct DeniedProtection {
    requested: Vec<u64>,
    unlocked: Vec<u64>,
}

impl VtlProtectAccess for DeniedProtection {
    fn check_modify_and_lock_overlay_page(
        &mut self,
        gpn: u64,
        _check_perms: hvdef::HvMapGpaFlags,
        _new_perms: Option<hvdef::HvMapGpaFlags>,
    ) -> Result<guestmem::UserLockedPages, HvError> {
        self.requested.push(gpn);
        Err(HvError::InvalidParameter)
    }

    fn unlock_overlay_page(&mut self, gpn: u64) -> Result<(), HvError> {
        self.unlocked.push(gpn);
        Ok(())
    }
}

// Test: Program all SINT and timer slots with distinguishable values through the public MSR API.
// Expected: Every slot retains its own value, neighboring slots remain independent, version is one, and EOM always reads zero.
#[test]
fn msr_slots_preserve_distinct_sint_and_timer_values() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = DeniedProtection::default();
    assert_eq!(processor.read_msr(hvdef::HV_X64_MSR_SVERSION).unwrap(), 1);
    for index in 0..16u32 {
        let value = 0x40 + u64::from(index) + if index % 2 == 0 { 1 << 16 } else { 0 };
        processor
            .write_msr(hvdef::HV_X64_MSR_SINT0 + index, value, &mut protection)
            .unwrap();
    }
    for index in 0..4u32 {
        processor
            .write_msr(
                hvdef::HV_X64_MSR_STIMER0_CONFIG + index * 2,
                (u64::from(index) << 16) | 2,
                &mut protection,
            )
            .unwrap();
        processor
            .write_msr(
                hvdef::HV_X64_MSR_STIMER0_COUNT + index * 2,
                0x1000 + u64::from(index),
                &mut protection,
            )
            .unwrap();
    }
    for index in 0..16u32 {
        let expected = 0x40 + u64::from(index) + if index % 2 == 0 { 1 << 16 } else { 0 };
        assert_eq!(
            processor.read_msr(hvdef::HV_X64_MSR_SINT0 + index).unwrap(),
            expected
        );
    }
    for index in 0..4u32 {
        assert_eq!(
            processor
                .read_msr(hvdef::HV_X64_MSR_STIMER0_CONFIG + index * 2)
                .unwrap(),
            (u64::from(index) << 16) | 2
        );
        assert_eq!(
            processor
                .read_msr(hvdef::HV_X64_MSR_STIMER0_COUNT + index * 2)
                .unwrap(),
            0x1000 + u64::from(index)
        );
    }
    processor
        .write_msr(hvdef::HV_X64_MSR_SCONTROL, 1, &mut protection)
        .unwrap();
    assert_eq!(processor.read_msr(hvdef::HV_X64_MSR_SCONTROL).unwrap(), 1);
    processor
        .write_msr(hvdef::HV_X64_MSR_EOM, u64::MAX, &mut protection)
        .unwrap();
    assert_eq!(processor.read_msr(hvdef::HV_X64_MSR_EOM).unwrap(), 0);
    assert!(protection.requested.is_empty());
    assert!(protection.unlocked.is_empty());
}

// Test: Write read-only/unknown MSRs and read an unknown MSR.
// Expected: Read-only writes return InvalidAccess, unknown addresses return Unknown, and the version remains unchanged.
#[test]
fn invalid_msr_accesses_preserve_read_only_state() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = DeniedProtection::default();
    assert!(matches!(
        processor.write_msr(hvdef::HV_X64_MSR_SVERSION, 99, &mut protection),
        Err(MsrError::InvalidAccess)
    ));
    assert!(matches!(
        processor.write_msr(0xffff_ffff, 1, &mut protection),
        Err(MsrError::Unknown)
    ));
    assert!(matches!(
        processor.read_msr(0xffff_ffff),
        Err(MsrError::Unknown)
    ));
    assert_eq!(processor.sversion(), 1);
    assert!(protection.requested.is_empty());
}

// Test: Enable message/event overlays when the protection service refuses their pages.
// Expected: Exact requested GPNs are recorded, InvalidAccess is returned, and previously disabled register values remain unchanged.
#[test]
fn denied_overlay_mapping_preserves_message_and_event_registers() {
    let global = GlobalSynic::new(1);
    let mut processor = global.add_vp(VpIndex::new(0));
    let mut protection = DeniedProtection::default();
    for (msr, initial, attempted) in [
        (hvdef::HV_X64_MSR_SIEFP, 0x5000, 0x9001),
        (hvdef::HV_X64_MSR_SIMP, 0x7000, 0xb001),
    ] {
        processor.write_msr(msr, initial, &mut protection).unwrap();
        assert!(matches!(
            processor.write_msr(msr, attempted, &mut protection),
            Err(MsrError::InvalidAccess)
        ));
        assert_eq!(processor.read_msr(msr).unwrap(), initial);
    }
    assert_eq!(protection.requested, [9, 11]);
    assert!(protection.unlocked.is_empty());
}
