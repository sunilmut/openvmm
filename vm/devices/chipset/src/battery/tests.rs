// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use futures::task::Context;
use test_with_tracing::test;
use vmcore::line_interrupt::LineInterrupt;
use vmcore::line_interrupt::test_helpers::TestLineInterruptTarget;
use vmcore::save_restore::SaveRestore;

fn create_test_platform() -> (BatteryDevice, mesh::Sender<HostBatteryUpdate>) {
    create_platform_with_interrupt(
        LineInterrupt::detached(),
        BATTERY_MMIO_REGION_BASE_ADDRESS_X64,
    )
}

fn create_platform_with_interrupt(
    notify_interrupt: LineInterrupt,
    base: u64,
) -> (BatteryDevice, mesh::Sender<HostBatteryUpdate>) {
    let (tx, rx) = mesh::channel::<HostBatteryUpdate>();
    let battery = BatteryDevice::new(
        BatteryRuntimeDeps {
            battery_status_recv: {
                tx.send(HostBatteryUpdate::default());
                rx
            },
            notify_interrupt,
        },
        base,
    );
    (battery, tx)
}

fn mmio_read_helper(battery: &mut BatteryDevice, offset: u64) -> [u8; 4] {
    let mut bytes = [0; 4];
    battery
        .mmio_read(battery.base_addr + offset, &mut bytes)
        .unwrap();
    bytes
}

fn check_mmio_read(battery: &mut BatteryDevice, offset: u64, expected_value: u32) {
    assert_eq!(
        u32::from_ne_bytes(mmio_read_helper(battery, offset)),
        expected_value
    );
    assert_eq!(
        battery.read_register(RegisterOffset(offset)),
        expected_value
    );
}

fn send_update(
    battery: &mut BatteryDevice,
    update: HostBatteryUpdate,
    sender: &mesh::Sender<HostBatteryUpdate>,
) {
    sender.send(update);
    battery.poll_device(&mut Context::from_waker(std::task::Waker::noop()));
}

// Test: Checkpoint battery registers and a pending notification at both supported MMIO bases.
// Expected: Reset removes state/IRQ, restore recovers all values/IRQ, and only matching acknowledgements clear it.
#[test]
fn checkpoint_restores_registers_and_pending_notification_at_each_mmio_base() {
    for base in [
        BATTERY_MMIO_REGION_BASE_ADDRESS_X64,
        BATTERY_MMIO_REGION_BASE_ADDRESS_ARM,
    ] {
        let target = TestLineInterruptTarget::new_arc();
        let (mut battery, sender) = create_platform_with_interrupt(
            LineInterrupt::new_with_target("battery", target.clone(), 0),
            base,
        );
        send_update(
            &mut battery,
            HostBatteryUpdate {
                battery_present: true,
                charging: true,
                discharging: false,
                rate: 27,
                remaining_capacity: 42,
                max_capacity: 100,
                ac_online: true,
            },
            &sender,
        );
        let expected = [(0, 0x1f), (4, 2), (8, 1350), (12, 2100), (16, 1), (20, 2)];
        for (offset, value) in expected {
            assert_eq!(
                u32::from_le_bytes(mmio_read_helper(&mut battery, offset)),
                value
            );
        }
        assert!(target.is_high(0));
        let saved = battery.save().unwrap();
        block_on(battery.reset());
        assert!(!target.is_high(0));
        for (offset, value) in [
            (0, 0xf),
            (4, 0),
            (8, u32::MAX),
            (12, u32::MAX),
            (16, 0),
            (20, 0),
        ] {
            assert_eq!(
                u32::from_le_bytes(mmio_read_helper(&mut battery, offset)),
                value
            );
        }
        battery.restore(saved).unwrap();
        for (offset, value) in expected {
            assert_eq!(
                u32::from_le_bytes(mmio_read_helper(&mut battery, offset)),
                value
            );
        }
        assert!(target.is_high(0));
        battery
            .supports_mmio()
            .unwrap()
            .mmio_write(base + 0x18, &1u32.to_le_bytes())
            .unwrap();
        assert!(target.is_high(0));
        assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 0x14)), 2);
        battery
            .mmio_write(base + 0x18, &2u32.to_le_bytes())
            .unwrap();
        assert!(!target.is_high(0));
        assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 0x14)), 0);
        let acknowledged = battery.save().unwrap();
        block_on(battery.reset());
        battery.restore(acknowledged).unwrap();
        assert!(!target.is_high(0));
        assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 12)), 2100);
        assert_eq!(
            battery.get_static_regions(),
            &[("battery", base..=base + 0x1f)]
        );
    }
}

// Test: Queue several host updates, close the channel, and attempt writes to read-only registers.
// Expected: Polling retains the latest update, channel closure preserves it, and writes cannot clear notification/state.
#[test]
fn polling_drains_updates_and_read_only_writes_preserve_the_latest_state() {
    let target = TestLineInterruptTarget::new_arc();
    let base = BATTERY_MMIO_REGION_BASE_ADDRESS_X64;
    let (mut battery, sender) = create_platform_with_interrupt(
        LineInterrupt::new_with_target("battery", target.clone(), 0),
        base,
    );
    for remaining_capacity in [100, 50, 25] {
        sender.send(HostBatteryUpdate {
            battery_present: true,
            discharging: true,
            max_capacity: 100,
            remaining_capacity,
            rate: 20,
            ..HostBatteryUpdate::default()
        });
    }
    drop(sender);
    for _ in 0..2 {
        battery
            .supports_poll_device()
            .unwrap()
            .poll_device(&mut Context::from_waker(std::task::Waker::noop()));
        assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 12)), 1250);
        assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 8)), 1000);
        assert!(target.is_high(0));
    }
    for offset in [0, 4, 8, 12, 16, 20, 28] {
        battery
            .mmio_write(base + offset, &u32::MAX.to_le_bytes())
            .unwrap();
    }
    assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 0)), 0x1f);
    assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 4)), 1);
    assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 12)), 1250);
    assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 20)), 2);
    assert_eq!(u32::from_le_bytes(mmio_read_helper(&mut battery, 28)), 0);
    assert!(target.is_high(0));
}

/// Test basic battery mmio behavior
#[test]
fn test_basic_battery_mmio() {
    // create battery, send channel, and a blank battery state
    let (mut battery, tx) = create_test_platform();
    let mut state = HostBatteryUpdate::default();

    // test uninitialized state.
    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0xF);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_PRESENT_RATE.0,
        0xFFFFFFFF,
    );
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        0xFFFFFFFF,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        0,
    );

    // set battery to be present, with AC power and full capacity
    state.battery_present = true;
    state.remaining_capacity = 100;
    state.max_capacity = 100;
    state.ac_online = true;
    send_update(&mut battery, state, &tx);

    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0x1F);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_PRESENT_RATE.0, 0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        (100 * VIRTUAL_BATTERY_CAPACITY) / 100,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0x1);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        2,
    );

    // set battery to be charging, with 50% capacity
    state.charging = true;
    state.remaining_capacity = 50;
    state.rate = 40;
    send_update(&mut battery, state, &tx);

    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0x1F);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0x2);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_PRESENT_RATE.0,
        (40 * VIRTUAL_BATTERY_CAPACITY) / 100,
    );
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        (50 * VIRTUAL_BATTERY_CAPACITY) / 100,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0x1);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        2,
    );

    // set battery to be discharging, no ac, 50% capacity
    state.ac_online = false;
    state.charging = false;
    state.discharging = true;
    state.rate = 45;
    send_update(&mut battery, state, &tx);
    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0x1F);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0x1);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_PRESENT_RATE.0,
        (45 * VIRTUAL_BATTERY_CAPACITY) / 100,
    );
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        (50 * VIRTUAL_BATTERY_CAPACITY) / 100,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0x0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        2,
    );

    // ensure that mmio_write clears the notify_bits
    let data: u32 = 0x2;
    let _ = battery.mmio_write(
        battery.base_addr + RegisterOffset::BATTERY_ACPI_NOTIFY_CLEAR.0,
        &data.to_ne_bytes(),
    );
    assert_eq!(battery.notify_bits, 0);
}

/// Test values when battery is not present
#[test]
fn test_battery_not_present() {
    // create battery and send channel
    let (mut battery, tx) = create_test_platform();

    // set ac power online, no battery present
    let state = HostBatteryUpdate {
        ac_online: true,
        ..HostBatteryUpdate::default()
    };
    send_update(&mut battery, state, &tx);
    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0xF);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_PRESENT_RATE.0,
        0xFFFFFFFF,
    );
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        0xFFFFFFFF,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0x1);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        0x2,
    );
}

/// Test bad register read/write operations and ensure they error
#[test]
fn test_bad_register_read_writes() {
    // create battery and send channel
    let (mut battery, _) = create_test_platform();

    // Test reading with a data size not equal to size_of::<u32>()
    let mut data = vec![0; size_of::<u32>() + 1];
    match battery.mmio_read(battery.base_addr, &mut data) {
        IoResult::Err(e) => assert!(matches!(e, IoError::InvalidAccessSize)),
        _ => panic!("Expected error, but got Ok"),
    }

    // Test writing with a data size not equal to size_of::<u32>()
    let data = vec![0; size_of::<u32>() + 1];
    match battery.mmio_write(battery.base_addr, &data) {
        IoResult::Err(e) => assert!(matches!(e, IoError::InvalidAccessSize)),
        _ => panic!("Expected error, but got Ok"),
    }

    // Test writing with data that cannot be converted into a `u32`
    let data = vec![0; size_of::<u32>() - 1];
    match battery.mmio_write(battery.base_addr, &data) {
        IoResult::Err(e) => assert!(matches!(e, IoError::InvalidAccessSize)),
        _ => panic!("Expected error, but got Ok"),
    }
}

/// Test bad capacity on a battery
#[test]
fn test_bad_battery_capacity() {
    // create battery and send channel
    let (mut battery, tx) = create_test_platform();

    // set battery present with 50% capacity and 0 max capacity
    let state = HostBatteryUpdate {
        battery_present: true,
        remaining_capacity: 50,
        max_capacity: 0,
        ac_online: true,
        ..HostBatteryUpdate::default()
    };
    send_update(&mut battery, state, &tx);
    check_mmio_read(&mut battery, RegisterOffset::STA_BATTERY_STATUS.0, 0xF);
    check_mmio_read(&mut battery, RegisterOffset::BST_BATTERY_STATE.0, 0x0);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_PRESENT_RATE.0,
        0xFFFFFFFF,
    );
    check_mmio_read(
        &mut battery,
        RegisterOffset::BST_BATTERY_REMAINING_CAPACITY.0,
        0xFFFFFFFF,
    );
    check_mmio_read(&mut battery, RegisterOffset::PSR_AC_POWER_STATUS.0, 0x1);
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        0x2,
    );
}
