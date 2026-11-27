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
    let base = *battery.get_static_regions()[0].1.start();
    battery.mmio_read(base + offset, &mut bytes).unwrap();
    bytes
}

fn check_mmio_read(battery: &mut BatteryDevice, offset: u64, expected_value: u32) {
    assert_eq!(
        u32::from_ne_bytes(mmio_read_helper(battery, offset)),
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

// Test: Publish absent, full, charging and discharging host battery updates.
// Expected: Guest registers reflect each update and acknowledgement clears notify.
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
    battery
        .mmio_write(
            BATTERY_MMIO_REGION_BASE_ADDRESS_X64 + RegisterOffset::BATTERY_ACPI_NOTIFY_CLEAR.0,
            &data.to_ne_bytes(),
        )
        .unwrap();
    check_mmio_read(
        &mut battery,
        RegisterOffset::BATTERY_ACPI_NOTIFY_STATUS.0,
        0,
    );
}

// Test: Publish AC-online state with no battery present.
// Expected: Battery values stay unavailable while AC status and notify are set.
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

// Test: Read and write unsupported MMIO transfer sizes.
// Expected: InvalidAccessSize preserves read buffers and the battery registers.
#[test]
fn test_bad_register_read_writes() {
    // create battery and send channel
    let (mut battery, _) = create_test_platform();

    let expected = [0, 4, 8, 12, 16, 20].map(|offset| mmio_read_helper(&mut battery, offset));
    for size in [0, 1, 2, 3, 5, 8] {
        let mut data = vec![0xa5; size];
        assert!(matches!(
            battery.mmio_read(BATTERY_MMIO_REGION_BASE_ADDRESS_X64, &mut data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(data, vec![0xa5; size]);
        assert!(matches!(
            battery.mmio_write(BATTERY_MMIO_REGION_BASE_ADDRESS_X64, &data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(
            [0, 4, 8, 12, 16, 20].map(|offset| mmio_read_helper(&mut battery, offset)),
            expected
        );
    }
}

// Test: Publish a present battery whose maximum capacity is zero.
// Expected: The guest sees an unavailable battery but retains AC status and notify.
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
