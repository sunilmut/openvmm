// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::pio::ExternallyManagedPortIoIntercepts;
use mesh::rpc::RpcSend;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use std::sync::Arc;
use vmcore::line_interrupt::test_helpers::TestLineInterruptTarget;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;

const BASE: u16 = 0x1000;

struct PioRegion(Option<u16>);

impl ControlPortIoIntercept for PioRegion {
    fn region_name(&self) -> &str {
        "pm"
    }
    fn map(&mut self, addr: u16) {
        self.0 = Some(addr);
    }
    fn unmap(&mut self) {
        self.0 = None;
    }
    fn addr(&self) -> Option<u16> {
        self.0
    }
    fn len(&self) -> u16 {
        0x37
    }
    fn offset_of(&self, addr: u16) -> Option<u16> {
        addr.checked_sub(self.0?)
            .filter(|offset| *offset < self.len())
    }
}

async fn new_pm(
    driver: &DefaultDriver,
    line: LineInterrupt,
    power_button_recv: Option<mesh::Receiver<PowerButtonRpc>>,
) -> (VmTimeKeeper, PowerManagementDevice) {
    let time = VmTimeKeeper::new(driver, VmTime::from_100ns(0));
    let access = time.builder().build(driver).await.unwrap();
    let mut pm = PowerManagementDevice::new(
        Box::new(|_| panic!("unexpected power action")),
        line,
        &mut ExternallyManagedPortIoIntercepts,
        access.access("pm"),
        Some(EnableAcpiMode {
            default_pio_dynamic: BASE,
        }),
        None,
        power_button_recv,
    );
    pm.rt.pio_dynamic = Box::new(PioRegion(Some(BASE)));
    (time, pm)
}

fn write(pm: &mut PowerManagementDevice, reg: DynReg, value: u16) {
    pm.io_write(BASE + u16::from(reg.0), &value.to_le_bytes())
        .unwrap();
}

fn gpe_status(pm: &mut PowerManagementDevice) -> u16 {
    let mut data = [0; 2];
    pm.io_read(BASE + u16::from(DynReg::GEN_PURPOSE_STATUS.0), &mut data)
        .unwrap();
    u16::from_le_bytes(data)
}

fn read(pm: &mut PowerManagementDevice, reg: DynReg) -> u32 {
    let mut data = [0; 4];
    pm.supports_pio()
        .unwrap()
        .io_read(BASE + u16::from(reg.0), &mut data)
        .unwrap();
    u32::from_le_bytes(data)
}

// Test: Construct, relocate, unmap, and reset a PM device with hypervisor timer assist.
// Expected: Timer-assist callbacks disable first and always track the current mapped timer port.
#[async_test]
async fn timer_assist_tracks_construction_remapping_unmapping_and_reset(driver: DefaultDriver) {
    struct RecordingAssist(Arc<Mutex<Vec<Option<u16>>>>);
    impl PmTimerAssist for RecordingAssist {
        fn set(&self, port: Option<u16>) {
            self.0.lock().push(port);
        }
    }
    let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let source = time.builder().build(&driver).await.unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut pm = PowerManagementDevice::new(
        Box::new(|_| panic!("unexpected power action")),
        LineInterrupt::detached(),
        &mut ExternallyManagedPortIoIntercepts,
        source.access("pm_assist_test"),
        Some(EnableAcpiMode {
            default_pio_dynamic: BASE,
        }),
        Some(Box::new(RecordingAssist(calls.clone()))),
        None,
    );
    pm.rt.pio_dynamic = Box::new(PioRegion(Some(BASE)));
    assert_eq!(*calls.lock(), [None, Some(0x1008)]);
    pm.update_dynamic_pio_mappings(Some(0x2000));
    assert_eq!(*calls.lock(), [None, Some(0x1008), Some(0x2008)]);
    pm.update_dynamic_pio_mappings(None);
    assert_eq!(*calls.lock(), [None, Some(0x1008), Some(0x2008), None]);
    pm.reset().await;
    assert_eq!(
        *calls.lock(),
        [None, Some(0x1008), Some(0x2008), None, None, Some(0x1008)]
    );
    assert_eq!(read(&mut pm, DynReg::CONTROL), 1);
}

// Test: Program all writable control fields and checkpoint them across device reset.
// Expected: Reserved bits stay clear and every programmed register is restored through port reads.
#[async_test]
async fn writable_register_masks_and_checkpoint_round_trip(driver: DefaultDriver) {
    let (_time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    let registers = [
        (DynReg::RESUME_ENABLE, 0x0521),
        (DynReg::GEN_PURPOSE_ENABLE, 0x0f01),
        (DynReg::PROC_CONTROL, 0x00023e1e),
        (DynReg::GLOBAL_ENABLE, 0x8d13),
        (DynReg::GLOBAL_CONTROL, 0x0701ffe5),
        (DynReg::DEVICE_CONTROL, u32::MAX),
    ];
    for (reg, expected) in registers {
        pm.io_write(BASE + u16::from(reg.0), &u32::MAX.to_le_bytes())
            .unwrap();
        assert_eq!(read(&mut pm, reg), expected, "register {reg:?}");
    }
    let saved = pm.save().unwrap();
    pm.reset().await;
    for (reg, _) in registers {
        assert_eq!(read(&mut pm, reg), 0);
    }
    pm.restore(saved).unwrap();
    for (reg, expected) in registers {
        assert_eq!(read(&mut pm, reg), expected, "restored register {reg:?}");
    }
}

// Test: Rewrite individual byte lanes in processor and device control registers.
// Expected: The written lane changes, other lanes survive, and processor reserved bits remain clear.
#[async_test]
async fn byte_lane_writes_preserve_neighboring_control_bytes(driver: DefaultDriver) {
    let (_time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    pm.io_write(
        BASE + u16::from(DynReg::DEVICE_CONTROL.0),
        &0x12345678u32.to_le_bytes(),
    )
    .unwrap();
    pm.io_write(BASE + u16::from(DynReg::DEVICE_CONTROL.0) + 1, &[0xab])
        .unwrap();
    assert_eq!(read(&mut pm, DynReg::DEVICE_CONTROL), 0x1234ab78);
    let mut middle = [0; 2];
    pm.io_read(BASE + u16::from(DynReg::DEVICE_CONTROL.0) + 1, &mut middle)
        .unwrap();
    assert_eq!(middle, [0xab, 0x34]);
    pm.io_write(
        BASE + u16::from(DynReg::PROC_CONTROL.0),
        &u32::MAX.to_le_bytes(),
    )
    .unwrap();
    pm.io_write(BASE + u16::from(DynReg::PROC_CONTROL.0) + 1, &[0])
        .unwrap();
    assert_eq!(read(&mut pm, DynReg::PROC_CONTROL), 0x0002001e);
    pm.io_write(BASE + u16::from(DynReg::PROC_CONTROL.0), &[0x12])
        .unwrap();
    assert_eq!(read(&mut pm, DynReg::PROC_CONTROL), 0x00020012);
}

// Test: Request platform-defined sleep states, unsupported states, and reset values through ports.
// Expected: Only enabled S5, enabled S4, and the reset value produce their distinct power callbacks.
#[async_test]
async fn sleep_and_reset_commands_deliver_only_the_requested_power_actions(driver: DefaultDriver) {
    let (_time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    let actions = Arc::new(Mutex::new(Vec::new()));
    let recorded = actions.clone();
    *pm.power_action() = Box::new(move |action| {
        recorded.lock().push(match action {
            PowerAction::PowerOff => "off",
            PowerAction::Hibernate => "hibernate",
            PowerAction::Reboot => "reboot",
        })
    });
    write(&mut pm, DynReg::CONTROL, 0x0401);
    write(&mut pm, DynReg::CONTROL, 0x2801);
    assert!(actions.lock().is_empty());
    write(&mut pm, DynReg::CONTROL, 0x2001);
    write(&mut pm, DynReg::CONTROL, 0x2401);
    pm.io_write(BASE + u16::from(DynReg::RESET.0), &[RESET_VALUE ^ 0xff])
        .unwrap();
    assert_eq!(*actions.lock(), ["off", "hibernate"]);
    pm.io_write(BASE + u16::from(DynReg::RESET.0), &[RESET_VALUE])
        .unwrap();
    assert_eq!(*actions.lock(), ["off", "hibernate", "reboot"]);
}

// Test: Advance stopped VM time by one second and past a 32-bit PM timer wrap, then write the timer.
// Expected: Reads use 3.579545 MHz VM time with wraparound and ignore guest writes.
#[async_test]
async fn timer_uses_vm_time_wraps_and_ignores_writes(driver: DefaultDriver) {
    let (mut time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    assert_eq!(read(&mut pm, DynReg::TIMER), 0);
    time.restore(vmcore::vmtime::SavedState::from_vmtime(VmTime::from_100ns(
        10_000_000,
    )))
    .await;
    assert_eq!(read(&mut pm, DynReg::TIMER), 3_579_545);
    pm.io_write(BASE + u16::from(DynReg::TIMER.0), &u32::MAX.to_le_bytes())
        .unwrap();
    assert_eq!(read(&mut pm, DynReg::TIMER), 3_579_545);
    time.restore(vmcore::vmtime::SavedState::from_vmtime(VmTime::from_100ns(
        12_000_000_000,
    )))
    .await;
    assert_eq!(read(&mut pm, DynReg::TIMER), 486_704);
}

// Test: Relocate and unmap the dynamic I/O window with a latched GPE event.
// Expected: Only the current window responds, state survives remapping, and reset restores ACPI defaults.
#[async_test]
async fn remapping_preserves_registers_and_reset_restores_the_default_window(
    driver: DefaultDriver,
) {
    let (_time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    pm.supports_line_interrupt_target()
        .unwrap()
        .set_irq(8, true);
    pm.set_irq(8, false);
    pm.update_dynamic_pio_mappings(Some(0x2000));
    assert!(matches!(
        pm.io_read(BASE, &mut [0; 2]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    let mut status = [0; 2];
    pm.io_read(
        0x2000 + u16::from(DynReg::GEN_PURPOSE_STATUS.0),
        &mut status,
    )
    .unwrap();
    assert_eq!(u16::from_le_bytes(status), 0x100);
    pm.update_dynamic_pio_mappings(None);
    assert!(matches!(
        pm.io_read(0x2000, &mut [0; 2]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        pm.io_write(0x2000, &[0; 2]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    pm.reset().await;
    assert_eq!(read(&mut pm, DynReg::CONTROL), 1);
    assert_eq!(gpe_status(&mut pm), 0);
    assert_eq!(pm.valid_lines(), &[0..=15]);
}

// Test: Access inert processor/input registers and unused holes in the mapped PM window.
// Expected: Inert registers and holes read zero, ignore writes, and do not request power actions.
#[async_test]
async fn inert_registers_and_holes_ignore_writes(driver: DefaultDriver) {
    let (_time, mut pm) = new_pm(&driver, LineInterrupt::detached(), None).await;
    for offset in [0x06, 0x14, 0x15, 0x16, 0x24, 0x30, 0x31, 0x32] {
        pm.io_write(BASE + offset, &[0xff]).unwrap();
        let mut value = [0xa5];
        pm.io_read(BASE + offset, &mut value).unwrap();
        assert_eq!(value, [0], "offset {offset:#x}");
    }
}

#[async_test]
async fn power_button_latches_until_cleared_and_obeys_sci_enable(driver: DefaultDriver) {
    let target = TestLineInterruptTarget::new_arc();
    let (send, recv) = mesh::channel();
    let (_time, mut pm) = new_pm(
        &driver,
        LineInterrupt::new_with_target("pm", target.clone(), 0),
        Some(recv),
    )
    .await;

    write(&mut pm, DynReg::RESUME_ENABLE, ENABLE_TIMER_OVERFLOW_MASK);
    let mut response = std::pin::pin!(send.call(PowerButtonRpc::Press, ()));
    assert!(futures::poll!(&mut response).is_pending());
    futures::future::poll_fn(|cx| {
        pm.poll_device(cx);
        std::task::Poll::Ready(())
    })
    .await;
    response.await.unwrap();
    let mut status = [0; 2];
    pm.io_read(BASE + u16::from(DynReg::STATUS.0), &mut status)
        .unwrap();
    assert_eq!(u16::from_le_bytes(status), POWER_BUTTON_MASK);
    assert!(
        !target.is_high(0),
        "timer enable must not enable the power button"
    );

    write(&mut pm, DynReg::RESUME_ENABLE, POWER_BUTTON_MASK);
    assert!(target.is_high(0));
    write(&mut pm, DynReg::CONTROL, 0);
    assert!(!target.is_high(0));
    write(&mut pm, DynReg::CONTROL, CONTROL_SCI_ENABLE_MASK);
    assert!(target.is_high(0));

    let saved = pm.save().unwrap();
    pm.reset().await;
    assert!(!target.is_high(0));
    assert_eq!(pm.state.status, 0);
    pm.restore(saved).unwrap();
    assert!(target.is_high(0));
    pm.pcat_facp_acpi_enable(false);
    assert!(!target.is_high(0));
    pm.pcat_facp_acpi_enable(true);
    assert!(target.is_high(0));
    write(&mut pm, DynReg::STATUS, POWER_BUTTON_MASK);
    assert!(!target.is_high(0));
    assert_eq!(pm.state.status & POWER_BUTTON_MASK, 0);
}

#[async_test]
async fn sci_requires_a_matching_enabled_gpe(driver: DefaultDriver) {
    let target = TestLineInterruptTarget::new_arc();
    let (_time, mut pm) = new_pm(
        &driver,
        LineInterrupt::new_with_target("pm", target.clone(), 0),
        None,
    )
    .await;
    write(&mut pm, DynReg::GEN_PURPOSE_ENABLE, 1);
    pm.set_irq(8, true);
    pm.set_irq(8, false);
    assert_eq!(gpe_status(&mut pm), 1 << 8);
    assert!(!target.is_high(0), "GPE0 enable must not enable GPE8");
    write(&mut pm, DynReg::GEN_PURPOSE_ENABLE, 1 << 8);
    assert!(target.is_high(0));
    write(&mut pm, DynReg::GEN_PURPOSE_STATUS, 1 << 8);
    assert!(!target.is_high(0));
}

#[async_test]
async fn sci_requires_a_matching_enabled_pm_event(driver: DefaultDriver) {
    let target = TestLineInterruptTarget::new_arc();
    let (_time, mut pm) = new_pm(
        &driver,
        LineInterrupt::new_with_target("pm", target.clone(), 0),
        None,
    )
    .await;
    pm.state.status = 1 << 5;
    write(&mut pm, DynReg::RESUME_ENABLE, ENABLE_TIMER_OVERFLOW_MASK);
    assert!(
        !target.is_high(0),
        "timer enable must not enable the global event"
    );
    write(&mut pm, DynReg::RESUME_ENABLE, 1 << 5);
    assert!(target.is_high(0));
    write(&mut pm, DynReg::STATUS, 1 << 5);
    assert!(!target.is_high(0));
}
