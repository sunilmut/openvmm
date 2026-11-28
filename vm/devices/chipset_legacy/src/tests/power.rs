// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::piix4_pm::Piix4Pm;
use chipset::pm::PowerAction;
use chipset::pm::PowerManagementDevice;
use chipset_device::ChipsetDevice;
use chipset_device::interrupt::LineInterruptTarget;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use test_with_tracing::test;
use vmcore::line_interrupt::LineInterrupt;
use vmcore::line_interrupt::LineSetTarget;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;

#[derive(Default)]
struct Sci(AtomicBool);

impl LineSetTarget for Sci {
    fn set_irq(&self, _vector: u32, high: bool) {
        self.0.store(high, Ordering::SeqCst);
    }
}

struct TestPm {
    pool: pal_async::DefaultPool,
    _time: VmTimeKeeper,
    device: Piix4Pm,
    ports: PioRegistrar,
    actions: Arc<Mutex<Vec<PowerAction>>>,
    sci: Arc<Sci>,
}

impl TestPm {
    fn new() -> Self {
        let mut pool = pal_async::DefaultPool::new();
        let driver = pool.driver();
        let time = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
        let source = pool.run_until(time.builder().build(&driver)).unwrap();
        let mut ports = PioRegistrar::default();
        let actions = Arc::new(Mutex::new(Vec::new()));
        let recorded = actions.clone();
        let sci = Arc::new(Sci::default());
        let inner = PowerManagementDevice::new(
            Box::new(move |action| recorded.lock().push(action)),
            LineInterrupt::new_with_target("sci", sci.clone(), 9),
            &mut ports,
            source.access("piix4-pm"),
            None,
            None,
            None,
        );
        let device = Piix4Pm::new(inner, &mut ports);
        Self {
            pool,
            _time: time,
            device,
            ports,
            actions,
            sci,
        }
    }
}

// Test: Program the PM BAR and enable bits, then reset and restore the device.
// Expected: Port registration follows the enabled BAR and saved configuration survives reset.
#[test]
fn pm_bar_enable_and_restore_update_registered_io_ranges() {
    let mut pm = TestPm::new();
    assert_eq!(pm.ports.base("control"), Some(0xb2));
    assert_eq!(pm.ports.base("status"), Some(0xb3));
    assert_eq!(pm.ports.base("dynamic"), None);
    assert_eq!(pci_read(&mut pm.device, 0), 0x71138086);
    assert_eq!(pci_read(&mut pm.device, 4), 0x02800000);
    assert_eq!(pci_read(&mut pm.device, 0x3c) & 0xff00, 0x100);
    pci_write(&mut pm.device, 0x80, 1);
    assert_eq!(pm.ports.base("dynamic"), None);
    pci_write(&mut pm.device, 0x40, 0x403);
    assert_eq!(pci_read(&mut pm.device, 0x40), 0x401);
    assert_eq!(pm.ports.base("dynamic"), Some(0x400));
    pm.device
        .pci_cfg_write(
            0x80,
            ByteEnabledDwordWrite::new(0, PciConfigByteEnable::BYTE2),
        )
        .unwrap();
    assert_eq!(pm.ports.base("dynamic"), Some(0x400));
    pci_write(&mut pm.device, 0x80, 0);
    assert_eq!(pm.ports.base("dynamic"), None);
    pci_write(&mut pm.device, 0x40, 0x800);
    assert_eq!(pm.ports.base("dynamic"), None);
    pci_write(&mut pm.device, 0x80, 1);
    pci_write(&mut pm.device, 4, 1);
    pm.device
        .pci_cfg_write(4, ByteEnabledDwordWrite::new(0, PciConfigByteEnable::BYTE1))
        .unwrap();
    assert_eq!(pci_read(&mut pm.device, 4), 0x02800001);
    write8(&mut pm.device, 0xb3, 0x5a);
    let saved = pm.device.save().unwrap();
    pm.pool.run_until(pm.device.reset());
    assert_eq!(pm.ports.base("dynamic"), None);
    assert_eq!(pci_read(&mut pm.device, 4), 0x02800000);
    assert_eq!(read8(&mut pm.device, 0xb3), 0);
    let mut pm = TestPm::new();
    pm.device.restore(saved).unwrap();
    assert_eq!(pm.ports.base("dynamic"), Some(0x800));
    assert_eq!(pci_read(&mut pm.device, 0x80), 1);
    assert_eq!(pci_read(&mut pm.device, 4), 0x02800001);
    assert_eq!(read8(&mut pm.device, 0xb3), 0x5a);
}

// Test: Partially overwrite PM resource registers and round-trip their saved state.
// Expected: Disabled byte lanes are retained and unsupported registers reject accesses.
#[test]
fn pm_resource_registers_honor_byte_enables_and_saved_state() {
    let mut pm = TestPm::new();
    for offset in (0x44..=0x7c).step_by(4) {
        pci_write(&mut pm.device, offset, 0x12345600 | u32::from(offset));
        pm.device
            .pci_cfg_write(
                offset,
                ByteEnabledDwordWrite::new(0x00ab0000, PciConfigByteEnable::BYTE2),
            )
            .unwrap();
        assert_eq!(
            pci_read(&mut pm.device, offset),
            0x12ab5600 | u32::from(offset)
        );
    }
    for offset in [0x90, 0xd0] {
        pci_write(&mut pm.device, offset, u32::MAX);
        assert_eq!(pci_read(&mut pm.device, offset), 0);
    }
    let saved = pm.device.save().unwrap();
    pm.pool.run_until(pm.device.reset());
    let mut pm = TestPm::new();
    pm.device.restore(saved).unwrap();
    for offset in (0x44..=0x7c).step_by(4) {
        assert_eq!(
            pci_read(&mut pm.device, offset),
            0x12ab5600 | u32::from(offset)
        );
    }
    let mut value = 0;
    assert!(matches!(
        pm.device.pci_cfg_read(
            0xfc,
            ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::FULL)
        ),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        pm.device
            .pci_cfg_write(0xfc, ByteEnabledDwordWrite::with_all_bytes_enabled(0)),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Enable ACPI through the BIOS control port and signal a general-purpose event.
// Expected: Guest-visible event status raises SCI until acknowledged; ET requests power-off.
#[test]
fn pm_bios_commands_route_acpi_events_and_power_actions() {
    let mut pm = TestPm::new();
    pci_write(&mut pm.device, 0x40, 0x400);
    pci_write(&mut pm.device, 0x80, 1);
    write8(&mut pm.device, 0xb2, 0xe1);
    assert_eq!(read8(&mut pm.device, 0x404) & 1, 0);
    pci_write(&mut pm.device, 0x58, 1 << 25);
    write8(&mut pm.device, 0xb2, 0xe1);
    assert_eq!(read8(&mut pm.device, 0x404) & 1, 1);
    assert_eq!(read8(&mut pm.device, 0x402) & 1, 1);
    write8(&mut pm.device, 0x40e, 1);
    pm.device
        .supports_line_interrupt_target()
        .unwrap()
        .set_irq(0, true);
    assert_eq!(read8(&mut pm.device, 0x40c) & 1, 1);
    assert!(pm.sci.0.load(Ordering::SeqCst));
    pm.device.set_irq(0, false);
    write8(&mut pm.device, 0x40c, 1);
    assert!(!pm.sci.0.load(Ordering::SeqCst));
    write8(&mut pm.device, 0xb2, 0x1e);
    assert_eq!(read8(&mut pm.device, 0x404) & 1, 0);
    for port in [0xb2, 0xb3] {
        let before = read8(&mut pm.device, port);
        pm.device.io_write(port, b"ET").unwrap();
        let mut value = [0x5a; 2];
        pm.device.io_read(port, &mut value).unwrap();
        assert_eq!(value, [0x5a; 2]);
        assert_eq!(read8(&mut pm.device, port), before);
    }
    assert!(pm.actions.lock().is_empty());
    write8(&mut pm.device, 0xb2, b'E');
    write8(&mut pm.device, 0xb2, b'T');
    assert!(matches!(
        pm.actions.lock().as_slice(),
        [PowerAction::PowerOff]
    ));
}

// Test: Interrupt the BIOS ET power-off sequence, then checkpoint its prefix
//       into a fresh device and separately reset an in-progress sequence.
// Expected: Only consecutive control-port E/T writes request power-off;
//       restore retains the prefix and routes the action to the new peer,
//       while reset discards the prefix.
#[test]
fn pm_power_off_sequence_requires_consecutive_bytes_across_restore() {
    let mut original = TestPm::new();
    for byte in *b"TEXT" {
        write8(&mut original.device, 0xb2, byte);
    }
    assert!(original.actions.lock().is_empty());
    write8(&mut original.device, 0xb2, b'E');
    let saved = original.device.save().unwrap();

    let mut restored = TestPm::new();
    restored.device.restore(saved).unwrap();
    assert_eq!(read8(&mut restored.device, 0xb2), b'E');
    assert!(restored.actions.lock().is_empty());
    write8(&mut restored.device, 0xb2, b'T');
    assert!(matches!(
        restored.actions.lock().as_slice(),
        [PowerAction::PowerOff]
    ));
    assert!(original.actions.lock().is_empty());

    write8(&mut original.device, 0xb2, b'E');
    original.pool.run_until(original.device.reset());
    write8(&mut original.device, 0xb2, b'T');
    assert!(original.actions.lock().is_empty());
}
