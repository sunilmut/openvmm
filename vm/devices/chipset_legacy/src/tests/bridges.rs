// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::i440bx_host_pci_bridge::AdjustGpaRange;
use crate::i440bx_host_pci_bridge::GpaState;
use crate::i440bx_host_pci_bridge::HostPciBridge;
use crate::piix4_pci_isa_bridge::PciIsaBridge;
use memory_range::MemoryRange;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

#[derive(Clone, Default)]
struct Mappings(Arc<Mutex<Vec<(MemoryRange, GpaState)>>>);

impl AdjustGpaRange for Mappings {
    fn adjust_gpa_range(&mut self, range: MemoryRange, state: GpaState) {
        self.0.lock().push((range, state));
    }
}

// Test: Program all PAM regions into alternating ROM and RAM protection modes.
// Expected: Only changed ranges are remapped, with their documented address and mode.
#[test]
fn host_pam_registers_apply_each_regions_memory_protection() {
    let mappings = Mappings::default();
    let mut device = HostPciBridge::new(Box::new(mappings.clone()), false);
    {
        let initial = mappings.0.lock();
        assert_eq!(
            initial[0],
            (MemoryRange::new(0xa0000..0xc0000), GpaState::Mmio)
        );
        assert!(
            initial[1..]
                .iter()
                .all(|(_, state)| *state == GpaState::Mmio)
        );
        assert_eq!(initial.len(), 14);
    }
    mappings.0.lock().clear();
    let mut pam = 3u64;
    for index in 0..13 {
        pam |= (((index + 1) % 4) as u64) << ((index + 3) * 4);
    }
    pci_write(&mut device, 0x58, pam as u32);
    pci_write(&mut device, 0x5c, (pam >> 32) as u32);
    assert_eq!(pci_read(&mut device, 0x58), pam as u32);
    assert_eq!(pci_read(&mut device, 0x5c), (pam >> 32) as u32);
    let changed = mappings.0.lock().clone();
    let expected: Vec<_> = (0..13)
        .filter_map(|index| {
            let state = match (index + 1) % 4 {
                0 => return None,
                1 => GpaState::WriteProtected,
                2 => GpaState::WriteOnly,
                _ => GpaState::Writable,
            };
            let range = if index == 0 {
                0xf0000..0x100000
            } else {
                let start = 0xc0000 + (index - 1) * 0x4000;
                start..start + 0x4000
            };
            Some((MemoryRange::new(range), state))
        })
        .collect();
    assert_eq!(changed, expected);
    mappings.0.lock().clear();
    pci_write(&mut device, 0x58, pam as u32);
    pci_write(&mut device, 0x5c, (pam >> 32) as u32);
    assert!(mappings.0.lock().is_empty());
}

// Test: Modify host scratch, DRAM, and locked SMRAM registers, then save and restore.
// Expected: Byte enables and SMRAM restrictions hold; restore reapplies VGA/PAM mappings.
#[test]
fn host_register_masks_locking_and_restored_mappings_preserve_guest_state() {
    let mappings = Mappings::default();
    let mut device = HostPciBridge::new(Box::new(mappings.clone()), true);
    assert!(mappings.0.lock().is_empty());
    assert_eq!(pci_read(&mut device, 0), 0x71928086);
    assert_eq!(pci_read(&mut device, 4), 0x02000006);
    assert_eq!(pci_read(&mut device, 0x78), 0x380a0000);
    assert_eq!(pci_read(&mut device, 0xf8), 0xf20);
    for offset in [0x60, 0x64, 0xd0, 0xd4] {
        pci_write(&mut device, offset, 0xaabbccdd);
        device
            .pci_cfg_write(
                offset,
                ByteEnabledDwordWrite::new(0x00110000, PciConfigByteEnable::BYTE2),
            )
            .unwrap();
        assert_eq!(pci_read(&mut device, offset), 0xaa11ccdd);
    }
    pci_write(&mut device, 0x70, u32::MAX);
    assert_eq!(pci_read(&mut device, 0x70), 0x383a0000);
    pci_write(&mut device, 0x70, 0);
    assert_eq!(pci_read(&mut device, 0x70), 0x383a0000);
    for offset in [
        0x50, 0x54, 0x68, 0x74, 0x7c, 0x90, 0xa0, 0xa4, 0xa8, 0xb0, 0xb4, 0xb8, 0xbc, 0xf0, 0xf4,
    ] {
        pci_write(&mut device, offset, u32::MAX);
        assert_eq!(pci_read(&mut device, offset), 0);
    }
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    assert_eq!(pci_read(&mut device, 0xd0), 0);
    assert_eq!(pci_read(&mut device, 0x70), 0x38020000);
    mappings.0.lock().clear();
    device.restore(saved).unwrap();
    assert_eq!(pci_read(&mut device, 0xd0), 0xaa11ccdd);
    assert_eq!(pci_read(&mut device, 0x70), 0x383a0000);
    assert_eq!(
        mappings.0.lock()[0],
        (MemoryRange::new(0xa0000..0xc0000), GpaState::Mmio)
    );
    let mut value = 0;
    assert!(matches!(
        device.pci_cfg_read(
            0xfc,
            ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::FULL)
        ),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.pci_cfg_write(0xfc, ByteEnabledDwordWrite::with_all_bytes_enabled(0)),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Toggle fast A20, request reset, and exercise legacy coprocessor ports.
// Expected: Callbacks reflect valid writes only; oversized accesses are harmless.
#[test]
fn isa_legacy_ports_drive_a20_and_reset_without_accepting_oversized_writes() {
    let resets = Arc::new(AtomicUsize::new(0));
    let a20 = Arc::new(Mutex::new(Vec::new()));
    let recorded = a20.clone();
    let reset = resets.clone();
    let mut device = PciIsaBridge::new(
        Box::new(move || {
            reset.fetch_add(1, Ordering::SeqCst);
        }),
        Box::new(move |enabled| recorded.lock().push(enabled)),
    );
    assert_eq!(read8(&mut device, 0x92), 0);
    write8(&mut device, 0x92, 2);
    assert_eq!(read8(&mut device, 0x92), 2);
    write8(&mut device, 0x92, 0);
    write8(&mut device, 0x92, 1);
    assert_eq!(*a20.lock(), [false, true]);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    let mut invalid = [0x5a; 2];
    device.io_read(0x92, &mut invalid).unwrap();
    device.io_write(0x92, &[1, 2]).unwrap();
    assert_eq!(invalid, [0x5a; 2]);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    for port in [0xf0, 0xf1] {
        for size in 1..=3 {
            let mut value = vec![0; size];
            device.io_read(port, &mut value).unwrap();
            assert!(value.iter().all(|value| *value == 0xff));
            device.io_write(port, &value).unwrap();
        }
    }
    assert!(matches!(
        device.io_write(0x93, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.io_read(0x93, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
}

// Test: Program ISA bridge configuration and restore a disabled A20 gate.
// Expected: Defined write masks apply, immutable registers stay fixed, and A20 is resynchronized.
#[test]
fn isa_configuration_masks_and_restore_preserve_external_a20_state() {
    let a20 = Arc::new(Mutex::new(Vec::new()));
    let recorded = a20.clone();
    let mut device = PciIsaBridge::new(
        Box::new(|| panic!("unexpected reset")),
        Box::new(move |enabled| recorded.lock().push(enabled)),
    );
    assert_eq!(pci_read(&mut device, 0), 0x71108086);
    assert_eq!(pci_read(&mut device, 4), 0x02000007);
    for (offset, expected) in [
        (0x60, u32::MAX),
        (0xa0, 0x00ff001f),
        (0xa4, u32::MAX),
        (0xa8, u32::MAX),
        (0xac, u32::MAX),
        (0x80, u32::MAX),
    ] {
        pci_write(&mut device, offset, u32::MAX);
        assert_eq!(pci_read(&mut device, offset), expected);
    }
    for (offset, expected) in [
        (0x4c, 0x3004d),
        (0x64, 0xd0),
        (0x68, 0x200),
        (0x70, 0),
        (0x74, 0),
        (0x78, 0),
        (0x90, 0),
        (0x94, 0),
        (0xb0, 0),
        (0xc8, 0x25000000),
    ] {
        pci_write(&mut device, offset, 0);
        assert_eq!(pci_read(&mut device, offset), expected);
    }
    assert_eq!(pci_read(&mut device, 0xf8), 0xf30);
    write8(&mut device, 0x92, 2);
    let saved = device.save().unwrap();
    pal_async::local::block_on(device.reset());
    assert_eq!(read8(&mut device, 0x92), 0);
    device.restore(saved).unwrap();
    assert_eq!(read8(&mut device, 0x92), 2);
    assert_eq!(a20.lock().last(), Some(&false));
    assert_eq!(pci_read(&mut device, 0xa0), 0x00ff001f);
    let mut value = 0;
    assert!(matches!(
        device.pci_cfg_read(
            0xfc,
            ByteEnabledDwordRead::new(&mut value, PciConfigByteEnable::FULL)
        ),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.pci_cfg_write(0xfc, ByteEnabledDwordWrite::with_all_bytes_enabled(0)),
        IoResult::Err(IoError::InvalidRegister)
    ));
}
