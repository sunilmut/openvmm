// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Look up multiple device IDs in a device table whose base points outside guest memory through both device and shared-state APIs.
// Expected: Each lookup returns DevTabHardwareError with the original requester and exact 32-byte entry GPA, never interpreting missing memory as an invalid or pass-through entry.
#[test]
fn unreadable_device_table_preserves_requester_and_exact_entry_address() {
    let mut dev = create_test_device_for_translation();
    let table = 0x20_0000;
    setup_iommu_with_devtab(&mut dev, table, 256);
    for device_id in [0, 0x71, 0xff] {
        let expected = table + u64::from(device_id) * 32;
        for result in [
            dev.lookup_dte(device_id),
            dev.shared_state().lookup_dte(device_id),
        ] {
            assert!(
                matches!(result, Err(IommuFault::DevTabHardwareError { device_id: actual, address }) if actual == device_id && address == expected)
            );
        }
    }
}

// Test: Attempt every unsupported MMIO width against a programmed command-ring register through the advertised chipset MMIO interface.
// Expected: Invalid reads fill the complete caller buffer with open-bus bytes, invalid writes leave the programmed register unchanged, and the static region covers exactly the advertised register aperture.
#[test]
fn unsupported_mmio_widths_return_open_bus_without_mutating_registers() {
    let mut dev = create_test_device_for_translation();
    let programmed = CmdBufBase::new()
        .with_base_addr(0x8_0000 >> 12)
        .with_length(8)
        .into_bits();
    mmio_write64(&mut dev, MmioRegister::CMD_BUF_BASE.0 as u64, programmed);
    let mmio = dev.supports_mmio().unwrap();
    let regions = mmio.get_static_regions();
    assert_eq!(regions.len(), 1);
    assert_eq!(
        regions[0].1,
        TEST_MMIO_BASE..=TEST_MMIO_BASE + MMIO_REGION_SIZE - 1
    );
    let address = TEST_MMIO_BASE + MmioRegister::CMD_BUF_BASE.0 as u64;
    for len in [0, 1, 2, 3, 5, 6, 7, 9, 16] {
        let mut bytes = vec![0x5a; len];
        assert!(matches!(
            mmio.mmio_read(address, &mut bytes),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(bytes, vec![0xff; len]);
        assert!(matches!(
            mmio.mmio_write(address, &vec![0xa5; len]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    assert_eq!(
        mmio_read64(&mut dev, MmioRegister::CMD_BUF_BASE.0 as u64),
        programmed
    );
    assert_eq!(mmio_read64(&mut dev, 0x3ff8), 0);
}

// Test: Program extended interrupt registers and an enabled IOMMU, attempt unsupported save, then reset through ChangeDeviceState while retaining shared translation state.
// Expected: Save reports NotSupported without changing state; reset clears programmed/control registers, preserves the advertised capabilities, and makes preexisting translation handles bypass again.
#[test]
fn reset_clears_programmed_state_without_invalidating_shared_translation_handles() {
    use vmcore::device_state::ChangeDeviceState;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    let mut dev = create_test_device_for_translation();
    let shared = dev.shared_state().clone();
    let pci = dev.supports_pci().unwrap();
    let mut vendor = 0;
    assert!(matches!(
        pci.pci_cfg_read(0, ByteEnabledDwordRead::with_all_bytes_enabled(&mut vendor)),
        IoResult::Ok
    ));
    assert_eq!(vendor as u16, spec::registers::PCI_VENDOR_ID);
    for (register, value) in [
        (MmioRegister::GEN_XT_INT_CTRL, 0x1234_5678),
        (MmioRegister::PPR_XT_INT_CTRL, 0x8765_4321),
    ] {
        mmio_write64(&mut dev, register.0 as u64, value);
        assert_eq!(mmio_read64(&mut dev, register.0 as u64), value);
    }
    let control = IommuCtrl::new().with_iommu_en(true).with_ga_en(true);
    mmio_write64(
        &mut dev,
        MmioRegister::IOMMU_CTRL.0 as u64,
        control.into_bits(),
    );
    assert!(dev.iommu_ctrl().iommu_en());
    assert!(dev.iommu_ctrl().ga_en());
    assert!(matches!(dev.save(), Err(SaveError::NotSupported)));
    assert_eq!(dev.iommu_ctrl().into_bits(), control.into_bits());
    futures::executor::block_on(dev.reset());
    for register in [
        MmioRegister::IOMMU_CTRL,
        MmioRegister::GEN_XT_INT_CTRL,
        MmioRegister::PPR_XT_INT_CTRL,
        MmioRegister::IOMMU_STATUS,
    ] {
        assert_eq!(mmio_read64(&mut dev, register.0 as u64), 0);
    }
    assert_eq!(
        mmio_read64(&mut dev, MmioRegister::EXT_FEAT.0 as u64),
        ADVERTISED_EXT_FEAT
    );
    assert_eq!(mmio_read64(&mut dev, MmioRegister::EXT_FEAT2.0 as u64), 0);
    assert_eq!(
        shared.translate(0xffff, 0x1234_5678, true).unwrap(),
        0x1234_5678
    );
}

// Test: Execute an unmapped completion-store command followed by a valid completion-store command in the same ring batch.
// Expected: The invalid target cannot panic or prevent later accepted commands from progressing, the second store reaches its exact target, and the visible head consumes both commands.
#[test]
fn completion_store_failure_does_not_prevent_later_command_progress() {
    let mut dev = create_test_device_with_memory();
    setup_iommu_enabled(&mut dev);
    write_cmd(&dev, 0, &completion_wait_store(0xdead_0000, 0x1122_3344));
    write_cmd(
        &dev,
        1,
        &completion_wait_store(0x2000, 0xfedc_ba98_7654_3210),
    );
    poke_tail(&mut dev, 2);
    assert_eq!(
        CmdBufHead::from_bits(mmio_read64(&mut dev, MmioRegister::CMD_BUF_HEAD.0 as u64))
            .head_ptr(),
        2
    );
    assert!(
        IommuStatus::from_bits(mmio_read64(&mut dev, MmioRegister::IOMMU_STATUS.0 as u64))
            .cmd_buf_run()
    );
    assert_eq!(
        dev.shared.guest_memory.read_plain::<u64>(0x2000).unwrap(),
        0xfedc_ba98_7654_3210
    );
}

// Test: Look up a zeroed GA-format interrupt entry whose RemapEn bit is clear.
// Expected: Lookup returns the exact device/domain interrupt page fault rather than accepting the stored destination/vector.
#[test]
fn ga_entry_without_remap_enable_faults_with_device_and_domain() {
    let mut dev = create_test_device_for_translation();
    let control = IommuCtrl::new().with_iommu_en(true).with_ga_en(true);
    mmio_write64(
        &mut dev,
        MmioRegister::IOMMU_CTRL.0 as u64,
        control.into_bits(),
    );
    let dte = make_dte_with_interrupt_remap(0xa_0000, 4, IntCtl::REMAP.0);
    assert!(matches!(
        dev.lookup_irte(0x71, &dte, 3),
        Err(IommuFault::IoPageFault {
            device_id: 0x71,
            domain_id: 1,
            address: 0,
            is_write: false
        })
    ));
}

// Test: Deliver an MSI through the public InterruptRemapper interface using pass-through and target-abort device entries.
// Expected: Pass-through preserves the exact address/data without an event; abort drops delivery and logs the exact interrupt fault payload for the requester.
#[test]
fn registered_route_remapper_preserves_valid_msi_and_logs_abort_fault() {
    for pass_through in [true, false] {
        let mut dev = create_test_device_for_translation();
        setup_iommu_with_devtab(&mut dev, 0x1_0000, 256);
        let mode = if pass_through {
            IntCtl::PASS_THROUGH
        } else {
            IntCtl::ABORT
        };
        write_dte(
            &dev,
            0x1_0000,
            0x71,
            &make_dte_with_interrupt_remap(0xa_0000, 4, mode.0),
        );
        let remapper: &dyn iommu_common::InterruptRemapper = dev.shared_state().as_ref();
        let result = remapper.remap_msi(0x71, 0xfee2_3000, 0x81);
        if pass_through {
            assert_eq!(result, Some((0xfee2_3000, 0x81)));
            assert_eq!(
                mmio_read64(&mut dev, MmioRegister::EVT_LOG_TAIL.0 as u64),
                0
            );
        } else {
            assert_eq!(result, None);
            assert_eq!(
                EvtLogTail::from_bits(mmio_read64(&mut dev, MmioRegister::EVT_LOG_TAIL.0 as u64))
                    .tail_ptr(),
                1
            );
            let event: EventEntry = dev.shared.guest_memory.read_plain(0x9_0000).unwrap();
            assert_eq!(
                event.as_bytes(),
                EventEntry::illegal_dev_table_entry(0x71, true, false, 0xfee2_3000).as_bytes()
            );
        }
    }
}

// Test: Read basic and GA-format interrupt-remapping entries from an unmapped guest address at a nonzero index.
// Expected: Both formats return PageTabHardwareError with the original device ID and exact format-dependent entry GPA rather than remapping an interrupt or returning a generic page fault.
#[test]
fn unreadable_interrupt_tables_report_exact_device_and_entry_address() {
    for ga in [false, true] {
        let mut dev = create_test_device_for_translation();
        setup_iommu_with_devtab(&mut dev, 0x1_0000, 256);
        let control = IommuCtrl::new().with_iommu_en(true).with_ga_en(ga);
        mmio_write64(
            &mut dev,
            MmioRegister::IOMMU_CTRL.0 as u64,
            control.into_bits(),
        );
        let table = 0x20_0000;
        let dte = make_dte_with_interrupt_remap(table, 4, IntCtl::REMAP.0);
        let error = dev.lookup_irte(0x71, &dte, 3).unwrap_err();
        assert!(
            matches!(error, IommuFault::PageTabHardwareError { device_id: 0x71, address } if address == table + 3 * if ga { 16 } else { 4 })
        );
    }
}

// Test: Attempt to publish an event into unmapped guest memory, then reconfigure the log to valid backing and retry.
// Expected: A failed write neither advances the visible event tail nor announces a logged event, and a subsequent valid publication records exactly the requested event and advances the tail once.
#[test]
fn failed_event_log_write_does_not_publish_tail_or_interrupt_status() {
    let mut dev = create_test_device_for_translation();
    let control = IommuCtrl::new()
        .with_iommu_en(true)
        .with_evt_log_en(true)
        .with_evt_int_en(true);
    mmio_write64(
        &mut dev,
        MmioRegister::EVT_LOG_BASE.0 as u64,
        EvtLogBase::new()
            .with_base_addr(0x20_0000 >> 12)
            .with_length(8)
            .into_bits(),
    );
    mmio_write64(
        &mut dev,
        MmioRegister::IOMMU_CTRL.0 as u64,
        control.into_bits(),
    );
    let event = EventEntry::io_page_fault(0x71, 0x1234, false, true, 0xdead_1234);
    dev.write_event(event);
    assert_eq!(
        mmio_read64(&mut dev, MmioRegister::EVT_LOG_TAIL.0 as u64),
        0
    );
    assert!(
        !IommuStatus::from_bits(mmio_read64(&mut dev, MmioRegister::IOMMU_STATUS.0 as u64))
            .evt_log_int()
    );
    mmio_write64(&mut dev, MmioRegister::IOMMU_CTRL.0 as u64, 0);
    mmio_write64(
        &mut dev,
        MmioRegister::EVT_LOG_BASE.0 as u64,
        EvtLogBase::new()
            .with_base_addr(0x9_0000 >> 12)
            .with_length(8)
            .into_bits(),
    );
    mmio_write64(
        &mut dev,
        MmioRegister::IOMMU_CTRL.0 as u64,
        control.into_bits(),
    );
    dev.write_event(event);
    let recorded: EventEntry = dev.shared.guest_memory.read_plain(0x9_0000).unwrap();
    assert_eq!(recorded.as_bytes(), event.as_bytes());
    assert_eq!(
        EvtLogTail::from_bits(mmio_read64(&mut dev, MmioRegister::EVT_LOG_TAIL.0 as u64))
            .tail_ptr(),
        1
    );
    assert!(
        IommuStatus::from_bits(mmio_read64(&mut dev, MmioRegister::IOMMU_STATUS.0 as u64))
            .evt_log_int()
    );
}

// Test: Execute successive store-and-interrupt completion waits with an MSI receiver that reads the completion word synchronously.
// Expected: Each delivered MSI observes its own complete 64-bit store, never the previous token, and each command advances the visible head exactly once.
#[test]
fn completion_store_is_visible_when_its_msi_is_delivered() {
    struct CompletionObserver {
        memory: GuestMemory,
        observations: parking_lot::Mutex<Vec<(u64, u32, u64)>>,
    }
    impl SignalMsi for CompletionObserver {
        fn signal_msi(&self, _: Option<u32>, address: u64, data: u32) {
            let token = self.memory.read_plain::<u64>(0x2000).unwrap();
            self.observations.lock().push((address, data, token));
        }
    }
    let memory = GuestMemory::allocate(0x10000);
    memory
        .write_plain(0x2000, &0x5555_5555_5555_5555u64)
        .unwrap();
    let observer = Arc::new(CompletionObserver {
        memory: memory.clone(),
        observations: parking_lot::Mutex::new(Vec::new()),
    });
    let connection = pci_core::msi::MsiConnection::new();
    connection.connect(observer.clone());
    let mut dev = AmdIommuDevice::new(memory, test_config(), &connection.target());
    let capability = ((pci_read(&mut dev, 0x40) >> 8) & 0xff) as u16;
    assert_ne!(capability, 0);
    for (offset, value) in [(4, 0xfee0_0000), (8, 0), (12, 0x41)] {
        assert!(matches!(
            dev.pci_cfg_write(
                capability + offset,
                ByteEnabledDwordWrite::with_all_bytes_enabled(value)
            ),
            IoResult::Ok
        ));
    }
    let control = pci_read(&mut dev, capability);
    assert!(matches!(
        dev.pci_cfg_write(
            capability,
            ByteEnabledDwordWrite::with_all_bytes_enabled(control | (1 << 16))
        ),
        IoResult::Ok
    ));
    setup_iommu_enabled(&mut dev);
    assert!(observer.observations.lock().is_empty());
    let mut expected = Vec::new();
    for (index, token) in [0x1122_3344_5566_7788u64, 0xfedc_ba98_7654_3210]
        .into_iter()
        .enumerate()
    {
        let mut command = completion_wait_store(0x2000, token);
        command.dw0 |= 2;
        write_cmd(&dev, index as u64, &command);
        poke_tail(&mut dev, index as u64 + 1);
        expected.push((0xfee0_0000, 0x41, token));
        assert_eq!(*observer.observations.lock(), expected);
        assert_eq!(
            CmdBufHead::from_bits(mmio_read64(&mut dev, MmioRegister::CMD_BUF_HEAD.0 as u64))
                .head_ptr(),
            index as u32 + 1
        );
    }
}
