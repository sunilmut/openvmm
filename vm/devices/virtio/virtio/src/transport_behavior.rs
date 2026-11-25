// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

async fn finish_io<F: Future>(device: &mut impl PollDevice, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    mesh::CancelContext::new()
        .with_timeout(Duration::from_secs(5))
        .until_cancelled(poll_fn(|cx| {
            device.poll_device(cx);
            future.as_mut().poll(cx)
        }))
        .await
        .expect("transport did not complete deferred guest IO")
}

// Test: Queue reads and a guest reset behind an MMIO device enable operation.
// Expected: The pre-reset read sees DRIVER_OK, reset cancels outstanding reads,
//       and a fresh access observes reset status after both async transitions.
#[async_test]
async fn mmio_stalled_accesses_replay_in_guest_order(driver: DefaultDriver) {
    let mut transport =
        MmioTestTransport::new(Box::new(PartialFailTestDevice::new(1, 99)), &driver, 1);
    let dev = &mut transport.dev;
    let IoResult::Defer(enable) = dev.mmio_write(112, &VIRTIO_DRIVER_OK.to_le_bytes()) else {
        panic!("enable must defer")
    };
    let mut before = [0; 4];
    let IoResult::Defer(read_before) = dev.mmio_read(112, &mut before) else {
        panic!("busy read must defer")
    };
    let IoResult::Defer(reset) = dev.mmio_write(112, &0u32.to_le_bytes()) else {
        panic!("busy reset must defer")
    };
    let mut after = [0xff; 4];
    let IoResult::Defer(read_after) = dev.mmio_read(112, &mut after) else {
        panic!("second busy read must defer")
    };
    let results = finish_io(dev, async {
        futures::join!(
            enable.write_future(),
            read_before.read_future(&mut before),
            reset.write_future(),
            read_after.read_future(&mut after)
        )
    })
    .await;
    results.0.unwrap();
    results.1.unwrap();
    results.2.unwrap();
    assert!(matches!(results.3, Err(IoError::NoResponse)));
    assert_ne!(u32::from_le_bytes(before) & VIRTIO_DRIVER_OK, 0);
    dev.mmio_read(112, &mut after).unwrap();
    assert_eq!(u32::from_le_bytes(after), 0);
    transport.teardown().await;
}

// Test: Queue reads and a reset through PCI BAR0 while device enable is pending.
// Expected: The pre-reset read succeeds, reset cancels outstanding reads,
//       and the guest can read the reset device through the same BAR.
#[async_test]
async fn pci_stalled_accesses_replay_in_guest_order(driver: DefaultDriver) {
    let mut transport =
        PciTestTransport::new(Box::new(PartialFailTestDevice::new(1, 99)), &driver, 1);
    let dev = &mut transport.dev;
    let status = 0x10000000000 + 20;
    let IoResult::Defer(enable) = dev.mmio_write(status, &[VIRTIO_DRIVER_OK as u8]) else {
        panic!("enable must defer")
    };
    let mut before = [0];
    let IoResult::Defer(read_before) = dev.mmio_read(status, &mut before) else {
        panic!("busy read must defer")
    };
    let IoResult::Defer(reset) = dev.mmio_write(status, &[0]) else {
        panic!("busy reset must defer")
    };
    let mut after = [0xff];
    let IoResult::Defer(read_after) = dev.mmio_read(status, &mut after) else {
        panic!("second busy read must defer")
    };
    let results = finish_io(dev, async {
        futures::join!(
            enable.write_future(),
            read_before.read_future(&mut before),
            reset.write_future(),
            read_after.read_future(&mut after)
        )
    })
    .await;
    results.0.unwrap();
    results.1.unwrap();
    results.2.unwrap();
    assert!(matches!(results.3, Err(IoError::NoResponse)));
    assert_ne!(before[0] & VIRTIO_DRIVER_OK as u8, 0);
    dev.mmio_read(status, &mut after).unwrap();
    assert_eq!(after, [0]);
    transport.teardown().await;
}

// Test: Remap PCI BAR0 after reads and writes have stalled behind device enable.
// Expected: Stalled accesses to the old mapping fail explicitly; the original
//       enable still completes and the device responds at the new mapping.
#[async_test]
async fn remapped_pci_bar_rejects_stalled_old_addresses(driver: DefaultDriver) {
    let mut transport =
        PciTestTransport::new(Box::new(PartialFailTestDevice::new(1, 99)), &driver, 1);
    let dev = &mut transport.dev;
    let old = 0x10000000000;
    let IoResult::Defer(enable) = dev.mmio_write(old + 20, &[VIRTIO_DRIVER_OK as u8]) else {
        panic!("enable must defer")
    };
    let mut bytes = [0];
    let IoResult::Defer(read) = dev.mmio_read(old + 20, &mut bytes) else {
        panic!("busy read must defer")
    };
    let IoResult::Defer(write) = dev.mmio_write(old + 22, &0u16.to_le_bytes()) else {
        panic!("busy write must defer")
    };
    for (offset, value) in [(0x04, 0), (0x10, 0x100000), (0x04, 2)] {
        dev.pci_cfg_write(offset, ByteEnabledDwordWrite::with_all_bytes_enabled(value))
            .unwrap();
    }
    let results = finish_io(dev, async {
        futures::join!(
            enable.write_future(),
            read.read_future(&mut bytes),
            write.write_future()
        )
    })
    .await;
    results.0.unwrap();
    assert!(matches!(results.1, Err(IoError::InvalidRegister)));
    assert!(matches!(results.2, Err(IoError::InvalidRegister)));
    dev.mmio_read(old + 0x100000 + 20, &mut bytes).unwrap();
    assert_ne!(bytes[0] & VIRTIO_DRIVER_OK as u8, 0);
    transport.teardown().await;
}

fn select_cfg_window(device: &mut VirtioPciDevice, cap: u16, bar: u32, offset: u32, length: u32) {
    for (field, value) in [(4, bar), (8, offset), (12, length)] {
        device
            .pci_cfg_write(
                cap + field,
                ByteEnabledDwordWrite::with_all_bytes_enabled(value),
            )
            .unwrap();
    }
}

// Test: Access MSI-X table bytes through the PCI configuration capability window.
// Expected: Byte and halfword writes update only the requested table bytes,
//       and window reads left-align the selected bytes in pci_cfg_data.
#[async_test]
async fn pci_config_window_preserves_neighboring_msix_bytes(driver: DefaultDriver) {
    let memory = VirtioTestMemoryAccess::new();
    let mut fixture = VirtioPciTestDevice::new(&driver, 1, &memory, None);
    let device = &mut fixture.pci_device;
    let cap = find_pci_cfg_cap_offset(device);
    for (offset, length, value, expected) in [
        (8, 4, 0x11223344, 0x11223344),
        (9, 1, 0xab, 0x1122ab44),
        (10, 2, 0xcdef, 0xcdefab44),
    ] {
        select_cfg_window(device, cap, 2, offset, length);
        device
            .pci_cfg_write(
                cap + 16,
                ByteEnabledDwordWrite::with_all_bytes_enabled(value),
            )
            .unwrap();
        let mut actual = 0;
        device
            .pci_cfg_read(
                cap + 16,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut actual),
            )
            .unwrap();
        assert_eq!(actual, value);
        select_cfg_window(device, cap, 2, 8, 4);
        device
            .pci_cfg_read(
                cap + 16,
                ByteEnabledDwordRead::with_all_bytes_enabled(&mut actual),
            )
            .unwrap();
        assert_eq!(actual, expected);
    }
    fixture.pci_device.teardown().await;
}
