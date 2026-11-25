// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use std::collections::BTreeMap;
use std::task::{Context, Poll, Waker};
use test_with_tracing::test;

#[derive(Default)]
struct Calls {
    pci_writes: Vec<(u16, u32)>,
    reads: Vec<(u64, usize)>,
    writes: Vec<(u64, Vec<u8>)>,
}
struct Device {
    config: [u32; 64],
    memory: BTreeMap<u64, u8>,
    calls: Arc<Mutex<Calls>>,
}
impl InspectMut for Device {
    fn inspect_mut(&mut self, _request: inspect::Request<'_>) {}
}
impl ChipsetDevice for Device {}
impl PciConfigSpace for Device {
    fn pci_cfg_read(&mut self, address: u16, mut output: ByteEnabledDwordRead<'_>) -> IoResult {
        let value = self.config[address as usize / 4];
        output.set(if (0x10..=0x24).contains(&address) && value == u32::MAX {
            if address == 0x10 { 0xfffff000 } else { 0 }
        } else {
            value
        });
        IoResult::Ok
    }
    fn pci_cfg_write(&mut self, address: u16, value: ByteEnabledDwordWrite) -> IoResult {
        self.calls
            .lock()
            .pci_writes
            .push((address, value.extract()));
        value.merge_into(&mut self.config[address as usize / 4]);
        IoResult::Ok
    }
}
impl MmioIntercept for Device {
    fn mmio_read(&mut self, address: u64, output: &mut [u8]) -> IoResult {
        self.calls.lock().reads.push((address, output.len()));
        for (offset, byte) in output.iter_mut().enumerate() {
            *byte = self
                .memory
                .get(&(address + offset as u64))
                .copied()
                .unwrap_or(0);
        }
        IoResult::Ok
    }
    fn mmio_write(&mut self, address: u64, input: &[u8]) -> IoResult {
        self.calls.lock().writes.push((address, input.to_vec()));
        for (offset, byte) in input.iter().copied().enumerate() {
            self.memory.insert(address + offset as u64, byte);
        }
        IoResult::Ok
    }
}

// Test: Construct the emulated PCI device, map its BAR through independent clones and deliver valid/invalid MSI vector addresses to mapped interrupts.
// Expected: Constructor enables MMIO/MSI-X with exact table bytes, BAR length is 4 KiB, 32/64-bit register bytes round-trip through shared clones, unsupported BAR/vector requests fail, and only the addressed interrupt signals once.
#[test]
fn emulated_device_preserves_register_bytes_and_interrupt_routing() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut config = [0; 64];
    config[0x40 / 4] = 0x00030011;
    let memory = DeviceTestMemory::new(8, false, "device-wrapper");
    let dma = memory.dma_client();
    let mut wrapper = EmulatedDevice::new(
        Device {
            config,
            memory: BTreeMap::new(),
            calls: calls.clone(),
        },
        MsiConnection::new(),
        dma.clone(),
    );
    assert_eq!(wrapper.id(), "emulated");
    assert_eq!(wrapper.max_interrupt_count(), 4);
    assert!(
        wrapper
            .map_bar(1)
            .err()
            .unwrap()
            .to_string()
            .contains("invalid bar 1")
    );
    let mapping = wrapper.map_bar(0).unwrap();
    assert_eq!(mapping.len(), 4096);
    let mut clone = wrapper.clone();
    let cloned = clone.map_bar(0).unwrap();
    mapping.write_u32(0x20, 0x44332211);
    assert_eq!(cloned.read_u32(0x20), 0x44332211);
    cloned.write_u64(0x38, 0x9182736455463728);
    assert_eq!(mapping.read_u64(0x38), 0x9182736455463728);
    let calls = calls.lock();
    for expected in [(0x20, 0), (0x24, 1), (4, 2), (0x40, 0x80000000)] {
        assert!(calls.pci_writes.contains(&expected));
    }
    assert_eq!(calls.writes.len(), 130);
    for index in 0u64..64 {
        assert_eq!(
            calls.writes[index as usize * 2],
            (0x100000000 + index * 16, index.to_ne_bytes().to_vec())
        );
        assert_eq!(
            calls.writes[index as usize * 2 + 1],
            (0x100000000 + index * 16 + 12, 0u32.to_ne_bytes().to_vec())
        );
    }
    assert_eq!(
        &calls.writes[128..],
        &[
            (0x20, 0x44332211u32.to_ne_bytes().to_vec()),
            (0x38, 0x9182736455463728u64.to_ne_bytes().to_vec())
        ]
    );
    assert_eq!(calls.reads, [(0x20, 4), (0x38, 8)]);
    drop(calls);
    let mut first = wrapper.map_interrupt(0, 0).unwrap();
    let mut fourth = clone.map_interrupt(3, 15).unwrap();
    assert!(wrapper.map_interrupt(4, 0).is_err());
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(first.poll(&mut context), Poll::Pending);
    wrapper.controller.signal_msi(None, 3, 0);
    assert_eq!(first.poll(&mut context), Poll::Pending);
    assert_eq!(fourth.poll(&mut context), Poll::Ready(()));
    assert_eq!(fourth.poll(&mut context), Poll::Pending);
    wrapper.controller.signal_msi(None, 4, 0);
    assert_eq!(first.poll(&mut context), Poll::Pending);
    wrapper.controller.signal_msi(None, 0, 0);
    assert_eq!(first.poll(&mut context), Poll::Ready(()));
    let allocation = wrapper.dma_client().allocate_dma_buffer(4096).unwrap();
    assert_eq!(allocation.len(), 4096);
    let second = clone
        .dma_client_for(user_driver::DmaPool::Persistent)
        .unwrap()
        .allocate_dma_buffer(4096)
        .unwrap();
    assert_ne!(allocation.pfns(), second.pfns());
}
