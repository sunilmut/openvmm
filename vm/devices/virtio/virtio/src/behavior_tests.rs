// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::test_helpers::{make_available, read_used_entry, write_descriptor};
use test_with_tracing::test;

fn payload_chain(driver: &DefaultDriver) -> (GuestMemory, VirtioQueue) {
    let (memory, queue) = new_bound_test_queue(driver, false, None);
    for (index, address, length, writable) in [
        (0, 0x8000, 4, false),
        (1, 0x8200, 3, true),
        (2, 0x8100, 5, false),
        (3, 0x8300, 4, true),
    ] {
        write_descriptor(
            &memory,
            BOUND_TEST_DESC_ADDR,
            index,
            address,
            length,
            DescriptorFlags::new()
                .with_write(writable)
                .with_next(index != 3),
            index + 1,
        );
    }
    memory.write_at(0x8000, b"ABCD").unwrap();
    memory.write_at(0x8100, b"efghi").unwrap();
    memory.write_at(0x8200, &[0xa5; 3]).unwrap();
    memory.write_at(0x8300, &[0xa5; 4]).unwrap();
    make_available(
        &memory,
        BOUND_TEST_AVAIL_ADDR,
        BOUND_TEST_QUEUE_SIZE,
        0,
        &mut 0,
    );
    (memory, queue)
}

// Test: Peek an interleaved readable/writable chain and read across its buffers.
// Expected: Reads skip writable buffers, honor offsets and truncation, and a
//       dropped peek leaves the same descriptor available for completion.
#[async_test]
async fn peeked_payload_reads_respect_direction_offsets_and_capacity(driver: DefaultDriver) {
    let (memory, mut queue) = payload_chain(&driver);
    {
        let peek = queue.peek().await.unwrap();
        assert_eq!(peek.descriptor_index(), 0);
        assert_eq!(peek.readable_length(), 9);
        assert_eq!(peek.payload().len(), 4);
        let mut bytes = [0xcc; 12];
        assert_eq!(peek.read(&memory, &mut bytes).unwrap(), 9);
        assert_eq!(&bytes[..9], b"ABCDefghi");
        assert_eq!(&bytes[9..], &[0xcc; 3]);
        for (offset, expected) in [
            (0, &b"ABC"[..]),
            (3, &b"Def"[..]),
            (4, &b"efg"[..]),
            (8, &b"i"[..]),
            (9, &b""[..]),
            (20, &b""[..]),
        ] {
            let mut output = [0xcc; 3];
            assert_eq!(
                peek.read_at_offset(offset, &memory, &mut output).unwrap(),
                expected.len()
            );
            assert_eq!(&output[..expected.len()], expected);
            assert!(output[expected.len()..].iter().all(|b| *b == 0xcc));
        }
    }
    let work = queue.try_peek().unwrap().unwrap().consume();
    queue.complete(work, 0);
    assert_eq!(
        read_used_entry(&memory, BOUND_TEST_USED_ADDR, BOUND_TEST_QUEUE_SIZE, 0),
        (0, 0)
    );
    assert!(queue.try_next().unwrap().is_none());
}

// Test: Read and write interleaved buffers through a consumed descriptor chain.
// Expected: Payload lengths match their directions, writes span only writable
//       buffers and a short destination returns an explicit partial-write error.
#[async_test]
async fn consumed_payload_scatter_gather_preserves_unwritten_bytes(driver: DefaultDriver) {
    let (memory, mut queue) = payload_chain(&driver);
    let work = queue.try_next().unwrap().unwrap();
    assert_eq!(work.get_payload_length(false), 9);
    assert_eq!(work.get_payload_length(true), 7);
    let mut bytes = [0; 9];
    assert_eq!(work.read(&memory, &mut bytes).unwrap(), 9);
    assert_eq!(&bytes, b"ABCDefghi");
    let mut suffix = [0; 7];
    assert_eq!(work.read_at_offset(2, &memory, &mut suffix).unwrap(), 7);
    assert_eq!(&suffix, b"CDefghi");
    work.write_at_offset(1, &memory, b"123456").unwrap();
    let mut first = [0; 3];
    let mut second = [0; 4];
    memory.read_at(0x8200, &mut first).unwrap();
    memory.read_at(0x8300, &mut second).unwrap();
    assert_eq!(&first, &[0xa5, b'1', b'2']);
    assert_eq!(&second, b"3456");
    assert!(matches!(
        work.write_at_offset(6, &memory, b"XY"),
        Err(crate::VirtioWriteError::NotAllWritten(2))
    ));
    work.write(&memory, b"7654321").unwrap();
    memory.read_at(0x8200, &mut first).unwrap();
    memory.read_at(0x8300, &mut second).unwrap();
    assert_eq!(&first, b"765");
    assert_eq!(&second, b"4321");
    queue.complete(work, 7);
    assert_eq!(
        read_used_entry(&memory, BOUND_TEST_USED_ADDR, BOUND_TEST_QUEUE_SIZE, 0),
        (0, 7)
    );
}

// Test: Access readable and writable payloads whose GPAs are outside guest memory.
// Expected: Both operations report memory errors without writing low guest
//       addresses, and the descriptor can still be explicitly completed.
#[async_test]
async fn inaccessible_payloads_surface_memory_errors(driver: DefaultDriver) {
    let (memory, mut queue) = payload_chain(&driver);
    write_descriptor(
        &memory,
        BOUND_TEST_DESC_ADDR,
        0,
        u64::MAX - 2,
        8,
        DescriptorFlags::new().with_next(true),
        1,
    );
    write_descriptor(
        &memory,
        BOUND_TEST_DESC_ADDR,
        1,
        0x10000,
        4,
        DescriptorFlags::new().with_write(true),
        0,
    );
    let work = queue.try_next().unwrap().unwrap();
    assert!(work.read(&memory, &mut [0; 1]).is_err());
    assert!(work.read_at_offset(4, &memory, &mut [0; 1]).is_err());
    assert!(matches!(
        work.write(&memory, b"bad"),
        Err(crate::VirtioWriteError::Memory(_))
    ));
    let mut untouched = [1; 8];
    memory.read_at(0, &mut untouched).unwrap();
    assert_eq!(untouched, [0; 8]);
    queue.complete(work, 0);
}

#[derive(InspectMut)]
#[inspect(skip)]
struct Registers {
    bytes: Arc<Mutex<[u8; 16]>>,
    queue_size: u16,
}

impl VirtioDevice for Registers {
    fn traits(&self) -> DeviceTraits {
        DeviceTraits {
            device_id: VirtioDeviceType::CONSOLE,
            max_queues: 1,
            device_register_length: 16,
            ..Default::default()
        }
    }
    fn queue_size(&self, _: u16) -> u16 {
        self.queue_size
    }
    async fn read_registers_u32(&mut self, offset: u16) -> u32 {
        u32::from_le_bytes(
            self.bytes.lock()[offset as usize..offset as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    async fn write_registers_u32(&mut self, offset: u16, value: u32) {
        self.bytes.lock()[offset as usize..offset as usize + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
    async fn start_queue(
        &mut self,
        _: u16,
        _: QueueResources,
        _: &VirtioDeviceFeatures,
        _: Option<QueueState>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn stop_queue(&mut self, _: u16) -> Option<QueueState> {
        None
    }
}

// Test: Read and write MMIO device config using unaligned one-to-eight-byte spans.
// Expected: Deferred accesses preserve neighboring register bytes and return
//       exactly the byte range requested by the guest.
#[async_test]
async fn deferred_mmio_device_config_preserves_partial_words(driver: DefaultDriver) {
    let bytes = Arc::new(Mutex::new(std::array::from_fn(|i| i as u8)));
    let mut device = VirtioMmioDevice::new(
        Box::new(Registers {
            bytes,
            queue_size: 256,
        }),
        &driver,
        GuestMemory::empty(),
        LineInterrupt::detached(),
        None,
        0x1000,
        0x1000,
    )
    .unwrap();
    let mut expected = std::array::from_fn::<_, 16, _>(|i| i as u8);
    for (offset, length) in [(0, 4), (1, 1), (2, 2), (3, 8), (6, 3), (9, 7)] {
        let data = vec![0xa0 + offset as u8; length];
        let IoResult::Defer(write) = device.mmio_write(0x1100 + offset as u64, &data) else {
            panic!("expected deferred write")
        };
        write.write_future().await.unwrap();
        expected[offset..offset + length].copy_from_slice(&data);
        for start in [0, 8] {
            let mut actual = [0; 8];
            let IoResult::Defer(read) = device.mmio_read(0x1100 + start as u64, &mut actual) else {
                panic!("expected deferred read")
            };
            read.read_future(&mut actual).await.unwrap();
            assert_eq!(&actual, &expected[start..start + 8]);
        }
    }
    device.teardown().await;
}

// Test: Construct transports with invalid backend-advertised default queue sizes.
// Expected: Zero, non-power-of-two and oversized queues fail construction with
//       an explicit input error rather than advertising unusable queues.
#[async_test]
async fn invalid_backend_queue_sizes_are_rejected(driver: DefaultDriver) {
    for queue_size in [0, 3, 2048] {
        let device = Registers {
            bytes: Default::default(),
            queue_size,
        };
        let result = VirtioMmioDevice::new(
            Box::new(device),
            &driver,
            GuestMemory::empty(),
            LineInterrupt::detached(),
            None,
            0,
            0x1000,
        );
        match result {
            Ok(_) => panic!("invalid queue size accepted"),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        }
    }
}

// Test: Enumerate PCI identities for storage, networking, communication and other devices.
// Expected: Config space reports the device's PCI class/subclass rather than
//       classifying all virtio devices as one device category.
#[async_test]
async fn pci_device_classes_follow_virtio_device_identity(driver: DefaultDriver) {
    for (device_id, expected) in [
        (VirtioDeviceType::NET, 0x0200),
        (VirtioDeviceType::BLK, 0x0100),
        (VirtioDeviceType::CONSOLE, 0x0780),
        (VirtioDeviceType::RTC, 0x0803),
        (VirtioDeviceType::RNG, 0x0880),
        (VirtioDeviceType::P9, 0x0880),
        (VirtioDeviceType::VSOCK, 0x0880),
        (VirtioDeviceType::FS, 0x0880),
        (VirtioDeviceType::PMEM, 0x0880),
        (VirtioDeviceType(100), 0x0880),
    ] {
        let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
        let endpoint = TestDevice::new(
            &source,
            DeviceTraits {
                device_id,
                max_queues: 1,
                ..Default::default()
            },
            None,
        );
        let msi = MsiConnection::new();
        let mut device = VirtioPciDevice::new(
            Box::new(endpoint),
            &driver,
            GuestMemory::empty(),
            PciInterruptModel::Msix(&msi.target()),
            None,
            &mut ExternallyManagedMmioIntercepts,
            None,
        )
        .unwrap();
        let mut value = 0;
        device
            .pci_cfg_read(8, ByteEnabledDwordRead::with_all_bytes_enabled(&mut value))
            .unwrap();
        assert_eq!(value >> 16, expected, "{device_id:?}");
        device.teardown().await;
    }
}

// Test: Restore PCI snapshots with excessive feature banks, queue counts and sizes.
// Expected: Each malformed snapshot is rejected through the public restore API.
#[async_test]
async fn pci_snapshots_validate_feature_and_queue_shapes(driver: DefaultDriver) {
    use vmcore::save_restore::AsyncSaveRestore;
    for case in 0..3 {
        let memory = VirtioTestMemoryAccess::new();
        let mut original = VirtioPciTestDevice::new(&driver, 1, &memory, None);
        original.pci_device.stop().await;
        let mut saved = original.pci_device.save().await.unwrap();
        match case {
            0 => saved.common.driver_feature_banks = vec![0; 3],
            1 => saved.queues.clear(),
            2 => saved.queues[0].common.size = 2048,
            _ => unreachable!(),
        }
        let mut restored = VirtioPciTestDevice::new(&driver, 1, &memory, None);
        assert!(restored.pci_device.restore(saved).await.is_err());
        original.pci_device.teardown().await;
        restored.pci_device.teardown().await;
    }
}
