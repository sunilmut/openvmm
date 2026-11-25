// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::DefaultDriver;
use pal_async::async_test;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use test_with_tracing::test;
use vmcore::vm_task::SingleDriverBackend;

mod mapping_tests;
mod queue_tests;

// Test: Attach empty, non-page-aligned, already-aligned, writable-short and genuinely read-only-short files, then read their advertised shared-memory geometry.
// Expected: Invalid files are rejected with specific errors, valid ranges are 2 MiB aligned, writable files extend with zero padding, and read-only files retain original length and data.
#[async_test]
async fn backing_file_validation_alignment_and_read_only_preservation(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    for (len, expected) in [
        (0, "persistent memory file must not be empty"),
        (
            4095,
            "persistent memory file size must be a multiple of 4 KiB",
        ),
    ] {
        let file = tempfile::tempfile().unwrap();
        file.set_len(len).unwrap();
        let error = Device::new(&driver_source, file, true).err().unwrap();
        assert_eq!(error.to_string(), expected);
    }
    for (len, writable, expected_len) in [
        (4096, false, 4096),
        (4096, true, 0x20_0000),
        (0x20_0000, true, 0x20_0000),
    ] {
        let mut backing = tempfile::NamedTempFile::new().unwrap();
        backing.as_file().set_len(len).unwrap();
        backing.write_all(&[0x91; 64]).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .open(backing.path())
            .unwrap();
        let mut device = Device::new(&driver_source, file, writable).unwrap();
        let traits = device.traits();
        assert_eq!(traits.device_id, virtio::spec::VirtioDeviceType::PMEM);
        assert_eq!(traits.max_queues, 1);
        assert_eq!(traits.shared_memory.id, 0);
        assert_eq!(traits.shared_memory.size, 0x20_0000);
        assert_eq!(traits.device_register_length, 16);
        assert!(device.supports_save_restore());
        assert_eq!(backing.as_file().metadata().unwrap().len(), expected_len);
        backing.seek(SeekFrom::Start(0)).unwrap();
        let mut prefix = [0; 64];
        backing.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, [0x91; 64]);
        if expected_len > len {
            backing.seek(SeekFrom::Start(len)).unwrap();
            backing.read_exact(&mut prefix).unwrap();
            assert_eq!(prefix, [0; 64]);
        }
        for offset in [0, 4, 8, 12, 16, u16::MAX] {
            device.write_registers_u32(offset, u32::MAX).await;
            assert_eq!(device.read_registers_u32(offset).await, 0);
        }
    }
}
