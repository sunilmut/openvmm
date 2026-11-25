// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MMIO access types for Linux environments.

use crate::CreateMemoryAccess;
use anyhow::Context as _;
use hcl::ioctl::MshvHvcall;
use std::sync::Arc;
use vpci_client::MemoryAccess;

/// Accesses MMIO space directly via `/dev/mem`.
pub struct DirectMmio(fs_err::File);

impl DirectMmio {
    /// Opens `/dev/mem` for MMIO access.
    pub fn new() -> anyhow::Result<Self> {
        let dev_mem = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mem")
            .context("failed to open /dev/mem")?;
        Ok(Self(dev_mem))
    }
}

impl CreateMemoryAccess for DirectMmio {
    fn create_memory_access(&self, gpa: u64) -> anyhow::Result<Box<dyn MemoryAccess>> {
        let mapping = sparse_mmap::SparseMapping::new(0x2000)
            .context("failed to create sparse mapping for vpci mmio")?;
        mapping
            .map_file(0, 0x2000, &self.0, gpa, true)
            .context("failed to map /dev/mem for vpci mmio")?;

        Ok(Box::new(DirectMmioInstance(gpa, mapping)))
    }
}

struct DirectMmioInstance(u64, sparse_mmap::SparseMapping);

impl MemoryAccess for DirectMmioInstance {
    fn gpa(&mut self) -> u64 {
        self.0
    }

    fn read(&mut self, addr: u64, data: &mut [u8]) {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        let res = match data.len() {
            1 => self
                .1
                .read_volatile::<[u8; 1]>(offset)
                .map(|v| data.copy_from_slice(&v)),
            2 => self
                .1
                .read_volatile::<[u8; 2]>(offset)
                .map(|v| data.copy_from_slice(&v)),
            4 => self
                .1
                .read_volatile::<[u8; 4]>(offset)
                .map(|v| data.copy_from_slice(&v)),
            _ => panic!("size must be 1-, 2-, or 4-bytes"),
        };
        if let Err(err) = res {
            tracelimit::error_ratelimited!(
                addr,
                error = &err as &dyn std::error::Error,
                "vpci mmio read failure"
            );
            data.fill(!0);
        }
    }

    fn write(&mut self, addr: u64, value: &[u8]) {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        let res = match value.len() {
            1 => self
                .1
                .write_volatile(offset, value.as_array::<1>().unwrap()),
            2 => self
                .1
                .write_volatile(offset, value.as_array::<2>().unwrap()),
            4 => self
                .1
                .write_volatile(offset, value.as_array::<4>().unwrap()),
            _ => panic!("size must be 1-, 2-, or 4-bytes"),
        };
        if let Err(err) = res {
            tracelimit::error_ratelimited!(
                addr,
                value,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

/// MMIO access via hypercalls.
pub struct HypercallMmio(Arc<MshvHvcall>);

impl HypercallMmio {
    /// Opens a hypercall interface for MMIO access.
    pub fn new() -> anyhow::Result<Self> {
        let mshv_hvcall = MshvHvcall::new().context("failed to open mshv_hvcall device")?;
        mshv_hvcall.set_allowed_hypercalls(&[
            hvdef::HypercallCode::HvCallMemoryMappedIoRead,
            hvdef::HypercallCode::HvCallMemoryMappedIoWrite,
        ]);
        Ok(Self(Arc::new(mshv_hvcall)))
    }
}

impl CreateMemoryAccess for HypercallMmio {
    fn create_memory_access(&self, gpa: u64) -> anyhow::Result<Box<dyn MemoryAccess>> {
        Ok(Box::new(HypercallMmioInstance(gpa, self.0.clone())))
    }
}

struct HypercallMmioInstance(u64, Arc<MshvHvcall>);

impl MemoryAccess for HypercallMmioInstance {
    fn gpa(&mut self) -> u64 {
        self.0
    }

    fn read(&mut self, addr: u64, data: &mut [u8]) {
        if let Err(err) = self.1.mmio_read(addr, data) {
            tracelimit::error_ratelimited!(
                addr,
                error = &err as &dyn std::error::Error,
                "vpci mmio read failure"
            );
            data.fill(!0);
        }
    }

    fn write(&mut self, addr: u64, data: &[u8]) {
        if let Err(err) = self.1.mmio_write(addr, data) {
            tracelimit::error_ratelimited!(
                addr,
                data,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DirectMmio;
    use super::DirectMmioInstance;
    use crate::CreateMemoryAccess;
    use sparse_mmap::SparseMapping;
    use test_with_tracing::test;
    use vpci_client::MemoryAccess;

    #[test]
    fn direct_mmio_write_widths() {
        let mapping = SparseMapping::new(0x2000).unwrap();
        mapping.alloc(0, 0x2000).unwrap();
        let mut mmio = DirectMmioInstance(0x1000, mapping);

        for value in [
            &[0x5a][..],
            &[0x12, 0x34][..],
            &[0x12, 0x34, 0x56, 0x78][..],
        ] {
            mmio.write(0x1100, value);

            let mut readback = vec![0; value.len()];
            mmio.read(0x1100, &mut readback);
            assert_eq!(readback, value);
        }
    }

    // Test: Access unmapped, underflowing and out-of-range MMIO addresses at each width.
    // Expected: Reads return all ones and rejected writes preserve valid mapped memory.
    #[test]
    fn invalid_mmio_addresses_fail_closed_without_corrupting_memory() {
        let mapping = SparseMapping::new(0x2000).unwrap();
        mapping.alloc(0, 0x1000).unwrap();
        let base = 0x4000;
        let mut mmio = DirectMmioInstance(base, mapping);
        mmio.write(base, &[0x12, 0x34, 0x56, 0x78]);
        for width in [1, 2, 4] {
            for address in [base - 4, base + 0x1000, base + 0x2000, u64::MAX - 3] {
                let mut data = vec![0; width];
                mmio.read(address, &mut data);
                assert_eq!(
                    data,
                    vec![0xff; width],
                    "address {address:#x}, width {width}"
                );
                mmio.write(address, &vec![0xab; width]);
            }
        }
        let mut data = [0; 4];
        mmio.read(base, &mut data);
        assert_eq!(data, [0x12, 0x34, 0x56, 0x78]);
    }

    // Test: Map a file-backed MMIO factory at two GPAs and alias one mapping.
    // Expected: Aliases share writes, distinct windows do not, and bad alignment fails.
    #[test]
    fn file_backed_mmio_instances_preserve_gpa_and_mapping_boundaries() {
        let path = std::env::temp_dir().join(format!(
            "vpci-relay-mmio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        // Unlink immediately: the open file and mappings own its lifetime.
        fs_err::remove_file(&path).unwrap();
        file.set_len(0x8000).unwrap();
        let factory = DirectMmio(file);
        let mut first = factory.create_memory_access(0x4000).unwrap();
        let mut alias = factory.create_memory_access(0x4000).unwrap();
        let mut second = factory.create_memory_access(0x6000).unwrap();
        assert_eq!(first.gpa(), 0x4000);
        assert_eq!(alias.gpa(), 0x4000);
        assert_eq!(second.gpa(), 0x6000);
        first.write(0x4100, &[0x12, 0x34, 0x56, 0x78]);
        second.write(0x6100, &[0xab, 0xcd, 0xef, 0x01]);
        let mut data = [0; 4];
        alias.read(0x4100, &mut data);
        assert_eq!(data, [0x12, 0x34, 0x56, 0x78]);
        second.read(0x6100, &mut data);
        assert_eq!(data, [0xab, 0xcd, 0xef, 0x01]);

        let err = factory.create_memory_access(1).err().unwrap();
        assert!(
            format!("{err:#}").contains("failed to map /dev/mem for vpci mmio"),
            "{err:#}"
        );
    }
}
