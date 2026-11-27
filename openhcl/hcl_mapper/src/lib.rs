// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides a mapper implementation for the page pool that uses the hcl ioctl
//! crate to map guest memory.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use anyhow::Context;
use hcl::ioctl::MshvVtlLow;
use inspect::Inspect;
use page_pool_alloc::PoolSource;
use std::os::fd::AsFd;

/// A mapper that uses [`MshvVtlLow`] to map pages.
#[derive(Inspect)]
pub struct HclMapper {
    #[inspect(skip)]
    fd: MshvVtlLow,
    gpa_bias: u64,
    is_shared: bool,
}

impl HclMapper {
    /// Creates an instance for mapping shared memory, with shared memory
    /// appearing to the guest starting at `vtom`.
    pub fn new_shared(vtom: u64) -> anyhow::Result<Self> {
        Self::new_inner(vtom, true)
    }

    /// Creates an instance for mapping private memory.
    pub fn new_private() -> anyhow::Result<Self> {
        Self::new_inner(0, false)
    }

    fn new_inner(gpa_bias: u64, is_shared: bool) -> anyhow::Result<Self> {
        let fd = MshvVtlLow::new().context("failed to open gpa fd")?;
        Ok(Self {
            fd,
            gpa_bias,
            is_shared,
        })
    }
}

impl PoolSource for HclMapper {
    fn address_bias(&self) -> u64 {
        self.gpa_bias
    }

    fn file_offset(&self, address: u64) -> u64 {
        address.wrapping_add(if self.is_shared {
            MshvVtlLow::SHARED_MEMORY_FLAG
        } else {
            0
        })
    }

    fn mappable(&self) -> sparse_mmap::MappableRef<'_> {
        self.fd.get().as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // IGNORED: Requires an OpenHCL Linux environment with read/write access to
    //       /dev/mshv_vtl_low. Ordinary host Linux cannot construct the mapper.
    //
    // Test: Translate private-pool addresses through the real mapper.
    // Expected: The guest bias is zero and file offsets preserve each address.
    #[test]
    #[ignore = "requires read/write access to /dev/mshv_vtl_low"]
    fn private_pool_offsets_preserve_guest_addresses() -> anyhow::Result<()> {
        let mapper = HclMapper::new_private()?;
        assert_eq!(mapper.address_bias(), 0);
        for address in [0, 0x2000, 0x0000_ffff_ffff_f000] {
            assert_eq!(mapper.file_offset(address), address);
        }
        Ok(())
    }

    // IGNORED: Requires an OpenHCL Linux environment with read/write access to
    //       /dev/mshv_vtl_low. Ordinary host Linux cannot construct the mapper.
    //
    // Test: Translate shared-pool offsets with a nonzero guest address bias.
    // Expected: Offsets select shared memory without adding the guest bias.
    #[test]
    #[ignore = "requires read/write access to /dev/mshv_vtl_low"]
    fn shared_pool_offsets_do_not_double_apply_guest_bias() -> anyhow::Result<()> {
        let mapper = HclMapper::new_shared(0x4000_0000_0000)?;
        assert_eq!(mapper.address_bias(), 0x4000_0000_0000);
        for (address, offset) in [
            (0, 0x8000_0000_0000_0000),
            (0x2000, 0x8000_0000_0000_2000),
            (0x0000_ffff_ffff_f000, 0x8000_ffff_ffff_f000),
        ] {
            assert_eq!(mapper.file_offset(address), offset);
        }
        Ok(())
    }
}
