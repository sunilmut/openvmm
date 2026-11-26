// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements a VtlMemoryProtection guard that can be used to temporarily allow
//! access to pages that were previously protected.

#![cfg(target_os = "linux")]

mod device_dma;

pub use device_dma::LowerVtlDmaBuffer;

use anyhow::Context;
use anyhow::Result;
use inspect::Inspect;
use std::sync::Arc;
use user_driver::DmaClient;
use user_driver::memory::MemoryBlock;
use virt::VtlMemoryProtection;

/// A guard that will restore [`hvdef::HV_MAP_GPA_PERMISSIONS_NONE`] permissions
/// on the pages when dropped.
#[derive(Inspect)]
struct PagesAccessibleToLowerVtl {
    #[inspect(skip)]
    vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
    #[inspect(hex, iter_by_index)]
    pages: Vec<u64>,
}

impl PagesAccessibleToLowerVtl {
    /// Creates a new guard that will lower the VTL permissions of the pages
    /// while the returned guard is held.
    fn new_from_pages(
        vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
        pages: &[u64],
    ) -> Result<Self> {
        // Track pages that we have successfully lowered the VTL permissions on,
        // so that we can restore them if any subsequent pages fail.
        let mut guard = Self {
            vtl_protect,
            pages: Vec::with_capacity(pages.len()),
        };

        for pfn in pages {
            guard
                .vtl_protect
                .modify_vtl_page_setting(*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_ALL)
                .context("failed to update VTL protections on page")?;

            guard.pages.push(*pfn);
        }
        Ok(guard)
    }
}

impl Drop for PagesAccessibleToLowerVtl {
    fn drop(&mut self) {
        if let Err(err) = self
            .pages
            .iter()
            .map(|pfn| {
                self.vtl_protect
                    .modify_vtl_page_setting(*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_NONE)
                    .context("failed to update VTL protections on page")
            })
            .collect::<Result<Vec<_>>>()
        {
            // The inability to rollback any pages is fatal. We cannot leave the
            // pages in the state where the correct VTL protections are not
            // applied, because that would compromise the security of the
            // platform.
            panic!(
                "failed to reset page protections {}",
                err.as_ref() as &dyn std::error::Error
            );
        }
    }
}

/// A [`DmaClient`] wrapper that will lower the VTL permissions of the page
/// on the allocated memory block.
#[derive(Inspect)]
pub struct LowerVtlMemorySpawner<T: DmaClient> {
    #[inspect(skip)]
    spawner: T,
    #[inspect(skip)]
    vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
}

impl<T: DmaClient> LowerVtlMemorySpawner<T> {
    /// Create a new wrapped [`DmaClient`] spawner that will lower the VTL
    /// permissions of the returned [`MemoryBlock`].
    pub fn new(spawner: T, vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>) -> Self {
        Self {
            spawner,
            vtl_protect,
        }
    }
}

impl<T: DmaClient> DmaClient for LowerVtlMemorySpawner<T> {
    fn allocate_dma_buffer(&self, len: usize) -> Result<MemoryBlock> {
        let mem = self.spawner.allocate_dma_buffer(len)?;
        let vtl_guard =
            PagesAccessibleToLowerVtl::new_from_pages(self.vtl_protect.clone(), mem.pfns())
                .context("failed to lower VTL permissions on memory block")?;

        Ok(MemoryBlock::new(LowerVtlDmaBuffer {
            block: mem,
            _vtl_guard: vtl_guard,
        }))
    }

    fn attach_pending_buffers(&self) -> Result<Vec<MemoryBlock>> {
        anyhow::bail!("restore is not supported for LowerVtlMemorySpawner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use test_with_tracing::test;

    #[derive(Default)]
    struct ProtectionHost {
        requests: Mutex<Vec<(u64, hvdef::HvMapGpaFlags)>>,
        deny: Option<u64>,
    }

    impl VtlMemoryProtection for ProtectionHost {
        fn modify_vtl_page_setting(&self, pfn: u64, flags: hvdef::HvMapGpaFlags) -> Result<()> {
            self.requests.lock().push((pfn, flags));
            if Some(pfn) == self.deny && flags == hvdef::HV_MAP_GPA_PERMISSIONS_ALL {
                anyhow::bail!("host denied page {pfn}");
            }
            Ok(())
        }
    }

    // Test: Hold two independent permission guards and drop them separately.
    // Expected: Only the dropped guard's pages are revoked; full-width, noncontiguous
    //       PFNs retain their identity and no revocation occurs while a guard is held.
    #[test]
    fn permission_lifetimes_are_independent() {
        let host = Arc::new(ProtectionHost::default());
        let first_pages = [1, 0x1_0000_1234, 37];
        let second_pages = [9, 0x2_0000_4321];
        let first = PagesAccessibleToLowerVtl::new_from_pages(host.clone(), &first_pages).unwrap();
        let second =
            PagesAccessibleToLowerVtl::new_from_pages(host.clone(), &second_pages).unwrap();
        let grants: Vec<_> = first_pages
            .into_iter()
            .chain(second_pages)
            .map(|pfn| (pfn, hvdef::HV_MAP_GPA_PERMISSIONS_ALL))
            .collect();
        assert_eq!(*host.requests.lock(), grants);
        drop(second);
        let mut expected = grants;
        expected.extend(second_pages.map(|pfn| (pfn, hvdef::HV_MAP_GPA_PERMISSIONS_NONE)));
        assert_eq!(*host.requests.lock(), expected);
        drop(first);
        expected.extend(first_pages.map(|pfn| (pfn, hvdef::HV_MAP_GPA_PERMISSIONS_NONE)));
        assert_eq!(*host.requests.lock(), expected);
    }

    // Test: A host refuses a page at each position of a multi-page grant.
    // Expected: Creation returns the host error and revokes exactly the accepted
    //       prefix, never the rejected page or unattempted suffix.
    #[test]
    fn partial_grant_failure_revokes_only_successful_pages() {
        let pages = [3, 0x1_0000_0009, 13];
        for (index, denied) in pages.into_iter().enumerate() {
            let host = Arc::new(ProtectionHost {
                deny: Some(denied),
                ..Default::default()
            });
            let error = PagesAccessibleToLowerVtl::new_from_pages(host.clone(), &pages)
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(&format!("host denied page {denied}")));
            let mut expected: Vec<_> = pages[..=index]
                .iter()
                .map(|pfn| (*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_ALL))
                .collect();
            expected.extend(
                pages[..index]
                    .iter()
                    .map(|pfn| (*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_NONE)),
            );
            assert_eq!(*host.requests.lock(), expected);
        }
    }
}
