// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod device_memory;
mod dma;
mod memory;
mod partition;

use crate::GuestMemoryBuilder;
use crate::GuestMemoryManager;
use crate::Mappable;
use crate::RamBackingRequest;
use memory_range::MemoryRange;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

const PAGE: u64 = 4096;

async fn manager(ranges: Vec<MemoryRange>, max_addr: u64) -> GuestMemoryManager {
    GuestMemoryBuilder::new()
        .add_backing(RamBackingRequest::new(ranges))
        .build(max_addr)
        .await
        .unwrap()
}

fn backing(data: &[u8]) -> Mappable {
    let fd = sparse_mmap::alloc_shared_memory(data.len(), "membacking-behavior").unwrap();
    let backing = Mappable::from(Arc::new(fd));
    let file = std::fs::File::from(OwnedFd::from(backing.clone()));
    file.write_all_at(data, 0).unwrap();
    backing
}

fn read_byte(gm: &guestmem::GuestMemory, address: u64) -> u8 {
    let mut byte = [0];
    gm.read_at(address, &mut byte).unwrap();
    byte[0]
}
