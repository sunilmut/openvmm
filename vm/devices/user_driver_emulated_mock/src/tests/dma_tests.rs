// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

struct Callbacks {
    calls: Arc<Mutex<Vec<usize>>>,
    fail: bool,
}
impl DeviceTestDmaClientCallbacks for Callbacks {
    fn allocate_dma_buffer(
        &self,
        allocator: &PagePoolAllocator,
        total_size: usize,
    ) -> anyhow::Result<user_driver::memory::MemoryBlock> {
        self.calls.lock().push(total_size);
        if self.fail {
            anyhow::bail!("callback allocation denied");
        }
        allocator.allocate_dma_buffer(total_size.next_multiple_of(4096))
    }
    fn attach_pending_buffers(
        &self,
        allocator: &PagePoolAllocator,
    ) -> anyhow::Result<Vec<user_driver::memory::MemoryBlock>> {
        self.calls.lock().push(0);
        if self.fail {
            anyhow::bail!("callback attach denied");
        }
        let buffer = allocator.allocate_dma_buffer(4096)?;
        buffer.write_at(0, b"callback buffer");
        Ok(vec![buffer])
    }
}

// Test: Forward allocation and attachment through recording callbacks backed by the actual test allocator, including explicit callback failures.
// Expected: The exact unrounded request reaches the callback, returned buffers share guest backing and retain bytes, attachment preserves the returned list, and callback errors propagate unchanged.
#[test]
fn dma_callbacks_preserve_requests_buffers_and_errors() {
    let memory = DeviceTestMemory::new(8, false, "callback-test");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let client = DeviceTestDmaClient::new(
        memory.dma_client(),
        Callbacks {
            calls: calls.clone(),
            fail: false,
        },
    );
    let buffer = client.allocate_dma_buffer(5000).unwrap();
    assert_eq!(buffer.len(), 8192);
    buffer.write_at(0, b"shared bytes");
    assert_eq!(
        memory
            .guest_memory()
            .read_plain::<[u8; 12]>(buffer.pfns()[0] * PAGE_SIZE64)
            .unwrap(),
        *b"shared bytes"
    );
    let attached = client.attach_pending_buffers().unwrap();
    assert_eq!(attached.len(), 1);
    let mut bytes = [0; 15];
    attached[0].read_at(0, &mut bytes);
    assert_eq!(&bytes, b"callback buffer");
    assert_eq!(*calls.lock(), [5000, 0]);
    let failures = DeviceTestDmaClient::new(
        memory.dma_client(),
        Callbacks {
            calls: calls.clone(),
            fail: true,
        },
    );
    assert_eq!(
        failures.allocate_dma_buffer(17).unwrap_err().to_string(),
        "callback allocation denied"
    );
    assert_eq!(
        failures.attach_pending_buffers().unwrap_err().to_string(),
        "callback attach denied"
    );
    assert_eq!(*calls.lock(), [5000, 0, 17, 0]);
}

// Test: Retain exported guest/payload views and a live DMA block beyond the fixture owner, then release the views in different orders.
// Expected: Live handles retain their backing, DMA writes remain visible through guest memory, payload bytes stay separate, and the last surviving handles preserve their contents.
#[test]
fn exported_memory_views_and_dma_block_retain_backing_after_fixture_drop() {
    for allow_dma in [false, true] {
        let (guest, payload, buffer) = {
            let memory = DeviceTestMemory::new(8, allow_dma, "retained-backing");
            let buffer = memory.dma_client().allocate_dma_buffer(4096).unwrap();
            buffer.write_at(0, &[0x81, 0, 0xff, 0x27]);
            (memory.guest_memory(), memory.payload_mem(), buffer)
        };
        let address = buffer.pfns()[0] * PAGE_SIZE64;
        assert_eq!(
            guest.read_plain::<[u8; 4]>(address).unwrap(),
            [0x81, 0, 0xff, 0x27]
        );
        guest.write_plain(address + 4094, &[0x12u8, 0x34]).unwrap();
        let mut tail = [0; 2];
        buffer.read_at(4094, &mut tail);
        assert_eq!(tail, [0x12, 0x34]);
        payload.write_plain(0, &0x55667788u32).unwrap();
        assert_eq!(
            guest.read_plain::<u32>(4 * PAGE_SIZE64).unwrap(),
            0x55667788
        );
        drop(guest);
        buffer.write_at(0, &[0xde, 0xad, 0xbe, 0xef]);
        let mut bytes = [0; 4];
        buffer.read_at(0, &mut bytes);
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(payload.read_plain::<u32>(0).unwrap(), 0x55667788);
        drop(buffer);
        assert_eq!(payload.read_plain::<u32>(0).unwrap(), 0x55667788);
        assert_eq!(payload.iova(17), allow_dma.then_some(4 * PAGE_SIZE64 + 17));
    }
}
