// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_event::Event;
use test_with_tracing::test;
use virtio::queue::QueueParams;
use virtio::spec::queue::DescriptorFlags;
use virtio::test_helpers::*;
use vmcore::interrupt::Interrupt;

const DESC: u64 = 0;
const AVAIL: u64 = 0x1000;
const USED: u64 = 0x2000;
const REQUEST: u64 = 0x3000;
const RESPONSE: u64 = 0x4000;
const QUEUE_SIZE: u16 = 8;

// Test: Submit real virtio-pmem flush, unsupported, and inaccessible-memory requests for writable and read-only files, then stop/resume the queue with its returned state.
// Expected: Flush returns success without changing file bytes, unsupported/bad-memory requests return the protocol error, every response has four used bytes, and restored queue cursors continue completing later requests exactly once.
#[async_test]
async fn real_queue_flush_errors_and_stop_resume_preserve_protocol_and_data(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    for writable in [false, true] {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(0x20_0000).unwrap();
        file.write_all(&[0x91; 64]).unwrap();
        let mut device = Device::new(&driver_source, file.try_clone().unwrap(), writable).unwrap();
        assert!(device.stop_queue(0).await.is_none());
        let mem = GuestMemory::allocate(0x5000);
        init_avail_ring(&mem, AVAIL);
        init_used_ring(&mem, USED);
        let event = Event::new();
        let interrupt = Event::new();
        let resources = || QueueResources {
            params: QueueParams {
                size: QUEUE_SIZE,
                enable: true,
                desc_addr: DESC,
                avail_addr: AVAIL,
                used_addr: USED,
            },
            notify: Interrupt::from_event(interrupt.clone()),
            event: event.clone(),
            guest_memory: mem.clone(),
        };
        device
            .start_queue(0, resources(), &VirtioDeviceFeatures::new(), None)
            .await
            .unwrap();
        let mut avail_index = 0;
        let mut used_index = 0;
        for (request, bad_address, expected) in [
            (0, false, 0),
            (1, false, u32::MAX),
            (u32::MAX, false, u32::MAX),
            (0, true, u32::MAX),
            (0, false, 0),
        ] {
            mem.write_at(REQUEST, &request.to_le_bytes()).unwrap();
            mem.write_at(RESPONSE, &[0xcc; 8]).unwrap();
            write_descriptor(
                &mem,
                DESC,
                0,
                if bad_address { 0x5000 } else { REQUEST },
                4,
                DescriptorFlags::new().with_next(true),
                1,
            );
            write_descriptor(
                &mem,
                DESC,
                1,
                RESPONSE,
                8,
                DescriptorFlags::new().with_write(true),
                0,
            );
            make_available(&mem, AVAIL, QUEUE_SIZE, 0, &mut avail_index);
            event.signal();
            assert_eq!(
                wait_for_used(&driver, &interrupt, &mem, USED, QUEUE_SIZE, &mut used_index).await,
                (0, 4)
            );
            let mut response = [0; 8];
            mem.read_at(RESPONSE, &mut response).unwrap();
            assert_eq!(&response[..4], expected.to_le_bytes());
            assert_eq!(&response[4..], &[0xcc; 4]);
            if request == 1 {
                let state = device.stop_queue(0).await.unwrap();
                assert_eq!(state.avail_index, avail_index);
                assert_eq!(state.used_index, used_index);
                assert!(device.stop_queue(0).await.is_none());
                device
                    .start_queue(0, resources(), &VirtioDeviceFeatures::new(), Some(state))
                    .await
                    .unwrap();
            }
        }
        device.stop_queue(0).await.unwrap();
        assert!(read_used(&mem, USED, QUEUE_SIZE, &mut used_index).is_none());
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = [0; 64];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [0x91; 64]);
    }
}
