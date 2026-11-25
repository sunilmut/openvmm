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

// Test: Queue mixed flush/unsupported requests in four-request batches and reuse descriptor IDs through multiple ring wraps.
// Expected: Every completion retains its descriptor identity and four-byte status, unsupported requests do not stop later flushes, and response guards remain unchanged without duplicate completions.
#[async_test]
async fn batched_flush_statuses_keep_descriptor_identity_across_ring_wrap(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let file = tempfile::tempfile().unwrap();
    file.set_len(0x20_0000).unwrap();
    let mut device = Device::new(&driver_source, file, true).unwrap();
    let mem = GuestMemory::allocate(0x5000);
    init_avail_ring(&mem, AVAIL);
    init_used_ring(&mem, USED);
    let event = Event::new();
    let interrupt = Event::new();
    device
        .start_queue(
            0,
            QueueResources {
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
            },
            &VirtioDeviceFeatures::new(),
            None,
        )
        .await
        .unwrap();
    let mut avail_index = 0;
    let mut used_index = 0;
    for batch in 0..5 {
        let requests = if batch % 2 == 0 {
            [0u32, 1, 0, u32::MAX]
        } else {
            [1u32, 0, u32::MAX, 0]
        };
        for (index, request) in requests.iter().enumerate() {
            let offset = index as u64 * 16;
            let descriptor = index as u16 * 2;
            mem.write_at(REQUEST + offset, &request.to_le_bytes())
                .unwrap();
            mem.write_at(RESPONSE + offset, &[0xcc; 16]).unwrap();
            write_descriptor(
                &mem,
                DESC,
                descriptor,
                REQUEST + offset,
                4,
                DescriptorFlags::new().with_next(true),
                descriptor + 1,
            );
            write_descriptor(
                &mem,
                DESC,
                descriptor + 1,
                RESPONSE + offset,
                8,
                DescriptorFlags::new().with_write(true),
                0,
            );
            make_available(&mem, AVAIL, QUEUE_SIZE, descriptor, &mut avail_index);
        }
        event.signal();
        let mut completed = [false; 4];
        for _ in 0..4 {
            let (descriptor, len) =
                wait_for_used(&driver, &interrupt, &mem, USED, QUEUE_SIZE, &mut used_index).await;
            assert_eq!(len, 4);
            assert!(descriptor < QUEUE_SIZE && descriptor % 2 == 0);
            let index = descriptor as usize / 2;
            assert!(!std::mem::replace(&mut completed[index], true));
            let mut response = [0; 16];
            mem.read_at(RESPONSE + index as u64 * 16, &mut response)
                .unwrap();
            let expected = if requests[index] == 0 { 0u32 } else { u32::MAX };
            assert_eq!(&response[..4], expected.to_le_bytes());
            assert_eq!(&response[4..], &[0xcc; 12]);
        }
        assert_eq!(completed, [true; 4]);
        assert_eq!(used_index, avail_index);
        assert!(read_used(&mem, USED, QUEUE_SIZE, &mut used_index).is_none());
    }
    let state = device.stop_queue(0).await.unwrap();
    assert_eq!(state.avail_index, 20);
    assert_eq!(state.used_index, 20);
    assert!(read_used(&mem, USED, QUEUE_SIZE, &mut used_index).is_none());
}
