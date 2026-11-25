// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Deliver binary RX payloads as multiple backend segments including an empty middle segment into a real virtio receive queue.
// Expected: The guest receives exactly the concatenated bytes, a correct header and used length, unchanged trailing capacity, and can reuse the descriptor for subsequent packets.
#[async_test]
async fn segmented_rx_preserves_exact_payload_and_used_length(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let mut backend = harness.enable_and_get_handle().await;
    *backend.rx_write_mode.lock() = RxWriteMode::Segments;
    for len in [14, 15, 127, 1500] {
        let data: Vec<u8> = (0..len).map(|index| (index * 37) as u8).collect();
        let address = harness.post_rx_buffer_and_signal(0, (header_size() + len + 32) as u32);
        harness
            .mem
            .write_at(address, &vec![0xcc; header_size() + len + 32])
            .unwrap();
        backend.wait_for_rx_pending().await;
        let info = backend.rx_buffer_info.lock().pop().unwrap();
        assert_eq!(info.id.0, 0);
        assert_eq!(info.capacity, (len + 32) as u32);
        assert_eq!(
            info.segments,
            vec![(address, (header_size() + len + 32) as u32)]
        );
        assert_eq!(info.prefix, Some(0xcc));
        backend.inject_rx_packet(&data);
        assert_eq!(
            harness.wait_for_rx_used().await,
            (0, (header_size() + len) as u32)
        );
        let mut bytes = vec![0; header_size() + len + 32];
        harness.mem.read_at(address, &mut bytes).unwrap();
        assert_eq!(&bytes[header_size()..header_size() + len], data);
        assert_eq!(&bytes[header_size() + len..], &[0xcc; 32]);
        let header = VirtioNetHeader::read_from_prefix(&bytes).unwrap().0;
        assert_eq!(header.flags, 0);
        assert_eq!(header.gso_type, 0);
        assert_eq!(header.num_buffers, 1);
    }
    harness.disable().await;
}

// Test: Receive segmented packets with inconsistent metadata lengths or payloads exceeding guest capacity, followed by a valid packet on the same descriptor.
// Expected: Invalid packets publish a zero-length completion without changing guest bytes; a subsequent valid packet succeeds without inheriting the prior drop state.
#[async_test]
async fn segmented_rx_rejects_bad_lengths_without_writes_and_recovers(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let mut backend = harness.enable_and_get_handle().await;
    for mode in [RxWriteMode::Packet, RxWriteMode::Segments] {
        *backend.rx_write_mode.lock() = mode;
        for (data_len, reported_len) in [(31, 32), (31, 0), (65, 65), (64, 64)] {
            let address = harness.post_rx_buffer_and_signal(0, (header_size() + 64) as u32);
            harness
                .mem
                .write_at(address, &vec![0xcc; header_size() + 64])
                .unwrap();
            backend.wait_for_rx_pending().await;
            backend.inject_rx_packet_with_metadata(
                &vec![0x81; data_len],
                &RxMetadata {
                    offset: 0,
                    len: reported_len,
                    ..Default::default()
                },
            );
            let valid = data_len == 64;
            assert_eq!(
                harness.wait_for_rx_used().await,
                (
                    0,
                    if valid {
                        (header_size() + 64) as u32
                    } else {
                        0
                    }
                )
            );
            let mut bytes = vec![0; header_size() + 64];
            harness.mem.read_at(address, &mut bytes).unwrap();
            if valid {
                assert_eq!(&bytes[header_size()..], &[0x81; 64]);
            } else {
                assert_eq!(bytes, vec![0xcc; header_size() + 64]);
            }
        }
    }
    harness.disable().await;
}

// Test: Provide RX descriptor chains whose header or payload points immediately beyond guest memory, using both contiguous and segmented backend writes.
// Expected: Neither fault is reported as a successful receive; payload failure leaves the valid header untouched, and header failure does not invalidate safely written payload bytes.
#[async_test]
async fn rx_memory_faults_never_publish_successful_packets(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let mut backend = harness.enable_and_get_handle().await;
    for mode in [RxWriteMode::Packet, RxWriteMode::Segments] {
        *backend.rx_write_mode.lock() = mode;
        for bad_header in [false, true] {
            let valid = harness.alloc_data(256);
            harness.mem.write_at(valid, &[0xcc; 256]).unwrap();
            let invalid = TOTAL_MEM_SIZE as u64;
            let header = if bad_header { invalid } else { valid };
            let payload = if bad_header { valid } else { invalid };
            write_descriptor(
                &harness.mem,
                RX_DESC_ADDR,
                0,
                header,
                header_size() as u32,
                DescriptorFlags::new().with_write(true).with_next(true),
                1,
            );
            write_descriptor(
                &harness.mem,
                RX_DESC_ADDR,
                1,
                payload,
                128,
                DescriptorFlags::new().with_write(true),
                0,
            );
            make_available(
                &harness.mem,
                RX_AVAIL_ADDR,
                QUEUE_SIZE,
                0,
                &mut harness.rx_avail_idx,
            );
            harness.rx_event.signal();
            backend.wait_for_rx_pending().await;
            backend.inject_rx_packet(&[0x81; 128]);
            assert_eq!(harness.wait_for_rx_used().await, (0, 0));
            let mut bytes = vec![0; if bad_header { 128 } else { header_size() }];
            harness.mem.read_at(valid, &mut bytes).unwrap();
            assert_eq!(
                bytes,
                vec![if bad_header { 0x81 } else { 0xcc }; bytes.len()]
            );
        }
    }
    harness.disable().await;
}

// Test: Report an RX descriptor complete without writing a packet, then reuse it with a normal backend write.
// Expected: Incomplete work returns zero used length and unchanged bytes, while the replacement packet receives a normal length and exact payload.
#[async_test]
async fn incomplete_rx_is_dropped_and_descriptor_can_be_reused(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let mut backend = harness.enable_and_get_handle().await;
    for complete in [false, true] {
        *backend.rx_write_mode.lock() = if complete {
            RxWriteMode::Packet
        } else {
            RxWriteMode::Incomplete
        };
        let address = harness.post_rx_buffer_and_signal(0, (header_size() + 64) as u32);
        harness
            .mem
            .write_at(address, &vec![0xcc; header_size() + 64])
            .unwrap();
        backend.wait_for_rx_pending().await;
        backend.inject_rx_packet(&[0x72; 64]);
        assert_eq!(
            harness.wait_for_rx_used().await,
            (
                0,
                if complete {
                    (header_size() + 64) as u32
                } else {
                    0
                }
            )
        );
        let mut bytes = vec![0; header_size() + 64];
        harness.mem.read_at(address, &mut bytes).unwrap();
        if complete {
            assert_eq!(&bytes[header_size()..], &[0x72; 64]);
        } else {
            assert_eq!(bytes, vec![0xcc; header_size() + 64]);
        }
    }
    harness.disable().await;
}
