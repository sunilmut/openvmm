// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn queue_resources(harness: &TestHarness, rx: bool) -> QueueResources {
    QueueResources {
        params: QueueParams {
            size: QUEUE_SIZE,
            enable: true,
            desc_addr: if rx { RX_DESC_ADDR } else { TX_DESC_ADDR },
            avail_addr: if rx { RX_AVAIL_ADDR } else { TX_AVAIL_ADDR },
            used_addr: if rx { RX_USED_ADDR } else { TX_USED_ADDR },
        },
        notify: Interrupt::from_event(if rx {
            harness.rx_interrupt_event.clone()
        } else {
            harness.tx_interrupt_event.clone()
        }),
        event: if rx {
            harness.rx_event.clone()
        } else {
            harness.tx_event.clone()
        },
        guest_memory: harness.mem.clone(),
    }
}

// Test: Read the guest configuration words for a distinct MAC address and endpoint speed, attempt writes to each word, and probe unsupported offsets.
// Expected: Configuration follows the virtio-net little-endian wire layout, advertises one queue pair and 1500-byte MTU with link-up/unknown-duplex state, ignores writes, and returns zero for unsupported offsets.
#[async_test]
async fn configuration_register_abi_is_exact_and_read_only(driver: DefaultDriver) {
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut device = Device::builder()
        .build(
            &driver_source,
            Box::new(MockEndpointWithTxOffloads {
                offloads: TxOffloadSupport::default(),
                link_speed: 12_345 * BITS_PER_MEGABIT,
            }),
            MacAddress::new([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        )
        .unwrap();
    let expected = [0x7856_3412, 0x0001_bc9a, (1500 << 16) | 1, 12_345, 0xff, 0];
    for (index, word) in expected.into_iter().enumerate() {
        let offset = index as u16 * 4;
        assert_eq!(device.read_registers_u32(offset).await, word);
        device.write_registers_u32(offset, !word).await;
        assert_eq!(device.read_registers_u32(offset).await, word);
    }
    for offset in [1, 2, 3, 6, 24, 28, u16::MAX] {
        assert_eq!(device.read_registers_u32(offset).await, 0);
        device.write_registers_u32(offset, u32::MAX).await;
        assert_eq!(device.read_registers_u32(offset).await, 0);
    }
}

// Test: Start TX before RX, reject duplicate half-open/active queues, stop the unopened RX half, then complete the pair and receive a packet before restarting it.
// Expected: Invalid lifecycle operations report specific errors without discarding the accepted TX half, RX still completes correctly, and stopping/restarting the active pair creates another functional backend queue.
#[async_test]
async fn tx_first_queue_pair_survives_duplicate_and_unopened_stop(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let features = VirtioDeviceFeatures::new();
    harness
        .device
        .start_queue(1, queue_resources(&harness, false), &features, None)
        .await
        .unwrap();
    let error = harness
        .device
        .start_queue(1, queue_resources(&harness, false), &features, None)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "duplicate TX queue for pair 0");
    assert!(harness.device.stop_queue(0).await.is_none());
    harness
        .device
        .start_queue(0, queue_resources(&harness, true), &features, None)
        .await
        .unwrap();
    let mut backend = harness.wait_for_recreated_queue().await;
    let error = harness
        .device
        .start_queue(1, queue_resources(&harness, false), &features, None)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "queue pair 0 already active");
    let address = harness.post_rx_buffer_and_signal(0, (header_size() + 64) as u32);
    backend.wait_for_rx_pending().await;
    backend.inject_rx_packet(&[0x91; 64]);
    assert_eq!(
        harness.wait_for_rx_used().await,
        (0, (header_size() + 64) as u32)
    );
    let mut bytes = [0; 64];
    harness
        .mem
        .read_at(address + header_size() as u64, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0x91; 64]);
    assert!(harness.device.stop_queue(1).await.is_none());
    harness.rx_avail_idx = 0;
    harness.rx_used_idx = 0;
    init_avail_ring(&harness.mem, RX_AVAIL_ADDR);
    init_used_ring(&harness.mem, RX_USED_ADDR);
    let mut restarted = harness.enable_and_get_handle().await;
    let address = harness.post_rx_buffer_and_signal(0, (header_size() + 64) as u32);
    restarted.wait_for_rx_pending().await;
    restarted.inject_rx_packet(&[0x27; 64]);
    assert_eq!(
        harness.wait_for_rx_used().await,
        (0, (header_size() + 64) as u32)
    );
    harness
        .mem
        .read_at(address + header_size() as u64, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0x27; 64]);
    harness.disable().await;
}
