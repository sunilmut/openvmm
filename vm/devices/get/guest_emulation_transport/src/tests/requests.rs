// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::setup;
use get_protocol as p;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Map and unmap a framebuffer with success, failure, and unknown host statuses.
// Expected: The requested GPA reaches the host and only SUCCESS is accepted;
//       failures do not prevent subsequent requests on the same connection.
#[async_test]
async fn framebuffer_requests_preserve_addresses_and_host_failures(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    for status in [0, 1, 99] {
        let result = host
            .exchange(
                client.map_framebuffer(0x1234_5000),
                p::MapFramebufferRequest::new(0x1234_5000).as_bytes(),
                p::MapFramebufferResponse::new(p::MapFramebufferStatus(status)).as_bytes(),
            )
            .await;
        assert_eq!(result.is_ok(), status == 0);
        let result = host
            .exchange(
                client.unmap_framebuffer(),
                p::UnmapFramebufferRequest::new().as_bytes(),
                p::UnmapFramebufferResponse::new(p::UnmapFramebufferStatus(status)).as_bytes(),
            )
            .await;
        assert_eq!(result.is_ok(), status == 0);
    }
}

// Test: Read and write proxied VGA PCI registers and create/reset a host RAM range.
// Expected: Offsets, values, slot, addresses and ROM flags reach the wire intact;
//       readback and the returned range handle identify the requested resources.
#[async_test]
async fn vga_and_ram_range_requests_preserve_wire_parameters(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let read = host
        .exchange(
            client.vga_proxy_pci_read(0x123),
            p::VgaProxyPciReadRequest::new(0x123).as_bytes(),
            p::VgaProxyPciReadResponse::new(0xdead_beef).as_bytes(),
        )
        .await;
    assert_eq!(read, 0xdead_beef);
    host.exchange(
        client.vga_proxy_pci_write(0x44, 0x8765_4321),
        p::VgaProxyPciWriteRequest::new(0x44, 0x8765_4321).as_bytes(),
        p::VgaProxyPciWriteResponse::new().as_bytes(),
    )
    .await;
    let flags = p::CreateRamGpaRangeFlags::new().with_rom_mb(true);
    let handle = host
        .exchange(
            client.create_ram_gpa_range(7, 0x1000, 4, 2, flags),
            p::CreateRamGpaRangeRequest::new(7, 0x1000, 4, 2, flags).as_bytes(),
            p::CreateRamGpaRangeResponse::new(p::CreateRamGpaRangeStatus::SUCCESS).as_bytes(),
        )
        .await
        .unwrap();
    host.exchange(
        client.reset_ram_gpa_range(handle),
        p::ResetRamGpaRangeRequest::new(7).as_bytes(),
        p::ResetRamGpaRangeResponse::new().as_bytes(),
    )
    .await;
}

// Test: Reject RAM-range creation and firmware loading at the host.
// Expected: Non-success statuses are surfaced as errors, and a later successful
//       firmware load returns the host-specified 64-bit entry offset.
#[async_test]
async fn ram_and_firmware_failures_are_reported_without_poisoning_transport(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let flags = p::CreateRamGpaRangeFlags::new();
    assert!(
        host.exchange(
            client.create_ram_gpa_range(9, 0x1000, 2, 0, flags),
            p::CreateRamGpaRangeRequest::new(9, 0x1000, 2, 0, flags).as_bytes(),
            p::CreateRamGpaRangeResponse::new(p::CreateRamGpaRangeStatus::SLOT_OCCUPIED).as_bytes()
        )
        .await
        .is_err()
    );
    for status in [p::LoadFirmwareStatus(99), p::LoadFirmwareStatus::SUCCESS] {
        let result = host
            .exchange(
                client.load_firmware(0x9876_5432),
                p::LoadFirmwareRequest::new(0x9876_5432).as_bytes(),
                p::LoadFirmwareResponse::new(status, 0x1_2345_6789).as_bytes(),
            )
            .await;
        if status == p::LoadFirmwareStatus::SUCCESS {
            assert_eq!(result.unwrap(), 0x1_2345_6789);
        } else {
            assert!(result.is_err());
        }
    }
}

// Test: Have the host reject VPCI offer, revoke, and binding changes.
// Expected: Each request retains its bus ID and operation, and each failure
//       is returned to the caller rather than reported as success.
#[async_test]
async fn vpci_control_failures_retain_bus_and_operation(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let id = guid::Guid::new_random();
    assert!(
        host.exchange(
            client.offer_vpci_device(id),
            p::VpciDeviceControlRequest::new(p::VpciDeviceControlCode::OFFER, id).as_bytes(),
            p::VpciDeviceControlResponse::new(p::VpciDeviceControlStatus::DEVICE_NOT_FOUND)
                .as_bytes()
        )
        .await
        .is_err()
    );
    assert!(
        host.exchange(
            client.revoke_vpci_device(id),
            p::VpciDeviceControlRequest::new(p::VpciDeviceControlCode::REVOKE, id).as_bytes(),
            p::VpciDeviceControlResponse::new(p::VpciDeviceControlStatus::INVALID_DEVICE_STATE)
                .as_bytes()
        )
        .await
        .is_err()
    );
    assert!(
        host.exchange(
            client.report_vpci_device_binding_state(id, true),
            p::VpciDeviceBindingChangeRequest::new(id, true).as_bytes(),
            p::VpciDeviceBindingChangeResponse::new(
                id,
                p::VpciDeviceControlStatus::GENERIC_FAILURE
            )
            .as_bytes()
        )
        .await
        .is_err()
    );
}

// Test: Receive VMGS metadata larger than the transport supports, then host IO errors.
// Expected: Transfer size is clamped, geometry is retained, and failed info,
//       flush, read, and write operations are returned as errors.
#[async_test]
async fn vmgs_limits_and_host_io_failures_are_observable(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let info = host
        .exchange(
            client.vmgs_get_device_info(),
            p::VmgsGetDeviceInfoRequest::new().as_bytes(),
            p::VmgsGetDeviceInfoResponse::new(p::VmgsIoStatus::SUCCESS, 1024, 512, 4096, u32::MAX)
                .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(info.capacity, 1024);
    assert_eq!(info.bytes_per_logical_sector, 512);
    assert_eq!(info.bytes_per_physical_sector, 4096);
    assert_eq!(info.maximum_transfer_size_bytes, p::MAX_PAYLOAD_SIZE as u32);
    let failure = p::VmgsIoStatus(99);
    assert!(
        host.exchange(
            client.vmgs_get_device_info(),
            p::VmgsGetDeviceInfoRequest::new().as_bytes(),
            p::VmgsGetDeviceInfoResponse::new(failure, 0, 0, 0, 0).as_bytes()
        )
        .await
        .is_err()
    );
    assert!(
        host.exchange(
            client.vmgs_flush(),
            p::VmgsFlushRequest::new().as_bytes(),
            p::VmgsFlushResponse::new(failure).as_bytes()
        )
        .await
        .is_err()
    );
    assert!(
        host.exchange(
            client.vmgs_read(17, 1, 512),
            p::VmgsReadRequest::new(p::VmgsReadFlags::NONE, 17, 1).as_bytes(),
            p::VmgsReadResponse::new(failure).as_bytes()
        )
        .await
        .is_err()
    );
    let payload = vec![0x5a; 512];
    let request = [
        p::VmgsWriteRequest::new(p::VmgsWriteFlags::NONE, 19, 1).as_bytes(),
        &payload,
    ]
    .concat();
    assert!(
        host.exchange(
            client.vmgs_write(19, payload, 512),
            &request,
            p::VmgsWriteResponse::new(failure).as_bytes()
        )
        .await
        .is_err()
    );
}
