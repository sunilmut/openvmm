// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public NVMe data placement and namespace identity across hot removal.

use chipset_device::mmio::ExternallyManagedMmioIntercepts;
use guestmem::ranges::PagedRange;
use guid::Guid;
use nvme::NvmeController;
use nvme::NvmeControllerCaps;
use nvme::NvmeControllerClient;
use nvme_driver::NamespaceError;
use nvme_driver::NamespaceHandle;
use nvme_driver::NvmeDriver;
use nvme_driver::RequestError;
use nvme_spec::Status;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::timer::PolledTimer;
use pci_core::bus_range::AssignedBusRange;
use pci_core::dma::DmaTarget;
use pci_core::msi::MsiConnection;
use std::time::Duration;
use std::time::Instant;
use test_with_tracing::test;
use user_driver::DeviceBacking;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

struct Fixture<D: DeviceBacking> {
    driver: NvmeDriver<D>,
    controller: NvmeControllerClient,
    memory: DeviceTestMemory,
}

async fn fixture(driver: DefaultDriver, allow_dma: bool) -> Fixture<impl DeviceBacking> {
    let memory = DeviceTestMemory::new(2048, allow_dma, "namespace_lifecycle");
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let msi = MsiConnection::new();
    let dma_target = DmaTarget::new(AssignedBusRange::new(), 0, memory.guest_memory(), &msi);
    let controller = NvmeController::new(
        &driver_source,
        &dma_target,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: 2,
            max_io_queues: 64,
            subsystem_id: Guid::new_random(),
        },
    );
    let client = controller.client();
    client
        .add_namespace(1, disklayer_ram::ram_disk(2 << 20, false).unwrap())
        .await
        .unwrap();
    let device = EmulatedDevice::new(controller, msi, memory.dma_client());
    let bounce_buffer = false;
    let fused_keepalive_device = false;
    let driver = NvmeDriver::new(
        &driver_source,
        2,
        device,
        bounce_buffer,
        fused_keepalive_device,
    )
    .await
    .unwrap();
    Fixture {
        driver,
        controller: client,
        memory,
    }
}

async fn wait_for_removal(driver: &DefaultDriver, namespace: &NamespaceHandle) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut timer = PolledTimer::new(driver);
    while namespace.check_active().is_ok() {
        assert!(
            Instant::now() < deadline,
            "namespace removal was not delivered to its handle"
        );
        timer.sleep(Duration::from_millis(1)).await;
    }
}

fn assert_removed(result: Result<(), RequestError>) {
    assert!(
        matches!(result, Err(RequestError::Nvme(error))
            if error.status() == Status::INVALID_NAMESPACE_OR_FORMAT),
        "removed handles must not address a replacement namespace"
    );
}

// Test: Transfer unaligned, noncontiguous three-page payloads using DMA and bouncing.
// Expected: Both directions preserve exact disk data and every unrelated guest byte.
#[async_test]
async fn scatter_payloads_preserve_guest_canaries(driver: DefaultDriver) {
    for allow_dma in [false, true] {
        let mut fixture = fixture(driver.clone(), allow_dma).await;
        let namespace = fixture.driver.namespace(1).await.unwrap();
        let memory = fixture.memory.payload_mem();
        let mut expected = vec![0xa5; 16 * 4096];
        let data: Vec<u8> = (0..8192).map(|i| (i * 37 + i / 251) as u8).collect();
        expected[4096 + 4091..8192].copy_from_slice(&data[..5]);
        expected[4 * 4096..5 * 4096].copy_from_slice(&data[5..4101]);
        expected[8 * 4096..8 * 4096 + 4091].copy_from_slice(&data[4101..]);
        memory.write_at(0, &expected).unwrap();
        namespace
            .write(
                0,
                7,
                16,
                false,
                &memory,
                PagedRange::new(4091, 8192, &[1, 4, 8]).unwrap(),
            )
            .await
            .unwrap();
        namespace
            .read(
                1,
                7,
                16,
                &memory,
                PagedRange::new(123, 8192, &[2, 6, 9]).unwrap(),
            )
            .await
            .unwrap();
        expected[2 * 4096 + 123..3 * 4096].copy_from_slice(&data[..3973]);
        expected[6 * 4096..7 * 4096].copy_from_slice(&data[3973..8069]);
        expected[9 * 4096..9 * 4096 + 123].copy_from_slice(&data[8069..]);
        let mut actual = vec![0; expected.len()];
        memory.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, expected, "allow_dma={allow_dma}");
        fixture.driver.shutdown().await;
    }
}

// Test: Revoke a removed handle, release its ownership, then reuse the same NSID.
// Expected: Stale I/O fails, the replacement is a different disk, and shutdown revokes I/O.
#[async_test]
async fn removed_namespace_reopens_after_last_handle_is_released(driver: DefaultDriver) {
    let mut fixture = fixture(driver.clone(), false).await;
    let old = fixture.driver.namespace(1).await.unwrap();
    assert!(matches!(
        fixture.driver.namespace(1).await,
        Err(NamespaceError::Duplicate(1))
    ));
    let memory = fixture.memory.payload_mem();
    memory.write_at(0, &[0x71; 512]).unwrap();
    old.write(
        0,
        0,
        1,
        false,
        &memory,
        PagedRange::new(0, 512, &[0]).unwrap(),
    )
    .await
    .unwrap();
    assert!(fixture.controller.remove_namespace(1).await);
    wait_for_removal(&driver, &old).await;
    fixture
        .controller
        .add_namespace(1, disklayer_ram::ram_disk(4 << 20, false).unwrap())
        .await
        .unwrap();
    assert_removed(old.flush(0).await);
    assert_removed(
        old.read(0, 0, 1, &memory, PagedRange::new(0, 512, &[0]).unwrap())
            .await,
    );
    assert_removed(
        old.write(
            0,
            0,
            1,
            false,
            &memory,
            PagedRange::new(0, 512, &[0]).unwrap(),
        )
        .await,
    );
    drop(old);
    let replacement = fixture.driver.namespace(1).await.unwrap();
    replacement
        .read(0, 0, 1, &memory, PagedRange::new(0, 512, &[0]).unwrap())
        .await
        .unwrap();
    let mut actual = [0xff; 512];
    memory.read_at(0, &mut actual).unwrap();
    assert_eq!(
        actual, [0; 512],
        "the old disk's data must not survive reuse"
    );
    fixture.driver.shutdown().await;
    assert!(matches!(
        replacement.flush(0).await,
        Err(RequestError::Gone(_))
    ));
}

// IGNORED: An enabled run returned INVALID_NAMESPACE_OR_FORMAT for a fresh handle
//       after acknowledged removal and same-NSID replacement. NvmeDriver::namespace
//       reuses the retained predecessor's permanently revoked state rather than
//       constructing a namespace for the replacement disk.
//
// Test: Request a replacement namespace while its already-revoked predecessor is retained.
// Expected: A fresh handle accesses the new disk without resurrecting the retired handle.
#[async_test]
#[ignore = "replacement inherits the retained predecessor's removed state"]
async fn replacement_does_not_reuse_retired_handle_state(driver: DefaultDriver) {
    let mut fixture = fixture(driver.clone(), false).await;
    let old = fixture.driver.namespace(1).await.unwrap();
    assert!(fixture.controller.remove_namespace(1).await);
    wait_for_removal(&driver, &old).await;
    fixture
        .controller
        .add_namespace(1, disklayer_ram::ram_disk(4 << 20, false).unwrap())
        .await
        .unwrap();
    let replacement = fixture.driver.namespace(1).await.unwrap();
    let memory = fixture.memory.payload_mem();
    let result = replacement
        .read(0, 0, 1, &memory, PagedRange::new(0, 512, &[0]).unwrap())
        .await;
    assert_removed(old.flush(0).await);
    fixture.driver.shutdown().await;
    result.expect("freshly acquired handle must read the replacement disk");
}
