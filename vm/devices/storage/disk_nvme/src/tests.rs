// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Translate NVMe command errors that require distinct disk outcomes.
// Expected: Reservation, argument, LBA and preemption errors keep their precise
//       classifications instead of becoming generic IO or medium errors.
#[test]
fn command_statuses_preserve_disk_error_classification() {
    assert!(matches!(
        map_nvme_error(nvme_driver::RequestError::Nvme(
            Status::RESERVATION_CONFLICT.into()
        )),
        DiskError::ReservationConflict
    ));
    assert!(matches!(
        map_nvme_error(nvme_driver::RequestError::Nvme(
            Status::INVALID_FIELD_IN_COMMAND.into()
        )),
        DiskError::InvalidInput
    ));
    assert!(matches!(
        map_nvme_error(nvme_driver::RequestError::Nvme(
            Status::LBA_OUT_OF_RANGE.into()
        )),
        DiskError::IllegalBlock
    ));
    assert!(matches!(
        map_nvme_error(nvme_driver::RequestError::Nvme(
            Status::COMMAND_ABORTED_DUE_TO_PREEMPT_AND_ABORT.into()
        )),
        DiskError::AbortDueToPreemptAndAbort
    ));
}

// Test: Translate each media fault used to produce SCSI medium-error details.
// Expected: Write, read, guard, application-tag and reference-tag failures keep
//       distinct sense details and the original NVMe error context.
#[test]
fn media_statuses_preserve_specific_sense_details_and_source() {
    for (status, expected) in [
        (Status::MEDIA_WRITE_FAULT, MediumErrorDetails::WriteFault),
        (
            Status::MEDIA_UNRECOVERED_READ_ERROR,
            MediumErrorDetails::UnrecoveredReadError,
        ),
        (
            Status::MEDIA_END_TO_END_GUARD_CHECK_ERROR,
            MediumErrorDetails::GuardCheckFailed,
        ),
        (
            Status::MEDIA_END_TO_END_APPLICATION_TAG_CHECK_ERROR,
            MediumErrorDetails::ApplicationTagCheckFailed,
        ),
        (
            Status::MEDIA_END_TO_END_REFERENCE_TAG_CHECK_ERROR,
            MediumErrorDetails::ReferenceTagCheckFailed,
        ),
    ] {
        let request = nvme_driver::RequestError::Nvme(status.into());
        let original = match &request {
            nvme_driver::RequestError::Nvme(error) => error.to_string(),
            _ => unreachable!(),
        };
        let DiskError::MediumError(error, detail) = map_nvme_error(request) else {
            panic!("media error lost its sense classification");
        };
        assert_eq!(
            std::mem::discriminant(&detail),
            std::mem::discriminant(&expected)
        );
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.get_ref().unwrap().to_string(), original);
    }
}

// Test: Translate transfer, capacity, unknown-status and oversized-request errors.
// Expected: Generic NVMe failures retain their source; oversized requests remain
//       InvalidInput IO errors with a typed TooLarge cause.
#[test]
fn generic_and_oversized_errors_preserve_io_kind_and_source() {
    for status in [
        Status::DATA_TRANSFER_ERROR,
        Status::CAPACITY_EXCEEDED,
        Status(0x7ff),
    ] {
        let request = nvme_driver::RequestError::Nvme(status.into());
        let original = match &request {
            nvme_driver::RequestError::Nvme(error) => error.to_string(),
            _ => unreachable!(),
        };
        let DiskError::Io(error) = map_nvme_error(request) else {
            panic!("generic NVMe failure changed classification");
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.get_ref().unwrap().to_string(), original);
    }
    let DiskError::Io(error) = map_nvme_error(nvme_driver::RequestError::TooLarge) else {
        panic!("oversized request lost its IO error");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(matches!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<nvme_driver::RequestError>(),
        Some(nvme_driver::RequestError::TooLarge)
    ));
}

enum PayloadAccess {
    Dma,
    Bounce,
}

async fn new_emulated_disk(
    driver: pal_async::DefaultDriver,
    access: PayloadAccess,
) -> (
    nvme_driver::NvmeDriver<impl user_driver::DeviceBacking>,
    NvmeDisk,
    disk_backend::Disk,
    user_driver_emulated_mock::DeviceTestMemory,
) {
    use chipset_device::mmio::ExternallyManagedMmioIntercepts;
    use disk_backend::Disk;
    use disk_prwrap::DiskWithReservations;
    use guid::Guid;
    use nvme::NvmeControllerCaps;
    use nvme_driver::NvmeDriver;
    use pci_core::bus_range::AssignedBusRange;
    use pci_core::dma::DmaTarget;
    use pci_core::msi::MsiConnection;
    use user_driver_emulated_mock::DeviceTestMemory;
    use user_driver_emulated_mock::EmulatedDevice;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    let allow_dma = matches!(access, PayloadAccess::Dma);
    let memory = DeviceTestMemory::new(2048, allow_dma, "disk-nvme-backend");
    let guest_memory = memory.guest_memory();
    let source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let msi = MsiConnection::new();
    let dma = DmaTarget::new(AssignedBusRange::new(), 0, guest_memory, &msi);
    let controller = nvme::NvmeController::new(
        &source,
        &dma,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: 2,
            max_io_queues: 64,
            subsystem_id: Guid::new_random(),
        },
    );
    let backing = Disk::new(DiskWithReservations::new(
        disklayer_ram::ram_disk(2 << 20, false).unwrap(),
    ))
    .unwrap();
    controller
        .client()
        .add_namespace(1, backing.clone())
        .await
        .unwrap();
    let device = EmulatedDevice::new(controller, msi, memory.dma_client());
    let bounce_buffer = !allow_dma;
    let fused_keepalive_device = false;
    let mut driver = NvmeDriver::new(&source, 64, device, bounce_buffer, fused_keepalive_device)
        .await
        .unwrap();
    let namespace = driver.namespace(1).await.unwrap();
    let disk = NvmeDisk::new(namespace);
    (driver, disk, backing, memory)
}

// Test: Use the real driver over an owned NVMe controller and RAM disk to transfer
//       beyond the configured transfer limit with DMA and bounce buffering,
//       deallocate blocks and update persistent reservations.
// Expected: Independent backing IO verifies data and untouched neighbors; reads,
//       deallocation, reservation state and closed-queue errors remain correct.
#[pal_async::async_test]
async fn emulated_disk_preserves_split_io_and_reservation_state(driver: pal_async::DefaultDriver) {
    use scsi_buffers::OwnedRequestBuffers;

    for access in [PayloadAccess::Dma, PayloadAccess::Bounce] {
        let (driver, disk, backing, memory) = new_emulated_disk(driver.clone(), access).await;
        let payload = memory.payload_mem();
        let block_count = u64::from(disk.namespace.max_transfer_block_count()) + 3;
        let sector_size = disk.sector_size() as usize;
        let length = block_count as usize * sector_size;
        assert!(length + 2 * sector_size <= 4 << 20);
        assert!(17 + block_count < disk.sector_count());
        let buffers = OwnedRequestBuffers::linear(0, length, true);
        let expected: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        payload.write_at(0, &expected).unwrap();
        disk.write_vectored(&buffers.buffer(&payload), 17, true)
            .await
            .unwrap();
        disk.sync_cache().await.unwrap();

        // A separate backend oracle prevents matching read/write offset bugs from cancelling.
        let guard_buffers = OwnedRequestBuffers::linear(0, length + 2 * sector_size, true);
        backing
            .read_vectored(&guard_buffers.buffer(&payload), 16)
            .await
            .unwrap();
        let mut actual = vec![0; length + 2 * sector_size];
        payload.read_at(0, &mut actual).unwrap();
        assert!(actual[..sector_size].iter().all(|&byte| byte == 0));
        assert_eq!(&actual[sector_size..sector_size + length], expected);
        assert!(actual[sector_size + length..].iter().all(|&byte| byte == 0));

        let replacement: Vec<_> = (0..length).map(|i| 255 - (i % 251) as u8).collect();
        payload.write_at(0, &replacement).unwrap();
        backing
            .write_vectored(&buffers.buffer(&payload), 17, false)
            .await
            .unwrap();
        payload.write_at(0, &vec![0; length]).unwrap();
        disk.read_vectored(&buffers.buffer(&payload), 17)
            .await
            .unwrap();
        actual.resize(length, 0);
        payload.read_at(0, &mut actual).unwrap();
        assert_eq!(actual, replacement);

        disk.unmap(19, 3, false).await.unwrap();
        backing
            .read_vectored(&buffers.buffer(&payload), 17)
            .await
            .unwrap();
        payload.read_at(0, &mut actual).unwrap();
        let mut deallocated = replacement;
        deallocated[2 * sector_size..5 * sector_size].fill(0);
        assert_eq!(actual, deallocated);

        let reservations = disk.pr().expect("reservation-capable namespace");
        reservations
            .register(None, 0x1234, Some(true))
            .await
            .unwrap();
        let report = reservations.report().await.unwrap();
        assert_eq!(report.controllers.len(), 1);
        assert_eq!(report.controllers[0].key, 0x1234);
        assert!(
            backing
                .pr()
                .unwrap()
                .report()
                .await
                .unwrap()
                .persist_through_power_loss,
            "SET power-loss persistence must reach the backend"
        );
        assert!(!report.controllers[0].holds_reservation);
        let reservation_type = pr::ReservationType::WriteExclusive;
        reservations
            .reserve(0x1234, reservation_type)
            .await
            .unwrap();
        let report = reservations.report().await.unwrap();
        assert_eq!(report.reservation_type, Some(reservation_type));
        assert!(report.controllers[0].holds_reservation);
        reservations
            .release(0x1234, reservation_type)
            .await
            .unwrap();
        assert!(
            reservations
                .report()
                .await
                .unwrap()
                .reservation_type
                .is_none()
        );
        assert!(matches!(
            reservations.register(Some(0x7777), 0x5678, None).await,
            Err(DiskError::ReservationConflict)
        ));
        reservations
            .register(Some(0x1234), 0x5678, None)
            .await
            .unwrap();
        let report = reservations.report().await.unwrap();
        assert_eq!(report.controllers[0].key, 0x5678);
        assert!(
            backing
                .pr()
                .unwrap()
                .report()
                .await
                .unwrap()
                .persist_through_power_loss,
            "None must preserve backend power-loss persistence"
        );
        reservations.register(Some(0x5678), 0, None).await.unwrap();
        assert!(reservations.report().await.unwrap().controllers.is_empty());
        reservations.register(None, 0xabcd, None).await.unwrap();
        reservations.clear(0xabcd).await.unwrap();
        assert!(reservations.report().await.unwrap().controllers.is_empty());

        driver.shutdown().await;
        let DiskError::Io(error) = disk.sync_cache().await.unwrap_err() else {
            panic!("closed queue lost its IO error");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(matches!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<nvme_driver::RequestError>(),
            Some(nvme_driver::RequestError::Gone(_))
        ));
    }
}

// IGNORED: entry309-bug1. The virtual NVMe controller hardcodes PTPLS to zero
//       when serializing reservation reports, even after setting backend PTPL.
//
// Test: Set power-loss persistence and compare the backend with its NVMe report.
// Expected: Both reports retain the enabled state rather than losing it across
//       the NVMe reservation-report serialization boundary.
#[pal_async::async_test]
#[ignore = "entry309-bug1: virtual NVMe reservation report drops PTPL state"]
async fn reservation_report_preserves_power_loss_persistence(driver: pal_async::DefaultDriver) {
    let (driver, disk, backing, _memory) = new_emulated_disk(driver, PayloadAccess::Dma).await;
    disk.pr()
        .unwrap()
        .register(None, 0x1234, Some(true))
        .await
        .unwrap();
    let backend_enabled = backing
        .pr()
        .unwrap()
        .report()
        .await
        .unwrap()
        .persist_through_power_loss;
    let reported_enabled = disk
        .pr()
        .unwrap()
        .report()
        .await
        .unwrap()
        .persist_through_power_loss;
    driver.shutdown().await;
    assert!(backend_enabled, "fixture did not enable backend PTPL");
    assert!(reported_enabled, "NVMe report lost enabled PTPL");
}
