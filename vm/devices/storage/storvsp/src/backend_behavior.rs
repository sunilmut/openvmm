// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use scsi_core::ScsiSaveRestore;
use scsi_core::save_restore::{ScsiDiskSavedState, ScsiSavedState};
use stackfuture::StackFuture;
use test_with_tracing::test;

#[derive(Default)]
struct Gate {
    entered: event_listener::Event,
    release: event_listener::Event,
}

#[derive(Inspect)]
struct Backend {
    #[inspect(skip)]
    gate: Option<Arc<Gate>>,
    save_supported: bool,
}

impl AsyncScsiDisk for Backend {
    fn execute_scsi<'a>(
        &'a self,
        _: &'a RequestBuffers<'a>,
        request: &'a Request,
    ) -> StackFuture<'a, ScsiResult, { scsi_core::ASYNC_SCSI_DISK_STACK_SIZE }> {
        StackFuture::from(async move {
            if let Some(gate) = &self.gate {
                let release = gate.release.listen();
                gate.entered.notify(1);
                release.await;
            }
            ScsiResult {
                scsi_status: ScsiStatus::GOOD,
                srb_status: SrbStatus(request.cdb[1]),
                tx: 0,
                sense_data: None,
            }
        })
    }
}

impl ScsiSaveRestore for Backend {
    fn save(&self) -> Result<Option<ScsiSavedState>, SaveError> {
        Ok(self
            .save_supported
            .then_some(ScsiSavedState::ScsiDisk(ScsiDiskSavedState {
                sector_count: 2048,
                sense_data: None,
            })))
    }
    fn restore(&self, _: &ScsiSavedState) -> Result<(), RestoreError> {
        Ok(())
    }
}

fn backend_controller(backend: Arc<Backend>) -> ScsiController {
    let controller = ScsiController::new();
    controller
        .attach(ScsiPath::default(), ScsiControllerDisk::new(backend))
        .unwrap();
    controller
}

fn request(status: SrbStatus) -> storvsp_protocol::ScsiRequest {
    let mut request = inquiry(0);
    request.payload = [0; 20];
    request.payload[0] = ScsiOp::TEST_UNIT_READY.0;
    request.payload[1] = status.0;
    request.data_transfer_length = 0;
    request
}

// Test: Complete SCSI requests with the backend's distinct SRB failure statuses.
// Expected: Transaction IDs and SRB statuses are preserved and each guest reply
//       uses the corresponding NTSTATUS, including the generic error case.
#[async_test]
async fn backend_statuses_map_to_guest_error_completions(driver: DefaultDriver) {
    use storvsp_protocol::NtStatus;
    let controller = backend_controller(Arc::new(Backend {
        gate: None,
        save_supported: true,
    }));
    let fixture = Fixture::new(&driver, &controller, GuestMemory::allocate(65536)).await;
    let mut guest = fixture.open(&driver).await;
    for step in 0..4 {
        guest.negotiate_step(step).await;
    }
    for (status, expected) in [
        (SrbStatus::BUSY, NtStatus::DEVICE_BUSY),
        (SrbStatus::NO_DEVICE, NtStatus::DEVICE_DOES_NOT_EXIST),
        (SrbStatus::INVALID_LUN, NtStatus::DEVICE_DOES_NOT_EXIST),
        (
            SrbStatus::INVALID_TARGET_ID,
            NtStatus::DEVICE_DOES_NOT_EXIST,
        ),
        (SrbStatus::NO_HBA, NtStatus::DEVICE_DOES_NOT_EXIST),
        (SrbStatus::TIMEOUT, NtStatus::IO_TIMEOUT),
        (SrbStatus::COMMAND_TIMEOUT, NtStatus::IO_TIMEOUT),
        (SrbStatus::SELECTION_TIMEOUT, NtStatus::DEVICE_NOT_CONNECTED),
        (SrbStatus::BAD_FUNCTION, NtStatus::INVALID_DEVICE_REQUEST),
        (
            SrbStatus::BAD_SRB_BLOCK_LENGTH,
            NtStatus::INVALID_DEVICE_REQUEST,
        ),
        (SrbStatus::DATA_OVERRUN, NtStatus::BUFFER_OVERFLOW),
        (SrbStatus::REQUEST_FLUSHED, NtStatus::UNSUCCESSFUL),
        (SrbStatus::ABORTED, NtStatus::CANCELLED),
        (SrbStatus::ERROR, NtStatus::IO_DEVICE_ERROR),
    ] {
        let (header, reply) = guest.scsi(&request(status), 0).await;
        assert_eq!(header.status, expected);
        assert_eq!(reply.srb_status.status(), status);
        assert!(!reply.srb_status.autosense_valid());
        assert_eq!(reply.scsi_status, ScsiStatus::GOOD);
        assert_eq!(reply.data_transfer_length, 0);
        assert_eq!(reply.payload, [0; 20]);
    }
    drop(guest);
    fixture.finish().await;
}

// Test: Save an in-flight request, restore it into a fresh device and release I/O.
// Expected: A fresh backend completes the original transaction with the full
//       successful reply, then independently completes another request.
#[async_test]
async fn pending_io_survives_device_snapshot_restore(driver: DefaultDriver) {
    let gate = Arc::new(Gate::default());
    let controller = backend_controller(Arc::new(Backend {
        gate: Some(gate.clone()),
        save_supported: true,
    }));
    let memory = GuestMemory::allocate(65536);
    let original = Fixture::new(&driver, &controller, memory.clone()).await;
    let mut guest = original.open(&driver).await;
    for step in 0..4 {
        guest.negotiate_step(step).await;
    }
    let entered = gate.entered.listen();
    let transaction = guest.submit_scsi(&request(SrbStatus::SUCCESS), 0).await;
    bounded(&driver, entered).await;
    original.handle.stop().await;
    let saved = original.handle.save().await.unwrap().unwrap();
    gate.release.notify(usize::MAX);
    drop(guest);
    original.finish().await;

    let restored_gate = Arc::new(Gate::default());
    let restored_controller = backend_controller(Arc::new(Backend {
        gate: Some(restored_gate.clone()),
        save_supported: true,
    }));
    let restored = Fixture::new(&driver, &restored_controller, memory).await;
    let (mut guest, open, gpadl) = restored.rings(&driver);
    *restored.bus.offers.lock()[0].plan.lock() = Some(RestoreResult {
        open_request: Some(open),
        gpadls: vec![RestoredGpadl {
            request: gpadl,
            accepted: true,
        }],
    });
    restored.handle.restore(saved).await.unwrap();
    let entered = restored_gate.entered.listen();
    restored.handle.start();
    bounded(&driver, entered).await;
    restored_gate.release.notify(usize::MAX);
    let (header, payload) = guest.completion(transaction).await;
    assert_eq!(header.status, storvsp_protocol::NtStatus::SUCCESS);
    assert_eq!(payload, successful_completion(0).as_bytes());
    let reply = storvsp_protocol::ScsiRequest::read_from_prefix(&payload)
        .unwrap()
        .0;
    assert_eq!(reply.srb_status.status(), SrbStatus::SUCCESS);
    assert_eq!(reply.scsi_status, ScsiStatus::GOOD);
    assert_eq!(reply.data_transfer_length, 0);
    assert!(!reply.srb_status.autosense_valid());
    assert_eq!(reply.payload, [0; 20]);
    // A new request must progress independently of the restored request.
    let entered = restored_gate.entered.listen();
    let retry = guest.submit_scsi(&request(SrbStatus::SUCCESS), 0).await;
    bounded(&driver, entered).await;
    restored_gate.release.notify(usize::MAX);
    let (header, payload) = guest.completion(retry).await;
    assert_eq!(header.status, storvsp_protocol::NtStatus::SUCCESS);
    assert_eq!(payload, successful_completion(0).as_bytes());
    drop(guest);
    restored.finish().await;
}

// Test: Restore corrupt pending requests and a pending request before negotiation.
// Expected: Oversized CDB payloads, malformed GPA ranges, range length conflicts
//       and premature requests are rejected as invalid saved state.
#[async_test]
async fn pending_request_snapshots_validate_payloads_and_ranges(driver: DefaultDriver) {
    for case in 0..4 {
        let fixture = Fixture::new(&driver, &controller(), GuestMemory::allocate(65536)).await;
        let (_, open, gpadl) = fixture.rings(&driver);
        *fixture.bus.offers.lock()[0].plan.lock() = Some(RestoreResult {
            open_request: Some(open),
            gpadls: vec![RestoredGpadl {
                request: gpadl,
                accepted: true,
            }],
        });
        let mut request = request(SrbStatus::SUCCESS);
        let mut external_data = state::RangeSavedState {
            buf: Vec::new(),
            count: 0,
        };
        let protocol_state = if case == 3 {
            state::ProtocolState::Init(state::InitState::QueryVersion)
        } else {
            state::ProtocolState::Ready {
                version: storvsp_protocol::VERSION_BLUE,
            }
        };
        if case == 1 {
            external_data.count = 1;
        }
        if case == 2 {
            request.data_transfer_length = 512;
        }
        let request = if case == 0 {
            vec![0; 4096]
        } else {
            request.as_bytes().to_vec()
        };
        let saved = state::SavedState {
            protocol_state,
            drives: Vec::new(),
            channels: vec![state::ChannelSavedState {
                channel: Some(state::WorkerSavedState {
                    scsi_requests: vec![state::ScsiRequestSavedState {
                        transaction_id: 17,
                        external_data,
                        request,
                    }],
                }),
            }],
        };
        assert!(
            fixture
                .handle
                .restore(SavedStateBlob::new(saved))
                .await
                .is_err()
        );
        fixture.finish().await;
    }
}

// Test: Save a controller whose backend does not support saving state.
// Expected: Saving returns an explicit error rather than omitting that drive.
#[async_test]
async fn unsupported_backend_snapshot_is_reported(driver: DefaultDriver) {
    let controller = backend_controller(Arc::new(Backend {
        gate: None,
        save_supported: false,
    }));
    let fixture = Fixture::new(&driver, &controller, GuestMemory::allocate(65536)).await;
    assert!(fixture.handle.save().await.is_err());
    fixture.finish().await;
}
