// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use disk_backend::DiskError;
use disk_backend::pr::{
    PersistentReservation, RegisteredController, ReservationCapabilities, ReservationReport,
    ReservationType,
};
use disk_prwrap::DiskWithReservations;
use disklayer_ram::ram_disk;
use pal_async::async_test;
use parking_lot::Mutex;
use test_with_tracing::test;

#[derive(Debug, PartialEq, Eq)]
enum PrCall {
    Register(Option<u64>, u64, Option<bool>),
    Reserve(u64, ReservationType),
    Release(u64, ReservationType),
    Clear(u64),
    Preempt(u64, u64, ReservationType, bool),
}

struct PrBackend {
    calls: Mutex<Vec<PrCall>>,
    failure: Mutex<Option<DiskError>>,
    ptpl_capable: bool,
}

impl Default for PrBackend {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
            ptpl_capable: true,
        }
    }
}

impl PrBackend {
    // Observe the storage API boundary and optionally return a realistic backend failure.
    fn record(&self, call: PrCall) -> Result<(), DiskError> {
        self.calls.lock().push(call);
        match self.failure.lock().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl PersistentReservation for PrBackend {
    fn capabilities(&self) -> ReservationCapabilities {
        ReservationCapabilities {
            write_exclusive: true,
            exclusive_access: true,
            write_exclusive_registrants_only: true,
            exclusive_access_registrants_only: true,
            write_exclusive_all_registrants: true,
            exclusive_access_all_registrants: true,
            persist_through_power_loss: self.ptpl_capable,
        }
    }

    async fn report(&self) -> Result<ReservationReport, DiskError> {
        Ok(ReservationReport {
            generation: 41,
            reservation_type: Some(ReservationType::WriteExclusive),
            persist_through_power_loss: false,
            controllers: vec![
                RegisteredController {
                    key: 0x11,
                    host_id: (0..20).collect(),
                    controller_id: 17,
                    holds_reservation: true,
                },
                RegisteredController {
                    key: 0x22,
                    host_id: vec![0x5a; 3],
                    controller_id: 23,
                    holds_reservation: false,
                },
            ],
        })
    }

    async fn register(
        &self,
        current_key: Option<u64>,
        new_key: u64,
        ptpl: Option<bool>,
    ) -> Result<(), DiskError> {
        self.record(PrCall::Register(current_key, new_key, ptpl))
    }

    async fn reserve(&self, key: u64, reservation_type: ReservationType) -> Result<(), DiskError> {
        self.record(PrCall::Reserve(key, reservation_type))
    }

    async fn release(&self, key: u64, reservation_type: ReservationType) -> Result<(), DiskError> {
        self.record(PrCall::Release(key, reservation_type))
    }

    async fn clear(&self, key: u64) -> Result<(), DiskError> {
        self.record(PrCall::Clear(key))
    }

    async fn preempt(
        &self,
        current_key: u64,
        preempt_key: u64,
        reservation_type: ReservationType,
        abort: bool,
    ) -> Result<(), DiskError> {
        self.record(PrCall::Preempt(
            current_key,
            preempt_key,
            reservation_type,
            abort,
        ))
    }
}

// Keep request buffers separate from the disk so tests observe actual DMA contents.
fn namespace() -> (GuestMemory, Namespace) {
    let mem = GuestMemory::allocate(0x10000);
    let namespace = Namespace::new(mem.clone(), 1, ram_disk(1 << 20, false).unwrap());
    (mem, namespace)
}

// Build one-block NVM requests with a valid guest buffer.
fn command(opcode: nvm::NvmOpcode) -> spec::Command {
    let mut command = spec::Command::new_zeroed();
    command.cdw0.set_opcode(opcode.0);
    command.nsid = 1;
    command.dptr[0] = 0x1000;
    command
}

// Read the completion status without requiring access to NvmeError's private fields.
fn error_status(result: Result<(), NvmeError>) -> spec::Status {
    CommandResult::from(result.unwrap_err()).status
}

// Test: Translate register/unregister/replace actions and persistence options to the storage API.
// Expected: Key checking and persistence changes match each request, including unsupported persistence.
#[async_test]
async fn reservation_registration_forwards_keys_actions_and_persistence() {
    let (mem, ns) = namespace();
    let backend = PrBackend::default();
    mem.write_plain(
        0x1000,
        &nvm::ReservationRegister {
            crkey: 0x11,
            nrkey: 0x22,
        },
    )
    .unwrap();
    let mut request = command(nvm::NvmOpcode::RESERVATION_REGISTER);
    for (action, ignore_key, persistence, expected) in [
        (0, false, 0, PrCall::Register(None, 0x22, None)),
        (1, false, 2, PrCall::Register(Some(0x11), 0, Some(false))),
        (2, true, 3, PrCall::Register(None, 0x22, Some(true))),
        (2, false, 0, PrCall::Register(Some(0x11), 0x22, None)),
    ] {
        request.cdw10 = nvm::Cdw10ReservationRegister::new()
            .with_rrega(action)
            .with_iekey(ignore_key)
            .with_cptpl(persistence)
            .into();
        ns.reservation_register(&backend, &request).await.unwrap();
        assert_eq!(*backend.calls.lock(), [expected]);
        backend.calls.lock().clear();
    }
    let backend = PrBackend {
        ptpl_capable: false,
        ..Default::default()
    };
    request.cdw10 = nvm::Cdw10ReservationRegister::new().with_cptpl(3).into();
    ns.reservation_register(&backend, &request).await.unwrap();
    assert_eq!(*backend.calls.lock(), [PrCall::Register(None, 0x22, None)]);
}

// Test: Translate every reservation type with acquire, preempt, preempt-and-abort and release.
// Expected: Storage calls receive the exact keys, reservation type and abort choice from the request.
#[async_test]
async fn reservation_acquire_and_release_forward_service_actions() {
    let (mem, ns) = namespace();
    let backend = PrBackend::default();
    mem.write_plain(
        0x1000,
        &nvm::ReservationAcquire {
            crkey: 0x11,
            prkey: 0x22,
        },
    )
    .unwrap();
    for (encoded_type, kind) in [
        (1, ReservationType::WriteExclusive),
        (2, ReservationType::ExclusiveAccess),
        (3, ReservationType::WriteExclusiveRegistrantsOnly),
        (4, ReservationType::ExclusiveAccessRegistrantsOnly),
        (5, ReservationType::WriteExclusiveAllRegistrants),
        (6, ReservationType::ExclusiveAccessAllRegistrants),
    ] {
        for action in 0..3 {
            let mut request = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
            request.cdw10 = nvm::Cdw10ReservationAcquire::new()
                .with_rtype(encoded_type)
                .with_racqa(action)
                .into();
            ns.reservation_acquire(&backend, &request).await.unwrap();
            let expected = if action == 0 {
                PrCall::Reserve(0x11, kind)
            } else {
                PrCall::Preempt(0x11, 0x22, kind, action == 2)
            };
            assert_eq!(*backend.calls.lock(), [expected]);
            backend.calls.lock().clear();
        }
        let mut request = command(nvm::NvmOpcode::RESERVATION_RELEASE);
        request.cdw10 = nvm::Cdw10ReservationRelease::new()
            .with_rtype(encoded_type)
            .into();
        ns.reservation_release(&backend, &request).await.unwrap();
        assert_eq!(*backend.calls.lock(), [PrCall::Release(0x11, kind)]);
        backend.calls.lock().clear();
    }
    let mut request = command(nvm::NvmOpcode::RESERVATION_RELEASE);
    request.cdw10 = nvm::Cdw10ReservationRelease::new().with_rrela(1).into();
    ns.reservation_release(&backend, &request).await.unwrap();
    assert_eq!(*backend.calls.lock(), [PrCall::Clear(0x11)]);
}

// Test: Request both reservation-report formats from a backend with long and short host IDs.
// Expected: Headers, keys and ownership survive encoding, with host IDs truncated or zero-padded.
#[async_test]
async fn reservation_report_formats_preserve_backend_records() {
    let (mem, ns) = namespace();
    let backend = PrBackend::default();
    for extended in [false, true] {
        let mut request = command(nvm::NvmOpcode::RESERVATION_REPORT);
        let len = if extended { 64 + 2 * 64 } else { 24 + 2 * 24 };
        request.cdw10 = len / 4 - 1;
        request.cdw11 = nvm::Cdw11ReservationReport::new().with_eds(extended).into();
        mem.fill_at(0x1000, 0xa5, 4096).unwrap();
        ns.reservation_report(&backend, &request).await.unwrap();
        let header = mem.read_plain::<nvm::ReservationReport>(0x1000).unwrap();
        assert_eq!(header.generation, 41);
        assert_eq!(header.rtype, nvm::ReservationType::WRITE_EXCLUSIVE);
        assert_eq!(header.regctl.get(), 2);
        for (index, key, controller_id, owns) in [(0, 0x11, 17, true), (1, 0x22, 23, false)] {
            if extended {
                let record = mem
                    .read_plain::<nvm::RegisteredControllerExtended>(0x1000 + 64 + index * 64)
                    .unwrap();
                assert_eq!(
                    (record.rkey, record.cntlid, record.rcsts.holds_reservation()),
                    (key, controller_id, owns)
                );
                let expected = if index == 0 {
                    std::array::from_fn(|i| i as u8)
                } else {
                    let mut bytes = [0; 16];
                    bytes[..3].fill(0x5a);
                    bytes
                };
                assert_eq!(record.hostid, expected);
            } else {
                let record = mem
                    .read_plain::<nvm::RegisteredController>(0x1000 + 24 + index * 24)
                    .unwrap();
                assert_eq!(
                    (record.rkey, record.cntlid, record.rcsts.holds_reservation()),
                    (key, controller_id, owns)
                );
                assert_eq!(
                    record.hostid,
                    if index == 0 {
                        [0, 1, 2, 3, 4, 5, 6, 7]
                    } else {
                        [0x5a, 0x5a, 0x5a, 0, 0, 0, 0, 0]
                    }
                );
            }
        }
        assert_eq!(mem.read_plain::<u8>(0x1000 + u64::from(len)).unwrap(), 0xa5);
    }
}

// Test: Submit reserved actions, unsupported types, and illegal ignore-key bits.
// Expected: Requests fail as invalid fields before making any reservation-changing storage call.
#[async_test]
async fn invalid_reservation_fields_do_not_reach_the_backend() {
    let (mem, ns) = namespace();
    let backend = PrBackend::default();
    mem.write_at(0x1000, &[0; 16]).unwrap();
    for encoded in [7, 1 << 30] {
        let mut request = command(nvm::NvmOpcode::RESERVATION_REGISTER);
        request.cdw10 = encoded;
        assert_eq!(
            error_status(ns.reservation_register(&backend, &request).await),
            spec::Status::INVALID_FIELD_IN_COMMAND
        );
    }
    for encoded in [1 << 3, 7 << 8, 7 | (1 << 8)] {
        let mut request = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
        request.cdw10 = encoded;
        assert_eq!(
            error_status(ns.reservation_acquire(&backend, &request).await),
            spec::Status::INVALID_FIELD_IN_COMMAND
        );
    }
    for encoded in [1 << 3, 7 << 8, 7] {
        let mut request = command(nvm::NvmOpcode::RESERVATION_RELEASE);
        request.cdw10 = encoded;
        assert_eq!(
            error_status(ns.reservation_release(&backend, &request).await),
            spec::Status::INVALID_FIELD_IN_COMMAND
        );
    }
    assert!(backend.calls.lock().is_empty());
}

// Test: Run reservation commands through the namespace dispatcher backed by a real reservation disk.
// Expected: Registration, acquisition, reporting, release and unregister form a usable end-to-end sequence.
#[async_test]
async fn namespace_dispatches_a_complete_reservation_lifecycle() {
    let mem = GuestMemory::allocate(0x10000);
    let disk = Disk::new(DiskWithReservations::new(ram_disk(1 << 20, false).unwrap())).unwrap();
    let ns = Namespace::new(mem.clone(), 1, disk);
    let mut request = command(nvm::NvmOpcode::RESERVATION_REGISTER);
    mem.write_plain(
        0x1000,
        &nvm::ReservationRegister {
            crkey: 0,
            nrkey: 0x1234,
        },
    )
    .unwrap();
    ns.nvm_command(4096, &request).await.unwrap();
    request = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
    request.cdw10 = 1 << 8;
    mem.write_plain(
        0x1000,
        &nvm::ReservationAcquire {
            crkey: 0x1234,
            prkey: 0,
        },
    )
    .unwrap();
    ns.nvm_command(4096, &request).await.unwrap();
    request = command(nvm::NvmOpcode::RESERVATION_REPORT);
    request.cdw10 = 31;
    request.cdw11 = 1;
    ns.nvm_command(4096, &request).await.unwrap();
    let header = mem.read_plain::<nvm::ReservationReport>(0x1000).unwrap();
    assert_eq!(
        (header.rtype, header.regctl.get()),
        (nvm::ReservationType::WRITE_EXCLUSIVE, 1)
    );
    let record = mem
        .read_plain::<nvm::RegisteredControllerExtended>(0x1040)
        .unwrap();
    assert_eq!(record.rkey, 0x1234);
    assert!(record.rcsts.holds_reservation());
    request = command(nvm::NvmOpcode::RESERVATION_RELEASE);
    request.cdw10 = 1 << 8;
    mem.write_plain(0x1000, &nvm::ReservationRelease { crkey: 0x1234 })
        .unwrap();
    ns.nvm_command(4096, &request).await.unwrap();
    request = command(nvm::NvmOpcode::RESERVATION_REGISTER);
    request.cdw10 = 1;
    mem.write_plain(
        0x1000,
        &nvm::ReservationRegister {
            crkey: 0x1234,
            nrkey: 0,
        },
    )
    .unwrap();
    ns.nvm_command(4096, &request).await.unwrap();
    request = command(nvm::NvmOpcode::RESERVATION_REPORT);
    request.cdw10 = 31;
    ns.nvm_command(4096, &request).await.unwrap();
    let header = mem.read_plain::<nvm::ReservationReport>(0x1000).unwrap();
    assert_eq!((header.rtype.0, header.regctl.get()), (0, 0));
}

// Test: Return backend reservation, access, media and I/O failures during acquisition.
// Expected: Each failure reaches the NVMe boundary with the protocol-defined status.
#[async_test]
async fn backend_failures_map_to_distinct_nvme_statuses() {
    use disk_backend::MediumErrorDetails as Medium;
    let (mem, ns) = namespace();
    mem.write_plain(
        0x1000,
        &nvm::ReservationAcquire {
            crkey: 0x11,
            prkey: 0x22,
        },
    )
    .unwrap();
    let mut request = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
    request.cdw10 = 1 << 8;
    let mut cases = vec![
        (
            DiskError::ReservationConflict,
            spec::Status::RESERVATION_CONFLICT,
        ),
        (DiskError::IllegalBlock, spec::Status::LBA_OUT_OF_RANGE),
        (
            DiskError::InvalidInput,
            spec::Status::INVALID_FIELD_IN_COMMAND,
        ),
        (
            DiskError::ReadOnly,
            spec::Status::ATTEMPTED_WRITE_TO_READ_ONLY_RANGE,
        ),
        (
            DiskError::UnsupportedEject,
            spec::Status::INVALID_COMMAND_OPCODE,
        ),
        (
            DiskError::AbortDueToPreemptAndAbort,
            spec::Status::COMMAND_ABORTED_DUE_TO_PREEMPT_AND_ABORT,
        ),
        (
            DiskError::Io(std::io::Error::other("injected I/O failure")),
            spec::Status::DATA_TRANSFER_ERROR,
        ),
    ];
    for (details, expected) in [
        (
            Medium::ApplicationTagCheckFailed,
            spec::Status::MEDIA_END_TO_END_APPLICATION_TAG_CHECK_ERROR,
        ),
        (
            Medium::GuardCheckFailed,
            spec::Status::MEDIA_END_TO_END_GUARD_CHECK_ERROR,
        ),
        (
            Medium::ReferenceTagCheckFailed,
            spec::Status::MEDIA_END_TO_END_REFERENCE_TAG_CHECK_ERROR,
        ),
        (
            Medium::UnrecoveredReadError,
            spec::Status::MEDIA_UNRECOVERED_READ_ERROR,
        ),
        (Medium::WriteFault, spec::Status::MEDIA_WRITE_FAULT),
    ] {
        cases.push((
            DiskError::MediumError(std::io::Error::other("injected medium failure"), details),
            expected,
        ));
    }
    for (failure, expected) in cases {
        let backend = PrBackend {
            failure: Mutex::new(Some(failure)),
            ..Default::default()
        };
        assert_eq!(
            error_status(ns.reservation_acquire(&backend, &request).await),
            expected
        );
        assert_eq!(
            *backend.calls.lock(),
            [PrCall::Reserve(0x11, ReservationType::WriteExclusive)]
        );
    }
}

// IGNORED: Reservation reports write the complete payload into the requested
//          range; a short transfer panics instead of truncating the response.
//
// Test: Request only one dword of a populated reservation report.
// Expected: The generation is returned and bytes beyond the requested transfer remain unchanged.
#[async_test]
#[ignore = "product bug: reservation report does not truncate to NUMD"]
async fn short_reservation_reports_respect_the_requested_transfer_length() {
    let (mem, ns) = namespace();
    mem.fill_at(0x1000, 0xa5, 4096).unwrap();
    let request = command(nvm::NvmOpcode::RESERVATION_REPORT);
    ns.reservation_report(&PrBackend::default(), &request)
        .await
        .unwrap();
    assert_eq!(mem.read_plain::<u32>(0x1000).unwrap(), 41);
    assert_eq!(mem.read_plain::<[u8; 16]>(0x1004).unwrap(), [0xa5; 16]);
}

// Test: Write, read and discard a block, then issue oversized, out-of-range and unmapped transfers.
// Expected: Successful data round-trips exactly, discard reads as zero, and each bad request is refused.
#[async_test]
async fn namespace_data_transfers_and_boundaries_remain_usable_after_errors() {
    let (mem, ns) = namespace();
    mem.write_at(0x1000, &[0x74; 512]).unwrap();
    let write = command(nvm::NvmOpcode::WRITE);
    ns.nvm_command(4096, &write).await.unwrap();
    mem.fill_at(0x1000, 0xa5, 512).unwrap();
    let read = command(nvm::NvmOpcode::READ);
    ns.nvm_command(4096, &read).await.unwrap();
    assert_eq!(mem.read_plain::<[u8; 512]>(0x1000).unwrap(), [0x74; 512]);
    mem.write_plain(
        0x1000,
        &nvm::DsmRange {
            context_attributes: 0,
            lba_count: 1,
            starting_lba: 0,
        },
    )
    .unwrap();
    let mut discard = command(nvm::NvmOpcode::DSM);
    discard.cdw11 = nvm::Cdw11Dsm::new().with_ad(true).into();
    ns.nvm_command(4096, &discard).await.unwrap();
    ns.nvm_command(4096, &read).await.unwrap();
    assert_eq!(mem.read_plain::<[u8; 512]>(0x1000).unwrap(), [0; 512]);
    for opcode in [nvm::NvmOpcode::READ, nvm::NvmOpcode::WRITE] {
        for (low, high, blocks, expected) in [
            (2048, 0, 0, spec::Status::LBA_OUT_OF_RANGE),
            (u32::MAX, u32::MAX, 0, spec::Status::LBA_OUT_OF_RANGE),
            (0, 0, 8, spec::Status::INVALID_FIELD_IN_COMMAND),
        ] {
            let mut request = command(opcode);
            request.cdw10 = low;
            request.cdw11 = high;
            request.cdw12 = blocks;
            let result = ns.nvm_command(4096, &request).await.err().unwrap();
            assert_eq!(CommandResult::from(result).status, expected);
        }
    }
    let mut unmapped = read;
    unmapped.dptr[0] = 0x20000;
    assert_eq!(
        CommandResult::from(ns.nvm_command(4096, &unmapped).await.err().unwrap()).status,
        spec::Status::DATA_TRANSFER_ERROR
    );
    ns.nvm_command(4096, &read).await.unwrap();
    let mut unsupported = spec::Command::new_zeroed();
    unsupported.cdw10 = spec::Feature::NVM_RESERVATION_PERSISTENCE.0.into();
    assert_eq!(
        CommandResult::from(ns.get_feature(&unsupported).await.err().unwrap()).status,
        spec::Status::INVALID_FIELD_IN_COMMAND
    );
}
