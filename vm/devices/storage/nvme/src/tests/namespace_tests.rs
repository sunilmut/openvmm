// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::CommandResult;
use crate::namespace::Namespace;
use crate::spec;
use crate::spec::nvm;
use disk_backend::Disk;
use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::MediumErrorDetails;
use disk_prwrap::DiskWithReservations;
use disklayer_ram::ram_disk;
use guestmem::GuestMemory;
use pal_async::async_test;
use parking_lot::Mutex;
use scsi_buffers::RequestBuffers;
use std::sync::Arc;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::FromZeros;

const DATA: u64 = 0x2000;
const MAX_TRANSFER: usize = 0x10000;

fn command(opcode: nvm::NvmOpcode) -> spec::Command {
    let mut command = spec::Command::new_zeroed();
    command.cdw0.set_opcode(opcode.0);
    command.nsid = 1;
    command.dptr[0] = DATA;
    command
}

async fn execute(ns: &Namespace, command: &spec::Command) -> CommandResult {
    ns.nvm_command(MAX_TRANSFER, command)
        .await
        .unwrap_or_else(CommandResult::from)
}

fn namespace(pr: bool) -> (GuestMemory, Namespace) {
    let mem = GuestMemory::allocate(0x10000);
    let disk = ram_disk(0x10000, false).unwrap();
    let disk = if pr {
        Disk::new(DiskWithReservations::new(disk)).unwrap()
    } else {
        disk
    };
    (mem.clone(), Namespace::new(mem, 1, disk))
}

// Test: Write/read the last two sectors using a split, noncontiguous PRP buffer,
//       then submit oversized and out-of-range reads and writes.
// Expected: Data survives the roundtrip; invalid commands return their NVMe
//       status without modifying the disk or invalidating subsequent reads.
#[async_test]
async fn split_prp_roundtrip_and_transfer_boundaries() {
    let (mem, ns) = namespace(false);
    let mut cmd = command(nvm::NvmOpcode::WRITE);
    cmd.dptr = [0x2f00, 0x6000];
    cmd.cdw10 = 126;
    cmd.cdw12 = nvm::Cdw12ReadWrite::new()
        .with_nlb_z(1)
        .with_fua(true)
        .into();
    mem.fill_at(0x2f00, 0x71, 256).unwrap();
    mem.fill_at(0x6000, 0x71, 768).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    for opcode in [nvm::NvmOpcode::READ, nvm::NvmOpcode::WRITE] {
        cmd.cdw0.set_opcode(opcode.0);
        assert_eq!(
            CommandResult::from(ns.nvm_command(512, &cmd).await.err().unwrap()).status,
            spec::Status::INVALID_FIELD_IN_COMMAND,
        );
        for (low, high) in [(127, 0), (u32::MAX, u32::MAX)] {
            cmd.cdw10 = low;
            cmd.cdw11 = high;
            assert_eq!(
                execute(&ns, &cmd).await.status,
                spec::Status::LBA_OUT_OF_RANGE
            );
        }
    }
    cmd.cdw0.set_opcode(nvm::NvmOpcode::READ.0);
    cmd.cdw10 = 126;
    cmd.cdw11 = 0;
    mem.fill_at(0x2f00, 0, 256).unwrap();
    mem.fill_at(0x6000, 0, 768).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    let mut head = [0; 256];
    let mut tail = [0; 768];
    mem.read_at(0x2f00, &mut head).unwrap();
    mem.read_at(0x6000, &mut tail).unwrap();
    assert_eq!(head, [0x71; 256]);
    assert_eq!(tail, [0x71; 768]);
}

// Test: Deallocate two nonadjacent sectors of a RAM-backed namespace.
// Expected: Only the selected sectors become zero; the intervening sector and
//       adjacent data remain readable with their original contents.
#[async_test]
async fn dataset_management_preserves_unselected_sectors() {
    let (mem, ns) = namespace(false);
    mem.fill_at(DATA, 0xa6, 5 * 512).unwrap();
    let mut write = command(nvm::NvmOpcode::WRITE);
    write.cdw12 = nvm::Cdw12ReadWrite::new().with_nlb_z(4).into();
    assert_eq!(execute(&ns, &write).await.status, spec::Status::SUCCESS);
    for (index, lba) in [1, 3].into_iter().enumerate() {
        mem.write_plain(
            DATA + (index * size_of::<nvm::DsmRange>()) as u64,
            &nvm::DsmRange {
                context_attributes: 0,
                lba_count: 1,
                starting_lba: lba,
            },
        )
        .unwrap();
    }
    let mut dsm = command(nvm::NvmOpcode::DSM);
    dsm.cdw10 = nvm::Cdw10Dsm::new().with_nr_z(1).into();
    dsm.cdw11 = nvm::Cdw11Dsm::new().with_ad(true).into();
    assert_eq!(execute(&ns, &dsm).await.status, spec::Status::SUCCESS);
    write.cdw0.set_opcode(nvm::NvmOpcode::READ.0);
    assert_eq!(execute(&ns, &write).await.status, spec::Status::SUCCESS);
    let mut bytes = [0; 5 * 512];
    mem.read_at(DATA, &mut bytes).unwrap();
    for (index, sector) in bytes.chunks_exact(512).enumerate() {
        assert!(
            sector
                .iter()
                .all(|&b| b == if index == 1 || index == 3 { 0 } else { 0xa6 })
        );
    }
    assert_eq!(
        execute(&ns, &command(nvm::NvmOpcode::FLUSH)).await.status,
        spec::Status::SUCCESS
    );
}

fn register(
    key: u64,
    new_key: u64,
    action: u8,
    ptpl: u8,
) -> (spec::Command, nvm::ReservationRegister) {
    let mut cmd = command(nvm::NvmOpcode::RESERVATION_REGISTER);
    cmd.cdw10 = nvm::Cdw10ReservationRegister::new()
        .with_rrega(action)
        .with_cptpl(ptpl)
        .into();
    (
        cmd,
        nvm::ReservationRegister {
            crkey: key,
            nrkey: new_key,
        },
    )
}

async fn report(
    mem: &GuestMemory,
    ns: &Namespace,
    extended: bool,
) -> (nvm::ReservationReport, u64) {
    let mut cmd = command(nvm::NvmOpcode::RESERVATION_REPORT);
    cmd.cdw10 = 1023;
    cmd.cdw11 = nvm::Cdw11ReservationReport::new().with_eds(extended).into();
    assert_eq!(execute(ns, &cmd).await.status, spec::Status::SUCCESS);
    let header: nvm::ReservationReport = mem.read_plain(DATA).unwrap();
    let key = if extended {
        let entry: nvm::RegisteredControllerExtended = mem
            .read_plain(DATA + size_of::<nvm::ReservationReportExtended>() as u64)
            .unwrap();
        entry.rkey
    } else {
        let entry: nvm::RegisteredController = mem
            .read_plain(DATA + size_of::<nvm::ReservationReport>() as u64)
            .unwrap();
        entry.rkey
    };
    (header, key)
}

// Test: Register, acquire, release, replace and unregister a persistent key
//       through NVMe commands, reading both reservation report formats.
// Expected: Reports expose the registered key, reservation type and controller
//       count, and Get Features reflects the requested persistence setting.
#[async_test]
async fn reservation_lifecycle_is_visible_in_both_report_formats() {
    let (mem, ns) = namespace(true);
    let (cmd, data) = register(0, 0x1234, 0, 3);
    mem.write_plain(DATA, &data).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    let mut get = spec::Command::new_zeroed();
    get.cdw10 = spec::Cdw10GetFeatures::new()
        .with_fid(spec::Feature::NVM_RESERVATION_PERSISTENCE.0)
        .into();
    assert_eq!(ns.get_feature(&get).await.unwrap().dw[0], 1);
    for extended in [false, true] {
        let (header, key) = report(&mem, &ns, extended).await;
        assert_eq!(u16::from(header.regctl), 1);
        assert_eq!(key, 0x1234);
        assert_eq!(header.rtype.0, 0);
    }
    let mut acquire = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
    acquire.cdw10 = nvm::Cdw10ReservationAcquire::new().with_rtype(1).into();
    mem.write_plain(
        DATA,
        &nvm::ReservationAcquire {
            crkey: 0x1234,
            prkey: 0,
        },
    )
    .unwrap();
    assert_eq!(execute(&ns, &acquire).await.status, spec::Status::SUCCESS);
    assert_eq!(report(&mem, &ns, true).await.0.rtype.0, 1);
    let mut release = command(nvm::NvmOpcode::RESERVATION_RELEASE);
    release.cdw10 = nvm::Cdw10ReservationRelease::new().with_rtype(1).into();
    mem.write_plain(DATA, &nvm::ReservationRelease { crkey: 0x1234 })
        .unwrap();
    assert_eq!(execute(&ns, &release).await.status, spec::Status::SUCCESS);
    assert_eq!(report(&mem, &ns, false).await.0.rtype.0, 0);
    let (cmd, data) = register(0x1234, 0x5678, 2, 2);
    mem.write_plain(DATA, &data).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    assert_eq!(report(&mem, &ns, true).await.1, 0x5678);
    assert_eq!(ns.get_feature(&get).await.unwrap().dw[0], 0);
    let (cmd, data) = register(0x5678, 0, 1, 0);
    mem.write_plain(DATA, &data).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    assert_eq!(u16::from(report(&mem, &ns, false).await.0.regctl), 0);
}

// Test: Send malformed reservation controls after registering a key.
// Expected: Reserved actions, reservation types, persistence controls and IEKEY
//       combinations are rejected without changing the registered key.
#[async_test]
async fn invalid_reservation_controls_preserve_registration() {
    let (mem, ns) = namespace(true);
    let (cmd, data) = register(0, 0x48, 0, 0);
    mem.write_plain(DATA, &data).unwrap();
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    let invalid = [
        (
            nvm::NvmOpcode::RESERVATION_REGISTER,
            nvm::Cdw10ReservationRegister::new().with_rrega(7).into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_REGISTER,
            nvm::Cdw10ReservationRegister::new().with_cptpl(1).into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_ACQUIRE,
            nvm::Cdw10ReservationAcquire::new()
                .with_iekey(true)
                .with_rtype(1)
                .into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_ACQUIRE,
            nvm::Cdw10ReservationAcquire::new().with_rtype(0).into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_ACQUIRE,
            nvm::Cdw10ReservationAcquire::new()
                .with_racqa(7)
                .with_rtype(1)
                .into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_RELEASE,
            nvm::Cdw10ReservationRelease::new()
                .with_iekey(true)
                .with_rtype(1)
                .into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_RELEASE,
            nvm::Cdw10ReservationRelease::new().with_rtype(0).into(),
        ),
        (
            nvm::NvmOpcode::RESERVATION_RELEASE,
            nvm::Cdw10ReservationRelease::new().with_rrela(7).into(),
        ),
    ];
    for (opcode, cdw10) in invalid {
        mem.write_plain(
            DATA,
            &nvm::ReservationAcquire {
                crkey: 0x48,
                prkey: 0,
            },
        )
        .unwrap();
        let mut cmd = command(opcode);
        cmd.cdw10 = cdw10;
        assert_eq!(
            execute(&ns, &cmd).await.status,
            spec::Status::INVALID_FIELD_IN_COMMAND,
            "{opcode:?} {cdw10:#x}"
        );
        assert_eq!(report(&mem, &ns, false).await.1, 0x48);
    }
}

// Test: Clear a registration and issue preempt requests with and without abort.
// Expected: Clear removes the controller; each preempt is forwarded with the
//       supplied keys, producing a new backend report generation.
#[async_test]
async fn clear_and_preempt_commands_reach_the_reservation_backend() {
    let (mem, ns) = namespace(true);
    for action in [1, 2] {
        let (cmd, data) = register(0, 0x48, 0, 0);
        mem.write_plain(DATA, &data).unwrap();
        assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
        let generation = report(&mem, &ns, false).await.0.generation;
        let mut cmd = command(nvm::NvmOpcode::RESERVATION_ACQUIRE);
        cmd.cdw10 = nvm::Cdw10ReservationAcquire::new()
            .with_racqa(action)
            .with_rtype(1)
            .into();
        mem.write_plain(
            DATA,
            &nvm::ReservationAcquire {
                crkey: 0x48,
                prkey: 0x48,
            },
        )
        .unwrap();
        assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
        assert!(report(&mem, &ns, true).await.0.generation > generation);
        let mut cmd = command(nvm::NvmOpcode::RESERVATION_RELEASE);
        cmd.cdw10 = nvm::Cdw10ReservationRelease::new().with_rrela(1).into();
        mem.write_plain(DATA, &nvm::ReservationRelease { crkey: 0x48 })
            .unwrap();
        assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
        assert_eq!(u16::from(report(&mem, &ns, false).await.0.regctl), 0);
    }
}

#[derive(inspect::Inspect)]
struct FaultDisk {
    inner: Disk,
    #[inspect(skip)]
    error: Arc<Mutex<Option<DiskError>>>,
}

impl FaultDisk {
    fn check(&self) -> Result<(), DiskError> {
        self.error.lock().take().map_or(Ok(()), Err)
    }
}

impl DiskIo for FaultDisk {
    fn disk_type(&self) -> &str {
        "nvme-test-fault"
    }
    fn sector_count(&self) -> u64 {
        self.inner.sector_count()
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
    fn physical_sector_size(&self) -> u32 {
        self.inner.physical_sector_size()
    }
    fn disk_id(&self) -> Option<[u8; 16]> {
        Some([0x47; 16])
    }
    fn is_fua_respected(&self) -> bool {
        self.inner.is_fua_respected()
    }
    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }
    fn unmap_behavior(&self) -> disk_backend::UnmapBehavior {
        self.inner.unmap_behavior()
    }
    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        self.check()?;
        self.inner.read_vectored(buffers, sector).await
    }
    async fn write_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
        fua: bool,
    ) -> Result<(), DiskError> {
        self.check()?;
        self.inner.write_vectored(buffers, sector, fua).await
    }
    async fn sync_cache(&self) -> Result<(), DiskError> {
        self.check()?;
        self.inner.sync_cache().await
    }
    async fn unmap(
        &self,
        sector: u64,
        count: u64,
        block_level_only: bool,
    ) -> Result<(), DiskError> {
        self.check()?;
        self.inner.unmap(sector, count, block_level_only).await
    }
}

// Test: Inject backend failures into a valid namespace read.
// Expected: NVMe reports the corresponding transfer, reservation, media or
//       permission status; a successful retry remains possible after each error.
#[async_test]
async fn backend_errors_are_translated_without_poisoning_later_io() {
    use disk_backend::MediumErrorDetails as M;

    let mem = GuestMemory::allocate(0x10000);
    let error = Arc::new(Mutex::new(None));
    let disk = Disk::new(FaultDisk {
        inner: ram_disk(0x10000, false).unwrap(),
        error: error.clone(),
    })
    .unwrap();
    let ns = Namespace::new(mem.clone(), 1, disk);
    let mut cases = vec![
        (
            DiskError::ReservationConflict,
            spec::Status::RESERVATION_CONFLICT,
        ),
        (
            DiskError::AbortDueToPreemptAndAbort,
            spec::Status::COMMAND_ABORTED_DUE_TO_PREEMPT_AND_ABORT,
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
            DiskError::Io(std::io::Error::other("injected I/O error")),
            spec::Status::DATA_TRANSFER_ERROR,
        ),
        (
            DiskError::MemoryAccess(guestmem::AccessError::Memory(
                mem.read_at(0x10000, &mut [0]).unwrap_err(),
            )),
            spec::Status::DATA_TRANSFER_ERROR,
        ),
    ];
    for (detail, status) in [
        (
            M::ApplicationTagCheckFailed,
            spec::Status::MEDIA_END_TO_END_APPLICATION_TAG_CHECK_ERROR,
        ),
        (
            M::GuardCheckFailed,
            spec::Status::MEDIA_END_TO_END_GUARD_CHECK_ERROR,
        ),
        (
            M::ReferenceTagCheckFailed,
            spec::Status::MEDIA_END_TO_END_REFERENCE_TAG_CHECK_ERROR,
        ),
        (
            M::UnrecoveredReadError,
            spec::Status::MEDIA_UNRECOVERED_READ_ERROR,
        ),
        (M::WriteFault, spec::Status::MEDIA_WRITE_FAULT),
    ] {
        let detail: MediumErrorDetails = detail;
        cases.push((
            DiskError::MediumError(std::io::Error::other("injected medium error"), detail),
            status,
        ));
    }
    for (failure, expected) in cases {
        *error.lock() = Some(failure);
        let err = ns
            .nvm_command(MAX_TRANSFER, &command(nvm::NvmOpcode::READ))
            .await
            .err()
            .unwrap();
        assert!(!err.to_string().is_empty());
        let completion = CommandResult::from(err).completion_status();
        assert_eq!(completion.status(), expected.0);
        assert!(!completion.dnr());
        assert_eq!(
            execute(&ns, &command(nvm::NvmOpcode::READ)).await.status,
            spec::Status::SUCCESS
        );
    }
    let mut descriptor = [0u8; size_of::<nvm::NamespaceIdentificationDescriptor>()];
    ns.namespace_id_descriptor(&mut descriptor);
    let descriptor = nvm::NamespaceIdentificationDescriptor::read_from_bytes(&descriptor).unwrap();
    assert_eq!(descriptor.nid, [0x47; 16]);
}

// IGNORED: Reservation report writes the full header into a four-byte PRP
// range, panicking in PagedRange::subrange instead of truncating the response.
//
// Test: Read a reservation report with space for only its first dword.
// Expected: The command returns a successful truncated report without touching
//       the bytes following the requested transfer.
#[async_test]
#[ignore = "product regression: short reservation report panics"]
async fn short_reservation_report_respects_requested_transfer_length() {
    let (mem, ns) = namespace(true);
    mem.fill_at(DATA, 0xa5, 64).unwrap();
    let cmd = command(nvm::NvmOpcode::RESERVATION_REPORT);
    assert_eq!(execute(&ns, &cmd).await.status, spec::Status::SUCCESS);
    let mut suffix = [0; 60];
    mem.read_at(DATA + 4, &mut suffix).unwrap();
    assert_eq!(suffix, [0xa5; 60]);
}
