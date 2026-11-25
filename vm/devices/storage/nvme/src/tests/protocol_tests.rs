// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::controller_tests::instantiate_and_build_admin_queue;
use super::controller_tests::instantiate_controller;
use super::controller_tests::submit_admin_command;
use super::test_helpers::test_memory;
use crate::NvmeController;
use crate::PAGE_SIZE64;
use crate::prp::PrpRange;
use crate::spec;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use disklayer_ram::ram_disk;
use guestmem::GuestMemory;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pci_core::test_helpers::TestPciInterruptController;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

struct Controller {
    device: NvmeController,
    mem: GuestMemory,
    asq: PrpRange,
    acq: PrpRange,
    interrupts: TestPciInterruptController,
    driver: DefaultDriver,
    slot: u32,
}

impl Controller {
    async fn new(driver: DefaultDriver) -> Self {
        let acq = PrpRange::new(vec![0], 0, PAGE_SIZE64).unwrap();
        let asq = PrpRange::new(vec![0x1000], 0, PAGE_SIZE64).unwrap();
        let mem = test_memory();
        let interrupts = TestPciInterruptController::new();
        let device = instantiate_and_build_admin_queue(
            &acq,
            64,
            &asq,
            64,
            true,
            Some(&interrupts),
            driver.clone(),
            &mem,
        )
        .await;
        Self {
            device,
            mem,
            asq,
            acq,
            interrupts,
            driver,
            slot: 0,
        }
    }

    async fn send(
        &mut self,
        mut command: spec::Command,
        expected: spec::Status,
    ) -> spec::Completion {
        assert!(
            self.slot < 63,
            "test must not overrun its admin submission queue"
        );
        command.cdw0.set_cid(0x700 + self.slot as u16);
        let completion = submit_admin_command(
            &mut self.device,
            &self.mem,
            &self.asq,
            &self.acq,
            &self.interrupts,
            self.driver.clone(),
            self.slot,
            &command,
        )
        .await;
        assert_eq!(completion.cid, command.cdw0.cid());
        assert_eq!(completion.status.status(), expected.0, "{command:?}");
        self.slot += 1;
        self.device
            .write_bar0(0x1004, self.slot.as_bytes())
            .unwrap();
        completion
    }
}

fn command(opcode: spec::AdminOpcode) -> spec::Command {
    let mut command = spec::Command::new_zeroed();
    command.cdw0.set_opcode(opcode.0);
    command.dptr[0] = 0x8000;
    command
}

fn create_cq(qid: u16, size: u16, pc: bool, vector: u16) -> spec::Command {
    let mut command = command(spec::AdminOpcode::CREATE_IO_COMPLETION_QUEUE);
    command.cdw10 = spec::Cdw10CreateIoQueue::new()
        .with_qid(qid)
        .with_qsize_z(size)
        .into();
    command.cdw11 = spec::Cdw11CreateIoCompletionQueue::new()
        .with_pc(pc)
        .with_ien(true)
        .with_iv(vector)
        .into();
    command.dptr[0] = 0x4000;
    command
}

fn create_sq(qid: u16, cqid: u16, size: u16, pc: bool) -> spec::Command {
    let mut command = command(spec::AdminOpcode::CREATE_IO_SUBMISSION_QUEUE);
    command.cdw10 = spec::Cdw10CreateIoQueue::new()
        .with_qid(qid)
        .with_qsize_z(size)
        .into();
    command.cdw11 = spec::Cdw11CreateIoSubmissionQueue::new()
        .with_pc(pc)
        .with_cqid(cqid)
        .into();
    command.dptr[0] = 0x5000;
    command
}

fn delete(opcode: spec::AdminOpcode, qid: u16) -> spec::Command {
    let mut command = command(opcode);
    command.cdw10 = spec::Cdw10DeleteIoQueue::new().with_qid(qid).into();
    command
}

// Test: Create invalid, duplicate and dependent I/O queues, then delete and
//       recreate a valid pair using the same queue identifiers.
// Expected: Queue completions distinguish size, ID, vector, contiguity and
//       dependency errors; rejected commands leave valid queue operations usable.
#[async_test]
async fn queue_validation_and_identifier_reuse(driver: DefaultDriver) {
    let mut c = Controller::new(driver).await;
    for (cmd, status) in [
        (
            create_cq(0, 7, true, 1),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            create_cq(65, 7, true, 1),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (create_cq(1, 0, true, 1), spec::Status::INVALID_QUEUE_SIZE),
        (
            create_cq(1, u16::MAX, true, 1),
            spec::Status::INVALID_QUEUE_SIZE,
        ),
        (
            create_cq(1, 7, false, 1),
            spec::Status::INVALID_FIELD_IN_COMMAND,
        ),
        (
            create_cq(1, 7, true, 64),
            spec::Status::INVALID_INTERRUPT_VECTOR,
        ),
        (
            create_sq(1, 1, 7, true),
            spec::Status::COMPLETION_QUEUE_INVALID,
        ),
        (create_cq(1, 7, true, 1), spec::Status::SUCCESS),
        (
            create_cq(1, 7, true, 1),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            create_sq(0, 1, 7, true),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            create_sq(65, 1, 7, true),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            create_sq(1, 0, 7, true),
            spec::Status::COMPLETION_QUEUE_INVALID,
        ),
        (
            create_sq(1, 2, 7, true),
            spec::Status::COMPLETION_QUEUE_INVALID,
        ),
        (create_sq(1, 1, 0, true), spec::Status::INVALID_QUEUE_SIZE),
        (
            create_sq(1, 1, u16::MAX, true),
            spec::Status::INVALID_QUEUE_SIZE,
        ),
        (
            create_sq(1, 1, 7, false),
            spec::Status::INVALID_FIELD_IN_COMMAND,
        ),
        (create_sq(1, 1, 7, true), spec::Status::SUCCESS),
        (
            create_sq(1, 1, 7, true),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_COMPLETION_QUEUE, 1),
            spec::Status::INVALID_QUEUE_DELETION,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_SUBMISSION_QUEUE, 0),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_SUBMISSION_QUEUE, 2),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_SUBMISSION_QUEUE, 1),
            spec::Status::SUCCESS,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_SUBMISSION_QUEUE, 1),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_COMPLETION_QUEUE, 1),
            spec::Status::SUCCESS,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_COMPLETION_QUEUE, 1),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (
            delete(spec::AdminOpcode::DELETE_IO_COMPLETION_QUEUE, 0),
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (create_cq(1, 7, true, 1), spec::Status::SUCCESS),
        (create_sq(1, 1, 7, true), spec::Status::SUCCESS),
    ] {
        c.send(cmd, status).await;
    }
}

// Test: Identify active, inactive and invalid namespaces with sparse namespace
//       IDs, including namespace descriptors and cursor-based enumeration.
// Expected: Guest buffers contain the appropriate geometry, descriptor, sorted
//       IDs or zeros; invalid selectors and IDs produce explicit error status.
#[async_test]
async fn identify_sparse_namespaces_and_descriptors(driver: DefaultDriver) {
    let mut c = Controller::new(driver).await;
    let disk = ram_disk(0x10000, false).unwrap();
    for nsid in [2, 7] {
        c.device
            .client()
            .add_namespace(nsid, disk.clone())
            .await
            .unwrap();
    }
    for (cursor, expected) in [(0, [2, 7, 0]), (2, [7, 0, 0]), (7, [0, 0, 0])] {
        let mut cmd = command(spec::AdminOpcode::IDENTIFY);
        cmd.nsid = cursor;
        cmd.cdw10 = spec::Cdw10Identify::new()
            .with_cns(spec::Cns::ACTIVE_NAMESPACES.0)
            .into();
        c.send(cmd, spec::Status::SUCCESS).await;
        let ids: [u32; 3] = c.mem.read_plain(0x8000).unwrap();
        assert_eq!(ids, expected);
    }
    for cns in [spec::Cns::NAMESPACE, spec::Cns::DESCRIPTOR_NAMESPACE] {
        let mut cmd = command(spec::AdminOpcode::IDENTIFY);
        cmd.cdw10 = spec::Cdw10Identify::new().with_cns(cns.0).into();
        cmd.nsid = 2;
        c.send(cmd, spec::Status::SUCCESS).await;
        if cns == spec::Cns::NAMESPACE {
            let id: spec::nvm::IdentifyNamespace = c.mem.read_plain(0x8000).unwrap();
            assert_eq!(id.nsze, 128);
            assert_eq!(id.lbaf[0].lbads(), 9);
        } else {
            let id: spec::nvm::NamespaceIdentificationDescriptor =
                c.mem.read_plain(0x8000).unwrap();
            assert_eq!(id.nidt, spec::nvm::NamespaceIdentifierType::NSGUID.0);
            assert_eq!(id.nidl, 16);
        }
        c.mem.fill_at(0x8000, 0xa5, 4096).unwrap();
        cmd.nsid = 3;
        c.send(cmd, spec::Status::SUCCESS).await;
        let mut bytes = [0xff; 4096];
        c.mem.read_at(0x8000, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 4096]);
        for invalid in [0, crate::MAX_NSID + 1] {
            cmd.nsid = invalid;
            c.send(cmd, spec::Status::INVALID_NAMESPACE_OR_FORMAT).await;
        }
    }
    for (cns, nsid, status) in [
        (
            spec::Cns::ACTIVE_NAMESPACES.0,
            0xffff_fffe,
            spec::Status::INVALID_NAMESPACE_OR_FORMAT,
        ),
        (0xff, 0, spec::Status::INVALID_FIELD_IN_COMMAND),
    ] {
        let mut cmd = command(spec::AdminOpcode::IDENTIFY);
        cmd.cdw10 = spec::Cdw10Identify::new().with_cns(cns).into();
        cmd.nsid = nsid;
        c.send(cmd, status).await;
    }
}

// Test: Read short controller log pages and consume the changed-namespace list.
// Expected: Only the requested bytes are overwritten, the namespace list is
//       cleared after reading, and unsupported log pages return Invalid Log Page.
#[async_test]
async fn logs_respect_transfer_size_and_consume_namespace_changes(driver: DefaultDriver) {
    let mut c = Controller::new(driver).await;
    for lid in [
        spec::LogPageIdentifier::ERROR_INFORMATION,
        spec::LogPageIdentifier::FIRMWARE_SLOT_INFORMATION,
    ] {
        c.mem.fill_at(0x8000, 0xa5, 128).unwrap();
        let mut cmd = command(spec::AdminOpcode::GET_LOG_PAGE);
        cmd.cdw10 = spec::Cdw10GetLogPage::new()
            .with_lid(lid.0)
            .with_numdl_z(15)
            .into();
        c.send(cmd, spec::Status::SUCCESS).await;
        let mut bytes = [0; 128];
        c.mem.read_at(0x8000, &mut bytes).unwrap();
        assert_eq!(&bytes[..64], &[0; 64]);
        assert_eq!(&bytes[64..], &[0xa5; 64]);
    }
    for nsid in [2, 7] {
        c.device
            .client()
            .add_namespace(nsid, ram_disk(0x10000, false).unwrap())
            .await
            .unwrap();
    }
    let mut changed = command(spec::AdminOpcode::GET_LOG_PAGE);
    changed.cdw10 = spec::Cdw10GetLogPage::new()
        .with_lid(spec::LogPageIdentifier::CHANGED_NAMESPACE_LIST.0)
        .with_numdl_z(1023)
        .into();
    c.send(changed, spec::Status::SUCCESS).await;
    let mut ids: [u32; 3] = c.mem.read_plain(0x8000).unwrap();
    ids[..2].sort();
    assert_eq!(ids, [2, 7, 0]);
    c.send(changed, spec::Status::SUCCESS).await;
    let mut bytes = [0xff; 4096];
    c.mem.read_at(0x8000, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 4096]);
    changed.cdw10 = spec::Cdw10GetLogPage::new().with_lid(0xff).into();
    c.send(changed, spec::Status::INVALID_LOG_PAGE).await;
}

// Test: Negotiate queue counts, try changing them after queue creation, disable
//       the fixed write cache, and submit unsupported features/opcodes and Abort.
// Expected: Results preserve negotiated limits, reject out-of-sequence changes,
//       report the fixed enabled cache, and identify an un-aborted command.
#[async_test]
async fn feature_limits_sequence_and_abort_results(driver: DefaultDriver) {
    let mut c = Controller::new(driver).await;
    let mut set = command(spec::AdminOpcode::SET_FEATURES);
    set.cdw10 = spec::Cdw10SetFeatures::new()
        .with_fid(spec::Feature::NUMBER_OF_QUEUES.0)
        .into();
    set.cdw11 = spec::Cdw11FeatureNumberOfQueues::new()
        .with_nsq_z(u16::MAX)
        .into();
    c.send(set, spec::Status::INVALID_FIELD_IN_COMMAND).await;
    set.cdw11 = spec::Cdw11FeatureNumberOfQueues::new()
        .with_nsq_z(127)
        .with_ncq_z(127)
        .into();
    let completion = c.send(set, spec::Status::SUCCESS).await;
    assert_eq!(completion.dw0, (63 << 16) | 63);
    c.send(create_cq(1, 7, true, 1), spec::Status::SUCCESS)
        .await;
    c.send(set, spec::Status::COMMAND_SEQUENCE_ERROR).await;
    let mut get = command(spec::AdminOpcode::GET_FEATURES);
    get.cdw10 = spec::Cdw10GetFeatures::new()
        .with_fid(spec::Feature::NUMBER_OF_QUEUES.0)
        .into();
    assert_eq!(
        c.send(get, spec::Status::SUCCESS).await.dw0,
        (63 << 16) | 63
    );
    set.cdw10 = spec::Cdw10SetFeatures::new()
        .with_fid(spec::Feature::VOLATILE_WRITE_CACHE.0)
        .into();
    set.cdw11 = 0;
    c.send(set, spec::Status::SUCCESS).await;
    get.cdw10 = spec::Cdw10GetFeatures::new()
        .with_fid(spec::Feature::VOLATILE_WRITE_CACHE.0)
        .into();
    assert_eq!(c.send(get, spec::Status::SUCCESS).await.dw0, 1);
    set.cdw10 = spec::Cdw10SetFeatures::new().with_fid(0xff).into();
    c.send(set, spec::Status::INVALID_FIELD_IN_COMMAND).await;
    get.cdw10 = spec::Cdw10GetFeatures::new().with_fid(0xff).into();
    c.send(get, spec::Status::INVALID_FIELD_IN_COMMAND).await;
    c.send(
        command(spec::AdminOpcode(0xff)),
        spec::Status::INVALID_COMMAND_OPCODE,
    )
    .await;
    assert_eq!(
        c.send(command(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
            .await
            .dw0,
        1
    );
}

fn register(device: &mut NvmeController, offset: u64) -> u32 {
    let mut value = 0u32;
    device.read_bar0(offset, value.as_mut_bytes()).unwrap();
    value
}

// Test: Exercise split 64-bit queue-address registers and interrupt-mask
//       set/clear registers while the controller is disabled.
// Expected: Address low bits are masked, untouched halves are preserved, and
//       both mask aliases expose the same externally visible mask.
#[async_test]
async fn split_address_registers_and_interrupt_mask_aliases(driver: DefaultDriver) {
    let mem = test_memory();
    let mut device = instantiate_controller(driver, &mem, None);
    for offset in [0x28, 0x30] {
        device
            .write_bar0(offset, 0x1234_5678u64.as_bytes())
            .unwrap();
        assert_eq!(register(&mut device, offset), 0x1234_5000);
        device.write_bar0(offset + 4, 0x87u32.as_bytes()).unwrap();
        assert_eq!(register(&mut device, offset + 4), 0x87);
        assert_eq!(register(&mut device, offset), 0x1234_5000);
        device
            .write_bar0(offset, 0x5555_ffffu32.as_bytes())
            .unwrap();
        assert_eq!(register(&mut device, offset), 0x5555_f000);
        assert_eq!(register(&mut device, offset + 4), 0x87);
    }
    device.write_bar0(0x0c, 5u32.as_bytes()).unwrap();
    device.write_bar0(0x0c, 2u32.as_bytes()).unwrap();
    assert_eq!(register(&mut device, 0x0c), 7);
    device.write_bar0(0x10, 2u32.as_bytes()).unwrap();
    assert_eq!(register(&mut device, 0x0c), 5);
    assert_eq!(register(&mut device, 0x10), 5);
    for offset in [0x18, 0x20, 0x38, 0x3c, 0x40, 0x44, 0x48] {
        assert_eq!(register(&mut device, offset), 0);
    }
}

// Test: Submit invalid BAR access widths, alignment, register addresses and
//       doorbell encodings, then perform a normal register operation.
// Expected: Invalid accesses return the appropriate I/O error without changing
//       the controller's usable register interface.
#[async_test]
async fn invalid_register_accesses_leave_valid_accesses_usable(driver: DefaultDriver) {
    let mem = test_memory();
    let mut device = instantiate_controller(driver, &mem, None);
    assert!(matches!(
        device.read_bar0(0, &mut [0; 2]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        device.write_bar0(0x28, &[0; 2]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        device.read_bar0(1, &mut [0; 4]),
        IoResult::Err(IoError::UnalignedAccess)
    ));
    assert!(matches!(
        device.write_bar0(0x29, &[0; 4]),
        IoResult::Err(IoError::UnalignedAccess)
    ));
    assert!(matches!(
        device.read_bar0(8, &mut [0; 8]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    assert!(matches!(
        device.write_bar0(8, &[0; 8]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    for offset in [0xffc, 0x1001, 0x1000 + (0x10000 << 2)] {
        assert!(matches!(
            device.write_bar0(offset, &[0; 4]),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert!(matches!(
        device.read_bar0(0xffc, &mut [0; 4]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.write_bar0(0x1000, &[0; 8]),
        IoResult::Err(IoError::InvalidAccessSize)
    ));
    device.write_bar0(0x24, 0x0007_0007u32.as_bytes()).unwrap();
    assert_eq!(register(&mut device, 0x24), 0x0007_0007);
}

// Test: Reset an enabled controller after programming queue addresses and an
//       interrupt mask, and try unsupported controller configuration fields.
// Expected: Full device reset clears registers; unsupported formats set CFS,
//       and a shutdown request reports completion through CSTS.
#[async_test]
async fn reset_and_configuration_failures_are_reported_in_registers(driver: DefaultDriver) {
    let mut c = Controller::new(driver.clone()).await;
    c.device.write_bar0(0x0c, u32::MAX.as_bytes()).unwrap();
    c.device.reset().await;
    for offset in [0x14, 0x1c, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x0c] {
        assert_eq!(register(&mut c.device, offset), 0);
    }
    for config in [
        spec::Cc::new().with_css(1),
        spec::Cc::new().with_ams(2),
        spec::Cc::new().with_en(true).with_iocqes(5),
        spec::Cc::new().with_en(true).with_iosqes(7),
    ] {
        let mut device = instantiate_controller(driver.clone(), &c.mem, None);
        device
            .write_bar0(0x14, u32::from(config).as_bytes())
            .unwrap();
        assert!(spec::Csts::from(register(&mut device, 0x1c)).cfs());
    }
    c.device
        .write_bar0(0x14, u32::from(spec::Cc::new().with_shn(1)).as_bytes())
        .unwrap();
    assert_eq!(spec::Csts::from(register(&mut c.device, 0x1c)).shst(), 2);
}
