// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

struct AdminHarness {
    controller: NvmeFaultController,
    mem: GuestMemory,
    acq: PrpRange,
    asq: PrpRange,
    interrupts: TestPciInterruptController,
    driver: DefaultDriver,
    slot: u32,
}

impl AdminHarness {
    // Enable a real emulated controller and use guest-memory queues for every request.
    async fn new(driver: DefaultDriver) -> Self {
        Self::with_faults(
            driver,
            FaultConfiguration::new(CellUpdater::new(false).cell()),
        )
        .await
    }

    // Use the same guest protocol setup when testing configured fault behavior.
    async fn with_faults(driver: DefaultDriver, faults: FaultConfiguration) -> Self {
        let mem = test_memory();
        let acq = PrpRange::new(vec![0], 0, PAGE_SIZE64).unwrap();
        let asq = PrpRange::new(vec![0x1000], 0, PAGE_SIZE64).unwrap();
        let interrupts = TestPciInterruptController::new();
        let controller = instantiate_and_build_admin_queue(
            &acq,
            64,
            &asq,
            64,
            true,
            Some(&interrupts),
            driver.clone(),
            &mem,
            faults,
        )
        .await;
        Self {
            controller,
            mem,
            acq,
            asq,
            interrupts,
            driver,
            slot: 0,
        }
    }
}

// Test: Read supported/empty log pages, temperature defaults, Abort and an unsupported opcode.
// Expected: Payloads and transfer bounds match the advertised API and invalid commands retain statuses.
#[async_test]
async fn logs_temperature_defaults_and_abort_have_guest_visible_results(driver: DefaultDriver) {
    let mut h = AdminHarness::new(driver).await;
    for (lid, len) in [
        (spec::LogPageIdentifier::SUPPORTED_LOG_PAGES, 1024),
        (spec::LogPageIdentifier::ERROR_INFORMATION, 64),
        (spec::LogPageIdentifier::FIRMWARE_SLOT_INFORMATION, 512),
    ] {
        h.mem.fill_at(0x8000, 0xa5, 4096).unwrap();
        let mut request = admin(spec::AdminOpcode::GET_LOG_PAGE);
        request.dptr[0] = 0x8000;
        request.cdw10 = u32::from(lid.0) | ((len / 4 - 1) << 16);
        h.expect(request, spec::Status::SUCCESS).await;
        let bytes = h.mem.read_plain::<[u8; 4096]>(0x8000).unwrap();
        if lid == spec::LogPageIdentifier::SUPPORTED_LOG_PAGES {
            let entries = h.mem.read_plain::<[u32; 256]>(0x8000).unwrap();
            for (index, entry) in entries.into_iter().enumerate() {
                assert_eq!(entry & 1, u32::from([0, 1, 2, 3, 4].contains(&index)));
            }
        } else {
            assert!(bytes[..len as usize].iter().all(|&b| b == 0));
        }
        assert!(bytes[len as usize..].iter().all(|&b| b == 0xa5));
    }
    let mut request = admin(spec::AdminOpcode::GET_LOG_PAGE);
    request.cdw10 = 0xff;
    request.dptr[0] = 0x8000;
    h.expect(request, spec::Status::INVALID_LOG_PAGE).await;
    for (threshold_type, expected) in [(0, 0xffff), (1, 0)] {
        let mut request = admin(spec::AdminOpcode::SET_FEATURES);
        request.cdw10 = spec::Feature::TEMPERATURE_THRESHOLD.0.into();
        request.cdw11 = (threshold_type << 20) | (3 << 16) | 300;
        h.expect(request, spec::Status::SUCCESS).await;
        let response = h
            .expect(
                get_feature_command(
                    spec::Feature::TEMPERATURE_THRESHOLD,
                    (threshold_type << 20) | (3 << 16),
                ),
                spec::Status::SUCCESS,
            )
            .await;
        assert_eq!(response.dw0, (threshold_type << 20) | (3 << 16) | expected);
    }
    assert_eq!(
        h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
            .await
            .dw0,
        1
    );
    h.expect(
        admin(spec::AdminOpcode(0xff)),
        spec::Status::INVALID_COMMAND_OPCODE,
    )
    .await;
}

// Match the externally assigned command identifier without constraining unrelated fields.
fn cid_pattern(cid: u16) -> nvme_resources::fault::CommandMatch {
    CommandMatchBuilder::new()
        .match_cdw0(u32::from(spec::Cdw0::new().with_cid(cid)), 0xffff_0000)
        .build()
}

// Test: Apply submission/completion update, verify, delay, payload and drop faults.
// Expected: Each configured effect is visible; dropped entries do not stop subsequent valid work.
#[async_test]
async fn admin_fault_effects_preserve_progress_and_payload_boundaries(driver: DefaultDriver) {
    let (sq_send, sq_seen) = mesh::oneshot();
    let (cq_send, cq_seen) = mesh::oneshot();
    let mut replacement = get_feature_command(spec::Feature::VOLATILE_WRITE_CACHE, 0);
    replacement.cdw0.set_cid(0x100);
    let replacement_completion = Completion {
        cid: 0x103,
        dw0: 0xdead_beef,
        ..FromZeros::new_zeroed()
    };
    let delay = Duration::from_millis(5);
    let config = AdminQueueFaultConfig::new()
        .with_submission_queue_fault(
            cid_pattern(0x100),
            AdminQueueFaultBehavior::Update(replacement),
        )
        .with_submission_queue_fault(
            cid_pattern(0x101),
            AdminQueueFaultBehavior::Verify(Some(sq_send)),
        )
        .with_submission_queue_fault(cid_pattern(0x102), AdminQueueFaultBehavior::Delay(delay))
        .with_completion_queue_fault(
            cid_pattern(0x103),
            AdminQueueFaultBehavior::Update(replacement_completion),
        )
        .with_completion_queue_fault(
            cid_pattern(0x104),
            AdminQueueFaultBehavior::Verify(Some(cq_send)),
        )
        .with_completion_queue_fault(
            cid_pattern(0x105),
            AdminQueueFaultBehavior::CustomPayload(vec![0xd3; 32]),
        )
        .with_completion_queue_fault(cid_pattern(0x106), AdminQueueFaultBehavior::Delay(delay))
        .with_submission_queue_fault(cid_pattern(0x107), AdminQueueFaultBehavior::Drop)
        .with_completion_queue_fault(cid_pattern(0x108), AdminQueueFaultBehavior::Drop);
    let faults =
        FaultConfiguration::new(CellUpdater::new(true).cell()).with_admin_queue_fault(config);
    let mut h = AdminHarness::with_faults(driver, faults).await;
    assert_eq!(
        h.expect(
            get_feature_command(spec::Feature::NUMBER_OF_QUEUES, 0),
            spec::Status::SUCCESS
        )
        .await
        .dw0,
        1
    );
    h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
        .await;
    sq_seen.await.unwrap();
    let start = std::time::Instant::now();
    h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
        .await;
    assert!(start.elapsed() >= delay);
    assert_eq!(
        h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
            .await
            .dw0,
        0xdead_beef
    );
    h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
        .await;
    cq_seen.await.unwrap();
    h.mem.fill_at(0x8000, 0xa5, 33).unwrap();
    let mut payload = admin(spec::AdminOpcode::ABORT);
    payload.dptr[0] = 0x8000;
    h.expect(payload, spec::Status::SUCCESS).await;
    assert_eq!(h.mem.read_plain::<[u8; 32]>(0x8000).unwrap(), [0xd3; 32]);
    assert_eq!(h.mem.read_plain::<u8>(0x8020).unwrap(), 0xa5);
    let start = std::time::Instant::now();
    h.expect(admin(spec::AdminOpcode::ABORT), spec::Status::SUCCESS)
        .await;
    assert!(start.elapsed() >= delay);

    // A final non-dropped command is a deterministic progress witness for both drops.
    for slot in 7..10 {
        let mut request = admin(spec::AdminOpcode::ABORT);
        request.cdw0.set_cid(0x100 + slot as u16);
        write_command_to_queue(&h.mem, &h.asq, slot, &request);
    }
    h.controller.write_bar0(0x1000, 10u32.as_bytes()).unwrap();
    wait_for_msi(h.driver.clone(), &h.interrupts, 1000, 0xfeed0000, 0x1111).await;
    let result = read_completion_from_queue(&h.mem, &h.acq, 7);
    assert_eq!(result.cid, 0x109);
    assert_eq!(result.status.status(), spec::Status::SUCCESS.0);
    assert_eq!(h.mem.read_plain::<[u8; 16]>(8 * 16).unwrap(), [0; 16]);
}
impl AdminHarness {
    // Consume each completion so later requests do not depend on accidental CQ capacity.
    async fn submit(&mut self, mut command: Command) -> Completion {
        assert!(
            self.slot < 63,
            "test must not wrap this helper's submission queue"
        );
        command.cdw0.set_cid(0x100 + self.slot as u16);
        let completion = submit_admin_command(
            &mut self.controller,
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
        self.slot += 1;
        self.controller
            .write_bar0(0x1004, self.slot.as_bytes())
            .unwrap();
        completion
    }

    // Check protocol status at the same boundary a guest driver observes.
    async fn expect(&mut self, command: Command, status: spec::Status) -> Completion {
        let completion = self.submit(command).await;
        assert_eq!(completion.status.status(), status.0);
        completion
    }
}

// Build an admin request without setting fields unrelated to the selected command.
fn admin(opcode: spec::AdminOpcode) -> Command {
    let mut command = Command::new_zeroed();
    command.cdw0.set_opcode(opcode.0);
    command
}

// Test: Set and get mutable features, including a request to disable the always-on write cache.
// Expected: Values round-trip through completions while unsupported saving and invalid values fail.
#[async_test]
async fn features_round_trip_and_reject_invalid_updates(driver: DefaultDriver) {
    let mut h = AdminHarness::new(driver).await;
    for (feature, value, query) in [
        (spec::Feature::ARBITRATION, 0x1234, 0),
        (spec::Feature::POWER_MANAGEMENT, 0x60, 0),
        (spec::Feature::ERROR_RECOVERY, 0x5678, 0),
        (spec::Feature::INTERRUPT_COALESCING, 0x3456, 0),
        (spec::Feature::INTERRUPT_VECTOR_CONFIG, 0x10001, 1),
        (spec::Feature::VOLATILE_WRITE_CACHE, 0, 0),
    ] {
        let mut set = admin(spec::AdminOpcode::SET_FEATURES);
        set.cdw10 = feature.0.into();
        set.cdw11 = value;
        h.expect(set, spec::Status::SUCCESS).await;
        let got = h
            .expect(get_feature_command(feature, query), spec::Status::SUCCESS)
            .await;
        let expected = if feature == spec::Feature::VOLATILE_WRITE_CACHE {
            1
        } else {
            value
        };
        assert_eq!(got.dw0, expected);
    }
    for (feature, value) in [
        (spec::Feature::NUMBER_OF_QUEUES, 0xffff),
        (spec::Feature::NUMBER_OF_QUEUES, 0xffff_0000),
        (spec::Feature::POWER_MANAGEMENT, 1),
        (spec::Feature::TEMPERATURE_THRESHOLD, 2 << 20),
        (spec::Feature::INTERRUPT_VECTOR_CONFIG, 64),
        (spec::Feature(0xfe), 0),
    ] {
        let mut command = admin(spec::AdminOpcode::SET_FEATURES);
        command.cdw10 = feature.0.into();
        command.cdw11 = value;
        h.expect(command, spec::Status::INVALID_FIELD_IN_COMMAND)
            .await;
    }
    let mut saved = admin(spec::AdminOpcode::SET_FEATURES);
    saved.cdw10 = u32::from(spec::Feature::ARBITRATION.0) | (1 << 31);
    saved.cdw11 = 0xeeee;
    h.expect(saved, spec::Status::FEATURE_IDENTIFIER_NOT_SAVEABLE)
        .await;
    assert_eq!(
        h.expect(
            get_feature_command(spec::Feature::ARBITRATION, 0),
            spec::Status::SUCCESS
        )
        .await
        .dw0,
        0x1234
    );
    for command in [
        get_feature_command(spec::Feature(0xfe), 0),
        get_feature_command(spec::Feature::INTERRUPT_VECTOR_CONFIG, 64),
        get_feature_command(spec::Feature::TEMPERATURE_THRESHOLD, 2 << 20),
        {
            let mut selected = get_feature_command(spec::Feature::ARBITRATION, 0);
            selected.cdw10 |= 1 << 8;
            selected
        },
    ] {
        h.expect(command, spec::Status::INVALID_FIELD_IN_COMMAND)
            .await;
    }
}

// Test: Resize queue allocations, create/delete a queue pair, and issue invalid queue requests.
// Expected: Status codes distinguish identifier, size, vector and sequence errors; deleted IDs are reusable.
#[async_test]
async fn queue_validation_deletion_and_identifier_reuse(driver: DefaultDriver) {
    let mut h = AdminHarness::new(driver).await;
    let mut set = admin(spec::AdminOpcode::SET_FEATURES);
    set.cdw10 = spec::Feature::NUMBER_OF_QUEUES.0.into();
    set.cdw11 = 0x0063_0063;
    assert_eq!(h.expect(set, spec::Status::SUCCESS).await.dw0, 0x003f_003f);
    set.cdw11 = 0x0002_0001;
    assert_eq!(h.expect(set, spec::Status::SUCCESS).await.dw0, 0x0002_0001);
    assert_eq!(
        h.expect(
            get_feature_command(spec::Feature::NUMBER_OF_QUEUES, 0),
            spec::Status::SUCCESS
        )
        .await
        .dw0,
        0x0002_0001
    );
    let mut cq = admin(spec::AdminOpcode::CREATE_IO_COMPLETION_QUEUE);
    cq.dptr[0] = 0x4000;
    cq.cdw10 = 1 | (3 << 16);
    cq.cdw11 = 1;
    for (cdw10, cdw11, status) in [
        (3 << 16, 1, spec::Status::INVALID_QUEUE_IDENTIFIER),
        (4 | (3 << 16), 1, spec::Status::INVALID_QUEUE_IDENTIFIER),
        (1, 1, spec::Status::INVALID_QUEUE_SIZE),
        (1 | (256 << 16), 1, spec::Status::INVALID_QUEUE_SIZE),
        (cq.cdw10, 0, spec::Status::INVALID_FIELD_IN_COMMAND),
        (
            cq.cdw10,
            3 | (64 << 16),
            spec::Status::INVALID_INTERRUPT_VECTOR,
        ),
    ] {
        h.expect(Command { cdw10, cdw11, ..cq }, status).await;
    }
    h.expect(cq, spec::Status::SUCCESS).await;
    h.expect(cq, spec::Status::INVALID_QUEUE_IDENTIFIER).await;
    h.expect(set, spec::Status::COMMAND_SEQUENCE_ERROR).await;
    let mut sq = admin(spec::AdminOpcode::CREATE_IO_SUBMISSION_QUEUE);
    sq.dptr[0] = 0x5000;
    sq.cdw10 = 1 | (3 << 16);
    sq.cdw11 = 1 | (1 << 16);
    for (cdw10, cdw11, status) in [
        (3 << 16, sq.cdw11, spec::Status::INVALID_QUEUE_IDENTIFIER),
        (
            3 | (3 << 16),
            sq.cdw11,
            spec::Status::INVALID_QUEUE_IDENTIFIER,
        ),
        (sq.cdw10, 1, spec::Status::COMPLETION_QUEUE_INVALID),
        (1, sq.cdw11, spec::Status::INVALID_QUEUE_SIZE),
        (sq.cdw10, 1 << 16, spec::Status::INVALID_FIELD_IN_COMMAND),
    ] {
        h.expect(Command { cdw10, cdw11, ..sq }, status).await;
    }
    h.expect(sq, spec::Status::SUCCESS).await;
    h.expect(sq, spec::Status::INVALID_QUEUE_IDENTIFIER).await;
    h.expect(
        Command {
            cdw10: 2 | (3 << 16),
            ..sq
        },
        spec::Status::COMPLETION_QUEUE_INVALID,
    )
    .await;
    let mut delete_cq = admin(spec::AdminOpcode::DELETE_IO_COMPLETION_QUEUE);
    delete_cq.cdw10 = 1;
    h.expect(delete_cq, spec::Status::INVALID_QUEUE_DELETION)
        .await;
    let mut delete_sq = admin(spec::AdminOpcode::DELETE_IO_SUBMISSION_QUEUE);
    delete_sq.cdw10 = 1;
    h.expect(delete_sq, spec::Status::SUCCESS).await;
    h.expect(delete_sq, spec::Status::INVALID_QUEUE_IDENTIFIER)
        .await;
    h.expect(delete_cq, spec::Status::SUCCESS).await;
    h.expect(delete_cq, spec::Status::INVALID_QUEUE_IDENTIFIER)
        .await;
    h.expect(cq, spec::Status::SUCCESS).await;
    h.expect(sq, spec::Status::SUCCESS).await;
}

// Test: Identify active/inactive namespaces and unsupported command-set selectors.
// Expected: The guest receives sorted namespace IDs, real capacity/IDs, zeroed inactive data, and precise errors.
#[async_test]
async fn identify_namespace_lists_descriptors_and_selector_validation(driver: DefaultDriver) {
    let mut h = AdminHarness::new(driver).await;
    let disk = ram_disk(1 << 20, false).unwrap();
    let disk_id = disk.disk_id().unwrap_or([0; 16]);
    h.controller
        .client()
        .add_namespace(7, ram_disk(1 << 20, false).unwrap())
        .await
        .unwrap();
    h.controller.client().add_namespace(1, disk).await.unwrap();
    assert!(
        h.controller
            .client()
            .add_namespace(1, ram_disk(1 << 20, false).unwrap())
            .await
            .is_err()
    );
    for nsid in [0, MAX_NSID + 1] {
        assert!(
            h.controller
                .client()
                .add_namespace(nsid, ram_disk(1 << 20, false).unwrap())
                .await
                .is_err()
        );
    }
    let mut identify = admin(spec::AdminOpcode::IDENTIFY);
    identify.dptr[0] = 0x8000;
    for (start, expected) in [(0, [1u32, 7, 0]), (1, [7, 0, 0]), (7, [0, 0, 0])] {
        identify.nsid = start;
        identify.cdw10 = spec::Cns::ACTIVE_NAMESPACES.0.into();
        h.expect(identify, spec::Status::SUCCESS).await;
        assert_eq!(h.mem.read_plain::<[u32; 3]>(0x8000).unwrap(), expected);
    }
    identify.nsid = 0xffff_fffe;
    h.expect(identify, spec::Status::INVALID_NAMESPACE_OR_FORMAT)
        .await;
    identify.nsid = 1;
    identify.cdw10 = spec::Cns::NAMESPACE.0.into();
    h.expect(identify, spec::Status::SUCCESS).await;
    let namespace = h.mem.read_plain::<nvm::IdentifyNamespace>(0x8000).unwrap();
    assert_eq!(
        (namespace.nsze, namespace.ncap, namespace.nuse),
        (2048, 2048, 2048)
    );
    assert_eq!(namespace.lbaf[0].lbads(), 9);
    identify.cdw10 = spec::Cns::DESCRIPTOR_NAMESPACE.0.into();
    h.expect(identify, spec::Status::SUCCESS).await;
    let descriptor = h
        .mem
        .read_plain::<nvm::NamespaceIdentificationDescriptor>(0x8000)
        .unwrap();
    assert_eq!(
        (descriptor.nidt, descriptor.nidl),
        (nvm::NamespaceIdentifierType::NSGUID.0, 16)
    );
    assert_eq!(descriptor.nid, disk_id);
    for cns in [
        spec::Cns::NAMESPACE,
        spec::Cns::DESCRIPTOR_NAMESPACE,
        spec::Cns::SPECIFIC_CONTROLLER_IO_COMMAND_SET,
    ] {
        identify.cdw10 = cns.0.into();
        identify.nsid = 2;
        h.mem.write_at(0x8000, &[0xa5; 4096]).unwrap();
        h.expect(identify, spec::Status::SUCCESS).await;
        assert_eq!(h.mem.read_plain::<[u8; 4096]>(0x8000).unwrap(), [0; 4096]);
    }
    for (cns, nsid, cdw11, status) in [
        (
            spec::Cns::NAMESPACE,
            0,
            0,
            spec::Status::INVALID_NAMESPACE_OR_FORMAT,
        ),
        (
            spec::Cns::DESCRIPTOR_NAMESPACE,
            MAX_NSID + 1,
            0,
            spec::Status::INVALID_NAMESPACE_OR_FORMAT,
        ),
        (
            spec::Cns::SPECIFIC_CONTROLLER_IO_COMMAND_SET,
            0,
            1 << 24,
            spec::Status::INVALID_FIELD_IN_COMMAND,
        ),
        (
            spec::Cns(0xfe),
            0,
            0,
            spec::Status::INVALID_FIELD_IN_COMMAND,
        ),
    ] {
        identify.cdw10 = cns.0.into();
        identify.nsid = nsid;
        identify.cdw11 = cdw11;
        h.expect(identify, status).await;
    }
}

// IGNORED: The admin handler captures the opcode before applying submission
//          updates, so changing the opcode does not select the new handler.
//
// Test: Replace an unsupported submission opcode with a valid Abort command.
// Expected: The replacement is executed and returns Abort's successful "not aborted" result.
#[async_test]
#[ignore = "product bug: submission update dispatches the original opcode"]
async fn submission_fault_opcode_replacement_selects_the_new_handler(driver: DefaultDriver) {
    let mut replacement = admin(spec::AdminOpcode::ABORT);
    replacement.cdw0.set_cid(0x100);
    let faults = FaultConfiguration::new(CellUpdater::new(true).cell()).with_admin_queue_fault(
        AdminQueueFaultConfig::new().with_submission_queue_fault(
            cid_pattern(0x100),
            AdminQueueFaultBehavior::Update(replacement),
        ),
    );
    let mut h = AdminHarness::with_faults(driver, faults).await;
    assert_eq!(
        h.expect(admin(spec::AdminOpcode(0xff)), spec::Status::SUCCESS)
            .await
            .dw0,
        1
    );
}

// Test: Reject malformed register accesses and update the halves of disabled 64-bit queue registers.
// Expected: Access errors are precise, reserved registers read zero, and each half preserves its neighbor.
#[async_test]
async fn register_width_alignment_masks_and_split_queue_addresses(driver: DefaultDriver) {
    use chipset_device::io::{IoError, IoResult};
    let mem = test_memory();
    let mut controller = instantiate_controller(
        driver,
        &mem,
        None,
        FaultConfiguration::new(CellUpdater::new(false).cell()),
    );
    for (address, len, expected) in [
        (0, 3, IoError::InvalidAccessSize),
        (1, 4, IoError::UnalignedAccess),
        (8, 8, IoError::InvalidAccessSize),
        (0x80, 4, IoError::InvalidRegister),
    ] {
        assert!(
            matches!(controller.read_bar0(address, &mut vec![0; len]), IoResult::Err(error) if std::mem::discriminant(&error) == std::mem::discriminant(&expected))
        );
    }
    for (address, len, expected) in [
        (0, 3, IoError::InvalidAccessSize),
        (1, 4, IoError::UnalignedAccess),
        (8, 8, IoError::InvalidAccessSize),
        (0x80, 4, IoError::InvalidRegister),
        (0x1001, 4, IoError::InvalidRegister),
        (0x1000, 8, IoError::InvalidAccessSize),
        (0x41000, 4, IoError::InvalidRegister),
    ] {
        assert!(
            matches!(controller.write_bar0(address, &vec![0; len]), IoResult::Err(error) if std::mem::discriminant(&error) == std::mem::discriminant(&expected))
        );
    }
    for address in [0x18, 0x20, 0x38, 0x3c, 0x40, 0x44, 0x48, 0x4c] {
        let mut value = [0xff; 4];
        controller.read_bar0(address, &mut value).unwrap();
        assert_eq!(value, [0; 4]);
    }
    for address in [0x28, 0x30] {
        controller
            .write_bar0(address, 0x89ab_cfffu32.as_bytes())
            .unwrap();
        controller
            .write_bar0(address + 4, 0x0123_4567u32.as_bytes())
            .unwrap();
        let mut value = 0u64;
        controller.read_bar0(address, value.as_mut_bytes()).unwrap();
        assert_eq!(value, 0x0123_4567_89ab_c000);
        let mut high = 0u32;
        controller
            .read_bar0(address + 4, high.as_mut_bytes())
            .unwrap();
        assert_eq!(high, 0x0123_4567);
    }
    controller.write_bar0(0x0c, 0xf0f0u32.as_bytes()).unwrap();
    controller.write_bar0(0x0c, 0x0f0fu32.as_bytes()).unwrap();
    controller.write_bar0(0x10, 0x00ffu32.as_bytes()).unwrap();
    for address in [0x0c, 0x10] {
        let mut value = 0u32;
        controller.read_bar0(address, value.as_mut_bytes()).unwrap();
        assert_eq!(value, 0xff00);
    }
}

// Test: Write queue bases while enabled, request shutdown, reset the controller, then reset the device.
// Expected: Enabled bases are protected; controller reset preserves queues, while device reset clears them.
#[async_test]
async fn controller_and_device_reset_have_distinct_register_contracts(driver: DefaultDriver) {
    use chipset_device::io::IoResult;
    use vmcore::device_state::ChangeDeviceState;
    let mut h = AdminHarness::new(driver.clone()).await;
    for address in [0x28, 0x30] {
        h.controller
            .write_bar0(address, 0x9000u64.as_bytes())
            .unwrap();
        let mut value = 0u64;
        h.controller
            .read_bar0(address, value.as_mut_bytes())
            .unwrap();
        assert_eq!(value, if address == 0x28 { 0x1000 } else { 0 });
    }
    let mut cc = 0u32;
    h.controller.read_bar0(0x14, cc.as_mut_bytes()).unwrap();
    let shutdown = spec::Cc::from(cc).with_shn(1);
    h.controller
        .write_bar0(0x14, u32::from(shutdown).as_bytes())
        .unwrap();
    let mut status = 0u32;
    h.controller.read_bar0(0x1c, status.as_mut_bytes()).unwrap();
    assert_eq!(spec::Csts::from(status).shst(), 2);
    h.controller.write_bar0(0x0c, 0xffffu32.as_bytes()).unwrap();
    h.controller.write_bar0(0x14, 0u32.as_bytes()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut timer = PolledTimer::new(&driver);
    loop {
        h.controller.read_bar0(0x1c, status.as_mut_bytes()).unwrap();
        if !spec::Csts::from(status).rdy() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "controller reset timed out"
        );
        timer.sleep(Duration::from_millis(1)).await;
    }
    for (address, expected) in [
        (0x14, 0),
        (0x0c, 0),
        (0x24, 0x003f_003f),
        (0x28, 0x1000),
        (0x30, 0),
    ] {
        let mut value = 0u32;
        h.controller
            .read_bar0(address, value.as_mut_bytes())
            .unwrap();
        assert_eq!(value, expected);
    }
    h.controller.reset().await;
    for address in [0x14, 0x24, 0x28, 0x30] {
        let mut value = 0u32;
        h.controller
            .read_bar0(address, value.as_mut_bytes())
            .unwrap();
        assert_eq!(value, 0);
    }
    assert!(matches!(
        h.controller.mmio_read(0, &mut [0; 4]),
        IoResult::Err(_)
    ));
}

// Test: Report changed namespaces through an AER, consume their sorted log, then notify again.
// Expected: The AER carries the namespace-change event and consuming the log rearms notification.
#[async_test]
async fn namespace_change_events_and_log_consumption_rearm_notifications(driver: DefaultDriver) {
    use mesh::rpc::RpcSend;
    use nvme_resources::fault::{NamespaceChange, NamespaceFaultConfig};
    let (changes, recv) = mesh::channel();
    let faults = FaultConfiguration::new(CellUpdater::new(false).cell())
        .with_namespace_fault(NamespaceFaultConfig::new(recv));
    let mut h = AdminHarness::with_faults(driver, faults).await;
    let mut event = admin(spec::AdminOpcode::ASYNCHRONOUS_EVENT_REQUEST);
    event.cdw0.set_cid(0xa1);
    write_command_to_queue(&h.mem, &h.asq, 0, &event);
    h.controller.write_bar0(0x1000, 1u32.as_bytes()).unwrap();
    changes
        .call(NamespaceChange::ChangeNotification, 7)
        .await
        .unwrap();
    wait_for_msi(h.driver.clone(), &h.interrupts, 1000, 0xfeed0000, 0x1111).await;
    let completion = read_completion_from_queue(&h.mem, &h.acq, 0);
    assert_eq!(completion.cid, 0xa1);
    assert_eq!(completion.status.status(), spec::Status::SUCCESS.0);
    let notice = spec::AsynchronousEventRequestDw0::from(completion.dw0);
    assert_eq!(notice.event_type(), spec::AsynchronousEventType::NOTICE.0);
    assert_eq!(
        notice.log_page_identifier(),
        spec::LogPageIdentifier::CHANGED_NAMESPACE_LIST.0
    );
    assert_eq!(
        notice.information(),
        spec::AsynchronousEventInformationNotice::NAMESPACE_ATTRIBUTE_CHANGED.0
    );
    h.slot = 1;
    h.controller.write_bar0(0x1004, 1u32.as_bytes()).unwrap();
    for nsid in [3, 1] {
        h.controller
            .client()
            .add_namespace(nsid, ram_disk(1 << 20, false).unwrap())
            .await
            .unwrap();
    }
    let mut log = admin(spec::AdminOpcode::GET_LOG_PAGE);
    log.cdw10 = u32::from(spec::LogPageIdentifier::CHANGED_NAMESPACE_LIST.0) | (1023 << 16);
    log.dptr[0] = 0x8000;
    h.expect(log, spec::Status::SUCCESS).await;
    assert_eq!(h.mem.read_plain::<[u32; 4]>(0x8000).unwrap(), [1, 3, 7, 0]);
    event.cdw0.set_cid(0xa2);
    write_command_to_queue(&h.mem, &h.asq, 2, &event);
    h.controller.write_bar0(0x1000, 3u32.as_bytes()).unwrap();
    changes
        .call(NamespaceChange::ChangeNotification, 9)
        .await
        .unwrap();
    wait_for_msi(h.driver.clone(), &h.interrupts, 1000, 0xfeed0000, 0x1111).await;
    let completion = read_completion_from_queue(&h.mem, &h.acq, 2);
    assert_eq!(completion.cid, 0xa2);
    assert_eq!(completion.status.status(), spec::Status::SUCCESS.0);
}

// Test: Enable with unsupported page, command-set and I/O queue-entry sizes.
// Expected: Each invalid configuration sets fatal status without making the controller ready or enabled.
#[async_test]
async fn invalid_controller_configuration_reports_fatal_without_enabling(driver: DefaultDriver) {
    let enabled = spec::Cc::new().with_en(true);
    for config in [
        enabled.with_mps(1),
        enabled.with_css(1),
        enabled.with_iocqes(5),
        enabled.with_iosqes(7),
    ] {
        let mem = test_memory();
        let mut controller = instantiate_controller(
            driver.clone(),
            &mem,
            None,
            FaultConfiguration::new(CellUpdater::new(false).cell()),
        );
        controller
            .write_bar0(0x14, u32::from(config).as_bytes())
            .unwrap();
        let mut status = 0u32;
        controller.read_bar0(0x1c, status.as_mut_bytes()).unwrap();
        let status = spec::Csts::from(status);
        assert!(status.cfs(), "configuration {config:?} must fail");
        assert!(!status.rdy());
        let mut cc = 0u32;
        controller.read_bar0(0x14, cc.as_mut_bytes()).unwrap();
        assert!(!spec::Cc::from(cc).en());
    }
}

// Test: Reuse admin queue slots with different submission and completion depths.
// Expected: Completions keep the right command ID, SQ head and status across wraps;
//       their phase changes each CQ lap, leaving the next unwritten slot stale.
#[async_test]
async fn admin_queue_wraps_preserve_completion_identity_and_phase(driver: DefaultDriver) {
    let mem = test_memory();
    let acq = PrpRange::new(vec![0], 0, PAGE_SIZE64).unwrap();
    let asq = PrpRange::new(vec![0x1000], 0, PAGE_SIZE64).unwrap();
    let interrupts = TestPciInterruptController::new();
    let mut controller = instantiate_and_build_admin_queue(
        &acq,
        4,
        &asq,
        8,
        true,
        Some(&interrupts),
        driver.clone(),
        &mem,
        FaultConfiguration::new(CellUpdater::new(false).cell()),
    )
    .await;
    for sequence in 0..20u32 {
        let next_sq = (sequence + 1) % 8;
        let next_cq = (sequence + 1) % 4;
        let mut command = admin(spec::AdminOpcode::ABORT);
        command.cdw0.set_cid(0xa00 + sequence as u16);
        write_command_to_queue(&mem, &asq, (sequence % 8) as usize, &command);
        controller.write_bar0(0x1000, next_sq.as_bytes()).unwrap();
        wait_for_msi(driver.clone(), &interrupts, 1000, 0xfeed0000, 0x1111).await;
        let result = read_completion_from_queue(&mem, &acq, (sequence % 4) as usize);
        assert_eq!(result.cid, command.cdw0.cid());
        assert_eq!(result.sqhd, next_sq as u16);
        assert_eq!(result.sqid, 0);
        assert_eq!(result.status.status(), spec::Status::SUCCESS.0);
        assert_eq!(result.dw0, 1);
        assert_eq!(result.status.phase(), (sequence / 4) % 2 == 0);
        let unwritten = read_completion_from_queue(&mem, &acq, next_cq as usize);
        assert_ne!(unwritten.status.phase(), ((sequence + 1) / 4) % 2 == 0);
        controller.write_bar0(0x1004, next_cq.as_bytes()).unwrap();
    }
}
