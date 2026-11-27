// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vmcore::save_restore::{RestoreError, SaveRestore};

fn register(tpm: &mut Tpm, offset: usize) -> u32 {
    let mut bytes = [0; 4];
    assert!(matches!(
        tpm.mmio_read(
            TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + offset as u64,
            &mut bytes
        ),
        IoResult::Ok
    ));
    u32::from_le_bytes(bytes)
}

fn select(tpm: &mut Tpm, command: TpmIoCommand) {
    assert!(matches!(
        tpm.io_write(TPM_DEVICE_IO_PORT_RANGE_BEGIN, &command.0.to_le_bytes()),
        IoResult::Ok
    ));
}

fn port_value(tpm: &mut Tpm, command: TpmIoCommand) -> u32 {
    select(tpm, command);
    let mut bytes = [0; 4];
    assert!(matches!(
        tpm.io_read(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &mut bytes),
        IoResult::Ok
    ));
    u32::from_le_bytes(bytes)
}

async fn finish(tpm: &mut Tpm, result: IoResult) {
    match result {
        IoResult::Ok => {}
        IoResult::Defer(mut token) => complete(tpm, &mut token).await,
        other => panic!("unexpected I/O result: {other:?}"),
    }
}

async fn map(tpm: &mut Tpm, address: u32) {
    select(tpm, TpmIoCommand::MAP_SHARED_MEMORY);
    let result = tpm.io_write(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &address.to_le_bytes());
    finish(tpm, result).await;
}

// Test: Read CRB registers bytewise and as words after mapping across 4 GiB,
//       and request/relinquish locality using the guest interface.
// Expected: Native register widths agree, high address bits are preserved,
//       and locality status changes without corrupting other registers.
#[test]
fn crb_registers_preserve_address_width_and_locality() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            let mut tpm = new_test_tpm(version, None, None, TpmAkCertType::None, false)
                .await
                .unwrap();
            map(&mut tpm, u32::MAX).await;
            for (offset, expected) in [
                (0x00, 0x81),
                (0x08, 0),
                (0x0c, 1),
                (0x30, 0x4011),
                (0x40, 0),
                (0x44, 0),
                (0x48, 0),
                (0x4c, 0),
                (0x58, 4096),
                (0x5c, u32::MAX),
                (0x60, 0),
                (0x64, 4096),
                (0x68, 4095),
                (0x6c, 1),
            ] {
                assert_eq!(register(&mut tpm, offset), expected);
                let mut bytes = [0; 4];
                for (lane, byte) in bytes.iter_mut().enumerate() {
                    assert!(matches!(
                        tpm.mmio_read(
                            TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + (offset + lane) as u64,
                            std::slice::from_mut(byte)
                        ),
                        IoResult::Ok
                    ));
                }
                assert_eq!(u32::from_le_bytes(bytes), expected);
                for lane in [0, 2] {
                    let mut half = [0; 2];
                    assert!(matches!(
                        tpm.mmio_read(
                            TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + (offset + lane) as u64,
                            &mut half
                        ),
                        IoResult::Ok
                    ));
                    assert_eq!(half, expected.to_le_bytes()[lane..lane + 2]);
                }
            }
            for (offset, expected) in [
                (0x30, 0x4011u64),
                (0x5c, u32::MAX as u64),
                (0x68, 0x1_0000_0fff),
            ] {
                let mut bytes = [0; 8];
                assert!(matches!(
                    tpm.mmio_read(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + offset, &mut bytes),
                    IoResult::Ok
                ));
                assert_eq!(u64::from_le_bytes(bytes), expected);
            }
            assert!(matches!(
                tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 8, &[1]),
                IoResult::Ok
            ));
            assert_eq!(register(&mut tpm, 0), 0x83);
            assert!(matches!(
                tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 8, &[2, 0]),
                IoResult::Ok
            ));
            assert_eq!(register(&mut tpm, 0), 0x81);
        }
    });
}

// Test: Issue malformed register accesses and unknown port commands.
// Expected: Typed I/O errors reject bad sizes/offsets; unsupported commands
//       do not write a fabricated response or change the mapped buffers.
#[test]
fn invalid_accesses_preserve_guest_buffers_and_mapping() {
    pal_async::DefaultPool::run_with(async |_| {
        let mut tpm = new_test_tpm(TpmVersion::V185, None, None, TpmAkCertType::None, false)
            .await
            .unwrap();
        map(&mut tpm, 0x2000).await;
        for len in [0, 3, 8, 16] {
            let mut data = vec![0xa5; len];
            assert!(matches!(
                tpm.mmio_read(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x44, &mut data),
                IoResult::Err(IoError::InvalidAccessSize)
            ));
            assert_eq!(data, vec![0xa5; len]);
            assert!(matches!(
                tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x48, &data),
                IoResult::Err(IoError::InvalidAccessSize)
            ));
        }
        assert!(matches!(
            tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x49, &[1]),
            IoResult::Err(IoError::UnalignedAccess)
        ));
        assert!(matches!(
            tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x24, &[1]),
            IoResult::Err(IoError::InvalidRegister)
        ));
        let mut bytes = [0xa5; 4];
        assert!(matches!(
            tpm.mmio_read(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x24, &mut bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert_eq!(bytes, [0xa5; 4]);
        assert!(matches!(
            tpm.io_read(TPM_DEVICE_IO_PORT_RANGE_BEGIN, &mut bytes),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            tpm.io_write(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 8, &[0; 4]),
            IoResult::Err(IoError::InvalidRegister)
        ));
        select(&mut tpm, TpmIoCommand(u32::MAX));
        assert!(matches!(
            tpm.io_read(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &mut bytes),
            IoResult::Ok
        ));
        assert_eq!(bytes, [0xa5; 4]);
        assert!(matches!(
            tpm.io_write(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &[0; 4]),
            IoResult::Ok
        ));
        assert_eq!(port_value(&mut tpm, TpmIoCommand::ESTABLISHED), 0x2000);
        select(&mut tpm, TpmIoCommand::ESTABLISHED);
        assert!(matches!(
            tpm.io_read(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &mut [0; 2]),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    });
}

// Test: Execute a guest SelfTest command through CRB shared memory on both
//       reference engines, including cancellation register normalization.
// Expected: START clears on completion, the TPM returns success, and writes
//       remain inside the response page.
#[test]
fn crb_commands_complete_and_preserve_memory_guards() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            let mut tpm = new_test_tpm(version, None, None, TpmAkCertType::None, false)
                .await
                .unwrap();
            map(&mut tpm, 0x2000).await;
            let gm = tpm.rt.mem.clone();
            gm.write_at(0x1ff0, &[0xa5; 16]).unwrap();
            gm.write_at(0x4000, &[0x5a; 16]).unwrap();
            gm.write_at(0x2000, &[0x80, 1, 0, 0, 0, 11, 0, 0, 1, 0x43, 0])
                .unwrap();
            for (value, expected) in [(u32::MAX, 1), (0, 0)] {
                assert!(matches!(
                    tpm.mmio_write(
                        TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x48,
                        &value.to_le_bytes()
                    ),
                    IoResult::Ok
                ));
                assert_eq!(register(&mut tpm, 0x48), expected);
            }
            let result = tpm.mmio_write(
                TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x4c,
                &1u32.to_le_bytes(),
            );
            finish(&mut tpm, result).await;
            assert_eq!(register(&mut tpm, 0x4c), 0);
            let reply: [u8; 10] = gm.read_plain(0x3000).unwrap();
            assert_eq!(&reply[..2], &[0x80, 1]);
            assert_eq!(u32::from_be_bytes(reply[2..6].try_into().unwrap()), 10);
            assert_eq!(&reply[6..], &[0; 4]);
            assert_eq!(gm.read_plain::<[u8; 16]>(0x1ff0).unwrap(), [0xa5; 16]);
            assert_eq!(gm.read_plain::<[u8; 16]>(0x4000).unwrap(), [0x5a; 16]);
            tpm.reset().await;
            assert_eq!(register(&mut tpm, 0x58), 0);
            assert_eq!(register(&mut tpm, 0x5c), 0);
            assert_eq!(register(&mut tpm, 0), 0x81);
            map(&mut tpm, 0x2000).await;
            let result = tpm.mmio_write(
                TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x4c,
                &1u32.to_le_bytes(),
            );
            finish(&mut tpm, result).await;
            assert_eq!(register(&mut tpm, 0x4c), 0);
        }
    });
}

// Test: Save and restore a device after guest mapping/locality/PPI changes.
// Expected: Both engines restore the guest-visible values and command
//       selection, and a legacy state without optional renewal data loads.
#[test]
fn saved_device_roundtrip_restores_guest_contract() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            let mut tpm = new_test_tpm(version, None, None, TpmAkCertType::None, false)
                .await
                .unwrap();
            map(&mut tpm, 0x2000).await;
            let mut token = issue_ppi_write(&mut tpm, u32::MAX);
            complete(&mut tpm, &mut token).await;
            assert!(matches!(
                tpm.mmio_write(TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 8, &[1]),
                IoResult::Ok
            ));
            select(&mut tpm, TpmIoCommand::PPI_GET_PENDING_OPERATION);
            let mut state = tpm.save().unwrap();
            state.allow_ak_cert_renewal = None;
            if version == TpmVersion::V138 {
                state.version = None;
            }
            map(&mut tpm, 0x6000).await;
            tpm.restore(state).unwrap();
            let mut bytes = [0; 4];
            assert!(matches!(
                tpm.io_read(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &mut bytes),
                IoResult::Ok
            ));
            assert_eq!(u32::from_le_bytes(bytes), u32::MAX);
            assert_eq!(register(&mut tpm, 0x5c), 0x2000);
            assert_eq!(register(&mut tpm, 0x68), 0x3000);
            assert_eq!(register(&mut tpm, 0), 0x83);
            assert_eq!(
                port_value(&mut tpm, TpmIoCommand::GET_TCG_PROTOCOL_VERSION),
                1
            );
            assert_eq!(
                port_value(&mut tpm, TpmIoCommand::PPI_GET_USER_CONFIRMATION),
                4
            );
        }
    });
}

// Test: Restore a state produced by another TPM reference version.
// Expected: Version mismatch returns a typed error before replacing the
//       receiving device's register mapping.
#[test]
fn mismatched_saved_version_does_not_replace_mapping() {
    pal_async::DefaultPool::run_with(async |_| {
        let mut old = new_test_tpm(TpmVersion::V138, None, None, TpmAkCertType::None, false)
            .await
            .unwrap();
        let mut new = new_test_tpm(TpmVersion::V185, None, None, TpmAkCertType::None, false)
            .await
            .unwrap();
        map(&mut old, 0x2000).await;
        map(&mut new, 0x6000).await;
        let RestoreError::Other(error) = new.restore(old.save().unwrap()).unwrap_err() else {
            panic!("typed version error expected");
        };
        assert!(matches!(
            error.downcast_ref::<save_restore::TpmRestoreError>(),
            Some(save_restore::TpmRestoreError::VersionMismatch { .. })
        ));
        assert_eq!(register(&mut new, 0x5c), 0x6000);
        assert_eq!(register(&mut new, 0x68), 0x7000);
    });
}

// Test: Transport persisted PPI records containing unknown future operations.
// Expected: All seven fields survive byte serialization, while a truncated or
//       overlong record is rejected rather than silently partially restored.
#[test]
fn persisted_ppi_records_preserve_future_operations() {
    let words = [u32::MAX, 0x8000_0000, 3, 0xdead_beef, 5, 6, 7];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_ne_bytes).collect();
    let state = persist_restore::deserialize_ppi_state(bytes.clone()).unwrap();
    assert_eq!(persist_restore::serialize_ppi_state(state), bytes);
    for len in 0..bytes.len() {
        assert!(persist_restore::deserialize_ppi_state(bytes[..len].to_vec()).is_none());
    }
    let mut overlong = bytes;
    overlong.push(0);
    assert!(persist_restore::deserialize_ppi_state(overlong).is_none());
}

// Test: Execute guest-requested clear operations and a PCR-bank allocation.
// Expected: Completed operations move from pending to last-operation with a
//       successful result, including after the allocation's engine restart.
#[test]
fn ppi_operations_publish_completion_results() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            let mut tpm = new_test_tpm(version, None, None, TpmAkCertType::None, false)
                .await
                .unwrap();
            for operation in [
                PpiOperation::CLEAR,
                PpiOperation::CLEAR_ENABLE_ACTIVATE,
                PpiOperation::ENABLE_ACTIVATE_CLEAR,
                PpiOperation::ENABLE_ACTIVATE_CLEAR_ENABLE_ACTIVATE,
            ] {
                let mut token = issue_ppi_write(&mut tpm, operation.0);
                complete(&mut tpm, &mut token).await;
                tpm.execute_pending_ppi().unwrap();
                assert_eq!(
                    port_value(&mut tpm, TpmIoCommand::PPI_GET_PENDING_OPERATION),
                    0
                );
                assert_eq!(
                    port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_OPERATION),
                    operation.0
                );
                assert_eq!(port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_RESULT), 0);
            }
            for command in [
                TpmIoCommand::CAPABILITY_HASH_ALG_BITMAP,
                TpmIoCommand::PPI_SET_OPERATION_ARG3_INTEGER2,
            ] {
                select(&mut tpm, command);
                let result = tpm.io_write(TPM_DEVICE_IO_PORT_RANGE_BEGIN + 4, &3u32.to_le_bytes());
                finish(&mut tpm, result).await;
            }
            let mut token = issue_ppi_write(&mut tpm, PpiOperation::SET_PCR_BANKS.0);
            complete(&mut tpm, &mut token).await;
            tpm.execute_pending_ppi().unwrap();
            assert_eq!(
                port_value(&mut tpm, TpmIoCommand::PPI_GET_PENDING_OPERATION),
                0
            );
            assert_eq!(
                port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_OPERATION),
                PpiOperation::SET_PCR_BANKS.0
            );
            assert_eq!(port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_RESULT), 0);
        }
    });
}

struct EchoAttestationInput;

#[async_trait::async_trait]
impl RequestAkCert for EchoAttestationInput {
    fn create_ak_cert_request(
        &self,
        ak_modulus: &[u8],
        ak_exponent: &[u8],
        ek_modulus: &[u8],
        ek_exponent: &[u8],
        guest_input: &[u8],
        _is_report: bool,
        existing_cert: Option<&[u8]>,
    ) -> Result<tpm_resources::AkCertRequest, Box<dyn std::error::Error + Send + Sync>> {
        assert_eq!(ak_modulus.len(), 256);
        assert_eq!(ek_modulus.len(), 256);
        assert_eq!(ak_exponent, [1, 0, 1]);
        assert_eq!(ek_exponent, [1, 0, 1]);
        Ok(tpm_resources::AkCertRequest {
            data: guest_input.to_vec(),
            has_cert: existing_cert.is_some(),
        })
    }

    async fn request_ak_cert(
        &self,
        _request: Vec<u8>,
    ) -> Result<AkCertResponse, Box<dyn std::error::Error + Send + Sync>> {
        Ok(AkCertResponse::Certificate(vec![0x5a; 32]))
    }
}

// Test: Provision an attested device, bind a report to guest NV input, and
//       restore its key-bearing engine state after a certificate request.
// Expected: In-flight requests block save; completed requests permit save,
//       and report payloads retain the same guest input across restore.
#[test]
fn attestation_report_binds_guest_input_across_restore() {
    pal_async::DefaultPool::run_with(async |_| {
        for kind in [false, true] {
            let helper: Arc<dyn RequestAkCert> = Arc::new(EchoAttestationInput);
            let cert_type = if kind {
                TpmAkCertType::HwAttested(helper)
            } else {
                TpmAkCertType::SwAttested(helper)
            };
            let mut tpm = new_test_tpm(TpmVersion::V185, None, None, cert_type, false)
                .await
                .unwrap();
            let empty = tpm
                .create_ak_cert_request_or_attestation_report(true)
                .unwrap();
            assert_eq!(empty.data, vec![0; 64]);
            assert!(!empty.has_cert);
            let input: Vec<u8> = (0..64).map(|n| n ^ 0xa5).collect();
            tpm.tpm_engine_helper
                .nv_define_space(TPM20_RH_OWNER, 0, TPM_NV_INDEX_GUEST_ATTESTATION_INPUT, 64)
                .unwrap();
            tpm.tpm_engine_helper
                .nv_write(
                    TPM20_RH_OWNER,
                    None,
                    TPM_NV_INDEX_GUEST_ATTESTATION_INPUT,
                    &input,
                )
                .unwrap();
            assert_eq!(
                tpm.create_ak_cert_request_or_attestation_report(true)
                    .unwrap()
                    .data,
                input
            );
            tpm.renew_attestation_report().unwrap();
            let mut report = [0; 64];
            assert!(matches!(
                tpm.tpm_engine_helper
                    .read_from_nv_index(TPM_NV_INDEX_ATTESTATION_REPORT, &mut report)
                    .unwrap(),
                tpm_lib::NvIndexState::Available
            ));
            assert_eq!(report.as_slice(), input);
            let Err(vmcore::save_restore::SaveError::Other(error)) = tpm.save() else {
                panic!("outstanding request should block save");
            };
            assert!(matches!(
                error.downcast_ref::<save_restore::TpmSaveError>(),
                Some(save_restore::TpmSaveError::OutstandingAkCertRequest)
            ));
            tpm.poll_device(&mut Context::from_waker(Waker::noop()));
            let state = tpm.save().unwrap();
            tpm.restore(state).unwrap();
            assert_eq!(
                tpm.create_ak_cert_request_or_attestation_report(true)
                    .unwrap()
                    .data,
                input
            );
        }
    });
}

async fn boot_with_ppi(version: TpmVersion, bytes: Vec<u8>) -> Result<Tpm, TpmError> {
    let mut ppi = EphemeralNonVolatileStore::new_boxed();
    ppi.persist(bytes).await.unwrap();
    Tpm::new(
        version,
        TpmRegisterLayout::IoPort,
        GuestMemory::allocate(0x10000),
        ppi,
        EphemeralNonVolatileStore::new_boxed(),
        None,
        Box::new(|| std::time::Duration::ZERO),
        false,
        false,
        TpmAkCertType::None,
        None,
        None,
        false,
        guid::guid!("00000000-0000-0000-0000-000000000000"),
    )
    .await
}

// Test: Boot from persisted pending PPI requests, then inspect the persisted
//       completion record and the guest's query response.
// Expected: Clear and future operations complete once, retain unrelated PPI
//       arguments, and leave no pending request for a subsequent boot.
#[test]
fn boot_consumes_and_persists_pending_ppi() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            for operation in [PpiOperation::CLEAR.0, u32::MAX] {
                let mut words = [operation, 0x8000_0000, 0, 17, 18, 3, 3];
                let bytes = words.into_iter().flat_map(u32::to_ne_bytes).collect();
                let mut tpm = boot_with_ppi(version, bytes).await.unwrap();
                assert_eq!(
                    port_value(&mut tpm, TpmIoCommand::PPI_GET_PENDING_OPERATION),
                    0
                );
                assert_eq!(
                    port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_OPERATION),
                    operation
                );
                assert_eq!(port_value(&mut tpm, TpmIoCommand::PPI_GET_LAST_RESULT), 0);
                words[0] = 0;
                words[3] = operation;
                words[4] = 0;
                let expected: Vec<u8> = words.into_iter().flat_map(u32::to_ne_bytes).collect();
                let persisted = tpm.idle_stores().ppi.restore().await.unwrap().unwrap();
                assert_eq!(persisted, expected);
                drop(tpm);
                let mut rebooted = boot_with_ppi(version, persisted).await.unwrap();
                assert_eq!(
                    port_value(&mut rebooted, TpmIoCommand::PPI_GET_LAST_OPERATION),
                    operation
                );
                assert_eq!(
                    port_value(&mut rebooted, TpmIoCommand::PPI_GET_PENDING_OPERATION),
                    0
                );
            }
        }
    });
}

// Test: Boot with a truncated persisted PPI record.
// Expected: Construction rejects the bad record with InvalidPpiState instead
//       of booting with partially restored operations.
#[test]
fn boot_rejects_malformed_ppi_record() {
    pal_async::DefaultPool::run_with(async |_| {
        let Err(error) = boot_with_ppi(TpmVersion::V185, vec![0; 27]).await else {
            panic!("malformed PPI record was accepted");
        };
        assert!(matches!(error.0, TpmErrorKind::InvalidPpiState));
    });
}

// Test: Restore persisted identity data while requesting a TPM seed refresh.
// Expected: Both engines generate a different attestation key rather than
//       reusing the prior VM identity.
#[test]
fn seed_refresh_changes_attestation_identity() {
    pal_async::DefaultPool::run_with(async |_| {
        for version in [TpmVersion::V138, TpmVersion::V185] {
            let cert_type = || TpmAkCertType::Trusted(Arc::new(EchoAttestationInput), Some(false));
            let mut old = new_test_tpm(version, None, None, cert_type(), false)
                .await
                .unwrap();
            let old_key = old.tpm_engine_helper.create_ak_pub(false).unwrap().0;
            let blob = old.idle_stores().nvram.restore().await.unwrap().unwrap();
            drop(old);
            let mut renewed = new_test_tpm(version, None, Some(blob), cert_type(), true)
                .await
                .unwrap();
            let new_key = renewed.tpm_engine_helper.create_ak_pub(false).unwrap().0;
            assert_ne!(new_key.modulus, old_key.modulus);
            assert_eq!(new_key.exponent, [1, 0, 1]);
        }
    });
}
