// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::collections::VecDeque;
use test_with_tracing::test;
use tpm_protocol::tpm20proto::protocol::{NvReadCmd, Tpm2bNvPublic};

#[derive(Debug, thiserror::Error)]
#[error("backend disconnected")]
struct BackendDisconnected;

enum Reply {
    Bytes(Vec<u8>),
    Disconnected,
}

struct ScriptedEngine {
    steps: VecDeque<(CommandCodeEnum, Reply)>,
    commands: Vec<Vec<u8>>,
}

impl TpmEngine for ScriptedEngine {
    fn execute_command(
        &mut self,
        command: &mut [u8],
        response: &mut [u8],
    ) -> Result<(), TpmEngineError> {
        let (expected, reply) = self.steps.pop_front().expect("unexpected command");
        assert_eq!(
            u32::from_be_bytes(command[6..10].try_into().unwrap()),
            expected as u32
        );
        assert_eq!(
            u32::from_be_bytes(command[2..6].try_into().unwrap()) as usize,
            command.len()
        );
        self.commands.push(command.to_vec());
        match reply {
            Reply::Disconnected => Err(TpmEngineError::from_error(BackendDisconnected)),
            Reply::Bytes(bytes) => {
                response[..bytes.len()].copy_from_slice(&bytes);
                Ok(())
            }
        }
    }

    fn max_nv_index_size(&self) -> u16 {
        TPM_V185_MAX_NV_INDEX_SIZE
    }
}

fn helper(
    steps: impl IntoIterator<Item = (CommandCodeEnum, Reply)>,
) -> TpmEngineHelper<ScriptedEngine> {
    TpmEngineHelper::new(ScriptedEngine {
        steps: steps.into_iter().collect(),
        commands: Vec::new(),
    })
}

fn frame(tag: u16, code: u32, payload: &[u8]) -> Reply {
    let mut bytes = tag.to_be_bytes().to_vec();
    bytes.extend_from_slice(&((10 + payload.len()) as u32).to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(payload);
    Reply::Bytes(bytes)
}

fn failure(code: u32) -> Reply {
    frame(0x8001, code, &[])
}

fn success(sessions: bool) -> Reply {
    if sessions {
        frame(0x8002, 0, &[0; 9])
    } else {
        frame(0x8001, 0, &[])
    }
}

fn nv_public(index: u32, size: u16, attrs: TpmaNvBits) -> Reply {
    let public = TpmsNvPublic::new(index, AlgIdEnum::SHA256.into(), attrs, &[], size).unwrap();
    let mut payload = Tpm2bNvPublic::new(public).unwrap().serialize();
    payload.extend_from_slice(&[0, 0]);
    frame(0x8001, 0, &payload)
}

fn nv_data(data: &[u8]) -> Reply {
    let mut payload = ((2 + data.len()) as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&Tpm2bBuffer::new(data).unwrap().serialize());
    payload.extend_from_slice(&[0; 5]);
    frame(0x8002, 0, &payload)
}

type Command = fn(&mut TpmEngineHelper<ScriptedEngine>) -> Result<(), TpmCommandError>;

fn command_cases() -> [(CommandCodeEnum, Command); 18] {
    [
        (CommandCodeEnum::Startup, |h| h.startup(StartupType::Clear)),
        (CommandCodeEnum::SelfTest, |h| h.self_test(true)),
        (CommandCodeEnum::ClearControl, |h| {
            h.clear_control(TPM20_RH_PLATFORM, false)
        }),
        (CommandCodeEnum::Clear, |h| {
            h.clear(TPM20_RH_PLATFORM).map(|_| ())
        }),
        (CommandCodeEnum::PCR_Allocate, |h| {
            h.pcr_allocate(TPM20_RH_PLATFORM, 3, 1).map(|_| ())
        }),
        (CommandCodeEnum::ChangeEPS, |h| {
            h.change_seed(TPM20_RH_PLATFORM, CommandCodeEnum::ChangeEPS)
        }),
        (CommandCodeEnum::ChangePPS, |h| {
            h.change_seed(TPM20_RH_PLATFORM, CommandCodeEnum::ChangePPS)
        }),
        (CommandCodeEnum::ReadPublic, |h| {
            h.read_public(TPM_AZURE_AIK_HANDLE).map(|_| ())
        }),
        (CommandCodeEnum::FlushContext, |h| {
            h.flush_context(TPM_AZURE_AIK_HANDLE)
        }),
        (CommandCodeEnum::EvictControl, |h| {
            h.evict_control(TPM20_RH_OWNER, TPM_AZURE_AIK_HANDLE, TPM_AZURE_AIK_HANDLE)
        }),
        (CommandCodeEnum::NV_ReadPublic, |h| {
            h.nv_read_public(TPM_NV_INDEX_AIK_CERT).map(|_| ())
        }),
        (CommandCodeEnum::NV_UndefineSpace, |h| {
            h.nv_undefine_space(TPM20_RH_PLATFORM, TPM_NV_INDEX_AIK_CERT)
        }),
        (CommandCodeEnum::NV_DefineSpace, |h| {
            h.nv_define_space(TPM20_RH_PLATFORM, 0, TPM_NV_INDEX_AIK_CERT, 32)
        }),
        (CommandCodeEnum::CreatePrimary, |h| {
            h.create_primary(TPM20_RH_ENDORSEMENT, ak_pub_template().unwrap())
                .map(|_| ())
        }),
        (CommandCodeEnum::NV_Write, |h| {
            h.nv_write(TPM20_RH_OWNER, None, TPM_NV_INDEX_AIK_CERT, &[1, 2])
        }),
        (CommandCodeEnum::NV_Read, |h| {
            h.nv_read(TPM20_RH_OWNER, TPM_NV_INDEX_AIK_CERT, 2, &mut [0; 2])
        }),
        (CommandCodeEnum::Import, |h| {
            h.import(
                TPM_RSA_SRK_HANDLE,
                &Tpm2bPublic::new(ak_pub_template().unwrap()),
                &Tpm2bBuffer::new_zeroed(),
                &Tpm2bBuffer::new_zeroed(),
            )
            .map(|_| ())
        }),
        (CommandCodeEnum::Load, |h| {
            h.load(
                TPM_RSA_SRK_HANDLE,
                &Tpm2bBuffer::new_zeroed(),
                &Tpm2bPublic::new(ak_pub_template().unwrap()),
            )
            .map(|_| ())
        }),
    ]
}

fn contextual(error: Error, code: CommandCodeEnum, index: Option<u32>) -> TpmCommandError {
    let Error::TpmCommandError {
        command_debug_info,
        error,
    } = error
    else {
        panic!("command error expected");
    };
    assert_eq!(command_debug_info.command_code, code);
    assert_eq!(command_debug_info.nv_index, index);
    error
}

// Test: Disconnect the engine while sending each supported helper command.
// Expected: Callers receive the original typed backend cause through the
//       command error chain rather than success or a fabricated TPM code.
#[test]
fn command_errors_preserve_backend_cause() {
    for (code, command) in command_cases() {
        let mut h = helper([(code, Reply::Disconnected)]);
        let TpmCommandError::TpmExecuteCommand(error) = command(&mut h).unwrap_err() else {
            panic!("backend error expected for {code:?}");
        };
        assert!(error.downcast_ref::<BackendDisconnected>().is_some());
        assert!(error.as_error().is::<BackendDisconnected>());
        assert!(
            StdError::source(&error)
                .unwrap()
                .is::<BackendDisconnected>()
        );
        assert_eq!(error.to_string(), "backend disconnected");
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Return a valid TPM failure with an unknown response code to each command.
// Expected: Every helper preserves the entire code for the caller, without
//       treating an unknown value as success or as a transport disconnection.
#[test]
fn unknown_tpm_codes_are_not_normalized() {
    for (code, command) in command_cases() {
        let mut h = helper([(code, failure(0x1234_5678))]);
        assert!(matches!(
            command(&mut h),
            Err(TpmCommandError::TpmCommandFailed {
                response_code: 0x1234_5678
            })
        ));
    }
}

// Test: Return an invalid header tag through each supported helper command.
// Expected: Each operation surfaces InvalidResponse, preserving the distinction
//       between malformed transport data and an ordinary TPM rejection.
#[test]
fn malformed_reply_tags_are_not_tpm_failures() {
    for (code, command) in command_cases() {
        let mut h = helper([(code, frame(0xffff, 0x1234, &[]))]);
        assert!(matches!(
            command(&mut h),
            Err(TpmCommandError::InvalidResponse(_))
        ));
    }
}

// Test: Fail either phase of engine initialization.
// Expected: The reported command identifies the failed phase, and SelfTest is
//       not sent if Startup failed.
#[test]
fn initialization_stops_at_the_failed_phase() {
    let mut h = helper([(CommandCodeEnum::Startup, Reply::Disconnected)]);
    assert!(matches!(
        contextual(
            h.initialize_tpm_engine().unwrap_err(),
            CommandCodeEnum::Startup,
            None
        ),
        TpmCommandError::TpmExecuteCommand(_)
    ));
    let mut h = helper([
        (CommandCodeEnum::Startup, success(false)),
        (CommandCodeEnum::SelfTest, Reply::Disconnected),
    ]);
    assert!(matches!(
        contextual(
            h.initialize_tpm_engine().unwrap_err(),
            CommandCodeEnum::SelfTest,
            None
        ),
        TpmCommandError::TpmExecuteCommand(_)
    ));
}

// Test: Clear the platform context with failures at either command stage.
// Expected: TPM rejection codes are returned for the guest PPI result;
//       transport failures remain errors with the correct phase/hierarchy.
#[test]
fn platform_clear_distinguishes_ppi_results_from_transport_errors() {
    for fail_at_clear in [false, true] {
        for disconnect in [false, true] {
            let failed = if fail_at_clear {
                CommandCodeEnum::Clear
            } else {
                CommandCodeEnum::ClearControl
            };
            let mut steps = Vec::new();
            if fail_at_clear {
                steps.push((CommandCodeEnum::ClearControl, success(true)));
            }
            steps.push((
                failed,
                if disconnect {
                    Reply::Disconnected
                } else {
                    failure(0x1234)
                },
            ));
            let mut h = helper(steps);
            if disconnect {
                let Error::TpmCommandError {
                    command_debug_info,
                    error,
                } = h.clear_tpm_platform_context().unwrap_err()
                else {
                    panic!("transport failure expected");
                };
                assert_eq!(command_debug_info.command_code, failed);
                assert_eq!(command_debug_info.auth_handle, Some(TPM20_RH_PLATFORM));
                assert!(matches!(error, TpmCommandError::TpmExecuteCommand(_)));
            } else {
                assert_eq!(h.clear_tpm_platform_context().unwrap(), 0x1234);
            }
        }
    }
}

// Test: Fail either seed-refresh command.
// Expected: A failed EPS update does not update PPS, and each failure reports
//       the appropriate seed command rather than a generic provisioning error.
#[test]
fn seed_refresh_preserves_phase_context() {
    let mut h = helper([(CommandCodeEnum::ChangeEPS, Reply::Disconnected)]);
    contextual(
        h.refresh_tpm_seeds().unwrap_err(),
        CommandCodeEnum::ChangeEPS,
        None,
    );
    let mut h = helper([
        (CommandCodeEnum::ChangeEPS, success(true)),
        (CommandCodeEnum::ChangePPS, Reply::Disconnected),
    ]);
    contextual(
        h.refresh_tpm_seeds().unwrap_err(),
        CommandCodeEnum::ChangePPS,
        None,
    );
}

// Test: Look up NV indices and objects with missing handles and other failures.
// Expected: Only the designated first-handle-not-found code becomes absence;
//       other TPM/engine failures retain command and handle context.
#[test]
fn lookup_absence_does_not_hide_other_failures() {
    let missing = ResponseCode::Handle as u32 | ResponseCode::Rc1 as u32;
    let mut h = helper([(CommandCodeEnum::NV_ReadPublic, failure(missing))]);
    let mut output = [0xa5; 8];
    assert!(matches!(
        h.read_from_nv_index(TPM_NV_INDEX_AIK_CERT, &mut output)
            .unwrap(),
        NvIndexState::Unallocated
    ));
    assert_eq!(output, [0xa5; 8]);
    let mut h = helper([(CommandCodeEnum::ReadPublic, failure(missing))]);
    assert!(h.find_object(TPM_GUEST_SECRET_HANDLE).unwrap().is_none());
    for reply in [failure(0x1234), Reply::Disconnected] {
        let mut h = helper([(CommandCodeEnum::NV_ReadPublic, reply)]);
        contextual(
            h.find_nv_index(TPM_NV_INDEX_AIK_CERT).unwrap_err(),
            CommandCodeEnum::NV_ReadPublic,
            Some(TPM_NV_INDEX_AIK_CERT),
        );
    }
    for reply in [failure(0x1234), Reply::Disconnected] {
        let mut h = helper([(CommandCodeEnum::ReadPublic, reply)]);
        contextual(
            h.find_object(TPM_GUEST_SECRET_HANDLE).unwrap_err(),
            CommandCodeEnum::ReadPublic,
            Some(TPM_GUEST_SECRET_HANDLE.0.get()),
        );
    }
}

// Test: Attempt writes to non-platform/non-password indices and beyond their size.
// Expected: The exact permission/size error is returned before an NV_Write
//       command can change any data.
#[test]
fn nv_write_permissions_and_size_are_checked_before_transfer() {
    for (auth_write, platform_created) in [(false, true), (true, false), (false, false)] {
        let attrs = TpmaNvBits::new()
            .with_nv_authwrite(auth_write)
            .with_nv_platformcreate(platform_created);
        let mut h = helper([(
            CommandCodeEnum::NV_ReadPublic,
            nv_public(TPM_NV_INDEX_AIK_CERT, 4, attrs),
        )]);
        assert!(
            matches!(h.write_to_nv_index(7, TPM_NV_INDEX_AIK_CERT, &[1, 2]),
            Err(Error::InvalidPermission { nv_index: TPM_NV_INDEX_AIK_CERT, auth_write: a, platform_created: p }) if a == auth_write && p == platform_created)
        );
    }
    let mut h = helper([(
        CommandCodeEnum::NV_ReadPublic,
        nv_public(TPM_NV_INDEX_AIK_CERT, 2, platform_akcert_attributes()),
    )]);
    assert!(matches!(
        h.write_to_nv_index(7, TPM_NV_INDEX_AIK_CERT, &[1, 2, 3]),
        Err(Error::NvWriteInputTooLarge {
            nv_index: TPM_NV_INDEX_AIK_CERT,
            input_size: 3,
            allocated_size: 2
        })
    ));
}

// Test: Read indices without owner permission, uninitialized indices and failed reads.
// Expected: NoOwnerRead is enforced; uninitialized data stays untouched, while
//       ordinary failures retain the NV_Read index/hierarchy context.
#[test]
fn nv_read_failures_preserve_output_and_context() {
    let mut h = helper([(
        CommandCodeEnum::NV_ReadPublic,
        nv_public(TPM_NV_INDEX_AIK_CERT, 8, TpmaNvBits::new()),
    )]);
    let mut output = [0xa5; 8];
    assert!(matches!(
        h.read_from_nv_index(TPM_NV_INDEX_AIK_CERT, &mut output),
        Err(Error::NoOwnerReadFlag(TPM_NV_INDEX_AIK_CERT))
    ));
    for reply in [
        failure(ResponseCode::NvUninitialized as u32),
        failure(0x1234),
        Reply::Disconnected,
    ] {
        let uninitialized = matches!(&reply, Reply::Bytes(bytes) if bytes[6..10] == (ResponseCode::NvUninitialized as u32).to_be_bytes());
        let mut h = helper([
            (
                CommandCodeEnum::NV_ReadPublic,
                nv_public(
                    TPM_NV_INDEX_AIK_CERT,
                    8,
                    TpmaNvBits::new().with_nv_ownerread(true),
                ),
            ),
            (CommandCodeEnum::NV_Read, reply),
        ]);
        let result = h.read_from_nv_index(TPM_NV_INDEX_AIK_CERT, &mut output);
        if uninitialized {
            assert!(matches!(result.unwrap(), NvIndexState::Uninitialized));
        } else {
            let Error::TpmCommandError {
                command_debug_info, ..
            } = result.unwrap_err()
            else {
                panic!("read error expected");
            };
            assert_eq!(command_debug_info.command_code, CommandCodeEnum::NV_Read);
            assert_eq!(command_debug_info.auth_handle, Some(TPM20_RH_OWNER));
            assert_eq!(command_debug_info.nv_index, Some(TPM_NV_INDEX_AIK_CERT));
        }
        assert_eq!(output, [0xa5; 8]);
    }
}

// Test: Write a short certificate into a larger platform-created NV index.
// Expected: The wire sends the full zero-padded index in bounded chunks with
//       contiguous offsets and the supplied big-endian password.
#[test]
fn certificate_writes_pad_and_authorize_each_chunk() {
    let mut h = helper([
        (
            CommandCodeEnum::NV_ReadPublic,
            nv_public(TPM_NV_INDEX_AIK_CERT, 1500, platform_akcert_attributes()),
        ),
        (CommandCodeEnum::NV_Write, success(true)),
        (CommandCodeEnum::NV_Write, success(true)),
    ]);
    let data: Vec<u8> = (0..1001).map(|n| (n % 251) as u8).collect();
    h.write_to_nv_index(0x0123_4567_89ab_cdef, TPM_NV_INDEX_AIK_CERT, &data)
        .unwrap();
    let mut transferred = Vec::new();
    for (command, offset) in h.tpm_engine.commands[1..].iter().zip([0u16, 1024]) {
        assert_eq!(&command[10..14], &TPM_NV_INDEX_AIK_CERT.to_be_bytes());
        assert_eq!(&command[14..18], &TPM_NV_INDEX_AIK_CERT.to_be_bytes());
        assert_eq!(&command[18..22], &17u32.to_be_bytes());
        assert_eq!(&command[31..39], &0x0123_4567_89ab_cdefu64.to_be_bytes());
        let len = u16::from_be_bytes(command[39..41].try_into().unwrap()) as usize;
        assert!(len <= 1024);
        assert_eq!(
            u16::from_be_bytes(command[41 + len..43 + len].try_into().unwrap()),
            offset
        );
        transferred.extend_from_slice(&command[41..41 + len]);
    }
    let mut expected = data;
    expected.resize(1500, 0);
    assert_eq!(transferred, expected);
}

// Test: Read a multi-chunk index into a larger caller buffer.
// Expected: Requests cover exactly the index with contiguous offsets and the
//       extra caller capacity remains untouched.
#[test]
fn nv_read_chunks_preserve_extra_output_capacity() {
    let data: Vec<u8> = (0..1500).map(|n| (n % 251) as u8).collect();
    let mut h = helper([
        (CommandCodeEnum::NV_Read, nv_data(&data[..1024])),
        (CommandCodeEnum::NV_Read, nv_data(&data[1024..])),
    ]);
    let mut output = [0xa5; 1536];
    h.nv_read(TPM20_RH_OWNER, TPM_NV_INDEX_AIK_CERT, 1500, &mut output)
        .unwrap();
    assert_eq!(&output[..1500], data);
    assert_eq!(output[1500..], [0xa5; 36]);
    for (command, (offset, size)) in h.tpm_engine.commands.iter().zip([(0, 1024), (1024, 476)]) {
        let read = NvReadCmd::deserialize(command).unwrap();
        assert_eq!(read.offset.get(), offset);
        assert_eq!(
            u16::from_be_bytes(
                command[command.len() - 4..command.len() - 2]
                    .try_into()
                    .unwrap()
            ),
            size
        );
        assert_eq!(read.nv_index.get(), TPM_NV_INDEX_AIK_CERT);
    }
}

// Test: Disconnect the engine after one successful chunk of an NV read.
// Expected: Completed bytes remain available, untouched bytes retain their
//       sentinels, and the transport failure is not reported as success.
#[test]
fn interrupted_nv_read_preserves_completed_work() {
    let mut h = helper([
        (CommandCodeEnum::NV_Read, nv_data(&[0x5a; 1024])),
        (CommandCodeEnum::NV_Read, Reply::Disconnected),
    ]);
    let mut output = [0xa5; 1500];
    assert!(matches!(
        h.nv_read(TPM20_RH_OWNER, TPM_NV_INDEX_AIK_CERT, 1500, &mut output),
        Err(TpmCommandError::TpmExecuteCommand(_))
    ));
    assert_eq!(output[..1024], [0x5a; 1024]);
    assert_eq!(output[1024..], [0xa5; 476]);
}

// Test: Return fewer NV bytes than the helper requested in a valid reply frame.
// Expected: A short reply is rejected without inventing zero-filled bytes.
// IGNORED: entry372-bug1: nv_read accepts a short payload and copies the protocol
//       buffer's zero-filled tail as if those bytes were returned by the TPM.
#[test]
#[ignore = "entry372-bug1: short NV replies are accepted and zero-filled"]
fn short_nv_reply_is_not_a_successful_full_read() {
    let mut h = helper([(CommandCodeEnum::NV_Read, nv_data(&[1, 2]))]);
    let mut output = [0xa5; 8];
    assert!(
        h.nv_read(TPM20_RH_OWNER, TPM_NV_INDEX_AIK_CERT, 8, &mut output)
            .is_err()
    );
    assert_eq!(output, [0xa5; 8]);
}

// Test: Fail EK creation because the TPM rejects the hierarchy or disconnects.
// Expected: Guest-caused TPM rejection is nonfatal with no key material, while
//       a disconnected engine is a contextual CreatePrimary error.
#[test]
fn key_creation_distinguishes_guest_rejection_from_engine_failure() {
    let mut h = helper([(CommandCodeEnum::CreatePrimary, failure(0x1234))]);
    let key = h.create_ek_pub().unwrap();
    assert_eq!(key.modulus, [0; 256]);
    assert_eq!(key.exponent, [0; 3]);
    let mut h = helper([(CommandCodeEnum::CreatePrimary, Reply::Disconnected)]);
    contextual(
        h.create_ek_pub().unwrap_err(),
        CommandCodeEnum::CreatePrimary,
        None,
    );
}

// Test: Export RSA public material with default and unsupported encodings.
// Expected: Default exponent expands to 65537 and modulus bytes are exact;
//       nondefault exponents and wrong modulus sizes return typed errors.
#[test]
fn rsa_export_preserves_key_material_and_rejects_unsupported_encodings() {
    let mut area = ak_pub_template().unwrap();
    let modulus: Vec<u8> = (0..256).map(|n| n as u8).collect();
    area.unique = Tpm2bBuffer::new(&modulus).unwrap();
    let key = export_rsa_public(&Tpm2bPublic::new(area)).unwrap();
    assert_eq!(key.modulus.as_slice(), modulus);
    assert_eq!(key.exponent, [1, 0, 1]);
    area.parameters.exponent = 65537.into();
    assert!(matches!(
        export_rsa_public(&Tpm2bPublic::new(area)),
        Err(TpmHelperUtilityError::UnexpectedRsaExponent)
    ));
    area.parameters.exponent = 0.into();
    for size in [0, 255, 257] {
        area.unique = Tpm2bBuffer::new(&vec![0x5a; size]).unwrap();
        assert!(matches!(
            export_rsa_public(&Tpm2bPublic::new(area)),
            Err(TpmHelperUtilityError::UnexpectedRsaModulusSize)
        ));
    }
}

fn object_public(mut area: TpmtPublic, modulus: &[u8]) -> Reply {
    area.unique = Tpm2bBuffer::new(modulus).unwrap();
    let mut payload = Tpm2bPublic::new(area).serialize();
    payload.extend_from_slice(&[0; 4]);
    frame(0x8001, 0, &payload)
}

fn certificate_read(cert: &[u8]) -> Vec<(CommandCodeEnum, Reply)> {
    let mut steps = vec![(
        CommandCodeEnum::NV_ReadPublic,
        nv_public(
            TPM_NV_INDEX_AIK_CERT,
            cert.len() as u16,
            platform_akcert_attributes(),
        ),
    )];
    steps.extend(
        cert.chunks(1024)
            .map(|chunk| (CommandCodeEnum::NV_Read, nv_data(chunk))),
    );
    steps
}

fn take_certificate(cert: &[u8]) -> Vec<(CommandCodeEnum, Reply)> {
    let mut steps = certificate_read(cert);
    steps.push((
        CommandCodeEnum::NV_ReadPublic,
        nv_public(
            TPM_NV_INDEX_AIK_CERT,
            cert.len() as u16,
            platform_akcert_attributes(),
        ),
    ));
    steps.push((CommandCodeEnum::NV_UndefineSpace, success(true)));
    steps
}

fn allocation_params(mitigate: bool) -> AllocateNvIndicesParams {
    AllocateNvIndicesParams {
        preserve_ak_cert: true,
        support_attestation_report: false,
        mitigate_legacy_akcert: mitigate,
        create_if_missing: false,
        recovered: false,
    }
}

// Test: Reuse an existing AK with expected, changed and invalid RSA public data.
// Expected: Renewal is permitted only for expected attributes, key bytes remain
//       exact, and malformed material identifies the existing AK export.
#[test]
fn existing_ak_attributes_gate_certificate_renewal() {
    for expected in [true, false] {
        let mut area = ak_pub_template().unwrap();
        if !expected {
            area.object_attributes = TpmaObjectBits::new().into();
        }
        let mut h = helper([(
            CommandCodeEnum::ReadPublic,
            object_public(area, &[0x5a; 256]),
        )]);
        let (key, allow_renewal) = h.create_ak_pub(false).unwrap();
        assert_eq!(allow_renewal, expected);
        assert_eq!(key.modulus, [0x5a; 256]);
        assert!(h.tpm_engine.steps.is_empty());
    }
    let mut h = helper([(
        CommandCodeEnum::ReadPublic,
        object_public(ak_pub_template().unwrap(), &[0x5a; 255]),
    )]);
    assert!(matches!(h.create_ak_pub(false),
        Err(Error::ExportRsaPublicFromAkHandle { ak_handle, error: TpmHelperUtilityError::UnexpectedRsaModulusSize })
        if ak_handle == TPM_AZURE_AIK_HANDLE.0.get()));
}

// Test: Force AK renewal when the old persistent key cannot be evicted.
// Expected: A guest TPM rejection remains nonfatal, but a transport failure
//       prevents creating a replacement and retains the old handle context.
#[test]
fn forced_ak_renewal_distinguishes_eviction_failures() {
    for disconnect in [false, true] {
        let mut steps = vec![
            (
                CommandCodeEnum::ReadPublic,
                object_public(ak_pub_template().unwrap(), &[0x5a; 256]),
            ),
            (
                CommandCodeEnum::EvictControl,
                if disconnect {
                    Reply::Disconnected
                } else {
                    failure(0x1234)
                },
            ),
        ];
        if !disconnect {
            steps.push((CommandCodeEnum::CreatePrimary, failure(0x1234)));
        }
        let mut h = helper(steps);
        if disconnect {
            contextual(
                h.create_ak_pub(true).unwrap_err(),
                CommandCodeEnum::EvictControl,
                Some(TPM_AZURE_AIK_HANDLE.0.get()),
            );
        } else {
            let (key, allow_renewal) = h.create_ak_pub(true).unwrap();
            assert_eq!(key.modulus, [0; 256]);
            assert!(allow_renewal);
        }
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Resize or preserve a platform certificate while index definition fails.
// Expected: Ordinary allocation failure is fatal; mitigation failure is
//       best-effort, bounds the DER size, uses owner auth and does not write.
#[test]
fn mitigation_definition_failure_is_best_effort_only_for_legacy_certificates() {
    for mitigate in [false, true] {
        let mut cert = vec![
            0x5a;
            if mitigate {
                TPM_DEFAULT_AKCERT_SIZE
            } else {
                16
            }
        ];
        cert[..4].copy_from_slice(&[0x30, 0x82, 0, 12]);
        let mut steps = Vec::new();
        if mitigate {
            steps.push((
                CommandCodeEnum::NV_ReadPublic,
                failure(ResponseCode::Handle as u32 | ResponseCode::Rc1 as u32),
            ));
        }
        steps.extend(take_certificate(&cert));
        if mitigate {
            steps.push((CommandCodeEnum::NV_DefineSpace, Reply::Disconnected));
        }
        steps.push((CommandCodeEnum::NV_DefineSpace, Reply::Disconnected));
        let mut params = allocation_params(mitigate);
        params.recovered = mitigate;
        let mut h = helper(steps);
        let result = h.allocate_guest_attestation_nv_indices(7, params);
        if mitigate {
            result.unwrap();
            let definition = h.tpm_engine.commands.last().unwrap();
            assert_eq!(&definition[10..14], &TPM20_RH_OWNER.0.get().to_be_bytes());
            assert_eq!(&definition[definition.len() - 2..], &16u16.to_be_bytes());
        } else {
            contextual(
                result.unwrap_err(),
                CommandCodeEnum::NV_DefineSpace,
                Some(TPM_NV_INDEX_AIK_CERT),
            );
        }
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Restore owner authorization on a platform certificate with a mitigation marker.
// Expected: The exact certificate is transferred with owner auth; define/write
//       failures are not hidden by the earlier best-effort marker behavior.
#[test]
fn existing_mitigation_marker_restores_owner_auth_and_preserves_failures() {
    for failure_stage in [
        None,
        Some(CommandCodeEnum::NV_DefineSpace),
        Some(CommandCodeEnum::NV_Write),
    ] {
        let cert = [0x5a; 16];
        let mut steps = vec![(
            CommandCodeEnum::NV_ReadPublic,
            nv_public(TPM_NV_INDEX_MITIGATED, 1, TpmaNvBits::new()),
        )];
        steps.extend(certificate_read(&cert));
        steps.push((
            CommandCodeEnum::NV_ReadPublic,
            nv_public(TPM_NV_INDEX_AIK_CERT, 16, platform_akcert_attributes()),
        ));
        steps.extend(take_certificate(&cert));
        steps.push((
            CommandCodeEnum::NV_DefineSpace,
            if failure_stage == Some(CommandCodeEnum::NV_DefineSpace) {
                Reply::Disconnected
            } else {
                success(true)
            },
        ));
        if failure_stage != Some(CommandCodeEnum::NV_DefineSpace) {
            steps.push((
                CommandCodeEnum::NV_Write,
                if failure_stage == Some(CommandCodeEnum::NV_Write) {
                    Reply::Disconnected
                } else {
                    success(true)
                },
            ));
        }
        let mut h = helper(steps);
        let result = h.allocate_guest_attestation_nv_indices(7, allocation_params(true));
        if let Some(code) = failure_stage {
            let Error::TpmCommandError {
                command_debug_info,
                error,
            } = result.unwrap_err()
            else {
                panic!("migration error expected");
            };
            assert_eq!(command_debug_info.command_code, code);
            assert_eq!(command_debug_info.auth_handle, Some(TPM20_RH_OWNER));
            assert_eq!(command_debug_info.nv_index, Some(TPM_NV_INDEX_AIK_CERT));
            assert!(matches!(error, TpmCommandError::TpmExecuteCommand(_)));
        } else {
            result.unwrap();
            let write = h.tpm_engine.commands.last().unwrap();
            assert_eq!(&write[10..14], &TPM20_RH_OWNER.0.get().to_be_bytes());
            assert_eq!(&write[33..49], &cert);
        }
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Inspect a missing, unreadable or uninitialized certificate with a mitigation marker.
// Expected: These diagnostic states do not mutate already-mitigated NVRAM.
#[test]
fn mitigation_marker_diagnostics_do_not_reallocate_missing_data() {
    for state in 0..3 {
        let mut steps = vec![(
            CommandCodeEnum::NV_ReadPublic,
            nv_public(TPM_NV_INDEX_MITIGATED, 1, TpmaNvBits::new()),
        )];
        if state == 0 {
            steps.push((
                CommandCodeEnum::NV_ReadPublic,
                failure(ResponseCode::Handle as u32 | ResponseCode::Rc1 as u32),
            ));
        } else {
            steps.push((
                CommandCodeEnum::NV_ReadPublic,
                nv_public(
                    TPM_NV_INDEX_AIK_CERT,
                    16,
                    TpmaNvBits::new().with_nv_ownerread(state == 2),
                ),
            ));
            if state == 2 {
                steps.push((
                    CommandCodeEnum::NV_Read,
                    failure(ResponseCode::NvUninitialized as u32),
                ));
            }
        }
        let mut h = helper(steps);
        h.allocate_guest_attestation_nv_indices(7, allocation_params(true))
            .unwrap();
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Fail removal or definition of a preexisting attestation report index.
// Expected: Allocation stops at the failed stage with the report index and
//       platform hierarchy in its typed error metadata.
#[test]
fn attestation_report_replacement_preserves_failure_context() {
    for failed in [
        CommandCodeEnum::NV_UndefineSpace,
        CommandCodeEnum::NV_DefineSpace,
    ] {
        let mut steps = vec![
            (
                CommandCodeEnum::NV_ReadPublic,
                failure(ResponseCode::Handle as u32 | ResponseCode::Rc1 as u32),
            ),
            (
                CommandCodeEnum::NV_ReadPublic,
                nv_public(
                    TPM_NV_INDEX_ATTESTATION_REPORT,
                    16,
                    platform_akcert_attributes(),
                ),
            ),
            (
                CommandCodeEnum::NV_UndefineSpace,
                if failed == CommandCodeEnum::NV_UndefineSpace {
                    Reply::Disconnected
                } else {
                    success(true)
                },
            ),
        ];
        if failed == CommandCodeEnum::NV_DefineSpace {
            steps.push((failed, Reply::Disconnected));
        }
        let mut params = allocation_params(false);
        params.support_attestation_report = true;
        let mut h = helper(steps);
        let Error::TpmCommandError {
            command_debug_info,
            error,
        } = h
            .allocate_guest_attestation_nv_indices(7, params)
            .unwrap_err()
        else {
            panic!("allocation failure expected");
        };
        assert_eq!(command_debug_info.command_code, failed);
        assert_eq!(command_debug_info.auth_handle, Some(TPM20_RH_PLATFORM));
        assert_eq!(
            command_debug_info.nv_index,
            Some(TPM_NV_INDEX_ATTESTATION_REPORT)
        );
        assert!(matches!(error, TpmCommandError::TpmExecuteCommand(_)));
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Fail removal of an available or uninitialized platform AK certificate.
// Expected: The index is not redefined after failed removal and the error
//       identifies NV_UndefineSpace, the platform hierarchy and AK certificate.
#[test]
fn certificate_removal_failure_prevents_redefinition() {
    for uninitialized in [false, true] {
        let mut steps = if uninitialized {
            vec![
                (
                    CommandCodeEnum::NV_ReadPublic,
                    nv_public(TPM_NV_INDEX_AIK_CERT, 16, platform_akcert_attributes()),
                ),
                (
                    CommandCodeEnum::NV_Read,
                    failure(ResponseCode::NvUninitialized as u32),
                ),
            ]
        } else {
            let mut steps = certificate_read(&[0x5a; 16]);
            steps.push((
                CommandCodeEnum::NV_ReadPublic,
                nv_public(TPM_NV_INDEX_AIK_CERT, 16, platform_akcert_attributes()),
            ));
            steps
        };
        steps.push((CommandCodeEnum::NV_UndefineSpace, Reply::Disconnected));
        let mut h = helper(steps);
        let Error::TpmCommandError {
            command_debug_info,
            error,
        } = h
            .allocate_guest_attestation_nv_indices(7, allocation_params(false))
            .unwrap_err()
        else {
            panic!("removal error expected");
        };
        assert_eq!(
            command_debug_info.command_code,
            CommandCodeEnum::NV_UndefineSpace
        );
        assert_eq!(command_debug_info.auth_handle, Some(TPM20_RH_PLATFORM));
        assert_eq!(command_debug_info.nv_index, Some(TPM_NV_INDEX_AIK_CERT));
        assert!(matches!(error, TpmCommandError::TpmExecuteCommand(_)));
        assert!(h.tpm_engine.steps.is_empty());
    }
}

// Test: Disconnect while preserving the certificate after redefining its index.
// Expected: The write failure is returned with certificate/password-handle
//       context, and report allocation does not proceed.
#[test]
fn certificate_preservation_failure_stops_report_allocation() {
    let mut steps = take_certificate(&[0x5a; 16]);
    steps.extend([
        (CommandCodeEnum::NV_DefineSpace, success(true)),
        (CommandCodeEnum::NV_Write, Reply::Disconnected),
    ]);
    let mut params = allocation_params(false);
    params.support_attestation_report = true;
    let mut h = helper(steps);
    let Error::TpmCommandError {
        command_debug_info,
        error,
    } = h
        .allocate_guest_attestation_nv_indices(7, params)
        .unwrap_err()
    else {
        panic!("preservation error expected");
    };
    assert_eq!(command_debug_info.command_code, CommandCodeEnum::NV_Write);
    assert_eq!(
        command_debug_info.auth_handle,
        Some(ReservedHandle(TPM_NV_INDEX_AIK_CERT.into()))
    );
    assert_eq!(command_debug_info.nv_index, Some(TPM_NV_INDEX_AIK_CERT));
    assert!(matches!(error, TpmCommandError::TpmExecuteCommand(_)));
    assert!(h.tpm_engine.steps.is_empty());
}
