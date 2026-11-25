// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use test_with_tracing::test;
use tpm_lib::TpmEngineError;

const READ_PUBLIC: u32 = 0x169;
const UNDEFINE: u32 = 0x122;
const DEFINE: u32 = 0x12a;
const WRITE: u32 = 0x137;
const READ: u32 = 0x14e;
const INDEX: u32 = 0x1500016;
type Step = (u32, Vec<u8>);

#[derive(Default)]
struct State {
    steps: VecDeque<Step>,
    commands: Vec<Vec<u8>>,
}
struct Script(Arc<Mutex<State>>);
impl TpmEngine for Script {
    fn execute_command(
        &mut self,
        command: &mut [u8],
        response: &mut [u8],
    ) -> Result<(), TpmEngineError> {
        let mut state = self.0.lock();
        let (expected, reply) = state.steps.pop_front().expect("unexpected TPM command");
        assert_eq!(
            u32::from_be_bytes(command[2..6].try_into().unwrap()) as usize,
            command.len()
        );
        assert_eq!(
            u32::from_be_bytes(command[6..10].try_into().unwrap()),
            expected
        );
        state.commands.push(command.to_vec());
        response.fill(0);
        response[..reply.len()].copy_from_slice(&reply);
        Ok(())
    }
    fn max_nv_index_size(&self) -> u16 {
        tpm_lib::TPM_V185_MAX_NV_INDEX_SIZE
    }
}
fn helper(steps: Vec<Step>) -> (TpmEngineHelper<Script>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        steps: steps.into(),
        commands: Vec::new(),
    }));
    (TpmEngineHelper::new(Script(state.clone())), state)
}
fn reply(tag: u16, status: u32, body: &[u8]) -> Vec<u8> {
    [
        tag.to_be_bytes().as_slice(),
        &((10 + body.len()) as u32).to_be_bytes(),
        &status.to_be_bytes(),
        body,
    ]
    .concat()
}
fn success() -> Vec<u8> {
    reply(0x8002, 0, &[])
}
fn failure() -> Vec<u8> {
    reply(0x8001, 0x18b, &[])
}
fn public(index: u32, size: usize) -> Vec<u8> {
    let body = [
        14u16.to_be_bytes().as_slice(),
        &index.to_be_bytes(),
        &[0, 0x0b],
        &[0; 4],
        &[0; 2],
        &(size as u16).to_be_bytes(),
        &[0; 2],
    ]
    .concat();
    reply(0x8001, 0, &body)
}
fn data(bytes: &[u8]) -> Vec<u8> {
    let body = [
        ((2 + bytes.len()) as u32).to_be_bytes().as_slice(),
        &(bytes.len() as u16).to_be_bytes(),
        bytes,
        &[0; 5],
    ]
    .concat();
    reply(0x8002, 0, &body)
}
fn reads(index: u32, bytes: &[u8]) -> Vec<Step> {
    let mut steps = vec![(READ_PUBLIC, public(index, bytes.len()))];
    steps.extend(
        bytes
            .chunks(tpm_protocol::tpm20proto::MAX_DIGEST_BUFFER_SIZE)
            .map(|chunk| (READ, data(chunk))),
    );
    steps
}
fn assert_consumed(state: &Arc<Mutex<State>>) {
    assert!(state.lock().steps.is_empty());
}
fn assert_tpm_failure(error: Box<dyn Error>) {
    assert!(matches!(
        error.downcast_ref::<tpm_lib::TpmCommandError>(),
        Some(tpm_lib::TpmCommandError::TpmCommandFailed {
            response_code: 0x18b
        })
    ));
}

// Test: Redefine an existing NV index, write binary bytes, and verify those exact bytes through the helper's public read action.
// Expected: Public-read/undefine/define precede write/read in order; the wire uses owner authorization, the requested index and size, exact payload bytes and offset zero.
#[test]
fn nv_define_write_and_read_preserve_owner_index_and_binary_data() {
    let bytes = [0, 0x91, 0x20, 0xff];
    let mut steps = vec![
        (READ_PUBLIC, public(INDEX, 7)),
        (UNDEFINE, success()),
        (DEFINE, success()),
        (WRITE, success()),
    ];
    steps.extend(reads(INDEX, &bytes));
    let (mut helper, state) = helper(steps);
    handle_nv_define(&mut helper, INDEX, 4).unwrap();
    handle_nv_write(&mut helper, INDEX, &bytes).unwrap();
    handle_nv_read(&mut helper, INDEX, Some(&bytes)).unwrap();
    assert_consumed(&state);
    let state = state.lock();
    let commands = &state.commands;
    assert_eq!(&commands[0][10..14], &INDEX.to_be_bytes());
    for position in [1, 3, 5] {
        assert_eq!(&commands[position][10..14], &0x40000001u32.to_be_bytes());
        assert_eq!(&commands[position][14..18], &INDEX.to_be_bytes());
    }
    let define = &commands[2];
    assert_eq!(
        &define[define.len() - 14..define.len() - 10],
        &INDEX.to_be_bytes()
    );
    assert_eq!(&define[define.len() - 2..], &[0, 4]);
    assert_eq!(&commands[3][31..], &[0, 4, 0, 0x91, 0x20, 0xff, 0, 0]);
    assert_eq!(&commands[5][commands[5].len() - 4..], &[0, 4, 0, 0]);
}

// Test: Read empty and nonempty NV indices, compare mismatched expected data, and fail public metadata lookup.
// Expected: Empty indices need no data read, optional comparison remains optional, mismatch reports actual/expected lengths, and missing metadata retains the requested NV handle in the error.
#[test]
fn nv_reads_distinguish_empty_optional_mismatch_and_missing_data() {
    let mut steps = reads(INDEX, &[]);
    steps.extend(reads(INDEX, &[0x91; 4]));
    steps.extend(reads(INDEX, &[0x91; 4]));
    steps.push((READ_PUBLIC, failure()));
    let (mut helper, state) = helper(steps);
    handle_nv_read(&mut helper, INDEX, Some(&[])).unwrap();
    handle_nv_read(&mut helper, INDEX, None).unwrap();
    let error = handle_nv_read(&mut helper, INDEX, Some(&[0x91; 3])).unwrap_err();
    assert!(error.to_string().contains("got 4 bytes, expected 3 bytes"));
    let error = read_nv_index(&mut helper, INDEX).unwrap_err();
    assert!(error.to_string().contains("NV index 0x1500016 not found"));
    assert_consumed(&state);
}

// Test: Define an absent index and inject failures into undefine, define, write and read commands.
// Expected: An absent probe falls through to define; failed destructive or data commands return their TPM error and do not send a later command.
#[test]
fn nv_command_failures_stop_without_sending_followup_commands() {
    let (mut helper, state) = helper(vec![(READ_PUBLIC, failure()), (DEFINE, success())]);
    handle_nv_define(&mut helper, INDEX, 4).unwrap();
    assert_consumed(&state);
    let (mut helper, state) =
        self::helper(vec![(READ_PUBLIC, public(INDEX, 4)), (UNDEFINE, failure())]);
    assert_tpm_failure(handle_nv_define(&mut helper, INDEX, 4).unwrap_err());
    assert_consumed(&state);
    let (mut helper, state) = self::helper(vec![(READ_PUBLIC, failure()), (DEFINE, failure())]);
    assert_tpm_failure(handle_nv_define(&mut helper, INDEX, 4).unwrap_err());
    assert_consumed(&state);
    let (mut helper, state) = self::helper(vec![(WRITE, failure())]);
    assert_tpm_failure(handle_nv_write(&mut helper, INDEX, &[0x91]).unwrap_err());
    assert_consumed(&state);
    let (mut helper, state) =
        self::helper(vec![(READ_PUBLIC, public(INDEX, 4)), (READ, failure())]);
    assert_tpm_failure(read_nv_index(&mut helper, INDEX).unwrap_err());
    assert_consumed(&state);
}

// Test: Request attestation with an absent and an existing guest-input NV index, including a report larger than the accepted limit.
// Expected: Only the absent index is allocated at 64 bytes; payload write precedes its readback and report read, exact report bytes are returned, and over-limit report data is rejected.
#[test]
fn attestation_allocates_only_when_needed_and_bounds_report_data() {
    for existing in [false, true] {
        let payload = [0x91; 64];
        let report = if existing {
            vec![0x31; MAX_ATTESTATION_READ_SIZE + 1]
        } else {
            vec![0x31; 20]
        };
        let mut steps = vec![(
            READ_PUBLIC,
            if existing {
                public(NV_INDEX_GUEST_INPUT, 64)
            } else {
                failure()
            },
        )];
        if !existing {
            steps.push((DEFINE, success()));
        }
        steps.push((WRITE, success()));
        steps.extend(reads(NV_INDEX_GUEST_INPUT, &payload));
        steps.extend(reads(NV_INDEX_ATTESTATION_REPORT, &report));
        let (mut helper, state) = helper(steps);
        let result = handle_report(&mut helper, &payload);
        if existing {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("exceeds maximum 2900 bytes")
            );
        } else {
            assert_eq!(result.unwrap(), report);
        }
        assert_consumed(&state);
        let state = state.lock();
        let write = &state.commands[if existing { 1 } else { 2 }];
        assert_eq!(&write[14..18], &NV_INDEX_GUEST_INPUT.to_be_bytes());
        assert_eq!(&write[31..33], &[0, 64]);
        assert_eq!(&write[33..97], &payload);
        if !existing {
            let define = &state.commands[1];
            assert_eq!(&define[define.len() - 2..], &[0, 64]);
        }
    }
}

// Test: Read AK certificate contents with no expectation, an exact expectation, mismatch, missing index, over-limit size and retries that succeed after mismatch or failed lookup.
// Expected: Successful data includes padding unchanged; final mismatch/read errors are distinguishable, excessive certificate size is rejected, and retry returns only the later matching certificate.
#[test]
fn ak_certificate_comparison_limits_and_retry_are_observable() {
    let bytes = [0, 0x91, 0xff, 0];
    let mut steps = reads(NV_INDEX_AK_CERT, &bytes);
    steps.extend(reads(NV_INDEX_AK_CERT, &bytes));
    steps.extend(reads(NV_INDEX_AK_CERT, &bytes));
    steps.push((READ_PUBLIC, failure()));
    steps.extend(reads(NV_INDEX_AK_CERT, &vec![0x91; MAX_NV_READ_SIZE + 1]));
    steps.extend(reads(NV_INDEX_AK_CERT, b"old"));
    steps.extend(reads(NV_INDEX_AK_CERT, b"new"));
    steps.push((READ_PUBLIC, failure()));
    steps.extend(reads(NV_INDEX_AK_CERT, b"recovered"));
    let (mut helper, state) = helper(steps);
    assert_eq!(handle_ak_cert(&mut helper, None, 0).unwrap(), bytes);
    assert_eq!(handle_ak_cert(&mut helper, Some(&bytes), 0).unwrap(), bytes);
    assert!(
        handle_ak_cert(&mut helper, Some(b"different"), 0)
            .unwrap_err()
            .to_string()
            .contains("contents did not match")
    );
    assert!(
        handle_ak_cert(&mut helper, None, 0)
            .unwrap_err()
            .to_string()
            .contains("Failed to read AK certificate")
    );
    assert!(
        handle_ak_cert(&mut helper, None, 0)
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum 4096 bytes")
    );
    assert_eq!(
        handle_ak_cert(&mut helper, Some(b"new"), 1).unwrap(),
        b"new"
    );
    assert_eq!(
        handle_ak_cert(&mut helper, Some(b"recovered"), 1).unwrap(),
        b"recovered"
    );
    assert_consumed(&state);
}
