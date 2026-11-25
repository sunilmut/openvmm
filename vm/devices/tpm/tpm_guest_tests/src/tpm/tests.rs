// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;

type Calls = Arc<Mutex<Vec<Vec<u8>>>>;

struct Transport {
    calls: Calls,
    reply: Result<Vec<u8>, io::ErrorKind>,
}
impl RawTpm for Transport {
    fn transmit_raw(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        self.calls.lock().push(command.to_vec());
        self.reply.clone().map_err(io::Error::from)
    }
}

fn command() -> Vec<u8> {
    vec![0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x7b, 0x91, 0xff]
}

// Test: Forward binary command bytes to a recording raw transport and copy a shorter response into a guarded engine buffer.
// Expected: The command is forwarded once unchanged; exact reply bytes are copied, only the remaining response slice is zeroed, and bytes outside that slice are preserved.
#[test]
fn engine_forwards_exact_command_and_pads_only_the_response_slice() {
    let calls = Calls::default();
    let reply = vec![0x80, 1, 0, 0, 0, 13, 0, 0, 0, 0, 0x91, 0, 0xff];
    let mut engine = DriverTpmEngine::new(Transport {
        calls: calls.clone(),
        reply: Ok(reply.clone()),
    });
    let mut command = command();
    let original = command.clone();
    let mut storage = [0xa7; 32];
    engine
        .execute_command(&mut command, &mut storage[4..24])
        .unwrap();
    assert_eq!(command, original);
    assert_eq!(*calls.lock(), [original]);
    assert_eq!(&storage[..4], &[0xa7; 4]);
    assert_eq!(&storage[4..17], reply);
    assert_eq!(&storage[17..24], &[0; 7]);
    assert_eq!(&storage[24..], &[0xa7; 8]);
    assert_eq!(
        engine.max_nv_index_size(),
        tpm_lib::TPM_V185_MAX_NV_INDEX_SIZE
    );
}

// Test: Submit every command length below the ten-byte TPM header and a valid command whose response exceeds the caller buffer.
// Expected: Short commands never reach the transport; oversize responses return an error after exactly one transport call, and neither rejection changes any response-buffer byte.
#[test]
fn invalid_command_and_response_lengths_preserve_output_buffers() {
    let calls = Calls::default();
    let mut engine = DriverTpmEngine::new(Transport {
        calls: calls.clone(),
        reply: Ok(vec![0x91; 32]),
    });
    for length in 0..10 {
        let mut output = [0xa7; 31];
        let error = engine
            .execute_command(&mut vec![0; length], &mut output)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("TPM command shorter than header")
        );
        assert_eq!(output, [0xa7; 31]);
    }
    assert!(calls.lock().is_empty());
    let mut output = [0xa7; 31];
    let error = engine
        .execute_command(&mut command(), &mut output)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("TPM response length 32 exceeds reply buffer 31")
    );
    assert_eq!(calls.lock().len(), 1);
    assert_eq!(output, [0xa7; 31]);
}

// Test: Return a raw transport failure while executing a valid command.
// Expected: The adapter returns the original failure context after one exact command and leaves the caller's response bytes unchanged.
#[test]
fn transport_failure_does_not_publish_partial_output() {
    let calls = Calls::default();
    let mut engine = DriverTpmEngine::new(Transport {
        calls: calls.clone(),
        reply: Err(io::ErrorKind::PermissionDenied),
    });
    let mut output = [0xa7; 32];
    let error = engine
        .execute_command(&mut command(), &mut output)
        .unwrap_err();
    assert!(error.to_string().contains("permission denied"));
    assert_eq!(*calls.lock(), [command()]);
    assert_eq!(output, [0xa7; 32]);
}
