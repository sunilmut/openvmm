// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::tpm::RawTpm;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use test_with_tracing::test;

fn pair() -> (crate::tpm::Tpm, UnixStream) {
    let (device, peer) = UnixStream::pair().unwrap();
    for socket in [&device, &peer] {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    (
        crate::tpm::Tpm {
            inner: Tpm {
                file: Mutex::new(OwnedFd::from(device).into()),
            },
        },
        peer,
    )
}
fn command() -> Vec<u8> {
    vec![0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x7b, 0x91, 0xff]
}

// Test: Send commands through the actual Unix file transport and return byte-fragmented TPM responses with and without a body.
// Expected: Exactly the original command reaches the peer, declared response bytes are returned unchanged after all fragments arrive, and a short command emits no bytes.
#[test]
fn unix_transport_preserves_fragmented_response_and_command_bytes() {
    for response in [
        vec![0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0],
        vec![0x80, 1, 0, 0, 0, 13, 0, 0, 0, 0, 0x91, 0, 0xff],
    ] {
        let (device, mut peer) = pair();
        std::thread::scope(|scope| {
            let expected = &response;
            scope.spawn(move || {
                let mut received = [0; 12];
                peer.read_exact(&mut received).unwrap();
                assert_eq!(received.as_slice(), command());
                for byte in expected {
                    peer.write_all(&[*byte]).unwrap();
                }
            });
            assert_eq!(device.transmit_raw(&command()).unwrap(), response);
        });
    }
    let (device, mut peer) = pair();
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        device.transmit(&[0; 9]).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

// Test: Return a TPM header declaring less than ten bytes, truncate the header, or truncate a declared response body.
// Expected: Invalid lengths return InvalidData, either truncation returns UnexpectedEof, and no partial response is published as success.
#[test]
fn unix_transport_rejects_invalid_and_truncated_response_lengths() {
    for (response, kind) in [
        (
            vec![0x80, 1, 0, 0, 0, 9, 0, 0, 0, 0],
            io::ErrorKind::InvalidData,
        ),
        (
            vec![0x80, 1, 0, 0, 0, 10, 0, 0, 0],
            io::ErrorKind::UnexpectedEof,
        ),
        (
            vec![0x80, 1, 0, 0, 0, 13, 0, 0, 0, 0, 0x91],
            io::ErrorKind::UnexpectedEof,
        ),
    ] {
        let (device, mut peer) = pair();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut received = [0; 12];
                peer.read_exact(&mut received).unwrap();
                assert_eq!(received.as_slice(), command());
                peer.write_all(&response).unwrap();
            });
            assert_eq!(device.transmit(&command()).unwrap_err().kind(), kind);
        });
    }
}

// Test: Build the public engine helper from a socket-backed TPM and issue an NV metadata read that receives a valid TPM missing-handle error.
// Expected: The helper sends the exact requested NV_ReadPublic command through both adapters and returns the TPM failure rather than swallowing it or querying another NV handle.
#[test]
fn unix_tpm_engine_helper_preserves_nv_handle_and_tpm_failure() {
    let (device, mut peer) = pair();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let mut command = [0; 14];
            peer.read_exact(&mut command).unwrap();
            assert_eq!(
                command,
                [0x80, 1, 0, 0, 0, 14, 0, 0, 1, 0x69, 1, 0x50, 0, 0x16]
            );
            peer.write_all(&[0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x8b])
                .unwrap();
        });
        let error = device
            .into_engine_helper()
            .nv_read_public(0x1500016)
            .unwrap_err();
        assert!(matches!(
            error,
            tpm_lib::TpmCommandError::TpmCommandFailed {
                response_code: 0x18b
            }
        ));
    });
}
