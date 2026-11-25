// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::backing::FileError;
use crate::backing::FileInfo;
use crate::backing::VmbfsIo;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

fn channel() -> (VmbfsChannel<FlatRingMem>, MessagePipe<FlatRingMem>) {
    let (host, guest) = vmbus_channel::connected_async_channels(65536);
    (
        VmbfsChannel {
            state: State::VersionRequest,
            pipe: MessagePipe::new(host).unwrap(),
            buf: vec![0; protocol::MAX_MESSAGE_SIZE],
        },
        MessagePipe::new(guest).unwrap(),
    )
}

// Test: Decode all truncated headers/version/read bodies, unsupported message types, odd-length/NUL/invalid-surrogate paths, and a valid backslash/supplementary-Unicode path.
// Expected: Invalid wire input returns its specific typed error without panicking, while a valid path preserves Unicode and normalizes separators.
#[async_test]
async fn malformed_wire_messages_are_rejected_and_unicode_paths_normalize(driver: DefaultDriver) {
    let mut cases = Vec::new();
    for len in 0..size_of::<protocol::MessageHeader>() {
        cases.push((vec![0; len], "short"));
    }
    for (ty, required) in [
        (
            protocol::MessageType::VERSION_REQUEST,
            size_of::<protocol::VersionRequest>(),
        ),
        (
            protocol::MessageType::READ_FILE_REQUEST,
            size_of::<protocol::ReadFileRequest>(),
        ),
    ] {
        for len in 0..required {
            cases.push((packet(ty, &vec![0; len]), "short"));
        }
    }
    for ty in [0, 2, 4, 6, 7, 8, u32::MAX] {
        cases.push((packet(protocol::MessageType(ty), &[]), "type"));
    }
    for (path, expected) in [
        (vec![1], "unaligned"),
        (vec![0, 0], "nul"),
        (vec![0, 0xd8], "utf16"),
    ] {
        cases.push((
            packet(protocol::MessageType::GET_FILE_INFO_REQUEST, &path),
            expected,
        ));
    }
    for (wire, expected) in cases {
        let (mut host, mut guest) = channel();
        guest.try_send(&wire).unwrap();
        let error = with_timeout(&driver, host.read_message())
            .await
            .unwrap_err();
        assert!(
            match expected {
                "short" => matches!(error, DeviceError::TooShort),
                "type" => matches!(error, DeviceError::InvalidMessageType(_)),
                "unaligned" => matches!(error, DeviceError::Unaligned),
                "nul" => matches!(error, DeviceError::NullTerminatorInPath),
                "utf16" => matches!(error, DeviceError::InvalidUtf16Path),
                _ => unreachable!(),
            },
            "unexpected error for {expected}: {error:?}"
        );
    }
    let (mut host, mut guest) = channel();
    guest
        .try_send(&packet(
            protocol::MessageType::GET_FILE_INFO_REQUEST,
            &path_bytes("\\folder\\\u{1f642}.bin"),
        ))
        .unwrap();
    assert!(
        matches!(with_timeout(&driver, host.read_message()).await.unwrap(), Request::GetFileInfo(path) if path == "/folder/\u{1f642}.bin")
    );
}

#[derive(InspectMut)]
struct FaultBacking {
    #[inspect(skip)]
    reads: Arc<AtomicUsize>,
}

impl VmbfsIo for FaultBacking {
    fn file_info(&mut self, path: &str) -> Result<FileInfo, FileError> {
        if path == "/dir" {
            Ok(FileInfo {
                directory: true,
                file_size: 0,
            })
        } else {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "file denied").into())
        }
    }

    fn read_file(&mut self, _path: &str, _offset: u64, buf: &mut [u8]) -> Result<(), FileError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        buf.fill(0x5a);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read denied").into())
    }
}

// Test: Query directory/denied metadata, let a failed backing read dirty its scratch buffer, then request one byte above the protocol read limit.
// Expected: Directory/error flags and sizes are exact, failed reads return no scratch data, and oversized reads fail before any backing call or response publication.
#[async_test]
async fn backing_errors_do_not_leak_data_and_oversized_reads_never_reach_backing(
    driver: DefaultDriver,
) {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut device = VmbfsDevice::new(Box::new(FaultBacking {
        reads: reads.clone(),
    }));
    let (mut host, mut guest) = channel();
    for (path, status, directory) in [
        ("/dir", protocol::Status::SUCCESS, true),
        ("/denied", protocol::Status::ERROR, false),
    ] {
        host.handle_get_file_info(&mut device, path).unwrap();
        let reply = receive(&driver, &mut guest).await;
        let (_, body) = protocol::MessageHeader::read_from_prefix(&reply).unwrap();
        let (info, tail) = protocol::GetFileInfoResponse::read_from_prefix(body).unwrap();
        assert!(tail.is_empty());
        assert_eq!(info.status, status);
        assert_eq!(info.file_size, 0);
        assert_eq!(info.flags.directory(), directory);
        assert!(!info.flags.rdma_capable());
    }
    host.handle_read_file(&mut device, "/denied", 0, 64)
        .unwrap();
    let reply = receive(&driver, &mut guest).await;
    let (header, body) = protocol::MessageHeader::read_from_prefix(&reply).unwrap();
    assert_eq!(
        header.message_type,
        protocol::MessageType::READ_FILE_RESPONSE
    );
    let (response, data) = protocol::ReadFileResponse::read_from_prefix(body).unwrap();
    assert_eq!(response.status, protocol::Status::ERROR);
    assert!(data.is_empty());
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert!(matches!(
        host.handle_read_file(
            &mut device,
            "/denied",
            0,
            protocol::MAX_READ_SIZE as u32 + 1
        ),
        Err(DeviceError::ReadTooLarge)
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    let mut reply = [0; 32];
    assert!(guest.recv(&mut reply).now_or_never().is_none());
}

// Test: Read alternating sparse-file offsets above and below 4 GiB with identical low 32 bits through real message rings.
// Expected: Each response contains the exact bytes at its full-width absolute offset, never the low-offset alias or bytes from the preceding read position.
#[async_test]
async fn sparse_file_wire_reads_preserve_full_width_absolute_offsets(driver: DefaultDriver) {
    use std::io::Seek;

    let high_offset = (1u64 << 32) + 7;
    let mut file = tempfile::tempfile().unwrap();
    file.seek(io::SeekFrom::Start(7)).unwrap();
    file.write_all(b"lower123").unwrap();
    file.seek(io::SeekFrom::Start(high_offset)).unwrap();
    file.write_all(b"UPPER\0\x81\xff").unwrap();
    let backing = single_file_backing::VmbfsSingleFileBacking::new("hello.bin", file).unwrap();
    let mut device = VmbfsDevice::new(Box::new(backing));
    let (mut host, mut guest) = channel();

    for (offset, expected) in [
        (high_offset, b"UPPER\0\x81\xff"),
        (7, b"lower123"),
        (high_offset, b"UPPER\0\x81\xff"),
    ] {
        let request = protocol::ReadFileRequest {
            byte_count: expected.len() as u32,
            offset: offset.into(),
        };
        guest
            .try_send(&packet(
                protocol::MessageType::READ_FILE_REQUEST,
                &[request.as_bytes(), &path_bytes("/hello.bin")].concat(),
            ))
            .unwrap();
        let Request::ReadFile {
            byte_count,
            offset,
            path,
        } = with_timeout(&driver, host.read_message()).await.unwrap()
        else {
            panic!("expected a file read request");
        };
        host.handle_read_file(&mut device, &path, offset, byte_count)
            .unwrap();
        let reply = receive(&driver, &mut guest).await;
        assert_eq!(
            reply,
            packet(
                protocol::MessageType::READ_FILE_RESPONSE,
                &[
                    protocol::ReadFileResponse {
                        status: protocol::Status::SUCCESS,
                    }
                    .as_bytes(),
                    expected,
                ]
                .concat(),
            )
        );
    }
}
