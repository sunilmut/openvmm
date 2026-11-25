// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::io::Write;
use test_with_tracing::test;
use vmbus_ring::FlatRingMem;

mod error_tests;
mod lifecycle_tests;

struct FileWorker {
    device: VmbfsDevice,
    channel: VmbfsChannel<FlatRingMem>,
}

impl AsyncRun<()> for FileWorker {
    async fn run(&mut self, stop: &mut StopTask<'_>, _: &mut ()) -> Result<(), Cancelled> {
        let check = stop.check_handle()?;
        stop.until_stopped(self.channel.process(&mut self.device, &check))
            .await?
    }
}

fn packet(ty: protocol::MessageType, body: &[u8]) -> Vec<u8> {
    [
        protocol::MessageHeader {
            message_type: ty,
            reserved: 0,
        }
        .as_bytes(),
        body,
    ]
    .concat()
}

fn path_bytes(path: &str) -> Vec<u8> {
    path.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

async fn receive<M: RingMem + Unpin>(driver: &DefaultDriver, pipe: &mut MessagePipe<M>) -> Vec<u8> {
    let mut buffer = vec![0; protocol::MAX_MESSAGE_SIZE];
    let len = with_timeout(driver, pipe.recv(&mut buffer)).await.unwrap();
    buffer.truncate(len);
    buffer
}

async fn start(driver: &DefaultDriver) -> (TaskControl<FileWorker, ()>, MessagePipe<FlatRingMem>) {
    let (host, guest) = vmbus_channel::connected_async_channels(65536);
    let mut file = tempfile::tempfile().unwrap();
    let data: Vec<u8> = (0..protocol::MAX_READ_SIZE + 64)
        .map(|index| index as u8)
        .collect();
    file.write_all(&data).unwrap();
    let backing = single_file_backing::VmbfsSingleFileBacking::new("hello.bin", file).unwrap();
    let mut task = TaskControl::new(FileWorker {
        device: VmbfsDevice::new(Box::new(backing)),
        channel: VmbfsChannel {
            state: State::VersionRequest,
            pipe: MessagePipe::new(host).unwrap(),
            buf: vec![0; protocol::MAX_MESSAGE_SIZE],
        },
    });
    task.insert(driver, "vmbfs-behavior", ());
    assert!(task.start());
    let mut guest = MessagePipe::new(guest).unwrap();
    guest
        .try_send(&packet(
            protocol::MessageType::VERSION_REQUEST,
            protocol::VersionRequest {
                requested_version: protocol::Version::WIN10,
            }
            .as_bytes(),
        ))
        .unwrap();
    let reply = receive(driver, &mut guest).await;
    assert_eq!(reply, vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    (task, guest)
}

// Test: Negotiate WIN10 over real message rings, query present/missing files, and read offset data through the maximum protocol payload and end of file.
// Expected: Replies have exact headers/status/lengths, file information matches the real backing, successful reads return only the requested bytes, and EOF/missing reads return no stale payload.
#[async_test]
async fn negotiated_file_info_and_reads_return_exact_wire_data(driver: DefaultDriver) {
    let (mut task, mut guest) = start(&driver).await;
    for (path, status, size) in [
        (
            "/hello.bin",
            protocol::Status::SUCCESS,
            (protocol::MAX_READ_SIZE + 64) as u64,
        ),
        ("/missing", protocol::Status::NOT_FOUND, 0),
    ] {
        guest
            .try_send(&packet(
                protocol::MessageType::GET_FILE_INFO_REQUEST,
                &path_bytes(path),
            ))
            .unwrap();
        let reply = receive(&driver, &mut guest).await;
        let (header, body) = protocol::MessageHeader::read_from_prefix(&reply).unwrap();
        assert_eq!(
            header.message_type,
            protocol::MessageType::GET_FILE_INFO_RESPONSE
        );
        assert_eq!(header.reserved, 0);
        let (info, tail) = protocol::GetFileInfoResponse::read_from_prefix(body).unwrap();
        assert!(tail.is_empty());
        assert_eq!(info.status, status);
        assert_eq!(info.file_size, size);
        assert!(!info.flags.directory());
        assert!(!info.flags.rdma_capable());
    }
    for (path, offset, count, status) in [
        ("/hello.bin", 7, 31, protocol::Status::SUCCESS),
        (
            "/hello.bin",
            64,
            protocol::MAX_READ_SIZE as u32,
            protocol::Status::SUCCESS,
        ),
        (
            "/hello.bin",
            (protocol::MAX_READ_SIZE + 64) as u64,
            1,
            protocol::Status::END_OF_FILE,
        ),
        ("/missing", 0, 1, protocol::Status::NOT_FOUND),
    ] {
        let request = protocol::ReadFileRequest {
            byte_count: count,
            offset: offset.into(),
        };
        guest
            .try_send(&packet(
                protocol::MessageType::READ_FILE_REQUEST,
                &[request.as_bytes(), &path_bytes(path)].concat(),
            ))
            .unwrap();
        let reply = receive(&driver, &mut guest).await;
        let (header, body) = protocol::MessageHeader::read_from_prefix(&reply).unwrap();
        assert_eq!(
            header.message_type,
            protocol::MessageType::READ_FILE_RESPONSE
        );
        assert_eq!(header.reserved, 0);
        let (response, data) = protocol::ReadFileResponse::read_from_prefix(body).unwrap();
        assert_eq!(response.status, status);
        let expected = if status == protocol::Status::SUCCESS {
            (0..count)
                .map(|index| offset.wrapping_add(index as u64) as u8)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        assert_eq!(data, expected);
    }
    stop_with_timeout(&mut task, &driver).await;
}
