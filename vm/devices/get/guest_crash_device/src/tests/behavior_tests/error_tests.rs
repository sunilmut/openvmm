// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Fail the host file-open RPC, then send write and complete messages on the failed dump channel.
// Expected: Start and later write replies use the original activity ID and negative status; completion does not falsely notify success, and no second file request is emitted.
#[async_test]
async fn open_failure_returns_negative_status_without_false_completion(driver: DefaultDriver) {
    let (host, guest) = connected_async_channels(16384);
    let mut guest = MessagePipe::new(guest).unwrap();
    let (send, mut requests) = mesh::channel();
    let mut worker = worker(host, send);
    let activity = Guid::from_slice(&[0x31; 16]);
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_START_V1, activity).as_bytes())
        .unwrap();
    advance(&mut worker, &driver).await.unwrap();
    let (done, response) = requests.next().await.unwrap().split();
    response.complete(Err(mesh::error::RemoteError::new(anyhow!(
        "dump file denied"
    ))));
    advance(&mut worker, &driver).await.unwrap();
    let expected = crash::DumpStartResponseV1 {
        header: header(crash::MessageType::RESPONSE_NIX_DUMP_START_V1, activity),
        status: -1,
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    assert!(done.await.is_err());
    guest
        .try_send(
            header(
                crash::MessageType::REQUEST_NIX_DUMP_WRITE_V1,
                Guid::from_slice(&[0x91; 16]),
            )
            .as_bytes(),
        )
        .unwrap();
    advance(&mut worker, &driver).await.unwrap();
    let expected = crash::DumpWriteResponseV1 {
        header: header(crash::MessageType::RESPONSE_NIX_DUMP_WRITE_V1, activity),
        status: -1,
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    guest
        .try_send(header(crash::MessageType::REQUEST_NIX_DUMP_COMPLETE_V1, activity).as_bytes())
        .unwrap();
    advance(&mut worker, &driver).await.unwrap();
    assert!(requests.next().now_or_never().is_none());
    assert!(guest.recv(&mut [0; 256]).now_or_never().is_none());
    guest
        .try_send(header(crash::MessageType::REQUEST_GET_CAPABILITIES_V1, activity).as_bytes())
        .unwrap();
    assert!(
        advance(&mut worker, &driver)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid message type")
    );
}

// Test: Accept a dump on a read-only file and attempt a payload write.
// Expected: The file remains unchanged, a negative write response identifies the original dump, and the host's completion receiver closes without success.
#[async_test]
async fn file_write_failure_returns_error_and_preserves_backing(driver: DefaultDriver) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"original bytes").unwrap();
    let (host, guest) = connected_async_channels(16384);
    let mut guest = MessagePipe::new(guest).unwrap();
    let (send, mut requests) = mesh::channel();
    let mut worker = worker(host, send);
    let done = open_dump(
        &mut worker,
        &mut guest,
        &mut requests,
        File::open(file.path()).unwrap(),
        &driver,
    )
    .await;
    let activity = Guid::from_slice(&[0x31; 16]);
    let write = crash::DumpWriteRequestV1 {
        header: header(crash::MessageType::REQUEST_NIX_DUMP_WRITE_V1, activity),
        offset: 0,
        size: 4,
    };
    guest.try_send(write.as_bytes()).unwrap();
    advance(&mut worker, &driver).await.unwrap();
    guest.try_send(b"new!").unwrap();
    advance(&mut worker, &driver).await.unwrap();
    let expected = crash::DumpWriteResponseV1 {
        header: header(crash::MessageType::RESPONSE_NIX_DUMP_WRITE_V1, activity),
        status: -1,
    };
    assert_eq!(receive(&mut guest, &driver).await, expected.as_bytes());
    assert_eq!(std::fs::read(file.path()).unwrap(), b"original bytes");
    assert!(done.await.is_err());
}

// Test: Send a mismatched payload size, a range crossing the configured dump limit, and an extreme offset.
// Expected: The relevant size/range error is returned without overflow or any file mutation, completion remains unsignaled, and no file is reopened.
#[async_test]
async fn payload_size_and_range_rejection_preserve_file_bytes(driver: DefaultDriver) {
    for (offset, declared, payload, expected) in [
        (0, 4, b"bad".as_slice(), "size mismatch"),
        (61, 4, b"four".as_slice(), "dump file out of range"),
        (u64::MAX, 4, b"four".as_slice(), "dump file out of range"),
    ] {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"original bytes").unwrap();
        let (host, guest) = connected_async_channels(16384);
        let mut guest = MessagePipe::new(guest).unwrap();
        let (send, mut requests) = mesh::channel();
        let mut worker = worker(host, send);
        let done = open_dump(
            &mut worker,
            &mut guest,
            &mut requests,
            file.try_clone().unwrap(),
            &driver,
        )
        .await;
        let write = crash::DumpWriteRequestV1 {
            header: header(
                crash::MessageType::REQUEST_NIX_DUMP_WRITE_V1,
                Guid::from_slice(&[0x31; 16]),
            ),
            offset,
            size: declared,
        };
        guest.try_send(write.as_bytes()).unwrap();
        advance(&mut worker, &driver).await.unwrap();
        guest.try_send(payload).unwrap();
        assert!(
            advance(&mut worker, &driver)
                .await
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original bytes");
        assert!(done.now_or_never().is_none());
        assert!(requests.next().now_or_never().is_none());
    }
}
