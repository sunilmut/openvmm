// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::kvp::KvpIc;
use crate::test_helpers::Guest;
use crate::test_helpers::Worker;
use crate::test_helpers::start;
use hyperv_ic_protocol::MessageType;
use hyperv_ic_protocol::Status;
use hyperv_ic_protocol::kvp as proto;
use hyperv_ic_resources::kvp as r;
use mesh::rpc::RpcSend;
use pal_async::DefaultDriver;
use pal_async::async_test;
use task_control::TaskControl;
use test_with_tracing::test;
use vmbus_channel::test_helpers::stop_with_timeout;
use vmbus_channel::test_helpers::with_timeout;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

pub(super) async fn connected(
    driver: &DefaultDriver,
    version: hyperv_ic_protocol::Version,
) -> (
    TaskControl<Worker<KvpIc>, ()>,
    Guest,
    mesh::Sender<r::KvpRpc>,
    mesh::OneshotReceiver<()>,
) {
    let (send, recv) = mesh::channel();
    let (task, mut guest) = start(driver, KvpIc::new(recv));
    let ready = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
    guest.negotiate(version).await;
    let (rpc, disconnected) = with_timeout(driver, ready).await.unwrap();
    (task, guest, rpc, disconnected)
}

fn text_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub(super) fn body<T: FromBytes>(bytes: &[u8], operation: proto::KvpOperation) -> T {
    let (header, _) = proto::KvpHeader::read_from_prefix(bytes).unwrap();
    assert_eq!(header.operation, operation);
    T::read_from_prefix(&bytes[align_of::<T>().max(2)..])
        .unwrap()
        .0
}

pub(super) fn packet<T: IntoBytes + Immutable>(
    operation: proto::KvpOperation,
    value: &T,
) -> Vec<u8> {
    let header = proto::KvpHeader {
        operation,
        pool: proto::KvpPool::GUEST,
    };
    let mut bytes = vec![0; align_of::<T>().max(2)];
    bytes[..2].copy_from_slice(header.as_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

// Test: Set values in each public KVP pool and delete a Unicode key.
// Expected: Requests carry exact UTF-16 strings, integer widths, pool IDs, and
//       operation codes; guest success and failure reach the caller.
#[async_test]
async fn set_and_delete_preserve_values_pools_and_status(driver: DefaultDriver) {
    let (mut task, mut guest, rpc, _disconnected) = connected(&driver, proto::KVP_VERSION_5).await;
    for (pool, wire_pool) in [
        (r::KvpPool::External, proto::KvpPool::EXTERNAL),
        (r::KvpPool::Guest, proto::KvpPool::GUEST),
        (r::KvpPool::Auto, proto::KvpPool::AUTO),
        (r::KvpPool::AutoExternal, proto::KvpPool::AUTO_EXTERNAL),
    ] {
        for value in [
            r::Value::String("text \u{1f642}".into()),
            r::Value::U32(0x12345678),
            r::Value::U64(0xfedcba9876543210),
        ] {
            let result = rpc.call_failable(
                r::KvpRpc::Set,
                r::SetParams {
                    pool,
                    key: "key \u{1f680}".into(),
                    value: value.clone(),
                },
            );
            let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
            let header = proto::KvpHeader::read_from_prefix(&frame.body).unwrap().0;
            assert_eq!(header.pool, wire_pool);
            let message: proto::MessageGetSet = body(&frame.body, proto::KvpOperation::SET);
            let expected_key = text_bytes("key \u{1f680}");
            assert_eq!(message.value.key_size as usize, expected_key.len());
            assert_eq!(
                &message.value.key.as_bytes()[..expected_key.len()],
                expected_key
            );
            let (kind, expected) = match value {
                r::Value::String(ref text) => (proto::ValueType::STRING, text_bytes(text)),
                r::Value::U32(value) => (proto::ValueType::DWORD, value.to_le_bytes().to_vec()),
                r::Value::U64(value) => (proto::ValueType::QWORD, value.to_le_bytes().to_vec()),
            };
            assert_eq!(message.value.value_type, kind);
            assert_eq!(message.value.value_size as usize, expected.len());
            assert_eq!(&message.value.value[..expected.len()], expected);
            guest.respond(&frame, Status::SUCCESS, &[]).await;
            with_timeout(&driver, result).await.unwrap();
        }
    }
    for status in [Status::SUCCESS, Status::FAIL] {
        let result = rpc.call_failable(
            r::KvpRpc::Delete,
            r::DeleteParams {
                pool: r::KvpPool::Guest,
                key: "key \u{1f680}".into(),
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let message: proto::MessageDelete = body(&frame.body, proto::KvpOperation::DELETE);
        let expected = text_bytes("key \u{1f680}");
        assert_eq!(message.key_size as usize, expected.len());
        assert_eq!(&message.key.as_bytes()[..expected.len()], expected);
        guest.respond(&frame, status, &[]).await;
        assert_eq!(
            with_timeout(&driver, result).await.is_ok(),
            status == Status::SUCCESS
        );
    }
    let result = rpc.call_failable(
        r::KvpRpc::Set,
        r::SetParams {
            pool: r::KvpPool::Guest,
            key: String::new(),
            value: r::Value::String(String::new()),
        },
    );
    let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
    let message: proto::MessageGetSet = body(&frame.body, proto::KvpOperation::SET);
    assert_eq!(message.value.key_size, 2);
    assert_eq!(message.value.value_size, 2);
    guest.respond(&frame, Status::FAIL, &[]).await;
    assert!(with_timeout(&driver, result).await.is_err());
    stop_with_timeout(&mut task, &driver).await;
}

fn enumerate_response(value: r::Value) -> proto::MessageEnumerate {
    let mut response = proto::MessageEnumerate::new_zeroed();
    let key: Vec<_> = "item".encode_utf16().chain([0]).collect();
    response.value.key[..key.len()].copy_from_slice(&key);
    response.value.key_size = (key.len() * 2) as u32;
    let (kind, bytes) = match value {
        r::Value::String(text) => (proto::ValueType::STRING, text_bytes(&text)),
        r::Value::U32(value) => (proto::ValueType::DWORD, value.to_le_bytes().to_vec()),
        r::Value::U64(value) => (proto::ValueType::QWORD, value.to_le_bytes().to_vec()),
    };
    response.value.value_type = kind;
    response.value.value_size = bytes.len() as u32;
    response.value.value[..bytes.len()].copy_from_slice(&bytes);
    response
}

// Test: Enumerate string and integer entries, exhaustion, and a guest error.
// Expected: Typed values and keys are preserved, exhaustion is None, and other
//       failures are not mistaken for the end of enumeration.
#[async_test]
async fn enumeration_preserves_types_and_distinguishes_exhaustion(driver: DefaultDriver) {
    let (mut task, mut guest, rpc, _disconnected) = connected(&driver, proto::KVP_VERSION_5).await;
    for (index, value) in [
        r::Value::U32(0x78563412),
        r::Value::U64(0xfedcba9876543210),
        r::Value::String("guest \u{1f642}".into()),
        r::Value::String(String::new()),
    ]
    .into_iter()
    .enumerate()
    {
        let result = rpc.call_failable(
            r::KvpRpc::Enumerate,
            r::EnumerateParams {
                pool: r::KvpPool::Auto,
                index: index as u32,
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let request: proto::MessageEnumerate = body(&frame.body, proto::KvpOperation::ENUMERATE);
        assert_eq!(request.index, index as u32);
        let response = enumerate_response(value.clone());
        guest
            .respond(
                &frame,
                Status::SUCCESS,
                &packet(proto::KvpOperation::ENUMERATE, &response),
            )
            .await;
        let actual = with_timeout(&driver, result).await.unwrap().unwrap();
        assert_eq!(actual.key, "item");
        assert_eq!(actual.value, value);
    }
    for status in [Status::NO_MORE_ITEMS, Status::FAIL] {
        let result = rpc.call_failable(
            r::KvpRpc::Enumerate,
            r::EnumerateParams {
                pool: r::KvpPool::Guest,
                index: u32::MAX,
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        guest.respond(&frame, status, &[]).await;
        let result = with_timeout(&driver, result).await;
        if status == Status::NO_MORE_ITEMS {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
    }
    stop_with_timeout(&mut task, &driver).await;
}

// Test: Return malformed enumeration bodies, lengths, types, and UTF-16 strings.
// Expected: Requests and disconnect observers report failure without a panic or
//       returning a fabricated key/value result.
#[async_test]
async fn malformed_enumeration_is_reported_to_callers(driver: DefaultDriver) {
    for case in 0..11 {
        let (mut task, mut guest, rpc, disconnected) =
            connected(&driver, proto::KVP_VERSION_5).await;
        let result = rpc.call_failable(
            r::KvpRpc::Enumerate,
            r::EnumerateParams {
                pool: r::KvpPool::Guest,
                index: 0,
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let mut response = enumerate_response(r::Value::U32(123));
        match case {
            0 | 1 => {}
            2 => response.value.key_size = 3,
            3 => response.value.key_size = proto::MAX_KEY_BYTES as u32 + 2,
            4 => response.value.key_size = 0,
            5 => {
                response.value.key[..2].copy_from_slice(&[0xd800, 0]);
                response.value.key_size = 4;
            }
            6 => response.value.value_size = 3,
            7 => {
                response.value.value_type = proto::ValueType::QWORD;
                response.value.value_size = 7;
            }
            8 => response.value.value_type = proto::ValueType(0xdead),
            9 => {
                response.value.value_type = proto::ValueType::STRING;
                response.value.value_size = 3;
            }
            10 => {
                response.value.value_type = proto::ValueType::STRING;
                response.value.value_size = 2;
                response.value.value[..2].copy_from_slice(&65u16.to_le_bytes());
            }
            _ => unreachable!(),
        }
        let mut bytes = packet(proto::KvpOperation::ENUMERATE, &response);
        if case < 2 {
            bytes.truncate(case * 4);
        }
        guest.respond(&frame, Status::SUCCESS, &bytes).await;
        assert!(with_timeout(&driver, result).await.is_err(), "case {case}");
        assert!(with_timeout(&driver, disconnected).await.is_err());
        stop_with_timeout(&mut task, &driver).await;
    }
}

// Test: Submit maximum-length keys and values, then an oversized key or value.
// Expected: Boundary strings retain their terminator and full contents;
//       oversized requests fail without transmitting truncated data.
#[async_test]
async fn string_limits_reject_truncation(driver: DefaultDriver) {
    for oversized_value in [false, true] {
        let (mut task, mut guest, rpc, disconnected) =
            connected(&driver, proto::KVP_VERSION_5).await;
        let key = "k".repeat(proto::MAX_KEY_BYTES / 2 - 1);
        let value = "v".repeat(proto::MAX_VALUE_BYTES / 2 - 1);
        let result = rpc.call_failable(
            r::KvpRpc::Set,
            r::SetParams {
                pool: r::KvpPool::Guest,
                key: key.clone(),
                value: r::Value::String(value.clone()),
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let message: proto::MessageGetSet = body(&frame.body, proto::KvpOperation::SET);
        assert_eq!(message.value.key.as_bytes(), text_bytes(&key));
        assert_eq!(message.value.value, text_bytes(&value).as_slice());
        guest.respond(&frame, Status::SUCCESS, &[]).await;
        with_timeout(&driver, result).await.unwrap();
        let result = rpc.call_failable(
            r::KvpRpc::Set,
            r::SetParams {
                pool: r::KvpPool::Guest,
                key: if oversized_value { key } else { key + "x" },
                value: r::Value::String(if oversized_value { value + "x" } else { value }),
            },
        );
        assert!(with_timeout(&driver, result).await.is_err());
        assert!(with_timeout(&driver, disconnected).await.is_err());
        stop_with_timeout(&mut task, &driver).await;
    }
}

// Test: Register clients before and after negotiation, including a dropped client.
// Expected: Each live caller receives a usable RPC connection, and dropping one
//       disconnect observer does not prevent later clients from connecting.
#[async_test]
async fn multiple_clients_connect_before_and_after_negotiation(driver: DefaultDriver) {
    let (send, recv) = mesh::channel();
    let (mut task, mut guest) = start(&driver, KvpIc::new(recv));
    let first = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
    let second = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
    guest.negotiate(proto::KVP_VERSION_5).await;
    let (_, first_closed) = with_timeout(&driver, first).await.unwrap();
    let (_second_rpc, _second_closed) = with_timeout(&driver, second).await.unwrap();
    drop(first_closed);
    let (rpc, _closed) = with_timeout(
        &driver,
        send.call_failable(r::KvpConnectRpc::WaitForGuest, ()),
    )
    .await
    .unwrap();
    let result = rpc.call_failable(
        r::KvpRpc::Enumerate,
        r::EnumerateParams {
            pool: r::KvpPool::Guest,
            index: 0,
        },
    );
    let request = guest.receive(MessageType::KVP_EXCHANGE).await;
    guest.respond(&request, Status::NO_MORE_ITEMS, &[]).await;
    assert!(with_timeout(&driver, result).await.unwrap().is_none());
    stop_with_timeout(&mut task, &driver).await;
}

// Test: Reject negotiation with an unsupported version or guest failure status.
// Expected: Both queued and later connection requests fail promptly.
#[async_test]
async fn negotiation_failure_reaches_queued_and_later_clients(driver: DefaultDriver) {
    for case in 0..3 {
        let (send, recv) = mesh::channel();
        let (mut task, mut guest) = start(&driver, KvpIc::new(recv));
        let first = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
        let second = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
        let offer = guest.receive(MessageType::VERSION_NEGOTIATION).await;
        let counts = hyperv_ic_protocol::NegotiateMessage {
            framework_version_count: 1,
            message_version_count: 1,
            reserved: 0,
        };
        let invalid = hyperv_ic_protocol::Version::new(99, 99);
        let versions = [
            if case == 0 {
                invalid
            } else {
                hyperv_ic_protocol::FRAMEWORK_VERSION_3
            },
            if case == 1 {
                invalid
            } else {
                proto::KVP_VERSION_5
            },
        ];
        guest
            .respond(
                &offer,
                if case == 2 {
                    Status::FAIL
                } else {
                    Status::SUCCESS
                },
                &[counts.as_bytes(), versions.as_bytes()].concat(),
            )
            .await;
        assert!(with_timeout(&driver, first).await.is_err());
        assert!(with_timeout(&driver, second).await.is_err());
        assert!(
            with_timeout(
                &driver,
                send.call_failable(r::KvpConnectRpc::WaitForGuest, ())
            )
            .await
            .is_err()
        );
        stop_with_timeout(&mut task, &driver).await;
    }

    // Test: Save and restore a connected KVP device using its public device hooks.
    // Expected: Old clients disconnect, the guest renegotiates, and a new connection
    //       can enumerate normally without inheriting the old transaction.
    #[async_test]
    async fn restore_requires_fresh_negotiation_and_new_clients(driver: DefaultDriver) {
        let (send, recv) = mesh::channel();
        let (mut task, mut guest) = start(&driver, KvpIc::new(recv));
        let ready = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
        guest.negotiate(proto::KVP_VERSION_5).await;
        let (_old_rpc, disconnected) = with_timeout(&driver, ready).await.unwrap();
        stop_with_timeout(&mut task, &driver).await;
        let mut guest = crate::test_helpers::restore(&driver, &mut task);
        assert!(with_timeout(&driver, disconnected).await.is_err());
        assert!(task.start());
        let ready = send.call_failable(r::KvpConnectRpc::WaitForGuest, ());
        guest.negotiate(proto::KVP_VERSION_4).await;
        let (rpc, _disconnected) = with_timeout(&driver, ready).await.unwrap();
        let result = rpc.call_failable(
            r::KvpRpc::Enumerate,
            r::EnumerateParams {
                pool: r::KvpPool::Guest,
                index: 0,
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        assert_eq!(frame.header.message_version, proto::KVP_VERSION_4);
        guest.respond(&frame, Status::NO_MORE_ITEMS, &[]).await;
        assert!(with_timeout(&driver, result).await.unwrap().is_none());
        stop_with_timeout(&mut task, &driver).await;
    }
}
