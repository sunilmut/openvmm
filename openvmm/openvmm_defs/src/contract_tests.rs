// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config::{LateMapVtl0MemoryPolicy, Vtl2Config};
use crate::rpc::{PulseSaveRestoreError, VmRpc};
use mesh::rpc::RpcSend;
use pal_async::async_test;
use test_with_tracing::test;

fn transfer(request: VmRpc) -> VmRpc {
    let (bytes, resources) = mesh::Message::new(request).serialize();
    mesh::Message::serialized(&bytes, resources)
        .parse()
        .unwrap()
}

// Test: Transport memory RPCs with a high GPA, binary data and live reply ports.
// Expected: Read/write requests retain direction, full address, size and bytes;
//       successful replies still reach the original caller after serialization.
#[async_test]
async fn memory_rpc_payload_and_reply_ports_survive_transport() {
    let (sender, mut receiver) = mesh::channel();
    let gpa = 0x1234_5678_9abc_def0;
    let payload = vec![0x80, 0x00, 0xff, 0x42, 0x17];
    let reply = sender.call_failable(VmRpc::WriteMemory, (gpa, payload.clone()));
    match transfer(receiver.recv().await.unwrap()) {
        VmRpc::WriteMemory(rpc) => {
            assert_eq!(rpc.input(), &(gpa, payload.clone()));
            rpc.complete(Ok(()));
        }
        _ => panic!("write memory changed RPC direction"),
    }
    reply.await.unwrap();
    let reply = sender.call_failable(VmRpc::ReadMemory, (gpa, payload.len()));
    match transfer(receiver.recv().await.unwrap()) {
        VmRpc::ReadMemory(rpc) => {
            assert_eq!(rpc.input(), &(gpa, payload.len()));
            rpc.complete(Ok(payload.clone()));
        }
        _ => panic!("read memory changed RPC direction"),
    }
    assert_eq!(reply.await.unwrap(), payload);
}

// Test: Carry both typed unsupported-reset and contextual save failures by RPC.
// Expected: The receiver can distinguish the failure kinds and recover the
//       original remote error and its cause, not just a generic failure string.
#[async_test]
async fn pulse_save_error_identity_and_cause_survive_transport() {
    use std::error::Error;

    let (sender, mut receiver) = mesh::channel();
    for unsupported in [true, false] {
        let reply = sender.call(VmRpc::PulseSaveRestore, ());
        let VmRpc::PulseSaveRestore(rpc) = transfer(receiver.recv().await.unwrap()) else {
            panic!("pulse save changed RPC kind");
        };
        let error = if unsupported {
            PulseSaveRestoreError::ResetNotSupported
        } else {
            anyhow::anyhow!("storage refused")
                .context("save image")
                .into()
        };
        let (bytes, resources) = mesh::Message::new(error).serialize();
        let error = mesh::Message::serialized(&bytes, resources)
            .parse()
            .unwrap();
        rpc.complete(Err(error));
        let error = reply.await.unwrap().unwrap_err();
        if unsupported {
            assert!(matches!(error, PulseSaveRestoreError::ResetNotSupported));
        } else {
            let PulseSaveRestoreError::Other(remote) = error else {
                panic!("contextual failure changed kind");
            };
            assert_eq!(remote.to_string(), "save image");
            assert_eq!(remote.source().unwrap().to_string(), "storage refused");
        }
    }
}

// Test: Transport each VTL0 late-map policy within its VTL2 configuration.
// Expected: Alias-map choice is preserved and the resulting partition policy
//       selects the same halt, log/emulate or guest-exception behavior.
#[test]
fn vtl2_policy_survives_transport_and_partition_conversion() {
    for (policy, expected) in [
        (
            LateMapVtl0MemoryPolicy::Halt,
            virt::LateMapVtl0MemoryPolicy::Halt,
        ),
        (
            LateMapVtl0MemoryPolicy::Log,
            virt::LateMapVtl0MemoryPolicy::Log,
        ),
        (
            LateMapVtl0MemoryPolicy::InjectException,
            virt::LateMapVtl0MemoryPolicy::InjectException,
        ),
    ] {
        for alias in [false, true] {
            let (bytes, resources) = mesh::Message::new(Vtl2Config {
                vtl0_alias_map: alias,
                late_map_vtl0_memory: Some(policy),
            })
            .serialize();
            let restored: Vtl2Config = mesh::Message::serialized(&bytes, resources)
                .parse()
                .unwrap();
            assert_eq!(restored.vtl0_alias_map, alias);
            assert_eq!(restored.late_map_vtl0_memory, Some(policy));
            let converted: virt::LateMapVtl0MemoryPolicy =
                restored.late_map_vtl0_memory.unwrap().into();
            assert_eq!(converted, expected);
        }
    }
}
