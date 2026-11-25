// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::barrier;
use super::wire::setup;
use crate::error::IgvmAttestError;
use futures::FutureExt;
use get_protocol as p;
use pal_async::DefaultDriver;
use pal_async::async_test;
use std::pin::pin;
use test_with_tracing::test;
use user_driver::DmaClient;
use user_driver_emulated_mock::DeviceTestMemory;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

// Test: Run an attestation backed by shared DMA while a normal time request is serviced.
// Expected: Agent/report bytes reach the host, primary requests do not block
//       behind attestation, and the caller receives exactly the shared response.
#[async_test]
async fn attestation_uses_shared_memory_without_blocking_primary_requests(driver: DefaultDriver) {
    let (mut client, mut host, _task) = setup(&driver).await;
    let memory = DeviceTestMemory::new(4, true, "get-attestation");
    let dma = memory.dma_client();
    client.set_gpa_allocator(dma.clone());
    let mut call = pin!(client.igvm_attest(b"agent".to_vec(), b"report".to_vec(), 8192));
    assert!(call.as_mut().now_or_never().is_none());
    let request = p::IgvmAttestRequest::read_from_bytes(&host.receive().await).unwrap();
    assert_eq!(
        request.message_header.message_id(),
        p::HostRequests::IGVM_ATTEST
    );
    assert_eq!(
        &request.agent_data[..request.agent_data_length as usize],
        b"agent"
    );
    assert_eq!(&request.report[..request.report_length as usize], b"report");
    assert!(request.agent_data[5..].iter().all(|&b| b == 0));
    assert!(request.report[6..].iter().all(|&b| b == 0));
    barrier(&client, &mut host).await;
    assert!(call.as_mut().now_or_never().is_none());
    let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    for (gpa, bytes) in request.shared_gpa.iter().zip(payload.chunks(4096)) {
        memory.guest_memory().write_at(*gpa, bytes).unwrap();
    }
    host.send(
        p::IgvmAttestResponse {
            message_header: p::HeaderGeneric::new(p::HostRequests::IGVM_ATTEST),
            length: payload.len() as u32,
        }
        .as_bytes(),
    )
    .await;
    assert_eq!(call.await.unwrap().response, payload);
    let _reused = dma.allocate_dma_buffer(8192).unwrap();
}

// Test: Reject agent data and reports exceeding their protocol limits.
// Expected: Public size errors identify the rejected length, no host request
//       is emitted, and later ordinary requests continue to work.
#[async_test]
async fn attestation_input_limits_return_errors_without_sending_packets(driver: DefaultDriver) {
    let (mut client, mut host, _task) = setup(&driver).await;
    let memory = DeviceTestMemory::new(8, true, "get-attestation-limits");
    client.set_gpa_allocator(memory.dma_client());
    let result = client
        .igvm_attest(
            vec![1; p::IGVM_ATTEST_MSG_REQ_AGENT_DATA_MAX_SIZE + 1],
            Vec::new(),
            4096,
        )
        .await;
    assert!(
        matches!(result, Err(IgvmAttestError::InvalidAgentDataSize { input_size, expected_size })
        if input_size == expected_size + 1 && expected_size == p::IGVM_ATTEST_MSG_REQ_AGENT_DATA_MAX_SIZE)
    );
    let result = client
        .igvm_attest(
            Vec::new(),
            vec![2; p::IGVM_ATTEST_MSG_REQ_REPORT_MAX_SIZE + 1],
            4096,
        )
        .await;
    assert!(
        matches!(result, Err(IgvmAttestError::InvalidReportSize { input_size, expected_size })
        if input_size == expected_size + 1 && expected_size == p::IGVM_ATTEST_MSG_REQ_REPORT_MAX_SIZE)
    );
    barrier(&client, &mut host).await;
}

// Test: Have the IGVM agent return its protocol-defined generic failure code.
// Expected: The caller receives the public agent-error variant rather than
//       attempting to allocate or read that sentinel as a response length.
#[async_test]
async fn attestation_agent_failure_is_not_treated_as_a_response_length(driver: DefaultDriver) {
    let (mut client, mut host, _task) = setup(&driver).await;
    let memory = DeviceTestMemory::new(8, true, "get-attestation-error");
    client.set_gpa_allocator(memory.dma_client());
    let mut call = pin!(client.igvm_attest(Vec::new(), Vec::new(), 4096));
    assert!(call.as_mut().now_or_never().is_none());
    let request = p::IgvmAttestRequest::read_from_bytes(&host.receive().await).unwrap();
    assert_eq!(
        request.message_header.message_id(),
        p::HostRequests::IGVM_ATTEST
    );
    host.send(
        p::IgvmAttestResponse {
            message_header: p::HeaderGeneric::new(p::HostRequests::IGVM_ATTEST),
            length: p::IGVM_ATTEST_VMWP_GENERIC_ERROR_CODE as u32,
        }
        .as_bytes(),
    )
    .await;
    assert!(matches!(
        call.await,
        Err(IgvmAttestError::IgvmAgentGenericError)
    ));
}

// Test: Receive an attestation response longer than the shared output allocation.
// Expected: The worker returns a descriptive fatal error instead of reading
//       outside the shared buffer or returning truncated data.
#[async_test]
async fn oversized_attestation_response_is_a_reported_transport_failure(driver: DefaultDriver) {
    let (mut client, mut host, task) = setup(&driver).await;
    let memory = DeviceTestMemory::new(8, true, "get-attestation-oversize");
    client.set_gpa_allocator(memory.dma_client());
    let mut call = pin!(client.igvm_attest(Vec::new(), Vec::new(), 4096));
    assert!(call.as_mut().now_or_never().is_none());
    let request = p::IgvmAttestRequest::read_from_bytes(&host.receive().await).unwrap();
    assert_eq!(
        request.message_header.message_id(),
        p::HostRequests::IGVM_ATTEST
    );
    host.send(
        p::IgvmAttestResponse {
            message_header: p::HeaderGeneric::new(p::HostRequests::IGVM_ATTEST),
            length: 4097,
        }
        .as_bytes(),
    )
    .await;
    let error = anyhow::Error::new(task.await.unwrap_err());
    assert!(format!("{error:#}").contains("reported size 4097 was larger than maximum size 4096"));
}

// Test: Request attestation without an allocator or with an exhausted DMA pool.
// Expected: The worker reports the distinct setup/allocation failures instead
//       of silently hanging without a transport error.
#[async_test]
async fn attestation_allocator_failures_are_reported_by_the_worker(driver: DefaultDriver) {
    for configured in [false, true] {
        let (mut client, _host, task) = setup(&driver).await;
        let memory = DeviceTestMemory::new(2, true, "get-attestation-no-memory");
        if configured {
            client.set_gpa_allocator(memory.dma_client());
        }
        let mut call = pin!(client.igvm_attest(Vec::new(), Vec::new(), 8192));
        assert!(call.as_mut().now_or_never().is_none());
        let error = anyhow::Error::new(task.await.unwrap_err());
        assert!(format!("{error:#}").contains(if configured {
            "failed to allocate memory for attestation request"
        } else {
            "gpa allocator is unavailable"
        }));
    }
}

// Test: Receive an encryption seed whose declared length exceeds its fixed buffer.
// Expected: The public seed API returns a malformed-length error rather than
//       exposing the invalid seed as usable protection material.
#[async_test]
async fn protection_seed_rejects_an_oversized_declared_length(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let mut response = p::GuestStateProtectionByIdResponse::new_zeroed();
    response.message_header = p::HeaderGeneric::new(p::HostRequests::GUEST_STATE_PROTECTION_BY_ID);
    response.seed.length = response.seed.buffer.len() as u32 + 1;
    let error = host
        .exchange(
            client.guest_state_protection_data_by_id(),
            p::GuestStateProtectionByIdRequest::new().as_bytes(),
            response.as_bytes(),
        )
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("reported len > actual len"));
}
