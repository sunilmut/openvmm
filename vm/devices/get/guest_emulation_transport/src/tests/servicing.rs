// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::setup;
use futures_concurrency::future::Join;
use get_protocol as p;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Save state that spans multiple packets, with accepted and rejected completion.
// Expected: Chunk payloads are complete and ordered, only the last chunk is
//       marked successful, and the host's final status reaches the caller.
#[async_test]
async fn servicing_save_chunks_and_propagates_final_host_status(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    for accepted in [true, false] {
        let data: Vec<u8> = (0..p::MAX_PAYLOAD_SIZE + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let peer = async {
            host.expect(
                &[
                    p::SaveGuestVtl2StateRequest::new(p::GuestVtl2SaveRestoreStatus::MORE_DATA)
                        .as_bytes(),
                    &data[..p::MAX_PAYLOAD_SIZE],
                ]
                .concat(),
            )
            .await;
            host.expect(
                &[
                    p::SaveGuestVtl2StateRequest::new(p::GuestVtl2SaveRestoreStatus::SUCCESS)
                        .as_bytes(),
                    &data[p::MAX_PAYLOAD_SIZE..],
                ]
                .concat(),
            )
            .await;
            host.send(
                p::SaveGuestVtl2StateResponse::new(if accepted {
                    p::GuestVtl2SaveRestoreStatus::SUCCESS
                } else {
                    p::GuestVtl2SaveRestoreStatus::FAILURE
                })
                .as_bytes(),
            )
            .await;
        };
        let (result, ()) = (client.send_servicing_state(data.clone()), peer)
            .join()
            .await;
        assert_eq!(result.is_ok(), accepted);
    }
}

// Test: Report a local save failure when the host does not send an acknowledgement.
// Expected: The failure packet is delivered and the caller completes without
//       waiting for a response that the protocol does not provide.
#[async_test]
async fn servicing_failure_is_sent_without_waiting_for_host_response(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    client.send_servicing_failure("cannot save").await.unwrap();
    host.expect(
        p::SaveGuestVtl2StateRequest::new(p::GuestVtl2SaveRestoreStatus::FAILURE).as_bytes(),
    )
    .await;
}

// Test: Restore state received as multiple packets, then receive a failed restore.
// Expected: Successful data is concatenated without losing fragment boundaries;
//       a later host failure returns an error rather than partial bytes.
#[async_test]
async fn servicing_restore_reassembles_data_and_rejects_host_failure(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let peer = async {
        host.expect(
            p::RestoreGuestVtl2StateRequest::new(p::GuestVtl2SaveRestoreStatus::REQUEST_DATA)
                .as_bytes(),
        )
        .await;
        for (bytes, status) in [
            (
                b"saved".as_slice(),
                p::GuestVtl2SaveRestoreStatus::MORE_DATA,
            ),
            (b"-state".as_slice(), p::GuestVtl2SaveRestoreStatus::SUCCESS),
        ] {
            host.send(
                &[
                    p::RestoreGuestVtl2StateResponse::new(bytes.len() as u32, status).as_bytes(),
                    bytes,
                ]
                .concat(),
            )
            .await;
        }
    };
    let (result, ()) = (client.get_saved_state_from_host(), peer).join().await;
    assert_eq!(result.unwrap(), b"saved-state");
    let result = host
        .exchange(
            client.get_saved_state_from_host(),
            p::RestoreGuestVtl2StateRequest::new(p::GuestVtl2SaveRestoreStatus::REQUEST_DATA)
                .as_bytes(),
            p::RestoreGuestVtl2StateResponse::new(0, p::GuestVtl2SaveRestoreStatus::FAILURE)
                .as_bytes(),
        )
        .await;
    assert!(result.is_err());
}

// Test: Notify the host of restore success/failure, completed startup, and power changes.
// Expected: Each operation sends its own exact wire status, and startup
//       completion succeeds without requiring a host response.
#[async_test]
async fn lifecycle_notifications_retain_status_and_power_action(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    for (success, status) in [
        (true, p::GuestVtl2SaveRestoreStatus::SUCCESS),
        (false, p::GuestVtl2SaveRestoreStatus::FAILURE),
    ] {
        client.report_restore_result_to_host(success).await;
        host.expect(p::RestoreGuestVtl2StateHostNotification::new(status).as_bytes())
            .await;
    }
    client.complete_start_vtl0(None).await;
    host.expect(p::StartVtl0CompleteNotification::new(p::StartVtl0Status::SUCCESS, 0).as_bytes())
        .await;
    client.send_hibernate();
    host.expect(p::PowerOffNotification::new(true).as_bytes())
        .await;
    client.send_power_off();
    host.expect(p::PowerOffNotification::new(false).as_bytes())
        .await;
    client.send_reset();
    host.expect(p::ResetNotification::new().as_bytes()).await;
}

// Test: Send fatal logging, a VTL crash, and a triple fault with register data.
// Expected: The flush completes only after the fatal log is sent, and crash
//       notifications preserve VP identity and complete register payloads.
#[async_test]
async fn fatal_events_flush_and_crash_notifications_preserve_payloads(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    client.event_log_fatal(p::EventLogId::BOOT_FAILURE).await;
    host.expect(p::EventLogNotification::new(p::EventLogId::BOOT_FAILURE).as_bytes())
        .await;
    client.notify_of_vtl_crash(3, 2, 0x55, [1, 2, 3, 4, 5]);
    host.expect(p::VtlCrashNotification::new(3, 2, 0x55, [1, 2, 3, 4, 5]).as_bytes())
        .await;
    let registers = vec![
        p::RegisterState {
            name: 7,
            value: [0x12; 16],
        },
        p::RegisterState {
            name: 8,
            value: [0x34; 16],
        },
    ];
    let expected = [
        p::TripleFaultNotification::new(9, p::TripleFaultType::UNRECOVERABLE_EXCEPTION, 2)
            .as_bytes(),
        registers.as_bytes(),
    ]
    .concat();
    client.triple_fault(9, p::TripleFaultType::UNRECOVERABLE_EXCEPTION, registers);
    host.expect(&expected).await;
}
