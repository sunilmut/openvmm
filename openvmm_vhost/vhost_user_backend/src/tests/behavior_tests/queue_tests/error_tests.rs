// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Reject malformed memory tables while a queue is active, fail a queue restart after valid memory replacement, and then explicitly activate again.
// Expected: Rejected tables do not stop or restart the queue; failed restart publishes no active queue, and retry receives the committed new backing with the existing setup rather than stale memory.
#[async_test]
async fn rejected_tables_and_failed_restart_preserve_recoverable_queue_state(
    driver: DefaultDriver,
) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let (front, back) = socket_pair();
    let frontend = VhostUserSocket::new(PolledSocket::new(&driver, front).unwrap());
    let backend = VhostUserSocket::new(PolledSocket::new(&driver, back).unwrap());
    let client = async {
        enable_ack(&frontend).await;
        install_memory(&frontend, 0x11223344).await;
        setup_and_enable_queue(&frontend).await;
        let enable = VhostUserVringState { index: 0, num: 1 };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::SET_VRING_ENABLE,
                enable.as_bytes(),
                true
            )
            .await,
            0u64.to_le_bytes()
        );
        for payload in [
            [((VHOST_USER_MAX_FDS + 1) as u32).to_le_bytes(), [0; 4]].concat(),
            [1u32.to_le_bytes(), [0; 4]].concat(),
            mem_table_payload(0, 16384, 0x10000000),
        ] {
            assert_eq!(
                exchange(
                    &frontend,
                    VhostUserRequestCode::SET_MEM_TABLE,
                    &payload,
                    true
                )
                .await,
                1u64.to_le_bytes()
            );
        }
        assert!(calls.lock().active);
        assert_eq!(calls.lock().starts.len(), 1);
        assert!(calls.lock().stopped.is_empty());
        calls.lock().fail_next_start = true;
        install_memory(&frontend, 0x55667788).await;
        assert!(!calls.lock().active);
        assert_eq!(calls.lock().starts.len(), 2);
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::SET_VRING_ENABLE,
                enable.as_bytes(),
                true
            )
            .await,
            0u64.to_le_bytes()
        );
        assert!(calls.lock().active);
        assert_eq!(calls.lock().starts.len(), 3);
        let query = VhostUserVringState { index: 0, num: 0 };
        let expected = VhostUserVringState {
            index: 0,
            num: 0x8023,
        };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::GET_VRING_BASE,
                query.as_bytes(),
                false
            )
            .await,
            expected.as_bytes()
        );
        drop(frontend);
    };
    let (result, ()) = futures::join!(
        VhostUserDeviceServer::new(Box::new(Device(calls.clone()))).serve_connection(backend),
        client
    );
    result.unwrap();
    let calls = calls.lock();
    assert_eq!(calls.resets, 1);
    assert_eq!(calls.stopped, [0, 0]);
    assert_eq!(
        calls
            .starts
            .iter()
            .map(|start| start.marker)
            .collect::<Vec<_>>(),
        [0x11223344, 0x55667788, 0x55667788]
    );
    assert_eq!(calls.starts[1].cursors, (0x8023, 0x8045));
    assert_eq!(calls.starts[2].cursors, (0, 0));
}

// Test: Send an invalid protocol version and invalid queue indices followed by valid feature and cursor queries.
// Expected: Invalid-version messages emit no reply or mutate negotiation, out-of-range queue setup does not start a device queue, and subsequent valid requests retain exact reply framing/data.
#[async_test]
async fn invalid_version_and_queue_indices_do_not_poison_connection(driver: DefaultDriver) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let (front, back) = socket_pair();
    let frontend = VhostUserSocket::new(PolledSocket::new(&driver, front).unwrap());
    let backend = VhostUserSocket::new(PolledSocket::new(&driver, back).unwrap());
    let client = async {
        enable_ack(&frontend).await;
        let invalid = VhostUserMsgHeader {
            request: VhostUserRequestCode::GET_FEATURES.0,
            flags: 2,
            size: 0,
        };
        frontend
            .send_message(&invalid, &[], &[] as &[OwnedFd])
            .await
            .unwrap();
        assert_eq!(
            exchange(&frontend, VhostUserRequestCode::GET_QUEUE_NUM, &[], false).await,
            2u64.to_le_bytes()
        );
        let state = VhostUserVringState { index: 2, num: 1 };
        for code in [
            VhostUserRequestCode::SET_VRING_NUM,
            VhostUserRequestCode::SET_VRING_BASE,
            VhostUserRequestCode::SET_VRING_ENABLE,
        ] {
            assert_eq!(
                exchange(&frontend, code, state.as_bytes(), true).await,
                0u64.to_le_bytes()
            );
        }
        let address = VhostUserVringAddr {
            index: 2,
            flags: 0,
            desc_user_addr: 0,
            avail_user_addr: 0,
            used_user_addr: 0,
            log_guest_addr: 0,
        };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::SET_VRING_ADDR,
                address.as_bytes(),
                true
            )
            .await,
            0u64.to_le_bytes()
        );
        let query = VhostUserVringState { index: 2, num: 0 };
        assert_eq!(
            exchange(
                &frontend,
                VhostUserRequestCode::GET_VRING_BASE,
                query.as_bytes(),
                false
            )
            .await,
            query.as_bytes()
        );
        assert!(calls.lock().starts.is_empty());
        drop(frontend);
    };
    let (result, ()) = futures::join!(
        VhostUserDeviceServer::new(Box::new(Device(calls.clone()))).serve_connection(backend),
        client
    );
    result.unwrap();
    assert_eq!(calls.lock().resets, 1);
}
