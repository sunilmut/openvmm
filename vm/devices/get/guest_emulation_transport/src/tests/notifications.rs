// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::barrier;
use super::wire::setup;
use futures::StreamExt;
use get_protocol as p;
use guid::Guid;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// Test: Buffer generation IDs before listener registration, then deliver another live.
// Expected: IDs arrive once in order, and the receiver can only be taken once.
#[async_test]
async fn generation_ids_survive_late_registration_and_remain_ordered(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    for id in [[1; 16], [2; 16]] {
        host.send(p::UpdateGenerationId::new(id).as_bytes()).await;
    }
    barrier(&client, &mut host).await;
    let mut ids = client.take_generation_id_recv().await.unwrap();
    assert!(client.take_generation_id_recv().await.is_none());
    assert_eq!(ids.next().await.unwrap(), [1; 16]);
    assert_eq!(ids.next().await.unwrap(), [2; 16]);
    host.send(p::UpdateGenerationId::new([3; 16]).as_bytes())
        .await;
    assert_eq!(ids.next().await.unwrap(), [3; 16]);
}

// Test: Deliver battery and save requests before downstream listeners are installed.
// Expected: Receivers retain flags, capacities, timeout and correlation ID,
//       and cannot be taken twice.
#[async_test]
async fn battery_and_save_notifications_retain_payloads_for_late_consumers(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let id = Guid::new_random();
    host.send(
        p::BatteryStatusNotification::new(
            p::BatteryStatusFlags::new()
                .with_ac_online(true)
                .with_battery_present(true)
                .with_charging(true),
            1000,
            750,
            42,
        )
        .as_bytes(),
    )
    .await;
    host.send(
        p::SaveGuestVtl2StateNotification {
            message_header: p::HeaderGeneric::new(p::GuestNotifications::SAVE_GUEST_VTL2_STATE),
            correlation_id: id,
            capabilities_flags: p::SaveGuestVtl2StateFlags::new().with_enable_nvme_keepalive(true),
            timeout_hint_secs: 17,
        }
        .as_bytes(),
    )
    .await;
    barrier(&client, &mut host).await;
    let mut batteries = client.take_battery_status_recv().await.unwrap();
    assert!(client.take_battery_status_recv().await.is_none());
    let battery = batteries.next().await.unwrap();
    assert!(battery.battery_present && battery.ac_online && battery.charging);
    assert!(!battery.discharging);
    assert_eq!(
        (
            battery.max_capacity,
            battery.remaining_capacity,
            battery.rate
        ),
        (1000, 750, 42)
    );
    let mut saves = client.take_save_request_recv().await.unwrap();
    assert!(client.take_save_request_recv().await.is_none());
    let save = saves.next().await.unwrap();
    assert_eq!(save.correlation_id, id);
    assert_eq!(save.timeout_hint, std::time::Duration::from_secs(17));
    assert!(save.capabilities_flags.enable_nvme_keepalive());
    host.send(
        p::BatteryStatusNotification::new(
            p::BatteryStatusFlags::new().with_discharging(true),
            500,
            300,
            11,
        )
        .as_bytes(),
    )
    .await;
    let battery = batteries.next().await.unwrap();
    assert!(battery.discharging);
    assert!(!battery.charging && !battery.ac_online && !battery.battery_present);
    assert_eq!(battery.remaining_capacity, 300);
}

// Test: Register independent VPCI listeners and remove one while the other remains live.
// Expected: Each bus receives only its events; unregistered buses are ignored,
//       and deregistration closes only the removed listener.
#[async_test]
async fn vpci_notifications_are_isolated_by_bus_and_deregistration(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let first = Guid::new_random();
    let second = Guid::new_random();
    let mut a = client.connect_to_vpci_event_source(first).await;
    let mut b = client.connect_to_vpci_event_source(second).await;
    for (id, code) in [
        (
            Guid::new_random(),
            p::VpciDeviceNotificationCode::ENUMERATED,
        ),
        (first, p::VpciDeviceNotificationCode::ENUMERATED),
        (second, p::VpciDeviceNotificationCode::PREPARE_FOR_REMOVAL),
    ] {
        host.send(
            p::VpciDeviceNotification {
                message_header: p::HeaderGeneric::new(
                    p::GuestNotifications::VPCI_DEVICE_NOTIFICATION,
                ),
                bus_instance_id: id,
                code,
            }
            .as_bytes(),
        )
        .await;
    }
    assert!(matches!(
        a.next().await.unwrap(),
        vpci::bus_control::VpciBusEvent::DeviceEnumerated
    ));
    assert!(matches!(
        b.next().await.unwrap(),
        vpci::bus_control::VpciBusEvent::PrepareForRemoval
    ));
    client.disconnect_from_vpci_event_source(first);
    assert!(a.next().await.is_none());
    host.send(
        p::VpciDeviceNotification {
            message_header: p::HeaderGeneric::new(p::GuestNotifications::VPCI_DEVICE_NOTIFICATION),
            bus_instance_id: second,
            code: p::VpciDeviceNotificationCode::ENUMERATED,
        }
        .as_bytes(),
    )
    .await;
    assert!(matches!(
        b.next().await.unwrap(),
        vpci::bus_control::VpciBusEvent::DeviceEnumerated
    ));
}

// Test: Send debug interrupts without a handler, for an invalid VTL, and for VTL0.
// Expected: Only the valid VTL0 notification invokes the installed callback.
#[async_test]
async fn debug_interrupts_are_delivered_only_to_registered_vtl0_handler(driver: DefaultDriver) {
    let (mut client, mut host, _task) = setup(&driver).await;
    let notification = |vtl| p::InjectDebugInterruptNotification {
        message_header: p::HeaderGeneric::new(p::GuestNotifications::INJECT_DEBUG_INTERRUPT),
        vtl,
        _pad: 0,
    };
    host.send(notification(0).as_bytes()).await;
    barrier(&client, &mut host).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let received = calls.clone();
    client.set_debug_interrupt_callback(Box::new(move |vtl| received.lock().push(vtl)));
    client.take_generation_id_recv().await.unwrap();
    host.send(notification(1).as_bytes()).await;
    host.send(notification(0).as_bytes()).await;
    barrier(&client, &mut host).await;
    assert_eq!(*calls.lock(), [0]);
}

// Test: Receive legacy settings and fragmented settings, then complete or reject them.
// Expected: Consumers see the complete original bytes and the host receives a
//       successful acknowledgement or a failure document for consumer errors.
#[async_test]
async fn settings_updates_reassemble_payloads_and_report_consumer_results(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let mut settings = client.take_vtl2_settings_recv().await.unwrap();
    assert!(client.take_vtl2_settings_recv().await.is_none());
    for outcome in 0..3 {
        if outcome == 0 {
            let header = p::ModifyVtl2SettingsNotification {
                message_header: p::HeaderGeneric::new(p::GuestNotifications::MODIFY_VTL2_SETTINGS),
                size: 6,
            };
            host.send(&[header.as_bytes(), b"config"].concat()).await;
        } else {
            for (bytes, state) in [
                (b"con", p::LargePayloadState::MORE),
                (b"fig", p::LargePayloadState::END),
            ] {
                let header = p::ModifyVtl2SettingsRev1Notification {
                    message_header: p::HeaderGeneric::new(
                        p::GuestNotifications::MODIFY_VTL2_SETTINGS_REV1,
                    ),
                    size: 3,
                    payload_state: state,
                };
                host.send(&[header.as_bytes(), bytes].concat()).await;
            }
        }
        let request = settings.next().await.unwrap();
        assert_eq!(request.0.input(), b"config");
        match outcome {
            0 => request.0.complete(Ok(())),
            1 => request
                .0
                .complete(Err(vec![underhill_config::Vtl2SettingsErrorInfo::new(
                    underhill_config::Vtl2SettingsErrorCode::InternalFailure,
                    "bad settings".into(),
                )])),
            _ => drop(request),
        }
        let message = host.receive().await;
        let (header, document) =
            p::ModifyVtl2SettingsCompleteNotification::read_from_prefix(&message).unwrap();
        assert_eq!({ header.result_document_size } as usize, document.len());
        if outcome == 0 {
            assert_eq!(
                { header.modify_status },
                p::ModifyVtl2SettingsStatus::SUCCESS
            );
            assert!(document.is_empty());
        } else {
            assert_eq!(
                { header.modify_status },
                p::ModifyVtl2SettingsStatus::FAILURE
            );
            let errors: serde_json::Value = serde_json::from_slice(document).unwrap();
            assert_eq!(errors.as_array().unwrap().len(), 1);
            if outcome == 1 {
                assert!(String::from_utf8_lossy(document).contains("bad settings"));
            }
        }
    }
}
