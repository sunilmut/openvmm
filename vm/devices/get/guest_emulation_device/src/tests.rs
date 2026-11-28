// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{GedChannel, GuestConfig, GuestEmulationDevice, GuestFirmwareConfig};
use disk_backend::Disk;
use futures::StreamExt;
use get_protocol as wire;
use get_resources::ged::{FirmwareEvent, GuestEmulationRequest, GuestServicingFlags, IpmiSelEvent};
use guestmem::GuestMemory;
use mesh::rpc::RpcSend;
use pal_async::task::{Spawn, Task};
use pal_async::{DefaultDriver, async_test};
use power_resources::PowerRequest;
use task_control::StopTask;
use test_with_tracing::test;
use vmbus_async::async_dgram::{AsyncRecvExt, AsyncSendExt};
use vmbus_async::pipe::{MessagePipe, connected_message_pipes};
use vmbus_ring::FlatRingMem;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

fn config() -> GuestConfig {
    GuestConfig {
        firmware: GuestFirmwareConfig::Uefi {
            enable_vpci_boot: true,
            firmware_debug: true,
            enable_memory_protections: true,
            disable_frontpage: true,
            console_mode: wire::UefiConsoleMode::COM2,
            default_boot_always_attempt: true,
        },
        com1: true,
        com2: false,
        serial_tx_only: false,
        vmbus_redirection: true,
        enable_tpm: true,
        vtl2_settings: Some(vec![1, 2, 3]),
        secure_boot_enabled: true,
        secure_boot_template: wire::SecureBootTemplateType::MICROSOFT_WINDOWS,
        enable_battery: true,
        enable_ipmi: true,
        enable_hibernation: true,
        no_persistent_secrets: false,
        guest_state_lifetime: Default::default(),
        guest_state_encryption_policy: Default::default(),
        management_vtl_features: Default::default(),
        hardware_sealing_policy: Default::default(),
        efi_diagnostics_log_level: Default::default(),
        force_dma_bounce_enabled: true,
        smbios: Default::default(),
    }
}

struct Harness {
    pipe: MessagePipe<FlatRingMem>,
    requests: mesh::Sender<GuestEmulationRequest>,
    power: mesh::Receiver<PowerRequest>,
    events: mesh::Receiver<FirmwareEvent>,
    ipmi: mesh::Receiver<IpmiSelEvent>,
    _task: Task<Result<(), super::Error>>,
}

impl Harness {
    fn new(driver: &DefaultDriver, config: GuestConfig, disk: Option<Disk>) -> Self {
        Self::with_framebuffer(driver, config, disk, None)
    }

    fn with_framebuffer(
        driver: &DefaultDriver,
        config: GuestConfig,
        disk: Option<Disk>,
        framebuffer: Option<Box<dyn video_core::FramebufferControl>>,
    ) -> Self {
        let (host, pipe) = connected_message_pipes(65536);
        let (requests, recv) = mesh::channel();
        let (power_send, power) = mesh::channel();
        let (events_send, events) = mesh::channel();
        let (ipmi_send, ipmi) = mesh::channel();
        let mut device = GuestEmulationDevice::new(
            config,
            (move |request| power_send.send(request)).into(),
            Some(events_send),
            Some(ipmi_send),
            recv,
            framebuffer,
            disk,
            None,
            false,
        );
        let task = driver.spawn("GED behavioral test", async move {
            let mut channel = GedChannel::new(host, GuestMemory::allocate(65536));
            StopTask::run_unstoppable(async |stop| channel.process(stop, &mut device).await).await
        });
        Self {
            pipe,
            requests,
            power,
            events,
            ipmi,
            _task: task,
        }
    }

    async fn receive(&mut self) -> Vec<u8> {
        let mut bytes = vec![0; wire::MAX_MESSAGE_SIZE];
        let len = self.pipe.recv(&mut bytes).await.unwrap();
        bytes.truncate(len);
        bytes
    }

    async fn response<T: FromBytes>(&mut self) -> T {
        T::read_from_bytes(&self.receive().await).expect("response shape")
    }

    async fn connect(&mut self) {
        self.pipe
            .send(wire::VersionRequest::new(wire::ProtocolVersion::RS5).as_bytes())
            .await
            .unwrap();
        let response: wire::VersionResponse = self.response().await;
        assert_eq!(response.version_accepted.0, 1);
        let battery: wire::BatteryStatusNotification = self.response().await;
        assert!(battery.flags.ac_online());
        assert!(battery.flags.battery_present());
        assert!(battery.flags.charging());
        assert_eq!(battery.remaining_capacity, 950);
    }

    async fn request<T: FromBytes>(&mut self, request: &[u8]) -> T {
        self.pipe.send(request).await.unwrap();
        self.response().await
    }

    async fn barrier(&mut self) {
        let _: wire::TimeResponse = self.request(wire::TimeRequest::new().as_bytes()).await;
    }
}

// Test: Negotiate GED and exercise clock, firmware, RAM-range and framebuffer requests.
// Expected: Responses use their protocol-defined IDs and report unsupported resources
//       without preventing subsequent requests.
#[async_test]
async fn basic_requests_use_real_pipe_responses(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    let before = std::time::SystemTime::now();
    let time: wire::TimeResponse = h.request(wire::TimeRequest::new().as_bytes()).await;
    let windows_epoch = 116444736000000000_i64;
    let lower = before
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        / 100;
    let upper = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        / 100;
    assert!((lower..=upper).contains(&((time.utc - windows_epoch) as u128)));
    let bios = wire::BiosBootFinalizeRequest {
        message_header: wire::HeaderGeneric::new(wire::HostRequests::BIOS_BOOT_FINALIZE),
        value: 1,
        _pad: 0,
    };
    let response: wire::BiosBootFinalizeResponse = h.request(bios.as_bytes()).await;
    assert_eq!(
        response.message_header.message_id(),
        wire::HostRequests::BIOS_BOOT_FINALIZE
    );
    let response: wire::CreateRamGpaRangeResponse = h
        .request(
            wire::CreateRamGpaRangeRequest::new(1, 0x1000, 2, 0, Default::default()).as_bytes(),
        )
        .await;
    assert_eq!(response.status, wire::CreateRamGpaRangeStatus::FAILED);
    let response: wire::ResetRamGpaRangeResponse = h
        .request(wire::ResetRamGpaRangeRequest::new(1).as_bytes())
        .await;
    assert_eq!(
        response.message_header.message_id(),
        wire::HostRequests::RESET_RAM_GPA_RANGE
    );
    let response: wire::LoadFirmwareResponse = h
        .request(wire::LoadFirmwareRequest::new(42).as_bytes())
        .await;
    assert_eq!(response.status, wire::LoadFirmwareStatus::SUCCESS);
    let entry = response.entry_point_image_offset;
    assert_eq!(entry, 0);
    let response: wire::MapFramebufferResponse = h
        .request(wire::MapFramebufferRequest::new(0x1000).as_bytes())
        .await;
    assert_eq!({ response.status }, wire::MapFramebufferStatus::FAILURE);
    let response: wire::UnmapFramebufferResponse = h
        .request(wire::UnmapFramebufferRequest::new().as_bytes())
        .await;
    assert_eq!({ response.status }, wire::UnmapFramebufferStatus::FAILURE);
}

// Test: Request platform settings for UEFI and PCAT guests with distinct identities.
// Expected: The JSON delivered on the wire preserves firmware choices and SMBIOS
//       all system identity overrides and secure boot templates, with a complete
//       revision-one response header.
#[async_test]
async fn platform_settings_forward_configuration(driver: DefaultDriver) {
    for (template, expected_template) in [
        (wire::SecureBootTemplateType::SECURE_BOOT_DISABLED, "None"),
        (
            wire::SecureBootTemplateType::MICROSOFT_WINDOWS,
            "MicrosoftWindows",
        ),
        (
            wire::SecureBootTemplateType::MICROSOFT_UEFI_CERTIFICATE_AUTHORITY,
            "MicrosoftUEFICertificateAuthority",
        ),
    ] {
        let mut cfg = config();
        cfg.secure_boot_template = template;
        cfg.smbios.system.manufacturer = Some("maker".into());
        cfg.smbios.system.serial_number = Some("serial".into());
        cfg.smbios.system.product_name = Some("product".into());
        cfg.smbios.system.version = Some("version".into());
        cfg.smbios.system.sku_number = Some("sku".into());
        cfg.smbios.system.family = Some("family".into());
        cfg.smbios.system.uuid = guid::guid!("00112233-4455-6677-8899-aabbccddeeff");
        let mut h = Harness::new(&driver, cfg, None);
        h.connect().await;
        h.pipe
            .send(wire::DevicePlatformSettingsRequestV2::new().as_bytes())
            .await
            .unwrap();
        let bytes = h.receive().await;
        let (header, json) =
            wire::DevicePlatformSettingsResponseV2Rev1::read_from_prefix(&bytes).unwrap();
        assert_eq!(
            header.message_header.message_id(),
            wire::HostRequests::DEVICE_PLATFORM_SETTINGS_V2_REV1
        );
        assert_eq!(header.size as usize, json.len());
        assert_eq!(header.payload_state, wire::LargePayloadState::END);
        let settings: wire::dps_json::DevicePlatformSettingsV2Json =
            serde_json::from_slice(json).unwrap();
        assert!(settings.v1.com1.enable_port);
        assert!(!settings.v1.com2.enable_port);
        assert_eq!(settings.v1.serial_number, "serial");
        assert_eq!(settings.v2.r#static.smbios.system_manufacturer, "maker");
        assert_eq!(settings.v2.r#static.smbios.system_product_name, "product");
        assert_eq!(settings.v2.r#static.smbios.system_version, "version");
        assert_eq!(settings.v2.r#static.smbios.system_sku_number, "sku");
        assert_eq!(settings.v2.r#static.smbios.system_family, "family");
        assert_eq!(
            settings.v1.bios_guid,
            guid::guid!("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(
            serde_json::to_value(settings.v1.secure_boot_template_id).unwrap(),
            expected_template
        );
        assert!(settings.v2.r#static.vpci_boot_enabled);
        assert!(settings.v2.r#static.force_dma_bounce_enabled);
        assert_eq!(settings.v2.r#static.vtl2_settings, Some(vec![1, 2, 3]));
    }
    let mut cfg = config();
    let order = [
        wire::dps_json::PcatBootDevice::Network,
        wire::dps_json::PcatBootDevice::Optical,
        wire::dps_json::PcatBootDevice::HardDrive,
        wire::dps_json::PcatBootDevice::Floppy,
    ];
    cfg.firmware = GuestFirmwareConfig::Pcat { boot_order: order };
    let mut h = Harness::new(&driver, cfg, None);
    h.connect().await;
    h.pipe
        .send(wire::DevicePlatformSettingsRequestV2::new().as_bytes())
        .await
        .unwrap();
    let bytes = h.receive().await;
    let (_, json) = wire::DevicePlatformSettingsResponseV2Rev1::read_from_prefix(&bytes).unwrap();
    let settings: wire::dps_json::DevicePlatformSettingsV2Json =
        serde_json::from_slice(json).unwrap();
    assert!(settings.v2.r#static.firmware_mode_is_pcat);
    assert_eq!(
        serde_json::to_value(settings.v2.r#static.pcat_boot_device_order).unwrap(),
        serde_json::to_value(Some(order)).unwrap()
    );
    assert!(!settings.v2.r#static.vpci_boot_enabled);
}

// Test: Read, write and flush VMGS, including absent disks and invalid disk offsets.
// Expected: Successful data roundtrips exactly; unavailable or out-of-range I/O
//       returns DEVICE_ERROR without terminating the channel or changing adjacent
//       sectors; a subsequent valid read retains the previously written data.
#[async_test]
async fn vmgs_roundtrip_and_device_errors(driver: DefaultDriver) {
    for present in [false, true] {
        let disk = present.then(|| disklayer_ram::ram_disk(8192, false).unwrap());
        let mut h = Harness::new(&driver, config(), disk);
        h.connect().await;
        let info: wire::VmgsGetDeviceInfoResponse = h
            .request(wire::VmgsGetDeviceInfoRequest::new().as_bytes())
            .await;
        assert_eq!(
            info.message_header.message_id(),
            wire::HostRequests::VMGS_GET_DEVICE_INFO
        );
        assert_eq!(
            info.status,
            if present {
                wire::VmgsIoStatus::SUCCESS
            } else {
                wire::VmgsIoStatus::DEVICE_ERROR
            }
        );
        let mut write = wire::VmgsWriteRequest::new(wire::VmgsWriteFlags::NONE, 1, 1)
            .as_bytes()
            .to_vec();
        write.extend_from_slice(&[0x5a; 512]);
        let response: wire::VmgsWriteResponse = h.request(&write).await;
        assert_eq!(response.status, info.status);
        h.pipe
            .send(wire::VmgsReadRequest::new(wire::VmgsReadFlags::NONE, 1, 1).as_bytes())
            .await
            .unwrap();
        let bytes = h.receive().await;
        let (response, data) = wire::VmgsReadResponse::read_from_prefix(&bytes).unwrap();
        assert_eq!(response.status, info.status);
        assert_eq!(data, if present { &[0x5a; 512][..] } else { &[] });
        let response: wire::VmgsFlushResponse =
            h.request(wire::VmgsFlushRequest::new().as_bytes()).await;
        assert_eq!(response.status, info.status);
        if present {
            let response: wire::VmgsReadResponse = h
                .request(wire::VmgsReadRequest::new(wire::VmgsReadFlags::NONE, 100, 1).as_bytes())
                .await;
            assert_eq!(response.status, wire::VmgsIoStatus::DEVICE_ERROR);
            write[..size_of::<wire::VmgsWriteRequest>()].copy_from_slice(
                wire::VmgsWriteRequest::new(wire::VmgsWriteFlags::NONE, 100, 1).as_bytes(),
            );
            let response: wire::VmgsWriteResponse = h.request(&write).await;
            assert_eq!(response.status, wire::VmgsIoStatus::DEVICE_ERROR);
            h.pipe
                .send(wire::VmgsReadRequest::new(wire::VmgsReadFlags::NONE, 0, 3).as_bytes())
                .await
                .unwrap();
            let bytes = h.receive().await;
            let (response, data) = wire::VmgsReadResponse::read_from_prefix(&bytes).unwrap();
            assert_eq!(
                response.message_header.message_id(),
                wire::HostRequests::VMGS_READ
            );
            assert_eq!(response.status, wire::VmgsIoStatus::SUCCESS);
            let mut expected = vec![0; 1536];
            expected[512..1024].fill(0x5a);
            assert_eq!(data, expected);
        }
    }
}

// Test: Forward power, firmware-log, and IPMI notifications to their registered clients.
// Expected: Each supported event arrives once with its public payload; informational
//       and unknown firmware events produce no spurious firmware notifications.
#[async_test]
async fn notifications_reach_external_observers(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    for (hibernate, expected) in [
        (false, PowerRequest::PowerOff),
        (true, PowerRequest::Hibernate),
    ] {
        h.pipe
            .send(wire::PowerOffNotification::new(hibernate).as_bytes())
            .await
            .unwrap();
        assert_eq!(h.power.next().await.unwrap(), expected);
    }
    h.pipe
        .send(wire::ResetNotification::new().as_bytes())
        .await
        .unwrap();
    assert_eq!(h.power.next().await.unwrap(), PowerRequest::Reset);
    for (event, expected) in [
        (wire::EventLogId::BOOT_ATTEMPT, FirmwareEvent::BootAttempt),
        (wire::EventLogId::BOOT_SUCCESS, FirmwareEvent::BootSuccess),
        (
            wire::EventLogId::BOOT_SUCCESS_SECURE_BOOT_FAILED,
            FirmwareEvent::BootSuccess,
        ),
        (wire::EventLogId::BOOT_FAILURE, FirmwareEvent::BootFailed),
        (
            wire::EventLogId::BOOT_FAILURE_SECURE_BOOT_FAILED,
            FirmwareEvent::BootFailed,
        ),
        (
            wire::EventLogId::NO_BOOT_DEVICE,
            FirmwareEvent::NoBootDevice,
        ),
    ] {
        h.pipe
            .send(wire::EventLogNotification::new(event).as_bytes())
            .await
            .unwrap();
        assert_eq!(h.events.next().await.unwrap(), expected);
    }
    for event in [
        wire::EventLogId::ATTESTATION_FAILED,
        wire::EventLogId::VMGS_FILE_CLEAR,
        wire::EventLogId::VMGS_INIT_FAILED,
        wire::EventLogId::VMGS_INVALID_FORMAT,
        wire::EventLogId::VMGS_CORRUPT_FORMAT,
        wire::EventLogId::KEY_NOT_RELEASED,
        wire::EventLogId::DEK_DECRYPTION_FAILED,
        wire::EventLogId::WATCHDOG_TIMEOUT_RESET,
        wire::EventLogId(0xffff),
    ] {
        h.pipe
            .send(wire::EventLogNotification::new(event).as_bytes())
            .await
            .unwrap();
    }
    h.barrier().await;
    assert!(futures::poll!(h.events.next()).is_pending());
    let notification = wire::IpmiSelNotification::new(19, [0x5a; wire::IPMI_SEL_RECORD_SIZE]);
    h.pipe.send(notification.as_bytes()).await.unwrap();
    let event = h.ipmi.next().await.unwrap();
    assert_eq!(event.record_id, 19);
    assert_eq!(event.record.as_bytes(), &[0x5a; wire::IPMI_SEL_RECORD_SIZE]);
    let fault =
        wire::TripleFaultNotification::new(3, wire::TripleFaultType::UNRECOVERABLE_EXCEPTION, 0);
    h.pipe.send(fault.as_bytes()).await.unwrap();
    assert_eq!(
        h.power.next().await.unwrap(),
        PowerRequest::TripleFault { vp: 3 }
    );
}

// Test: Issue settings modifications while an earlier operation is still pending.
// Expected: The guest receives the exact payload, duplicate and oversized requests
//       fail, and guest success or failure reaches the initiating RPC.
#[async_test]
async fn settings_modifications_complete_and_reject_overlap(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    h.requests
        .call(GuestEmulationRequest::WaitForConnect, ())
        .await
        .unwrap();
    let first = h.requests.call(
        GuestEmulationRequest::ModifyVtl2Settings,
        b"settings".to_vec(),
    );
    let bytes = h.receive().await;
    let (header, payload) =
        wire::ModifyVtl2SettingsRev1Notification::read_from_prefix(&bytes).unwrap();
    assert_eq!(
        header.message_header.message_id(),
        wire::GuestNotifications::MODIFY_VTL2_SETTINGS_REV1
    );
    assert_eq!(header.size, 8);
    assert_eq!(header.payload_state, wire::LargePayloadState::END);
    assert_eq!(payload, b"settings");
    let duplicate = h
        .requests
        .call(GuestEmulationRequest::ModifyVtl2Settings, vec![])
        .await
        .unwrap();
    assert!(matches!(
        duplicate,
        Err(get_resources::ged::ModifyVtl2SettingsError::OperationInProgress)
    ));
    h.pipe
        .send(
            wire::ModifyVtl2SettingsCompleteNotification::new(
                wire::ModifyVtl2SettingsStatus::SUCCESS,
                0,
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    first.await.unwrap().unwrap();
    let large = h
        .requests
        .call(
            GuestEmulationRequest::ModifyVtl2Settings,
            vec![0; wire::MAX_PAYLOAD_SIZE + 1],
        )
        .await
        .unwrap();
    assert!(matches!(
        large,
        Err(get_resources::ged::ModifyVtl2SettingsError::LargeSettingsNotSupported)
    ));
    let failed = h.requests.call(
        GuestEmulationRequest::ModifyVtl2Settings,
        b"second".to_vec(),
    );
    let bytes = h.receive().await;
    let (header, payload) =
        wire::ModifyVtl2SettingsRev1Notification::read_from_prefix(&bytes).unwrap();
    assert_eq!(header.size, 6);
    assert_eq!(header.payload_state, wire::LargePayloadState::END);
    assert_eq!(payload, b"second");
    let mut response = wire::ModifyVtl2SettingsCompleteNotification::new(
        wire::ModifyVtl2SettingsStatus::FAILURE,
        6,
    )
    .as_bytes()
    .to_vec();
    response.extend_from_slice(b"denied");
    h.pipe.send(&response).await.unwrap();
    let result = failed.await.unwrap();
    assert!(
        matches!(result, Err(get_resources::ged::ModifyVtl2SettingsError::Guest(message)) if message == "denied")
    );
}

// Test: Wait for VTL0 start both before and after the guest's completion report.
// Expected: All callers receive the same result and a failed start powers off the VM.
#[async_test]
async fn vtl0_start_waiters_observe_success_and_failure(driver: DefaultDriver) {
    for success in [true, false] {
        let mut h = Harness::new(&driver, config(), None);
        h.connect().await;
        let waiting = h.requests.call(GuestEmulationRequest::WaitForVtl0Start, ());
        h.barrier().await;
        let detail = if success {
            &b""[..]
        } else {
            &b"boot failed"[..]
        };
        let status = if success {
            wire::StartVtl0Status::SUCCESS
        } else {
            wire::StartVtl0Status::FAILURE
        };
        let mut bytes = wire::StartVtl0CompleteNotification::new(status, detail.len() as u32)
            .as_bytes()
            .to_vec();
        bytes.extend_from_slice(detail);
        h.pipe.send(&bytes).await.unwrap();
        let result = waiting.await.unwrap();
        assert_eq!(result.is_ok(), success);
        if let Err(error) = &result {
            assert_eq!(error.0, "boot failed");
        }
        let later = h
            .requests
            .call(GuestEmulationRequest::WaitForVtl0Start, ())
            .await
            .unwrap();
        assert_eq!(later.is_ok(), success);
        if !success {
            assert_eq!(h.power.next().await.unwrap(), PowerRequest::PowerOff);
        }
    }
}

// Test: Save VTL2 state in multiple chunks and restore it over the guest protocol.
// Expected: Overlapping saves fail, capability flags survive, and restore emits
//       the original bytes with MORE_DATA followed by SUCCESS and exact chunk sizes.
#[async_test]
async fn save_restore_streams_bytes_and_rejects_overlapping_saves(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    let save = h.requests.call(
        GuestEmulationRequest::SaveGuestVtl2State,
        GuestServicingFlags {
            nvme_keepalive: true,
            mana_keepalive: true,
        },
    );
    let notification: wire::SaveGuestVtl2StateNotification = h.response().await;
    let flags = notification.capabilities_flags;
    assert!(flags.enable_nvme_keepalive());
    assert!(flags.enable_mana_keepalive());
    let duplicate = h
        .requests
        .call(
            GuestEmulationRequest::SaveGuestVtl2State,
            GuestServicingFlags::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        duplicate,
        Err(get_resources::ged::SaveRestoreError::OperationInProgress)
    ));
    let bytes: Vec<u8> = (0..wire::MAX_PAYLOAD_SIZE + 23).map(|i| i as u8).collect();
    for (status, data) in [
        (
            wire::GuestVtl2SaveRestoreStatus::MORE_DATA,
            &bytes[..wire::MAX_PAYLOAD_SIZE],
        ),
        (
            wire::GuestVtl2SaveRestoreStatus::SUCCESS,
            &bytes[wire::MAX_PAYLOAD_SIZE..],
        ),
    ] {
        let mut packet = wire::SaveGuestVtl2StateRequest::new(status)
            .as_bytes()
            .to_vec();
        packet.extend_from_slice(data);
        h.pipe.send(&packet).await.unwrap();
    }
    let response: wire::SaveGuestVtl2StateResponse = h.response().await;
    assert_eq!(
        response.save_status,
        wire::GuestVtl2SaveRestoreStatus::SUCCESS
    );
    save.await.unwrap().unwrap();
    h.pipe
        .send(
            wire::RestoreGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::REQUEST_DATA)
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut restored = Vec::new();
    for (expected, expected_data) in [
        (
            wire::GuestVtl2SaveRestoreStatus::MORE_DATA,
            &bytes[..wire::MAX_PAYLOAD_SIZE],
        ),
        (
            wire::GuestVtl2SaveRestoreStatus::SUCCESS,
            &bytes[wire::MAX_PAYLOAD_SIZE..],
        ),
    ] {
        let packet = h.receive().await;
        let (header, data) =
            wire::RestoreGuestVtl2StateResponse::read_from_prefix(&packet).unwrap();
        assert_eq!({ header.restore_status }, expected);
        assert_eq!(
            header.message_header.message_id(),
            wire::HostRequests::RESTORE_GUEST_VTL2_STATE
        );
        assert_eq!(header.data_length as usize, data.len());
        assert_eq!(data, expected_data);
        restored.extend_from_slice(data);
    }
    assert_eq!(restored, bytes);
    for status in [
        wire::GuestVtl2SaveRestoreStatus::SUCCESS,
        wire::GuestVtl2SaveRestoreStatus::FAILURE,
    ] {
        h.pipe
            .send(wire::RestoreGuestVtl2StateHostNotification::new(status).as_bytes())
            .await
            .unwrap();
    }
    h.barrier().await;
    let failed = h.requests.call(
        GuestEmulationRequest::SaveGuestVtl2State,
        GuestServicingFlags::default(),
    );
    let _: wire::SaveGuestVtl2StateNotification = h.response().await;
    h.pipe
        .send(
            wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::FAILURE)
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(matches!(
        failed.await.unwrap(),
        Err(get_resources::ged::SaveRestoreError::GuestError)
    ));
}

// Test: Ask the host for guest-state protection using both protocol variants.
// Expected: The stub reports no persistent registry seed and returns zeroed
//       protection material without breaking the channel.
#[async_test]
async fn guest_state_protection_stub_responses_are_well_formed(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    let response: wire::GuestStateProtectionByIdResponse = h
        .request(wire::GuestStateProtectionByIdRequest::new().as_bytes())
        .await;
    assert!(response.extended_status_flags.no_registry_file());
    assert_eq!(response.seed.length, 0);
    let mut request = wire::GuestStateProtectionRequest::new_zeroed();
    request.message_header = wire::HeaderGeneric::new(wire::HostRequests::GUEST_STATE_PROTECTION);
    let response: wire::GuestStateProtectionResponse = h.request(request.as_bytes()).await;
    assert_eq!(
        response.message_header.message_id(),
        wire::HostRequests::GUEST_STATE_PROTECTION
    );
    assert_eq!(
        &response.as_bytes()[4..],
        &[0; size_of::<wire::GuestStateProtectionResponse>() - 4]
    );
}

// Test: Run the scripted GED peer with negotiation retries and VMGS traffic.
// Expected: Scripted replies retain message boundaries, writes are returned by
//       later reads, and power notifications satisfy the scripted halt actions.
#[cfg(feature = "test_utilities")]
#[async_test]
async fn scripted_peer_supports_notifications_and_vmgs_data(driver: DefaultDriver) {
    use crate::test_utilities::{Event, TestGetResponses, create_host_channel};

    let responses = vec![
        TestGetResponses::new(Event::Response(
            wire::TimeResponse::new(1, 2, 3, false).as_bytes().to_vec(),
        ))
        .add_response(Event::Response(
            wire::BatteryStatusNotification::new(
                wire::BatteryStatusFlags::new().with_battery_present(true),
                100,
                50,
                1,
            )
            .as_bytes()
            .to_vec(),
        )),
        TestGetResponses::default(),
        TestGetResponses::default(),
        TestGetResponses::new(Event::Halt(PowerRequest::PowerOff)),
        TestGetResponses::new(Event::Halt(PowerRequest::Reset)),
        TestGetResponses::new(Event::Response(
            wire::VmgsWriteResponse::new(wire::VmgsIoStatus::SUCCESS)
                .as_bytes()
                .to_vec(),
        )),
        TestGetResponses::new(Event::Response(
            wire::VmgsReadResponse::new(wire::VmgsIoStatus::SUCCESS)
                .as_bytes()
                .to_vec(),
        )),
    ];
    let (host, mut guest) = connected_message_pipes(65536);
    let _client = create_host_channel(
        driver,
        host,
        Some(responses),
        wire::ProtocolVersion::RS5,
        None,
        None,
    );
    for (version, accepted) in [
        (wire::ProtocolVersion::INVALID, false),
        (wire::ProtocolVersion::RS5, true),
    ] {
        guest
            .send(wire::VersionRequest::new(version).as_bytes())
            .await
            .unwrap();
        let mut bytes = vec![0; wire::MAX_MESSAGE_SIZE];
        let size = guest.recv(&mut bytes).await.unwrap();
        let response = wire::VersionResponse::read_from_bytes(&bytes[..size]).unwrap();
        assert_eq!(response.version_accepted.0 != 0, accepted);
    }
    guest
        .send(wire::TimeRequest::new().as_bytes())
        .await
        .unwrap();
    let mut buffer = vec![0; wire::MAX_MESSAGE_SIZE];
    let size = guest.recv(&mut buffer).await.unwrap();
    let response = wire::TimeResponse::read_from_bytes(&buffer[..size]).unwrap();
    assert_eq!(response.utc, 2);
    let size = guest.recv(&mut buffer).await.unwrap();
    let response = wire::BatteryStatusNotification::read_from_bytes(&buffer[..size]).unwrap();
    assert_eq!(response.remaining_capacity, 50);
    guest
        .send(wire::EventLogNotification::new(wire::EventLogId::BOOT_SUCCESS).as_bytes())
        .await
        .unwrap();
    guest
        .send(wire::IpmiSelNotification::new(1, [0; wire::IPMI_SEL_RECORD_SIZE]).as_bytes())
        .await
        .unwrap();
    guest
        .send(wire::PowerOffNotification::new(false).as_bytes())
        .await
        .unwrap();
    guest
        .send(wire::ResetNotification::new().as_bytes())
        .await
        .unwrap();
    let mut write = wire::VmgsWriteRequest::new(wire::VmgsWriteFlags::NONE, 1, 1)
        .as_bytes()
        .to_vec();
    write.extend_from_slice(&[0x76; 512]);
    guest.send(&write).await.unwrap();
    let size = guest.recv(&mut buffer).await.unwrap();
    assert_eq!(
        wire::VmgsWriteResponse::read_from_bytes(&buffer[..size])
            .unwrap()
            .status,
        wire::VmgsIoStatus::SUCCESS
    );
    guest
        .send(wire::VmgsReadRequest::new(wire::VmgsReadFlags::NONE, 1, 1).as_bytes())
        .await
        .unwrap();
    let size = guest.recv(&mut buffer).await.unwrap();
    let (header, bytes) = wire::VmgsReadResponse::read_from_prefix(&buffer[..size]).unwrap();
    assert_eq!(header.status, wire::VmgsIoStatus::SUCCESS);
    assert_eq!(bytes, &[0x76; 512]);
}

// Test: Use the public automated GED helper and request a VTL2 save from its client.
// Expected: The helper negotiates and completes the client operation only after
//       the guest sends a successful state payload.
#[cfg(feature = "test_utilities")]
#[async_test]
async fn automated_helper_completes_client_save_request(driver: DefaultDriver) {
    use crate::test_utilities::create_host_channel;

    let (host, mut guest) = connected_message_pipes(65536);
    let mut client = create_host_channel(
        driver,
        host,
        None,
        wire::ProtocolVersion::RS5,
        Some(GuestMemory::allocate(65536)),
        Some(Default::default()),
    );
    guest
        .send(wire::VersionRequest::new(wire::ProtocolVersion::RS5).as_bytes())
        .await
        .unwrap();
    let mut bytes = vec![0; wire::MAX_MESSAGE_SIZE];
    let size = guest.recv(&mut bytes).await.unwrap();
    assert_eq!(
        wire::VersionResponse::read_from_bytes(&bytes[..size])
            .unwrap()
            .version_accepted
            .0,
        1
    );
    let size = guest.recv(&mut bytes).await.unwrap();
    assert!(
        wire::BatteryStatusNotification::read_from_bytes(&bytes[..size])
            .unwrap()
            .flags
            .battery_present()
    );
    let mut save = Box::pin(client.test_save_guest_vtl2_state());
    assert!(futures::poll!(&mut save).is_pending());
    let size = guest.recv(&mut bytes).await.unwrap();
    let notification =
        wire::SaveGuestVtl2StateNotification::read_from_bytes(&bytes[..size]).unwrap();
    assert_eq!(
        notification.message_header.message_id(),
        wire::GuestNotifications::SAVE_GUEST_VTL2_STATE
    );
    let mut request =
        wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::SUCCESS)
            .as_bytes()
            .to_vec();
    request.extend_from_slice(b"state");
    guest.send(&request).await.unwrap();
    let size = guest.recv(&mut bytes).await.unwrap();
    assert_eq!(
        wire::SaveGuestVtl2StateResponse::read_from_bytes(&bytes[..size])
            .unwrap()
            .save_status,
        wire::GuestVtl2SaveRestoreStatus::SUCCESS
    );
    save.await;
}

// Test: Send invalid headers, unsupported requests, and malformed notification lengths.
// Expected: The protocol worker fails without acknowledging invalid input.
#[async_test]
async fn malformed_inputs_fail_without_acknowledgement(driver: DefaultDriver) {
    let mut bad_version = wire::TimeRequest::new().as_bytes().to_vec();
    bad_version[0] = 0xff;
    let mut invalid_power = wire::PowerOffNotification::new(false);
    invalid_power.hibernate.0 = 2;
    let mut start = wire::StartVtl0CompleteNotification::new(wire::StartVtl0Status::SUCCESS, 8)
        .as_bytes()
        .to_vec();
    start.push(1);
    for bytes in [
        vec![1],
        bad_version,
        wire::VersionResponse::new(true).as_bytes().to_vec(),
        wire::HeaderHostRequest::new(wire::HostRequests(0xeeee))
            .as_bytes()
            .to_vec(),
        wire::HeaderHostNotification::new(wire::HostNotifications(0xffff))
            .as_bytes()
            .to_vec(),
        invalid_power.as_bytes().to_vec(),
        start,
        wire::TripleFaultNotification::new(0, wire::TripleFaultType::UNRECOVERABLE_EXCEPTION, 1)
            .as_bytes()
            .to_vec(),
        wire::RestoreGuestVtl2StateHostNotification::new(
            wire::GuestVtl2SaveRestoreStatus::MORE_DATA,
        )
        .as_bytes()
        .to_vec(),
        wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::SUCCESS)
            .as_bytes()
            .to_vec(),
        wire::ModifyVtl2SettingsCompleteNotification::new(
            wire::ModifyVtl2SettingsStatus::SUCCESS,
            0,
        )
        .as_bytes()
        .to_vec(),
    ] {
        let mut h = Harness::new(&driver, config(), None);
        h.connect().await;
        h.pipe.send(&bytes).await.unwrap();
        assert!(
            h._task.await.is_err(),
            "malformed packet accepted: {bytes:?}"
        );
        assert!(futures::poll!(h.pipe.recv(&mut [0; 16])).is_pending());
    }
}

struct FramebufferObserver(mesh::Sender<Option<u64>>);

#[async_trait::async_trait]
impl video_core::FramebufferControl for FramebufferObserver {
    async fn map(&mut self, gpa: u64) {
        self.0.send(Some(gpa));
    }

    async fn unmap(&mut self) {
        self.0.send(None);
    }

    async fn set_format(&mut self, _: video_core::FramebufferFormat) {
        panic!("GED must not change framebuffer format");
    }
}

// Test: Map and unmap a framebuffer through the guest's pipe interface.
// Expected: The backend receives the requested GPA and an unmap operation, and
//       both wire responses report success.
#[async_test]
async fn framebuffer_requests_reach_the_registered_backend(driver: DefaultDriver) {
    let (send, mut recv) = mesh::channel();
    let mut h = Harness::with_framebuffer(
        &driver,
        config(),
        None,
        Some(Box::new(FramebufferObserver(send))),
    );
    h.connect().await;
    let response: wire::MapFramebufferResponse = h
        .request(wire::MapFramebufferRequest::new(0x12345000).as_bytes())
        .await;
    assert_eq!({ response.status }, wire::MapFramebufferStatus::SUCCESS);
    assert_eq!(recv.next().await, Some(Some(0x12345000)));
    let response: wire::UnmapFramebufferResponse = h
        .request(wire::UnmapFramebufferRequest::new().as_bytes())
        .await;
    assert_eq!({ response.status }, wire::UnmapFramebufferStatus::SUCCESS);
    assert_eq!(recv.next().await, Some(None));
}

// Test: Submit attestation requests whose declared lengths exceed their fields,
//       followed by a structurally valid envelope with an invalid report.
// Expected: The protocol worker rejects each request without sending a response.
#[async_test]
async fn attestation_rejects_invalid_lengths_and_reports(driver: DefaultDriver) {
    for field in 0..4 {
        let mut request = wire::IgvmAttestRequest::new_zeroed();
        request.message_header = wire::HeaderGeneric::new(wire::HostRequests::IGVM_ATTEST);
        match field {
            0 => request.agent_data_length = request.agent_data.len() as u32 + 1,
            1 => request.report_length = request.report.len() as u32 + 1,
            2 => request.number_gpa = request.shared_gpa.len() as u32 + 1,
            3 => request.number_gpa = 1,
            _ => unreachable!(),
        }
        let mut h = Harness::new(&driver, config(), None);
        h.connect().await;
        h.pipe.send(request.as_bytes()).await.unwrap();
        assert!(h._task.await.is_err());
        assert!(futures::poll!(h.pipe.recv(&mut [0; 16])).is_pending());
    }
}

// Test: Fail a chunked save after a partial payload, then retry and restore.
// Expected: The retry succeeds and restores only its bytes, not the failed prefix.
#[async_test]
async fn failed_chunked_save_does_not_contaminate_the_next_save(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    let failed = h.requests.call(
        GuestEmulationRequest::SaveGuestVtl2State,
        GuestServicingFlags::default(),
    );
    let _: wire::SaveGuestVtl2StateNotification = h.response().await;
    let mut partial =
        wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::MORE_DATA)
            .as_bytes()
            .to_vec();
    partial.extend_from_slice(b"discarded-prefix");
    h.pipe.send(&partial).await.unwrap();
    h.pipe
        .send(
            wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::FAILURE)
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(matches!(
        failed.await.unwrap(),
        Err(get_resources::ged::SaveRestoreError::GuestError)
    ));

    let retry = h.requests.call(
        GuestEmulationRequest::SaveGuestVtl2State,
        GuestServicingFlags::default(),
    );
    let _: wire::SaveGuestVtl2StateNotification = h.response().await;
    let mut fresh = wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::SUCCESS)
        .as_bytes()
        .to_vec();
    fresh.extend_from_slice(b"fresh-state");
    h.pipe.send(&fresh).await.unwrap();
    let response: wire::SaveGuestVtl2StateResponse = h.response().await;
    assert_eq!(
        response.save_status,
        wire::GuestVtl2SaveRestoreStatus::SUCCESS
    );
    retry.await.unwrap().unwrap();
    h.pipe
        .send(
            wire::RestoreGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::REQUEST_DATA)
                .as_bytes(),
        )
        .await
        .unwrap();
    let packet = h.receive().await;
    let (header, bytes) = wire::RestoreGuestVtl2StateResponse::read_from_prefix(&packet).unwrap();
    assert_eq!(
        { header.restore_status },
        wire::GuestVtl2SaveRestoreStatus::SUCCESS
    );
    assert_eq!(header.data_length as usize, b"fresh-state".len());
    assert_eq!(bytes, b"fresh-state");
    h.barrier().await;
}

// Test: Run settings modification and state save together, completing them in
//       both orders and reusing the channel with opposite keepalive capabilities.
// Expected: Each completion resolves only its own RPC; full notifications and
//       restored payloads retain the requested flags and bytes without leftovers.
#[async_test]
async fn settings_and_save_completions_remain_independent(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    h.connect().await;
    for nvme in [true, false] {
        let settings = if nvme {
            &b"first-settings"[..]
        } else {
            &b"second-settings"[..]
        };
        let state = if nvme {
            &b"first-state"[..]
        } else {
            &b"second-state"[..]
        };
        let mut modify = Box::pin(
            h.requests
                .call(GuestEmulationRequest::ModifyVtl2Settings, settings.to_vec()),
        );
        let bytes = h.receive().await;
        let (header, payload) =
            wire::ModifyVtl2SettingsRev1Notification::read_from_prefix(&bytes).unwrap();
        assert_eq!(
            header.message_header.message_id(),
            wire::GuestNotifications::MODIFY_VTL2_SETTINGS_REV1
        );
        assert_eq!(header.payload_state, wire::LargePayloadState::END);
        assert_eq!(header.size as usize, settings.len());
        assert_eq!(payload, settings);
        let mut save = Box::pin(h.requests.call(
            GuestEmulationRequest::SaveGuestVtl2State,
            GuestServicingFlags {
                nvme_keepalive: nvme,
                mana_keepalive: !nvme,
            },
        ));
        let notification: wire::SaveGuestVtl2StateNotification = h.response().await;
        assert_eq!(
            notification.message_header.message_id(),
            wire::GuestNotifications::SAVE_GUEST_VTL2_STATE
        );
        assert_eq!({ notification.correlation_id }, guid::Guid::ZERO);
        assert_eq!({ notification.timeout_hint_secs }, 60);
        let expected_flags = if nvme {
            [1, 0, 0, 0, 0, 0, 0, 0]
        } else {
            [2, 0, 0, 0, 0, 0, 0, 0]
        };
        let flags = notification.capabilities_flags;
        assert_eq!(flags.as_bytes(), expected_flags);
        assert!(futures::poll!(&mut modify).is_pending());
        assert!(futures::poll!(&mut save).is_pending());
        if nvme {
            h.pipe
                .send(
                    wire::ModifyVtl2SettingsCompleteNotification::new(
                        wire::ModifyVtl2SettingsStatus::SUCCESS,
                        0,
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            (&mut modify).await.unwrap().unwrap();
            assert!(futures::poll!(&mut save).is_pending());
        }
        let mut packet =
            wire::SaveGuestVtl2StateRequest::new(wire::GuestVtl2SaveRestoreStatus::SUCCESS)
                .as_bytes()
                .to_vec();
        packet.extend_from_slice(state);
        h.pipe.send(&packet).await.unwrap();
        let response: wire::SaveGuestVtl2StateResponse = h.response().await;
        assert_eq!(
            response.message_header.message_id(),
            wire::HostRequests::SAVE_GUEST_VTL2_STATE
        );
        assert_eq!(
            response.save_status,
            wire::GuestVtl2SaveRestoreStatus::SUCCESS
        );
        save.await.unwrap().unwrap();
        if !nvme {
            assert!(futures::poll!(&mut modify).is_pending());
            h.pipe
                .send(
                    wire::ModifyVtl2SettingsCompleteNotification::new(
                        wire::ModifyVtl2SettingsStatus::SUCCESS,
                        0,
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            modify.await.unwrap().unwrap();
        }
        h.pipe
            .send(
                wire::RestoreGuestVtl2StateRequest::new(
                    wire::GuestVtl2SaveRestoreStatus::REQUEST_DATA,
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let packet = h.receive().await;
        let (header, payload) =
            wire::RestoreGuestVtl2StateResponse::read_from_prefix(&packet).unwrap();
        assert_eq!(
            header.message_header.message_id(),
            wire::HostRequests::RESTORE_GUEST_VTL2_STATE
        );
        assert_eq!(
            { header.restore_status },
            wire::GuestVtl2SaveRestoreStatus::SUCCESS
        );
        assert_eq!(header.data_length as usize, state.len());
        assert_eq!(payload, state);
        h.barrier().await;
        assert!(futures::poll!(h.pipe.recv(&mut [0; wire::MAX_MESSAGE_SIZE])).is_pending());
    }
}

// Test: Reject an invalid settings completion while settings and save RPCs are
//       pending on one device, leaving a separate device connected.
// Expected: The rejected channel closes both RPC replies without an acknowledgement;
//       the other device still services requests and forwards its own power event.
#[async_test]
async fn invalid_completion_closes_only_its_device_requests(driver: DefaultDriver) {
    let mut h = Harness::new(&driver, config(), None);
    let mut peer = Harness::new(&driver, config(), None);
    h.connect().await;
    peer.connect().await;
    let mut modify = Box::pin(h.requests.call(
        GuestEmulationRequest::ModifyVtl2Settings,
        b"pending-settings".to_vec(),
    ));
    let packet = h.receive().await;
    let (header, payload) =
        wire::ModifyVtl2SettingsRev1Notification::read_from_prefix(&packet).unwrap();
    assert_eq!(
        header.message_header.message_id(),
        wire::GuestNotifications::MODIFY_VTL2_SETTINGS_REV1
    );
    assert_eq!(header.size, 16);
    assert_eq!(header.payload_state, wire::LargePayloadState::END);
    assert_eq!(payload, b"pending-settings");
    let mut save = Box::pin(h.requests.call(
        GuestEmulationRequest::SaveGuestVtl2State,
        GuestServicingFlags::default(),
    ));
    let _: wire::SaveGuestVtl2StateNotification = h.response().await;
    assert!(futures::poll!(&mut modify).is_pending());
    assert!(futures::poll!(&mut save).is_pending());
    h.pipe
        .send(
            wire::ModifyVtl2SettingsCompleteNotification::new(
                wire::ModifyVtl2SettingsStatus(0xffff),
                0,
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(matches!(
        h._task.await,
        Err(super::Error::InvalidFieldValue)
    ));
    assert!(modify.await.is_err());
    assert!(save.await.is_err());
    assert!(futures::poll!(h.pipe.recv(&mut [0; wire::MAX_MESSAGE_SIZE])).is_pending());
    let response: wire::LoadFirmwareResponse = peer
        .request(wire::LoadFirmwareRequest::new(7).as_bytes())
        .await;
    assert_eq!(
        response.message_header.message_id(),
        wire::HostRequests::LOAD_FIRMWARE
    );
    assert_eq!(response.status, wire::LoadFirmwareStatus::SUCCESS);
    assert_eq!(response.entry_point_image_offset, 0);
    peer.pipe
        .send(wire::ResetNotification::new().as_bytes())
        .await
        .unwrap();
    assert_eq!(peer.power.next().await, Some(PowerRequest::Reset));
    peer.barrier().await;
    assert!(futures::poll!(peer.power.next()).is_pending());
}
