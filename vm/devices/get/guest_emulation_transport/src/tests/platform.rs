// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::setup;
use crate::api::platform_settings::*;
use crate::error::DevicePlatformSettingsError;
use futures_concurrency::future::Join;
use get_protocol as p;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use zerocopy::IntoBytes;

fn response(json: &[u8]) -> Vec<u8> {
    let header = p::DevicePlatformSettingsResponseV2 {
        message_header: p::HeaderGeneric::new(p::HostRequests::DEVICE_PLATFORM_SETTINGS_V2),
        size: json.len() as u32,
    };
    [header.as_bytes(), json].concat()
}

// Test: Decode host platform settings for every console and memory-protection mode.
// Expected: Public settings retain the host's identity, hardware flags, ACPI
//       bytes and generation ID, including all supported secure-boot templates.
#[async_test]
async fn platform_settings_retain_host_values_and_supported_modes(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    for mode in 0..4 {
        let mut settings = p::dps_json::DevicePlatformSettingsV2Json::default();
        settings.v1.console_mode = mode;
        settings.v1.secure_boot_enabled = true;
        settings.v1.serial_number = "serial-42".into();
        settings.v1.secure_boot_template_id = match mode {
            0 => p::dps_json::HclSecureBootTemplateId::None,
            1 => p::dps_json::HclSecureBootTemplateId::MicrosoftWindows,
            _ => p::dps_json::HclSecureBootTemplateId::MicrosoftUEFICertificateAuthority,
        };
        settings.v2.r#static.memory_protection_mode = mode;
        settings.v2.r#static.smbios.system_manufacturer = "manufacturer".into();
        settings.v2.dynamic.smbios.processor_manufacturer = vec![0x80, 0xff];
        settings.v2.dynamic.generation_id_low = 0x0102_0304_0506_0708;
        settings.v2.dynamic.generation_id_high = 0x1112_1314_1516_1718;
        settings.v2.dynamic.acpi_tables = vec![b"ACPI".to_vec()];
        let json = serde_json::to_vec(&settings).unwrap();
        let result = host
            .exchange(
                client.device_platform_settings(),
                p::DevicePlatformSettingsRequestV2::new().as_bytes(),
                &response(&json),
            )
            .await
            .unwrap();
        assert!(result.general.secure_boot_enabled);
        assert_eq!(result.smbios.serial_number, "serial-42");
        assert_eq!(result.smbios.system_manufacturer, "manufacturer");
        assert_eq!(result.smbios.processor_manufacturer, [0x80, 0xff]);
        assert_eq!(result.acpi_tables, [b"ACPI".to_vec()]);
        assert_eq!(
            result.general.generation_id.unwrap(),
            [8, 7, 6, 5, 4, 3, 2, 1, 24, 23, 22, 21, 20, 19, 18, 17]
        );
        assert_eq!(result.general.console_mode as u8, mode);
        assert_eq!(result.general.memory_protection_mode as u8, mode);
        assert!(matches!(
            (mode, result.general.secure_boot_template),
            (0, SecureBootTemplateType::None)
                | (1, SecureBootTemplateType::MicrosoftWindows)
                | (
                    2..=3,
                    SecureBootTemplateType::MicrosoftUefiCertificateAuthority
                )
        ));
    }
}

// Test: Decode malformed JSON and invalid platform enum values.
// Expected: Callers receive the appropriate public error and can retry a
//       different settings request without losing the connection.
#[async_test]
async fn malformed_platform_settings_return_typed_errors(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let result = host
        .exchange(
            client.device_platform_settings(),
            p::DevicePlatformSettingsRequestV2::new().as_bytes(),
            &response(b"{"),
        )
        .await;
    assert!(matches!(
        result,
        Err(DevicePlatformSettingsError::BadJson(_))
    ));
    let mut settings = p::dps_json::DevicePlatformSettingsV2Json::default();
    settings.v1.console_mode = 255;
    let result = host
        .exchange(
            client.device_platform_settings(),
            p::DevicePlatformSettingsRequestV2::new().as_bytes(),
            &response(&serde_json::to_vec(&settings).unwrap()),
        )
        .await;
    assert!(matches!(
        result,
        Err(DevicePlatformSettingsError::InvalidConsoleMode(
            p::UefiConsoleMode(255)
        ))
    ));
    settings.v1.console_mode = 0;
    settings.v2.r#static.memory_protection_mode = 255;
    let result = host
        .exchange(
            client.device_platform_settings(),
            p::DevicePlatformSettingsRequestV2::new().as_bytes(),
            &response(&serde_json::to_vec(&settings).unwrap()),
        )
        .await;
    assert!(matches!(
        result,
        Err(DevicePlatformSettingsError::InvalidMemoryProtectionMode(
            255
        ))
    ));
    settings.v2.r#static.memory_protection_mode = 0;
    settings.v2.r#static.vtl2_settings = Some(vec![0xff]);
    let result = host
        .exchange(
            client.device_platform_settings(),
            p::DevicePlatformSettingsRequestV2::new().as_bytes(),
            &response(&serde_json::to_vec(&settings).unwrap()),
        )
        .await;
    assert!(matches!(
        result,
        Err(DevicePlatformSettingsError::BadVtl2Settings(_))
    ));
}

// Test: Convert Windows-epoch ticks with fractional seconds and positive/negative bias.
// Expected: The instant retains 100ns precision and Windows timezone bias is
//       negated when constructing the local timezone.
#[test]
fn host_time_conversion_preserves_precision_and_timezone_direction() {
    for bias in [-330, 0, 60] {
        let time = crate::api::Time {
            utc: 116_444_736_001_234_567,
            time_zone: bias,
        }
        .to_jiff();
        assert_eq!(time.timestamp().as_nanosecond(), 123_456_700);
        assert_eq!(time.offset().seconds(), -i32::from(bias) * 60);
    }
    let time = crate::api::Time {
        utc: 0,
        time_zone: 0,
    }
    .to_jiff();
    assert_eq!((time.year(), time.month(), time.day()), (1601, 1, 1));
}

// Test: Have the host split a settings response across revision-one packets.
// Expected: The caller receives a single parsed settings object with the full
//       string value, including bytes split in the middle of a JSON token.
#[async_test]
async fn fragmented_platform_settings_are_reassembled_before_decoding(driver: DefaultDriver) {
    let (client, mut host, _task) = setup(&driver).await;
    let mut settings = p::dps_json::DevicePlatformSettingsV2Json::default();
    settings.v1.serial_number = "serial-spanning-fragments".into();
    let json = serde_json::to_vec(&settings).unwrap();
    let peer = async {
        host.expect(p::DevicePlatformSettingsRequestV2::new().as_bytes())
            .await;
        let chunks: Vec<_> = json.chunks(37).collect();
        for (index, bytes) in chunks.iter().enumerate() {
            let header = p::DevicePlatformSettingsResponseV2Rev1 {
                message_header: p::HeaderGeneric::new(
                    p::HostRequests::DEVICE_PLATFORM_SETTINGS_V2_REV1,
                ),
                size: bytes.len() as u32,
                payload_state: if index + 1 == chunks.len() {
                    p::LargePayloadState::END
                } else {
                    p::LargePayloadState::MORE
                },
            };
            host.send(&[header.as_bytes(), bytes].concat()).await;
        }
    };
    let (result, ()) = (client.device_platform_settings(), peer).join().await;
    assert_eq!(
        result.unwrap().smbios.serial_number,
        "serial-spanning-fragments"
    );
}
