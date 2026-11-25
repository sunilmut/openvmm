// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use prost::Message;
use test_with_tracing::test;

fn chunk(namespace: &str, settings: Value) -> proto::Vtl2SettingsChunk {
    proto::Vtl2SettingsChunk {
        namespace: namespace.into(),
        settings: serde_json::to_vec(&settings).unwrap(),
    }
}

// Test: Apply device and acceleration namespaces without a base update.
// Expected: NICs are replaced/paired as requested; storage and fixed settings survive.
#[test]
fn network_only_updates_preserve_storage_and_ignore_unlisted_acceleration() {
    let mut original = read(storage_document(vec![controller("SCSI", vec![])])).unwrap();
    original.fixed.scsi_sub_channels = 19;
    original.fixed.io_ring_size = 128;
    original.fixed.max_bounce_buffer_pages = Some(4096);
    let original_storage = original.dynamic.scsi_controllers.clone();
    let document = proto::Vtl2Settings {
        namespace_settings: vec![
            chunk(
                "NetworkDevice",
                json!({"nic_devices": [
                    {"instance_id": CONTROLLER, "max_sub_channels": 8},
                    {"instance_id": BACKING},
                ]}),
            ),
            chunk(
                "NetworkAcceleration",
                json!({"nic_acceleration": [
                    {"instance_id": CONTROLLER, "subordinate_instance_id": BACKING},
                    {"instance_id": "00000000-0000-0000-0000-000000000001",
                     "subordinate_instance_id": BACKING},
                ]}),
            ),
        ],
        ..Default::default()
    };
    let parsed = Vtl2Settings::read_from(&document.encode_to_vec(), original).unwrap();
    assert_eq!(parsed.fixed.scsi_sub_channels, 19);
    assert_eq!(parsed.fixed.io_ring_size, 128);
    assert_eq!(parsed.fixed.max_bounce_buffer_pages, Some(4096));
    assert_eq!(parsed.dynamic.scsi_controllers, original_storage);
    let actual: Vec<_> = parsed
        .dynamic
        .nic_devices
        .iter()
        .map(|nic| {
            (
                nic.instance_id,
                nic.subordinate_instance_id,
                nic.max_sub_channels,
            )
        })
        .collect();
    assert_eq!(
        actual,
        [
            (
                CONTROLLER.parse().unwrap(),
                Some(BACKING.parse().unwrap()),
                Some(8)
            ),
            (BACKING.parse().unwrap(), None, None),
        ]
    );
}

// Test: Supply bad instance IDs in each network namespace, including a bad paired ID.
// Expected: All invalid NICs are reported and parsing continues across namespace chunks.
#[test]
fn invalid_network_ids_accumulate_across_namespaces() {
    let document = proto::Vtl2Settings {
        namespace_settings: vec![
            chunk(
                "NetworkDevice",
                json!({"nic_devices": [{"instance_id": "bad-device"}]}),
            ),
            chunk(
                "NetworkAcceleration",
                json!({"nic_acceleration": [
                    {"instance_id": "bad-acceleration", "subordinate_instance_id": BACKING},
                    {"instance_id": CONTROLLER, "subordinate_instance_id": "bad-pair"},
                ]}),
            ),
        ],
        ..Default::default()
    };
    let ParseError::Validation(errors) =
        Vtl2Settings::read_from(&document.encode_to_vec(), Default::default()).unwrap_err()
    else {
        panic!("expected validation errors");
    };
    assert_eq!(errors.errors.len(), 3);
    for (error, bad_id) in errors
        .errors
        .iter()
        .zip(["bad-device", "bad-acceleration", "bad-pair"])
    {
        assert_eq!(error.code(), Vtl2SettingsErrorCode::InvalidInstanceId);
        let value: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .starts_with(&format!("invalid instance ID '{bad_id}':"))
        );
    }
}

// Test: Put malformed JSON inside an otherwise valid protobuf namespace envelope.
// Expected: The nested JSON decoding failure is returned instead of a partial update.
#[test]
fn malformed_nested_namespace_preserves_the_decode_error() {
    for namespace in ["Base", "NetworkDevice", "NetworkAcceleration"] {
        let document = proto::Vtl2Settings {
            namespace_settings: vec![proto::Vtl2SettingsChunk {
                namespace: namespace.into(),
                settings: b"{".to_vec(),
            }],
            ..Default::default()
        };
        assert!(matches!(
            Vtl2Settings::read_from(&document.encode_to_vec(), Default::default()),
            Err(ParseError::Json(_))
        ));
    }
}
