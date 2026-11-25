// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use schema::ParseError;
use serde_json::Value;
use serde_json::json;
use test_with_tracing::test;
use vtl2_settings_proto as proto;

mod namespaces;
mod storage;

const CONTROLLER: &str = "ca567511-e643-4bef-bf54-f73678e8b7b5";
const BACKING: &str = "3217a48a-c820-4727-8c4c-3e2086aba839";

fn storage_document(controllers: Vec<Value>) -> Value {
    json!({"version": "V1", "dynamic": {"storage_controllers": controllers}})
}

fn controller(protocol: &str, luns: Vec<Value>) -> Value {
    json!({"instance_id": CONTROLLER, "protocol": protocol, "luns": luns})
}

fn device() -> Value {
    json!({"device_type": "NVME", "device_path": BACKING, "sub_device_path": 7})
}

fn read(document: Value) -> Result<Vtl2Settings, ParseError> {
    Vtl2Settings::read_from(&serde_json::to_vec(&document).unwrap(), Default::default())
}

fn assert_validation(document: Value, expected: &[(Vtl2SettingsErrorCode, String)]) {
    let ParseError::Validation(errors) = read(document).unwrap_err() else {
        panic!("expected configuration validation errors");
    };
    assert_eq!(errors.errors.len(), expected.len(), "{errors}");
    for (error, (code, message)) in errors.errors.iter().zip(expected) {
        assert_eq!(error.code(), *code, "{error}");
        let value: Value = serde_json::from_str(&error.to_string()).unwrap();
        assert!(
            value["message"].as_str().unwrap().contains(message),
            "{error}"
        );
    }
}

// Test: Decode truncated JSON and protobuf at the public configuration boundary.
// Expected: The caller receives the original encoding-specific error and source.
#[test]
fn malformed_encodings_retain_their_error_type_and_source() {
    use std::error::Error;

    let json = Vtl2Settings::read_from(b" \r\n{", Default::default()).unwrap_err();
    assert!(matches!(json, ParseError::Json(_)));
    assert!(json.source().unwrap().to_string().contains("EOF"));
    let protobuf = Vtl2Settings::read_from(&[0x0a, 3, b'A'], Default::default()).unwrap_err();
    assert!(matches!(protobuf, ParseError::Protobuf(_)));
    assert!(protobuf.source().is_some());
}

// Test: Reject an unsupported base version, unknown namespace and empty chunk together.
// Expected: All three stable wire error IDs and messages survive JSON-line formatting.
#[test]
fn envelope_errors_accumulate_with_stable_host_diagnostics() {
    use prost::Message;

    let document = proto::Vtl2Settings {
        version: 99,
        fixed: Some(Default::default()),
        namespace_settings: vec![
            proto::Vtl2SettingsChunk {
                namespace: "Future".into(),
                settings: vec![1],
            },
            proto::Vtl2SettingsChunk {
                namespace: "NetworkDevice".into(),
                settings: vec![],
            },
        ],
        ..Default::default()
    };
    let ParseError::Validation(errors) =
        Vtl2Settings::read_from(&document.encode_to_vec(), Default::default()).unwrap_err()
    else {
        panic!("expected validation errors");
    };
    let actual: Vec<Value> = errors
        .to_string()
        .lines()
        .map(|line| {
            let mut value: Value = serde_json::from_str(line).unwrap();
            assert!(!value["file_name"].as_str().unwrap().is_empty());
            assert!(value["line"].as_u64().unwrap() > 0);
            value.as_object_mut().unwrap().remove("file_name");
            value.as_object_mut().unwrap().remove("line");
            value
        })
        .collect();
    assert_eq!(
        actual,
        [
            json!({"error_id": "Configuration.UnsupportedSchemaVersion",
               "message": "unsupported schema version 0x63"}),
            json!({"error_id": "Configuration.UnsupportedSchemaNamespace",
               "message": "unsupported schema namespace Future"}),
            json!({"error_id": "Configuration.EmptyNamespaceChunk",
               "message": "empty namespace settings chunk NetworkDevice"}),
        ]
    );
}
