// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use Vtl2SettingsErrorCode as Code;
use test_with_tracing::test;

// Test: Parse IDE media at the last valid slot, including its NTFS identity.
// Expected: Channel, slot, media type, GUID and queue depth are preserved.
#[test]
fn ide_boundary_slot_preserves_media_identity() {
    let mut ide = controller(
        "IDE",
        vec![json!({
            "channel": 1, "location": 1, "is_dvd": true, "ntfs_guid": BACKING,
        })],
    );
    ide["io_queue_depth"] = json!(17);
    let parsed = read(storage_document(vec![ide])).unwrap();
    let ide = parsed.dynamic.ide_controller.unwrap();
    assert_eq!(ide.io_queue_depth, Some(17));
    let [disk]: [_; 1] = ide.disks.try_into().unwrap();
    assert_eq!((disk.channel, disk.location), (1, 1));
    assert!(disk.is_dvd);
    assert_eq!(disk.ntfs_guid, Some(BACKING.parse().unwrap()));
    assert_eq!(disk.physical_devices, PhysicalDevices::EmptyDrive);
}

// Test: Omit an IDE channel or specify the first out-of-range channel.
// Expected: Each rejected disk identifies its controller and, when known, its slot.
#[test]
fn invalid_ide_channels_report_the_failing_device() {
    for (lun, code, message) in [
        (
            json!({"is_dvd": true}),
            Code::StorageIdeChannelNotProvided,
            format!("ide controller channel not provided, instance ID: {CONTROLLER}"),
        ),
        (
            json!({"channel": 2, "location": 0, "is_dvd": true}),
            Code::StorageIdeChannelExceedsMaxLimits,
            format!(
                "ide controller channel exceeds 2 max channels, ide device 2/0, instance ID: {CONTROLLER}"
            ),
        ),
    ] {
        assert_validation(
            storage_document(vec![controller("IDE", vec![lun])]),
            &[(code, message)],
        );
    }
}

// Test: Configure two disks in one IDE slot and configure a second IDE controller.
// Expected: Both conflicts are reported rather than silently replacing a device.
#[test]
fn duplicate_ide_slots_and_controllers_are_rejected() {
    let lun = json!({"channel": 0, "location": 1, "is_dvd": true});
    let mut second = controller("IDE", vec![]);
    second["instance_id"] = json!(BACKING);
    assert_validation(
        storage_document(vec![controller("IDE", vec![lun.clone(), lun]), second]),
        &[
            (
                Code::StorageIdeChannelInvalidConfiguration,
                format!(
                    "ide controller has invalid configuration, ide device 0/1, instance ID: {CONTROLLER}"
                ),
            ),
            (
                Code::StorageIdeChannelExceedsMaxLimits,
                format!("instance ID: {BACKING}"),
            ),
        ],
    );
}

// Test: Put the first invalid SCSI LUN, a duplicate valid LUN and a bad NTFS GUID together.
// Expected: Validation continues and reports each fault with its own LUN and controller.
#[test]
fn scsi_errors_accumulate_without_losing_nested_context() {
    assert_validation(
        storage_document(vec![controller(
            "SCSI",
            vec![
                json!({"location": 64, "is_dvd": true}),
                json!({"location": 63, "is_dvd": true}),
                json!({"location": 63, "is_dvd": true}),
                json!({"location": 7, "is_dvd": true, "ntfs_guid": "broken"}),
            ],
        )]),
        &[
            (
                Code::StorageLunLocationExceedsMaxLimits,
                format!("disk location exceeds limits 64, scsi LUN 64, instance ID: {CONTROLLER}"),
            ),
            (
                Code::StorageInvalidNtfsFormatGuid,
                "invalid ntfs guid 'broken':".into(),
            ),
            (
                Code::StorageLunLocationDuplicated,
                format!("disk location is duplicated, instance ID: {CONTROLLER}"),
            ),
        ],
    );
}

// Test: Supply reserved NVMe namespace IDs, unsupported DVD media and duplicate IDs.
// Expected: All invalid namespaces are rejected with controller and namespace context.
#[test]
fn nvme_namespace_boundaries_and_duplicates_are_rejected() {
    let mut luns = vec![];
    let mut expected = vec![];
    for nsid in [0, u32::MAX] {
        luns.push(json!({"location": nsid, "is_dvd": true}));
        let context = format!(", nvme namespace ID {nsid}, instance ID: {CONTROLLER}");
        expected.push((
            Code::StorageLunLocationExceedsMaxLimits,
            format!("NVMe namespace id is invalid{context}"),
        ));
        expected.push((
            Code::StorageUnsupportedDeviceType,
            format!("NVMe namespace can't be a DVD drive{context}"),
        ));
    }
    let lun = json!({"location": 1, "physical_devices": {"type": "SINGLE", "device": device()}});
    luns.extend([lun.clone(), lun]);
    expected.push((
        Code::StorageLunLocationDuplicated,
        format!("disk location is duplicated, instance ID: {CONTROLLER}"),
    ));
    assert_validation(storage_document(vec![controller("NVME", luns)]), &expected);
}

// Test: Decode populated NVMe disk options from both JSON and protobuf.
// Expected: Namespace identity, backing and every optional disk override retain their values.
#[test]
fn nvme_disk_overrides_survive_both_wire_encodings() {
    use prost::Message;

    let document = storage_document(vec![controller(
        "NVME",
        vec![json!({
            "location": 42, "device_id": "disk", "vendor_id": "vendor", "product_id": "product",
            "product_revision_level": "rev", "serial_number": "serial", "model_number": "model",
            "medium_rotation_rate": 7200, "physical_sector_size": 4096,
            "fua": false, "write_cache": true, "scsi_disk_size_in_bytes": 1073741824,
            "odx": true, "disable_thin_provisioning": true, "max_transfer_length": 65536,
            "physical_devices": {"type": "SINGLE", "device": device()},
        })],
    )]);
    let protobuf: proto::Vtl2Settings = serde_json::from_value(document.clone()).unwrap();
    for bytes in [
        serde_json::to_vec(&document).unwrap(),
        protobuf.encode_to_vec(),
    ] {
        let parsed = Vtl2Settings::read_from(&bytes, Default::default()).unwrap();
        let [controller]: [_; 1] = parsed.dynamic.nvme_controllers.try_into().unwrap();
        assert_eq!(controller.instance_id, CONTROLLER.parse().unwrap());
        let [namespace]: [_; 1] = controller.namespaces.try_into().unwrap();
        assert_eq!(namespace.nsid, 42);
        assert_eq!(
            namespace.physical_devices,
            PhysicalDevices::Single {
                device: PhysicalDevice {
                    device_type: DeviceType::NVMe,
                    vmbus_instance_id: BACKING.parse().unwrap(),
                    sub_device_path: 7
                },
            }
        );
        assert_eq!(
            namespace.disk_params,
            DiskParameters {
                device_id: "disk".into(),
                vendor_id: "vendor".into(),
                product_id: "product".into(),
                product_revision_level: "rev".into(),
                serial_number: "serial".into(),
                model_number: "model".into(),
                medium_rotation_rate: 7200,
                physical_sector_size: Some(4096),
                fua: Some(false),
                write_cache: Some(true),
                scsi_disk_size_in_bytes: Some(1073741824),
                odx: Some(true),
                unmap: Some(false),
                max_transfer_length: Some(65536),
            }
        );
    }
}

// Test: Reject missing or excess backing disks for single and striped LUNs.
// Expected: The error reports the actual disk count and the affected SCSI LUN.
#[test]
fn invalid_backing_counts_are_rejected() {
    for (backing, count) in [
        (json!({"type": "SINGLE"}), 0),
        (
            json!({"type": "SINGLE", "device": device(), "devices": [device()]}),
            2,
        ),
        (json!({"type": "STRIPED", "devices": [device()]}), 1),
        (
            json!({"type": "STRIPED", "device": device(), "devices": [device(), device()]}),
            3,
        ),
    ] {
        assert_validation(
            storage_document(vec![controller(
                "SCSI",
                vec![json!({"location": 3, "physical_devices": backing})],
            )]),
            &[(
                Code::StorageInvalidPhysicalDiskCount,
                format!(
                    "invalid physical disk count: physical_disk_count = {count}, scsi LUN 3, instance ID: {CONTROLLER}"
                ),
            )],
        );
    }
}

// Test: Supply unknown backing/device types and incompatible legacy declarations.
// Expected: Invalid topology is rejected rather than accepted with a partial backing.
#[test]
fn invalid_or_mixed_backing_schemas_are_rejected() {
    for (lun, code, message) in [
        (
            json!({"physical_devices": {}}),
            Code::StorageUnsupportedDeviceType,
            "invalid device type",
        ),
        (
            json!({"physical_devices": {"type": "SINGLE", "device": {
                "device_path": BACKING, "sub_device_path": 1,
            }}}),
            Code::StorageUnsupportedDeviceType,
            "invalid device type",
        ),
        (
            json!({}),
            Code::JsonFormatError,
            "could not find any physical devices",
        ),
        (
            json!({"physical_devices": {"type": "SINGLE", "device": device()},
                "device_type": "NVME", "device_path": BACKING, "sub_device_path": 1}),
            Code::JsonFormatError,
            "cannot mix old/new physical device schema declarations",
        ),
    ] {
        assert_validation(
            storage_document(vec![controller("SCSI", vec![lun])]),
            &[(code, message.into())],
        );
    }
}

// Test: Configure an unknown protocol, malformed controller ID or reused controller GUID.
// Expected: The caller receives a specific diagnostic for each invalid controller.
#[test]
fn invalid_controller_identity_and_protocol_are_rejected() {
    assert_validation(
        storage_document(vec![controller("UNKNOWN", vec![])]),
        &[(
            Code::StorageInvalidControllerType,
            format!("controller has unknown storage protocol, instance ID: {CONTROLLER}"),
        )],
    );
    let mut invalid = controller("SCSI", vec![]);
    invalid["instance_id"] = json!("broken");
    assert_validation(
        storage_document(vec![invalid]),
        &[(
            Code::InvalidInstanceId,
            "invalid instance ID 'broken':".into(),
        )],
    );
    assert_validation(
        storage_document(vec![controller("SCSI", vec![]), controller("NVME", vec![])]),
        &[(
            Code::StorageControllerGuidAlreadyExists,
            format!("controller already exists, instance ID: {CONTROLLER}"),
        )],
    );
}

// IGNORED: Reproduced a product bug: an invalid IDE location maps to the
//       channel-limit error code instead of the existing location-limit code.
//
// Test: Set an IDE location to the first invalid slot on a valid channel.
// Expected: The host receives the location-specific error code, not a channel error.
#[test]
#[ignore = "product bug: invalid IDE locations return the channel-limit error code"]
fn invalid_ide_location_has_a_location_specific_error_code() {
    assert_validation(
        storage_document(vec![controller(
            "IDE",
            vec![json!({"channel": 0, "location": 2, "is_dvd": true})],
        )]),
        &[(
            Code::StorageIdeLocationExceedsMaxLimits,
            format!("ide device 0/2, instance ID: {CONTROLLER}"),
        )],
    );
}

// IGNORED: Reproduced a product bug: sorting only by location leaves duplicate
//       slots separated by another channel, so the adjacent-pair check misses them.
//
// Test: Separate two disks in one IDE slot with the same location on another channel.
// Expected: The duplicate channel/location is rejected regardless of declaration order.
#[test]
#[ignore = "product bug: interleaved IDE channels hide duplicate slots"]
fn interleaved_ide_channels_cannot_hide_a_duplicate_slot() {
    let luns = [0, 1, 0].map(|channel| json!({"channel": channel, "location": 0, "is_dvd": true}));
    assert_validation(
        storage_document(vec![controller("IDE", luns.into())]),
        &[(
            Code::StorageIdeChannelInvalidConfiguration,
            format!("ide device 0/0, instance ID: {CONTROLLER}"),
        )],
    );
}

// Test: Decode two virtual NVMe controllers that each expose namespace 1.
// Expected: Both encodings accept the repeated ID across controllers and keep
//       each namespace associated with its own controller, backing and serial.
#[test]
fn nvme_namespace_ids_are_scoped_to_their_virtual_controller() {
    use prost::Message;

    let expected = [(CONTROLLER, 7, "first"), (BACKING, 8, "second")];
    let document = storage_document(
        expected
            .map(|(id, sub_device_path, serial)| {
                let mut backing = device();
                backing["sub_device_path"] = json!(sub_device_path);
                let mut controller = controller(
                    "NVME",
                    vec![json!({
                        "location": 1, "serial_number": serial,
                        "physical_devices": {"type": "SINGLE", "device": backing},
                    })],
                );
                controller["instance_id"] = json!(id);
                controller
            })
            .into(),
    );
    let protobuf: proto::Vtl2Settings = serde_json::from_value(document.clone()).unwrap();
    for bytes in [
        serde_json::to_vec(&document).unwrap(),
        protobuf.encode_to_vec(),
    ] {
        let parsed = Vtl2Settings::read_from(&bytes, Default::default()).unwrap();
        let controllers = parsed.dynamic.nvme_controllers;
        assert_eq!(controllers.len(), 2);
        for (id, sub_device_path, serial) in expected {
            let controller = controllers
                .iter()
                .find(|controller| controller.instance_id == id.parse().unwrap())
                .unwrap();
            let [namespace] = controller.namespaces.as_slice() else {
                panic!("expected exactly one namespace per controller");
            };
            assert_eq!(namespace.nsid, 1);
            assert_eq!(namespace.disk_params.serial_number, serial);
            assert_eq!(
                namespace.physical_devices,
                PhysicalDevices::Single {
                    device: PhysicalDevice {
                        device_type: DeviceType::NVMe,
                        vmbus_instance_id: BACKING.parse().unwrap(),
                        sub_device_path,
                    },
                }
            );
        }
    }
}
