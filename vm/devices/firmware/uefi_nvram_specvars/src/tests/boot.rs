// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{END, OWNER, OWNER_BYTES, load_option, node};
use crate::boot_order::*;
use test_with_tracing::test;
use uefi_specs::uefi::boot;

// Test: Decode empty and nonempty boot orders, including high-byte IDs and duplicates.
// Expected: Little-endian order is preserved and every odd-length input is rejected.
#[test]
fn boot_order_preserves_ids_and_rejects_partial_entries() {
    assert_eq!(parse_boot_order(&[]).unwrap().collect::<Vec<_>>(), []);
    let bytes = [0x34, 0x12, 0xff, 0xff, 0, 0, 0x34, 0x12];
    assert_eq!(
        parse_boot_order(&bytes).unwrap().collect::<Vec<_>>(),
        [0x1234, 0xffff, 0, 0x1234]
    );
    for length in (1..bytes.len()).step_by(2) {
        assert!(matches!(
            parse_boot_order(&bytes[..length]),
            Err(Error::InvalidLength)
        ));
    }
}

// Test: Decode numeric memory, SCSI and hard-drive device paths from wire bytes.
// Expected: Numeric fields and partition identity retain their specified byte order.
#[test]
fn numeric_device_nodes_preserve_fields() {
    let mut memory = 7u32.to_le_bytes().to_vec();
    memory.extend(0x12345678u64.to_le_bytes());
    memory.extend(0x98765432u64.to_le_bytes());
    let bytes = node(1, 3, &memory);
    let (path, rest) = EfiDevicePathProtocol::parse(&bytes).unwrap();
    assert!(rest.is_empty());
    let EfiDevicePathProtocol::Hardware(HardwareDevice::MemoryMapped(device)) = path else {
        panic!("expected memory-mapped path");
    };
    assert_eq!(
        device,
        boot::EfiMemoryMappedDevice {
            memory_type: boot::EfiMemoryType(7),
            start_address: 0x12345678,
            end_address: 0x98765432,
        }
    );
    let bytes = node(3, 2, &[0x34, 0x12, 0x78, 0x56]);
    let (path, _) = EfiDevicePathProtocol::parse(&bytes).unwrap();
    let EfiDevicePathProtocol::Messaging(MessagingDevice::Scsi(device)) = path else {
        panic!("expected SCSI path");
    };
    assert_eq!(
        device,
        boot::EfiScsiDevice {
            target_id: 0x1234,
            logical_unit_num: 0x5678
        }
    );

    let mut drive = 3u32.to_le_bytes().to_vec();
    drive.extend(0x123456789u64.to_le_bytes());
    drive.extend(0x987654321u64.to_le_bytes());
    drive.extend(OWNER_BYTES);
    drive.extend([2, 2]);
    let bytes = node(4, 1, &drive);
    let (path, _) = EfiDevicePathProtocol::parse(&bytes).unwrap();
    let EfiDevicePathProtocol::Media(MediaDevice::HardDrive(device)) = path else {
        panic!("expected hard-drive path");
    };
    assert_eq!(
        device,
        boot::EfiHardDriveDevice {
            partition_number: 3,
            partition_start: 0x123456789,
            partition_size: 0x987654321,
            partition_signature: OWNER,
            partition_format: boot::EfiPartitionFormat(2),
            partition_type: boot::EfiSignatureType(2),
        }
    );
}

// Test: Decode vendor and firmware GUID nodes with a distinct byte pattern.
// Expected: GUIDs survive unchanged; vendor payload and trailing nodes stay separate.
#[test]
fn guid_nodes_preserve_identity_and_payload_boundaries() {
    for (kind, subtype) in [(1, 4), (4, 6), (4, 7)] {
        let mut payload = OWNER_BYTES.to_vec();
        if kind == 1 {
            payload.extend([9, 8, 7]);
        }
        let mut bytes = node(kind, subtype, &payload);
        bytes.extend(END);
        let (path, rest) = EfiDevicePathProtocol::parse(&bytes).unwrap();
        assert_eq!(rest, END);
        let guid = match path {
            EfiDevicePathProtocol::Hardware(HardwareDevice::Vendor { vendor_guid, data }) => {
                assert_eq!(data, [9, 8, 7]);
                vendor_guid
            }
            EfiDevicePathProtocol::Media(MediaDevice::PiwgFirmwareFile(guid)) if subtype == 6 => {
                guid
            }
            EfiDevicePathProtocol::Media(MediaDevice::PiwgFirmwareVolume(guid)) if subtype == 7 => {
                guid
            }
            _ => panic!("incorrect GUID path variant"),
        };
        assert_eq!(guid, OWNER);
    }
}

// Test: Decode an expanded ACPI path with three independently terminated strings.
// Expected: Numeric IDs, all strings and the following device node remain distinct.
#[test]
fn expanded_acpi_preserves_all_identifiers() {
    let mut payload = 0x11223344u32.to_le_bytes().to_vec();
    payload.extend(0x55667788u32.to_le_bytes());
    payload.extend(0x99aabbccu32.to_le_bytes());
    payload.extend(b"PNP0A03\0UID-1\0COMPAT\0");
    let mut bytes = node(2, 2, &payload);
    bytes.extend(END);
    let (path, rest) = EfiDevicePathProtocol::parse(&bytes).unwrap();
    let EfiDevicePathProtocol::Acpi(AcpiDevice::ExpandedAcpi {
        numeric,
        hidstr,
        uidstr,
        cidstr,
    }) = path
    else {
        panic!("expected expanded ACPI path");
    };
    assert_eq!(
        numeric,
        boot::EfiExpandedAcpiDevice {
            hid: 0x11223344,
            cid: 0x55667788,
            uid: 0x99aabbcc
        }
    );
    assert_eq!(
        (hidstr.to_bytes(), uidstr.to_bytes(), cidstr.to_bytes()),
        (&b"PNP0A03"[..], &b"UID-1"[..], &b"COMPAT"[..])
    );
    assert_eq!(rest, END);
}

// Test: Decode unknown node types/subtypes in each supported device family.
// Expected: Type, subtype and opaque payload are preserved, without consuming the next node.
#[test]
fn unknown_device_paths_remain_opaque() {
    for kind in [1, 2, 3, 4, 0x7f, 0x7e] {
        let mut bytes = node(kind, 0xfe, &[9, 8, 7]);
        bytes.extend(END);
        let (path, rest) = EfiDevicePathProtocol::parse(&bytes).unwrap();
        let (actual_kind, subtype, data) = match path {
            EfiDevicePathProtocol::Hardware(HardwareDevice::Unknown {
                device_subtype,
                path_data,
            }) => (1, device_subtype.0, path_data),
            EfiDevicePathProtocol::Acpi(AcpiDevice::Unknown {
                device_subtype,
                path_data,
            }) => (2, device_subtype.0, path_data),
            EfiDevicePathProtocol::Messaging(MessagingDevice::Unknown {
                device_subtype,
                path_data,
            }) => (3, device_subtype.0, path_data),
            EfiDevicePathProtocol::Media(MediaDevice::Unknown {
                device_subtype,
                path_data,
            }) => (4, device_subtype.0, path_data),
            EfiDevicePathProtocol::End(EndDevice::Unknown {
                device_subtype,
                path_data,
            }) => (0x7f, device_subtype.0, path_data),
            EfiDevicePathProtocol::Unknown {
                device_type,
                device_subtype,
                path_data,
            } => (device_type.0, device_subtype, path_data),
            _ => panic!("expected unknown path"),
        };
        assert_eq!((actual_kind, subtype, data), (kind, 0xfe, &[9, 8, 7][..]));
        assert_eq!(rest, END);
    }
}

// Test: Parse file-path nodes, including missing UCS-2 termination and trailing bytes.
// Expected: Valid names retain their encoding; malformed names return typed errors.
#[test]
fn file_device_paths_validate_name_boundaries() {
    let name = b"\\\0E\0F\0I\0\\\0b\0o\0o\0t\0.\0e\0f\0i\0\0\0";
    let bytes = node(4, 4, name);
    let (path, rest) = EfiDevicePathProtocol::parse(&bytes).unwrap();
    let EfiDevicePathProtocol::Media(MediaDevice::File(file)) = path else {
        panic!("expected file path");
    };
    assert_eq!(file.as_bytes(), name);
    assert!(rest.is_empty());
    for name in [&b"A\0"[..], &b"A"[..]] {
        assert!(matches!(
            EfiDevicePathProtocol::parse(&node(4, 4, name)),
            Err(Error::InvalidUcs2(_))
        ));
    }
    assert!(matches!(
        EfiDevicePathProtocol::parse(&node(4, 4, b"A\0\0\0B\0")),
        Err(Error::InvalidLength)
    ));
}

// Test: Supply truncated or inconsistent device-node headers and fixed-size payloads.
// Expected: Each invalid boundary returns InvalidLength rather than reading another node.
#[test]
fn malformed_device_lengths_are_rejected() {
    for length in 0..4 {
        assert!(matches!(
            EfiDevicePathProtocol::parse(&END[..length]),
            Err(Error::InvalidLength)
        ));
        let bytes = [1, 3, length as u8, 0];
        assert!(matches!(
            EfiDevicePathProtocol::parse(&bytes),
            Err(Error::InvalidLength)
        ));
    }
    assert!(matches!(
        EfiDevicePathProtocol::parse(&[1, 3, 0xff, 0xff]),
        Err(Error::InvalidLength)
    ));
    for (kind, subtype, size) in [
        (1, 3, 19),
        (1, 4, 15),
        (3, 2, 3),
        (4, 1, 41),
        (4, 6, 15),
        (4, 7, 17),
        (2, 2, 14),
    ] {
        assert!(matches!(
            EfiDevicePathProtocol::parse(&node(kind, subtype, &vec![0; size])),
            Err(Error::InvalidLength)
        ));
    }
}

// Test: Give expanded ACPI paths an unterminated final string or extra trailing bytes.
// Expected: Missing terminators and inconsistent lengths have distinct typed errors.
#[test]
fn malformed_acpi_strings_are_rejected() {
    let mut payload = vec![0; 12];
    payload.extend(b"HID\0UID\0CID");
    assert!(matches!(
        EfiDevicePathProtocol::parse(&node(2, 2, &payload)),
        Err(Error::NullTerminated(_))
    ));
    let mut payload = vec![0; 12];
    payload.extend(b"H\0U\0C\0trailing");
    assert!(matches!(
        EfiDevicePathProtocol::parse(&node(2, 2, &payload)),
        Err(Error::InvalidLength)
    ));
}

// Test: Parse a multi-instance boot path followed by binary optional data.
// Expected: Instance markers are skipped, the entire-path marker terminates parsing,
//       and optional data is not interpreted as another device node.
#[test]
fn load_option_preserves_instances_and_optional_data() {
    let mut paths = node(3, 2, &[1, 0, 2, 0]);
    paths.extend(node(0x7f, 1, &[]));
    paths.extend(node(3, 2, &[3, 0, 4, 0]));
    paths.extend(END);
    let bytes = load_option(&paths, &[0xff, 0, 0x7f, 0xff]);
    let option = EfiLoadOption::parse(&bytes).unwrap();
    assert_eq!(option.attributes, 0x11223344);
    assert_eq!(option.device_paths.len(), 2);
    for (path, target, lun) in [
        (&option.device_paths[0], 1, 2),
        (&option.device_paths[1], 3, 4),
    ] {
        let EfiDevicePathProtocol::Messaging(MessagingDevice::Scsi(device)) = path else {
            panic!("expected SCSI path");
        };
        assert_eq!(
            *device,
            boot::EfiScsiDevice {
                target_id: target,
                logical_unit_num: lun
            }
        );
    }
    assert_eq!(option.opt, Some(&[0xff, 0, 0x7f, 0xff][..]));
    let bytes = load_option(END, &[]);
    assert!(EfiLoadOption::parse(&bytes).unwrap().opt.is_none());
}

// Test: Supply truncated load-option headers, missing descriptions and bad end markers.
// Expected: Structural, string and path-end failures retain their typed errors.
#[test]
fn malformed_load_options_are_rejected() {
    for length in 0..6 {
        assert!(matches!(
            EfiLoadOption::parse(&[0; 6][..length]),
            Err(Error::InvalidLength)
        ));
    }
    assert!(matches!(
        EfiLoadOption::parse(&[0; 6]),
        Err(Error::InvalidUcs2(_))
    ));
    let bytes = load_option(&[], &[]);
    assert!(matches!(
        EfiLoadOption::parse(&bytes),
        Err(Error::DevicePathEnd)
    ));
    let bytes = load_option(&node(0x7f, 0xfe, &[]), &[]);
    assert!(matches!(
        EfiLoadOption::parse(&bytes),
        Err(Error::DevicePathEnd)
    ));
}

// IGNORED: The parser never bounds device paths by file_path_list_length. It accepts
//       an end node completed by bytes outside the declared device-path list.
//
// Test: Declare a device-path list shorter than its end-node header.
// Expected: Optional bytes outside that declared list cannot complete the path.
#[test]
#[ignore = "product bug: load options ignore their declared device-path-list length"]
fn load_option_respects_declared_device_path_length() {
    let mut bytes = load_option(END, &[]);
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert!(EfiLoadOption::parse(&bytes).is_err());
}
