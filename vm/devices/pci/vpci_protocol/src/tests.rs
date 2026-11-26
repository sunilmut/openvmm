// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Supply remapped MSI fields with nonzero data and an address above 4 GiB.
fn translated_interrupt() -> MsiResourceRemapped {
    MsiResourceRemapped {
        reserved: 0,
        message_count: 32,
        data_payload: 0x12345678,
        address: 0x00000001fee00120,
    }
}

// Verify the shared reply prefix and zero padding in every resource version.
fn assert_translated_wire(bytes: &[u8]) {
    assert_eq!(
        &bytes[..16],
        &[
            0, 0, 32, 0, 0x78, 0x56, 0x34, 0x12, 0x20, 1, 0xe0, 0xfe, 1, 0, 0, 0
        ]
    );
    assert!(bytes[16..].iter().all(|&byte| byte == 0));
}

// Test: Transport a legacy MSI request with affinity at both ends of its mask.
// Expected: Exact request/reply bytes retain the mask, count and 64-bit address;
//       edits through either union view change only the selected wire fields.
#[test]
fn legacy_msi_request_and_reply_preserve_the_wire_fields() {
    let mut request = MsiResource::from(MsiResourceDescriptor {
        vector: 0x70,
        delivery_mode: DeliveryMode::LOWEST_PRIORITY,
        vector_count: 32,
        reserved: [0; 2],
        processor_mask: 0x8000000000000001,
    });
    assert_eq!(
        request.as_bytes(),
        &[0x70, 1, 32, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x80]
    );
    assert_eq!(request.descriptor().processor_mask, 0x8000000000000001);
    request.descriptor_mut().processor_mask = 1 << 17;
    assert_eq!(
        request.as_bytes(),
        &[0x70, 1, 32, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0]
    );
    let mut reply = MsiResource::from(translated_interrupt());
    assert_translated_wire(reply.as_bytes());
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    reply.remapped_mut().data_payload = 0x81;
    assert_eq!(reply.remapped().data_payload, 0x81);
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    assert_eq!(&reply.as_bytes()[4..8], &[0x81, 0, 0, 0]);
}

// Test: Transport all 32 distinct processor IDs in a version-two MSI resource.
// Expected: IDs wider than a legacy CPU mask retain their exact array offsets;
//       retargeting the last ID and editing reply data preserve the other bytes.
#[test]
fn msi_v2_keeps_the_complete_processor_array_and_reply_padding() {
    let processors = std::array::from_fn(|i| u16::try_from(i * 257).unwrap());
    let mut request = MsiResource2::from(MsiResourceDescriptor2 {
        vector: 0x61,
        delivery_mode: DeliveryMode::FIXED,
        vector_count: 1,
        processor_count: 32,
        processor_array: processors,
        reserved: 0,
    });
    let mut expected = [0u8; 72];
    expected[..6].copy_from_slice(&[0x61, 0, 1, 0, 32, 0]);
    for (i, processor) in processors.iter().enumerate() {
        expected[6 + i * 2..8 + i * 2].copy_from_slice(&processor.to_le_bytes());
    }
    assert_eq!(request.as_bytes(), expected);
    assert_eq!(request.descriptor().processor_array, processors);
    request.descriptor_mut().processor_array[31] = 0x4321;
    expected[68..70].copy_from_slice(&[0x21, 0x43]);
    assert_eq!(request.as_bytes(), expected);
    let mut reply = MsiResource2::from(translated_interrupt());
    assert_translated_wire(reply.as_bytes());
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    reply.remapped_mut().data_payload = 0x81;
    assert_eq!(reply.remapped().data_payload, 0x81);
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    assert_eq!(&reply.as_bytes()[4..8], &[0x81, 0, 0, 0]);
    assert!(reply.as_bytes()[16..].iter().all(|&byte| byte == 0));
}

// Test: Transport a wide MSI vector and an unknown delivery mode in version three.
// Expected: Vector bits, all processor IDs and the opaque mode survive unchanged;
//       request/reply padding stays zero and edits do not truncate the wide vector.
#[test]
fn msi_v3_preserves_wide_vectors_and_unknown_delivery_modes() {
    let processors = std::array::from_fn(|i| u16::try_from(i * 257).unwrap());
    let mut request = MsiResource3::from(MsiResourceDescriptor3 {
        vector: 0x123456,
        delivery_mode: DeliveryMode(0xfe),
        reserved: 0,
        vector_count: 1,
        processor_count: 32,
        processor_array: processors,
        reserved2: 0,
    });
    let mut expected = [0u8; 80];
    expected[..10].copy_from_slice(&[0x56, 0x34, 0x12, 0, 0xfe, 0, 1, 0, 32, 0]);
    for (i, processor) in processors.iter().enumerate() {
        expected[10 + i * 2..12 + i * 2].copy_from_slice(&processor.to_le_bytes());
    }
    assert_eq!(request.as_bytes(), expected);
    assert_eq!(request.descriptor().processor_array, processors);
    assert_eq!(request.descriptor().delivery_mode, DeliveryMode(0xfe));
    request.descriptor_mut().vector = 0x654321;
    expected[..4].copy_from_slice(&[0x21, 0x43, 0x65, 0]);
    assert_eq!(request.as_bytes(), expected);
    assert_eq!(request.descriptor().vector, 0x654321);
    let mut reply = MsiResource3::from(translated_interrupt());
    assert_translated_wire(reply.as_bytes());
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    reply.remapped_mut().data_payload = 0x81;
    assert_eq!(reply.remapped().data_payload, 0x81);
    assert_eq!(reply.remapped().address, 0x00000001fee00120);
    assert_eq!(&reply.as_bytes()[4..8], &[0x81, 0, 0, 0]);
    assert!(reply.as_bytes()[16..].iter().all(|&byte| byte == 0));
}
