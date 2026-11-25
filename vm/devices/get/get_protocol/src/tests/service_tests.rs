// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

const GUID: Guid = guid::guid!("00112233-4455-6677-8899-aabbccddeeff");
const GUID_BYTES: [u8; 16] = [
    0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

// Test: Serialize save/restore state fragments and completion notifications for all statuses plus unknown open-enum values, preserving document sizes and generation IDs.
// Expected: Request/response/notification categories and IDs differ as specified, packed length fields are exact, and unknown statuses survive unchanged.
#[test]
fn state_and_settings_messages_keep_statuses_sizes_and_ids() {
    wire(DevicePlatformSettingsRequestV2::new(), &[1, 2, 18, 0]);
    for raw in [0u16, 1, 2, 3, 0x8877] {
        let status = GuestVtl2SaveRestoreStatus(raw);
        let bytes = raw.to_le_bytes();
        wire(
            SaveGuestVtl2StateRequest::new(status),
            &packet(2, 20, &bytes),
        );
        wire(
            SaveGuestVtl2StateResponse::new(status),
            &packet(3, 20, &bytes),
        );
        wire(
            RestoreGuestVtl2StateRequest::new(status),
            &packet(2, 21, &bytes),
        );
        wire(
            RestoreGuestVtl2StateHostNotification::new(status),
            &packet(1, 5, &bytes),
        );
        let mut body = 0x44332211u32.to_le_bytes().to_vec();
        body.extend_from_slice(&bytes);
        wire(
            RestoreGuestVtl2StateResponse::new(0x44332211, status),
            &packet(3, 21, &body),
        );
    }
    let mut body = vec![0; 4];
    body.extend_from_slice(&GUID_BYTES);
    wire(UpdateGenerationId::new(GUID_BYTES), &packet(4, 1, &body));
    for status in 0u32..=1 {
        let mut body = status.to_le_bytes().to_vec();
        body.extend_from_slice(&0x44332211u32.to_le_bytes());
        wire(
            ModifyVtl2SettingsCompleteNotification::new(
                ModifyVtl2SettingsStatus(status),
                0x44332211,
            ),
            &packet(1, 6, &body),
        );
        wire(
            StartVtl0CompleteNotification::new(StartVtl0Status(status), 0x44332211),
            &packet(1, 7, &body),
        );
    }
}

// Test: Construct guest-state protection messages with two distinct encrypted buffers, full cleartext bytes and extended status capabilities.
// Expected: The protocol's fixed cleartext length, both encrypted buffer lengths/content and capability bits occupy exact non-overlapping wire positions.
#[test]
fn guest_state_protection_preserves_both_encrypted_blobs() {
    wire(GuestStateProtectionByIdRequest::new(), &[1, 2, 9, 0]);
    let clear = std::array::from_fn(|index| index as u8);
    let encrypted = [
        GspCiphertextContent {
            length: 3,
            buffer: [0xa5; 512],
        },
        GspCiphertextContent {
            length: 5,
            buffer: [0x5a; 512],
        },
    ];
    let flags = GspExtendedStatusFlags::new()
        .with_state_refresh_request(true)
        .with_requires_rpc_server(true);
    let message = GuestStateProtectionRequest::new(clear, encrypted, flags);
    let mut body = 32u32.to_le_bytes().to_vec();
    body.extend_from_slice(&clear);
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&[0xa5; 512]);
    body.extend_from_slice(&5u32.to_le_bytes());
    body.extend_from_slice(&[0x5a; 512]);
    body.extend_from_slice(&17u32.to_le_bytes());
    wire(message, &packet(2, 17, &body));
}

// Test: Serialize PCI control/binding and VGA proxy messages using a GUID with nonuniform fields and nonzero register offsets/values.
// Expected: GUID endianness and category/operation IDs are exact, binding booleans are canonical, packed register fields are ordered correctly, and status values are unchanged.
#[test]
fn pci_binding_and_vga_messages_preserve_identity_and_registers() {
    for code in 0u32..=3 {
        let mut body = code.to_le_bytes().to_vec();
        body.extend_from_slice(&GUID_BYTES);
        wire(
            VpciDeviceControlRequest::new(VpciDeviceControlCode(code), GUID),
            &packet(2, 19, &body),
        );
    }
    for status in 0u32..=4 {
        wire(
            VpciDeviceControlResponse::new(VpciDeviceControlStatus(status)),
            &packet(3, 19, &status.to_le_bytes()),
        );
        let mut body = GUID_BYTES.to_vec();
        body.extend_from_slice(&status.to_le_bytes());
        wire(
            VpciDeviceBindingChangeResponse::new(GUID, VpciDeviceControlStatus(status)),
            &packet(3, 22, &body),
        );
    }
    for binding in [false, true] {
        let mut body = GUID_BYTES.to_vec();
        body.push(u8::from(binding));
        wire(
            VpciDeviceBindingChangeRequest::new(GUID, binding),
            &packet(2, 22, &body),
        );
    }
    wire(
        VgaProxyPciReadRequest::new(0x6655),
        &[1, 2, 23, 0, 0x55, 0x66],
    );
    wire(
        VgaProxyPciReadResponse::new(0x44332211),
        &[1, 3, 23, 0, 0x11, 0x22, 0x33, 0x44],
    );
    wire(
        VgaProxyPciWriteRequest::new(0x6655, 0x44332211),
        &[1, 2, 24, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    );
    wire(VgaProxyPciWriteResponse::new(), &[1, 3, 24, 0]);
}

// Test: Serialize framebuffer, RAM-range and firmware operations, varying statuses and preserving large addresses/offsets and ROM semantics; include battery flags/capacities.
// Expected: Experimental operation IDs remain distinct, all 64-bit values retain their bits, ROM occupies bit 1, reserved fields are zero, and status/address fields do not overlap.
#[test]
fn memory_firmware_and_battery_messages_match_wire_layouts() {
    wire(
        MapFramebufferRequest::new(0x8877665544332211),
        &[
            1, 2, 0xff, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ],
    );
    wire(UnmapFramebufferRequest::new(), &[1, 2, 0xfe, 0xff]);
    for status in 0u32..=1 {
        wire(
            MapFramebufferResponse::new(MapFramebufferStatus(status)),
            &packet(3, 0xffff, &status.to_le_bytes()),
        );
        wire(
            UnmapFramebufferResponse::new(UnmapFramebufferStatus(status)),
            &packet(3, 0xfffe, &status.to_le_bytes()),
        );
    }
    let flags = CreateRamGpaRangeFlags::new().with_rom_mb(true);
    let mut body = 0x44332211u32.to_le_bytes().to_vec();
    for value in [0x8877665544332211u64, 0x102030405, 0x60708090a, 2] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    wire(
        CreateRamGpaRangeRequest::new(
            0x44332211,
            0x8877665544332211,
            0x102030405,
            0x60708090a,
            flags,
        ),
        &packet(2, 28, &body),
    );
    for status in 0u32..=5 {
        wire(
            CreateRamGpaRangeResponse::new(CreateRamGpaRangeStatus(status)),
            &packet(3, 28, &status.to_le_bytes()),
        );
    }
    wire(
        ResetRamGpaRangeRequest::new(0x44332211),
        &[1, 2, 29, 0, 0x11, 0x22, 0x33, 0x44],
    );
    wire(ResetRamGpaRangeResponse::new(), &[1, 3, 29, 0]);
    wire(
        LoadFirmwareRequest::new(0x8877665544332211),
        &[1, 2, 30, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    );
    for status in 0u32..=2 {
        let mut body = status.to_le_bytes().to_vec();
        body.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
        wire(
            LoadFirmwareResponse::new(LoadFirmwareStatus(status), 0x8877665544332211),
            &packet(3, 30, &body),
        );
    }
    let flags = BatteryStatusFlags::new()
        .with_ac_online(true)
        .with_battery_present(true)
        .with_discharging(true);
    let mut body = 11u32.to_le_bytes().to_vec();
    for value in [0x44332211u32, 0x88776655, 0xccbbaa99] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    wire(
        BatteryStatusNotification::new(flags, 0x44332211, 0x88776655, 0xccbbaa99),
        &packet(4, 7, &body),
    );
}
