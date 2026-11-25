// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Serialize power/reset/event/IPMI notifications and version/time/boot request-response messages with nonzero values and both boolean states.
// Expected: IDs, categories, canonical booleans, multibyte values and reserved zero bytes match independent wire fixtures; every fixed-message truncation is rejected.
#[test]
fn boot_time_and_power_messages_match_wire_layouts() {
    for flag in [false, true] {
        wire(
            PowerOffNotification::new(flag),
            &packet(1, 1, &[u8::from(flag), 0]),
        );
        wire(
            VersionResponse::new(flag),
            &packet(3, 1, &[u8::from(flag), 0]),
        );
        assert_eq!(ProtocolBool::from(flag).as_bytes(), [u8::from(flag)]);
        let response = TimeResponse::new(0x8877665544332211, -123456789, -480, flag);
        let mut body = vec![0; 4];
        body.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
        body.extend_from_slice(&(-123456789i64).to_le_bytes());
        body.extend_from_slice(&(-480i16).to_le_bytes());
        body.push(u8::from(flag));
        body.extend_from_slice(&[0; 5]);
        wire(response, &packet(3, 2, &body));
    }
    wire(ResetNotification::new(), &[1, 1, 2, 0]);
    wire(BiosBootFinalizeResponse::new(), &[1, 3, 3, 0]);
    wire(TimeRequest::new(), &[1, 2, 2, 0]);
    wire(
        EventLogNotification::new(EventLogId(0x44332211)),
        &[1, 1, 3, 0, 0x11, 0x22, 0x33, 0x44],
    );
    wire(
        VersionRequest::new(ProtocolVersion::NICKEL_REV2),
        &[1, 2, 1, 0, 2, 0, 4, 0],
    );
    let record = std::array::from_fn(|index| index as u8 + 1);
    let mut body = vec![0x34, 0x12];
    body.extend_from_slice(&record);
    wire(
        IpmiSelNotification::new(0x1234, record),
        &packet(1, 13, &body),
    );
    for raw in 0..=5 {
        assert_eq!(u8::from(LogLevel(raw)), raw as u8);
    }
}

// Test: Serialize VTL crash/triple-fault and maximum-array attestation requests with distinctive registers, pages and binary data.
// Expected: Field offsets, lengths, reserved bytes and all array elements survive exactly, without mixing agent/report buffers or crash control/parameters.
#[test]
fn crash_and_attestation_messages_preserve_binary_fields() {
    let parameters = [1u64, 0x102, 0x30405, 0x6070809, 0xa0b0c0d0e];
    let mut body = vec![0x11, 0x22, 0x33, 0x44, 2, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
    for value in parameters {
        body.extend_from_slice(&value.to_le_bytes());
    }
    wire(
        VtlCrashNotification::new(0x44332211, 2, 0x8877665544332211, parameters),
        &packet(1, 8, &body),
    );
    wire(
        TripleFaultNotification::new(0x44332211, TripleFaultType::UNRECOVERABLE_EXCEPTION, 5),
        &[1, 1, 9, 0, 0x11, 0x22, 0x33, 0x44, 1, 0, 0, 0, 5, 0, 0, 0],
    );
    let pages = std::array::from_fn(|index| 0x12345000u64 + index as u64 * 4096);
    let agent = std::array::from_fn(|index| index.wrapping_mul(17) as u8);
    let report = std::array::from_fn(|index| index.wrapping_mul(31) as u8);
    let request = IgvmAttestRequest::new(pages, 16, agent, 2048, report, 4096);
    let mut body = 16u32.to_le_bytes().to_vec();
    for page in pages {
        body.extend_from_slice(&page.to_le_bytes());
    }
    body.extend_from_slice(&2048u32.to_le_bytes());
    body.extend_from_slice(&4096u32.to_le_bytes());
    body.extend_from_slice(&agent);
    body.extend_from_slice(&report);
    wire(request, &packet(2, 8, &body));
}

// Test: Serialize VMGS geometry/read/write/flush messages with nonzero flags, 64-bit sector offsets and every defined I/O status.
// Expected: Each operation has its own request/response ID, exact sector/count/geometry values and zero padding, while status codes round-trip unchanged.
#[test]
fn vmgs_messages_preserve_geometry_ranges_flags_and_status() {
    wire(VmgsGetDeviceInfoRequest::new(), &[1, 2, 4, 0]);
    wire(VmgsFlushRequest::new(), &[1, 2, 7, 0]);
    let mut body = vec![1, 0, 0, 0];
    body.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
    body.extend_from_slice(&0x44332211u32.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    wire(
        VmgsWriteRequest::new(
            VmgsWriteFlags::WRITE_THROUGH,
            0x8877665544332211,
            0x44332211,
        ),
        &packet(2, 6, &body),
    );
    body[..4].copy_from_slice(&[0; 4]);
    wire(
        VmgsReadRequest::new(VmgsReadFlags::NONE, 0x8877665544332211, 0x44332211),
        &packet(2, 5, &body),
    );
    for status in 0u32..=3 {
        wire(
            VmgsWriteResponse::new(VmgsIoStatus(status)),
            &packet(3, 6, &status.to_le_bytes()),
        );
        wire(
            VmgsReadResponse::new(VmgsIoStatus(status)),
            &packet(3, 5, &status.to_le_bytes()),
        );
        wire(
            VmgsFlushResponse::new(VmgsIoStatus(status)),
            &packet(3, 7, &status.to_le_bytes()),
        );
        let mut body = status.to_le_bytes().to_vec();
        body.extend_from_slice(&0x8877665544332211u64.to_le_bytes());
        body.extend_from_slice(&512u16.to_le_bytes());
        body.extend_from_slice(&4096u16.to_le_bytes());
        body.extend_from_slice(&8192u32.to_le_bytes());
        wire(
            VmgsGetDeviceInfoResponse::new(
                VmgsIoStatus(status),
                0x8877665544332211,
                512,
                4096,
                8192,
            ),
            &packet(3, 4, &body),
        );
    }
}
