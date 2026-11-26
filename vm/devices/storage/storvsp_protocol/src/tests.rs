// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::ChannelProperties;
use super::NotificationPacket;
use super::NtStatus;
use super::Operation;
use super::Packet;
use super::ProtocolVersion;
use super::ScsiRequest;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// Test: Decode known and unknown packet operations and encode supported versions.
// Expected: Full-width flags/status survive; the version byte order matches the
//       independent wire vectors used during negotiation.
#[test]
fn packet_and_version_wire_contract() {
    let wire = [3, 0, 0, 0, 0x78, 0x56, 0x34, 0x92, 0x59, 0, 0, 0xc0];
    let mut packet = Packet::read_from_bytes(&wire).unwrap();
    assert_eq!(packet.operation, Operation::EXECUTE_SRB);
    assert_eq!(packet.flags, 0x9234_5678);
    assert_eq!(packet.status, NtStatus::REVISION_MISMATCH);
    assert_eq!(packet.as_bytes(), &wire);
    packet.operation = Operation(0xfedc_ba98);
    packet.status = NtStatus(0x8765_4321);
    assert_eq!(packet.as_bytes()[..4], [0x98, 0xba, 0xdc, 0xfe]);
    assert_eq!(packet.as_bytes()[8..], [0x21, 0x43, 0x65, 0x87]);
    for (major_minor, expected) in [
        (super::VERSION_WIN6, [0, 2, 0, 0]),
        (super::VERSION_WIN7, [2, 4, 0, 0]),
        (super::VERSION_WIN8, [1, 5, 0, 0]),
        (super::VERSION_BLUE, [0, 6, 0, 0]),
        (super::VERSION_THRESHOLD, [2, 6, 0, 0]),
    ] {
        let version = ProtocolVersion {
            major_minor,
            reserved: 0,
        };
        assert_eq!(version.as_bytes(), &expected);
    }
}

// Test: Decode legacy and extended SRBs with distinct address, payload and tail.
// Expected: The 36-byte prefix stays compatible, full transfer lengths survive,
//       and Win8 queue/timeout fields do not overlap CDB or sense data.
#[test]
fn scsi_request_legacy_prefix_and_extended_tail() {
    for length in [36u16, 52] {
        let mut wire = [0u8; 52];
        wire[..2].copy_from_slice(&length.to_le_bytes());
        wire[2..12].copy_from_slice(&[0x82, 2, 0, 1, 3, 7, 16, 20, 1, 0xa5]);
        wire[12..16].copy_from_slice(&0xfedc_ba98u32.to_le_bytes());
        wire[16..36].copy_from_slice(&core::array::from_fn::<_, 20, _>(|i| i as u8));
        if length == 52 {
            wire[36..52].copy_from_slice(&[
                0x34, 0x12, 0x56, 0x78, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xcc, 0xbb,
                0xaa, 0x99,
            ]);
        }
        let request = ScsiRequest::read_from_bytes(&wire).unwrap();
        assert_eq!(request.length, length);
        assert_eq!(u8::from(request.srb_status), 0x82);
        assert_eq!(request.scsi_status.0, 2);
        assert_eq!((request.path_id, request.target_id, request.lun), (1, 3, 7));
        assert_eq!(request.cdb_length, 16);
        assert_eq!(request.sense_info_ex_length, 20);
        assert_eq!(request.data_in, 1);
        assert_eq!(request.properties, 0xa5);
        assert_eq!(request.data_transfer_length, 0xfedc_ba98);
        assert_eq!(
            request.payload,
            core::array::from_fn::<_, 20, _>(|i| i as u8)
        );
        if length == 52 {
            assert_eq!(request.reserve, 0x1234);
            assert_eq!((request.queue_tag, request.queue_action), (0x56, 0x78));
            assert_eq!(request.srb_flags, 0x1122_3344);
            assert_eq!(request.time_out_value, 0x5566_7788);
            assert_eq!(request.queue_sort_key, 0x99aa_bbcc);
        } else {
            assert_eq!(&request.as_bytes()[36..], &[0; 16]);
        }
        assert_eq!(request.as_bytes(), &wire);
    }
}

// Test: Decode channel limits and an asynchronous device-change address.
// Expected: Subchannel count and transfer maximum retain their full widths;
//       notification LUN, target and path use the independent wire order.
#[test]
fn channel_limits_and_notification_address() {
    let wire = [
        0, 0, 0, 0, 0xfe, 0xdc, 0, 0, 1, 0, 0, 0, 0x98, 0xba, 0xdc, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let properties = ChannelProperties::read_from_bytes(&wire).unwrap();
    assert_eq!(properties.maximum_sub_channel_count, 0xdcfe);
    assert_eq!(properties.flags, 1);
    assert_eq!(properties.max_transfer_bytes, 0xfedc_ba98);
    assert_eq!(properties.as_bytes(), &wire);
    let notification = NotificationPacket::read_from_bytes(&[7, 3, 1, 0xa5]).unwrap();
    assert_eq!(
        (notification.path, notification.target, notification.lun),
        (1, 3, 7)
    );
    assert_eq!(notification.flags, 0xa5);
    assert_eq!(notification.as_bytes(), &[7, 3, 1, 0xa5]);
}
