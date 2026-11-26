// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromBytes;

fn assert_parts(buffer: &[u8], expected: [&[u8]; 4]) -> TraceLoggingNotificationHeader {
    let (header, payload) = TraceLoggingNotificationHeader::read_from_prefix(buffer).unwrap();
    assert_eq!(payload, expected.concat());
    let mut offset = 0;
    for (description, part) in [
        &header.name,
        &header.target,
        &header.fields,
        &header.message,
    ]
    .into_iter()
    .zip(expected)
    {
        assert_eq!(usize::from(description.offset), offset);
        assert_eq!(usize::from(description.size), part.len());
        offset += part.len();
    }
    assert_eq!(header.mbz0, 0);
    header
}

// Test: Emit an empty event with optional byte fields absent or explicitly empty.
// Expected: Both forms produce a header-only record with zero-length regions,
//       no invented identifiers, and the requested severity and timestamp.
#[test]
fn absent_and_empty_fields_emit_a_header_only_record() {
    for empty in [None, Some(&[][..])] {
        let buffer = build_tracelogging_notification_buffer(
            LogType::EVENT,
            LogLevel::INFORMATION,
            LogFlags::new(),
            None,
            None,
            None,
            empty,
            empty,
            empty,
            &[],
            0,
        );
        let header = assert_parts(&buffer, [&[], &[], &[], &[]]);
        assert_eq!(header.log_type, LogType::EVENT);
        assert_eq!(header.level, 4);
        assert!(!header.flags.kmsg());
        assert_eq!(header.flags.mbz0(), 0);
        assert_eq!(header.activity_id, Guid::ZERO);
        assert_eq!(header.related_activity_id, Guid::ZERO);
        assert_eq!(header.correlation_id, Guid::ZERO);
        assert_eq!(header.timestamp, 0);
    }
}

// Test: Emit events and span transitions with distinct activity identifiers,
//       severity, flags, a full-width timestamp and embedded binary bytes.
// Expected: Metadata remains independent and the four byte regions follow
//       their declared order without terminators, padding or text conversion.
#[test]
fn metadata_and_binary_regions_survive_wire_construction() {
    let activity: Guid = "01234567-89ab-cdef-0123-456789abcdef".parse().unwrap();
    let related: Guid = "fedcba98-7654-3210-fedc-ba9876543210".parse().unwrap();
    let correlation: Guid = "11112222-3333-4444-5555-666677778888".parse().unwrap();
    let parts: [&[u8]; 4] = [b"n\0\xff", b"t\n\x80", b"{\"x\":1}\0", b"\xff\0\r\n"];
    for (log_type, level, expected_level, ids) in [
        (
            LogType::EVENT,
            LogLevel::ERROR,
            2,
            [Some(activity), None, None],
        ),
        (
            LogType::SPAN_ENTER,
            LogLevel::VERBOSE,
            5,
            [None, Some(related), None],
        ),
        (
            LogType::SPAN_EXIT,
            LogLevel::WARNING,
            3,
            [None, None, Some(correlation)],
        ),
        (
            LogType::EVENT,
            LogLevel::INFORMATION,
            4,
            [Some(activity), Some(related), Some(correlation)],
        ),
    ] {
        let buffer = build_tracelogging_notification_buffer(
            log_type,
            level,
            LogFlags::new().with_kmsg(true),
            ids[0],
            ids[1],
            ids[2],
            Some(parts[0]),
            Some(parts[1]),
            Some(parts[2]),
            parts[3],
            u64::MAX - 17,
        );
        let header = assert_parts(&buffer, parts);
        assert_eq!(header.log_type, log_type);
        assert_eq!(header.level, expected_level);
        assert!(header.flags.kmsg());
        assert_eq!(header.flags.mbz0(), 0);
        assert_eq!(header.activity_id, ids[0].unwrap_or(Guid::ZERO));
        assert_eq!(header.related_activity_id, ids[1].unwrap_or(Guid::ZERO));
        assert_eq!(header.correlation_id, ids[2].unwrap_or(Guid::ZERO));
        assert_eq!(header.timestamp, u64::MAX - 17);
    }
}

// Test: Supply every byte region just below, at, and above its protocol limit.
// Expected: Each region retains exactly its permitted prefix, and truncating
//       an earlier region never shifts later offsets by discarded input bytes.
#[test]
fn each_region_limit_is_enforced_without_offset_drift() {
    let limits = [
        TRACE_LOGGING_NAME_MAX_SIZE,
        TRACE_LOGGING_TARGET_MAX_SIZE,
        TRACE_LOGGING_FIELDS_MAX_SIZE,
        TRACE_LOGGING_MESSAGE_MAX_SIZE,
    ];
    for lengths in [
        limits.map(|limit| limit - 1),
        limits,
        limits.map(|limit| limit + 1),
    ] {
        let tags = [0x11, 0x22, 0x33, 0x44];
        let inputs: [Vec<u8>; 4] = std::array::from_fn(|i| {
            [tags[i], 0, 0xff]
                .into_iter()
                .cycle()
                .take(lengths[i])
                .collect()
        });
        let buffer = build_tracelogging_notification_buffer(
            LogType::EVENT,
            LogLevel::VERBOSE,
            LogFlags::new(),
            None,
            None,
            None,
            Some(&inputs[0]),
            Some(&inputs[1]),
            Some(&inputs[2]),
            &inputs[3],
            1,
        );
        assert_parts(
            &buffer,
            std::array::from_fn(|i| &inputs[i][..lengths[i].min(limits[i])]),
        );
    }
}
