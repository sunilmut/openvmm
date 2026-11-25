// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::collections::HashMap;
use std::time::Duration;
use test_with_tracing::test;

// Test: Translate portable I/O failures into Linux errors returned to filesystem clients.
// Expected: Supported error kinds keep their Linux meaning; unclassified failures become EINVAL.
#[test]
fn io_errors_keep_filesystem_and_network_failure_semantics() {
    for (kind, expected) in [
        (io::ErrorKind::NotFound, Error::ENOENT),
        (io::ErrorKind::PermissionDenied, Error::EACCES),
        (io::ErrorKind::ConnectionRefused, Error::ECONNREFUSED),
        (io::ErrorKind::ConnectionReset, Error::ECONNRESET),
        (io::ErrorKind::ConnectionAborted, Error::ECONNABORTED),
        (io::ErrorKind::NotConnected, Error::ENOTCONN),
        (io::ErrorKind::AddrInUse, Error::EADDRINUSE),
        (io::ErrorKind::AddrNotAvailable, Error::EADDRNOTAVAIL),
        (io::ErrorKind::BrokenPipe, Error::EPIPE),
        (io::ErrorKind::AlreadyExists, Error::EEXIST),
        (io::ErrorKind::WouldBlock, Error::EAGAIN),
        (io::ErrorKind::TimedOut, Error::ETIMEDOUT),
        (io::ErrorKind::Interrupted, Error::EINTR),
        (io::ErrorKind::InvalidData, Error::EINVAL),
    ] {
        assert_eq!(
            Error::from(io::Error::new(kind, "test failure")),
            expected,
            "{kind:?}"
        );
    }
}

// Test: Report known and unknown Linux error values through the public formatting API.
// Expected: Known names are recognizable and unknown numeric values remain available to callers.
#[test]
fn error_reports_preserve_unknown_codes_and_named_diagnostics() {
    let known = Error::from_lx(2);
    assert_eq!(known.value(), 2);
    assert_eq!(known.to_string(), "ENOENT (2)");
    assert_eq!(format!("{known:?}"), "Error(ENOENT (2))");
    let unknown = Error::from_lx(-1234);
    assert_eq!(unknown.value(), -1234);
    assert_eq!(unknown.to_string(), "Unknown error (-1234)");
    assert_eq!(format!("{unknown:?}"), "Error(Unknown error (-1234))");
}

// Test: Capture errno immediately after a harmless filesystem operation with an empty pathname.
// Expected: The public last-error constructor reports the actual Linux ENOENT failure.
#[test]
#[cfg(target_os = "linux")]
fn last_os_error_matches_the_failed_filesystem_operation() {
    let original = std::fs::metadata("").unwrap_err();
    let captured = Error::last_os_error();
    assert_eq!(original.raw_os_error(), Some(ENOENT));
    assert_eq!(captured, Error::ENOENT);
}

// Test: Classify each Linux file type with permission bits set and reject unknown file types.
// Expected: Exactly the correct predicate matches; permission bits never change the file type.
#[test]
fn mode_classification_is_exclusive_and_ignores_permissions() {
    let predicates: [fn(mode_t) -> bool; 7] = [
        s_isreg, s_isdir, s_ischr, s_isblk, s_isfifo, s_issock, s_islnk,
    ];
    for (expected, mode) in [
        0o100000, 0o040000, 0o020000, 0o060000, 0o010000, 0o140000, 0o120000,
    ]
    .into_iter()
    .enumerate()
    {
        for permissions in [0, 0o7777] {
            for (index, predicate) in predicates.iter().enumerate() {
                assert_eq!(predicate(mode | permissions), index == expected);
            }
        }
    }
    for mode in [0, 0o030000, 0o150000, 0o170000] {
        assert!(predicates.iter().all(|predicate| !predicate(mode | 0o7777)));
    }
}

// Test: Encode device IDs that cross the low-major and low-minor field boundaries.
// Expected: Linux ABI golden vectors match, and both device numbers decode without lost high bits.
#[test]
#[cfg(target_pointer_width = "64")]
fn device_number_encoding_matches_linux_vectors_and_round_trips() {
    for (major, minor_value, expected) in [
        (0, 0, 0),
        (1, 2, 0x102),
        (0x1234, 0x5678, 0x0000_1000_0562_3478),
        (u32::MAX, u32::MAX, u64::MAX),
    ] {
        let encoded = make_dev(major, minor_value);
        assert_eq!(encoded as u64, expected);
        assert_eq!(major64(encoded), major);
        assert_eq!(minor(encoded), minor_value);
        assert_eq!(major32(encoded), major & 0xfff);
    }
    assert_eq!(make_major32(0x1234), 0x23400);
    assert_eq!(make_major64(0x1000), 0x1000_0000_0000);
    assert_eq!(make_minor(0x100), 0x10_0000);
}

// Test: Convert precise durations and utimens sentinel values between timestamp representations.
// Expected: Subsecond precision and NOW/OMIT intent survive conversion, with reserved bits cleared.
#[test]
fn timestamp_conversion_preserves_duration_and_utime_intent() {
    let duration = Duration::new(1_234_567, 999_999_999);
    let time = Timespec::from(&duration);
    assert_eq!(
        time,
        Timespec {
            seconds: 1_234_567,
            nanoseconds: 999_999_999
        }
    );
    let timestamp = StatExTimestamp::from(time);
    assert_eq!(
        timestamp,
        StatExTimestamp {
            seconds: 1_234_567,
            nanoseconds: 999_999_999,
            _rsvd: 0,
        }
    );
    assert_eq!(Timespec::from(timestamp), Timespec::from(&duration));
    for (time, expected) in [
        (Timespec::now(), 0x3fff_ffff),
        (Timespec::omit(), 0x3fff_fffe),
    ] {
        let timestamp = StatExTimestamp::from(time);
        assert_eq!(timestamp.seconds, 0);
        assert_eq!(timestamp.nanoseconds, expected);
        assert_eq!(timestamp._rsvd, 0);
        let restored = Timespec::from(timestamp);
        assert_eq!(restored.nanoseconds, expected as usize);
    }
}

// Test: Convert a populated statx result into the platform's Linux stat representation.
// Expected: Device numbers, ownership, size, mode and all three supported timestamps are retained.
#[test]
fn stat_conversion_preserves_filesystem_metadata() {
    let stat = Stat::from(StatEx {
        block_size: 4096,
        link_count: 7,
        uid: 1001,
        gid: 1002,
        mode: 0o100754,
        inode_id: 0x1234_5678_9abc_def0,
        file_size: 0x2_0000_0001,
        block_count: 0x1_0000_0001,
        access_time: StatExTimestamp {
            seconds: 11,
            nanoseconds: 12,
            _rsvd: 0,
        },
        write_time: StatExTimestamp {
            seconds: 21,
            nanoseconds: 22,
            _rsvd: 0,
        },
        change_time: StatExTimestamp {
            seconds: 31,
            nanoseconds: 32,
            _rsvd: 0,
        },
        dev_major: 0x1234,
        dev_minor: 0x5678,
        rdev_major: 1,
        rdev_minor: 2,
        ..Default::default()
    });
    assert_eq!(stat.device_nr, 0x0000_1000_0562_3478);
    assert_eq!(stat.device_nr_special, 0x102);
    assert_eq!(stat.inode_nr, 0x1234_5678_9abc_def0);
    assert_eq!(stat.link_count, 7);
    assert_eq!((stat.uid, stat.gid, stat.mode), (1001, 1002, 0o100754));
    assert_eq!(
        (stat.file_size, stat.block_count),
        (0x2_0000_0001, 0x1_0000_0001)
    );
    assert_eq!(stat.block_size, 4096);
    assert_eq!(
        stat.access_time,
        Timespec {
            seconds: 11,
            nanoseconds: 12
        }
    );
    assert_eq!(
        stat.write_time,
        Timespec {
            seconds: 21,
            nanoseconds: 22
        }
    );
    assert_eq!(
        stat.change_time,
        Timespec {
            seconds: 31,
            nanoseconds: 32
        }
    );
}

// Test: Grow and reuse a byte-preserving filename, then look up distinct invalid-UTF8 names.
// Expected: Reallocation never changes bytes and borrowed hash lookups distinguish raw filenames.
#[test]
fn filename_storage_and_borrowed_lookup_preserve_non_unicode_bytes() {
    let mut name = LxString::with_capacity(1);
    name.reserve(8);
    name.push("dir/");
    name.reserve_exact(4);
    name.push(LxStr::from_bytes(b"bad\xff"));
    name.shrink_to_fit();
    assert_eq!(name.as_bytes(), b"dir/bad\xff");
    let mut files = HashMap::new();
    files.insert(name.clone(), 1);
    files.insert(LxStr::from_bytes(b"dir/bad\xfe").to_owned(), 2);
    assert_eq!(files.get(LxStr::from_bytes(b"dir/bad\xff")), Some(&1));
    assert_eq!(files.get(LxStr::from_bytes(b"dir/bad\xfe")), Some(&2));
    name.clear();
    name.push(String::from("new"));
    name.push(LxString::from("/file"));
    assert_eq!(name.as_bytes(), b"new/file");
    assert_eq!(files.get(LxStr::from_bytes(b"dir/bad\xff")), Some(&1));
}

// Test: Collect a Unicode filename and compare its owned and borrowed text forms in both directions.
// Expected: UTF8 bytes, ownership conversions and symmetric string comparisons agree.
#[test]
fn unicode_collection_and_text_comparisons_agree_across_owned_and_borrowed_forms() {
    let name: LxString = ['a', '\u{e9}', '\u{1f642}'].into_iter().collect();
    let expected = "a\u{e9}\u{1f642}";
    assert_eq!(name.as_bytes(), expected.as_bytes());
    assert!(expected == name);
    assert!(*expected == name);
    assert!(name == *expected);
    assert!(expected == name.as_lx_str());
    assert!(*expected == *name.as_lx_str());
    let borrowed: &LxStr = name.as_ref();
    assert_eq!(LxString::from(borrowed).into_vec(), expected.as_bytes());
}

// Test: Convert filesystem timestamps before 1970 and after the signed 2038 limit.
// Expected: The 64-bit stat ABI retains signed seconds and nanosecond precision;
//       conversion back to statx neither clamps negative dates nor narrows seconds.
#[test]
#[cfg(target_pointer_width = "64")]
fn stat_timestamps_preserve_pre_epoch_and_post_2038_values() {
    for (seconds, nanoseconds) in [
        (-1i64, 999_999_999),
        (-2_208_988_800, 0),
        (2_147_483_648, 1),
        (4_102_444_800, 123_456_789),
    ] {
        let expected = StatExTimestamp {
            seconds,
            nanoseconds,
            _rsvd: 0,
        };
        let stat = Stat::from(StatEx {
            access_time: StatExTimestamp {
                seconds,
                nanoseconds,
                _rsvd: 0,
            },
            ..Default::default()
        });
        assert_eq!(
            stat.access_time.seconds.to_ne_bytes(),
            seconds.to_ne_bytes()
        );
        assert_eq!(stat.access_time.nanoseconds as u64, u64::from(nanoseconds));
        assert_eq!(StatExTimestamp::from(stat.access_time), expected);
    }
}
