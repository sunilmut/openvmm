// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public log-buffer persistence and whole-message capacity behavior.

use string_page_buf::StringBuffer;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Drop a three-byte UTF-8 message with two bytes free, reopen the log,
//       then exactly fill it with a two-byte character and append empty input.
// Expected: Rejected text never partially commits; remaining space, valid
//       contents and drop accounting persist across independent reopenings.
#[test]
fn rejected_utf8_preserves_reopenable_remaining_space() {
    let mut storage = [0u16; 2048];
    let prefix = "x".repeat(4088);
    {
        let mut log = StringBuffer::new(storage.as_mut_bytes()).unwrap();
        assert!(log.append(&prefix).unwrap());
        assert!(!log.append("界").unwrap());
        assert_eq!(log.contents(), prefix);
        assert_eq!(log.dropped_messages(), 1);
    }
    let expected = format!("{prefix}é");
    {
        let mut log = StringBuffer::from_existing(storage.as_mut_bytes()).unwrap();
        assert!(log.append("é").unwrap());
        assert!(log.append("").unwrap());
        assert_eq!(log.dropped_messages(), 1);
        assert_eq!(log.contents(), expected);
        assert!(!log.append("!").unwrap());
    }
    let log = StringBuffer::from_existing(storage.as_mut_bytes()).unwrap();
    assert_eq!(log.contents(), expected);
    assert_eq!(log.dropped_messages(), 2);
}

// Test: Keep writing to a persisted full boot log beyond the drop counter's
//       representable range, then reopen it.
// Expected: Loss accounting saturates instead of wrapping or panicking, and
//       neither excess messages nor an empty append corrupt the saved text.
#[test]
fn sustained_log_loss_saturates_across_reopen() {
    let mut storage = [0u16; 2048];
    let expected = "x".repeat(4090);
    {
        let mut log = StringBuffer::new(storage.as_mut_bytes()).unwrap();
        assert!(log.append(&expected).unwrap());
        for _ in 0..=u16::MAX {
            assert!(!log.append("lost").unwrap());
        }
        assert_eq!(log.dropped_messages(), u16::MAX);
        assert_eq!(log.contents(), expected);
    }
    let mut log = StringBuffer::from_existing(storage.as_mut_bytes()).unwrap();
    assert!(log.append("").unwrap());
    assert!(!log.append("still full").unwrap());
    assert_eq!(log.contents(), expected);
    assert_eq!(log.dropped_messages(), u16::MAX);
}
