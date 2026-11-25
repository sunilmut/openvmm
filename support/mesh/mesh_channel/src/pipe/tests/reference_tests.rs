// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::pipe;
use futures::io::AsyncRead;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use test_with_tracing::test;

#[derive(Default)]
struct ReadWake(AtomicBool);

impl Wake for ReadWake {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// Test: Drop the writer after an empty pipe has registered a pending reader.
// Expected: Closure wakes the reader, which reports stable EOF without changing its buffer.
#[test]
fn writer_drop_wakes_pending_reader_for_eof() {
    let (mut reader, writer) = pipe();
    let notified = Arc::new(ReadWake::default());
    let waker = Waker::from(notified.clone());
    let mut context = Context::from_waker(&waker);
    let mut buffer = [0xa5; 4];
    assert!(
        Pin::new(&mut reader)
            .poll_read(&mut context, &mut buffer)
            .is_pending()
    );
    assert!(!notified.0.load(Ordering::SeqCst));
    drop(writer);
    assert!(notified.0.load(Ordering::SeqCst));
    for _ in 0..2 {
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut context, &mut buffer),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(buffer, [0xa5; 4]);
    }
}

// Test: Replace a pending reader's waker before writing distinct chunks and closing.
// Expected: The latest reader is notified, queued bytes retain order, and EOF follows them.
#[test]
fn pending_reader_replaces_waker_and_drains_before_eof() {
    let (mut reader, writer) = pipe();
    let previous = Arc::new(ReadWake::default());
    let current = Arc::new(ReadWake::default());
    let previous_waker = Waker::from(previous.clone());
    let current_waker = Waker::from(current.clone());
    let mut buffer = [0xa5; 6];
    assert!(
        Pin::new(&mut reader)
            .poll_read(&mut Context::from_waker(&previous_waker), &mut buffer)
            .is_pending()
    );
    let mut context = Context::from_waker(&current_waker);
    assert!(
        Pin::new(&mut reader)
            .poll_read(&mut context, &mut buffer)
            .is_pending()
    );
    assert_eq!(writer.write_nonblocking(b"ab").unwrap(), 2);
    assert!(!previous.0.load(Ordering::SeqCst));
    assert!(current.0.load(Ordering::SeqCst));
    assert_eq!(writer.write_nonblocking(b"cde").unwrap(), 3);
    drop(writer);
    assert!(matches!(
        Pin::new(&mut reader).poll_read(&mut context, &mut buffer[..3]),
        Poll::Ready(Ok(3))
    ));
    assert_eq!(&buffer[..3], b"abc");
    assert!(matches!(
        Pin::new(&mut reader).poll_read(&mut context, &mut buffer[3..]),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(&buffer, b"abcde\xa5");
    assert!(matches!(
        Pin::new(&mut reader).poll_read(&mut context, &mut buffer),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(&buffer, b"abcde\xa5");
}
