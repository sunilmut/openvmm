// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Asynchronous OS pipes.

pub use crate::sys::pipe::PolledPipe;

#[cfg(test)]
mod tests {
    use super::PolledPipe;
    use crate::DefaultDriver;
    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;
    use pal_async_test::async_test;
    use test_with_tracing::test;

    // Test: Read a pipe before and after its writer closes with buffered data.
    // Expected: Exact bytes arrive in order and EOF follows the final payload.
    #[async_test]
    async fn pipe(driver: DefaultDriver) {
        let (mut a, mut b) = PolledPipe::pair(&driver).unwrap();
        b.write_all(b"abc").await.unwrap();
        let mut v = vec![0; 3];
        a.read_exact(&mut v).await.unwrap();
        assert_eq!(v.as_slice(), b"abc");
        let mut read = a.read_to_end(&mut v);
        assert!(futures::poll!(&mut read).is_pending());
        b.write_all(b"def").await.unwrap();
        drop(b);
        read.await.unwrap();
        assert_eq!(v.as_slice(), b"abcdef");
    }

    // Test: Relay a large stream through independently owned bidirectional halves.
    // Expected: The whole stream drains and closing writers terminates both reads.
    #[cfg(windows)] // relies on pipes being bidirectional
    #[async_test]
    async fn pipe_relay(driver: DefaultDriver) {
        let (a, b) = PolledPipe::pair(&driver).unwrap();
        let (mut a_r, mut a_w) = a.split();
        let (b_r, mut b_w) = b.split();
        let relay = async move {
            assert_eq!(
                futures::io::copy(b_r.take(0x100000), &mut b_w)
                    .await
                    .unwrap(),
                0x100000
            );
            drop(b_w);
        };
        let feed = async move {
            assert_eq!(
                futures::io::copy(futures::io::repeat(0xcc).take(0x100000), &mut a_w)
                    .await
                    .unwrap(),
                0x100000
            );
            drop(a_w);
        };
        let drain = async {
            let mut received = Vec::new();
            a_r.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), 0x100000);
            assert!(received.iter().all(|&byte| byte == 0xcc));
        };
        futures::future::join3(relay, feed, drain).await;
    }
}
