// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Broadcast new device dirty rectangles to one full and one ready bounded client channel, then drain the slow channel and deliver another update.
// Expected: Backpressure never blocks or replaces queued data, only the slow subscriber receives a missed/full-refresh signal, the ready subscriber receives exact rectangles, and later delivery to the recovered subscriber succeeds.
#[test]
fn bounded_dirty_broadcast_signals_missed_updates_and_recovers_without_blocking() {
    block_with_io(async |driver| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let memory = alloc_shared_memory(FRAMEBUFFER_SIZE, "vnc-broadcast-test").unwrap();
        let (_framebuffer, access) = framebuffer::framebuffer(memory, FRAMEBUFFER_SIZE, 0).unwrap();
        let (input_send, _input_recv) = mesh::channel();
        let (dirty_send, dirty_recv) = mesh::channel();
        let (slow_send, slow_recv) = async_channel::bounded(1);
        let (fast_send, fast_recv) = async_channel::bounded(1);
        let slow_missed = Arc::new(AtomicBool::new(false));
        let fast_missed = Arc::new(AtomicBool::new(false));
        let rect = |left| {
            Arc::new(vec![DirtyRect {
                left,
                top: 0,
                right: left + 16,
                bottom: 16,
            }])
        };
        slow_send.try_send(rect(0)).unwrap();
        let mut server = MultiClientServer {
            listener: PolledSocket::new(&driver, listener).unwrap(),
            view: Arc::new(Mutex::new(ViewWrapper(access.view().unwrap()))),
            input_send,
            dirty_recv: Some(dirty_recv),
            dirty_senders: vec![
                ClientDirtySender {
                    id: 1,
                    sender: slow_send,
                    missed_dirty: slow_missed.clone(),
                },
                ClientDirtySender {
                    id: 2,
                    sender: fast_send,
                    missed_dirty: fast_missed.clone(),
                },
            ],
            clients: unicycle::FuturesUnordered::new(),
            abort_senders: Vec::new(),
            next_client_id: 3,
            max_clients: 2,
            evict_oldest: false,
        };
        dirty_send.send((*rect(16)).clone());
        assert!(server.process(&driver).now_or_never().is_none());
        let original = slow_recv.try_recv().unwrap();
        assert_eq!((original[0].left, original[0].right), (0, 16));
        let delivered = fast_recv.try_recv().unwrap();
        assert_eq!(
            (
                delivered[0].left,
                delivered[0].top,
                delivered[0].right,
                delivered[0].bottom
            ),
            (16, 0, 32, 16)
        );
        assert!(slow_missed.swap(false, Ordering::Relaxed));
        assert!(!fast_missed.load(Ordering::Relaxed));
        dirty_send.send((*rect(32)).clone());
        assert!(server.process(&driver).now_or_never().is_none());
        for receiver in [&slow_recv, &fast_recv] {
            let delivered = receiver.try_recv().unwrap();
            assert_eq!((delivered[0].left, delivered[0].right), (32, 48));
            assert!(receiver.try_recv().is_err());
        }
        assert!(!slow_missed.load(Ordering::Relaxed));
        assert!(!fast_missed.load(Ordering::Relaxed));
    });
}
