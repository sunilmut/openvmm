// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::offer::Offer;
use test_with_tracing::test;

// Test: Reject and drop pending opens, accept a retry, exchange interrupts, and close.
// Expected: Open responses reflect acceptance and the accepted endpoint sees closure.
#[test]
fn offer_acceptance_interrupts_and_close_follow_the_guest_protocol() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::OsEvent);
        let mut offer = Offer::new(driver.clone(), &bus, OfferParams::default())
            .await
            .unwrap();
        let child = offers.recv().await.unwrap();
        assert!(
            !child
                .request_send
                .call(
                    ChannelRequest::Gpadl,
                    GpadlRequest {
                        id: GpadlId(8),
                        count: 1,
                        buf: vec![]
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            child
                .request_send
                .call(ChannelRequest::Gpadl, ring_gpadl())
                .await
                .unwrap()
        );
        for reject in [true, false] {
            let open = child
                .request_send
                .call(ChannelRequest::Open, open_request());
            let mut open = std::pin::pin!(open);
            assert!(open.as_mut().now_or_never().is_none());
            let opening = offer.wait_for_open(&driver).await.unwrap();
            if reject {
                opening.reject();
            } else {
                drop(opening);
            }
            assert!(!open.await.unwrap());
        }
        let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = delivered.clone();
        let mut request = open_request();
        request.interrupt = Interrupt::from_fn(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        let open = child.request_send.call(ChannelRequest::Open, request);
        let mut open = std::pin::pin!(open);
        assert!(open.as_mut().now_or_never().is_none());
        let channel = offer.wait_for_open(&driver).await.unwrap().accept();
        assert!(open.await.unwrap());
        channel.channel.signal.signal_remote();
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
        assert!(
            poll_fn(|cx| channel.channel.signal.poll_for_signal(cx))
                .now_or_never()
                .is_none()
        );
        child.event.deliver();
        assert!(
            poll_fn(|cx| channel.channel.signal.poll_for_signal(cx))
                .await
                .is_ok()
        );
        assert_eq!(
            child
                .request_send
                .call(
                    ChannelRequest::Modify,
                    ModifyRequest::TargetVp { target_vp: 9 }
                )
                .await
                .unwrap(),
            0
        );
        let _closed = child.request_send.call(ChannelRequest::Close, ()).await;
        assert!(
            poll_fn(|cx| channel.channel.signal.poll_for_signal(cx))
                .await
                .is_err()
        );
        drop(channel);
        child
            .request_send
            .call(ChannelRequest::TeardownGpadl, GpadlId(7))
            .await
            .unwrap();
        drop(child);
        offer.revoke().await;
    }));
}

// Test: Open without a valid ring GPADL, then revoke the bus-side offer.
// Expected: Ring validation rejects the open, and the next wait reports revocation.
#[test]
fn invalid_open_is_rejected_and_revocation_ends_the_accept_loop() {
    let mut pool = pal_async::DefaultPool::new();
    let driver = pool.driver();
    pool.run_until(with_timeout(&driver, async {
        let (bus, mut offers) = TestBus::new(Notification::OsEvent);
        let mut offer = Offer::new(driver.clone(), &bus, OfferParams::default())
            .await
            .unwrap();
        let child = offers.recv().await.unwrap();
        let open = child
            .request_send
            .call(ChannelRequest::Open, open_request());
        let mut open = std::pin::pin!(open);
        assert!(open.as_mut().now_or_never().is_none());
        assert!(matches!(
            offer.wait_for_open(&driver).await,
            Err(crate::offer::Error::GpadlRing(_))
        ));
        assert!(!open.await.unwrap());
        drop(child);
        assert!(matches!(
            offer.wait_for_open(&driver).await,
            Err(crate::offer::Error::Revoked)
        ));
        offer.revoke().await;
    }));
}
