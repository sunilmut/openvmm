// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::cell::Cell;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use test_with_tracing::test;

// Test: Suspend an asynchronous constructor after it maps a dynamic region, then complete it and construct another device through the fallible async entry point.
// Expected: No partially constructed device can be dispatched; completion installs both static and dynamic working routes, and both async builder variants retain usable typed handles.
#[test]
fn async_construction_publishes_only_after_completion() {
    let chipset = TestChipset::default();
    let ready = Cell::new(false);
    let mut construction = std::pin::pin!(chipset.device_builder("async-device").add_async(
        async |services| {
            let mut region = services.register_mmio().new_io_region("async-dynamic", 4);
            region.map(100);
            std::future::poll_fn(|_| {
                if ready.get() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            Device::new(Some(region), true)
        }
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(construction.as_mut().poll(&mut cx).is_pending());
    assert_eq!(chipset.mmio_read(100, &mut [0; 4]), None);
    assert_eq!(chipset.mmio_read(10, &mut [0; 4]), None);
    ready.set(true);
    let device = match construction.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result.unwrap(),
        Poll::Pending => panic!("constructor did not complete"),
    };
    for address in [10, 100] {
        let mut data = [0; 4];
        assert_eq!(chipset.mmio_read(address, &mut data), Some(()));
        assert_eq!(data, [1, 2, 3, 4]);
    }
    assert_eq!(device.lock().region.as_ref().unwrap().addr(), Some(100));
    let chipset = TestChipset::default();
    let mut construction = std::pin::pin!(
        chipset
            .device_builder("fallible-async")
            .try_add_async(async |_| Ok::<_, std::io::Error>(Device::new(None, true)))
    );
    let _device = match construction.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result.unwrap(),
        Poll::Pending => panic!("ready constructor did not complete"),
    };
    let mut data = [0; 4];
    assert_eq!(chipset.mmio_read(10, &mut data), Some(()));
    assert_eq!(data, [1, 2, 3, 4]);
}

// Test: Return an error from an asynchronous device constructor.
// Expected: The named public error retains the original constructor error and no static route is installed.
#[test]
fn async_constructor_failure_keeps_source_and_no_route() {
    use std::error::Error;
    let chipset = TestChipset::default();
    let mut construction = std::pin::pin!(
        chipset
            .device_builder::<Device>("async-failure")
            .try_add_async(async |_| Err(std::io::Error::other("async fixture failure")))
    );
    let mut cx = Context::from_waker(Waker::noop());
    let error = match construction.as_mut().poll(&mut cx) {
        Poll::Ready(Err(error)) => error,
        _ => panic!("constructor error not returned"),
    };
    assert_eq!(error.to_string(), "could not initialize async-failure");
    assert_eq!(
        error.source().unwrap().source().unwrap().to_string(),
        "async fixture failure"
    );
    assert_eq!(chipset.mmio_read(10, &mut [0; 4]), None);
}
