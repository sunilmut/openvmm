// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::wire::setup;
use futures::FutureExt;
use get_protocol as p;
use pal_async::DefaultDriver;
use pal_async::async_test;
use std::pin::pin;
use test_with_tracing::test;
use zerocopy::IntoBytes;

// Test: Receive a short packet, an invalid notification version, or a truncated battery.
// Expected: Each malformed host input produces a descriptive worker error
//       rather than being silently accepted or causing a panic.
#[async_test]
async fn malformed_guest_notifications_are_reported_as_transport_errors(driver: DefaultDriver) {
    let mut invalid_version = p::UpdateGenerationId::new([1; 16]);
    invalid_version.message_header.message_version = p::MessageVersions(0);
    let truncated: p::HeaderGuestNotification =
        p::HeaderGeneric::new(p::GuestNotifications::BATTERY_STATUS);
    for (bytes, expected) in [
        (vec![0], "too small to read header"),
        (
            invalid_version.as_bytes().to_vec(),
            "notification message version",
        ),
        (
            truncated.as_bytes().to_vec(),
            "not correct to read guest notification",
        ),
    ] {
        let (_client, mut host, task) = setup(&driver).await;
        host.send(&bytes).await;
        let error = anyhow::Error::new(task.await.unwrap_err());
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

// IGNORED: Fixed-size response error reporting reads the entire malformed packet
//       as a header and panics when the body has the wrong size.
//
// Test: Receive a time response with a valid header and a truncated body.
// Expected: The worker returns a malformed-response error rather than panicking
//       while attempting to report the invalid packet size.
#[ignore = "product bug: malformed fixed-size response panics while reporting its size"]
#[async_test]
async fn truncated_fixed_size_response_is_reported_without_panicking(driver: DefaultDriver) {
    let (client, mut host, task) = setup(&driver).await;
    let mut call = pin!(client.host_time());
    assert!(call.as_mut().now_or_never().is_none());
    host.expect(p::TimeRequest::new().as_bytes()).await;
    let response = p::TimeResponse::new(0, 123, 0, false);
    host.send(&response.as_bytes()[..5]).await;
    let error = anyhow::Error::new(task.await.unwrap_err());
    assert!(
        format!("{error:#}").contains("not correct to read host response"),
        "{error:#}"
    );
}
