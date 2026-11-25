// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::DefaultDriver;
use crate::timer::PolledTimer;
use futures::FutureExt;
use std::future::Future;
use std::pin::pin;
use std::time::Duration;

async fn within<T>(driver: &DefaultDriver, future: impl Future<Output = T>) -> T {
    let mut timer = PolledTimer::new(driver);
    match futures::future::select(pin!(future), pin!(timer.sleep(Duration::from_secs(5)))).await {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right(_) => panic!("async operation timed out"),
    }
}

mod scheduling;
mod sockets;
mod timers;
mod wakers;
