// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cancel context support.

use super::bidir::Channel;
use super::deadline::DeadlineId;
use super::deadline::DeadlineSet;
use mesh_node::local_node::Port;
use mesh_node::resource::Resource;
use mesh_protobuf::EncodeAs;
use mesh_protobuf::Protobuf;
use mesh_protobuf::SerializedMessage;
use mesh_protobuf::Timestamp;
use mesh_protobuf::encoding::IgnoreField;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use thiserror::Error;

/// A cancellation context.
///
/// This is used to get a notification when an operation has been cancelled. It
/// can be cloned or sent across process boundaries.
#[derive(Debug, Protobuf)]
#[mesh(resource = "Resource")]
pub struct CancelContext {
    state: CancelState,
    deadline: Option<EncodeAs<Deadline, Timestamp>>,
    deadline_id: Ignore<DeadlineId>,
}

#[derive(Debug, Protobuf)]
#[mesh(resource = "Resource")]
enum CancelState {
    NotCancelled { ports: Vec<Channel> },
    Cancelled(CancelReason),
}

#[derive(Debug, Default)]
struct Ignore<T>(T);

impl<T: Default> mesh_protobuf::DefaultEncoding for Ignore<T> {
    type Encoding = IgnoreField;
}

impl Clone for CancelContext {
    fn clone(&self) -> Self {
        let state = match &self.state {
            CancelState::Cancelled(reason) => CancelState::Cancelled(*reason),
            CancelState::NotCancelled { ports, .. } => CancelState::NotCancelled {
                ports: ports
                    .iter()
                    .map(|port| {
                        // Each port has a peer port in a Cancel object; these
                        // ports will be closed on cancellation. Send a new port
                        // to each Cancel object; these new ports will be closed
                        // on cancel, too.
                        let (send, recv) = <Channel>::new_pair();
                        port.send(SerializedMessage {
                            data: vec![],
                            resources: vec![Resource::Port(recv.into())],
                        });
                        send
                    })
                    .collect(),
            },
        };
        Self {
            state,
            deadline: self.deadline,
            deadline_id: Default::default(),
        }
    }
}

impl CancelContext {
    /// Returns a new context that is never notified of cancellation.
    pub fn new() -> Self {
        Self {
            state: CancelState::NotCancelled { ports: Vec::new() },
            deadline: None,
            deadline_id: Default::default(),
        }
    }

    fn add_cancel(&mut self) -> Cancel {
        let (send, recv) = Channel::new_pair();
        match &mut self.state {
            CancelState::Cancelled(_) => {}
            CancelState::NotCancelled { ports, .. } => ports.push(send),
        }
        Cancel::new(recv)
    }

    /// Returns a new child context and a cancel function.
    ///
    /// The new context is notified when either this context is cancelled, or
    /// the returned `Cancel` object's `cancel` method is called.
    pub fn with_cancel(&self) -> (Self, Cancel) {
        let mut ctx = self.clone();
        let cancel = ctx.add_cancel();
        (ctx, cancel)
    }

    /// Returns a new child context with a deadline.
    ///
    /// The new context is notified when either this context is cancelled, or
    /// the deadline is exceeded.
    pub fn with_deadline(&self, deadline: Deadline) -> Self {
        let mut ctx = self.clone();
        ctx.deadline = Some(
            self.deadline
                .map_or(deadline, |old| old.min(deadline))
                .into(),
        );
        ctx
    }

    /// Returns a new child context with a timeout.
    ///
    /// The new context is notified when either this context is cancelled, or
    /// the timeout has expired.
    pub fn with_timeout(&self, timeout: Duration) -> Self {
        match Deadline::now().checked_add(timeout) {
            Some(deadline) => self.with_deadline(deadline),
            None => self.clone(),
        }
    }

    /// Returns the current deadline, if there is one.
    pub fn deadline(&self) -> Option<Deadline> {
        self.deadline.as_deref().copied()
    }

    /// Returns a future that completes when the context is cancelled.
    pub fn cancelled(&mut self) -> Cancelled<'_> {
        Cancelled(self)
    }

    /// Runs `fut` until this context is cancelled.
    pub async fn until_cancelled<F: Future>(&mut self, fut: F) -> Result<F::Output, CancelReason> {
        let mut fut = core::pin::pin!(fut);
        let mut cancelled = core::pin::pin!(self.cancelled());
        std::future::poll_fn(|cx| {
            if let Poll::Ready(r) = fut.as_mut().poll(cx) {
                return Poll::Ready(Ok(r));
            }
            if let Poll::Ready(reason) = cancelled.as_mut().poll(cx) {
                return Poll::Ready(Err(reason));
            }
            Poll::Pending
        })
        .await
    }

    /// Runs a failable future until this context is cancelled, merging the
    /// result with the cancellation reason.
    pub async fn until_cancelled_failable<F: Future<Output = Result<T, E>>, T, E>(
        &mut self,
        fut: F,
    ) -> Result<T, ErrorOrCancelled<E>> {
        match self.until_cancelled(fut).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(ErrorOrCancelled::Error(e)),
            Err(reason) => Err(ErrorOrCancelled::Cancelled(reason)),
        }
    }

    /// Returns true if the context has been cancelled.
    pub fn is_cancelled(&mut self) -> bool {
        Pin::new(&mut self.cancelled())
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_ready()
    }
}

impl Default for CancelContext {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
#[derive(Debug)]
pub struct Cancelled<'a>(&'a mut CancelContext);

#[derive(Debug, Protobuf, Copy, Clone, PartialEq, Eq)]
pub enum CancelReason {
    Cancelled,
    DeadlineExceeded,
}

impl std::fmt::Display for CancelReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match *self {
            CancelReason::Cancelled => "cancelled",
            CancelReason::DeadlineExceeded => "deadline exceeded",
        })
    }
}

impl std::error::Error for CancelReason {}

#[derive(Error, Debug)]
pub enum ErrorOrCancelled<E> {
    #[error(transparent)]
    Error(E),
    #[error(transparent)]
    Cancelled(CancelReason),
}

impl Future for Cancelled<'_> {
    type Output = CancelReason;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::get_mut(self);
        match &mut this.0.state {
            CancelState::Cancelled(reason) => return Poll::Ready(*reason),
            CancelState::NotCancelled { ports } => {
                for p in ports.iter_mut() {
                    if p.poll_recv(cx).is_ready() {
                        let reason = CancelReason::Cancelled;
                        this.0.state = CancelState::Cancelled(reason);
                        return Poll::Ready(reason);
                    }
                }
            }
        }
        if let Some(deadline) = this.0.deadline {
            if DeadlineSet::global()
                .poll(cx, &mut this.0.deadline_id.0, *deadline)
                .is_ready()
            {
                let reason = CancelReason::DeadlineExceeded;
                this.0.state = CancelState::Cancelled(reason);
                return Poll::Ready(reason);
            }
        }
        Poll::Pending
    }
}

impl Drop for CancelContext {
    fn drop(&mut self) {
        // Drop the deadline.
        DeadlineSet::global().remove(&mut self.deadline_id.0);
    }
}

/// A cancel notifier.
///
/// The associated [`CancelContext`] will be cancelled when this object is
/// dropped or [`Cancel::cancel()`] is called.
#[derive(Debug)]
pub struct Cancel(Arc<CancelList>);

/// A list of ports to be closed in order to cancel a chain of cancel contexts.
///
/// A cancel context can send additional ports to any one of these ports in
/// order to register additional cancel contexts.
#[derive(Debug)]
struct CancelList {
    ports: Mutex<Vec<Channel>>,
}

impl CancelList {
    /// Polls each port to accumulate more ports and to garbage collect any
    /// closed ports.
    fn poll(&self, cx: &mut Context<'_>) {
        let mut to_drop = Vec::new();
        let mut ports = self.ports.lock();
        let mut i = 0;
        'outer: while i < ports.len() {
            while let Poll::Ready(message) = ports[i].poll_recv(cx) {
                match message {
                    Ok(message) => {
                        // Accumulate any ports onto the main list so that they
                        // can be polled.
                        let resources = message.resources;
                        tracing::trace!(count = resources.len(), "adding ports");
                        ports.extend(resources.into_iter().filter_map(|resource| {
                            Port::try_from(resource).ok().map(|port| port.into())
                        }));
                    }
                    Err(_) => {
                        // The peer port is gone. Remove the port from the list.
                        // Push it onto a new list to be dropped outside the lock.
                        to_drop.push(ports.swap_remove(i));
                        continue 'outer;
                    }
                }
            }
            i += 1;
        }
        if !to_drop.is_empty() {
            tracing::trace!(count = to_drop.len(), "dropping ports");
        }
    }

    /// Returns all the accumulated ports.
    fn drain(&self) -> Vec<Channel> {
        std::mem::take(&mut self.ports.lock())
    }
}

/// Waker that processes the list inline.
struct ListWaker {
    list: Weak<CancelList>,
}

impl Wake for ListWaker {
    fn wake(self: Arc<Self>) {
        if let Some(list) = self.list.upgrade() {
            // Ordinarily it is a bad idea to do anything like this in a waker,
            // since this could run on an arbitrary thread, under locks, etc.
            // However, since we're within the same crate we know that it should
            // be safe to run CancelList::poll on the waking thread.
            let waker = self.into();
            let mut cx = Context::from_waker(&waker);
            list.poll(&mut cx);
        }
    }
}

impl Cancel {
    fn new(port: Channel) -> Self {
        let inner = Arc::new(CancelList {
            ports: Mutex::new(vec![port]),
        });
        // The waker is used to poll the port. This is done to detect when the
        // port is closed so that it can be dropped, and to accumulate any
        // incoming ports (due to CancelContext::clone) for the same.
        let waker = Arc::new(ListWaker {
            list: Arc::downgrade(&inner),
        });
        waker.wake();
        Self(inner)
    }

    /// Cancels the associated port context and any children contexts.
    pub fn cancel(&mut self) {
        drop(self.0.drain());
    }
}

/// A point in time that acts as a deadline for an operation.
///
/// A deadline internally tracks both wall-clock time and, optionally, OS
/// monotonic time. When two deadlines are compared, monotonic time is
/// preferred, but if one or more deadlines do not have monotonic time,
/// wall-clock time is used.
///
/// When a deadline is serialized, only its wall-clock time is serialized. The
/// monotonic time is not useful outside of the process that generated it, since
/// the monotonic time is not guaranteed to be consistent across processes.
#[derive(Debug, Copy, Clone, Eq)]
pub struct Deadline {
    system_time: SystemTime,
    instant: Option<Instant>,
}

impl Deadline {
    /// Returns a new deadline representing the current time.
    ///
    /// This will capture both wall-clock time and monotonic time.
    pub fn now() -> Self {
        Self {
            system_time: SystemTime::now(),
            instant: Some(Instant::now()),
        }
    }

    /// The monotonic OS instant of the deadline, if there is one.
    pub fn instant(&self) -> Option<Instant> {
        self.instant
    }

    /// The wall-clock time of the deadline.
    pub fn system_time(&self) -> SystemTime {
        self.system_time
    }

    /// Adds a duration to the deadline, returning `None` on overflow.
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        // Throw away the instant if it overflows.
        let instant = self.instant.and_then(|i| i.checked_add(duration));
        let system_time = self.system_time.checked_add(duration)?;
        Some(Self {
            system_time,
            instant,
        })
    }
}

impl std::ops::Add<Duration> for Deadline {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self.checked_add(rhs)
            .expect("overflow when adding duration to deadline")
    }
}

impl std::ops::Sub<Duration> for Deadline {
    type Output = Deadline;

    fn sub(self, rhs: Duration) -> Self::Output {
        // Saturate to the UNIX epoch on overflow. Since `SystemTime` does
        // generally allow times before the epoch, this might lead to the
        // deadline "snapping back" to 1970. But for our use case the
        // distinction between any time before now doesn't matter.
        Self {
            system_time: self.system_time.checked_sub(rhs).unwrap_or(UNIX_EPOCH),
            instant: self.instant.and_then(|i| i.checked_sub(rhs)),
        }
    }
}

impl std::ops::Sub<Deadline> for Deadline {
    type Output = Duration;

    fn sub(self, rhs: Deadline) -> Self::Output {
        // Saturate to zero on overflow.
        if let Some((lhs, rhs)) = self.instant.zip(rhs.instant) {
            lhs.checked_duration_since(rhs).unwrap_or_default()
        } else {
            self.system_time
                .duration_since(rhs.system_time)
                .unwrap_or_default()
        }
    }
}

impl PartialEq for Deadline {
    fn eq(&self, other: &Self) -> bool {
        if let Some((lhs, rhs)) = self.instant.zip(other.instant) {
            lhs.eq(&rhs)
        } else {
            self.system_time.eq(&other.system_time)
        }
    }
}

impl PartialOrd for Deadline {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Deadline {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if let Some((lhs, rhs)) = self.instant.zip(other.instant) {
            lhs.cmp(&rhs)
        } else {
            self.system_time.cmp(&other.system_time)
        }
    }
}

impl From<SystemTime> for Deadline {
    fn from(system_time: SystemTime) -> Self {
        Self {
            system_time,
            instant: None,
        }
    }
}

impl From<Deadline> for Timestamp {
    fn from(deadline: Deadline) -> Self {
        deadline.system_time.into()
    }
}

impl From<Timestamp> for Deadline {
    fn from(timestamp: Timestamp) -> Self {
        Self {
            system_time: timestamp.try_into().unwrap_or(UNIX_EPOCH),
            instant: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CancelContext;
    use super::CancelReason;
    use super::Deadline;
    use pal_async::async_test;
    use test_with_tracing::test;

    // Test: Poll a context with no cancellation source or deadline.
    // Expected: Waiting for cancellation stays pending.
    #[async_test]
    async fn no_cancel() {
        assert!(futures::poll!(CancelContext::new().cancelled()).is_pending());
    }

    // Test: Cancel a context through its owned notifier.
    // Expected: The waiting context reports Cancelled, not DeadlineExceeded.
    #[async_test]
    async fn basic_cancel() {
        let (mut ctx, mut cancel) = CancelContext::new().with_cancel();
        cancel.cancel();
        assert_eq!(ctx.cancelled().await, CancelReason::Cancelled);
    }

    /// Checks the cancellation reason through two deep chains of cloned contexts.
    #[expect(clippy::redundant_clone, reason = "explicitly testing chained clones")]
    async fn chain(reason: CancelReason) {
        let ctx = CancelContext::new();
        let (ctx, mut cancel) = ctx.with_cancel();
        let ctx = match reason {
            CancelReason::Cancelled => ctx,
            CancelReason::DeadlineExceeded => {
                ctx.with_timeout(std::time::Duration::from_millis(15))
            }
        };
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let ctx = ctx.clone();
        let mut ctx = ctx.clone();
        let ctx2 = ctx.clone();
        let ctx2 = ctx2.clone();
        let ctx2 = ctx2.clone();
        let ctx2 = ctx2.clone();
        let ctx2 = ctx2.clone();
        let mut ctx2 = ctx2.clone();
        let _ = ctx2
            .clone()
            .clone()
            .clone()
            .clone()
            .clone()
            .clone()
            .clone()
            .clone()
            .clone();
        if reason == CancelReason::Cancelled {
            assert!(futures::poll!(ctx.cancelled()).is_pending());
            assert!(futures::poll!(ctx2.cancelled()).is_pending());
            cancel.cancel();
        }
        assert_eq!(ctx.cancelled().await, reason);
        assert_eq!(ctx2.cancelled().await, reason);
    }

    // Test: Cancel two deep clone chains through their shared notifier.
    // Expected: Both remain pending until cancellation, then report Cancelled.
    #[async_test]
    async fn chain_cancel() {
        chain(CancelReason::Cancelled).await
    }

    // Test: Inherit a short deadline through two deep clone chains.
    // Expected: Both report DeadlineExceeded without an explicit cancellation.
    #[async_test]
    async fn chain_deadline() {
        chain(CancelReason::DeadlineExceeded).await
    }

    // Test: Wait for an immediate deadline and a later timeout.
    // Expected: Both waits complete with DeadlineExceeded.
    #[async_test]
    async fn cancel_deadline() {
        let mut ctx = CancelContext::new().with_timeout(std::time::Duration::from_millis(0));
        assert_eq!(ctx.cancelled().await, CancelReason::DeadlineExceeded);
        let mut ctx = CancelContext::new().with_timeout(std::time::Duration::from_millis(100));
        assert_eq!(ctx.cancelled().await, CancelReason::DeadlineExceeded);
    }

    // Test: Round-trip monotonic and pre/post-epoch deadlines through timestamps.
    // Expected: Every decoded deadline compares equal to its original.
    #[test]
    fn test_encode_deadline() {
        let check = |deadline: Deadline| {
            let timestamp: super::Timestamp = deadline.into();
            let deadline2: Deadline = timestamp.into();
            assert_eq!(deadline, deadline2);
        };

        check(Deadline::now());
        check(Deadline::now() + std::time::Duration::from_secs(1));
        check(Deadline::now() - std::time::Duration::from_secs(1));
        check(Deadline::from(
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_nanos(1_500_000_000),
        ));
        check(Deadline::from(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(1_500_000_000),
        ));
    }

    // Test: Run successful and failing operations under a live cancellation context.
    // Expected: Original values and errors survive without cancelling the context.
    #[async_test]
    async fn operation_results_survive_cancellation_wrappers() {
        let mut context = CancelContext::default();
        assert_eq!(context.until_cancelled(async { 42 }).await, Ok(42));
        assert_eq!(
            context
                .until_cancelled_failable(async { Ok::<_, &str>(7) })
                .await
                .unwrap(),
            7
        );
        assert!(matches!(
            context
                .until_cancelled_failable(async { Err::<u32, _>("operation failed") })
                .await,
            Err(super::ErrorOrCancelled::Error("operation failed"))
        ));
        assert!(!context.is_cancelled());
    }

    // Test: Drop a notifier and clone the already-cancelled child context.
    // Expected: All children stay cancelled and pending operations return that reason.
    #[async_test]
    async fn dropped_notifier_cancels_operations_and_later_children() {
        let (mut context, cancel) = CancelContext::new().with_cancel();
        assert!(!context.is_cancelled());
        drop(cancel);
        assert!(context.is_cancelled());
        assert_eq!(
            context.until_cancelled(std::future::pending::<()>()).await,
            Err(CancelReason::Cancelled)
        );
        assert!(matches!(
            context
                .until_cancelled_failable(std::future::pending::<Result<(), &str>>())
                .await,
            Err(super::ErrorOrCancelled::Cancelled(CancelReason::Cancelled))
        ));
        let mut clone = context.clone();
        assert_eq!(clone.cancelled().await, CancelReason::Cancelled);
        let (mut child, _cancel) = context.with_cancel();
        assert_eq!(child.cancelled().await, CancelReason::Cancelled);
    }

    // Test: Add later and earlier child deadlines, including an overflowing timeout.
    // Expected: The earliest inherited deadline wins and reports DeadlineExceeded.
    #[async_test]
    async fn child_deadlines_cannot_extend_parent_deadline() {
        use std::time::Duration;
        let expired = Deadline::from(std::time::UNIX_EPOCH);
        let context = CancelContext::new().with_deadline(expired);
        assert_eq!(
            context.with_deadline(Deadline::now()).deadline(),
            Some(expired)
        );
        assert_eq!(
            context.with_timeout(Duration::MAX).deadline(),
            Some(expired)
        );
        let mut earlier = CancelContext::new()
            .with_deadline(Deadline::now())
            .with_deadline(expired);
        assert_eq!(earlier.deadline(), Some(expired));
        assert_eq!(earlier.cancelled().await, CancelReason::DeadlineExceeded);
    }

    // Test: Add, compare, and subtract deadlines with and without monotonic clocks.
    // Expected: Exact durations survive and negative differences saturate at zero.
    #[test]
    fn deadline_arithmetic_preserves_clock_semantics() {
        use std::time::Duration;
        let now = Deadline::now();
        let later = now + Duration::from_secs(3);
        assert!(now.instant().is_some());
        assert_eq!(later - now, Duration::from_secs(3));
        assert_eq!(now - later, Duration::ZERO);
        assert_eq!(later - Duration::from_secs(3), now);
        assert_eq!(
            later
                .system_time()
                .duration_since(now.system_time())
                .unwrap(),
            Duration::from_secs(3)
        );
        let wall = Deadline::from(now.system_time());
        assert!(wall.instant().is_none());
        assert_eq!(wall, now);
        assert!(wall < later);
        assert_eq!(
            (wall + Duration::from_secs(3)) - wall,
            Duration::from_secs(3)
        );
        assert_eq!(wall - (wall + Duration::from_secs(3)), Duration::ZERO);
        assert!(wall.checked_add(Duration::MAX).is_none());
    }
}
