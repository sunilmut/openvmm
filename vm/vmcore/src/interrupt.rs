// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types to support delivering notifications to the guest.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use mesh::payload::DefaultEncoding;
use mesh::payload::FieldDecode;
use mesh::payload::FieldEncode;
use mesh::payload::inplace::InplaceOption;
use mesh::resource::Resource;
use pal_async::driver::SpawnDriver;
use pal_async::task::Task;
use pal_async::wait::PolledWait;
use pal_event::Event;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::OnceLock;

/// An object representing an interrupt-like signal to notify the guest of
/// device activity.
///
/// This is generally an edge-triggered interrupt, but it could also be a synic
/// event or similar notification.
///
/// The interrupt can be backed by a [`pal_event::Event`] or a function. In the
/// former case, the `Interrupt` can be sent across a mesh channel to remote
/// processes.
#[derive(Clone, Debug, MeshPayload)]
pub struct Interrupt {
    #[mesh(encoding = "InterruptEncoding")]
    inner: Arc<InterruptInner>,
}

impl Default for Interrupt {
    fn default() -> Self {
        Self::null()
    }
}

impl Interrupt {
    /// An interrupt that does nothing.
    ///
    /// Note that [`Self::event`] will still return a valid event, which will be
    /// lazily created on demand. This allows the interrupt to be used with APIs
    /// that require an event, without actually delivering any notifications.
    pub fn null() -> Self {
        Self::from_target(NullEventTarget)
    }

    /// Creates an interrupt from an event.
    ///
    /// The event will be signaled when [`Self::deliver`] is called.
    pub fn from_event(event: Event) -> Self {
        let event = Arc::new(event);
        Self {
            inner: Arc::new(InterruptInner {
                event: OnceLock::from(Some(event.clone())),
                t: EventTarget(event),
            }),
        }
    }

    /// Creates an interrupt from a function.
    ///
    /// The function will be called when [`Self::deliver`] is called. This type of
    /// interrupt cannot be sent to a remote process.
    pub fn from_fn<F>(f: F) -> Self
    where
        F: 'static + Send + Sync + Fn(),
    {
        Self {
            inner: Arc::new(InterruptInner {
                event: OnceLock::new(),
                t: FnTarget(f),
            }),
        }
    }

    /// Creates an interrupt from an [`InterruptTarget`] implementation.
    pub fn from_target(target: impl InterruptTarget + 'static) -> Self {
        Self {
            inner: Arc::new(InterruptInner {
                event: OnceLock::new(),
                t: target,
            }),
        }
    }

    /// Delivers the interrupt.
    pub fn deliver(&self) {
        self.inner.t.deliver();
    }

    /// Gets a reference to the backing event, if there is one.
    ///
    /// This will attempt to lazily create the event via the target if one
    /// has not already been cached.
    pub fn event(&self) -> Option<&Event> {
        self.inner.event().as_deref()
    }

    /// Returns an event that, when signaled, will deliver this interrupt.
    ///
    /// If [`Self::event`] returns an event, returns a clone of it and no
    /// proxy is needed. Otherwise, creates an [`EventProxy`] that spawns an
    /// async task to bridge a new event to [`Interrupt::deliver`]. The caller
    /// must keep the returned `Option<EventProxy>` alive for as long as the
    /// event is in use.
    pub fn event_or_proxy(
        &self,
        driver: &impl SpawnDriver,
    ) -> std::io::Result<(Event, Option<EventProxy>)> {
        if let Some(event) = self.event() {
            Ok((event.clone(), None))
        } else {
            let (proxy, event) = EventProxy::new(driver, self.clone())?;
            Ok((event, Some(proxy)))
        }
    }
}

/// A trait for implementing interrupt delivery.
///
/// Interrupt targets provide the core behavior for delivering interrupts
/// and optionally providing a backing OS event.
pub trait InterruptTarget: Send + Sync {
    /// Deliver the interrupt.
    fn deliver(&self);

    /// Called to lazily create an event-backed delivery path for this
    /// interrupt. If the implementation can provide an event (e.g., by
    /// allocating an irqfd route), it should do so here and return it.
    ///
    /// This will be called at most once per interrupt; the result is cached.
    fn event(&self) -> Option<Arc<Event>> {
        None
    }
}

struct InterruptInner<T: ?Sized = dyn InterruptTarget> {
    event: OnceLock<Option<Arc<Event>>>,
    t: T,
}

impl Debug for InterruptInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("InterruptInner")
    }
}

impl InterruptInner {
    fn event(&self) -> &Option<Arc<Event>> {
        self.event.get_or_init(|| self.t.event())
    }
}

/// Trivial target that wraps an event.
struct EventTarget(Arc<Event>);

impl InterruptTarget for EventTarget {
    fn deliver(&self) {
        self.0.signal();
    }

    fn event(&self) -> Option<Arc<Event>> {
        Some(self.0.clone())
    }
}

/// Target that wraps a function callback.
struct FnTarget<F>(F);

impl<F: Send + Sync + Fn()> InterruptTarget for FnTarget<F> {
    fn deliver(&self) {
        (self.0)()
    }
}

/// Target for null interrupts that lazily creates an event on demand.
struct NullEventTarget;

impl InterruptTarget for NullEventTarget {
    fn deliver(&self) {}

    fn event(&self) -> Option<Arc<Event>> {
        Some(Arc::new(Event::new()))
    }
}

struct InterruptEncoding;

type EventFieldEncoding = <Event as DefaultEncoding>::Encoding;

impl FieldEncode<Arc<InterruptInner>, Resource> for InterruptEncoding {
    fn write_field(
        item: Arc<InterruptInner>,
        writer: mesh::payload::protobuf::FieldWriter<'_, '_, Resource>,
    ) {
        if let Some(event) = item.event() {
            EventFieldEncoding::write_field_in_sequence((**event).clone(), &mut writer.sequence());
        } else {
            tracing::warn!("encoding local-only interrupt");
        }
    }

    fn compute_field_size(
        item: &mut Arc<InterruptInner>,
        sizer: mesh::payload::protobuf::FieldSizer<'_>,
    ) {
        if item.event().is_some() {
            sizer.sequence().field().resource();
        }
    }

    fn wrap_in_sequence() -> bool {
        true
    }
}

impl FieldDecode<'_, Arc<InterruptInner>, Resource> for InterruptEncoding {
    fn read_field(
        item: &mut InplaceOption<'_, Arc<InterruptInner>>,
        reader: mesh::payload::protobuf::FieldReader<'_, '_, Resource>,
    ) -> mesh::payload::Result<()> {
        mesh::payload::inplace_none!(event: Event);
        EventFieldEncoding::read_field_in_sequence(&mut event, reader)?;
        let event = Arc::new(event.take().unwrap());
        item.set(Arc::new(InterruptInner {
            event: OnceLock::from(Some(event.clone())),
            t: EventTarget(event),
        }));
        Ok(())
    }

    fn default_field(
        _item: &mut InplaceOption<'_, Arc<InterruptInner>>,
    ) -> mesh::payload::Result<()> {
        Err(mesh::payload::Error::new(
            "missing event in serialized interrupt",
        ))
    }

    fn wrap_in_sequence() -> bool {
        true
    }
}

/// An async task that bridges an [`Event`] to an [`Interrupt`].
///
/// When the interrupt is not directly backed by an OS event (e.g., it uses
/// a function callback for MSI-X), this wrapper creates a new event and
/// spawns a task that waits on it and calls [`Interrupt::deliver`]. When
/// the `EventProxy` is dropped, the task is cancelled.
pub struct EventProxy {
    _task: Task<()>,
}

impl EventProxy {
    /// Create a new proxy: returns the proxy (which owns the async task)
    /// and the [`Event`] that the caller should pass to the consumer.
    pub fn new(driver: &impl SpawnDriver, interrupt: Interrupt) -> std::io::Result<(Self, Event)> {
        let event = Event::new();
        let wait = PolledWait::new(driver, event.clone())?;
        let task = driver.spawn("interrupt-event-proxy", async move {
            Self::run(wait, interrupt).await;
        });
        Ok((Self { _task: task }, event))
    }

    async fn run(mut wait: PolledWait<Event>, interrupt: Interrupt) {
        loop {
            wait.wait().await.expect("wait should not fail");
            interrupt.deliver();
        }
    }
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod tests {
    use super::Interrupt;
    use super::InterruptTarget;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_event::Event;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use test_with_tracing::test;

    // Test: Deliver through an event-backed interrupt and its exposed event.
    // Expected: Both handles observe the same signal, consumed once per delivery.
    #[test]
    fn test_interrupt_event() {
        let event = Event::new();
        let interrupt = Interrupt::from_event(event.clone());
        interrupt.deliver();
        assert!(event.try_wait());
        assert!(!event.try_wait());
        interrupt.deliver();
        assert!(interrupt.event().unwrap().try_wait());
        assert!(!event.try_wait());
    }

    // Test: Deliver twice through a callback-backed interrupt.
    // Expected: The callback runs twice and no direct event is exposed.
    #[test]
    fn test_interrupt_fn() {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let interrupt = Interrupt::from_fn(move || {
            count2.fetch_add(1, Ordering::SeqCst);
        });
        assert!(interrupt.event().is_none());
        interrupt.deliver();
        interrupt.deliver();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert!(interrupt.event().is_none());
    }

    // Test: Deliver through a null interrupt with its lazy event allocated.
    // Expected: Neither the interrupt nor its clone signals that event.
    #[test]
    fn test_interrupt_null_does_not_signal() {
        let interrupt = Interrupt::null();
        let event = interrupt.event().unwrap();
        interrupt.deliver();
        assert!(!event.try_wait());
        interrupt.clone().deliver();
        assert!(!event.try_wait());
    }

    // Test: Request a null interrupt's event repeatedly and through a clone.
    // Expected: Each request shares one signal identity, not separate events.
    #[test]
    fn test_null_event_is_stable() {
        let interrupt = Interrupt::null();
        let cloned = interrupt.clone();
        let first = interrupt.event().unwrap();
        first.signal();
        assert!(interrupt.event().unwrap().try_wait());
        assert!(!first.try_wait());
        first.signal();
        assert!(cloned.event().unwrap().try_wait());
        assert!(!first.try_wait());
    }

    // Test: Deliver through a custom callback-only target.
    // Expected: The target receives one delivery and cannot expose a direct event.
    #[test]
    fn test_from_target() {
        struct TestTarget {
            count: Arc<AtomicUsize>,
        }
        impl InterruptTarget for TestTarget {
            fn deliver(&self) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let interrupt = Interrupt::from_target(TestTarget {
            count: count.clone(),
        });
        interrupt.deliver();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(interrupt.event().is_none());
    }

    // Test: Deliver through a custom target that also exposes its event.
    // Expected: Delivery and the exposed handle share the original event.
    #[test]
    fn test_from_target_with_event() {
        struct TestTarget(Arc<Event>);
        impl InterruptTarget for TestTarget {
            fn deliver(&self) {
                self.0.signal();
            }
            fn event(&self) -> Option<Arc<Event>> {
                Some(self.0.clone())
            }
        }
        let event = Arc::new(Event::new());
        let interrupt = Interrupt::from_target(TestTarget(event.clone()));
        assert!(interrupt.event().is_some());
        interrupt.deliver();
        assert!(event.try_wait());
        interrupt.deliver();
        assert!(interrupt.event().unwrap().try_wait());
        assert!(!event.try_wait());
    }

    // Test: Deliver through an interrupt and a clone.
    // Expected: Both deliveries reach the same callback.
    #[test]
    fn test_clone_shares_state() {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let interrupt = Interrupt::from_fn(move || {
            count2.fetch_add(1, Ordering::SeqCst);
        });
        let cloned = interrupt.clone();
        interrupt.deliver();
        cloned.deliver();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    // Test: Deliver through the default interrupt after obtaining its event.
    // Expected: It behaves as a null interrupt and leaves the event unsignaled.
    #[test]
    fn test_default_is_null() {
        let interrupt = Interrupt::default();
        let event = interrupt.event().unwrap();
        interrupt.deliver();
        assert!(!event.try_wait());
    }

    // Test: Obtain an OS event for an event-backed interrupt.
    // Expected: The returned event signals the original without a proxy.
    #[async_test]
    async fn test_event_or_proxy_event_backed(driver: DefaultDriver) {
        let orig_event = Event::new();
        let interrupt = Interrupt::from_event(orig_event.clone());
        let (event, proxy) = interrupt.event_or_proxy(&driver).unwrap();
        assert!(proxy.is_none());
        event.signal();
        assert!(orig_event.try_wait());
        assert!(!orig_event.try_wait());
    }

    // Test: Signal a callback interrupt through its automatically created proxy.
    // Expected: Each acknowledged signal delivers once; dropping both owners
    //       closes the callback channel without an extra delivery.
    #[async_test]
    async fn test_event_or_proxy_fn_backed(driver: DefaultDriver) {
        let (delivered, mut deliveries) = mesh::channel();
        let interrupt = Interrupt::from_fn(move || {
            delivered.send(());
        });
        let (event, proxy) = interrupt.event_or_proxy(&driver).unwrap();
        assert!(proxy.is_some());
        for _ in 0..2 {
            event.signal();
            deliveries.recv().await.unwrap();
        }
        drop(interrupt);
        drop(proxy);
        assert!(deliveries.recv().await.is_err());
        event.signal();
        assert!(deliveries.recv().await.is_err());
    }
}
