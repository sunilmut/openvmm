// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An abstraction over platform-specific event primitives:
//!
//! Windows: [event objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects)
//! Linux: [eventfd](https://man7.org/linux/man-pages/man2/eventfd.2.html)
//! Other Unix: [fifo](https://man.openbsd.org/mkfifo.2)

// UNSAFETY: FFI into platform-specific APIs.
#![expect(unsafe_code)]

mod unix;
mod windows;

cfg_select! {
    unix => {
        use unix as sys;
    }
    windows => {
        use windows as sys;
    }
}

/// A platform-specific synchronization event.
#[derive(Debug)]
pub struct Event(sys::Inner);

impl Event {
    /// Creates a new event.
    ///
    /// Panics if the event cannot be created. This should only be due to low
    /// resources.
    pub fn new() -> Self {
        match Self::new_inner() {
            Ok(event) => event,
            Err(err) => panic!("failed to create event: {}", err),
        }
    }

    /// Signals the event.
    pub fn signal(&self) {
        self.signal_inner();
    }

    /// Waits for the event to be signaled and consumes the signal.
    pub fn wait(&self) {
        self.wait_inner();
    }

    /// Tries to consume the event signal.
    ///
    /// Returns `false` if the event is not currently signaled.
    pub fn try_wait(&self) -> bool {
        self.try_wait_inner()
    }
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    #[test]
    fn test_event() {
        let event = crate::Event::new();
        event.signal();
        event.wait();
    }

    // Test: Poll an unready event, signal it repeatedly, and compare it with an independent event.
    // Expected: Signals coalesce into one consumable ready state without leaking into another event, and the event can be signaled again.
    #[test]
    fn signals_coalesce_and_events_remain_independent() {
        let event = crate::Event::new();
        let other = crate::Event::new();
        assert!(!event.try_wait());
        assert!(!event.try_wait());
        for _ in 0..4 {
            event.signal();
        }
        assert!(!other.try_wait());
        assert!(event.try_wait());
        assert!(!event.try_wait());
        other.signal();
        assert!(!event.try_wait());
        assert!(other.try_wait());
        event.signal();
        assert!(event.try_wait());
        assert!(!event.try_wait());
    }

    // Test: Clone an event and round-trip owned and borrowed descriptors, then drop the original owners.
    // Expected: Every surviving handle shares one ready state and remains usable after other handles are dropped.
    #[cfg(unix)]
    #[test]
    fn descriptor_round_trips_preserve_shared_readiness_and_ownership() {
        use std::os::fd::AsFd;
        use std::os::fd::OwnedFd;

        let event = crate::Event::new();
        let cloned = event.clone();
        let borrowed = crate::Event::from(event.as_fd().try_clone_to_owned().unwrap());
        event.signal();
        let descriptor: OwnedFd = event.into();
        let restored = crate::Event::from(descriptor);
        assert!(cloned.try_wait());
        assert!(!borrowed.try_wait());
        assert!(!restored.try_wait());
        restored.signal();
        drop(restored);
        assert!(borrowed.try_wait());
        assert!(!cloned.try_wait());
        borrowed.signal();
        drop(borrowed);
        assert!(cloned.try_wait());
        assert!(!cloned.try_wait());
    }

    // Test: Block a thread on an unready event and signal it from another thread.
    // Expected: The waiter does not complete before the signal, consumes it exactly once, and reports completion within a bounded interval.
    #[test]
    fn blocking_wait_wakes_and_consumes_a_cross_thread_signal() {
        let event = std::sync::Arc::new(crate::Event::new());
        let waiter_event = event.clone();
        let (started_send, started_recv) = std::sync::mpsc::channel();
        let (finished_send, finished_recv) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_send.send(()).unwrap();
            waiter_event.wait();
            finished_send.send(()).unwrap();
        });
        started_recv
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            finished_recv.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        event.signal();
        finished_recv
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        waiter.join().unwrap();
        assert!(!event.try_wait());
    }

    // Test: Signal an eventfd whose counter has already reached its maximum permitted value.
    // Expected: Backpressure preserves readiness without panicking, and draining the counter allows later signals to succeed.
    #[cfg(target_os = "linux")]
    #[test]
    fn saturated_eventfd_preserves_readiness_and_recovers_after_drain() {
        use std::io::Write;
        use std::os::fd::AsFd;

        let event = crate::Event::new();
        let mut writer = std::fs::File::from(event.as_fd().try_clone_to_owned().unwrap());
        writer.write_all(&(u64::MAX - 1).to_ne_bytes()).unwrap();
        event.signal();
        assert!(event.try_wait());
        assert!(!event.try_wait());
        event.signal();
        assert!(event.try_wait());
        assert!(!event.try_wait());
    }
}
