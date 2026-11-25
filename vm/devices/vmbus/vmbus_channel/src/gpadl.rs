// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GPADL support.

use inspect::Inspect;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;
pub use vmbus_core::protocol::GpadlId;
use vmbus_ring::gparange::MultiPagedRangeBuf;

/// Object to call when a GPADL is torn down.
pub type TeardownFn = Box<dyn FnOnce() + Send>;

struct Teardown(TeardownFn);

impl std::fmt::Debug for Teardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("Teardown")
    }
}

#[derive(Debug)]
struct GpadlState {
    tearing_down: bool,
    map_count: usize,
    teardown: Option<Teardown>,
}

#[derive(Debug)]
struct Gpadl {
    id: GpadlId,
    buf: MultiPagedRangeBuf,
    state: Mutex<GpadlState>,
}

impl Inspect for Gpadl {
    fn inspect(&self, req: inspect::Request<'_>) {
        let state = self.state.lock();
        req.respond()
            .field("tearing_down", state.tearing_down)
            .field("map_count", state.map_count)
            .child("ranges", |req| {
                let mut resp = req.respond();
                for (i, range) in self.buf.iter().enumerate() {
                    resp.child(&i.to_string(), |req| {
                        req.respond()
                            .hex("len", range.len())
                            .hex("offset", range.offset())
                            .field(
                                "pages",
                                range
                                    .gpns()
                                    .iter()
                                    .map(|gpa| format!("{:x}", gpa))
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            );
                    });
                }
            });
    }
}

/// A GPADL that has been provided by the guest. It has not yet been locked.
///
/// The guest will not reuse the associated memory while this exists.
#[derive(Debug)]
pub struct GpadlView(Arc<Gpadl>);

impl Clone for GpadlView {
    fn clone(&self) -> Self {
        let clone = GpadlView(self.0.clone());
        let mut state = self.0.state.lock();
        state.map_count += 1;
        clone
    }
}

impl GpadlView {
    /// Returns the GPADL identifier.
    pub fn id(&self) -> GpadlId {
        self.0.id
    }
}

impl Deref for GpadlView {
    type Target = MultiPagedRangeBuf;
    fn deref(&self) -> &Self::Target {
        &self.0.buf
    }
}

impl Drop for GpadlView {
    fn drop(&mut self) {
        let teardown = {
            let mut state = self.0.state.lock();
            state.map_count -= 1;
            if state.map_count == 0 && state.tearing_down {
                state.teardown.take()
            } else {
                None
            }
        };
        if let Some(Teardown(teardown)) = teardown {
            teardown();
        }
    }
}

/// A set of GPADLs that the guest has made available to the host.
#[derive(Debug)]
pub struct GpadlMap {
    map: Mutex<HashMap<GpadlId, Arc<Gpadl>>>,
}

impl Inspect for GpadlMap {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .fields("", self.map.lock().iter().map(|(id, gpadl)| (&id.0, gpadl)));
    }
}

impl GpadlMap {
    /// Creates an empty map.
    pub fn new() -> Arc<Self> {
        Arc::new(GpadlMap {
            map: Default::default(),
        })
    }

    /// Adds the specified GPADL to the map.
    pub fn add(&self, id: GpadlId, buf: MultiPagedRangeBuf) {
        let gpadl = Arc::new(Gpadl {
            id,
            buf,
            state: Mutex::new(GpadlState {
                tearing_down: false,
                map_count: 0,
                teardown: None,
            }),
        });
        let mut map = self.map.lock();
        map.insert(id, gpadl);
    }

    /// Removes the specified GPADL from the mapping, calling `f` when there are
    /// no more [`GpadlView`] instances.
    pub fn remove(&self, id: GpadlId, f: TeardownFn) -> Option<TeardownFn> {
        let gpadl = {
            let mut map = self.map.lock();
            map.remove(&id).unwrap()
        };
        let mut state = gpadl.state.lock();
        assert!(!state.tearing_down && state.teardown.is_none());
        state.tearing_down = true;
        if state.map_count > 0 {
            state.teardown = Some(Teardown(f));
            None
        } else {
            Some(f)
        }
    }

    /// Constructs a GPADL map view.
    pub fn view(self: Arc<Self>) -> GpadlMapView {
        GpadlMapView(Some(self))
    }
}

/// A GPADL map view for mapping GPADLs.
#[derive(Debug, Default, Clone)]
pub struct GpadlMapView(Option<Arc<GpadlMap>>);

/// An error indicating an attempt was made to map an unknown GPADL.
#[derive(Debug, Error)]
#[error("unknown gpadl ID {:#x}", (.0).0)]
pub struct UnknownGpadlId(GpadlId);

impl GpadlMapView {
    /// Maps the GPADL with `id`.
    pub fn map(&self, id: GpadlId) -> Result<GpadlView, UnknownGpadlId> {
        self.try_map(id).ok_or(UnknownGpadlId(id))
    }

    fn try_map(&self, id: GpadlId) -> Option<GpadlView> {
        let gpadl = {
            let map = self.0.as_ref()?.map.lock();
            map.get(&id)?.clone()
        };
        {
            let mut state = gpadl.state.lock();
            if state.tearing_down {
                return None;
            }
            state.map_count += 1;
        }
        Some(GpadlView(gpadl))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use test_with_tracing::test;

    // Test: Remove a GPADL while mapped and cloned views still refer to it.
    // Expected: New mappings fail, existing data remains readable, and teardown
    //       runs exactly once after the last view is dropped.
    #[test]
    fn teardown_waits_for_last_view() {
        let map = GpadlMap::new();
        let id = GpadlId(7);
        map.add(
            id,
            MultiPagedRangeBuf::from_range_buffer(1, vec![8192, 10, 11]).unwrap(),
        );
        let mapper = map.clone().view();
        let view = mapper.map(id).unwrap();
        let clone = view.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = calls.clone();
        let callback_mapper = mapper.clone();
        assert!(
            map.remove(
                id,
                Box::new(move || {
                    assert!(callback_mapper.map(id).is_err());
                    completed.fetch_add(1, Ordering::SeqCst);
                })
            )
            .is_none()
        );
        assert!(mapper.map(id).is_err());
        assert_eq!(view.id(), id);
        assert_eq!(view.first().unwrap().gpns(), &[10, 11]);
        drop(view);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(clone);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // Test: Remove a GPADL that has never been mapped.
    // Expected: Its teardown is returned for immediate execution by the caller.
    #[test]
    fn unmapped_teardown_is_returned() {
        let map = GpadlMap::new();
        let id = GpadlId(8);
        map.add(id, MultiPagedRangeBuf::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = calls.clone();
        let teardown = map
            .remove(
                id,
                Box::new(move || {
                    completed.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(map.view().map(id).is_err());
        teardown();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(GpadlMapView::default().map(id).is_err());
    }

    // Test: Reuse an identifier while a removed GPADL still has an active view.
    // Expected: Old and new views retain their own pages and teardown lifetimes.
    #[test]
    fn reused_id_does_not_replace_existing_views() {
        let map = GpadlMap::new();
        let id = GpadlId(9);
        let mapper = map.clone().view();
        map.add(
            id,
            MultiPagedRangeBuf::from_range_buffer(1, vec![4096, 20]).unwrap(),
        );
        let old = mapper.map(id).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let completed = calls.clone();
        assert!(
            map.remove(
                id,
                Box::new(move || {
                    completed.fetch_add(1, Ordering::SeqCst);
                })
            )
            .is_none()
        );
        map.add(
            id,
            MultiPagedRangeBuf::from_range_buffer(1, vec![4096, 30]).unwrap(),
        );
        let new = mapper.map(id).unwrap();
        assert_eq!(old.first().unwrap().gpns(), &[20]);
        assert_eq!(new.first().unwrap().gpns(), &[30]);
        drop(old);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(new.first().unwrap().gpns(), &[30]);
        drop(new);
        map.remove(id, Box::new(|| {})).unwrap()();
    }
}
