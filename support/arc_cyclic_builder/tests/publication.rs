// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public cyclic ownership with aligned data and erased weak references.

use arc_cyclic_builder::ArcCyclicBuilderExt;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use test_with_tracing::test;

trait Published: Send + Sync {
    fn payload(&self) -> &[u64; 32];
}

#[repr(align(64))]
struct Node {
    this: Weak<Node>,
    payload: [u64; 32],
    drops: Arc<AtomicUsize>,
}

impl Published for Node {
    fn payload(&self) -> &[u64; 32] {
        &self.payload
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

// Test: Hand an erased weak reference to another thread before building an
//       over-aligned self-referential value, then transfer its last ownership.
// Expected: Upgrade fails before build, afterward exposes all initialized data,
//       and retains the value until the remote owner releases it exactly once.
#[test]
fn erased_weak_can_own_aligned_data_after_build_and_release_it() {
    let builder = Arc::<Node>::new_cyclic_builder();
    let observer = builder.weak();
    let erased: Weak<dyn Published> = builder.weak();
    let expected = std::array::from_fn(|i| (i as u64 + 1) * 0x0102_0304_0506_0708);
    let drops = Arc::new(AtomicUsize::new(0));
    let (to_worker, from_main) = sync_channel(0);
    let (to_main, from_worker) = sync_channel(0);
    let worker = std::thread::spawn(move || {
        assert!(erased.upgrade().is_none());
        to_main.send(()).unwrap();
        from_main.recv().unwrap();
        let held = erased.upgrade().unwrap();
        assert_eq!(held.payload(), &expected);
        to_main.send(()).unwrap();
        from_main.recv().unwrap();
        assert_eq!(held.payload(), &expected);
    });
    from_worker.recv().unwrap();
    let node = builder.build(Node {
        this: observer.clone(),
        payload: expected,
        drops: drops.clone(),
    });
    assert!(Arc::ptr_eq(&node, &node.this.upgrade().unwrap()));
    to_worker.send(()).unwrap();
    from_worker.recv().unwrap();
    drop(node);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(observer.upgrade().unwrap().payload, expected);
    to_worker.send(()).unwrap();
    worker.join().unwrap();
    assert!(observer.upgrade().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
