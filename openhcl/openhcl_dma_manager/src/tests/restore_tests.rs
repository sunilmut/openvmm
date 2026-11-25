// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveRestore;

fn snapshot(shared: bool, private: bool) -> save_restore::OpenhclDmaManagerState {
    let mut manager = manager(shared, private);
    let mut buffers = Vec::new();
    for (enabled, visibility, name) in [
        (shared, AllocationVisibility::Shared, "shared"),
        (private, AllocationVisibility::Private, "private"),
    ] {
        if enabled {
            let client = manager
                .new_client(parameters(name, visibility, true, false))
                .unwrap();
            buffers.push(client.allocate_dma_buffer(2 * PAGE_SIZE).unwrap());
        }
    }
    manager.save().unwrap()
}

// Test: Restore both pools and reattach shared and private allocations in sequence.
// Expected: Pending allocations reserve their exact original PFNs, each pool independently blocks restore validation until attached, repeated attachment is empty, and remaining free capacity is still usable.
#[test]
fn both_pools_require_their_own_pending_allocations_to_be_attached() {
    let mut manager = manager(true, true);
    manager.restore(snapshot(true, true)).unwrap();
    assert!(
        manager
            .validate_restore()
            .unwrap_err()
            .to_string()
            .contains("shared pool")
    );
    let shared = manager
        .new_client(parameters(
            "shared",
            AllocationVisibility::Shared,
            true,
            false,
        ))
        .unwrap();
    let attached_shared = shared.attach_pending_buffers().unwrap();
    assert_eq!(attached_shared.len(), 1);
    assert_eq!(attached_shared[0].pfns(), &[2, 3]);
    assert!(shared.attach_pending_buffers().unwrap().is_empty());
    assert!(
        manager
            .validate_restore()
            .unwrap_err()
            .to_string()
            .contains("private pool")
    );
    let private = manager
        .new_client(parameters(
            "private",
            AllocationVisibility::Private,
            true,
            false,
        ))
        .unwrap();
    let attached_private = private.attach_pending_buffers().unwrap();
    assert_eq!(attached_private.len(), 1);
    assert_eq!(attached_private[0].pfns(), &[20, 21]);
    assert!(private.attach_pending_buffers().unwrap().is_empty());
    manager.validate_restore().unwrap();
    assert_eq!(
        shared.allocate_dma_buffer(2 * PAGE_SIZE).unwrap().pfns(),
        &[4, 5]
    );
    assert_eq!(
        private.allocate_dma_buffer(2 * PAGE_SIZE).unwrap().pfns(),
        &[22, 23]
    );
}

// Test: Restore snapshots requiring absent pools and restore into a pool with an existing allocator.
// Expected: Missing pools produce typed invalid-state errors, occupied pools retain their child error context, and rejected restores do not consume their existing free capacity.
#[test]
fn invalid_pool_configuration_and_occupied_pool_restore_have_typed_context() {
    let mut absent = manager(false, false);
    let error = absent.restore(snapshot(true, false)).unwrap_err();
    assert!(
        matches!(error, RestoreError::InvalidSavedState(cause) if cause.to_string().contains("saved state for shared pool but no shared pool"))
    );
    let error = absent.restore(snapshot(false, true)).unwrap_err();
    assert!(
        matches!(error, RestoreError::InvalidSavedState(cause) if cause.to_string().contains("saved state for private pool but no private pool"))
    );
    for shared in [true, false] {
        let mut occupied = manager(shared, !shared);
        let visibility = if shared {
            AllocationVisibility::Shared
        } else {
            AllocationVisibility::Private
        };
        let client = occupied
            .new_client(parameters("existing", visibility, true, false))
            .unwrap();
        let error = occupied.restore(snapshot(shared, !shared)).unwrap_err();
        let expected = if shared {
            "shared pool restore failed"
        } else {
            "private pool restore failed"
        };
        assert!(matches!(&error, RestoreError::ChildError(name, _) if name == expected));
        assert!(
            matches!(error, RestoreError::ChildError(_, cause) if matches!(cause.as_ref(), RestoreError::InvalidSavedState(source) if source.to_string().contains("pool must be empty to restore")))
        );
        let block = client.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
        assert_eq!(
            block.pfns(),
            if shared {
                &[2, 3, 4, 5]
            } else {
                &[20, 21, 22, 23]
            }
        );
    }
}

// Test: Restore an empty snapshot into each combination of newly available pools, including no pools.
// Expected: Adding pools after the snapshot is permitted, validation succeeds, and every new pool exposes its full original capacity without pending allocations.
#[test]
fn absent_snapshot_pools_can_be_added_without_pending_allocations() {
    for shared in [false, true] {
        for private in [false, true] {
            let mut manager = manager(shared, private);
            manager.restore(snapshot(false, false)).unwrap();
            manager.validate_restore().unwrap();
            for (enabled, visibility, expected) in [
                (shared, AllocationVisibility::Shared, &[2, 3, 4, 5]),
                (private, AllocationVisibility::Private, &[20, 21, 22, 23]),
            ] {
                if enabled {
                    let client = manager
                        .new_client(parameters("new-device", visibility, true, false))
                        .unwrap();
                    assert!(client.attach_pending_buffers().unwrap().is_empty());
                    assert_eq!(
                        client.allocate_dma_buffer(4 * PAGE_SIZE).unwrap().pfns(),
                        expected
                    );
                }
            }
        }
    }
}
