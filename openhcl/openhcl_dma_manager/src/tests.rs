// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use page_pool_alloc::TestMapper;
use test_with_tracing::test;

mod restore_tests;

const PAGE_SIZE: usize = 4096;

fn manager(shared: bool, private: bool) -> OpenhclDmaManager {
    let pool = |start| {
        PagePool::new(
            &[MemoryRange::from_4k_gpn_range(start..start + 4)],
            TestMapper::new(32).unwrap(),
        )
        .unwrap()
    };
    let shared_pool = shared.then(|| pool(2));
    let private_pool = private.then(|| pool(20));
    OpenhclDmaManager {
        inner: Arc::new(DmaManagerInner {
            shared_spawner: shared_pool.as_ref().map(PagePool::allocator_spawner),
            private_spawner: private_pool.as_ref().map(PagePool::allocator_spawner),
            lower_vtl: None,
        }),
        shared_pool,
        private_pool,
    }
}

fn parameters(
    name: &str,
    visibility: AllocationVisibility,
    persistent: bool,
    vtl0: bool,
) -> DmaClientParameters {
    DmaClientParameters {
        device_name: name.into(),
        lower_vtl_policy: if vtl0 {
            LowerVtlPermissionPolicy::Vtl0
        } else {
            LowerVtlPermissionPolicy::Any
        },
        allocation_visibility: visibility,
        persistent_allocations: persistent,
    }
}

fn client_error(manager: &OpenhclDmaManager, params: DmaClientParameters) -> anyhow::Error {
    match manager.new_client(params) {
        Ok(_) => panic!("client creation unexpectedly succeeded"),
        Err(error) => error,
    }
}

// Test: Request shared DMA for all persistence/lower-VTL policies while both shared and private pools exist.
// Expected: Shared visibility always selects the shared PFNs, does not require a hypercall service, enforces unique live device names, and releases pages and names for reuse.
#[test]
fn shared_visibility_uses_shared_pool_for_every_permission_and_persistence_policy() {
    let manager = manager(true, true);
    for persistent in [false, true] {
        for vtl0 in [false, true] {
            let client = manager
                .new_client(parameters(
                    "shared",
                    AllocationVisibility::Shared,
                    persistent,
                    vtl0,
                ))
                .unwrap();
            let block = client.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
            assert_eq!(block.pfns(), &[2, 3, 4, 5]);
            assert_eq!(block.len(), 4 * PAGE_SIZE);
            let mut bytes = [0xff; 8];
            block.read_at(0, &mut bytes);
            assert_eq!(bytes, [0; 8]);
            block.write_at(PAGE_SIZE - 2, &[1, 0x80, 0, 0xff]);
            let mut cross_page = [0; 4];
            block.read_at(PAGE_SIZE - 2, &mut cross_page);
            assert_eq!(cross_page, [1, 0x80, 0, 0xff]);
            let error = client_error(
                &manager,
                parameters("shared", AllocationVisibility::Shared, persistent, vtl0),
            );
            assert_eq!(error.to_string(), "failed to create shared allocator");
            assert!(error.root_cause().to_string().contains("already in use"));
        }
    }
    let private = manager
        .new_client(parameters(
            "private",
            AllocationVisibility::Private,
            true,
            false,
        ))
        .unwrap();
    assert_eq!(
        private.allocate_dma_buffer(4 * PAGE_SIZE).unwrap().pfns(),
        &[20, 21, 22, 23]
    );
}

// Test: Request unavailable shared/private-persistent pools and VTL0 access to private memory without a lower-VTL service.
// Expected: Each unsupported policy reports its specific error rather than falling back to memory with the wrong visibility, and failed creation releases any reserved device name.
#[test]
fn unavailable_visibility_and_lower_vtl_policies_fail_without_fallback() {
    for available_private in [false, true] {
        let manager = manager(false, available_private);
        for persistent in [false, true] {
            for vtl0 in [false, true] {
                assert_eq!(
                    client_error(
                        &manager,
                        parameters("shared", AllocationVisibility::Shared, persistent, vtl0)
                    )
                    .to_string(),
                    "no sources available for shared visibility"
                );
            }
        }
    }
    let empty = manager(true, false);
    for vtl0 in [false, true] {
        assert_eq!(
            client_error(
                &empty,
                parameters("private", AllocationVisibility::Private, true, vtl0)
            )
            .to_string(),
            "no sources available for private persistent allocations"
        );
    }
    let manager = manager(true, true);
    for persistent in [false, true] {
        assert_eq!(
            client_error(
                &manager,
                parameters("private", AllocationVisibility::Private, persistent, true)
            )
            .to_string(),
            "lower vtl not available on hardware isolated platforms"
        );
    }
    let client = manager
        .new_client(parameters(
            "private",
            AllocationVisibility::Private,
            true,
            false,
        ))
        .unwrap();
    assert_eq!(
        client.allocate_dma_buffer(4 * PAGE_SIZE).unwrap().pfns(),
        &[20, 21, 22, 23]
    );
}

// Test: Construct an empty manager through the public constructor for each hardware-isolation policy, then save/restore and create clients through its spawner.
// Expected: Empty hardware-isolated configurations require no device access, accept an empty restore, reject missing persistent/shared sources and lower-VTL requests, and retain nonpersistent private client semantics.
#[test]
fn empty_hardware_isolation_configurations_need_no_hypervisor_device() {
    use vmcore::save_restore::SaveRestore;

    for isolation in [
        virt::IsolationType::Snp,
        virt::IsolationType::Tdx,
        virt::IsolationType::Cca,
    ] {
        let mut manager = OpenhclDmaManager::new(&[], &[], 0, isolation).unwrap();
        let state = manager.save().unwrap();
        manager.restore(state).unwrap();
        manager.validate_restore().unwrap();
        assert_eq!(
            client_error(
                &manager,
                parameters("shared", AllocationVisibility::Shared, false, false)
            )
            .to_string(),
            "no sources available for shared visibility"
        );
        assert_eq!(
            client_error(
                &manager,
                parameters("private", AllocationVisibility::Private, true, false)
            )
            .to_string(),
            "no sources available for private persistent allocations"
        );
        assert_eq!(
            client_error(
                &manager,
                parameters("lower-vtl", AllocationVisibility::Private, false, true)
            )
            .to_string(),
            "lower vtl not available on hardware isolated platforms"
        );
        let spawner = manager.client_spawner();
        drop(manager);
        let transient = spawner
            .new_client(parameters(
                "private",
                AllocationVisibility::Private,
                false,
                false,
            ))
            .unwrap();
        assert!(
            transient
                .attach_pending_buffers()
                .unwrap_err()
                .to_string()
                .contains("not supported with locked memory")
        );
    }
}

// Test: Create transient private clients even when a private persistent pool exists, including duplicate device names.
// Expected: They use non-restorable locked-memory semantics without consuming pool capacity or names, reject invalid buffer lengths, and leave the full persistent pool available.
#[test]
fn transient_private_clients_do_not_consume_persistent_pool_capacity_or_identity() {
    let manager = manager(true, true);
    let first = manager
        .new_client(parameters(
            "same-device",
            AllocationVisibility::Private,
            false,
            false,
        ))
        .unwrap();
    let _second = manager
        .new_client(parameters(
            "same-device",
            AllocationVisibility::Private,
            false,
            false,
        ))
        .unwrap();
    assert!(
        first
            .attach_pending_buffers()
            .unwrap_err()
            .to_string()
            .contains("not supported with locked memory")
    );
    assert_eq!(
        first.allocate_dma_buffer(1).unwrap_err().to_string(),
        "not a page-size multiple"
    );
    let persistent = manager
        .new_client(parameters(
            "same-device",
            AllocationVisibility::Private,
            true,
            false,
        ))
        .unwrap();
    let block = persistent.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
    assert_eq!(block.pfns(), &[20, 21, 22, 23]);
    let error = client_error(
        &manager,
        parameters("same-device", AllocationVisibility::Private, true, false),
    );
    assert_eq!(error.to_string(), "failed to create private allocator");
    assert!(error.root_cause().to_string().contains("already in use"));
}

// Test: Clone a client spawner, drop its manager, then allocate through one clone and try the same device name through another.
// Expected: Spawners retain the actual pools and common identity registry, allocations remain functional without the manager, and a released name can be reused without freeing outstanding buffers early.
#[test]
fn cloned_spawners_keep_pools_and_device_identity_alive_after_manager_drop() {
    let manager = manager(true, true);
    let first = manager.client_spawner();
    let second = first.clone();
    drop(manager);
    let client = first
        .new_client(parameters(
            "retained",
            AllocationVisibility::Shared,
            true,
            false,
        ))
        .unwrap();
    let block = client.allocate_dma_buffer(2 * PAGE_SIZE).unwrap();
    assert_eq!(block.pfns(), &[2, 3]);
    assert!(
        second
            .new_client(parameters(
                "retained",
                AllocationVisibility::Shared,
                true,
                false
            ))
            .is_err()
    );
    drop(client);
    drop(first);
    let client = second
        .new_client(parameters(
            "retained",
            AllocationVisibility::Shared,
            true,
            false,
        ))
        .unwrap();
    let next = client.allocate_dma_buffer(2 * PAGE_SIZE).unwrap();
    assert_eq!(next.pfns(), &[4, 5]);
    block.write_at(PAGE_SIZE - 1, &[0x81, 0xfe]);
    let mut bytes = [0; 2];
    block.read_at(PAGE_SIZE - 1, &mut bytes);
    assert_eq!(bytes, [0x81, 0xfe]);
    assert!(client.allocate_dma_buffer(PAGE_SIZE).is_err());
    drop(block);
    assert_eq!(
        client.allocate_dma_buffer(2 * PAGE_SIZE).unwrap().pfns(),
        &[2, 3]
    );
}

// Test: Exhaust shared DMA while private capacity remains, then exhaust private DMA after freeing shared capacity.
// Expected: Neither client falls back across visibility pools, and failed allocations preserve live private bytes and reusable shared capacity.
#[test]
fn exhausted_dma_clients_never_borrow_capacity_from_other_visibility_pool() {
    let manager = manager(true, true);
    let shared = manager
        .new_client(parameters(
            "paired",
            AllocationVisibility::Shared,
            true,
            false,
        ))
        .unwrap();
    let private = manager
        .new_client(parameters(
            "paired",
            AllocationVisibility::Private,
            true,
            false,
        ))
        .unwrap();
    let shared_block = shared.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
    assert_eq!(shared_block.pfns(), &[2, 3, 4, 5]);
    shared_block.write_at(0, b"shared");
    let error = shared.allocate_dma_buffer(PAGE_SIZE).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<page_pool_alloc::Error>(),
        Some(page_pool_alloc::Error::PagePoolOutOfMemory { size: 1, .. })
    ));
    let private_block = private.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
    assert_eq!(private_block.pfns(), &[20, 21, 22, 23]);
    private_block.write_at(0, b"private");
    let mut shared_bytes = [0; 6];
    shared_block.read_at(0, &mut shared_bytes);
    assert_eq!(&shared_bytes, b"shared");
    drop(shared_block);
    let error = private.allocate_dma_buffer(PAGE_SIZE).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<page_pool_alloc::Error>(),
        Some(page_pool_alloc::Error::PagePoolOutOfMemory { size: 1, .. })
    ));
    let reused = shared.allocate_dma_buffer(4 * PAGE_SIZE).unwrap();
    assert_eq!(reused.pfns(), &[2, 3, 4, 5]);
    reused.read_at(0, &mut shared_bytes);
    assert_eq!(shared_bytes, [0; 6]);
    let mut private_bytes = [0; 7];
    private_block.read_at(0, &mut private_bytes);
    assert_eq!(&private_bytes, b"private");
}
