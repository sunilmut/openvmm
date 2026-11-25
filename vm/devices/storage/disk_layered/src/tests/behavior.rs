// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::DiskLayerMetadata;
use crate::InvalidLayer;
use crate::InvalidLayeredDisk;
use crate::LayerAttach;
use disk_backend::Disk;
use test_with_tracing::test;

// Configure an ordinary sparse layer without caching or write-through.
fn sparse(sectors: u64) -> LayerConfiguration {
    LayerConfiguration {
        layer: DiskLayer::new(Arc::new(TestLayer::new(sectors))),
        read_cache: false,
        write_through: false,
    }
}

// Test: Wrap a complete disk as a layer, then write, read, flush, and discard.
// Expected: Data and capabilities pass through, flush reaches storage, and discard reads zero.
#[async_test]
async fn full_disk_layer_forwards_io_flush_and_discard() {
    let backing = Arc::new(TestLayer::new(8));
    let inner = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            layer: DiskLayer::new(backing.clone()),
            read_cache: false,
            write_through: false,
        }],
    )
    .await
    .unwrap();
    let disk = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            layer: DiskLayer::from_disk(Disk::new(inner).unwrap()),
            read_cache: false,
            write_through: false,
        }],
    )
    .await
    .unwrap();
    assert_eq!(disk.sector_count(), 8);
    assert_eq!(disk.sector_size(), 512);
    assert_eq!(disk.physical_sector_size(), 512);
    assert!(!disk.is_read_only() && !disk.is_fua_respected());
    let mut mem = GuestMemory::allocate(512);
    let buffers = OwnedRequestBuffers::linear(0, 512, true);
    mem.inner_buf_mut().unwrap().fill(0x74);
    disk.write_vectored(&buffers.buffer(&mem), 2, true)
        .await
        .unwrap();
    let flushes = backing.flushes.load(Ordering::SeqCst);
    disk.sync_cache().await.unwrap();
    assert_eq!(backing.flushes.load(Ordering::SeqCst), flushes + 1);
    mem.inner_buf_mut().unwrap().fill(0);
    disk.read_vectored(&buffers.buffer(&mem), 2).await.unwrap();
    assert_eq!(&mem.inner_buf_mut().unwrap()[..512], &[0x74; 512]);
    disk.unmap(2, 1, false).await.unwrap();
    mem.inner_buf_mut().unwrap().fill(0xff);
    disk.read_vectored(&buffers.buffer(&mem), 2).await.unwrap();
    assert_eq!(&mem.inner_buf_mut().unwrap()[..512], &[0; 512]);
}

// Test: Write and flush through a cache and its backing layer above another parent.
// Expected: Both write-path layers change and flush; the parent and ignored discard do not.
#[async_test]
async fn write_through_and_flush_stop_at_the_first_non_through_layer() {
    let layers = std::array::from_fn::<_, 3, _>(|_| Arc::new(TestLayer::new(8)));
    let disk = LayeredDisk::new(
        false,
        layers
            .iter()
            .enumerate()
            .map(|(i, layer)| LayerConfiguration {
                layer: DiskLayer::new(layer.clone()),
                read_cache: false,
                write_through: i == 0,
            })
            .collect(),
    )
    .await
    .unwrap();
    let mut mem = GuestMemory::allocate(512);
    mem.inner_buf_mut().unwrap().fill(0x39);
    let buffers = OwnedRequestBuffers::linear(0, 512, true);
    disk.write_vectored(&buffers.buffer(&mem), 1, false)
        .await
        .unwrap();
    disk.sync_cache().await.unwrap();
    disk.unmap(1, 1, false).await.unwrap();
    for layer in &layers[..2] {
        assert_eq!(&layer.sectors.lock()[&1].0[..], &[0x39; 512]);
        assert_eq!(layer.flushes.load(Ordering::SeqCst), 1);
    }
    assert!(layers[2].sectors.lock().is_empty());
    assert_eq!(layers[2].flushes.load(Ordering::SeqCst), 0);
}

// Test: Construct empty, invalid-sector-size, and mixed-sector-size stacks.
// Expected: Each failure reports its precise validation error and offending layer.
#[async_test]
async fn invalid_geometry_reports_the_offending_layer() {
    assert!(matches!(
        LayeredDisk::new(false, vec![]).await,
        Err(InvalidLayeredDisk::NoLayers)
    ));
    for size in [0, 513] {
        let mut layer = TestLayer::new(8);
        layer.sector_size = size;
        let result = LayeredDisk::new(
            false,
            vec![LayerConfiguration {
                layer: DiskLayer::new(Arc::new(layer)),
                read_cache: false,
                write_through: false,
            }],
        )
        .await;
        assert!(
            matches!(result, Err(InvalidLayeredDisk::Layer(0, InvalidLayer::InvalidSectorSize(found))) if found == size)
        );
    }
    let mut layer = TestLayer::new(8);
    layer.sector_size = 1024;
    let result = LayeredDisk::new(
        false,
        vec![
            LayerConfiguration {
                layer: DiskLayer::new(Arc::new(layer)),
                read_cache: false,
                write_through: false,
            },
            sparse(8),
        ],
    )
    .await;
    assert!(matches!(
        result,
        Err(InvalidLayeredDisk::Layer(
            0,
            InvalidLayer::MismatchedSectorSize {
                expected: 512,
                found: 1024
            }
        ))
    ));
}

// Test: Leave a write-through tail or put a write-through layer behind a stopping layer.
// Expected: Construction rejects the exact layer that has no usable write-through target.
#[async_test]
async fn write_through_requires_a_contiguous_prefix_and_a_final_backing_layer() {
    let result = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            write_through: true,
            ..sparse(8)
        }],
    )
    .await;
    assert!(matches!(
        result,
        Err(InvalidLayeredDisk::Layer(
            0,
            InvalidLayer::UselessWriteThrough
        ))
    ));
    let result = LayeredDisk::new(
        false,
        vec![
            sparse(8),
            LayerConfiguration {
                write_through: true,
                ..sparse(8)
            },
        ],
    )
    .await;
    assert!(matches!(
        result,
        Err(InvalidLayeredDisk::Layer(
            1,
            InvalidLayer::UselessWriteThrough
        ))
    ));
}

// Test: Use a full disk as a read cache or put a read-only disk in a writable path.
// Expected: Unsupported cache writes and read-only writes are rejected during construction.
#[async_test]
async fn full_disk_layers_enforce_cache_and_write_capabilities() {
    let inner = LayeredDisk::new(false, vec![sparse(8)]).await.unwrap();
    let result = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            layer: DiskLayer::from_disk(Disk::new(inner).unwrap()),
            read_cache: true,
            write_through: false,
        }],
    )
    .await;
    assert!(matches!(
        result,
        Err(InvalidLayeredDisk::Layer(
            0,
            InvalidLayer::ReadCacheNotSupported
        ))
    ));
    let inner = LayeredDisk::new(true, vec![sparse(8)]).await.unwrap();
    let result = LayeredDisk::new(
        false,
        vec![LayerConfiguration {
            layer: DiskLayer::from_disk(Disk::new(inner).unwrap()),
            read_cache: false,
            write_through: false,
        }],
    )
    .await;
    assert!(matches!(
        result,
        Err(InvalidLayeredDisk::Layer(0, InvalidLayer::ReadOnly))
    ));
}

struct FailedAttach;

impl LayerAttach for FailedAttach {
    type Error = std::io::Error;
    type Layer = Arc<TestLayer>;

    async fn attach(self, _: Option<DiskLayerMetadata>) -> Result<Self::Layer, Self::Error> {
        Err(std::io::Error::other("injected attach failure"))
    }
}

// Test: Attach a failing layer above a valid bottom layer.
// Expected: Construction retains both the failing layer index and its original error.
#[async_test]
async fn attach_failures_retain_layer_identity_and_backend_error() {
    let result = LayeredDisk::new(
        false,
        vec![
            LayerConfiguration {
                layer: DiskLayer::new(FailedAttach),
                read_cache: false,
                write_through: false,
            },
            sparse(8),
        ],
    )
    .await;
    let Err(InvalidLayeredDisk::Layer(0, InvalidLayer::AttachFailed(error))) = result else {
        panic!("expected the top layer's attach failure");
    };
    assert_eq!(error.to_string(), "injected attach failure");
}

// Test: Wait with the current capacity and with an outdated capacity.
// Expected: The unchanged-size wait stays pending; the outdated size returns the backing capacity.
#[async_test]
async fn resize_wait_forwards_the_callers_observed_capacity() {
    let disk = LayeredDisk::new(false, vec![sparse(8)]).await.unwrap();
    assert!(matches!(
        futures::poll!(Box::pin(disk.wait_resize(8))),
        std::task::Poll::Pending
    ));
    assert!(matches!(
        futures::poll!(Box::pin(disk.wait_resize(7))),
        std::task::Poll::Ready(8)
    ));
}
