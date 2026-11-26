// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::layer::RamDiskLayerHandle;
use mesh::OwnedMessage;
use pal_async::async_test;
use std::convert::Infallible;
use test_with_tracing::test;
use vm_resource::CanResolveTo;
use vm_resource::ResolveResource;
use vm_resource::ResourceResolver;

#[derive(Debug, PartialEq, Eq)]
struct LayerSettings {
    len: Option<u64>,
    sector_size: Option<u32>,
}

impl CanResolveTo<LayerSettings> for DiskLayerHandleKind {
    type Input<'a> = ();
}

struct RamResolver;

impl ResolveResource<DiskLayerHandleKind, RamDiskLayerHandle> for RamResolver {
    type Output = LayerSettings;
    type Error = Infallible;

    fn resolve(&self, handle: RamDiskLayerHandle, _: ()) -> Result<LayerSettings, Infallible> {
        Ok(LayerSettings {
            len: handle.len,
            sector_size: handle.sector_size,
        })
    }
}

fn transfer(handle: LayeredDiskHandle) -> LayeredDiskHandle {
    OwnedMessage::serialized(OwnedMessage::new(handle).serialize())
        .parse()
        .unwrap()
}

// Test: Wrap a RAM layer with inherited sizing through the single-layer helper
//       and transfer its configuration through a serialized resource message.
// Expected: Exactly one RAM layer is emitted, without enabling read caching
//       or forwarding writes to a nonexistent lower layer.
#[test]
fn single_layer_preserves_default_io_policy() {
    let handle = transfer(LayeredDiskHandle::single_layer(RamDiskLayerHandle {
        len: None,
        sector_size: None,
    }));
    let [description] = &handle.layers[..] else {
        panic!("single-layer configuration did not contain exactly one layer");
    };
    assert_eq!(description.layer.id(), "ram");
    assert!(!description.read_cache);
    assert!(!description.write_through);
}

// Test: Transfer three same-type layers with distinct sizing and cache policies,
//       then resolve each opaque child through a configuration-only stub.
// Expected: Layer order, inherited versus explicit sizes, full 64-bit lengths,
//       and per-layer policies survive without being confused by identical IDs.
#[async_test]
async fn serialized_layers_keep_order_payloads_and_policies() {
    let handle = transfer(LayeredDiskHandle {
        layers: vec![
            DiskLayerDescription {
                layer: RamDiskLayerHandle {
                    len: Some(8192),
                    sector_size: Some(4096),
                }
                .into_resource(),
                read_cache: true,
                write_through: true,
            },
            DiskLayerDescription {
                layer: RamDiskLayerHandle {
                    len: None,
                    sector_size: None,
                }
                .into_resource(),
                read_cache: false,
                write_through: true,
            },
            RamDiskLayerHandle {
                len: Some(1 << 40),
                sector_size: Some(512),
            }
            .into_resource()
            .into(),
        ],
    });
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(RamResolver);
    assert_eq!(handle.layers.len(), 3);
    for (description, (len, sector_size, read_cache, write_through)) in
        handle.layers.into_iter().zip([
            (Some(8192), Some(4096), true, true),
            (None, None, false, true),
            (Some(1 << 40), Some(512), false, false),
        ])
    {
        assert_eq!(description.read_cache, read_cache);
        assert_eq!(description.write_through, write_through);
        assert_eq!(
            resolver.resolve(description.layer, ()).await.unwrap(),
            LayerSettings { len, sector_size }
        );
    }
}
