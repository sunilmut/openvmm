// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::blk::VirtioBlkOptions;
use super::fs::VirtioFsAggregateChild;
use super::fs::VirtioFsBackend;
use super::fs::VirtioFsHandle;
use super::fs::VirtioFsWindowsOptions;
use mesh::OwnedMessage;
use test_with_tracing::test;

/// Force wire encoding instead of a lazy message's same-type unwrap.
fn transport<T: mesh::MeshPayload + Send + 'static>(value: T) -> Result<T, mesh::payload::Error> {
    OwnedMessage::serialized(OwnedMessage::new(value).serialize()).parse()
}

// Test: Transport default and explicitly overridden block queue settings.
// Expected: Defaults remain one queue/64 requests; independent overrides survive.
#[test]
fn block_queue_policies_survive_transport() -> Result<(), Box<dyn std::error::Error>> {
    let defaults = transport(VirtioBlkOptions::default())?;
    assert_eq!((defaults.queue_count, defaults.io_depth), (1, 64));

    for (queue_count, io_depth) in [(1, 1), (256, 7), (3, u16::MAX)] {
        let restored = transport(VirtioBlkOptions {
            queue_count,
            io_depth,
        })?;
        assert_eq!(
            (restored.queue_count, restored.io_depth),
            (queue_count, io_depth)
        );
    }
    Ok(())
}

// Test: Transport an aggregate filesystem with distinct per-share options.
// Expected: The tag, child order and each name/path/options association survive.
#[test]
fn aggregate_filesystem_preserves_share_associations() -> Result<(), Box<dyn std::error::Error>> {
    let restored = transport(VirtioFsHandle {
        tag: "shared-folders".into(),
        fs: VirtioFsBackend::Aggregate {
            children: vec![
                VirtioFsAggregateChild {
                    name: "first".into(),
                    root_path: "/exports/alpha".into(),
                    mount_options: "ro".into(),
                },
                VirtioFsAggregateChild {
                    name: "second".into(),
                    root_path: "/exports/beta".into(),
                    mount_options: "rw,cache=never".into(),
                },
            ],
        },
    })?;
    assert_eq!(restored.tag, "shared-folders");
    let VirtioFsBackend::Aggregate { children } = restored.fs else {
        panic!("transport changed the aggregate filesystem backend");
    };
    let shares = children
        .iter()
        .map(|child| {
            (
                child.name.as_str(),
                child.root_path.as_str(),
                child.mount_options.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        shares,
        [
            ("first", "/exports/alpha", "ro"),
            ("second", "/exports/beta", "rw,cache=never"),
        ]
    );
    Ok(())
}

// Test: Transport omitted, default host-file and shared-memory filesystem options.
// Expected: Absence differs from an explicit option, and the selected mode survives.
#[test]
fn filesystem_modes_remain_distinct() -> Result<(), Box<dyn std::error::Error>> {
    for (windows_options, expected) in [
        (None, None),
        (Some(VirtioFsWindowsOptions::default()), Some(false)),
        (
            Some(VirtioFsWindowsOptions {
                shared_mem: true,
                #[cfg(windows)]
                user_token: None,
            }),
            Some(true),
        ),
    ] {
        let restored = transport(VirtioFsHandle {
            tag: "host-share".into(),
            fs: VirtioFsBackend::HostFs {
                root_path: "/exports/root".into(),
                mount_options: "ro".into(),
                windows_options,
            },
        })?;
        let VirtioFsBackend::HostFs {
            root_path,
            mount_options,
            windows_options,
        } = restored.fs
        else {
            panic!("transport changed the host filesystem backend");
        };
        assert_eq!(restored.tag, "host-share");
        assert_eq!(root_path, "/exports/root");
        assert_eq!(mount_options, "ro");
        assert_eq!(windows_options.map(|options| options.shared_mem), expected);
    }
    Ok(())
}

// Test: Transport a connected vhost-user endpoint and independent queue sizes.
// Expected: The restored endpoint reaches its original peer and closes on drop.
#[cfg(unix)]
#[test]
fn vhost_endpoint_preserves_connection_and_ownership() -> Result<(), Box<dyn std::error::Error>> {
    use super::vhost_user::VhostUserGenericHandle;
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let (frontend, mut peer) = UnixStream::pair()?;
    peer.set_nonblocking(true)?;
    let restored = transport(VhostUserGenericHandle {
        socket: frontend.into(),
        device_id: 2,
        queue_sizes: vec![128, 512, 1024],
    })?;
    assert_eq!(restored.device_id, 2);
    assert_eq!(restored.queue_sizes, [128, 512, 1024]);

    let mut endpoint = UnixStream::from(restored.socket);
    endpoint.write_all(b"vhost!")?;
    let mut data = [0; 6];
    peer.read_exact(&mut data)?;
    assert_eq!(&data, b"vhost!");

    drop(endpoint);
    assert_eq!(peer.read(&mut [0])?, 0);
    Ok(())
}
