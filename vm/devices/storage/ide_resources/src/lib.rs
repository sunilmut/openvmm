// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Client definitions for describing IDE controller configuration.
//!
//! TODO: refactor to support `Resource`-based instantiation of IDE controllers,
//! at which point this crate name makes sense.

#![forbid(unsafe_code)]

use inspect::Inspect;
use mesh::MeshPayload;
use vm_resource::Resource;
use vm_resource::kind::DiskHandleKind;
use vm_resource::kind::ScsiDeviceHandleKind;

/// The location of an IDE device on a controller.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, MeshPayload, Inspect)]
#[inspect(display)]
pub struct IdePath {
    /// The channel number. Must be zero or one.
    pub channel: u8,
    /// The device number on the channel. Must be zero or one.
    pub drive: u8,
}

impl std::fmt::Display for IdePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.channel, self.drive)
    }
}

/// Guest media for an IDE device.
#[derive(Debug, MeshPayload)]
pub enum GuestMedia {
    /// An ATAPI drive, backed by a SCSI device.
    Dvd(Resource<ScsiDeviceHandleKind>),
    /// An ATA disk, backed by a disk.
    Disk {
        /// The backing disk.
        disk_type: Resource<DiskHandleKind>,
        /// Whether the disk is read-only.
        read_only: bool,
    },
}

/// IDE device configuration.
#[derive(Debug, MeshPayload)]
pub struct IdeDeviceConfig {
    /// The location of the device on the controller.
    pub path: IdePath,
    /// The backing media for the device.
    pub guest_media: GuestMedia,
}

/// IDE controller configuration.
#[derive(Debug, MeshPayload)]
pub struct IdeControllerConfig {
    /// Disks on the primary channel.
    pub primary_channel_disks: Vec<IdeDeviceConfig>,
    /// Disks on the secondary channel.
    pub secondary_channel_disks: Vec<IdeDeviceConfig>,
    /// The maximum queue depth for the vmbus SCSI interface.
    pub io_queue_depth: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::OwnedMessage;
    use test_with_tracing::test;
    use vm_resource::ResourceId;

    #[derive(MeshPayload)]
    struct DiskBacking;

    impl ResourceId<DiskHandleKind> for DiskBacking {
        const ID: &'static str = "ide-test-disk";
    }

    #[derive(MeshPayload)]
    struct DvdBacking;

    impl ResourceId<ScsiDeviceHandleKind> for DvdBacking {
        const ID: &'static str = "ide-test-dvd";
    }

    // Test: Transport mixed ATA/ATAPI media in all four IDE slots through mesh.
    // Expected: Channel/drive addresses, backing kinds, read-only policy and
    //       optional queue depth survive actual serialization independently.
    #[test]
    fn transports_controller_slots_and_media() {
        for io_queue_depth in [None, Some(1), Some(31)] {
            let disks = |channel| {
                (0..=1)
                    .map(|drive| IdeDeviceConfig {
                        path: IdePath { channel, drive },
                        guest_media: if drive == channel {
                            GuestMedia::Disk {
                                disk_type: Resource::new(DiskBacking),
                                read_only: channel == 1,
                            }
                        } else {
                            GuestMedia::Dvd(Resource::new(DvdBacking))
                        },
                    })
                    .collect()
            };
            let serialized = OwnedMessage::new(IdeControllerConfig {
                primary_channel_disks: disks(0),
                secondary_channel_disks: disks(1),
                io_queue_depth,
            })
            .serialize();
            let restored: IdeControllerConfig =
                OwnedMessage::serialized(serialized).parse().unwrap();

            assert_eq!(restored.io_queue_depth, io_queue_depth);
            assert_eq!(restored.primary_channel_disks.len(), 2);
            assert_eq!(restored.secondary_channel_disks.len(), 2);
            for (device, label, expected_read_only) in restored
                .primary_channel_disks
                .into_iter()
                .chain(restored.secondary_channel_disks)
                .zip(["0/0", "0/1", "1/0", "1/1"])
                .zip([Some(false), None, None, Some(true)])
                .map(|((device, label), policy)| (device, label, policy))
            {
                assert_eq!(device.path.to_string(), label);
                match (device.guest_media, expected_read_only) {
                    (
                        GuestMedia::Disk {
                            disk_type,
                            read_only,
                        },
                        Some(expected),
                    ) => {
                        assert_eq!(disk_type.id(), "ide-test-disk");
                        assert_eq!(read_only, expected);
                    }
                    (GuestMedia::Dvd(backing), None) => {
                        assert_eq!(backing.id(), "ide-test-dvd");
                    }
                    _ => panic!("media kind changed at IDE slot {label}"),
                }
            }
        }
    }

    // Test: Transport a controller with no primary devices and only a secondary
    //       slave, as can occur with sparse user-selected IDE locations.
    // Expected: Empty channels remain empty and the device is not renumbered.
    #[test]
    fn transports_sparse_secondary_channel() {
        let serialized = OwnedMessage::new(IdeControllerConfig {
            primary_channel_disks: Vec::new(),
            secondary_channel_disks: vec![IdeDeviceConfig {
                path: IdePath {
                    channel: 1,
                    drive: 1,
                },
                guest_media: GuestMedia::Dvd(Resource::new(DvdBacking)),
            }],
            io_queue_depth: None,
        })
        .serialize();
        let restored: IdeControllerConfig = OwnedMessage::serialized(serialized).parse().unwrap();
        assert!(restored.primary_channel_disks.is_empty());
        let [device] = restored.secondary_channel_disks.as_slice() else {
            panic!("sparse controller changed device count");
        };
        assert_eq!(
            device.path,
            IdePath {
                channel: 1,
                drive: 1
            }
        );
        assert!(matches!(device.guest_media, GuestMedia::Dvd(_)));
        assert_eq!(restored.io_queue_depth, None);
    }
}
