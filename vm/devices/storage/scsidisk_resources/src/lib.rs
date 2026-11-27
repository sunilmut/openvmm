// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for emulated SCSI disks.

#![forbid(unsafe_code)]

use inspect::Inspect;
use mesh::MeshPayload;
use mesh::payload::Protobuf;
use mesh::rpc::FailableRpc;
use storage_string::AsciiString;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::kind::DiskHandleKind;
use vm_resource::kind::ScsiDeviceHandleKind;

/// Resource handle for an emulated SCSI disk.
#[derive(MeshPayload)]
pub struct SimpleScsiDiskHandle {
    /// The backing disk handle.
    pub disk: Resource<DiskHandleKind>,
    /// Whether the disk is read only.
    pub read_only: bool,
    /// Parameters controlling how the SCSI emulation behaves.
    pub parameters: DiskParameters,
}

impl ResourceId<ScsiDeviceHandleKind> for SimpleScsiDiskHandle {
    const ID: &'static str = "emulated_disk";
}

/// Parameters controlling SCSI disk behavior.
///
/// These parameters are all optional. If not provided, a default will be chosen
/// based on the backing disk's capabilities.
#[derive(Debug, Default, Clone, Protobuf)]
pub struct DiskParameters {
    /// The disk ID, used in T10 identification.
    pub disk_id: Option<[u8; 16]>,
    /// Vendor/model disk information.
    pub identity: Option<DiskIdentity>,
    /// The disk's serial number.
    pub serial_number: Vec<u8>,
    /// The SCSI medium rotation rate.
    pub medium_rotation_rate: Option<u16>,
    /// The physical sector size.
    pub physical_sector_size: Option<u32>,
    /// Whether FUA is supported.
    pub fua: Option<bool>,
    /// Whether a write cache is present.
    pub write_cache: Option<bool>,
    /// The disk size to present.
    pub scsi_disk_size_in_bytes: Option<u64>,
    /// Whether ODX (copy offload) is supported.
    ///
    /// TODO: remove this, our emulator doesn't support ODX.
    pub odx: Option<bool>,
    /// Whether unmap is supported.
    pub unmap: Option<bool>,
    /// The maximum transfer length for IOs (TODO: or is it for write same?)
    pub max_transfer_length: Option<usize>,
    /// The minimum optimal number of sectors to unmap in a request.
    pub optimal_unmap_sectors: Option<u32>,
    /// Report LBA status to the guest.
    ///
    /// Note that this will always report fully mapped LBAs, since the
    /// underlying disk implementation has no mechanism to report unmapped LBAs.
    pub get_lba_status: bool,
}

/// The disk identity.
#[derive(Debug, Clone, Inspect, Protobuf)]
pub struct DiskIdentity {
    /// The vendor ID.
    pub vendor_id: AsciiString<8>,
    /// The product ID.
    pub product_id: AsciiString<16>,
    /// The product revision level.
    pub product_revision_level: AsciiString<4>,
    /// The model number.
    pub model_number: Vec<u8>, // BUGBUG: this is never used.
}

impl DiskIdentity {
    /// Returns the default disk identity, which reports a "Msft Virtual Disk
    /// 1.0".
    pub fn msft() -> Self {
        Self {
            vendor_id: (*b"Msft    ").into(),
            product_id: (*b"Virtual Disk    ").into(),
            product_revision_level: (*b"1.0 ").into(),
            model_number: Vec::new(),
        }
    }
}

/// Resource handle for an emulated SCSI DVD drive.
#[derive(MeshPayload)]
pub struct SimpleScsiDvdHandle {
    /// The backing media, or `None` for an empty DVD drive.
    pub media: Option<Resource<DiskHandleKind>>,
    /// Request channel used to update the contents of the drive.
    pub requests: Option<mesh::Receiver<SimpleScsiDvdRequest>>,
}

/// An emulated DVD drive request.
#[derive(MeshPayload)]
pub enum SimpleScsiDvdRequest {
    /// Change the media to the new backing disk.
    ChangeMedia(FailableRpc<Option<Resource<DiskHandleKind>>, ()>),
}

impl ResourceId<ScsiDeviceHandleKind> for SimpleScsiDvdHandle {
    const ID: &'static str = "emulated_dvd";
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::payload::decode;
    use mesh::payload::encode;
    use test_with_tracing::test;

    // Test: Serialize the default SCSI identity and decode it again.
    // Expected: Stable field tags and fixed-width padding survive transport.
    #[test]
    fn default_identity_preserves_its_wire_layout_and_padding() {
        let encoded = encode(DiskIdentity::msft());
        assert_eq!(
            encoded,
            b"\x0a\x08Msft    \x12\x10Virtual Disk    \x1a\x041.0 "
        );
        let restored: DiskIdentity = decode(&encoded).unwrap();
        assert_eq!(restored.vendor_id.as_bytes(), b"Msft    ");
        assert_eq!(restored.product_id.as_bytes(), b"Virtual Disk    ");
        assert_eq!(restored.product_revision_level.as_bytes(), b"1.0 ");
        assert!(restored.model_number.is_empty());
    }

    // Test: Transport independent disk identity, geometry and feature policies.
    // Expected: Binary values and explicit false overrides remain distinct
    //       from omitted policies, with every field preserving its own value.
    #[test]
    fn disk_parameters_preserve_independent_optional_policies() {
        let parameters = DiskParameters {
            disk_id: Some([0x5a; 16]),
            identity: Some(DiskIdentity {
                vendor_id: (*b"Vendor  ").into(),
                product_id: (*b"Different Disk  ").into(),
                product_revision_level: (*b"2.1 ").into(),
                model_number: vec![0, 0xff, 1],
            }),
            serial_number: vec![0xff, 0, 0x80],
            medium_rotation_rate: Some(7_200),
            physical_sector_size: Some(4_096),
            fua: Some(false),
            write_cache: Some(true),
            scsi_disk_size_in_bytes: Some(1u64 << 40),
            odx: Some(false),
            unmap: Some(true),
            max_transfer_length: Some(65_536),
            optimal_unmap_sectors: Some(128),
            get_lba_status: true,
        };
        let restored: DiskParameters = decode(&encode(parameters)).unwrap();
        assert_eq!(restored.disk_id, Some([0x5a; 16]));
        let identity = restored.identity.unwrap();
        assert_eq!(identity.vendor_id.as_bytes(), b"Vendor  ");
        assert_eq!(identity.product_id.as_bytes(), b"Different Disk  ");
        assert_eq!(identity.product_revision_level.as_bytes(), b"2.1 ");
        assert_eq!(identity.model_number, [0, 0xff, 1]);
        assert_eq!(restored.serial_number, [0xff, 0, 0x80]);
        assert_eq!(restored.medium_rotation_rate, Some(7_200));
        assert_eq!(restored.physical_sector_size, Some(4_096));
        assert_eq!(restored.fua, Some(false));
        assert_eq!(restored.write_cache, Some(true));
        assert_eq!(restored.scsi_disk_size_in_bytes, Some(1u64 << 40));
        assert_eq!(restored.odx, Some(false));
        assert_eq!(restored.unmap, Some(true));
        assert_eq!(restored.max_transfer_length, Some(65_536));
        assert_eq!(restored.optimal_unmap_sectors, Some(128));
        assert!(restored.get_lba_status);

        let omitted: DiskParameters = decode(&encode(DiskParameters::default())).unwrap();
        assert!(omitted.fua.is_none());
        assert!(omitted.write_cache.is_none());
        assert!(omitted.odx.is_none());
        assert!(omitted.unmap.is_none());
        assert!(omitted.identity.is_none());
        assert!(omitted.serial_number.is_empty());
        assert!(!omitted.get_lba_status);
    }
}
