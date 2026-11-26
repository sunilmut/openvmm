// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for VMGS files.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::kind::DiskHandleKind;
use vm_resource::kind::NonVolatileStoreKind;
use vmgs_format::FileId;

/// A handle to an individual file within a VMGS file.
#[derive(MeshPayload)]
pub struct VmgsFileHandle {
    /// The file ID.
    ///
    /// FUTURE: figure out how to give this the nice type.
    pub file_id: u32,
    /// Whether the file is encrypted.
    pub encrypted: bool,
}

impl VmgsFileHandle {
    /// Returns a new handle to the given file.
    pub fn new(file_id: FileId, encrypted: bool) -> Self {
        Self {
            file_id: file_id.0,
            encrypted,
        }
    }
}

impl ResourceId<NonVolatileStoreKind> for VmgsFileHandle {
    const ID: &'static str = "vmgs";
}

/// Virtual machine guest state resource
#[derive(MeshPayload, Debug)]
pub enum VmgsResource {
    /// Use disk to store guest state
    Disk(VmgsDisk),
    /// Use disk to store guest state, reformatting if corrupted.
    ReprovisionOnFailure(VmgsDisk),
    /// Format and use disk to store guest state
    ReprovisionSingle(VmgsDisk),
    /// Store guest state in memory
    Ephemeral,
}

impl VmgsResource {
    /// get the encryption policy (returns None for ephemeral guest state)
    pub fn encryption_policy(&self) -> GuestStateEncryptionPolicy {
        match self {
            VmgsResource::Disk(vmgs)
            | VmgsResource::ReprovisionOnFailure(vmgs)
            | VmgsResource::ReprovisionSingle(vmgs) => vmgs.encryption_policy,
            VmgsResource::Ephemeral => GuestStateEncryptionPolicy::None(true),
        }
    }
}

/// VMGS disk resource
#[derive(MeshPayload, Debug)]
pub struct VmgsDisk {
    /// Backing disk
    pub disk: Resource<DiskHandleKind>,
    /// Guest state encryption policy
    pub encryption_policy: GuestStateEncryptionPolicy,
}

/// Guest state encryption policy
///
/// See detailed comments in `get_protocol`
#[derive(MeshPayload, Debug, Clone, Copy)]
pub enum GuestStateEncryptionPolicy {
    /// Use the best encryption available, allowing fallback.
    Auto,
    /// Prefer (or require, if strict) no encryption.
    None(bool),
    /// Prefer (or require, if strict) GspById.
    GspById(bool),
    /// Prefer (or require, if strict) GspKey.
    GspKey(bool),
}

impl GuestStateEncryptionPolicy {
    /// whether to use strict encryption policy
    pub fn is_strict(&self) -> bool {
        match self {
            GuestStateEncryptionPolicy::Auto => false,
            GuestStateEncryptionPolicy::None(strict)
            | GuestStateEncryptionPolicy::GspById(strict)
            | GuestStateEncryptionPolicy::GspKey(strict) => *strict,
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use test_with_tracing::test;

    #[derive(MeshPayload)]
    struct BackingDisk {
        marker: u64,
    }

    impl ResourceId<DiskHandleKind> for BackingDisk {
        const ID: &'static str = "vmgs-contract-disk";
    }

    fn transport<T: MeshPayload + Send + 'static>(value: T) -> T {
        let (bytes, resources) = mesh::Message::new(value).serialize();
        mesh::Message::serialized(&bytes, resources)
            .parse()
            .unwrap()
    }

    // Test: Transport all disk provisioning modes and encryption preferences,
    //       including strict and fallback policies, through actual mesh bytes.
    // Expected: Formatting intent, backing resource identity, policy family
    //       and strictness remain distinct; ephemeral storage requires none.
    #[test]
    fn provisioning_and_encryption_policies_survive_transport() {
        use GuestStateEncryptionPolicy as Policy;

        for policy in [
            Policy::Auto,
            Policy::None(false),
            Policy::None(true),
            Policy::GspById(false),
            Policy::GspById(true),
            Policy::GspKey(false),
            Policy::GspKey(true),
        ] {
            let identity = |policy| match policy {
                Policy::Auto => (0, false),
                Policy::None(strict) => (1, strict),
                Policy::GspById(strict) => (2, strict),
                Policy::GspKey(strict) => (3, strict),
            };
            let expected = identity(policy);
            for mode in 0..3 {
                let disk = VmgsDisk {
                    disk: Resource::new(BackingDisk {
                        marker: 0x1234_5678_9abc_def0,
                    }),
                    encryption_policy: policy,
                };
                let resource = match mode {
                    0 => VmgsResource::Disk(disk),
                    1 => VmgsResource::ReprovisionOnFailure(disk),
                    2 => VmgsResource::ReprovisionSingle(disk),
                    _ => unreachable!(),
                };
                let decoded: VmgsResource = transport(resource);
                assert_eq!(identity(decoded.encryption_policy()), expected);
                assert_eq!(decoded.encryption_policy().is_strict(), expected.1);
                let (decoded_mode, disk) = match decoded {
                    VmgsResource::Disk(disk) => (0, disk),
                    VmgsResource::ReprovisionOnFailure(disk) => (1, disk),
                    VmgsResource::ReprovisionSingle(disk) => (2, disk),
                    VmgsResource::Ephemeral => panic!("disk policy became ephemeral"),
                };
                assert_eq!(decoded_mode, mode);
                assert_eq!(disk.disk.id(), "vmgs-contract-disk");
                assert_eq!(identity(disk.encryption_policy), expected);
            }
        }
        let ephemeral: VmgsResource = transport(VmgsResource::Ephemeral);
        assert!(matches!(ephemeral, VmgsResource::Ephemeral));
        assert!(matches!(ephemeral.encryption_policy(), Policy::None(true)));
        assert!(ephemeral.encryption_policy().is_strict());
    }

    // Test: Transport encrypted and plain per-file handles, including future
    //       opaque IDs and the highest current table slot.
    // Expected: The receiver gets the complete unsigned ID and encryption
    //       selection without truncation, defaulting or remapping.
    #[test]
    fn file_handle_transport_preserves_opaque_id_and_encryption() {
        for id in [
            FileId::FILE_TABLE,
            FileId::TPM_NVRAM,
            FileId::EXTENDED_FILE_TABLE,
            FileId(0x8000_0042),
            FileId(u32::MAX),
        ] {
            for encrypted in [false, true] {
                let handle: VmgsFileHandle = transport(VmgsFileHandle::new(id, encrypted));
                assert_eq!(handle.file_id, id.0);
                assert_eq!(handle.encrypted, encrypted);
            }
        }
    }
}
