// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A generic, read-only PCI Capability (backed by an [`IntoBytes`] type).

use super::PciCapability;
use crate::spec::caps::CapabilityId;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use inspect::Inspect;
use std::fmt::Debug;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Helper to define a read-only [`PciCapability`] from an [`IntoBytes`] type.
#[derive(Debug)]
pub struct ReadOnlyCapability<T> {
    label: String,
    capability_id: CapabilityId,
    data: T,
}

impl<T: IntoBytes + Immutable + KnownLayout> ReadOnlyCapability<T> {
    /// Create a new [`ReadOnlyCapability`] with VENDOR_SPECIFIC capability ID
    pub fn new(label: impl Into<String>, data: T) -> Self {
        Self {
            label: label.into(),
            capability_id: CapabilityId::VENDOR_SPECIFIC,
            data,
        }
    }

    /// Create a new [`ReadOnlyCapability`] with a specific capability ID
    pub fn new_with_capability_id(
        label: impl Into<String>,
        capability_id: CapabilityId,
        data: T,
    ) -> Self {
        Self {
            label: label.into(),
            capability_id,
            data,
        }
    }
}

impl<T: Debug> Inspect for ReadOnlyCapability<T> {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("label", &self.label)
            .field("capability_id", format!("0x{:02X}", self.capability_id.0))
            .display_debug("data", &self.data);
    }
}

impl<T> PciCapability for ReadOnlyCapability<T>
where
    T: IntoBytes + Send + Sync + Debug + Immutable + KnownLayout + 'static,
{
    fn label(&self) -> &str {
        &self.label
    }

    fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    fn len(&self) -> usize {
        size_of::<T>()
    }

    fn read(&self, offset: u16, mut value: ByteEnabledDwordRead<'_>) {
        let dword_value = if offset as usize + 4 <= self.len() {
            let offset = offset.into();
            u32::from_ne_bytes(self.data.as_bytes()[offset..offset + 4].try_into().unwrap())
        } else {
            !0
        };
        value.set(dword_value);
    }

    fn write(&mut self, offset: u16, val: ByteEnabledDwordWrite) {
        tracelimit::warn_ratelimited!(
            label = ?self.label,
            ?offset,
            ?val,
            "write to read-only capability"
        );
    }

    fn reset(&mut self) {}
}

mod save_restore {
    use super::*;
    use vmcore::save_restore::NoSavedState;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    // This is a noop impl, as the capability is (by definition) read only.
    impl<T> SaveRestore for ReadOnlyCapability<T> {
        type SavedState = NoSavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            Ok(NoSavedState)
        }

        fn restore(&mut self, NoSavedState: Self::SavedState) -> Result<(), RestoreError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{read_cap_u32, write_cap_u32};
    use test_with_tracing::test;
    use vmcore::save_restore::SaveRestore;

    // Test: Read vendor/custom-ID capabilities through writes, reset, and checkpoint restore.
    // Expected: Payload words and identity stay intact; reads beyond the payload return all ones.
    #[test]
    fn payload_and_identity_remain_read_only_across_lifecycle_operations() {
        let payload = [0x09u8, 0, 0x11, 0x22, 0xa1, 0xb2, 0xc3, 0xd4];
        for (mut capability, expected_id) in [
            (
                ReadOnlyCapability::new("vendor", payload),
                CapabilityId::VENDOR_SPECIFIC,
            ),
            (
                ReadOnlyCapability::new_with_capability_id("custom", CapabilityId(0xab), payload),
                CapabilityId(0xab),
            ),
        ] {
            assert_eq!(capability.capability_id(), expected_id);
            assert_eq!(capability.len(), 8);
            assert_eq!(read_cap_u32(&capability, 0), 0x22110009);
            assert_eq!(read_cap_u32(&capability, 4), 0xd4c3b2a1);
            assert_eq!(read_cap_u32(&capability, 8), u32::MAX);
            assert_eq!(read_cap_u32(&capability, 0xfffc), u32::MAX);
            let saved = capability.save().unwrap();
            for offset in [0, 4, 8] {
                write_cap_u32(&mut capability, offset, u32::MAX);
            }
            assert_eq!(read_cap_u32(&capability, 0), 0x22110009);
            assert_eq!(read_cap_u32(&capability, 4), 0xd4c3b2a1);
            capability.reset();
            capability.restore(saved).unwrap();
            assert_eq!(read_cap_u32(&capability, 0), 0x22110009);
            assert_eq!(read_cap_u32(&capability, 4), 0xd4c3b2a1);
            assert_eq!(capability.capability_id(), expected_id);
        }
    }
}
