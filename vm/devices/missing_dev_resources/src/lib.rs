// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for a device that ignores accesses to specified regions.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use std::ops::RangeInclusive;
use vm_resource::ResourceId;
use vm_resource::kind::ChipsetDeviceHandleKind;

/// A handle to a device that ignores accesses to specified regions.
#[derive(MeshPayload, Default)]
pub struct MissingDevHandle {
    /// The port I/O regions ignored by this device, `(name, start, end_inclusive)`.
    pub pio: Vec<(String, u16, u16)>,
    /// The MMIO regions ignored by this device, `(name, start, end_inclusive)`.
    pub mmio: Vec<(String, u64, u64)>,
}

impl ResourceId<ChipsetDeviceHandleKind> for MissingDevHandle {
    const ID: &'static str = "missing-dev";
}

impl MissingDevHandle {
    /// Create an empty instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a PIO region to the device.
    pub fn claim_pio(mut self, region_name: impl Into<String>, range: RangeInclusive<u16>) -> Self {
        self.pio
            .push((region_name.into(), *range.start(), *range.end()));
        self
    }

    /// Add an MMIO region to the device.
    pub fn claim_mmio(
        mut self,
        region_name: impl Into<String>,
        range: RangeInclusive<u64>,
    ) -> Self {
        self.mmio
            .push((region_name.into(), *range.start(), *range.end()));
        self
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use test_with_tracing::test;

    fn transport(handle: MissingDevHandle) -> MissingDevHandle {
        let (bytes, resources) = mesh::Message::new(handle).serialize();
        mesh::Message::serialized(&bytes, resources)
            .parse()
            .unwrap()
    }

    // Test: Transport interleaved ignored-port and MMIO claims with singleton,
    //       multibyte and full-width boundary addresses and owned/borrowed names.
    // Expected: Both address spaces retain independent insertion order, exact
    //       inclusive endpoints and UTF-8 labels without truncation or merging.
    #[test]
    fn mixed_claims_preserve_space_order_names_and_inclusive_bounds() {
        let handle = MissingDevHandle::new()
            .claim_pio("last-port", u16::MAX..=u16::MAX)
            .claim_mmio("above-4G", 0x1_0000_1234..=0x1_0000_123b)
            .claim_pio(String::from("index/data"), 0x2e..=0x2f)
            .claim_mmio(String::from("末端"), u64::MAX..=u64::MAX)
            .claim_pio("first-port", 0..=0)
            .claim_mmio("first-byte", 0..=0);
        let decoded = transport(handle);
        assert_eq!(
            decoded.pio,
            [
                ("last-port".to_owned(), 0xffff, 0xffff),
                ("index/data".to_owned(), 0x2e, 0x2f),
                ("first-port".to_owned(), 0, 0),
            ]
        );
        assert_eq!(
            decoded.mmio,
            [
                ("above-4G".to_owned(), 0x1_0000_1234, 0x1_0000_123b),
                (
                    "末端".to_owned(),
                    0xffff_ffff_ffff_ffff,
                    0xffff_ffff_ffff_ffff
                ),
                ("first-byte".to_owned(), 0, 0),
            ]
        );
    }

    // Test: Serialize empty and one-address-space-only device descriptions.
    // Expected: Decoding never synthesizes a claim at address zero or leaks
    //       claims into the omitted space when its repeated field is absent.
    #[test]
    fn absent_claim_lists_stay_empty_on_transport() {
        let empty = transport(MissingDevHandle::new());
        assert!(empty.pio.is_empty());
        assert!(empty.mmio.is_empty());

        let pio = transport(MissingDevHandle::new().claim_pio("delay", 0xed..=0xed));
        assert_eq!(pio.pio, [("delay".to_owned(), 0xed, 0xed)]);
        assert!(pio.mmio.is_empty());

        let mmio = transport(
            MissingDevHandle::new().claim_mmio("register", 0x1_0000_0000..=0x1_0000_0007),
        );
        assert!(mmio.pio.is_empty());
        assert_eq!(
            mmio.mmio,
            [("register".to_owned(), 0x1_0000_0000, 0x1_0000_0007)]
        );
    }
}
