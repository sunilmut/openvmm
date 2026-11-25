// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MSI-X Capability.

use super::PciCapability;
use crate::msi::MsiRoute;
use crate::msi::MsiTarget;
use crate::spec::caps::CapabilityId;
use crate::spec::caps::msix::MsixCapabilityHeader;
use crate::spec::caps::msix::MsixTableEntryIdx;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use inspect::Inspect;
use inspect::InspectMut;
use pal_event::Event;
use parking_lot::Mutex;
use std::fmt::Debug;
use std::sync::Arc;
use vmcore::interrupt::Interrupt;
use vmcore::interrupt::InterruptTarget;

#[derive(Debug, Inspect)]
struct MsiTableLocation {
    #[inspect(hex)]
    // MSI-X table offsets are, per spec, no larger than 32 bits.
    offset: u32,
    bar: u8,
}

impl MsiTableLocation {
    fn new(bar: u8, offset: u32) -> Self {
        assert!(bar < 6);
        assert!(offset & 7 == 0);
        Self { offset, bar }
    }

    fn read_u32(&self) -> u32 {
        self.offset | self.bar as u32
    }
}

#[derive(Inspect)]
struct MsixCapability {
    count: u16,
    #[inspect(with = "|x| inspect::adhoc(|req| x.lock().inspect_mut(req))")]
    state: Arc<Mutex<MsixState>>,
    config_table_location: MsiTableLocation,
    pending_bits_location: MsiTableLocation,
}

impl PciCapability for MsixCapability {
    fn label(&self) -> &str {
        "msi-x"
    }

    fn capability_id(&self) -> CapabilityId {
        CapabilityId::MSIX
    }

    fn len(&self) -> usize {
        12
    }

    fn read(&self, offset: u16, mut value: ByteEnabledDwordRead<'_>) {
        match MsixCapabilityHeader(offset) {
            MsixCapabilityHeader::CONTROL_CAPS => {
                value.set_low_high(
                    CapabilityId::MSIX.0.into(),
                    (self.count - 1) | if self.state.lock().enabled { 0x8000 } else { 0 },
                );
            }
            MsixCapabilityHeader::OFFSET_TABLE => value.set(self.config_table_location.read_u32()),
            MsixCapabilityHeader::OFFSET_PBA => value.set(self.pending_bits_location.read_u32()),
            _ => panic!("Unreachable read offset {}", offset),
        }
    }

    fn write(&mut self, offset: u16, val: ByteEnabledDwordWrite) {
        match MsixCapabilityHeader(offset) {
            MsixCapabilityHeader::CONTROL_CAPS => {
                const MSIX_ENABLE_BIT_MASK: u32 = 0x8000_0000;
                if val.valid_mask() & MSIX_ENABLE_BIT_MASK != 0 {
                    let mut state = self.state.lock();
                    let was_enabled = state.enabled;
                    let new_enabled = (val.extract() & MSIX_ENABLE_BIT_MASK) != 0;

                    state.enabled = new_enabled;
                    if was_enabled && !new_enabled {
                        for entry in &mut state.vectors {
                            if entry.is_enabled(true) {
                                entry.msi.disable();
                            }
                        }
                    } else if new_enabled && !was_enabled {
                        for entry in &mut state.vectors {
                            if entry.is_enabled(true) {
                                entry.msi.enable(
                                    entry.state.address,
                                    entry.state.data,
                                    entry.state.is_pending,
                                );
                                entry.state.is_pending = false;
                            }
                        }
                    }
                }
            }
            MsixCapabilityHeader::OFFSET_TABLE | MsixCapabilityHeader::OFFSET_PBA => {
                tracelimit::warn_ratelimited!(
                    "Unexpected write offset {:?}",
                    MsixCapabilityHeader(offset)
                )
            }
            _ => panic!("Unreachable write offset {}", offset),
        }
    }

    fn reset(&mut self) {
        let mut state = self.state.lock();
        state.enabled = false;
        for vector in &mut state.vectors {
            vector.msi.disable();
            vector.state = EntryState::new();
        }
    }
}

#[derive(Clone, Inspect, Debug)]
pub(crate) struct MsiInterrupt(#[inspect(flatten)] Arc<Mutex<MsiInterruptInner>>);

#[derive(Inspect)]
struct MsiInterruptInner {
    #[inspect(skip)]
    target: MsiTarget,
    /// Optional kernel-mediated route for direct interrupt delivery.
    /// When present, `enable()`/`disable()` automatically program the
    /// kernel's MSI routing alongside the userspace `MsiTarget` path.
    #[inspect(skip)]
    route: Option<MsiRoute>,
    pending: bool,
    enabled: bool,
    #[inspect(hex)]
    address: u64,
    #[inspect(hex)]
    data: u32,
}

impl Debug for MsiInterruptInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsiInterruptInner")
            .field("pending", &self.pending)
            .field("enabled", &self.enabled)
            .field("address", &self.address)
            .field("data", &self.data)
            .field("has_route", &self.route.is_some())
            .finish()
    }
}

impl MsiInterruptInner {
    fn signal_msi(&self) {
        self.target.signal_msi(self.address, self.data);
    }

    fn enable_route(&self, route: &MsiRoute) {
        route.enable(self.address, self.data);
    }
}

impl MsiInterrupt {
    pub fn new(target: MsiTarget) -> Self {
        Self(Arc::new(Mutex::new(MsiInterruptInner {
            target,
            route: None,
            pending: false,
            enabled: false,
            address: 0,
            data: 0,
        })))
    }

    pub fn enable(&self, address: u64, data: u32, set_pending: bool) {
        let mut state = self.0.lock();
        state.pending |= set_pending;
        state.address = address;
        state.data = data;
        state.enabled = true;

        // Program the kernel route if present.
        if let Some(route) = &state.route {
            state.enable_route(route);
        }

        if state.pending {
            state.signal_msi();
            state.pending = false;
        }
    }

    pub fn disable(&self) {
        let mut state = self.0.lock();
        state.enabled = false;
        if let Some(route) = &state.route {
            route.disable();
        }
    }

    pub fn drain_pending(&self) -> bool {
        let mut state = self.0.lock();
        if let Some(route) = &state.route {
            state.pending |= route.consume_pending();
        }
        let was_pending = state.pending;
        state.pending = false;
        was_pending
    }

    pub fn interrupt(&self) -> Interrupt {
        Interrupt::from_target(MsiInterruptTarget(self.0.clone()))
    }
}

/// [`InterruptTarget`] for MSI-X vectors that lazily allocates an irqfd
/// route when [`event()`](InterruptTarget::event) is first called.
struct MsiInterruptTarget(Arc<Mutex<MsiInterruptInner>>);

impl InterruptTarget for MsiInterruptTarget {
    fn deliver(&self) {
        let mut state = self.0.lock();
        if state.enabled {
            state.signal_msi();
        } else {
            state.pending = true;
        }
    }

    fn event(&self) -> Option<Arc<Event>> {
        let mut state = self.0.lock();
        if let Some(route) = &state.route {
            return Some(Arc::new(route.event().clone()));
        }
        let route = match state.target.new_route() {
            Some(Ok(route)) => route,
            Some(Err(e)) => {
                tracelimit::warn_ratelimited!(error = ?e, "failed to allocate MSI route");
                return None;
            }
            None => return None,
        };
        if state.enabled {
            state.enable_route(&route);
        } else {
            route.disable();
        }
        let event = Arc::new(route.event().clone());
        state.route = Some(route);
        Some(event)
    }
}

struct MsixMessageTableEntry {
    msi: MsiInterrupt,
    state: EntryState,
}

impl InspectMut for MsixMessageTableEntry {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .hex("address", self.state.address)
            .hex("data", self.state.data)
            .hex("control", self.state.control)
            .field("enabled", self.state.control & 1 == 0)
            .field("is_pending", self.check_is_pending(true))
            // Delivery state, which can diverge from the table above (e.g. an
            // interrupt latched while masked).
            .field("msi", &self.msi);
    }
}

#[derive(Debug)]
struct EntryState {
    address: u64,
    data: u32,
    control: u32,
    is_pending: bool,
}

impl EntryState {
    fn new() -> Self {
        Self {
            address: 0,
            data: 0,
            control: 1,
            is_pending: false,
        }
    }
}

impl MsixMessageTableEntry {
    fn new(msi: MsiInterrupt) -> Self {
        Self {
            msi,
            state: EntryState::new(),
        }
    }

    fn read_u32(&self, offset: u64) -> u32 {
        match MsixTableEntryIdx(offset) {
            MsixTableEntryIdx::MSG_ADDR_LO => self.state.address as u32,
            MsixTableEntryIdx::MSG_ADDR_HI => (self.state.address >> 32) as u32,
            MsixTableEntryIdx::MSG_DATA => self.state.data,
            MsixTableEntryIdx::VECTOR_CTL => self.state.control,
            _ => panic!("Unexpected read offset {}", offset),
        }
    }

    fn write_u32(&mut self, offset: u64, val: u32) {
        match MsixTableEntryIdx(offset) {
            MsixTableEntryIdx::MSG_ADDR_LO => {
                self.state.address = (self.state.address & 0xffffffff00000000) | val as u64
            }
            MsixTableEntryIdx::MSG_ADDR_HI => {
                self.state.address = (val as u64) << 32 | self.state.address & 0xffffffff
            }
            MsixTableEntryIdx::MSG_DATA => self.state.data = val,
            MsixTableEntryIdx::VECTOR_CTL => self.state.control = val,
            _ => panic!("Unexpected write offset {}", offset),
        }
    }

    fn is_enabled(&self, global_enabled: bool) -> bool {
        global_enabled && self.state.control & 1 == 0
    }

    fn check_is_pending(&mut self, global_enabled: bool) -> bool {
        if !self.state.is_pending && !self.is_enabled(global_enabled) {
            self.state.is_pending = self.msi.drain_pending();
        }
        self.state.is_pending
    }
}

#[derive(InspectMut)]
struct MsixState {
    enabled: bool,
    #[inspect(mut, with = "inspect_entries")]
    vectors: Vec<MsixMessageTableEntry>,
}

fn inspect_entries(entries: &mut [MsixMessageTableEntry]) -> impl '_ + InspectMut {
    inspect::adhoc_mut(|req| {
        let mut resp = req.respond();
        for (i, entry) in entries.iter_mut().enumerate() {
            resp.field_mut(&i.to_string(), entry);
        }
    })
}

/// Emulator for the hardware-level interface required to configure and trigger
/// MSI-X interrupts on a PCI device.
#[derive(Clone)]
pub struct MsixEmulator {
    state: Arc<Mutex<MsixState>>,
    // PBA offsets, per spec, are no larger than 32 bits.
    pending_bits_offset: u32,
    pending_bits_dword_count: u16,
}

impl MsixEmulator {
    /// Create a new [`MsixEmulator`] instance, along with with its associated
    /// [`PciCapability`] structure.
    ///
    /// This implementation of MSI-X expects a dedicated BAR to store the vector
    /// and pending tables.
    ///
    /// * * *
    ///
    /// DEVNOTE: This current implementation of MSI-X isn't particularly
    /// "flexible" with respect to the various ways the PCI spec allows MSI-X to
    /// be implemented. e.g: it uses a shared BAR for the table and BPA, with
    /// fixed offsets into the BAR for both of those tables. It would be nice to
    /// re-visit this code and make it more flexible.
    pub fn new(bar: u8, count: u16, msi_target: &MsiTarget) -> (Self, impl PciCapability + use<>) {
        let state = MsixState {
            enabled: false,
            vectors: (0..count)
                .map(|_| MsixMessageTableEntry::new(MsiInterrupt::new(msi_target.clone())))
                .collect(),
        };
        let state = Arc::new(Mutex::new(state));
        let pending_bits_offset = count as u32 * 16;
        (
            Self {
                state: state.clone(),
                pending_bits_offset,
                pending_bits_dword_count: count.div_ceil(32),
            },
            MsixCapability {
                count,
                state,
                config_table_location: MsiTableLocation::new(bar, 0),
                pending_bits_location: MsiTableLocation::new(bar, pending_bits_offset),
            },
        )
    }

    /// Return the total length of the MSI-X BAR
    /// (Actually, the notion that there is an "MSI-X BAR" is an issue to fix sometime.
    /// MSI-X tables are often in the same bar as other things.)
    pub fn bar_len(&self) -> u64 {
        self.pending_bits_offset as u64 + self.pending_bits_dword_count as u64 * 4
    }

    /// Read a `u32` from the MSI-X BAR at the given offset.
    pub fn read_u32(&self, offset: u64) -> u32 {
        let mut state = self.state.lock();
        let state: &mut MsixState = &mut state;
        if offset < self.pending_bits_offset as u64 {
            let index = offset / 16;
            if let Some(entry) = state.vectors.get(index as usize) {
                return entry.read_u32(offset & 0xf);
            }
        } else {
            let dword = (offset - self.pending_bits_offset as u64) / 4;
            let start = dword as usize * 32;
            if start < state.vectors.len() {
                let end = (start + 32).min(state.vectors.len());
                let mut val = 0u32;
                for (i, entry) in state.vectors[start..end].iter_mut().enumerate() {
                    if entry.check_is_pending(state.enabled) {
                        val |= 1 << i;
                    }
                }
                return val;
            }
        }
        tracelimit::warn_ratelimited!(offset, "Unexpected read offset");
        0
    }

    /// Write a `u32` to the MSI-X BAR at the given offset.
    pub fn write_u32(&mut self, offset: u64, val: u32) {
        let mut state = self.state.lock();
        if offset < self.pending_bits_offset as u64 {
            let index = offset / 16;
            let global = state.enabled;
            if let Some(entry) = state.vectors.get_mut(index as usize) {
                let was_enabled = entry.is_enabled(global);
                entry.write_u32(offset & 0xf, val);
                let is_enabled = entry.is_enabled(global);
                if is_enabled && !was_enabled {
                    // Vector just unmasked.
                    entry.msi.enable(
                        entry.state.address,
                        entry.state.data,
                        entry.state.is_pending,
                    );
                    entry.state.is_pending = false;
                } else if was_enabled && !is_enabled {
                    // Vector just masked.
                    entry.msi.disable();
                } else if is_enabled {
                    // Still enabled. addr/data may have changed — enable()
                    // will update the route if present.
                    entry
                        .msi
                        .enable(entry.state.address, entry.state.data, false);
                }
                return;
            }
        } else if offset - (self.pending_bits_offset as u64)
            < self.pending_bits_dword_count as u64 * 4
        {
            return;
        }
        tracelimit::warn_ratelimited!(offset, "Unexpected write offset");
    }

    /// Return an [`Interrupt`] associated with the particular MSI-X vector, or
    /// `None` if the index is out of bounds.
    pub fn interrupt(&self, index: u16) -> Option<Interrupt> {
        Some(
            self.state
                .lock()
                .vectors
                .get_mut(index as usize)?
                .msi
                .interrupt(),
        )
    }

    #[cfg(test)]
    fn clear_pending_bit(&self, index: u8) {
        let mut state = self.state.lock();
        state.vectors[index as usize].state.is_pending = false;
    }

    /// Sets the pending bit for the given vector index.
    ///
    /// Used by device passthrough (e.g., VFIO with irqfd) to record that an
    /// interrupt arrived while the vector was masked, so PBA reads return
    /// the correct pending state.
    pub fn set_pending_bit(&self, index: u16) {
        let mut state = self.state.lock();
        if let Some(entry) = state.vectors.get_mut(index as usize) {
            entry.state.is_pending = true;
        } else {
            tracelimit::warn_ratelimited!(
                index,
                count = state.vectors.len(),
                "set_pending_bit: vector index out of range"
            );
        }
    }
}

mod save_restore {
    use super::*;
    use thiserror::Error;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        #[derive(Debug, Protobuf)]
        #[mesh(package = "pci.caps.msix")]
        pub struct SavedMsixMessageTableEntryState {
            #[mesh(1)]
            pub address: u64,
            #[mesh(2)]
            pub data: u32,
            #[mesh(3)]
            pub control: u32,
            #[mesh(4)]
            pub is_pending: bool,
        }

        #[derive(Debug, Protobuf, SavedStateRoot)]
        #[mesh(package = "pci.caps.msix")]
        pub struct SavedState {
            #[mesh(2)]
            pub enabled: bool,
            #[mesh(3)]
            pub vectors: Vec<SavedMsixMessageTableEntryState>,
        }
    }

    #[derive(Debug, Error)]
    enum MsixRestoreError {
        #[error("mismatched vector lengths: current:{0}, saved:{1}")]
        MismatchedTableLengths(usize, usize),
    }

    impl SaveRestore for MsixCapability {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            let state = self.state.lock();
            let saved_state = state::SavedState {
                enabled: state.enabled,
                vectors: {
                    state
                        .vectors
                        .iter()
                        .map(|vec| {
                            let EntryState {
                                address,
                                data,
                                control,
                                is_pending,
                            } = vec.state;

                            state::SavedMsixMessageTableEntryState {
                                address,
                                data,
                                control,
                                is_pending,
                            }
                        })
                        .collect()
                },
            };
            Ok(saved_state)
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            let state::SavedState { enabled, vectors } = state;

            let mut state = self.state.lock();
            state.enabled = enabled;

            if vectors.len() != state.vectors.len() {
                return Err(RestoreError::InvalidSavedState(
                    MsixRestoreError::MismatchedTableLengths(vectors.len(), state.vectors.len())
                        .into(),
                ));
            }

            for (new_vec, vec) in vectors.into_iter().zip(state.vectors.iter_mut()) {
                vec.state = EntryState {
                    address: new_vec.address,
                    data: new_vec.data,
                    control: new_vec.control,
                    is_pending: new_vec.is_pending,
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
