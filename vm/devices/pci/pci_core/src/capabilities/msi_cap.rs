// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MSI Capability.

use super::PciCapability;
use crate::capabilities::msix::MsiInterrupt;
use crate::msi::MsiTarget;
use crate::spec::caps::CapabilityId;
use crate::spec::caps::msi::MsiCapabilityHeader;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use inspect::Inspect;
use inspect::InspectMut;
use parking_lot::Mutex;
use std::fmt::Debug;
use std::sync::Arc;
use vmcore::interrupt::Interrupt;

/// MSI capability implementation for PCI configuration space.
#[derive(Debug, Clone, Inspect)]
pub struct MsiCapability {
    #[inspect(with = "|x| inspect::adhoc(|req| x.lock().inspect_mut(req))")]
    state: Arc<Mutex<MsiCapabilityState>>,
    addr_64bit: bool,
    per_vector_masking: bool,
}

#[derive(Debug, InspectMut)]
struct MsiCapabilityState {
    enabled: bool,
    multiple_message_enable: u8,  // 2^(MME) messages allocated
    multiple_message_capable: u8, // 2^(MMC) maximum messages requestable
    #[inspect(hex)]
    address: u64,
    #[inspect(hex)]
    data: u16,
    #[inspect(hex)]
    mask_bits: u32,
    #[inspect(hex)]
    pending_bits: u32,
    interrupt: Option<MsiInterrupt>,
}

impl MsiCapabilityState {
    fn new(multiple_message_capable: u8, _addr_64bit: bool, per_vector_masking: bool) -> Self {
        Self {
            enabled: false,
            multiple_message_enable: 0,
            multiple_message_capable,
            address: 0,
            data: 0,
            mask_bits: if per_vector_masking { 0xFFFFFFFF } else { 0 },
            pending_bits: 0,
            interrupt: None,
        }
    }

    fn control_register(&self, addr_64bit: bool, per_vector_masking: bool) -> u16 {
        let mut control = 0u16;
        control |= (self.multiple_message_capable as u16) << 1; // MMC field (bits 1-3)
        control |= (self.multiple_message_enable as u16) << 4; // MME field (bits 4-6)
        if addr_64bit {
            control |= 1 << 7; // 64-bit Address Capable (bit 7)
        }
        if per_vector_masking {
            control |= 1 << 8; // Per-vector Masking Capable (bit 8)
        }
        if self.enabled {
            control |= 1 << 0; // MSI Enable (bit 0)
        }
        control
    }

    fn read(
        &self,
        offset: u16,
        addr_64bit: bool,
        per_vector_masking: bool,
        mut value: ByteEnabledDwordRead<'_>,
    ) {
        match MsiCapabilityHeader(offset) {
            MsiCapabilityHeader::CONTROL_CAPS => {
                value.set_low_high(
                    CapabilityId::MSI.0.into(),
                    self.control_register(addr_64bit, per_vector_masking),
                );
            }
            MsiCapabilityHeader::MSG_ADDR_LO => value.set(self.address as u32),
            MsiCapabilityHeader::MSG_ADDR_HI if addr_64bit => {
                value.set((self.address >> 32) as u32)
            }
            MsiCapabilityHeader::MSG_DATA_32 if !addr_64bit => value.set_low_high(self.data, 0),
            MsiCapabilityHeader::MSG_DATA_64 if addr_64bit => value.set_low_high(self.data, 0),
            MsiCapabilityHeader::MASK_BITS if addr_64bit && per_vector_masking => {
                value.set(self.mask_bits)
            }
            MsiCapabilityHeader::PENDING_BITS if addr_64bit && per_vector_masking => {
                value.set(self.pending_bits);
            }
            _ => {
                tracelimit::warn_ratelimited!("Unexpected MSI read offset {:#x}", offset);
                value.set(0);
            }
        }
    }
}

impl MsiCapability {
    /// Create a new MSI capability.
    ///
    /// # Arguments
    /// * `multiple_message_capable` - log2 of maximum number of messages (0-5)
    /// * `addr_64bit` - Whether 64-bit addressing is supported
    /// * `per_vector_masking` - Whether per-vector masking is supported
    /// * `msi_target` - MSI target
    pub fn new(
        multiple_message_capable: u8,
        addr_64bit: bool,
        per_vector_masking: bool,
        msi_target: &MsiTarget,
    ) -> Self {
        assert!(multiple_message_capable <= 5, "MMC must be 0-5");

        let interrupt = MsiInterrupt::new(msi_target.clone());
        let state = MsiCapabilityState {
            interrupt: Some(interrupt),
            ..MsiCapabilityState::new(multiple_message_capable, addr_64bit, per_vector_masking)
        };

        Self {
            state: Arc::new(Mutex::new(state)),
            addr_64bit,
            per_vector_masking,
        }
    }

    /// Get the interrupt object for signaling MSI.
    pub fn interrupt(&self) -> Option<Interrupt> {
        self.state.lock().interrupt.as_mut().map(|i| i.interrupt())
    }

    fn len_bytes(&self) -> usize {
        let mut len = 8; // Base: ID + Next + Control + Message Address Low
        if self.addr_64bit {
            len += 4; // Message Address High
        }
        len += 2; // Message Data (16-bit, but aligned to 4-byte boundary)
        if self.per_vector_masking {
            len += 8; // Mask Bits + Pending Bits
        }
        // Round up to next 4-byte boundary
        (len + 3) & !3
    }
}

impl PciCapability for MsiCapability {
    fn label(&self) -> &str {
        "msi"
    }

    fn capability_id(&self) -> CapabilityId {
        CapabilityId::MSI
    }

    fn len(&self) -> usize {
        self.len_bytes()
    }

    fn read(&self, offset: u16, value: ByteEnabledDwordRead<'_>) {
        self.state
            .lock()
            .read(offset, self.addr_64bit, self.per_vector_masking, value);
    }

    fn write(&mut self, offset: u16, val: ByteEnabledDwordWrite) {
        let mut state = self.state.lock();
        match MsiCapabilityHeader(offset) {
            MsiCapabilityHeader::CONTROL_CAPS => {
                let control_val = val
                    .merge_high(state.control_register(self.addr_64bit, self.per_vector_masking));
                let old_enabled = state.enabled;
                let new_enabled = control_val & 1 != 0;
                let mme = ((control_val >> 4) & 0x7) as u8;

                // Update MME (Multiple Message Enable) - limited by MMC
                state.multiple_message_enable = mme.min(state.multiple_message_capable);
                state.enabled = new_enabled;

                // Handle enable/disable state changes
                let address = state.address;
                let data = state.data as u32;
                if let Some(ref mut interrupt) = state.interrupt {
                    if new_enabled && !old_enabled {
                        // Enable MSI
                        interrupt.enable(address, data, false);
                    } else if !new_enabled && old_enabled {
                        // Disable MSI
                        interrupt.disable();
                    }
                }
            }
            MsiCapabilityHeader::MSG_ADDR_LO => {
                let new_low = val.merge(state.address as u32);
                state.address = (state.address & 0xFFFFFFFF00000000) | (new_low as u64);

                // Update interrupt if enabled
                if state.enabled {
                    let address = state.address;
                    let data = state.data as u32;
                    if let Some(ref mut interrupt) = state.interrupt {
                        interrupt.enable(address, data, false);
                    }
                }
            }
            MsiCapabilityHeader::MSG_ADDR_HI if self.addr_64bit => {
                let new_high = val.merge((state.address >> 32) as u32);
                state.address = (state.address & 0xFFFFFFFF) | ((new_high as u64) << 32);

                // Update interrupt if enabled
                if state.enabled {
                    let address = state.address;
                    let data = state.data as u32;
                    if let Some(ref mut interrupt) = state.interrupt {
                        interrupt.enable(address, data, false);
                    }
                }
            }
            MsiCapabilityHeader::MSG_DATA_32 if !self.addr_64bit => {
                state.data = val.merge_low(state.data);

                // Update interrupt if enabled
                if state.enabled {
                    let address = state.address;
                    let data = state.data as u32;
                    if let Some(ref mut interrupt) = state.interrupt {
                        interrupt.enable(address, data, false);
                    }
                }
            }
            MsiCapabilityHeader::MSG_DATA_64 if self.addr_64bit => {
                state.data = val.merge_low(state.data);

                // Update interrupt if enabled
                if state.enabled {
                    let address = state.address;
                    let data = state.data as u32;
                    if let Some(ref mut interrupt) = state.interrupt {
                        interrupt.enable(address, data, false);
                    }
                }
            }
            MsiCapabilityHeader::MASK_BITS if self.addr_64bit && self.per_vector_masking => {
                val.merge_into(&mut state.mask_bits);
            }
            MsiCapabilityHeader::PENDING_BITS if self.addr_64bit && self.per_vector_masking => {
                // Pending bits are typically read-only, but some implementations may allow clearing
                tracelimit::warn_ratelimited!(
                    "Write to MSI pending bits register (typically read-only)"
                );
            }
            _ => {
                tracelimit::warn_ratelimited!("Unexpected MSI write offset {:#x}", offset);
            }
        }
    }

    fn reset(&mut self) {
        let mut state = self.state.lock();

        // Disable MSI
        if state.enabled {
            if let Some(ref mut interrupt) = state.interrupt {
                interrupt.disable();
            }
        }

        // Reset to default values
        state.enabled = false;
        state.multiple_message_enable = 0;
        state.address = 0;
        state.data = 0;
        if self.per_vector_masking {
            state.mask_bits = 0;
            state.pending_bits = 0;
        }
    }

    fn as_msi_cap(&self) -> Option<&MsiCapability> {
        Some(self)
    }

    fn as_msi_cap_mut(&mut self) -> Option<&mut MsiCapability> {
        Some(self)
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

        #[derive(Debug, Protobuf, SavedStateRoot)]
        #[mesh(package = "pci.caps.msi")]
        pub struct SavedState {
            #[mesh(1)]
            pub enabled: bool,
            #[mesh(2)]
            pub multiple_message_enable: u8,
            #[mesh(3)]
            pub address: u64,
            #[mesh(4)]
            pub data: u16,
            #[mesh(5)]
            pub mask_bits: u32,
            #[mesh(6)]
            pub pending_bits: u32,
        }
    }

    #[derive(Debug, Error)]
    enum MsiRestoreError {
        #[error("invalid multiple message enable value: {0}")]
        InvalidMultipleMessageEnable(u8),
    }

    impl SaveRestore for MsiCapability {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            let state = self.state.lock();
            Ok(state::SavedState {
                enabled: state.enabled,
                multiple_message_enable: state.multiple_message_enable,
                address: state.address,
                data: state.data,
                mask_bits: state.mask_bits,
                pending_bits: state.pending_bits,
            })
        }

        fn restore(&mut self, saved_state: Self::SavedState) -> Result<(), RestoreError> {
            let state::SavedState {
                enabled,
                multiple_message_enable,
                address,
                data,
                mask_bits,
                pending_bits,
            } = saved_state;

            if multiple_message_enable > 5 {
                return Err(RestoreError::InvalidSavedState(
                    MsiRestoreError::InvalidMultipleMessageEnable(multiple_message_enable).into(),
                ));
            }

            let mut state = self.state.lock();

            // Disable current interrupt if needed
            if state.enabled {
                if let Some(ref mut interrupt) = state.interrupt {
                    interrupt.disable();
                }
            }

            // Restore state
            state.enabled = enabled;
            state.multiple_message_enable =
                multiple_message_enable.min(state.multiple_message_capable);
            state.address = address;
            state.data = data;
            state.mask_bits = mask_bits;
            state.pending_bits = pending_bits;

            // Re-enable interrupt if needed
            if state.enabled {
                let address = state.address;
                let data = state.data as u32;
                if let Some(ref mut interrupt) = state.interrupt {
                    interrupt.enable(address, data, false);
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
