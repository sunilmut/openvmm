// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for originating PCI configuration space accesses in bus emulators.

use chipset_device::io::IoResult;
use chipset_device::io::deferred::DeferredRead;
use chipset_device::io::deferred::DeferredToken;
use chipset_device::io::deferred::DeferredWrite;
use chipset_device::io::deferred::defer_read;
use chipset_device::io::deferred::defer_write;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use chipset_device::pci::PciConfigAddress;
use chipset_device::pci::PciConfigByteEnable;
use inspect::Inspect;
use std::task::Context;
use std::task::Poll;
use zerocopy::IntoBytes;

/// Callback trait for the [`PciBusCfgAccessHandler`] for bus-specific operations.
pub trait PciBusCfgAccessCallbacks {
    /// Dispatches a read to the downstream config-space target.
    fn read(&mut self, addr: PciConfigAddress, value: ByteEnabledDwordRead<'_>) -> IoResult;

    /// Dispatches a write to the downstream config-space target.
    fn write(&mut self, addr: PciConfigAddress, value: ByteEnabledDwordWrite) -> IoResult;
}

/// A pending config space access that was deferred by a downstream device.
#[derive(Inspect)]
#[inspect(tag = "kind")]
enum DeferredCfgAccess {
    /// A read that was deferred by a downstream device.
    Read {
        #[inspect(skip)]
        deferred_device_read: DeferredToken,
        #[inspect(skip)]
        bus_read: DeferredRead,
        addr: PciConfigAddress,
        byte_enable: PciConfigByteEnable,
    },
    /// A write that was deferred by a downstream device.
    Write {
        #[inspect(skip)]
        deferred_device_write: DeferredToken,
        #[inspect(skip)]
        bus_write: DeferredWrite,
        addr: PciConfigAddress,
    },
}

/// A handler for managing PCI config space accesses to downstream devices.
#[derive(Default, Inspect)]
pub struct PciBusCfgAccessHandler {
    #[inspect(with = "|x| x.is_some()")]
    waker: Option<std::task::Waker>,
    #[inspect(iter_by_index)]
    actions: Vec<DeferredCfgAccess>,
}

impl PciBusCfgAccessHandler {
    /// Creates an empty deferred-access tracker.
    pub fn new() -> Self {
        Self {
            waker: None,
            actions: Vec::new(),
        }
    }

    /// Returns whether there are no deferred accesses pending.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Handles a config space read request.
    pub fn read(
        &mut self,
        addr: PciConfigAddress,
        mut inline_completion_value: ByteEnabledDwordRead<'_>,
        callbacks: &mut impl PciBusCfgAccessCallbacks,
    ) -> IoResult {
        match callbacks.read(addr, inline_completion_value.reborrow()) {
            IoResult::Ok => IoResult::Ok,
            IoResult::Err(err) => IoResult::Err(err),
            IoResult::Defer(deferred_device_read) => {
                let (bus_read, bus_token) = defer_read();
                self.push_action(DeferredCfgAccess::Read {
                    deferred_device_read,
                    bus_read,
                    addr,
                    byte_enable: inline_completion_value.byte_enable(),
                });
                IoResult::Defer(bus_token)
            }
        }
    }

    /// Handles a config space write request.
    pub fn write(
        &mut self,
        addr: PciConfigAddress,
        value: ByteEnabledDwordWrite,
        callbacks: &mut impl PciBusCfgAccessCallbacks,
    ) -> IoResult {
        let result = callbacks.write(addr, value);
        if let IoResult::Defer(deferred_device_write) = result {
            let (bus_write, bus_token) = defer_write();
            self.push_action(DeferredCfgAccess::Write {
                deferred_device_write,
                bus_write,
                addr,
            });
            return IoResult::Defer(bus_token);
        }

        result
    }

    /// Polls pending accesses and keeps any that are still incomplete.
    pub fn poll(&mut self, cx: &mut Context<'_>) {
        self.waker = Some(cx.waker().clone());
        self.actions = std::mem::take(&mut self.actions)
            .into_iter()
            .filter_map(|action| match action {
                DeferredCfgAccess::Read {
                    mut deferred_device_read,
                    bus_read,
                    addr,
                    byte_enable,
                } => {
                    // If the inner read is ready, complete the outer read accordingly.
                    let mut dword_buffer = 0;
                    if let Poll::Ready(res) =
                        deferred_device_read.poll_read(cx, dword_buffer.as_mut_bytes())
                    {
                        match res {
                            Ok(()) => {
                                let (byte_offset, len) = byte_enable.to_byte_offset_len();
                                let byte_offset = byte_offset as usize;
                                bus_read.complete(
                                    &dword_buffer.as_bytes()[byte_offset..byte_offset + len],
                                );
                            }
                            Err(err) => bus_read.complete_error(err),
                        }
                        None
                    } else {
                        // If the inner read is not ready, keep the outer read pending and
                        // leave the deferred action in the list for the next poll.
                        Some(DeferredCfgAccess::Read {
                            deferred_device_read,
                            bus_read,
                            addr,
                            byte_enable,
                        })
                    }
                }
                DeferredCfgAccess::Write {
                    mut deferred_device_write,
                    bus_write,
                    addr,
                } => {
                    // If the inner write completed, complete the outer write accordingly.
                    if let Poll::Ready(res) = deferred_device_write.poll_write(cx) {
                        match res {
                            Ok(()) => bus_write.complete(),
                            Err(err) => bus_write.complete_error(err),
                        }
                        None
                    } else {
                        // If the inner write is not ready, keep the outer write pending and
                        // leave the deferred action in the list for the next poll.
                        Some(DeferredCfgAccess::Write {
                            deferred_device_write,
                            bus_write,
                            addr,
                        })
                    }
                }
            })
            .collect();
    }

    fn push_action(&mut self, action: DeferredCfgAccess) {
        self.actions.push(action);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests;
