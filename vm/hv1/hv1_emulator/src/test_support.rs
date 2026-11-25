// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::VtlProtectAccess;
use guestmem::{AccessType, GuestMemory, UserLockedPages};
use hvdef::{HvError, HvMapGpaFlags};

pub(crate) struct RecordingProtection {
    pub(crate) memory: GuestMemory,
    pub(crate) requested: Vec<(u64, HvMapGpaFlags, Option<HvMapGpaFlags>)>,
    pub(crate) unlocked: Vec<u64>,
}

impl RecordingProtection {
    pub(crate) fn new() -> Self {
        Self {
            memory: GuestMemory::allocate(16 * 4096),
            requested: Vec::new(),
            unlocked: Vec::new(),
        }
    }
}

impl VtlProtectAccess for RecordingProtection {
    fn check_modify_and_lock_overlay_page(
        &mut self,
        gpn: u64,
        check_perms: HvMapGpaFlags,
        new_perms: Option<HvMapGpaFlags>,
    ) -> Result<UserLockedPages, HvError> {
        self.requested.push((gpn, check_perms, new_perms));
        self.memory
            .lock_user_gpns(AccessType::Write, &[gpn])
            .map_err(|_| HvError::InvalidParameter)
    }

    fn unlock_overlay_page(&mut self, gpn: u64) -> Result<(), HvError> {
        self.unlocked.push(gpn);
        Ok(())
    }
}
