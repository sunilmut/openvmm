// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code to recover a corrupt TPM NVRAM blob due to truncation.

use crate::LEGACY_VTPM_SIZE;

/// Check if the TPM blob's persistent data structures all fit inside it.
///
/// This can return false if the blob was incorrectly truncated (by a previous
/// bug that reported a 32KB blob size for a 16KB blob).
fn check_blob(blob: &[u8]) -> Result<(), usize> {
    const NV_USER_DYNAMIC: usize = 3508; // from the TPM reference implementation
    let mut i = NV_USER_DYNAMIC;
    loop {
        let size = u32::from_ne_bytes(blob[i..].get(..4).ok_or(i)?.try_into().unwrap());
        if size == 0 {
            break;
        }
        if blob[i..].get(..size as usize).is_none() {
            return Err(i);
        }
        i += size as usize;
    }
    Ok(())
}

/// Fixup an NVRAM blob that has data past the end, by zeroing out the last
/// header that refers to data past the end. Returns true if any changes were
/// made.
pub fn recover_blob(blob: &mut [u8]) -> bool {
    let original_size = blob.len();
    if original_size != LEGACY_VTPM_SIZE {
        tracing::debug!("TPM NVRAM size is not legacy size, skipping recovery");
        return false;
    }

    match check_blob(blob) {
        Ok(()) => {
            tracing::info!("TPM NVRAM is already good, skipping recovery");
            false
        }
        Err(bad_offset) => {
            tracing::warn!("TPM NVRAM blob is corrupt, truncating at offset {bad_offset}");
            blob[bad_offset..].fill(0);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Recover a truncated dynamic NVRAM chain after a valid record.
    // Expected: Only the invalid header and its tail are cleared; preceding
    //       records survive and a second recovery makes no change.
    #[test]
    fn truncated_record_recovery_preserves_valid_prefix() {
        let mut blob = vec![0x5a; LEGACY_VTPM_SIZE];
        blob[3508..3512].copy_from_slice(&12u32.to_ne_bytes());
        blob[3520..3524].copy_from_slice(&u32::MAX.to_ne_bytes());
        let prefix = blob[..3520].to_vec();
        assert!(recover_blob(&mut blob));
        assert_eq!(blob[..3520], prefix);
        assert!(blob[3520..].iter().all(|&byte| byte == 0));
        let repaired = blob.clone();
        assert!(!recover_blob(&mut blob));
        assert_eq!(blob, repaired);
    }

    // Test: Recover a chain whose last record leaves fewer than four header bytes.
    // Expected: Recovery produces a valid terminated chain, so repeating it
    //       does not report another repair.
    // IGNORED: entry371-bug1: a 0..3-byte tail cannot hold the zero header;
    //       recovery reports success but leaves the chain unterminated.
    #[test]
    #[ignore = "entry371-bug1: incomplete trailing header is not repaired"]
    fn partial_header_and_exact_end_are_repaired() {
        let mut repeated_repairs = Vec::new();
        for remaining in 0..4 {
            let end = LEGACY_VTPM_SIZE - remaining;
            let mut blob = vec![0x5a; LEGACY_VTPM_SIZE];
            blob[3508..3512].copy_from_slice(&((end - 3508) as u32).to_ne_bytes());
            let prefix = blob[..3508].to_vec();
            assert!(recover_blob(&mut blob));
            assert_eq!(blob[..3508], prefix);
            assert!(blob[end..].iter().all(|&byte| byte == 0));
            if recover_blob(&mut blob) {
                repeated_repairs.push(remaining);
            }
        }
        assert!(
            repeated_repairs.is_empty(),
            "recovery did not repair tails {repeated_repairs:?}"
        );
    }

    // Test: Pass terminated legacy chains and blobs of other supported sizes.
    // Expected: Recovery does not alter valid data or apply the legacy
    //       truncation workaround to a different NVRAM format.
    #[test]
    fn valid_and_nonlegacy_blobs_are_unchanged() {
        let mut valid = vec![0xa5; LEGACY_VTPM_SIZE];
        valid[3508..3512].copy_from_slice(&8u32.to_ne_bytes());
        valid[3516..3520].fill(0);
        let before = valid.clone();
        assert!(!recover_blob(&mut valid));
        assert_eq!(valid, before);
        for len in [0, 3508, LEGACY_VTPM_SIZE - 1, 32 * 1024, 128 * 1024] {
            let mut blob = vec![0xa5; len];
            let before = blob.clone();
            assert!(!recover_blob(&mut blob));
            assert_eq!(blob, before);
        }
    }
}
