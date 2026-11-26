// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public pthread signal error provenance.

#![cfg(target_os = "linux")]

use pal::unix::pthread::Pthread;
use std::io::ErrorKind;
use test_with_tracing::test;

// IGNORED: An enabled run returned NotFound from the preceding open failure,
//       not InvalidInput from pthread_kill. The wrapper reads errno instead
//       of using the error code returned directly by the pthread operation.
//
// Test: Send an invalid signal after an unrelated filesystem failure.
// Expected: The pthread operation reports InvalidInput, independent of the
//       previous syscall's errno.
#[test]
#[ignore = "pthread signal errors incorrectly use the previous errno"]
fn invalid_thread_signal_reports_its_own_error() {
    let thread = Pthread::current();
    let directory = tempfile::tempdir_in(".").unwrap();
    assert_eq!(
        std::fs::File::open(directory.path().join("missing"))
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        thread.signal(i32::MAX).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}
