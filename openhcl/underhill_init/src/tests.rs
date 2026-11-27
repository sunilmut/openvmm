// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Collect script stdout containing valid, repeated and malformed assignments.
// Expected: Valid UTF-8 assignments retain order, empty values and embedded equals;
//       progress lines and invalid UTF-8 are not exported.
#[test]
fn setup_scripts_preserve_assignments_and_skip_non_environment_output() {
    let scripts = vec![
        "printf 'FIRST=one\\nprogress\\nEMPTY=\\nEQUALS=x=y=z\\nSPACES=  a b  \\nFIRST=two\\n'"
            .into(),
        "printf '\\377BAD=value\\nLAST=done'".into(),
    ];
    let actual = run_setup_scripts(&scripts).unwrap();
    assert_eq!(
        actual,
        [
            ("FIRST".into(), "one".into()),
            ("EMPTY".into(), "".into()),
            ("EQUALS".into(), "x=y=z".into()),
            ("SPACES".into(), "  a b  ".into()),
            ("FIRST".into(), "two".into()),
            ("LAST".into(), "done".into()),
        ]
    );
}

// Test: Run successive setup scripts with child-local and exported assignments.
// Expected: Earlier output is collected for Underhill, not injected into later
//       scripts or the test process's environment.
#[test]
fn setup_script_environment_stays_child_local() {
    let key = format!("OPENHCL_INIT_TEST_CHILD_ONLY_{}", std::process::id());
    assert!(
        std::env::var_os(&key).is_none(),
        "test variable already exists"
    );
    let scripts = vec![
        format!("export {key}=child-only; printf '{key}=forwarded\\n'"),
        format!("printf 'OBSERVED=%s\\n' \"${{{key}:-missing}}\""),
    ];
    assert_eq!(
        run_setup_scripts(&scripts).unwrap(),
        [
            (key.clone(), "forwarded".into()),
            ("OBSERVED".into(), "missing".into()),
        ]
    );
    assert!(std::env::var_os(key).is_none());
}

// Test: Fail a setup script before a later script can create a private marker.
// Expected: Failure retains the exit status, aborts the sequence and does not
//       run the later script or return partially collected environment.
#[test]
fn failed_setup_script_aborts_remaining_scripts() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("later-script");
    let quoted_marker = marker.to_str().unwrap().replace('\'', "'\\''");
    let scripts = vec![
        "printf 'EARLIER=value\\n'".into(),
        "exit 17".into(),
        format!("printf reached > '{quoted_marker}'"),
    ];
    let error = run_setup_scripts(&scripts).unwrap_err();
    assert!(
        error.to_string().contains("setup script failed"),
        "{error:#}"
    );
    assert!(error.to_string().contains("17"), "{error:#}");
    assert!(!marker.exists(), "later script ran after failure");
}

// Test: Reap an unrelated child before the child whose status the caller requested.
// Expected: The returned exit status belongs to the selected child, not the
//       first child to exit.
#[test]
fn reaper_returns_selected_child_status() {
    let mut unrelated = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let stat = fs_err::read_to_string(format!("/proc/{}/stat", unrelated.id())).unwrap();
        if stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_ascii_whitespace()
            .next()
            == Some("Z")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "first child did not exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let selected = Command::new("/bin/sh")
        .args(["-c", "exit 23"])
        .spawn()
        .unwrap();
    let status = reap_until(selected).unwrap();
    assert_eq!(status.code(), Some(23));
    let error = unrelated
        .try_wait()
        .expect_err("earlier zombie child was reaped");
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
}

// Test: Reap the selected child after terminating that owned child by signal.
// Expected: Signal termination remains a signal status, not a fabricated
//       successful or ordinary exit code.
#[test]
fn reaper_preserves_signal_termination() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .spawn()
        .unwrap();
    child.kill().unwrap();
    let status = reap_until(child).unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(status.code(), None);
}
