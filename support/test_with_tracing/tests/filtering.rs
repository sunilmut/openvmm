// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public tracing initialization tested with process-isolated log settings.

use std::process::Command;
use test_with_tracing::test;

// Test: Initialize repeatedly and concurrently with default, target-specific,
//       and trace-level environment filters in isolated test processes.
// Expected: Levels and emitted output honor the selected filter without ANSI
//       escapes or duplicate-subscriber failures.
#[test]
fn filtering_and_repeated_initialization() {
    if std::env::var_os("OPENVMM_TRACE_FILTER_CHILD").is_some() {
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(test_with_tracing::init);
            }
        });
        tracing::debug!(target: "other", "other debug marker");
        tracing::trace!(target: "other", "other trace marker");
        tracing::debug!(target: "permitted", "permitted debug marker");
        tracing::trace!(target: "permitted", "permitted trace marker");
        tracing::error!(target: "silenced", "silenced error marker");
        tracing::info!(target: "other", "other info marker");
        return;
    }

    for (filter, expected) in [
        (None, "101011"),
        (Some("warn,permitted=debug,silenced=off"), "001000"),
        (Some("trace"), "111111"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "filtering_and_repeated_initialization",
            "--nocapture",
        ]);
        command.env("OPENVMM_TRACE_FILTER_CHILD", "1");
        match filter {
            Some(filter) => command.env("RUST_LOG", filter),
            None => command.env_remove("RUST_LOG"),
        };
        let output = command.output().unwrap();
        assert!(output.status.success(), "{filter:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for (marker, enabled) in [
            "other debug marker",
            "other trace marker",
            "permitted debug marker",
            "permitted trace marker",
            "silenced error marker",
            "other info marker",
        ]
        .into_iter()
        .zip(expected.bytes())
        {
            assert_eq!(
                stdout.contains(marker),
                enabled == b'1',
                "{filter:?}: {stdout}"
            );
        }
        assert!(!stdout.contains('\u{1b}'), "{stdout:?}");
    }
}
