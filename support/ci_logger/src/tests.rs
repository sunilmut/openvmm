// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::Command;
use test_with_tracing::test;

fn output(in_ci: bool, explicit: bool, filter: Option<&str>) -> String {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tests::logger_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "CI_LOGGER_FIXTURE",
            if explicit { "explicit" } else { "environment" },
        )
        .env_remove("TF_BUILD")
        .env_remove("CI_LOGGER_TEST_FILTER");
    if in_ci {
        command.env("TF_BUILD", "1");
    }
    if let Some(filter) = filter {
        command.env("CI_LOGGER_TEST_FILTER", filter);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stderr).unwrap()
}

// Test: Emit all log levels through the public logger in CI and terminal modes.
// Expected: CI emits severity commands without ANSI; terminal output has exact
//       colors/resets, and debug/trace retain known or missing source locations.
#[test]
fn public_logger_emits_ci_commands_and_terminal_colors() {
    assert_eq!(
        output(true, true, Some("trace")),
        concat!(
            "##vso[task.logissue type=error]error payload\n",
            "##vso[task.logissue type=warning]warning payload\n",
            "info payload\n",
            "##[debug][fixture_mod:42] debug payload\n",
            "##[debug](trace)[?:?] trace payload\n",
            "##[debug][?:?] other debug\n",
        )
    );
    assert_eq!(
        output(false, true, Some("trace")),
        concat!(
            "\x1b[0;31merror payload\x1b[0m\n",
            "\x1b[0;33mwarning payload\x1b[0m\n",
            "info payload\x1b[0m\n",
            "\x1b[0;36m[fixture_mod:42] debug payload\x1b[0m\n",
            "\x1b[0;35m[?:?] trace payload\x1b[0m\n",
            "\x1b[0;36m[?:?] other debug\x1b[0m\n",
        )
    );
}

// Test: Initialize from an absent environment value and a per-target override.
// Expected: Default logging excludes debug/trace; an off-by-default filter
//       emits only the selected target's debug record, not unrelated records.
#[test]
fn environment_filters_preserve_default_and_target_isolation() {
    assert_eq!(
        output(true, false, None),
        concat!(
            "##vso[task.logissue type=error]error payload\n",
            "##vso[task.logissue type=warning]warning payload\n",
            "info payload\n",
        )
    );
    assert_eq!(
        output(true, false, Some("off,kept=debug")),
        "##[debug][fixture_mod:42] debug payload\n"
    );
}

// Test: Install the public CI logger in a child process and deliver log records.
// Expected: Records go to stderr using the selected public initialization path.
// IGNORED: Parents invoke this isolated fixture explicitly. It deliberately uses
//       the built-in test attribute because tracing initialization installs a
//       competing global logger; this is not a product-failure ignore.
#[::core::prelude::v1::test]
#[ignore = "subprocess fixture invoked by parent tests"]
fn logger_fixture() {
    match std::env::var("CI_LOGGER_FIXTURE").unwrap().as_str() {
        "explicit" => {
            crate::init_with_level(&std::env::var("CI_LOGGER_TEST_FILTER").unwrap()).unwrap()
        }
        "environment" => crate::init("CI_LOGGER_TEST_FILTER").unwrap(),
        _ => panic!("invalid fixture mode"),
    }
    for (level, target, module, line, message) in [
        (log::Level::Error, "fixture", None, None, "error payload"),
        (log::Level::Warn, "fixture", None, None, "warning payload"),
        (log::Level::Info, "fixture", None, None, "info payload"),
        (
            log::Level::Debug,
            "kept",
            Some("fixture_mod"),
            Some(42),
            "debug payload",
        ),
        (log::Level::Trace, "kept", None, None, "trace payload"),
        (log::Level::Debug, "other", None, None, "other debug"),
    ] {
        log::logger().log(
            &log::Record::builder()
                .level(level)
                .target(target)
                .module_path(module)
                .line(line)
                .args(format_args!("{message}"))
                .build(),
        );
    }
}
