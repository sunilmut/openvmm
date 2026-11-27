// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers when writing fuzzing crates that get invoked via `cargo xtask fuzz`.
//!
//! Might end up getting deprecated, if/when
//! <https://github.com/rust-fuzz/cargo-fuzz/issues/346> is resolved

#![forbid(unsafe_code)]

use std::sync::OnceLock;

static IS_REPRO: OnceLock<bool> = OnceLock::new();

/// Check if the `XTASK_FUZZ_REPRO` env var was set.
///
/// Caches result in a global static, to avoid redundant lookups.
pub fn is_repro() -> bool {
    *IS_REPRO.get_or_init(|| std::env::var("XTASK_FUZZ_REPRO").is_ok())
}

/// Initialize tracing if this is a repro run.
pub fn init_tracing_if_repro() {
    use std::sync::Once;
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // cargo-fuzz can call our fuzz target multiple times, but we can only initialize tracing once.
    static INIT: Once = Once::new();

    if is_repro() {
        INIT.call_once(|| {
            let targets = if let Ok(var) = std::env::var("OPENVMM_LOG") {
                var.parse().unwrap()
            } else {
                Targets::new().with_default(LevelFilter::TRACE)
            };

            tracing_subscriber::fmt()
                .compact()
                .log_internal_errors(true)
                .with_max_level(LevelFilter::TRACE)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .finish()
                .with(targets)
                .init();
        });
    }
}

/// `eprintln!` that only gets calls when reproducing fuzz test cases locally
#[macro_export]
macro_rules! fuzz_eprintln {
    ($($arg:tt)*) => {
        if $crate::is_repro() {
            eprintln!($($arg)*)
        }
    };
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use libfuzzer_sys::fuzz_target;

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
/// Fake version of `libfuzzer_sys::fuzz_target` for non-linux-gnu targets.
#[macro_export]
macro_rules! fuzz_target {
    ($($tt:tt)*) => {
        // libfuzzer-sys is only supported on Linux gnu, so add a main function
        // that references do_fuzz to satisfy rust-analyzer.
        fn main() {
            let _ = do_fuzz;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHILD_MARKER: &str = "xtask-fuzz-child-ran";

    // Test: Outside repro mode, query the mode, initialize tracing and use the
    //       repro-only print macro; then rerun in a child process with
    //       XTASK_FUZZ_REPRO and OPENVMM_LOG set and repeat the same steps.
    // Expected: Without repro mode nothing is installed or printed and macro
    //       arguments are not evaluated; in repro mode tracing initializes once
    //       (a second call is harmless) and the macro prints.
    #[test]
    fn non_repro_mode_is_inert() {
        if std::env::var_os("XTASK_FUZZ_REPRO").is_some() {
            return repro_child_checks();
        }
        assert!(!is_repro());
        assert!(!is_repro());
        init_tracing_if_repro();
        assert!(!tracing::dispatcher::has_been_set());
        let mut evaluated = false;
        fuzz_eprintln!("{}", {
            evaluated = true;
            0
        });
        assert!(!evaluated);

        // Re-run this test in a child process with repro mode enabled.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::non_repro_mode_is_inert",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("XTASK_FUZZ_REPRO", "1")
            .env("OPENVMM_LOG", "xtask_fuzz=debug")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains(CHILD_MARKER), "{stderr}");
    }

    /// Repro-mode checks, run only inside the child process started above.
    fn repro_child_checks() {
        assert!(is_repro());
        init_tracing_if_repro();
        init_tracing_if_repro();
        assert!(tracing::dispatcher::has_been_set());
        let mut evaluated = false;
        fuzz_eprintln!("{} {}", CHILD_MARKER, {
            evaluated = true;
            1
        });
        assert!(evaluated);
    }
}
