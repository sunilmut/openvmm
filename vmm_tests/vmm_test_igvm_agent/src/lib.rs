// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for managing the test_igvm_agent_rpc_server used by VMM tests.
//! Intended for local runs where flowey is not starting the server globally.

#![cfg(windows)]
#![forbid(unsafe_code)]

use std::env;
use std::io::{BufRead, BufReader, Read};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;

use anyhow::Context;
use pal::pipe_pair;

/// Name of the RPC server executable.
pub const RPC_SERVER_EXE: &str = "test_igvm_agent_rpc_server.exe";

/// Environment variable that opts local runs into auto-starting the RPC server.
pub const LOCAL_AUTOSTART_ENV: &str = "VMM_TEST_IGVM_AGENT_LOCAL_AUTOSTART";

const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// Checks if any process with the given executable name is running.
pub fn is_process_running(exe_name: &str) -> bool {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", exe_name), "/NH"])
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            !stdout.contains("INFO: No tasks")
        }
        Err(e) => {
            tracing::warn!("failed to run tasklist: {}", e);
            false
        }
    }
}

/// Returns true when local auto-starting has been explicitly enabled.
pub fn local_autostart_enabled() -> bool {
    env::var(LOCAL_AUTOSTART_ENV)
        .ok()
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Ensures the RPC server process is running.
/// Returns Ok(()) if running, or an error if not.
pub fn ensure_rpc_server_running() -> anyhow::Result<()> {
    if is_process_running(RPC_SERVER_EXE) {
        tracing::info!(exe = RPC_SERVER_EXE, "RPC server is running");
        Ok(())
    } else {
        anyhow::bail!(
            "RPC server ({}) is not running. Start it before running tests or allow the test to start it.",
            RPC_SERVER_EXE
        )
    }
}

/// Guard that terminates the RPC server child process on drop.
pub struct RpcServerGuard(Child);

impl Drop for RpcServerGuard {
    fn drop(&mut self) {
        // If the process is still running, try to terminate it.
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(e) = self.0.kill() {
                    tracing::debug!("failed to kill RPC server child: {}", e);
                }
            }
            Err(e) => tracing::debug!("failed to query RPC server child: {}", e),
        }
    }
}

/// Starts the RPC server and returns a guard that will kill it when dropped.
/// Uses stdout EOF as a readiness signal (the server closes stdout once ready).
/// If the server exits immediately (e.g., endpoint already in use), this returns Ok(())
/// with a guard that will observe the exited process.
pub fn start_rpc_server(rpc_server_path: &Path) -> anyhow::Result<RpcServerGuard> {
    let (stderr_read, stderr_write) = pipe_pair()?;

    let mut child = Command::new(rpc_server_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr_write)
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("failed to spawn {}", rpc_server_path.display()))?;

    // Wait for stdout to close as readiness signal
    let mut stdout = child
        .stdout
        .take()
        .context("failed to take stdout from RPC server")?;
    let mut byte = [0u8];
    let n = stdout
        .read(&mut byte)
        .context("failed to read from RPC server stdout")?;
    if n != 0 {
        anyhow::bail!(
            "expected RPC server stdout to close (EOF), but read {} bytes",
            n
        );
    }
    drop(stdout);

    // Give it a moment in case it needs to fail fast (e.g., endpoint already in use)
    thread::sleep(std::time::Duration::from_millis(50));

    match child.try_wait()? {
        Some(status) => {
            tracing::info!(
                exit_code = ?status.code(),
                "RPC server exited immediately (likely already running elsewhere)"
            );
        }
        None => {
            tracing::info!(pid = child.id(), "RPC server started and running");
        }
    }

    // Forward stderr to tracing so it shows up with test output.
    thread::Builder::new()
        .name("igvm-agent-rpc-stderr".to_string())
        .spawn(move || {
            let reader = BufReader::new(stderr_read);
            for line in reader.lines() {
                match line {
                    Ok(line) => tracing::info!(target: "test_igvm_agent_rpc_server", "{}", line),
                    Err(err) => {
                        tracing::debug!("RPC server stderr closed: {}", err);
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn stderr forwarder thread");

    Ok(RpcServerGuard(child))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn missing_server_reports_spawn_context_and_io_cause() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("missing-test-rpc-server.exe");
        assert!(!path.exists());
        let error = start_rpc_server(&path).err().unwrap();
        assert_eq!(
            error.to_string(),
            format!("failed to spawn {}", path.display())
        );
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound,
        );
    }

    #[test]
    fn autostart_requires_explicit_opt_in() {
        const CHILD_EXPECTED: &str = "VMM_TEST_IGVM_AGENT_UNIT_TEST_EXPECTED_AUTOSTART";
        if let Ok(expected) = env::var(CHILD_EXPECTED) {
            assert_eq!(local_autostart_enabled(), expected == "true");
            return;
        }
        // Give each case its own process instead of mutating shared environment.
        for (value, expected) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("false"), false),
            (Some("TRUE"), false),
            (Some("enable"), false),
            (Some("1"), true),
            (Some("\ttrue\n"), true),
            (Some(" yes "), true),
            (Some("on"), true),
        ] {
            let mut command = Command::new(env::current_exe().unwrap());
            command
                .args(["--exact", "tests::autostart_requires_explicit_opt_in"])
                .env(CHILD_EXPECTED, expected.to_string());
            match value {
                Some(value) => {
                    command.env(LOCAL_AUTOSTART_ENV, value);
                }
                None => {
                    command.env_remove(LOCAL_AUTOSTART_ENV);
                }
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "autostart case {value:?}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
}
