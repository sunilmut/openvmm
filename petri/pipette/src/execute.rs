// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Handler for the execute request.

// UNSAFETY: Required for libc calls (chroot, chdir, setsid, ioctl) in pre_exec on Linux.
#![cfg_attr(target_os = "linux", expect(unsafe_code))]

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::process::Stdio;

use pal_async::pipe::PolledPipe;
use pal_async::process::PolledChild;
use pal_async::task::Spawn;

pub fn handle_execute(
    driver: &pal_async::DefaultDriver,
    mut request: pipette_protocol::ExecuteRequest,
) -> anyhow::Result<pipette_protocol::ExecuteResponse> {
    tracing::debug!(?request, "execute request");

    let mut command = std::process::Command::new(&request.program);
    command.args(&request.args);
    if let Some(dir) = &request.current_dir {
        command.current_dir(dir);
    }

    // If a chroot is requested, set up a pre_exec hook to chroot the child process.
    if let Some(ref root) = request.chroot {
        #[cfg(target_os = "linux")]
        {
            let root = std::ffi::CString::new(root.as_str())?;
            // SAFETY: calling libc::chroot and libc::chdir in the child process
            // before exec. These are async-signal-safe on Linux.
            unsafe {
                command.pre_exec(move || {
                    if libc::chroot(root.as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::chdir(c"/".as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            anyhow::bail!("chroot is only supported on Linux");
        }
    }

    if request.clear_env {
        command.env_clear();
    }
    for pipette_protocol::EnvPair { name, value } in request.env {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    // Configure stdio, set up relay tasks, then spawn the child.
    //
    // Relay tasks are started before spawn — they simply block until the
    // child produces/consumes data. This keeps all fallible setup before
    // spawn() so a failure can't leak a running child process.
    //
    // PTY mode (Linux only): stdin/stdout/stderr go through a PTY secondary.
    // Combined stderr: stdout and stderr share an OS pipe.
    // Normal: each stream gets its own pipe.
    if request.allocate_pty {
        #[cfg(target_os = "linux")]
        {
            let (primary, secondary) = term::open_pty()?;
            command.stdin(Stdio::from(secondary.try_clone()?));
            command.stdout(Stdio::from(secondary.try_clone()?));
            command.stderr(Stdio::from(secondary));

            // Create a new session and acquire the controlling terminal.
            // The secondary fd is on stdin/stdout/stderr, so use fd 0 for TIOCSCTTY.
            // SAFETY: setsid and ioctl are async-signal-safe.
            unsafe {
                command.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let primary = PolledPipe::new(driver, primary)?;
            let (primary_read, primary_write) = primary.split();
            if let Some(stdin_pipe) = request.stdin.take() {
                driver
                    .spawn("pty_stdin_relay", relay(stdin_pipe, primary_write))
                    .detach();
            }
            if let Some(stdout_pipe) = request.stdout.take() {
                driver
                    .spawn("pty_stdout_relay", relay(primary_read, stdout_pipe))
                    .detach();
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("PTY allocation is only supported on Linux");
        }
    } else {
        if let Some(stdin_pipe) = request.stdin.take() {
            let (read_end, write_end) = pal::pipe_pair()?;
            command.stdin(Stdio::from(read_end));
            let write_end = PolledPipe::new(driver, write_end)?;
            driver
                .spawn("stdin_relay", relay(stdin_pipe, write_end))
                .detach();
        } else {
            command.stdin(Stdio::null());
        }

        if request.combine_stderr {
            if let Some(stdout_pipe) = request.stdout.take() {
                let (read_end, write_end) = pal::pipe_pair()?;
                command.stdout(Stdio::from(write_end.try_clone()?));
                command.stderr(Stdio::from(write_end));
                let read_end = PolledPipe::new(driver, read_end)?;
                driver
                    .spawn("combined_stdout_relay", relay(read_end, stdout_pipe))
                    .detach();
            } else {
                command.stdout(Stdio::null());
                command.stderr(Stdio::null());
            }
        } else {
            if let Some(stdout_pipe) = request.stdout.take() {
                let (read_end, write_end) = pal::pipe_pair()?;
                command.stdout(Stdio::from(write_end));
                let read_end = PolledPipe::new(driver, read_end)?;
                driver
                    .spawn("stdout_relay", relay(read_end, stdout_pipe))
                    .detach();
            } else {
                command.stdout(Stdio::null());
            }
            if let Some(stderr_pipe) = request.stderr.take() {
                let (read_end, write_end) = pal::pipe_pair()?;
                command.stderr(Stdio::from(write_end));
                let read_end = PolledPipe::new(driver, read_end)?;
                driver
                    .spawn("stderr_relay", relay(read_end, stderr_pipe))
                    .detach();
            } else {
                command.stderr(Stdio::null());
            }
        }
    }

    let child = command.spawn()?;
    let mut polled_child = PolledChild::<std::process::Child>::new(driver, child)
        .expect("process was just spawned, driver must be able to wait on it");
    let pid = polled_child.get().id();
    let (send, recv) = mesh::oneshot();

    driver
        .spawn("child_wait", async move {
            let exit_status = polled_child
                .wait()
                .await
                .expect("waiting on a spawned child should not fail");
            let status = convert_exit_status(exit_status);
            tracing::debug!(pid, ?status, "process exited");
            send.send(status);
        })
        .detach();
    Ok(pipette_protocol::ExecuteResponse { pid, result: recv })
}

async fn relay(
    mut read: impl futures::io::AsyncRead + Unpin,
    mut write: impl futures::io::AsyncWrite + Unpin,
) {
    let _ = futures::io::copy(&mut read, &mut write).await;
}

fn convert_exit_status(exit_status: std::process::ExitStatus) -> pipette_protocol::ExitStatus {
    if let Some(code) = exit_status.code() {
        return pipette_protocol::ExitStatus::Normal(code);
    }

    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&exit_status) {
        return pipette_protocol::ExitStatus::Signal(signal);
    }

    pipette_protocol::ExitStatus::Unknown
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use futures::AsyncReadExt;
    use futures::AsyncWriteExt;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pipette_protocol::EnvPair;
    use pipette_protocol::ExecuteRequest;
    use pipette_protocol::ExitStatus;

    fn request(program: &str, args: &[&str]) -> ExecuteRequest {
        ExecuteRequest {
            program: program.into(),
            args: args.iter().map(|&a| a.into()).collect(),
            current_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            env: Vec::new(),
            clear_env: false,
            chroot: None,
            allocate_pty: false,
            combine_stderr: false,
        }
    }

    fn sh(script: &str) -> ExecuteRequest {
        request("/bin/sh", &["-c", script])
    }

    async fn read_all(mut pipe: mesh::pipe::ReadPipe) -> Vec<u8> {
        let mut out = Vec::new();
        pipe.read_to_end(&mut out).await.unwrap();
        out
    }

    /// Runs `req` with fresh stdout/stderr pipes and returns the exit status,
    /// stdout bytes and stderr bytes.
    async fn run(
        driver: &DefaultDriver,
        mut req: ExecuteRequest,
    ) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let (out_r, out_w) = mesh::pipe::pipe();
        let (err_r, err_w) = mesh::pipe::pipe();
        req.stdout = Some(out_w);
        req.stderr = Some(err_w);
        let response = handle_execute(driver, req).unwrap();
        assert!(response.pid > 0);
        let status = response.result.await.unwrap();
        (status, read_all(out_r).await, read_all(err_r).await)
    }

    // Test: Run an owned shell command that writes binary data to stdout and
    //       stderr separately, then exits with status 4, and one killed by a signal.
    // Expected: Each stream is relayed byte-for-byte to its own pipe, the exit
    //       code is reported as Normal(4), and a signal death as Signal(9).
    #[async_test]
    async fn separate_streams_and_exit_statuses_are_reported(driver: DefaultDriver) {
        let (status, out, err) = run(
            &driver,
            sh(r"printf 'out\000\377'; printf 'err' >&2; exit 4"),
        )
        .await;
        assert!(matches!(status, ExitStatus::Normal(4)), "{status:?}");
        assert_eq!(out, b"out\0\xff");
        assert_eq!(err, b"err");
        let (status, _, _) = run(&driver, sh("kill -9 $$")).await;
        assert!(matches!(status, ExitStatus::Signal(9)), "{status:?}");
    }

    // Test: Combine stderr into stdout for a command writing to both, in order.
    // Expected: The stdout pipe receives both streams in write order and the
    //       separate stderr pipe receives nothing.
    #[async_test]
    async fn combined_stderr_shares_the_stdout_pipe(driver: DefaultDriver) {
        let mut req = sh("printf a; printf b >&2; printf c");
        req.combine_stderr = true;
        let (status, out, err) = run(&driver, req).await;
        assert!(matches!(status, ExitStatus::Normal(0)), "{status:?}");
        assert_eq!(out, b"abc");
        assert!(err.is_empty());
    }

    // Test: Run with a cleared environment plus one set and one removed variable,
    //       and in an owned working directory.
    // Expected: The child sees only the explicitly set variable, the removed one
    //       is absent, and its working directory is the requested directory.
    #[async_test]
    async fn environment_and_working_directory_are_applied(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let mut req = request("/usr/bin/env", &[]);
        req.clear_env = true;
        req.env = vec![
            EnvPair {
                name: "PIPETTE_SET".into(),
                value: Some("a b=c".into()),
            },
            EnvPair {
                name: "PIPETTE_GONE".into(),
                value: None,
            },
        ];
        let (_, out, _) = run(&driver, req).await;
        assert_eq!(String::from_utf8(out).unwrap(), "PIPETTE_SET=a b=c\n");

        let mut req = request("/bin/pwd", &["-P"]);
        req.current_dir = Some(dir.path().to_str().unwrap().into());
        let (_, out, _) = run(&driver, req).await;
        let expected = format!("{}\n", dir.path().display());
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    // Test: Relay stdin data through `cat`, and run with no stdin pipe.
    // Expected: Data written to the stdin pipe is echoed exactly once the pipe
    //       closes; without a pipe, stdin is empty (null) rather than inherited.
    #[async_test]
    async fn stdin_is_relayed_or_null(driver: DefaultDriver) {
        let (in_r, mut in_w) = mesh::pipe::pipe();
        let mut req = request("/bin/cat", &[]);
        req.stdin = Some(in_r);
        let (out_r, out_w) = mesh::pipe::pipe();
        req.stdout = Some(out_w);
        let response = handle_execute(&driver, req).unwrap();
        in_w.write_all(b"line one\nline two").await.unwrap();
        drop(in_w);
        assert_eq!(read_all(out_r).await, b"line one\nline two");
        let status = response.result.await.unwrap();
        assert!(matches!(status, ExitStatus::Normal(0)), "{status:?}");

        let (status, out, _) = run(&driver, request("/bin/cat", &[])).await;
        assert!(matches!(status, ExitStatus::Normal(0)), "{status:?}");
        assert!(out.is_empty());
    }

    // Test: Allocate a pseudo-terminal for a shell that checks its stdin.
    // Expected: The child's stdin is a terminal and its output is relayed
    //       through the PTY primary to the stdout pipe.
    #[async_test]
    async fn pty_gives_the_child_a_terminal(driver: DefaultDriver) {
        let mut req = sh("test -t 0 && printf tty");
        req.allocate_pty = true;
        let (out_r, out_w) = mesh::pipe::pipe();
        req.stdout = Some(out_w);
        let response = handle_execute(&driver, req).unwrap();
        let status = response.result.await.unwrap();
        assert!(matches!(status, ExitStatus::Normal(0)), "{status:?}");
        let mut out = vec![0; 3];
        let mut out_r = out_r;
        out_r.read_exact(&mut out).await.unwrap();
        assert_eq!(out, b"tty");
    }

    // Test: Request a program that does not exist, and a working directory
    //       that does not exist.
    // Expected: Spawning fails with an error instead of reporting a process.
    #[async_test]
    async fn spawn_failures_are_errors(driver: DefaultDriver) {
        assert!(handle_execute(&driver, request("/nonexistent/pipette-prog", &[])).is_err());
        let mut req = request("/bin/true", &[]);
        req.current_dir = Some("/nonexistent/pipette-dir".into());
        assert!(handle_execute(&driver, req).is_err());
    }
}
