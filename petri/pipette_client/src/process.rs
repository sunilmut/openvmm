// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code to launch a command inside the guest.

use crate::PipetteClient;
use anyhow::Context;
use futures::AsyncReadExt;
use futures::executor::block_on;
use futures::io::AllowStdIo;
use futures_concurrency::future::Join;
use mesh::pipe::ReadPipe;
use mesh::pipe::WritePipe;
use pipette_protocol::EnvPair;
use pipette_protocol::PipetteRequest;
use std::fmt;

/// A builder for launching a command inside the guest.
///
/// This has a similar API to [`std::process::Command`].
pub struct Command<'a> {
    client: &'a PipetteClient,
    program: String,
    args: Vec<String>,
    current_dir: Option<String>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    env: Vec<EnvPair>,
    clear_env: bool,
    chroot: Option<String>,
    allocate_pty: bool,
    combine_stderr: bool,
}

impl<'a> Command<'a> {
    pub(super) fn new(client: &'a PipetteClient, program: impl AsRef<str>) -> Self {
        Self {
            client,
            program: program.as_ref().to_owned(),
            args: Vec::new(),
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

    /// Adds an argument to the command.
    pub fn arg(&mut self, arg: impl AsRef<str>) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Adds multiple arguments to the command.
    pub fn args<I: IntoIterator>(&mut self, args: I) -> &mut Self
    where
        I::Item: AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|item| item.as_ref().to_owned()));
        self
    }

    /// Sets the current working directory for the command.
    pub fn current_dir(&mut self, dir: impl AsRef<str>) -> &mut Self {
        self.current_dir = Some(dir.as_ref().to_owned());
        self
    }

    /// Clears the environment before setting the new environment.
    pub fn env_clear(&mut self) -> &mut Self {
        self.clear_env = true;
        self.env.clear();
        self
    }

    /// Sets an environment variable for the command.
    pub fn env(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> &mut Self {
        self.env.push(EnvPair {
            name: name.as_ref().to_owned(),
            value: Some(value.as_ref().to_owned()),
        });
        self
    }

    /// Removes an environment variable for the command.
    pub fn env_remove(&mut self, name: impl AsRef<str>) -> &mut Self {
        self.env.push(EnvPair {
            name: name.as_ref().to_owned(),
            value: None,
        });
        self
    }

    /// Sets the stdin for the command.
    pub fn stdin(&mut self, stdin: impl Into<Stdio>) -> &mut Self {
        self.stdin = Some(stdin.into());
        self
    }

    /// Sets the stdout for the command.
    pub fn stdout(&mut self, stdout: impl Into<Stdio>) -> &mut Self {
        self.stdout = Some(stdout.into());
        self
    }

    /// Sets the stderr for the command.
    pub fn stderr(&mut self, stderr: impl Into<Stdio>) -> &mut Self {
        self.stderr = Some(stderr.into());
        self
    }

    /// Sets the chroot directory for the command (Linux only).
    pub fn chroot(&mut self, root: impl AsRef<str>) -> &mut Self {
        self.chroot = Some(root.as_ref().to_owned());
        self
    }

    /// Allocate a PTY for the child process (Linux guests only).
    ///
    /// When set, stdin/stdout/stderr are all connected to a PTY secondary,
    /// enabling terminal features like Ctrl-C signal propagation and
    /// line editing. The PTY primary is relayed through the stdout pipe.
    pub fn pty(&mut self, allocate: bool) -> &mut Self {
        self.allocate_pty = allocate;
        self
    }

    /// Redirect stderr to the stdout pipe.
    ///
    /// When set, the child's stderr is merged into stdout so callers
    /// receive interleaved output through a single stream.
    pub fn combine_stderr(&mut self, combine: bool) -> &mut Self {
        self.combine_stderr = combine;
        self
    }

    /// Spawns the command, defaulting to inheriting (relaying, really) the
    /// current process for stdin, stdout, and stderr.
    pub async fn spawn(&self) -> anyhow::Result<Child> {
        self.spawn_inner(&StdioInner::Inherit, true).await
    }

    /// Spawns the command, capturing the standard output and standard error
    /// (if they are not already set).
    pub async fn output(&self) -> anyhow::Result<Output> {
        let child = self.spawn_inner(&StdioInner::Piped, false).await?;
        child.wait_with_output().await
    }

    async fn spawn_inner(
        &self,
        default_stdio: &StdioInner,
        default_stdin: bool,
    ) -> anyhow::Result<Child> {
        let (stdin_read, stdin_write) = self
            .stdin
            .as_ref()
            .map_or(
                if default_stdin {
                    default_stdio
                } else {
                    &StdioInner::Null
                },
                |x| &x.0,
            )
            .pipes(StdioFd::Stdin);

        let (stdout_read, stdout_write) = self
            .stdout
            .as_ref()
            .map_or(default_stdio, |x| &x.0)
            .pipes(StdioFd::Stdout);
        let (stderr_read, stderr_write) = if self.combine_stderr {
            (None, None)
        } else {
            self.stderr
                .as_ref()
                .map_or(default_stdio, |x| &x.0)
                .pipes(StdioFd::Stderr)
        };

        let request = pipette_protocol::ExecuteRequest {
            program: self.program.clone(),
            args: self.args.clone(),
            current_dir: self.current_dir.clone(),
            stdin: stdin_read,
            stdout: stdout_write,
            stderr: stderr_write,
            env: self.env.clone(),
            clear_env: self.clear_env,
            chroot: self.chroot.clone(),
            allocate_pty: self.allocate_pty,
            combine_stderr: self.combine_stderr,
        };

        let response = self
            .client
            .send
            .call_failable(PipetteRequest::Execute, request)
            .await
            .with_context(|| format!("failed to execute {}", self.program))?;

        Ok(Child {
            stdin: stdin_write,
            stdout: stdout_read,
            stderr: stderr_read,
            pid: response.pid,
            result: Ok(response.result),
        })
    }
}

/// Describes what to do with a standard I/O stream for a child process.
pub struct Stdio(StdioInner);

enum StdioInner {
    Inherit,
    Null,
    Piped,
}

impl Stdio {
    /// This stream will be "inherited" from the parent process.
    ///
    /// Internally, this will relay the standard input, output, or error of the
    /// current process to the guest process.
    pub fn inherit() -> Self {
        Self(StdioInner::Inherit)
    }

    /// This stream will be ignored by the child process.
    pub fn null() -> Self {
        Self(StdioInner::Null)
    }

    /// A new pipe will be created to communicate with the child process.
    pub fn piped() -> Self {
        Self(StdioInner::Piped)
    }
}

enum StdioFd {
    Stdin,
    Stdout,
    Stderr,
}

impl StdioInner {
    fn pipes(&self, fd: StdioFd) -> (Option<ReadPipe>, Option<WritePipe>) {
        match self {
            StdioInner::Null => (None, None),
            StdioInner::Piped => {
                let (read, write) = mesh::pipe::pipe();
                (Some(read), Some(write))
            }
            StdioInner::Inherit => {
                let (read, mut write) = mesh::pipe::pipe();
                match fd {
                    StdioFd::Stdin => {
                        std::thread::Builder::new()
                            .name("stdin-relay".to_owned())
                            .spawn({
                                move || {
                                    block_on(futures::io::copy(
                                        AllowStdIo::new(std::io::stdin()),
                                        &mut write,
                                    ))
                                }
                            })
                            .unwrap();
                        (Some(read), None)
                    }
                    StdioFd::Stdout => {
                        std::thread::Builder::new()
                            .name("stdout-relay".to_owned())
                            .spawn({
                                move || {
                                    block_on(futures::io::copy(
                                        read,
                                        &mut AllowStdIo::new(term::raw_stdout()),
                                    ))
                                }
                            })
                            .unwrap();
                        (None, Some(write))
                    }
                    StdioFd::Stderr => {
                        std::thread::Builder::new()
                            .name("stderr-relay".to_owned())
                            .spawn({
                                move || {
                                    block_on(futures::io::copy(
                                        read,
                                        &mut AllowStdIo::new(term::raw_stderr()),
                                    ))
                                }
                            })
                            .unwrap();
                        (None, Some(write))
                    }
                }
            }
        }
    }
}

/// A spawned child process, similar to [`std::process::Child`].
pub struct Child {
    /// The standard input pipe of the process.
    pub stdin: Option<WritePipe>,
    /// The standard output pipe of the process.
    pub stdout: Option<ReadPipe>,
    /// The standard error pipe of the process.
    pub stderr: Option<ReadPipe>,
    pid: u32,
    result: Result<mesh::OneshotReceiver<pipette_protocol::ExitStatus>, ExitStatus>,
}

impl Child {
    /// Returns the process ID of the child within the guest.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Waits for the child to exit, returning the exit status.
    pub async fn wait(&mut self) -> Result<ExitStatus, mesh::RecvError> {
        match &mut self.result {
            Ok(recv) => {
                let status = ExitStatus(recv.await?);
                self.result = Err(status.clone());
                Ok(status)
            }
            Err(status) => Ok(status.clone()),
        }
    }

    /// Waits for the child to exit, returning the exit status and the
    /// remaining data from standard output and standard error.
    pub async fn wait_with_output(mut self) -> anyhow::Result<Output> {
        self.stdin = None;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let stdout_pipe = self.stdout.take();
        let stderr_pipe = self.stderr.take();
        let stdout_task = async {
            if let Some(mut pipe) = stdout_pipe {
                let _ = pipe.read_to_end(&mut stdout).await;
            }
        };
        let stderr_task = async {
            if let Some(mut pipe) = stderr_pipe {
                let _ = pipe.read_to_end(&mut stderr).await;
            }
        };
        let wait_task = self.wait();
        let (status, (), ()) = (wait_task, stdout_task, stderr_task).join().await;
        let status = status?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

/// The exit status of a process.
#[derive(Debug, Clone)]
pub struct ExitStatus(pipette_protocol::ExitStatus);

impl ExitStatus {
    /// Returns `true` if the process exited successfully.
    pub fn success(&self) -> bool {
        matches!(self.0, pipette_protocol::ExitStatus::Normal(0))
    }

    /// Returns the exit code of the process, if it exited normally.
    pub fn code(&self) -> Option<i32> {
        match self.0 {
            pipette_protocol::ExitStatus::Normal(code) => Some(code),
            pipette_protocol::ExitStatus::Signal(_) | pipette_protocol::ExitStatus::Unknown => None,
        }
    }

    /// Returns the signal that terminated the process, if it was terminated
    /// by a signal.
    pub fn signal(&self) -> Option<i32> {
        match self.0 {
            pipette_protocol::ExitStatus::Signal(signal) => Some(signal),
            pipette_protocol::ExitStatus::Normal(_) | pipette_protocol::ExitStatus::Unknown => None,
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            pipette_protocol::ExitStatus::Normal(code) if code >= 0 => {
                write!(f, "exit code {}", code)
            }
            pipette_protocol::ExitStatus::Normal(code) => write!(f, "exit code {:#x}", code as u32),
            pipette_protocol::ExitStatus::Signal(signal) => {
                write!(f, "terminated by signal {}", signal)
            }
            pipette_protocol::ExitStatus::Unknown => write!(f, "unknown exit status"),
        }
    }
}

/// The result of a process execution.
pub struct Output {
    /// The exit status of the process.
    pub status: ExitStatus,
    /// The standard output of the process.
    pub stdout: Vec<u8>,
    /// The standard error of the process.
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncWriteExt;
    use test_with_tracing::test;

    // Test: Wait twice for a child whose exit status arrives through a one-shot channel.
    // Expected: Both waits return the original status; the second wait uses
    //       retained completion instead of consuming the one-shot channel again.
    #[test]
    fn repeated_wait_retains_the_original_completion() {
        block_on(async {
            let (send, recv) = mesh::oneshot();
            let mut child = Child {
                stdin: None,
                stdout: None,
                stderr: None,
                pid: 17,
                result: Ok(recv),
            };
            send.send(pipette_protocol::ExitStatus::Normal(37));
            assert_eq!(child.wait().await.unwrap().code(), Some(37));
            assert_eq!(child.wait().await.unwrap().code(), Some(37));
        });
    }

    // Test: Capture separate binary streams while the producer waits for stdin EOF,
    //       sends pipe-sized payloads and reports completion only after writing.
    // Expected: Waiting closes stdin, drains both streams without a status-first
    //       deadlock and returns the exact distinct bytes and reported exit status.
    #[test]
    fn output_wait_closes_stdin_and_drains_both_streams_before_completion() {
        block_on(async {
            let (mut stdin_read, stdin_write) = mesh::pipe::pipe();
            let (stdout_read, mut stdout_write) = mesh::pipe::pipe();
            let (stderr_read, mut stderr_write) = mesh::pipe::pipe();
            let (send, recv) = mesh::oneshot();
            let child = Child {
                stdin: Some(stdin_write),
                stdout: Some(stdout_read),
                stderr: Some(stderr_read),
                pid: 17,
                result: Ok(recv),
            };
            let stdout = b"out\0\xff".repeat(30_000);
            let stderr = b"err\0\x80".repeat(20_000);
            let producer = async {
                let mut input = Vec::new();
                stdin_read.read_to_end(&mut input).await.unwrap();
                assert!(input.is_empty());
                stdout_write.write_all(&stdout).await.unwrap();
                drop(stdout_write);
                stderr_write.write_all(&stderr).await.unwrap();
                drop(stderr_write);
                send.send(pipette_protocol::ExitStatus::Normal(19));
            };
            let (output, ()) = (child.wait_with_output(), producer).join().await;
            let output = output.unwrap();
            assert_eq!(output.stdout, stdout);
            assert_eq!(output.stderr, stderr);
            assert_eq!(output.status.code(), Some(19));
            assert!(!output.status.success());
        });
    }

    // Test: Lose the status sender while both output streams end normally.
    // Expected: Capturing output reports the missing completion channel as an
    //       error, rather than manufacturing a successful or unknown exit status.
    #[test]
    fn output_wait_reports_a_disconnected_completion_channel() {
        block_on(async {
            let (stdout, stdout_send) = mesh::pipe::pipe();
            let (stderr, stderr_send) = mesh::pipe::pipe();
            drop(stdout_send);
            drop(stderr_send);
            let (send, recv) = mesh::oneshot::<pipette_protocol::ExitStatus>();
            drop(send);
            let child = Child {
                stdin: None,
                stdout: Some(stdout),
                stderr: Some(stderr),
                pid: 17,
                result: Ok(recv),
            };
            let error = match child.wait_with_output().await {
                Err(error) => error,
                Ok(_) => panic!("missing process completion unexpectedly succeeded"),
            };
            assert!(error.downcast_ref::<mesh::RecvError>().is_some());
        });
    }
}
