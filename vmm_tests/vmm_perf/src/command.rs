// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::config::VmmPerfProfileVariant;
use super::host::platform_command;
use anyhow::Context as _;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io::BufRead as _;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;

pub(crate) struct VirtualClientCommandBuilder<'a> {
    runtime_dir: &'a Path,
    virtual_client: &'a Path,
    profile: Option<VmmPerfProfileVariant>,
    iterations: Option<u32>,
    metadata: BTreeMap<String, String>,
    parameters: BTreeMap<String, String>,
    package_dir: Option<PathBuf>,
    log_dir: Option<&'a Path>,
    experiment_id: Option<String>,
    loggers: Vec<&'a str>,
    log_to_file: bool,
    temp_dir: Option<&'a Path>,
}

#[derive(Debug, Eq, PartialEq)]
struct VirtualClientInvocation {
    program: PathBuf,
    current_dir: PathBuf,
    args: Vec<String>,
    env: Vec<(String, PathBuf)>,
}

impl<'a> VirtualClientCommandBuilder<'a> {
    pub(crate) fn new(runtime_dir: &'a Path, virtual_client: &'a Path) -> Self {
        Self {
            runtime_dir,
            virtual_client,
            profile: None,
            iterations: None,
            metadata: BTreeMap::new(),
            parameters: BTreeMap::new(),
            package_dir: None,
            log_dir: None,
            experiment_id: None,
            loggers: Vec::new(),
            log_to_file: false,
            temp_dir: None,
        }
    }

    pub(crate) fn profile(mut self, profile: VmmPerfProfileVariant) -> Self {
        self.profile = Some(profile);
        self
    }

    pub(crate) fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = Some(iterations);
        self
    }

    pub(crate) fn parameter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(name.into(), value.into());
        self
    }

    pub(crate) fn metadata(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(name.into(), value.into());
        self
    }

    pub(crate) fn package_dir(mut self, package_dir: &Path) -> Self {
        self.package_dir = Some(package_dir.to_owned());
        self
    }

    pub(crate) fn log_dir(mut self, log_dir: &'a Path) -> Self {
        self.log_dir = Some(log_dir);
        self
    }

    pub(crate) fn experiment_id(mut self, experiment_id: &str) -> Self {
        self.experiment_id = Some(experiment_id.to_owned());
        self
    }

    pub(crate) fn logger(mut self, logger: &'a str) -> Self {
        self.loggers.push(logger);
        self
    }

    pub(crate) fn log_to_file(mut self, log_to_file: bool) -> Self {
        self.log_to_file = log_to_file;
        self
    }

    pub(crate) fn temp_dir(mut self, temp_dir: &'a Path) -> Self {
        self.temp_dir = Some(temp_dir);
        self
    }

    pub(crate) fn build(self) -> anyhow::Result<Command> {
        self.build_invocation()?.into_command()
    }

    fn build_invocation(self) -> anyhow::Result<VirtualClientInvocation> {
        let profile = self.profile.context("VirtualClient profile was not set")?;
        let iterations = self
            .iterations
            .context("VirtualClient iterations were not set")?;
        let package_dir = self
            .package_dir
            .context("VirtualClient package directory was not set")?;
        let log_dir = self
            .log_dir
            .context("VirtualClient log directory was not set")?;
        let experiment_id = self
            .experiment_id
            .context("VirtualClient experiment ID was not set")?;
        let temp_dir = self
            .temp_dir
            .context("VirtualClient temp directory was not set")?;
        anyhow::ensure!(
            !self.loggers.is_empty(),
            "VirtualClient requires at least one logger"
        );

        let mut args = vec![
            format!(
                "--profile={}",
                self.runtime_dir
                    .join("profiles")
                    .join(profile.file())
                    .display()
            ),
            format!("--iterations={iterations}"),
            format!("--package-dir={}", package_dir.display()),
            format!("--log-dir={}", log_dir.display()),
            format!("--experiment-id={experiment_id}"),
        ];
        if !self.metadata.is_empty() {
            let metadata = self
                .metadata
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(",,,");
            args.push(format!("--metadata={metadata}"));
        }
        for (name, value) in self.parameters {
            args.push(format!("--parameters={name}={value}"));
        }
        for logger in self.loggers {
            args.push(format!("--logger={logger}"));
        }
        if self.log_to_file {
            args.push("--log-to-file".into());
        }

        Ok(VirtualClientInvocation {
            program: self.virtual_client.to_owned(),
            current_dir: self.runtime_dir.to_owned(),
            args,
            env: vec![
                ("TEMP".into(), temp_dir.to_owned()),
                ("TMP".into(), temp_dir.to_owned()),
                ("TMPDIR".into(), temp_dir.to_owned()),
            ],
        })
    }
}

impl VirtualClientInvocation {
    fn into_command(self) -> anyhow::Result<Command> {
        let env = self
            .env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_path()))
            .collect::<Vec<_>>();
        let mut command = platform_command(&self.program, &env)?;
        command.current_dir(&self.current_dir);
        command.args(&self.args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        Ok(command)
    }
}

pub(crate) fn run_command(
    command: &mut Command,
    console_log_path: &Path,
    config_name: &str,
) -> anyhow::Result<std::process::ExitStatus> {
    let log_file = fs_err::File::create(console_log_path).with_context(|| {
        format!(
            "failed to create VMM.Perf console log {}",
            console_log_path.display()
        )
    })?;
    let log_file = Arc::new(Mutex::new(BufWriter::new(log_file)));
    let mut child = command
        .spawn()
        .context("failed to launch VMM.Perf VirtualClient")?;
    let stdout = child
        .stdout
        .take()
        .context("VMM.Perf VirtualClient stdout was not piped")?;
    let stderr = child
        .stderr
        .take()
        .context("VMM.Perf VirtualClient stderr was not piped")?;
    let stdout_log = Arc::clone(&log_file);
    let stderr_log = Arc::clone(&log_file);

    std::thread::scope(|scope| {
        let stdout_task =
            scope.spawn(move || log_process_output("stdout", stdout, config_name, stdout_log));
        let stderr_task =
            scope.spawn(move || log_process_output("stderr", stderr, config_name, stderr_log));
        let status = child
            .wait()
            .context("failed to wait for VMM.Perf VirtualClient");
        let stdout_result = match stdout_task.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "VMM.Perf VirtualClient stdout logging thread panicked"
            )),
        };
        let stderr_result = match stderr_task.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "VMM.Perf VirtualClient stderr logging thread panicked"
            )),
        };
        let flush_result = log_file.lock().flush().with_context(|| {
            format!(
                "failed to flush VMM.Perf console log {}",
                console_log_path.display()
            )
        });
        let status = status?;
        stdout_result?;
        stderr_result?;
        flush_result?;
        Ok(status)
    })
}

fn log_process_output(
    stream_name: &str,
    stream: impl Read,
    config_name: &str,
    log_file: Arc<Mutex<BufWriter<fs_err::File>>>,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .with_context(|| format!("failed to read VMM.Perf VirtualClient {stream_name}"))?;
        if bytes_read == 0 {
            return Ok(());
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        let line = String::from_utf8_lossy(&line).into_owned();
        if stream_name == "stderr" {
            tracing::warn!(
                configuration = config_name,
                stream = stream_name,
                line = %line,
                "VirtualClient output"
            );
        } else {
            tracing::info!(
                configuration = config_name,
                stream = stream_name,
                line = %line,
                "VirtualClient output"
            );
        }
        let mut log_file = log_file.lock();
        writeln!(log_file, "[{stream_name}] {line}")
            .with_context(|| format!("failed to write VMM.Perf {stream_name} console output"))?;
        log_file
            .flush()
            .with_context(|| format!("failed to flush VMM.Perf {stream_name} console output"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::VirtualClientCommandBuilder;
    use crate::config::VmmPerfProfileVariant;
    use std::path::Path;
    use test_with_tracing::test;

    #[test]
    fn builds_virtual_client_arguments() -> anyhow::Result<()> {
        let runtime_dir = Path::new("runtime");
        let log_dir = Path::new("out");
        let profile = "fio"
            .parse::<VmmPerfProfileVariant>()
            .expect("test profile is valid");
        let invocation = VirtualClientCommandBuilder::new(
            runtime_dir,
            &runtime_dir.join(crate::runtime::virtual_client_name()),
        )
        .profile(profile.clone())
        .iterations(1)
        .parameter("CpuCount", "4")
        .parameter("MemoryMB", "4096")
        .package_dir(&runtime_dir.join("packages"))
        .log_dir(log_dir)
        .experiment_id("exp-1")
        .logger("file")
        .logger("summary")
        .log_to_file(true)
        .temp_dir(Path::new("temp"))
        .build_invocation()?;

        assert!(invocation.args.contains(&format!(
            "--profile={}",
            runtime_dir.join("profiles").join(profile.file()).display()
        )));
        assert!(invocation.args.contains(&"--iterations=1".to_string()));
        assert!(invocation.args.contains(&format!(
            "--package-dir={}",
            runtime_dir.join("packages").display()
        )));
        assert!(
            invocation
                .args
                .contains(&format!("--log-dir={}", log_dir.display()))
        );
        assert!(
            invocation
                .args
                .contains(&"--experiment-id=exp-1".to_string())
        );
        assert!(
            invocation
                .args
                .contains(&"--parameters=CpuCount=4".to_string())
        );
        assert!(
            invocation
                .args
                .contains(&"--parameters=MemoryMB=4096".to_string())
        );
        assert!(invocation.args.contains(&"--logger=file".to_string()));
        assert!(invocation.args.contains(&"--logger=summary".to_string()));
        assert!(invocation.args.contains(&"--log-to-file".to_string()));
        assert_eq!(
            invocation.env,
            vec![
                ("TEMP".into(), Path::new("temp").to_path_buf()),
                ("TMP".into(), Path::new("temp").to_path_buf()),
                ("TMPDIR".into(), Path::new("temp").to_path_buf()),
            ]
        );
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod process_tests {
    use super::run_command;
    use crate::test_support;
    use std::process::Command;
    use std::process::Stdio;
    use test_with_tracing::test;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    // Test: Run an owned shell command that writes CRLF, LF, unterminated and
    //       invalid UTF-8 lines to both streams, then exits with status 3.
    // Expected: The exit status is returned unchanged, and the console log keeps
    //       every line per stream in order with its tag and line endings removed.
    #[test]
    fn console_log_tags_each_stream_line_and_preserves_status() -> anyhow::Result<()> {
        let dir = test_support::tempdir("console")?;
        let log = dir.path().join("console.log");
        let status = run_command(
            &mut shell(r"printf 'one\r\ntwo\n\377x\nlast'; printf 'err1\nerr2\r\n' >&2; exit 3"),
            &log,
            "cfg",
        )?;
        assert_eq!(status.code(), Some(3));
        let text = fs_err::read_to_string(&log)?;
        let lines: Vec<_> = text.lines().collect();
        let stdout: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("[stdout] "))
            .copied()
            .collect();
        let stderr: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("[stderr] "))
            .copied()
            .collect();
        assert_eq!(
            stdout,
            [
                "[stdout] one",
                "[stdout] two",
                "[stdout] \u{fffd}x",
                "[stdout] last"
            ]
        );
        assert_eq!(stderr, ["[stderr] err1", "[stderr] err2"]);
        assert_eq!(lines.len(), 6);
        Ok(())
    }

    // Test: Run a missing program, and a command whose console log directory
    //       does not exist.
    // Expected: Launch failure and log creation failure are reported distinctly
    //       rather than as a successful empty run.
    #[test]
    fn launch_and_log_failures_are_reported_distinctly() -> anyhow::Result<()> {
        let dir = test_support::tempdir("failures")?;
        let mut missing = Command::new(dir.path().join("no-such-program"));
        missing.stdout(Stdio::piped()).stderr(Stdio::piped());
        let error = run_command(&mut missing, &dir.path().join("log"), "cfg").unwrap_err();
        assert!(
            format!("{error:#}").contains("failed to launch VMM.Perf VirtualClient"),
            "{error:#}"
        );

        let error =
            run_command(&mut shell("true"), &dir.path().join("no/dir/log"), "cfg").unwrap_err();
        assert!(
            format!("{error:#}").contains("failed to create VMM.Perf console log"),
            "{error:#}"
        );
        Ok(())
    }
}
