// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::future::Either;
use futures::future::select;
use pal_async::timer::PolledTimer;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use test_with_tracing::test;

// Test: Construct a console with a recording terminal and default or explicitly empty title options.
// Expected: The public constructor creates a numeric temporary socket, launches the exact relay arguments, preserves an empty title as an argument, and exposes the connected child through AsyncRead.
#[async_test]
async fn public_constructor_creates_random_socket_and_relays_recorded_child(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let app = directory.path().join("recording-terminal");
    recording_app(&app);
    for options in [
        None,
        Some(ConsoleLaunchOptions {
            window_title: Some(String::new()),
        }),
    ] {
        let has_title = options.is_some();
        let mut console = Console::new(driver.clone(), Some(&app), options).unwrap();
        let receive = async {
            let mut data = Vec::new();
            console.read_to_end(&mut data).await.unwrap();
            data
        };
        let mut timer = PolledTimer::new(&driver);
        let mut data = match select(
            Box::pin(receive),
            Box::pin(timer.sleep(Duration::from_secs(10))),
        )
        .await
        {
            Either::Left((data, _)) => data,
            Either::Right(_) => panic!("constructed console did not receive child data"),
        };
        assert_eq!(data.pop(), Some(0));
        let args: Vec<OsString> = data
            .split(|byte| *byte == 0)
            .map(|arg| OsString::from_vec(arg.to_vec()))
            .collect();
        assert_eq!(args[0], "--");
        assert_eq!(args[1], std::env::current_exe().unwrap());
        assert_eq!(args[2], "--relay-console-path");
        let socket_path = Path::new(&args[3]);
        assert_eq!(socket_path.parent(), Some(std::env::temp_dir().as_path()));
        assert!(
            socket_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<u128>()
                .is_ok()
        );
        assert!(socket_path.exists());
        if has_title {
            assert_eq!(args.len(), 6);
            assert_eq!(args[4], "--relay-console-title");
            assert!(args[5].is_empty());
        } else {
            assert_eq!(args.len(), 4);
        }
        drop(console);
        std::fs::remove_file(socket_path).unwrap();
    }
}

// Test: Launch default terminals in isolated environments with tmux, X11, both, neither, empty values, missing candidates, and a nonexecutable preferred candidate.
// Expected: tmux wins when present, missing X11 candidates fall back to xterm, empty/unset environments report no terminal, and permission errors stop rather than falling back.
#[async_test]
async fn default_terminal_selection_and_fallback_are_environment_local(driver: DefaultDriver) {
    const CASE: &str = "OPENVMM_CONSOLE_RELAY_SELECTION_CASE";
    if let Some(case) = std::env::var_os(CASE) {
        let directory = tempfile::tempdir().unwrap();
        let relay_path = directory.path().join("selected.sock");
        if case == "none" || case == "empty" || case == "missing" {
            let error =
                launch_console(None, &relay_path, ConsoleLaunchOptions::default()).unwrap_err();
            assert_eq!(error.to_string(), "could not find a terminal emulator");
        } else if case == "denied" {
            let error =
                launch_console(None, &relay_path, ConsoleLaunchOptions::default()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert!(error.to_string().contains("tmux"));
        } else {
            let mut listener =
                PolledSocket::new(&driver, UnixListener::bind(&relay_path).unwrap()).unwrap();
            launch_console(None, &relay_path, ConsoleLaunchOptions::default()).unwrap();
            let args = recorded_args(&driver, &mut listener).await;
            let prefix: Vec<OsString> = if case == "display" {
                vec!["-e".into()]
            } else {
                vec!["new-window".into(), "--".into()]
            };
            let mut expected = prefix;
            expected.extend([
                std::env::current_exe().unwrap().into_os_string(),
                "--relay-console-path".into(),
                relay_path.into_os_string(),
            ]);
            assert_eq!(args, expected);
        }
        return;
    }
    for case in [
        "none", "empty", "tmux", "display", "both", "missing", "denied",
    ] {
        let bin = tempfile::tempdir().unwrap();
        if case != "missing" {
            recording_app(&bin.path().join("xterm"));
            recording_app(&bin.path().join("tmux"));
        }
        if case == "denied" {
            std::fs::set_permissions(
                bin.path().join("tmux"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "tests::launch_tests::default_terminal_selection_and_fallback_are_environment_local", "--nocapture"])
            .env(CASE, case).env("PATH", bin.path()).env_remove("TMUX").env_remove("DISPLAY");
        if ["tmux", "both", "denied"].contains(&case) {
            child.env("TMUX", "test-session");
        }
        if ["display", "both", "missing", "denied"].contains(&case) {
            child.env("DISPLAY", ":99");
        }
        if case == "empty" {
            child.env("TMUX", "").env("DISPLAY", "");
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "case {case}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn recording_app(path: &Path) {
    let exe = std::env::current_exe().unwrap();
    let quoted_exe = exe.as_os_str().to_str().unwrap().replace('\'', "'\\''");
    std::fs::write(path, format!("#!/bin/sh\nexec '{quoted_exe}' --exact tests::launch_tests::launch_preserves_terminal_separator_and_argv --nocapture -- \"$@\"\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

async fn recorded_args(
    driver: &DefaultDriver,
    listener: &mut PolledSocket<UnixListener>,
) -> Vec<OsString> {
    let receive = async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = PolledSocket::new(driver, stream).unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data.pop(), Some(0));
        data.split(|byte| *byte == 0)
            .map(|arg| OsString::from_vec(arg.to_vec()))
            .collect()
    };
    let mut timer = PolledTimer::new(driver);
    match select(
        Box::pin(receive),
        Box::pin(timer.sleep(Duration::from_secs(10))),
    )
    .await
    {
        Either::Left((args, _)) => args,
        Either::Right(_) => panic!("recording terminal did not report arguments"),
    }
}

// Test: Launch recording executables under supported terminal names, including non-UTF8 names, with absent and space-containing titles/paths.
// Expected: The child receives the terminal-specific separator, current executable, relay path, and optional title as exact distinct argv entries; no GUI is launched.
#[async_test]
async fn launch_preserves_terminal_separator_and_argv(driver: DefaultDriver) {
    let args: Vec<OsString> = std::env::args_os().collect();
    if let Some(path_index) = args.iter().position(|arg| arg == "--relay-console-path") {
        let start = args.iter().position(|arg| arg == "--").unwrap() + 1;
        let mut stream = std::os::unix::net::UnixStream::connect(&args[path_index + 1]).unwrap();
        for arg in &args[start..] {
            stream.write_all(arg.as_bytes()).unwrap();
            stream.write_all(&[0]).unwrap();
        }
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let names = [
        (OsString::from("xterm"), Some("-e")),
        (OsString::from("rxvt"), Some("-e")),
        (OsString::from("urxvt"), Some("-e")),
        (OsString::from("x-terminal-emulator"), Some("-e")),
        (OsString::from("custom terminal"), Some("--")),
        (OsString::from_vec(b"nonutf8-\xff".to_vec()), None),
    ];
    for (name, separator) in names {
        let app = directory.path().join(name);
        recording_app(&app);
        for title in [None, Some("title with spaces --not-an-option")] {
            let socket_dir = tempfile::tempdir().unwrap();
            let relay_path = socket_dir.path().join("relay with spaces.sock");
            let mut listener =
                PolledSocket::new(&driver, UnixListener::bind(&relay_path).unwrap()).unwrap();
            launch_console(
                Some(&app),
                &relay_path,
                ConsoleLaunchOptions {
                    window_title: title.map(str::to_owned),
                },
            )
            .unwrap();
            let actual = recorded_args(&driver, &mut listener).await;
            let mut expected = Vec::<OsString>::new();
            if let Some(separator) = separator {
                expected.push(separator.into());
            }
            expected.extend([
                std::env::current_exe().unwrap().into_os_string(),
                "--relay-console-path".into(),
                relay_path.into_os_string(),
            ]);
            if let Some(title) = title {
                expected.extend(["--relay-console-title".into(), title.into()]);
            }
            assert_eq!(actual, expected);
        }
    }
}
