// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::StreamExt;
use futures::TryStreamExt;
use std::io::Write;
use test_with_tracing::test;

struct InputRecorder(mesh::Sender<Vec<u8>>);

impl AsyncWrite for InputRecorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.send(bytes.to_vec());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// Test: Run raw stdio relay under util-linux script in an isolated pseudo-terminal, feeding stdin and gating binary stdout on receiving that exact input.
// Expected: The input thread forwards the complete line, stdout preserves binary bytes exactly once, and the requested terminal title is emitted without modifying the parent terminal.
#[test]
fn raw_stdio_forwards_input_output_and_title_in_isolated_terminal() {
    const CHILD: &str = "OPENVMM_CONSOLE_RELAY_STDIO_CHILD";
    const INPUT: &[u8] = b"stdin-probe\n";
    const OUTPUT: &[u8] = b"stdout-probe\0\xff\n";
    const TITLE: &str = "raw-console-title-probe";
    if std::env::var_os(CHILD).is_some() {
        let (sender, mut receiver) = mesh::channel::<Vec<u8>>();
        let read = futures::stream::once(async move {
            let mut input = Vec::new();
            while input.len() < INPUT.len() {
                input.extend(receiver.recv().await.unwrap());
            }
            assert_eq!(input, INPUT);
            Ok::<_, std::io::Error>(OUTPUT.to_vec())
        })
        .boxed()
        .into_async_read();
        block_on(relay_stdio(read, InputRecorder(sender), TITLE)).unwrap();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let quoted_exe = exe.as_os_str().to_str().unwrap().replace('\'', "'\\''");
    let command = format!(
        "'{quoted_exe}' --exact tests::stdio_tests::raw_stdio_forwards_input_output_and_title_in_isolated_terminal --nocapture"
    );
    let mut child = Command::new("script")
        .args([
            "--quiet",
            "--return",
            "--echo",
            "never",
            "--command",
            &command,
            "/dev/null",
        ])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("raw stdio test requires util-linux script");
    child.stdin.as_mut().unwrap().write_all(INPUT).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output
            .stdout
            .windows(OUTPUT.len())
            .filter(|bytes| *bytes == OUTPUT)
            .count(),
        1
    );
    assert!(
        output
            .stdout
            .windows(TITLE.len())
            .any(|bytes| bytes == TITLE.as_bytes())
    );
}
