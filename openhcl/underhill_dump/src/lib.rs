// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Underhill process for writing core dumps.
//!
//! `underhill_dump <pid>`
//!
//! This command writes a core dump of process `pid` to stdout.
//!
//! This is done as a separate process instead of inside the diagnostics process
//! for two reasons:
//!
//! 1. To allow us to dump the diagnostics process.
//! 2. To ensure that waitpid() calls by the diagnostics process do not get
//!    tracing stop notifications.

#![cfg(target_os = "linux")]
#![expect(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::Context;
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use tracing::Level;

const KMSG_NOTE_BYTES: usize = 1024 * 256; // 256 KB

pub fn main() -> ! {
    if let Err(e) = do_main() {
        tracing::error!(?e, "core dump error");
        std::process::exit(libc::EXIT_FAILURE)
    }

    std::process::exit(libc::EXIT_SUCCESS)
}

pub fn do_main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();

    let level = if args.peek().is_some_and(|x| x == "-v") {
        args.next();
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .log_internal_errors(true)
        .with_max_level(level)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .compact()
        .with_ansi(false)
        .init();

    // We should have checks in our callers so this is never hit, but let's be safe.
    if underhill_confidentiality::confidential_filtering_enabled() {
        tracing::info!("crash reporting disabled due to CVM");
        std::process::exit(libc::EXIT_FAILURE);
    }

    let pid: i32 = args
        .next()
        .context("missing pid")?
        .parse()
        .context("failed to parse pid")?;

    if args.next().is_some() {
        anyhow::bail!("unexpected extra arguments");
    }

    let mut builder = elfcore::CoreDumpBuilder::new(pid)?;

    let mut kmsg_file = NonBlockingFile::new("/dev/kmsg");
    match kmsg_file.as_mut() {
        Ok(kmsg_file) => _ = builder.add_custom_file_note("KMSG", kmsg_file, KMSG_NOTE_BYTES),
        Err(e) => tracing::error!("Failed to open KMSG file: {:?}", e),
    }

    let n = builder
        .write(std::io::stdout().lock())
        .context("failed to write core dump")?;

    tracing::info!("dump: {} bytes", n);

    Ok(())
}

struct NonBlockingFile(File);

impl NonBlockingFile {
    fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)?,
        ))
    }
}

impl std::io::Read for NonBlockingFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf) {
            // return data
            Ok(len) => Ok(len),
            // would block, we are done
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
            // continue on interruptions or broken pipe, since
            // if old messages are overwritten while /dev/kmsg is open,
            // the next read returns -EPIPE
            Err(ref err)
                if err.kind() == ErrorKind::Interrupted || err.kind() == ErrorKind::BrokenPipe =>
            {
                self.read(buf)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::FcntlArg;
    use nix::fcntl::OFlag;
    use nix::fcntl::fcntl;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use test_with_tracing::test;

    // Test: Open an owned note file and read binary contents through EOF.
    // Expected: The descriptor is nonblocking and preserves every byte,
    //       including NUL/non-UTF-8 data, across short reads.
    #[test]
    fn constructor_opens_nonblocking_and_preserves_note_bytes() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"note\0\xfftail").unwrap();
        let mut reader = NonBlockingFile::new(file.path()).unwrap();
        let flags = fcntl(&reader.0, FcntlArg::F_GETFL).unwrap();
        assert!(OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK));

        let mut prefix = [0; 2];
        assert_eq!(reader.read(&mut prefix).unwrap(), 2);
        assert_eq!(&prefix, b"no");
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, b"te\0\xfftail");
        assert_eq!(reader.read(&mut prefix).unwrap(), 0);
    }

    // Test: Drain a live nonblocking stream, then append another note.
    // Expected: WouldBlock ends only the current drain without losing bytes
    //       or preventing later reads while the producer remains connected.
    #[test]
    fn would_block_ends_current_drain_and_allows_later_data() {
        let (stream, mut producer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut reader = NonBlockingFile(File::from(OwnedFd::from(stream)));
        producer.write_all(b"first\n").unwrap();

        let mut notes = b"prefix\n".to_vec();
        assert_eq!(reader.read_to_end(&mut notes).unwrap(), 6);
        assert_eq!(notes, b"prefix\nfirst\n");
        producer.write_all(b"second\n").unwrap();
        assert_eq!(reader.read_to_end(&mut notes).unwrap(), 7);
        assert_eq!(notes, b"prefix\nfirst\nsecond\n");
    }

    // Test: Open a missing note and read a descriptor that names a directory.
    // Expected: Both failures retain their OS errors rather than becoming
    //       empty successful notes or being retried indefinitely.
    #[test]
    fn open_and_nonretryable_read_errors_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let error = NonBlockingFile::new(directory.path().join("missing"))
            .err()
            .expect("missing note unexpectedly opened");
        assert_eq!(error.kind(), ErrorKind::NotFound);

        let mut reader = NonBlockingFile::new(directory.path()).unwrap();
        let error = reader.read(&mut [0; 1]).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EISDIR));
    }
}
