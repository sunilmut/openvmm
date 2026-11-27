// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This module implements the an interface to the kernel logger.
//!
//! Underhill_init performs no filtering of its logging messages when running in
//! a confidential VM. This is because it runs before any keys can be accessed
//! or any guest code is executed, and therefore it can not leak anything
//! sensitive.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;

pub struct SysLog {
    kmsg: File,
}

impl log::Log for SysLog {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        // Match the log levels fairly close to the kernel log level semantics.
        let level = match record.level() {
            log::Level::Error => kmsg_defs::LOGLEVEL_ERR,
            log::Level::Warn => kmsg_defs::LOGLEVEL_WARNING,
            log::Level::Info => kmsg_defs::LOGLEVEL_NOTICE,
            log::Level::Debug => kmsg_defs::LOGLEVEL_INFO,
            log::Level::Trace => kmsg_defs::LOGLEVEL_DEBUG,
        };

        let n = level | (kmsg_defs::UNDERHILL_INIT_KMSG_FACILITY << 3);

        // Construct a local buffer so that the write to /dev/kmsg happens as a
        // single write, which is necessary to ensure that the message stays
        // together on one line.
        let mut buf = Vec::new();
        writeln!(buf, "<{}>{}: {}", n, record.target(), record.args()).unwrap();
        let mut kmsg = &self.kmsg;
        let _ = kmsg.write(&buf);
    }

    fn flush(&self) {}
}

impl SysLog {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            kmsg: OpenOptions::new().write(true).open("/dev/kmsg")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;
    use test_with_tracing::test;

    // Test: Emit every Rust log severity through a private datagram-backed logger.
    // Expected: Each record is one complete write with the init facility's
    //       kernel priority, target, message and terminating newline.
    #[test]
    fn log_records_preserve_priority_and_single_write_framing() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let fd: OwnedFd = sender.into();
        let logger = SysLog {
            kmsg: File::from(fd),
        };
        for (level, expected) in [
            (log::Level::Error, "<19>init-test: boot phase ready\n"),
            (log::Level::Warn, "<20>init-test: boot phase ready\n"),
            (log::Level::Info, "<21>init-test: boot phase ready\n"),
            (log::Level::Debug, "<22>init-test: boot phase ready\n"),
            (log::Level::Trace, "<23>init-test: boot phase ready\n"),
        ] {
            let record = log::Record::builder()
                .level(level)
                .target("init-test")
                .args(format_args!("boot phase ready"))
                .build();
            log::Log::log(&logger, &record);
            let mut buffer = [0; 128];
            let n = receiver.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..n], expected.as_bytes());
        }
    }
}
