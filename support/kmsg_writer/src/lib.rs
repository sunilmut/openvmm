// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements a type for writing tracing events to `/dev/kmsg`.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::IoSlice;
use std::io::Write;
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// Implements [`MakeWriter`] on top of `/dev/kmsg`.
pub struct KmsgWriter {
    file: File,
    facility: u8,
}

impl KmsgWriter {
    /// Opens `/dev/kmsg`.
    pub fn new(facility: u8) -> std::io::Result<Self> {
        let file = fs_err::OpenOptions::new()
            .write(true)
            .open("/dev/kmsg")?
            .into();

        Ok(Self { facility, file })
    }

    fn make_prefix(&self, level: Level, target: &str) -> String {
        let level = match level {
            Level::ERROR => 3,
            Level::WARN => 4,
            Level::INFO => 6,
            Level::DEBUG | Level::TRACE => 7,
        };

        let n = (level as u8) | (self.facility << 3);
        format!("<{}>{}: ", n, target)
    }
}

/// A writer that writes to `/dev/kmsg` with a prefix.
pub struct KmsgWithPrefix<'a> {
    kmsg: &'a File,
    prefix: String,
}

impl<'a> MakeWriter<'a> for KmsgWriter {
    type Writer = KmsgWithPrefix<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        KmsgWithPrefix {
            kmsg: &self.file,
            prefix: self.make_prefix(Level::INFO, "underhill"),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        KmsgWithPrefix {
            kmsg: &self.file,
            prefix: self.make_prefix(*meta.level(), meta.target()),
        }
    }
}

impl Write for KmsgWithPrefix<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The maximum length for a kmsg write is either 976 or 992 bytes
        // depending on kernel configuration. Lets be safe.
        let max_buf_len = 976 - self.prefix.len();

        let buf_end = std::cmp::min(buf.len(), max_buf_len);
        let bytes_written = self.kmsg.write_vectored(&[
            IoSlice::new(self.prefix.as_bytes()),
            IoSlice::new(&buf[..buf_end]),
        ])?;

        Ok(bytes_written - self.prefix.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use test_with_tracing::test;

    /// Use an isolated regular file instead of the privileged kernel device.
    fn writer(facility: u8) -> (KmsgWriter, File) {
        let file = tempfile::tempfile().unwrap();
        let reader = file.try_clone().unwrap();
        (KmsgWriter { file, facility }, reader)
    }

    /// Read the bytes emitted through the public writer interfaces.
    fn read_records(mut file: File) -> Vec<u8> {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut records = Vec::new();
        file.read_to_end(&mut records).unwrap();
        records
    }

    // Test: Emit every tracing severity through a prefixed subscriber.
    // Expected: Each record carries the facility and its Linux severity code.
    #[test]
    fn subscriber_records_preserve_facility_target_and_severity() {
        let (writer, reader) = writer(1);
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(Level::TRACE)
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "writer-contract", "error");
            tracing::warn!(target: "writer-contract", "warn");
            tracing::info!(target: "writer-contract", "info");
            tracing::debug!(target: "writer-contract", "debug");
            tracing::trace!(target: "writer-contract", "trace");
        });
        assert_eq!(
            read_records(reader),
            b"<11>writer-contract: error\n\
              <12>writer-contract: warn\n\
              <14>writer-contract: info\n\
              <15>writer-contract: debug\n\
              <15>writer-contract: trace\n"
        );
    }

    // Test: Write binary bytes through the default writer and flush it.
    // Expected: The default INFO/underhill prefix precedes unchanged bytes.
    #[test]
    fn default_writer_preserves_binary_payload() {
        let (writer, reader) = writer(1);
        let mut record = writer.make_writer();
        assert_eq!(record.write(b"\x00\xffpayload").unwrap(), 9);
        record.flush().unwrap();
        assert_eq!(read_records(reader), b"<14>underhill: \x00\xffpayload");
    }

    // Test: Write a payload spanning several maximum-size kernel records.
    // Expected: Each record stays within 976 bytes and no payload is lost.
    #[test]
    fn write_all_retains_payload_across_record_boundaries() {
        let (writer, reader) = writer(1);
        let payload = vec![0xa5; 2_000];
        writer.make_writer().write_all(&payload).unwrap();
        let prefix = b"<14>underhill: ";
        let mut expected = Vec::new();
        for chunk in payload.chunks(976 - prefix.len()) {
            expected.extend_from_slice(prefix);
            expected.extend_from_slice(chunk);
        }
        assert_eq!(read_records(reader), expected);
    }

    // Test: Attempt a prefixed write through a read-only backing file.
    // Expected: The original I/O error is returned rather than a success count.
    #[test]
    fn backing_write_errors_are_propagated() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut read_only = File::open(file.path()).unwrap();
        let expected = read_only.write(b"probe").unwrap_err();
        let writer = KmsgWriter {
            file: read_only,
            facility: 1,
        };
        let actual = writer.make_writer().write(b"payload").unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.raw_os_error(), expected.raw_os_error());
        assert!(std::fs::read(file.path()).unwrap().is_empty());
    }

    // IGNORED: entry235-bug1: a 1024-byte target makes the record-size
    //       subtraction overflow. Reproduced enabled; no production fix.
    //
    // Test: Emit an event whose valid target exceeds the kernel record limit.
    // Expected: Logging does not panic or produce an oversized kernel record.
    #[test]
    #[ignore = "entry235-bug1: oversized tracing target panics"]
    fn oversized_target_does_not_panic() {
        const LONG_TARGET: &str = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let (writer, reader) = writer(1);
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .without_time()
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: LONG_TARGET, "payload");
        });
        assert!(read_records(reader).len() <= 976);
    }
}
