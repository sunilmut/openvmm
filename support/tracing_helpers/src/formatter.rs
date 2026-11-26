// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Formatter for use with tracing crate.

use std::fmt;
use std::io;
use std::io::Write;
use tracing::field::Visit;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;

struct FieldFormatterVisitor<'a> {
    writer: Writer<'a>,
    is_empty: bool,
    result: fmt::Result,
}

impl FieldFormatterVisitor<'_> {
    fn maybe_pad(&mut self) {
        if self.is_empty {
            self.is_empty = false;
        } else {
            self.result = write!(self.writer, " ");
        }
    }

    fn record_display(&mut self, field: &tracing::field::Field, value: &dyn fmt::Display) {
        if self.result.is_err() {
            return;
        }

        self.maybe_pad();
        self.result = match field.name() {
            "message" => write!(self.writer, "{}", value),
            // Skip fields that are actually log metadata that have already been handled
            name if name.starts_with("log.") => Ok(()),
            name if name.starts_with("r#") => write!(self.writer, "{}={}", &name[2..], value),
            name => write!(self.writer, "{}={}", name, value),
        };
    }
}

impl Visit for FieldFormatterVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record_display(field, &value)
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_display(field, &value)
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        // Use hex encoding for better readability for most values.
        self.record_display(field, &format_args!("{:#x}", value))
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_display(field, &value)
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_display(field, &format_args!("{:?}", value))
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        mut value: &(dyn std::error::Error + 'static),
    ) {
        self.record_debug(field, &format_args!("{}", value));
        while let Some(s) = value.source() {
            value = s;
            if self.result.is_err() {
                return;
            }
            self.result = write!(self.writer, ": {}", value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        // Use hex encoding for better readability for most values.
        self.record_display(field, &format_args!("{:x?}", value))
    }
}

/// Field formatter that fixes a few issues with the default formatter:
///
/// 1. Displays the full error source chain, not just the first error.
/// 2. Displays unsigned values as hex instead of decimal, improving readability
///    for values that we tend to log in OpenVMM.
pub struct FieldFormatter;

impl FormatFields<'_> for FieldFormatter {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'_>, fields: R) -> fmt::Result {
        let mut visitor = FieldFormatterVisitor {
            writer,
            is_empty: false,
            result: Ok(()),
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

/// A Write implementation that wraps `T` and converts LFs into CRLFs.
pub struct CrlfWriter<T> {
    inner: T,
    write_lf: bool,
}

impl<T: Write> CrlfWriter<T> {
    /// Creates a new writer around `t`.
    pub fn new(t: T) -> Self {
        CrlfWriter {
            inner: t,
            write_lf: false,
        }
    }

    fn flush_lf(&mut self) -> io::Result<()> {
        if self.write_lf {
            if self.inner.write(b"\n")? == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.write_lf = false;
        }
        Ok(())
    }
}

impl<T: Write> Write for CrlfWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.flush_lf()?;
        if buf.first() == Some(&b'\n') {
            return Ok(match self.inner.write(b"\r\n")? {
                0 => 0,
                1 => {
                    self.write_lf = true;
                    1
                }
                _ => 1,
            });
        }

        let len = buf.iter().position(|x| *x == b'\n').unwrap_or(buf.len());
        self.inner.write(&buf[..len])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_lf()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnyhowValueExt;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use test_with_tracing::test;
    use tracing_subscriber::layer::SubscriberExt;

    struct Capture(Arc<Mutex<String>>);
    impl tracing_subscriber::Layer<tracing_subscriber::Registry> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, tracing_subscriber::Registry>,
        ) {
            FieldFormatter
                .format_fields(Writer::new(&mut *self.0.lock()), event)
                .unwrap();
        }
    }

    // Test: Format a real event containing scalar/debug fields, escaped text, a raw identifier, and contextual error sources.
    // Expected: Unsigned/debug values are hexadecimal, strings are escaped, field names are readable, and the complete error chain appears once.
    #[test]
    fn event_fields_preserve_types_escaping_and_error_chain() {
        let output = Arc::new(Mutex::new(String::new()));
        let subscriber = tracing_subscriber::Registry::default().with(Capture(output.clone()));
        let error = anyhow::anyhow!("bad header").context("decode packet");
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(answer = 42u64, signed = -7i64, ratio = 1.5f64, enabled = true, text = "a\n\"b", r#type = "raw", bytes = ?[0x10u8, 0xff], error = error.as_error(), "packet failed");
        });
        assert_eq!(
            &*output.lock(),
            " packet failed answer=0x2a signed=-7 ratio=1.5 enabled=true text=\"a\\n\\\"b\" type=\"raw\" bytes=[10, ff] error=decode packet: bad header"
        );
    }

    // Test: Fail the downstream formatter while emitting an event with further fields and an error source chain.
    // Expected: Formatting returns an error and no later field/source text reaches the output sink.
    #[test]
    fn downstream_format_error_stops_later_fields_and_sources() {
        struct BrokenWriter<'a>(&'a mut String);
        impl fmt::Write for BrokenWriter<'_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                if text == "fail" {
                    return Err(fmt::Error);
                }
                self.0.push_str(text);
                Ok(())
            }
        }
        struct FailureCapture(Arc<Mutex<(String, bool)>>);
        impl tracing_subscriber::Layer<tracing_subscriber::Registry> for FailureCapture {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _context: tracing_subscriber::layer::Context<'_, tracing_subscriber::Registry>,
            ) {
                let mut captured = self.0.lock();
                let result = FieldFormatter
                    .format_fields(Writer::new(&mut BrokenWriter(&mut captured.0)), event);
                captured.1 = result.is_err();
            }
        }
        let output = Arc::new(Mutex::new((String::new(), false)));
        let subscriber =
            tracing_subscriber::Registry::default().with(FailureCapture(output.clone()));
        let error = anyhow::anyhow!("source must not appear").context("context must not appear");
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(later = "must not appear", error = error.as_error(), "fail");
        });
        assert_eq!(&*output.lock(), &(" ".to_owned(), true));
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        limit: usize,
        reject_lf: bool,
        flushes: usize,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.reject_lf && bytes == b"\n" {
                self.reject_lf = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let length = bytes.len().min(self.limit);
            self.bytes.extend_from_slice(&bytes[..length]);
            Ok(length)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    fn short_writer(limit: usize) -> CrlfWriter<ShortWriter> {
        CrlfWriter::new(ShortWriter {
            bytes: Vec::new(),
            limit,
            reject_lf: false,
            flushes: 0,
        })
    }

    // Test: Write LF, existing CRLF, binary bytes, and empty buffers with short and unrestricted downstream writes.
    // Expected: Every input LF becomes exactly CRLF; every other byte survives unchanged, with no duplication or loss.
    #[test]
    fn crlf_conversion_preserves_binary_bytes_under_short_writes() {
        for limit in [1, 2, 3, usize::MAX] {
            let mut writer = short_writer(limit);
            assert_eq!(writer.write(b"").unwrap(), 0);
            writer.write_all(b"\nfirst\nsecond\r\n\x00\xff\n").unwrap();
            writer.flush().unwrap();
            assert_eq!(writer.inner.bytes, b"\r\nfirst\r\nsecond\r\r\n\x00\xff\r\n");
            assert_eq!(writer.inner.flushes, 1);
        }
    }

    // Test: Leave the LF half of CRLF pending, encounter a retryable downstream error, then retry the next input.
    // Expected: The error consumes no next-input bytes, and recovery emits the pending LF exactly once before those bytes.
    #[test]
    fn pending_lf_survives_retryable_write_error() {
        let mut writer = short_writer(1);
        assert_eq!(writer.write(b"\n").unwrap(), 1);
        assert_eq!(writer.inner.bytes, b"\r");
        writer.inner.reject_lf = true;
        assert_eq!(
            writer.write(b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(writer.inner.bytes, b"\r");
        assert_eq!(writer.write(b"x").unwrap(), 1);
        writer.flush().unwrap();
        assert_eq!(writer.inner.bytes, b"\r\nx");
    }

    // Test: Encounter zero-byte writes both before consuming LF and while flushing its pending second byte.
    // Expected: Initial zero progress consumes nothing; pending zero progress reports WriteZero, and later flush recovers without duplicating CRLF.
    #[test]
    fn zero_progress_and_flush_preserve_pending_lf() {
        let mut writer = short_writer(0);
        assert_eq!(writer.write(b"\n").unwrap(), 0);
        assert!(writer.inner.bytes.is_empty());
        writer.inner.limit = 1;
        assert_eq!(writer.write(b"\n").unwrap(), 1);
        writer.inner.limit = 0;
        assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::WriteZero);
        assert_eq!(writer.inner.bytes, b"\r");
        assert_eq!(writer.inner.flushes, 0);
        writer.inner.limit = 1;
        writer.flush().unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.inner.bytes, b"\r\n");
        assert_eq!(writer.inner.flushes, 2);
    }
}
