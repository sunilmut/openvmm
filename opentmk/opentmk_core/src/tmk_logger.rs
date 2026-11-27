// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Logger implementation for OpenTMK.
//! This module provides a logger that formats log messages as JSON and writes them to a specified output
//! such as a serial port.

use alloc::borrow::ToOwned;
use alloc::fmt::format;
use alloc::string::String;
use alloc::string::ToString;
use core::fmt::Write;

use log::SetLoggerError;
use serde::Serialize;
use spin::Mutex;
use spin::MutexGuard;

#[derive(Serialize)]
struct LogEntry {
    #[serde(rename = "type")]
    log_type: &'static str,
    level: String,
    message: String,
    line: String,
}

impl LogEntry {
    fn new(level: log::Level, message: &str, line: &str) -> Self {
        LogEntry {
            log_type: "log",
            level: level.as_str().to_string(),
            message: message.to_owned(),
            line: line.to_owned(),
        }
    }
}

/// Formats a log message into a JSON string.
pub(crate) fn format_log_string_to_json(
    message: &str,
    line: &str,
    terminate_new_line: bool,
    level: log::Level,
) -> String {
    let log_entry = LogEntry::new(level, message, line);
    let mut out = serde_json::to_string(&log_entry).unwrap();
    if terminate_new_line {
        out.push('\n');
    }
    out
}

/// A logger that writes log messages to a provided writer, such as a serial port.
pub struct TmkLogger<T> {
    writer: T,
}

impl<T> TmkLogger<Mutex<T>>
where
    T: Write + Send,
{
    /// Creates a new `TmkLogger` instance with the provided writer.
    pub const fn new(provider: T) -> Self {
        TmkLogger {
            writer: Mutex::new(provider),
        }
    }

    /// Returns a lock guard to the underlying writer.
    /// This allows direct access to the writer for custom logging operations.
    pub fn get_writer(&self) -> MutexGuard<'_, T>
    where
        T: Write + Send,
    {
        self.writer.lock()
    }
}

impl<T> log::Log for TmkLogger<Mutex<T>>
where
    T: Write + Send,
{
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let str = format(*record.args());
        let line = format!(
            "{}:{}",
            record.file().unwrap_or_default(),
            record.line().unwrap_or_default()
        );
        let str = format_log_string_to_json(&str, &line, true, record.level());
        _ = self.writer.lock().write_str(str.as_str());
    }

    fn flush(&self) {}
}

cfg_select! {
    target_arch = "x86_64" => {
        use crate::arch::serial::SerialPort;
        use uart_16550::Uart16550Tty;
        use uart_16550::backend::PioBackend;

        /// The global logger instance for x86_64 architecture, using COM2 serial port.
        pub static LOGGER: TmkLogger<Mutex<Uart16550Tty<PioBackend>>> =
            TmkLogger::new(Uart16550Tty::from_inner(SerialPort::COM2.uart()));
    }
    target_arch = "aarch64" => {
        use minimal_rt::arch::Serial;

        /// The global logger instance for aarch64 architecture, using the default serial
        /// implementation.
        pub static LOGGER: TmkLogger<Mutex<Serial>> = TmkLogger::new(Serial {});
    }
}

/// Initializes the global logger.
pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Debug))
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;
    use test_with_tracing::test;

    // Test: Format escaped Unicode messages and emit consecutive records through
    //       an owned writer, including a record without source information.
    // Expected: Each record is one complete JSON line with lossless fields;
    //       optional termination changes framing, not the JSON data.
    #[test]
    fn owned_logger_preserves_json_fields_and_record_boundaries() {
        let message = "quotes \" slash \\ newline\n tab\t emoji \u{1f642}";
        let expected = serde_json::json!({
            "type": "log",
            "level": "INFO",
            "message": message,
            "line": "fixture.rs:27",
        });
        for terminate in [false, true] {
            let output =
                format_log_string_to_json(message, "fixture.rs:27", terminate, log::Level::Info);
            assert_eq!(output.ends_with('\n'), terminate);
            assert_eq!(
                output.bytes().filter(|&b| b == b'\n').count(),
                usize::from(terminate)
            );
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap(),
                expected
            );
        }
        let logger = TmkLogger::new(String::new());
        logger.log(
            &log::Record::builder()
                .args(format_args!("{message}"))
                .level(log::Level::Info)
                .file(Some("fixture.rs"))
                .line(Some(27))
                .build(),
        );
        logger.log(
            &log::Record::builder()
                .args(format_args!("without source {}", 9))
                .level(log::Level::Warn)
                .build(),
        );
        let output = logger.get_writer();
        assert!(output.ends_with('\n'));
        let entries: Vec<serde_json::Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            entries,
            vec![
                expected,
                serde_json::json!({
                    "type": "log",
                    "level": "WARN",
                    "message": "without source 9",
                    "line": ":0",
                }),
            ]
        );
    }
}
