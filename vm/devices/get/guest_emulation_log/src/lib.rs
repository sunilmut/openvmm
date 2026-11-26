// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest Emulation Log - GEL
//!
//! The GEL is the host side of a communication channel that uses VMBUS to
//! send logs from the guest to the host. This is an implementation to support
//! better integration testing within the OpenVMM CI.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

pub mod resolver;

use async_trait::async_trait;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use task_control::StopTask;
use thiserror::Error;
use vmbus_async::async_dgram::AsyncRecvExt;
use vmbus_async::pipe::MessagePipe;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::bus::ChannelType;
use vmbus_channel::bus::OfferParams;
use vmbus_channel::channel::ChannelOpenError;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_channel::simple::SaveRestoreSimpleVmbusDevice;
use vmbus_channel::simple::SimpleVmbusDevice;
use vmbus_ring::RingMem;
use vmcore::save_restore::NoSavedState;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

#[derive(Debug, Error)]
enum Error {
    #[error("cancelled")]
    Cancelled(task_control::Cancelled),
    #[error("pipe failed")]
    PipeFailure(#[source] std::io::Error),
    #[error("trace message has invalid size {0}")]
    InvalidTraceSize(u16),
    #[error("invalid payload length {0}")]
    InvalidPayloadSize(usize),
}

impl From<task_control::Cancelled> for Error {
    fn from(value: task_control::Cancelled) -> Self {
        Self::Cancelled(value)
    }
}

/// VMBUS device that implements the host side of the Guest Emulation Log protocol.
#[non_exhaustive]
pub struct GuestEmulationLog {}

impl GuestEmulationLog {
    /// Create a new Host side GEL device.
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl SimpleVmbusDevice for GuestEmulationLog {
    type Runner = GelChannel;
    type SavedState = NoSavedState;

    fn offer(&self) -> OfferParams {
        OfferParams {
            interface_name: "gel".to_owned(),
            interface_id: get_protocol::GUEST_EMULATION_INTERFACE_TYPE,
            instance_id: get_protocol::GET_LOG_INTERFACE_GUID,
            channel_type: ChannelType::Pipe {
                message_mode: true,
                user_defined: Default::default(),
                pipe_flags: Default::default(),
            },
            ..Default::default()
        }
    }

    fn inspect(&mut self, req: inspect::Request<'_>, task: Option<&mut GelChannel>) {
        let _ = (req, task);
    }

    fn open(
        &mut self,
        channel: RawAsyncChannel<GpadlRingMem>,
        _guest_memory: guestmem::GuestMemory,
    ) -> Result<Self::Runner, ChannelOpenError> {
        let pipe = MessagePipe::new(channel)?;
        Ok(GelChannel::new(pipe))
    }

    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        channel: &mut GelChannel,
    ) -> Result<(), task_control::Cancelled> {
        let check = stop.check_handle()?;
        stop.until_stopped(async {
            if let Err(err) = channel.process(self, &check).await {
                if let Error::Cancelled(cancelled) = err {
                    return Err(cancelled);
                }
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "trace channel failed"
                );
            }
            Ok(())
        })
        .await?
    }

    fn supports_save_restore(
        &mut self,
    ) -> Option<
        &mut dyn SaveRestoreSimpleVmbusDevice<SavedState = Self::SavedState, Runner = Self::Runner>,
    > {
        Some(self)
    }
}

impl SaveRestoreSimpleVmbusDevice for GuestEmulationLog {
    fn save_open(&mut self, _runner: &Self::Runner) -> Self::SavedState {
        NoSavedState
    }

    fn restore_open(
        &mut self,
        NoSavedState: Self::SavedState,
        channel: RawAsyncChannel<GpadlRingMem>,
    ) -> Result<Self::Runner, ChannelOpenError> {
        let pipe = MessagePipe::new(channel)?;
        Ok(GelChannel::new(pipe))
    }
}

#[derive(Deserialize, Debug, Default)]
struct TraceFields<'a> {
    #[serde(borrow)]
    message: Option<Cow<'a, str>>,
    #[serde(flatten, borrow)]
    extra: ExtraFields<'a>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(transparent)]
struct ExtraFields<'a> {
    #[serde(borrow)]
    map: HashMap<Cow<'a, str>, serde_json::value::Value>,
}

impl std::fmt::Display for ExtraFields<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (k, v) in &self.map {
            map.entry(k, &format_args!("{}", v));
        }
        map.finish()
    }
}

#[derive(Deserialize, Debug)]
struct TraceData<'a> {
    #[serde(borrow)]
    target: Cow<'a, str>,
    #[serde(borrow)]
    level: Cow<'a, str>,
    #[serde(default, borrow)]
    fields: TraceFields<'a>,
    #[serde(flatten, borrow)]
    extra: ExtraFields<'a>,
}

/// The GEL task.
pub struct GelChannel<T: RingMem = GpadlRingMem> {
    channel: MessagePipe<T>,
}

impl<T: RingMem + Unpin> GelChannel<T> {
    fn new(channel: MessagePipe<T>) -> Self {
        Self { channel }
    }

    async fn process(
        &mut self,
        _state: &mut GuestEmulationLog,
        check: &task_control::StopCheck<'_>,
    ) -> Result<(), Error> {
        let mut buffer = vec![0; get_protocol::TRACE_LOGGING_NOTIFICATION_MAX_SIZE];
        loop {
            check.check()?;
            let n = self
                .channel
                .recv(buffer.as_mut_bytes())
                .await
                .map_err(Error::PipeFailure)?;

            if n == 0 {
                break;
            }

            let buffer = &buffer[..n];

            let (header, buffer) =
                get_protocol::TraceLoggingNotificationHeader::read_from_prefix(buffer)
                    .map_err(|_| Error::InvalidPayloadSize(n))?; // TODO: zerocopy: map_err (https://github.com/microsoft/openvmm/issues/759)

            let message = buffer
                .get(
                    header.message.offset as usize
                        ..(header.message.offset + header.message.size) as usize,
                )
                .ok_or(Error::InvalidTraceSize(n as u16))?;

            match serde_json::from_slice::<'_, TraceData<'_>>(message) {
                Ok(data) => match &*data.level {
                    "ERROR" => {
                        tracing::error!(
                            target: "paravisor_log",
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                    "WARN" => {
                        tracing::warn!(
                            target: "paravisor_log",
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                    "INFO" => {
                        tracing::info!(
                            target: "paravisor_log",
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                    "DEBUG" => {
                        tracing::debug!(
                            target: "paravisor_log",
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                    "TRACE" => {
                        tracing::trace!(
                            target: "paravisor_log",
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                    some_level => {
                        tracing::info!(
                            target: "paravisor_log",
                            inner_level = some_level,
                            inner_target = &*data.target,
                            message = data.fields.message.as_deref(),
                            fields = %data.fields.extra,
                            extra = %data.extra,
                        )
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        target: "paravisor_log",
                        inner_level = ?header.level,
                        error = &err as &dyn std::error::Error,
                        message = String::from_utf8_lossy(message).as_ref(),
                        "failed to parse trace",
                    )
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use task_control::AsyncRun;
    use task_control::TaskControl;
    use test_with_tracing::test;
    use vmbus_channel::test_helpers::GatedRingMem;
    use vmbus_channel::test_helpers::gated_channels;
    use vmbus_channel::test_helpers::stop_with_timeout;
    use zerocopy::FromZeros;

    struct Worker(GelChannel<GatedRingMem>);

    impl AsyncRun<()> for Worker {
        async fn run(
            &mut self,
            stop: &mut StopTask<'_>,
            _: &mut (),
        ) -> Result<(), task_control::Cancelled> {
            let check = stop.check_handle()?;
            match stop
                .until_stopped(self.0.process(&mut GuestEmulationLog::new(), &check))
                .await?
            {
                Err(Error::Cancelled(cancelled)) => Err(cancelled),
                result => panic!("unexpected log worker result: {result:?}"),
            }
        }
    }

    #[async_test]
    async fn stop_bounds_ready_trace_messages_and_restart_retains_channel(driver: DefaultDriver) {
        let (_thread, worker_driver) = pal_async::DefaultPool::spawn_on_thread("gel-stop");
        let (host, guest, gate) = gated_channels(16384);
        let mut guest = MessagePipe::new(guest).unwrap();
        let json = br#"{"target":"test","level":"INFO","fields":{"message":"message"}}"#;
        let header = get_protocol::TraceLoggingNotificationHeader {
            message: get_protocol::TraceLoggingBufferOffset {
                size: json.len() as u16,
                offset: 0,
            },
            ..FromZeros::new_zeroed()
        };
        let message = [header.as_bytes(), json].concat();
        guest.try_send(&message).unwrap();
        guest.try_send(&message).unwrap();
        let mut task = TaskControl::new(Worker(GelChannel::new(MessagePipe::new(host).unwrap())));
        task.insert(&worker_driver, "gel", ());
        assert!(task.start());
        gate.stop(&mut task, &driver).await;
        let mut buffer = [0; 256];
        let remaining = task.task_mut().0.channel.recv(&mut buffer).now_or_never();
        assert_eq!(remaining.unwrap().unwrap(), message.len());
        assert_eq!(&buffer[..message.len()], message.as_slice());

        assert!(task.start());
        stop_with_timeout(&mut task, &driver).await;
    }

    fn log_frame(json: &[u8], offset: u16) -> Vec<u8> {
        let header = get_protocol::TraceLoggingNotificationHeader {
            message: get_protocol::TraceLoggingBufferOffset {
                size: json.len() as u16,
                offset,
            },
            ..FromZeros::new_zeroed()
        };
        let mut frame = header.as_bytes().to_vec();
        frame.extend(std::iter::repeat_n(0xee, offset as usize));
        frame.extend_from_slice(json);
        frame.extend_from_slice(b"not part of the selected JSON");
        frame
    }

    async fn process_frames(frames: &[Vec<u8>]) -> Result<(), Error> {
        let (host, mut guest) = vmbus_async::pipe::connected_message_pipes(16384);
        for frame in frames {
            guest.try_send(frame).unwrap();
        }
        guest.try_send(&[]).unwrap();
        let mut channel = GelChannel::new(host);
        StopTask::run_unstoppable(async |stop| {
            let check = stop.check_handle()?;
            channel.process(&mut GuestEmulationLog::new(), &check).await
        })
        .await
    }

    struct LogWriter(std::sync::Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Test: Forward every severity, an unknown severity and malformed JSON followed
    //       by a valid frame whose message has nonzero offset and trailing bytes.
    // Expected: Log events preserve target/message/extra fields, fallback severity
    //       and parse diagnostics; bad JSON does not suppress the following event.
    #[test]
    fn forward_levels_fields_and_recover_after_bad_json() {
        use tracing::instrument::WithSubscriber;

        let output = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_writer(move || LogWriter(writer.clone()))
            .finish();
        let mut frames = Vec::new();
        for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE", "CUSTOM"] {
            let json = format!(
                r#"{{"target":"guest-{level}","level":"{level}","fields":{{"message":"hello\nworld","count":17}},"source":"vm"}}"#
            );
            frames.push(log_frame(json.as_bytes(), 3));
        }
        frames.push(log_frame(b"\xff{bad json", 0));
        frames.push(log_frame(br#"{"target":"after-error","level":"INFO"}"#, 0));
        futures::executor::block_on(process_frames(&frames).with_subscriber(subscriber)).unwrap();
        let log = String::from_utf8(output.lock().clone()).unwrap();
        for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"] {
            let line = log
                .lines()
                .find(|line| line.contains(&format!("guest-{level}")))
                .unwrap();
            assert!(line.trim_start().starts_with(level), "{line}");
            let start = log
                .find(&format!("inner_target=\"guest-{level}\""))
                .unwrap();
            let event = log[start..].split("paravisor_log:").next().unwrap();
            assert!(event.contains("hello\nworld"), "{event}");
            assert!(
                event.contains("count")
                    && event.contains("17")
                    && event.contains("source")
                    && event.contains("vm"),
                "{event}"
            );
        }
        let fallback = log
            .lines()
            .find(|line| line.contains("guest-CUSTOM"))
            .unwrap();
        assert!(fallback.contains("INFO") && fallback.contains("inner_level=\"CUSTOM\""));
        let bad = log.find("failed to parse trace").unwrap();
        assert!(log.find("after-error").unwrap() > bad);
        assert!(!log.contains("not part of the selected JSON"));
    }

    // Test: Receive a truncated header or a message region outside the payload.
    // Expected: Processing returns a framing error, never a successful EOF.
    #[test]
    fn invalid_frame_boundaries_are_rejected() {
        let out_of_bounds = get_protocol::TraceLoggingNotificationHeader {
            message: get_protocol::TraceLoggingBufferOffset {
                size: 1,
                offset: 10,
            },
            ..FromZeros::new_zeroed()
        };
        for frame in [vec![1], out_of_bounds.as_bytes().to_vec()] {
            assert!(futures::executor::block_on(process_frames(&[frame])).is_err());
        }
    }

    // Test: Receive a message region whose offset plus length overflows u16.
    // Expected: The untrusted frame returns a framing error without panicking.
    //
    // IGNORED: Reproduced with offset=65535 and size=2: processing panics at
    //       the u16 addition in the message range before bounds validation.
    //       Widening or checked addition should return a framing error instead.
    //       Retained without a production fix under the test-only campaign.
    #[test]
    #[ignore = "product bug: GEL message offset plus size overflows before validation"]
    fn overflowing_message_region_is_rejected() {
        let header = get_protocol::TraceLoggingNotificationHeader {
            message: get_protocol::TraceLoggingBufferOffset {
                size: 2,
                offset: u16::MAX,
            },
            ..FromZeros::new_zeroed()
        };
        assert!(
            futures::executor::block_on(process_frames(&[header.as_bytes().to_vec()])).is_err()
        );
    }
}
