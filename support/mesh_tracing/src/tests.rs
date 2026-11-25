// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use parking_lot::Mutex;
use std::sync::Arc;
use test_with_tracing::test;
use tracing_subscriber::prelude::*;

#[derive(Clone)]
struct RecordedEvents(Arc<Mutex<Vec<tracing::Level>>>);

// Test: Poll the merged request stream with a closed first input and an already queued request on its second input.
// Expected: Removing the closed input does not skip the live input; the queued request is immediately returned without requiring an unrelated wake.
#[test]
#[ignore = "known product bug: removing a closed input skips the swapped-in ready receiver"]
fn known_bug_stream_returns_ready_input_after_removing_a_closed_input() {
    use futures::StreamExt;

    let (register, new_receivers) = mesh::channel();
    let (closed, closed_receiver) = bounded::<TracingRequest>(1);
    let (send, ready_receiver) = bounded::<TracingRequest>(1);
    let writer = TraceWriter::from(send);
    drop(closed);
    register.send(closed_receiver);
    register.send(ready_receiver);
    assert!(writer.send(
        Type::Event,
        17,
        Level::Info,
        None,
        None,
        None,
        None,
        None,
        None,
        b"ready-message".to_vec()
    ));
    let mut stream = TracingRequestStream {
        new_receivers,
        receivers: Vec::new(),
    };
    assert!(
        matches!(stream.next().now_or_never(), Some(Some(request)) if request.message == b"ready-message")
    );
}

impl<S: tracing::Subscriber> Layer<S> for RecordedEvents {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == "mesh_filter_probe" {
            self.0.lock().push(*event.metadata().level());
        }
    }
}

fn emit_probe() {
    tracing::warn!(target: "mesh_filter_probe", "warning");
    tracing::info!(target: "mesh_filter_probe", "information");
}

// Test: Apply valid, updater-invalid, and layer-parser-invalid dynamic filters while emitting real events through a local subscriber.
// Expected: Accepted filters immediately change delivery; rejected updates preserve the last working filter and do not leak unrelated events.
#[test]
fn dynamic_filter_updates_change_delivery_and_retain_the_last_valid_policy() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let (mut updater, filter) = filter("mesh_filter_probe=warn".into()).unwrap();
    let (layer, worker) = filter
        .apply(RecordedEvents(recorded.clone()), |value| {
            anyhow::ensure!(!value.ends_with("=debug"), "unsupported debug policy");
            Ok(value.parse::<Targets>()?)
        })
        .unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);
    let mut worker = std::pin::pin!(worker);
    tracing::subscriber::with_default(subscriber, || {
        assert!(worker.as_mut().now_or_never().is_none());
        emit_probe();
        assert_eq!(*recorded.lock(), [tracing::Level::WARN]);
        updater.update("mesh_filter_probe=info").unwrap();
        assert!(worker.as_mut().now_or_never().is_none());
        emit_probe();
        assert_eq!(
            *recorded.lock(),
            [
                tracing::Level::WARN,
                tracing::Level::WARN,
                tracing::Level::INFO
            ]
        );
        assert!(updater.update("mesh_filter_probe=not-a-level").is_err());
        assert_eq!(updater.get(), "mesh_filter_probe=info");
        updater.update("mesh_filter_probe=debug").unwrap();
        assert!(worker.as_mut().now_or_never().is_none());
        emit_probe();
        assert_eq!(
            *recorded.lock(),
            [
                tracing::Level::WARN,
                tracing::Level::WARN,
                tracing::Level::INFO,
                tracing::Level::WARN,
                tracing::Level::INFO
            ]
        );
    });
}

// Test: Reject invalid initial target syntax and a valid target string that a caller's layer parser refuses.
// Expected: Initialization returns an error before a usable filtered layer is created, retaining the parser failure context.
#[test]
fn initial_filter_validation_rejects_bad_syntax_and_layer_parse_failures() {
    assert!(filter("mesh_filter_probe=not-a-level".into()).is_err());
    let (_, filter) = filter("mesh_filter_probe=info".into()).unwrap();
    let result = filter.apply::<_, tracing_subscriber::Registry, Targets>(
        RecordedEvents(Arc::new(Mutex::new(Vec::new()))),
        |_| anyhow::bail!("caller parser rejected initial filter"),
    );
    let error = result
        .err()
        .expect("initial parser failure must be returned");
    assert_eq!(error.to_string(), "failed to parse filter");
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string() == "caller parser rejected initial filter")
    );
}

fn drain_requests(requests: &mut TracingRequestStream, sent: &mesh::Sender<TracingRequest>) {
    use futures::StreamExt;
    while let Some(Some(request)) = requests.next().now_or_never() {
        sent.send(request);
    }
}

fn exercise_backend() {
    use std::io::Write;

    let mut pool = pal_async::DefaultPool::new();
    let (sent, mut received) = mesh::channel();
    let mut backend = TracingBackend::new(
        pool.driver(),
        "info".into(),
        "warn".into(),
        move |mut requests, mut flush| async move {
            while let Ok(rpc) = flush.recv().await {
                drain_requests(&mut requests, &sent);
                rpc.handle_sync(|()| ());
            }
            drain_requests(&mut requests, &sent);
        },
    )
    .unwrap();
    let mut first = backend.tracer();
    let mut second = backend.tracer();
    first.perf_trace_file.write_all(b"first;").unwrap();
    second.perf_trace_file.write_all(b"second").unwrap();
    assert_eq!(
        std::fs::read("underhill.perfetto").unwrap(),
        b"first;second"
    );
    let activity: Guid = "01234567-89ab-cdef-0123-456789abcdef".parse().unwrap();
    let related: Guid = "11111111-2222-3333-4444-555555555555".parse().unwrap();
    let correlation: Guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".parse().unwrap();
    assert!(first.trace_writer.send(
        Type::SpanEnter,
        u64::MAX,
        Level::Error,
        Some(vec![0, 0xff]),
        Some(b"first-target".to_vec()),
        Some(b"field=value".to_vec()),
        Some(activity),
        Some(related),
        Some(correlation),
        b"first-message".to_vec()
    ));
    assert!(second.trace_writer.send(
        Type::Event,
        17,
        Level::Info,
        None,
        None,
        None,
        None,
        None,
        None,
        b"second-message".to_vec()
    ));
    pool.run_until(async {
        backend.flush().await;
        let first = received.recv().await.unwrap();
        assert!(matches!(first.log_type, Type::SpanEnter));
        assert!(matches!(first.level, Level::Error));
        assert_eq!(first.timestamp, u64::MAX);
        assert_eq!(first.name, Some(vec![0, 0xff]));
        assert_eq!(first.target.as_deref(), Some(b"first-target".as_slice()));
        assert_eq!(first.fields.as_deref(), Some(b"field=value".as_slice()));
        assert_eq!(first.activity_id, Some(activity));
        assert_eq!(first.related_activity_id, Some(related));
        assert_eq!(first.correlation_id, Some(correlation));
        assert_eq!(first.message, b"first-message");
        let second = received.recv().await.unwrap();
        assert!(matches!(second.log_type, Type::Event));
        assert!(matches!(second.level, Level::Info));
        assert_eq!(second.timestamp, 17);
        assert!(second.name.is_none() && second.target.is_none() && second.fields.is_none());
        assert!(
            second.activity_id.is_none()
                && second.related_activity_id.is_none()
                && second.correlation_id.is_none()
        );
        assert_eq!(second.message, b"second-message");
        backend.shutdown().await;
        assert!(received.recv().await.is_err());
    });
}

// Test: Run two backend tracers in an isolated working directory, append to their shared perf file, flush queued events, and shut down.
// Expected: Shared file writes append in order, every trace field reaches the consumer exactly, flush acknowledges drained requests, and shutdown releases the worker.
#[test]
fn backend_routes_metadata_flushes_and_shuts_down() {
    const CHILD: &str = "OPENVMM_MESH_TRACING_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        exercise_backend();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::backend_routes_metadata_flushes_and_shuts_down",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .current_dir(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// Test: Saturate a trace writer, drain one event, and send again before closing the producer.
// Expected: Overflow reports failure without overwriting accepted events; capacity recovers and accepted IDs/payloads drain in order.
#[test]
fn trace_writer_overflow_preserves_accepted_events_and_recovers_capacity() {
    use futures::StreamExt;

    let (send, mut receive) = bounded::<TracingRequest>(2);
    let writer = TraceWriter::from(send);
    let event = |sequence: u64| {
        writer.send(
            Type::Event,
            sequence,
            Level::Info,
            None,
            None,
            None,
            None,
            None,
            None,
            sequence.to_le_bytes().to_vec(),
        )
    };
    assert!(event(1));
    assert!(event(2));
    assert!(!event(3));
    let first = receive.next().now_or_never().unwrap().unwrap();
    assert_eq!(first.timestamp, 1);
    assert_eq!(first.message, 1u64.to_le_bytes());
    assert!(event(4));
    assert!(!event(5));
    drop(writer);
    let remaining = futures::executor::block_on(receive.collect::<Vec<_>>());
    assert_eq!(remaining.len(), 2);
    for (request, sequence) in remaining.iter().zip([2u64, 4]) {
        assert!(matches!(request.log_type, Type::Event));
        assert!(matches!(request.level, Level::Info));
        assert_eq!(request.timestamp, sequence);
        assert_eq!(request.message, sequence.to_le_bytes());
    }
}
