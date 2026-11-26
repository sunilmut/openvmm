// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Observable event output from filtered and unfiltered tracing layers.

use cvm_tracing::CVM_ALLOWED;
use cvm_tracing::CVM_CONFIDENTIAL;
use cvm_tracing::confidential_event_filter;
use parking_lot::Mutex;
use std::io::Write;
use std::sync::Arc;
use test_with_tracing::test;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Test: Send ordinary, allowed, confidential, dual-tagged and false-valued
//       confidential events to separate filtered and unfiltered output layers.
// Expected: The filtered sink emits only public text without metadata tags;
//       confidential-field presence wins, without suppressing the other sink.
#[test]
fn confidentiality_filter_preserves_exact_public_output_and_layer_isolation() {
    let external = Capture::default();
    let internal = Capture::default();
    let external_writer = external.clone();
    let internal_writer = internal.clone();
    let external_layer = tracing_subscriber::fmt::layer()
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || external_writer.clone())
        .with_filter(confidential_event_filter());
    let internal_layer = tracing_subscriber::fmt::layer()
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || internal_writer.clone());
    let subscriber = tracing_subscriber::registry()
        .with(external_layer)
        .with(internal_layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(CVM_ALLOWED, "public-event");
        tracing::info!(CVM_CONFIDENTIAL, key = "secret-value", "secret-event");
        tracing::warn!(CVM_ALLOWED, CVM_CONFIDENTIAL, "dual-marker-event");
        tracing::error!(CVM_CONFIDENTIAL = false, "false-valued-confidential-event");
        tracing::info!("ordinary-event");
    });
    let external = String::from_utf8(external.0.lock().clone()).unwrap();
    let internal = String::from_utf8(internal.0.lock().clone()).unwrap();
    assert_eq!(external, "public-event\nordinary-event\n");
    for text in [
        "public-event",
        "ordinary-event",
        "secret-event",
        "secret-value",
        "dual-marker-event",
        "false-valued-confidential-event",
    ] {
        assert!(internal.contains(text), "{text} missing from internal sink");
    }
}
