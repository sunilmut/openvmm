// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::OwnedMessage;
use pal_async::async_test;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::Future;
use std::future::poll_fn;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use test_with_tracing::test;
use vm_resource::ResolveResource;
use vm_resource::ResourceResolver;

#[derive(Debug, PartialEq, Eq, MeshPayload)]
struct ConfigBytes(Vec<u8>);

impl ResourceId<NonVolatileStoreKind> for ConfigBytes {
    const ID: &'static str = "test_tpm_store";
}

impl ResourceId<RequestAkCertKind> for ConfigBytes {
    const ID: &'static str = "test_tpm_certificate";
}

impl ResourceId<TpmLoggerKind> for ConfigBytes {
    const ID: &'static str = "test_tpm_logger";
}

impl CanResolveTo<ConfigBytes> for NonVolatileStoreKind {
    type Input<'a> = ();
}

impl CanResolveTo<ConfigBytes> for RequestAkCertKind {
    type Input<'a> = ();
}

impl CanResolveTo<ConfigBytes> for TpmLoggerKind {
    type Input<'a> = ();
}

struct ConfigResolver;

impl<K> ResolveResource<K, ConfigBytes> for ConfigResolver
where
    K: ResourceKind + CanResolveTo<ConfigBytes>,
    ConfigBytes: ResourceId<K>,
{
    type Output = ConfigBytes;
    type Error = Infallible;

    fn resolve(
        &self,
        handle: ConfigBytes,
        _: <K as CanResolveTo<ConfigBytes>>::Input<'_>,
    ) -> Result<ConfigBytes, Infallible> {
        Ok(handle)
    }
}

// Test: Transfer TPM configurations with separate same-type PPI/NVRAM stores,
//       both register layouts and versions, optional sizes and binary keys.
// Expected: A configuration-only consumer sees independent store contents and
//       policies, including the distinction between absent and empty options.
#[async_test]
async fn serialized_device_configuration_preserves_independent_inputs() {
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver::<NonVolatileStoreKind, ConfigBytes, ConfigBytes, _>(ConfigResolver);
    resolver.add_resolver::<TpmLoggerKind, ConfigBytes, ConfigBytes, _>(ConfigResolver);
    let bios_guid: Guid = "01234567-89ab-cdef-0123-456789abcdef".parse().unwrap();
    for (version, mmio, secret, size, refresh, confidential) in [
        (TpmVersion::V138, false, None, None, false, false),
        (
            TpmVersion::V185,
            true,
            Some(vec![]),
            Some(131072),
            true,
            true,
        ),
        (
            TpmVersion::V138,
            true,
            Some(vec![0, 0xff, 0x80, 1]),
            Some(0),
            false,
            true,
        ),
    ] {
        let handle = TpmDeviceHandle {
            version,
            ppi_store: Resource::new(ConfigBytes(vec![1, 0, 0xff])),
            nvram_store: Resource::new(ConfigBytes(vec![2, 0xff, 0, 0x80])),
            refresh_tpm_seeds: refresh,
            ak_cert_type: TpmAkCertTypeResource::None,
            register_layout: if mmio {
                TpmRegisterLayout::Mmio
            } else {
                TpmRegisterLayout::IoPort
            },
            guest_secret_key: secret.clone(),
            logger: confidential.then(|| Resource::new(ConfigBytes(vec![3, 0, 0xff]))),
            is_confidential_vm: confidential,
            bios_guid,
            nvram_size: size,
        };
        let received: TpmDeviceHandle =
            OwnedMessage::serialized(OwnedMessage::new(handle).serialize())
                .parse()
                .unwrap();
        assert_eq!(received.version, version);
        assert_eq!(
            matches!(received.register_layout, TpmRegisterLayout::Mmio),
            mmio
        );
        assert_eq!(received.guest_secret_key, secret);
        assert_eq!(received.nvram_size, size);
        assert_eq!(received.refresh_tpm_seeds, refresh);
        assert_eq!(received.is_confidential_vm, confidential);
        assert_eq!(received.bios_guid, bios_guid);
        assert!(matches!(received.ak_cert_type, TpmAkCertTypeResource::None));
        assert_eq!(
            resolver
                .resolve::<_, ConfigBytes>(received.ppi_store, ())
                .await
                .unwrap(),
            ConfigBytes(vec![1, 0, 0xff])
        );
        assert_eq!(
            resolver
                .resolve::<_, ConfigBytes>(received.nvram_store, ())
                .await
                .unwrap(),
            ConfigBytes(vec![2, 0xff, 0, 0x80])
        );
        assert_eq!(received.logger.is_some(), confidential);
        if let Some(logger) = received.logger {
            assert_eq!(
                resolver
                    .resolve::<_, ConfigBytes>(logger, ())
                    .await
                    .unwrap(),
                ConfigBytes(vec![3, 0, 0xff])
            );
        }
    }
}

fn certificate_resource() -> Resource<RequestAkCertKind> {
    Resource::new(ConfigBytes(vec![0xa1, 0, 0xff]))
}

// Test: Serialize every AK certificate policy, including all three optional
//       renewal settings for trusted certificates, and resolve its helper.
// Expected: Attestation kind, renewal policy and helper payload stay distinct;
//       no helper is invented when the certificate policy is absent.
#[async_test]
async fn certificate_policies_preserve_attestation_and_renewal_choices() {
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver::<RequestAkCertKind, ConfigBytes, ConfigBytes, _>(ConfigResolver);
    for (policy, expected_kind, expected_renewal) in [
        (TpmAkCertTypeResource::None, "none", None),
        (
            TpmAkCertTypeResource::Trusted(certificate_resource(), None),
            "trusted",
            None,
        ),
        (
            TpmAkCertTypeResource::Trusted(certificate_resource(), Some(false)),
            "trusted",
            Some(false),
        ),
        (
            TpmAkCertTypeResource::Trusted(certificate_resource(), Some(true)),
            "trusted",
            Some(true),
        ),
        (
            TpmAkCertTypeResource::HwAttested(certificate_resource()),
            "hardware",
            None,
        ),
        (
            TpmAkCertTypeResource::SwAttested(certificate_resource()),
            "software",
            None,
        ),
    ] {
        let received: TpmAkCertTypeResource =
            OwnedMessage::serialized(OwnedMessage::new(policy).serialize())
                .parse()
                .unwrap();
        let (kind, renewal, helper) = match received {
            TpmAkCertTypeResource::None => ("none", None, None),
            TpmAkCertTypeResource::Trusted(helper, renewal) => ("trusted", renewal, Some(helper)),
            TpmAkCertTypeResource::HwAttested(helper) => ("hardware", None, Some(helper)),
            TpmAkCertTypeResource::SwAttested(helper) => ("software", None, Some(helper)),
        };
        assert_eq!(kind, expected_kind);
        assert_eq!(renewal, expected_renewal);
        assert_eq!(helper.is_some(), expected_kind != "none");
        if let Some(helper) = helper {
            assert_eq!(
                resolver
                    .resolve::<_, ConfigBytes>(helper, ())
                    .await
                    .unwrap(),
                ConfigBytes(vec![0xa1, 0, 0xff])
            );
        }
    }
}

type Events = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

struct RecordingLogger {
    events: Events,
    flush_ready: Arc<AtomicBool>,
}

fn event_name(event: TpmLogEvent) -> &'static str {
    match event {
        TpmLogEvent::AkCertRenewalFailed => "certificate",
        TpmLogEvent::IdentityChangeFailed => "identity",
        TpmLogEvent::InvalidState => "state",
    }
}

#[async_trait::async_trait]
impl TpmLogger for RecordingLogger {
    async fn log_event_and_flush(&self, event: TpmLogEvent) {
        let event = event_name(event);
        self.events.lock().push(("flush-start", event));
        // The test drives polling directly and releases the gate between polls.
        poll_fn(|_| {
            if self.flush_ready.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.events.lock().push(("flush-done", event));
    }

    fn log_event(&self, event: TpmLogEvent) {
        self.events.lock().push(("log", event_name(event)));
    }
}

// Test: Forward every event through a configured optional logger and delay its
//       flush completion, then issue events with the logger absent.
// Expected: Events reach the host once, flush stays pending until completion,
//       and an absent logger finishes without reaching the earlier host logger.
#[test]
fn optional_logger_forwards_events_and_awaits_host_flush() {
    let events: Events = Arc::default();
    let flush_ready = Arc::new(AtomicBool::new(false));
    let resolved: ResolvedTpmLogger = RecordingLogger {
        events: events.clone(),
        flush_ready: flush_ready.clone(),
    }
    .into();
    let logger = Some(resolved.0);
    logger.log_event(TpmLogEvent::AkCertRenewalFailed);
    logger.log_event(TpmLogEvent::IdentityChangeFailed);
    logger.log_event(TpmLogEvent::InvalidState);
    let mut context = Context::from_waker(Waker::noop());
    let mut flush = std::pin::pin!(logger.log_event_and_flush(TpmLogEvent::InvalidState));
    assert!(flush.as_mut().poll(&mut context).is_pending());
    assert_eq!(
        *events.lock(),
        [
            ("log", "certificate"),
            ("log", "identity"),
            ("log", "state"),
            ("flush-start", "state"),
        ]
    );
    flush_ready.store(true, Ordering::Release);
    assert!(flush.as_mut().poll(&mut context).is_ready());
    let expected = [
        ("log", "certificate"),
        ("log", "identity"),
        ("log", "state"),
        ("flush-start", "state"),
        ("flush-done", "state"),
    ];
    assert_eq!(*events.lock(), expected);
    let absent: Option<Arc<dyn TpmLogger>> = None;
    for event in [
        TpmLogEvent::AkCertRenewalFailed,
        TpmLogEvent::IdentityChangeFailed,
        TpmLogEvent::InvalidState,
    ] {
        absent.log_event(event);
    }
    let mut absent_flush = std::pin::pin!(absent.log_event_and_flush(TpmLogEvent::InvalidState));
    assert!(absent_flush.as_mut().poll(&mut context).is_ready());
    assert_eq!(*events.lock(), expected);
}
