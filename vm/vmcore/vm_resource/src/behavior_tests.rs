// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::async_test;
use std::future::Future;
use std::future::poll_fn;
use std::io;
use std::task::Poll;
use test_with_tracing::test;

enum ValueKind {}
impl ResourceKind for ValueKind {
    const NAME: &'static str = "behavior_value";
}
impl CanResolveTo<String> for ValueKind {
    type Input<'a> = &'a str;
}

enum OtherKind {}
impl ResourceKind for OtherKind {
    const NAME: &'static str = "behavior_other";
}
impl CanResolveTo<u32> for OtherKind {
    type Input<'a> = u32;
}

#[derive(MeshPayload)]
struct Value {
    value: u32,
}
impl ResourceId<ValueKind> for Value {
    const ID: &'static str = "value";
}
impl ResourceId<OtherKind> for Value {
    const ID: &'static str = "value";
}

#[derive(MeshPayload)]
struct AsyncValue {
    value: u32,
}
impl ResourceId<ValueKind> for AsyncValue {
    const ID: &'static str = "async";
}

#[derive(MeshPayload)]
struct InvalidValue {
    value: String,
}
impl ResourceId<ValueKind> for InvalidValue {
    const ID: &'static str = "value";
}

#[derive(MeshPayload)]
struct InvalidAsyncValue {
    value: String,
}
impl ResourceId<ValueKind> for InvalidAsyncValue {
    const ID: &'static str = "async";
}

#[derive(MeshPayload)]
struct StaticValue {
    value: u32,
}
impl ResourceId<ValueKind> for StaticValue {
    const ID: &'static str = "static";
}

#[derive(MeshPayload)]
struct StaticAsyncValue {
    value: u32,
}
impl ResourceId<ValueKind> for StaticAsyncValue {
    const ID: &'static str = "static-async";
}

struct Multiply(u32);
impl ResolveResource<ValueKind, Value> for Multiply {
    type Output = String;
    type Error = io::Error;
    fn resolve(&self, resource: Value, input: &str) -> Result<String, Self::Error> {
        if resource.value == 0 {
            return Err(io::Error::other("zero value rejected"));
        }
        Ok(format!("{input}{}", resource.value * self.0))
    }
}
impl ResolveResource<OtherKind, Value> for Multiply {
    type Output = u32;
    type Error = io::Error;
    fn resolve(&self, resource: Value, input: u32) -> Result<u32, Self::Error> {
        Ok(resource.value * self.0 + input)
    }
}

struct NestedResolver;
#[async_trait]
impl AsyncResolveResource<ValueKind, AsyncValue> for NestedResolver {
    type Output = String;
    type Error = ResolveError;
    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        resource: AsyncValue,
        input: &str,
    ) -> Result<String, Self::Error> {
        resolver
            .resolve(
                Resource::<ValueKind>::new(Value {
                    value: resource.value,
                }),
                input,
            )
            .await
    }
}

struct StaticResolver;
impl ResolveResource<ValueKind, StaticValue> for StaticResolver {
    type Output = String;
    type Error = io::Error;
    fn resolve(&self, resource: StaticValue, input: &str) -> Result<String, Self::Error> {
        Ok(format!("{input}{}", resource.value + 100))
    }
}
declare_static_resolver!(StaticResolver, (ValueKind, StaticValue));

struct StaticAsyncResolver;
#[async_trait]
impl AsyncResolveResource<ValueKind, StaticAsyncValue> for StaticAsyncResolver {
    type Output = String;
    type Error = ResolveError;
    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        resource: StaticAsyncValue,
        input: &str,
    ) -> Result<String, Self::Error> {
        resolver
            .resolve(
                Resource::new(StaticValue {
                    value: resource.value,
                }),
                input,
            )
            .await
    }
}
declare_static_async_resolver!(StaticAsyncResolver, (ValueKind, StaticAsyncValue));
register_static_resolvers!(StaticResolver, StaticAsyncResolver);

fn resolver() -> ResourceResolver {
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver::<ValueKind, _, _, _>(Multiply(3));
    resolver.add_async_resolver(NestedResolver);
    resolver
}

// Test: Resolve a value with a borrowed prefix and the same resource ID in two kinds.
// Expected: Kind-specific resolvers return their own output types and retain the
//       caller's input without confusing identical IDs in different kinds.
#[async_test]
async fn dynamic_resolvers_keep_resource_kinds_and_borrowed_inputs_separate() {
    let mut resolver = resolver();
    resolver.add_resolver::<OtherKind, _, _, _>(Multiply(5));
    let prefix = String::from("result=");
    let resource: Resource<ValueKind> = Value { value: 7 }.into_resource();
    assert_eq!(
        resolver.resolve(resource, &prefix).await.unwrap(),
        "result=21"
    );
    let resource = Resource::<OtherKind>::new(Value { value: 7 });
    assert_eq!(resolver.resolve(resource, 2).await.unwrap(), 37);
}

// Test: Resolve nested resources through dynamic and link-time async resolvers.
// Expected: Nested resolution forwards borrowed input and reaches the correct
//       synchronous resolver, including resolvers registered at link time.
#[async_test]
async fn asynchronous_resolvers_can_resolve_dynamic_and_static_children() {
    let resolver = resolver();
    assert_eq!(
        resolver
            .resolve(Resource::new(AsyncValue { value: 11 }), "dynamic=")
            .await
            .unwrap(),
        "dynamic=33"
    );
    assert_eq!(
        resolver
            .resolve(Resource::new(StaticAsyncValue { value: 13 }), "static=")
            .await
            .unwrap(),
        "static=113"
    );
}

// Test: Add a resolver after cloning an otherwise empty resolver.
// Expected: Registration affects only the modified clone; existing registrations
//       remain usable after a populated resolver is cloned and extended.
#[async_test]
async fn cloned_resolvers_isolate_later_registrations() {
    let original = ResourceResolver::new();
    let mut modified = original.clone();
    modified.add_resolver::<ValueKind, _, _, _>(Multiply(2));
    assert!(matches!(
        original
            .resolve(Resource::<ValueKind>::new(Value { value: 3 }), "")
            .await,
        Err(ResolveError::NoResolver { .. })
    ));
    assert_eq!(
        modified
            .resolve(Resource::<ValueKind>::new(Value { value: 3 }), "")
            .await
            .unwrap(),
        "6"
    );
    let mut extended = modified.clone();
    extended.add_async_resolver(NestedResolver);
    assert_eq!(
        extended
            .resolve(Resource::new(AsyncValue { value: 5 }), "")
            .await
            .unwrap(),
        "10"
    );
    assert!(matches!(
        modified
            .resolve(Resource::new(AsyncValue { value: 5 }), "")
            .await,
        Err(ResolveError::NoResolver { .. })
    ));
}

// Test: Resolve missing resource types and deliberately failing backend requests.
// Expected: Errors expose the resource kind and ID and preserve the original
//       backend error, including failures reached through an async resolver.
#[async_test]
async fn resolution_errors_keep_resource_identity_and_source() {
    let empty = ResourceResolver::new();
    let error = empty
        .resolve(Resource::<ValueKind>::new(PlatformResource), "")
        .await
        .unwrap_err();
    assert!(
        matches!(&error, ResolveError::NoResolver { kind: "behavior_value", id } if id == "platform")
    );
    assert_eq!(error.to_string(), "no resolver for behavior_value:platform");
    let resolver = resolver();
    for (resource, expected_id) in [
        (Resource::new(Value { value: 0 }), "value"),
        (Resource::new(AsyncValue { value: 0 }), "async"),
    ] {
        let error = resolver.resolve(resource, "").await.unwrap_err();
        let ResolveError::ResolverError { kind, id, source } = error else {
            panic!("expected backend failure");
        };
        assert_eq!(kind, "behavior_value");
        assert_eq!(id, expected_id);
        let mut source: &(dyn std::error::Error + 'static) = source.as_ref();
        while let Some(next) = source.source() {
            source = next;
        }
        assert_eq!(
            source.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(source.to_string(), "zero value rejected");
    }
}

// Test: Decode incompatible payloads claiming the IDs of sync and async resources.
// Expected: Both paths return ParseError with the original identity instead of
//       calling a resolver with the wrong payload type.
#[async_test]
async fn incompatible_payloads_report_parse_errors() {
    let resolver = resolver();
    for resource in [
        Resource::new(InvalidValue {
            value: "invalid number".into(),
        }),
        Resource::new(InvalidAsyncValue {
            value: "invalid number".into(),
        }),
    ] {
        let expected_id = resource.id().to_owned();
        let error = resolver.resolve(resource, "").await.unwrap_err();
        assert!(
            matches!(error, ResolveError::ParseError { kind: "behavior_value", id, .. } if id == expected_id)
        );
    }
}

// Test: Register the same dynamic synchronous resource resolver twice.
// Expected: Registration rejects the collision and names the conflicting kind/ID.
#[test]
#[should_panic(expected = "duplicate resolver for behavior_value:value")]
fn duplicate_dynamic_sync_registration_is_rejected() {
    let mut resolver = resolver();
    resolver.add_resolver::<ValueKind, _, _, _>(Multiply(7));
}

// Test: Register the same dynamic asynchronous resource resolver twice.
// Expected: Registration rejects the collision and names the conflicting kind/ID.
#[test]
#[should_panic(expected = "duplicate resolver for behavior_value:async")]
fn duplicate_dynamic_async_registration_is_rejected() {
    let mut resolver = resolver();
    resolver.add_async_resolver(NestedResolver);
}

// Test: Dynamically register a resolver already registered at link time.
// Expected: Static registrations participate in duplicate detection.
#[test]
#[should_panic(expected = "duplicate resolver for behavior_value:static")]
fn duplicate_static_registration_is_rejected() {
    ResourceResolver::new().add_resolver(StaticResolver);
}

// Test: Format a resource for diagnostics without exposing its payload.
// Expected: The public resource ID is present and the sensitive payload is absent.
#[test]
fn resource_debug_output_reports_identity_without_payload() {
    let resource = Resource::<ValueKind>::new(InvalidValue {
        value: "private-payload".into(),
    });
    let text = format!("{resource:?}");
    assert!(text.contains("value"));
    assert!(!text.contains("private-payload"));
}

// Test: Resolve serialized resource envelopes after malformed sync/async payloads.
// Expected: Parse failures stay request-local; subsequent dynamic and static
//       resources retain their identity, payload and borrowed resolution input.
#[async_test]
async fn serialized_resource_failures_do_not_poison_later_resolution() {
    let resolver = resolver();
    for resource in [
        Resource::new(InvalidValue {
            value: "invalid integer".into(),
        }),
        Resource::new(InvalidAsyncValue {
            value: "invalid integer".into(),
        }),
    ] {
        let resource = OwnedMessage::serialized(OwnedMessage::new(resource).serialize())
            .parse::<Resource<ValueKind>>()
            .unwrap();
        assert!(matches!(
            resolver.resolve(resource, "").await,
            Err(ResolveError::ParseError { .. })
        ));
    }

    let prefix = String::from("wire=");
    for (resource, expected) in [
        (Resource::new(Value { value: 7 }), "wire=21"),
        (Resource::new(AsyncValue { value: 11 }), "wire=33"),
        (Resource::new(StaticValue { value: 13 }), "wire=113"),
        (Resource::new(StaticAsyncValue { value: 17 }), "wire=117"),
    ] {
        let resource = OwnedMessage::serialized(OwnedMessage::new(resource).serialize())
            .parse::<Resource<ValueKind>>()
            .unwrap();
        assert_eq!(resolver.resolve(resource, &prefix).await.unwrap(), expected);
    }
}

enum OwnedKind {}
impl ResourceKind for OwnedKind {
    const NAME: &'static str = "behavior_owned";
}
impl CanResolveTo<OwnedResult> for OwnedKind {
    type Input<'a> = &'a str;
}

#[derive(MeshPayload)]
struct OwnedRequest {
    label: String,
    lanes: Vec<u64>,
    bytes: Vec<u8>,
    gate: mesh::OneshotReceiver<()>,
    lease: mesh::OneshotSender<()>,
}
impl ResourceId<OwnedKind> for OwnedRequest {
    const ID: &'static str = "owned";
}

struct OwnedResult {
    label: String,
    lanes: Vec<u64>,
    bytes: Vec<u8>,
    prefix: String,
    lease: mesh::OneshotSender<()>,
}

struct OwnedResolver;
#[async_trait]
impl AsyncResolveResource<OwnedKind, OwnedRequest> for OwnedResolver {
    type Output = OwnedResult;
    type Error = io::Error;

    async fn resolve(
        &self,
        _resolver: &ResourceResolver,
        resource: OwnedRequest,
        input: &str,
    ) -> Result<OwnedResult, Self::Error> {
        resource
            .gate
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        Ok(OwnedResult {
            label: resource.label,
            lanes: resource.lanes,
            bytes: resource.bytes,
            prefix: input.to_owned(),
            lease: resource.lease,
        })
    }
}

// Test: Resolve fresh owned payloads directly and through serialized envelopes.
// Expected: Every payload field and borrowed input survives type erasure, including
//       wide integers and binary data; the returned object owns the channel lease.
#[async_test]
async fn owned_payload_resolution_preserves_all_fields_and_transfers_ownership() {
    let mut resolver = ResourceResolver::new();
    resolver.add_async_resolver(OwnedResolver);
    let prefix = String::from("borrowed=");
    for serialized in [false, true] {
        let (ready, gate) = mesh::oneshot();
        let (lease, mut released) = mesh::oneshot();
        let resource = Resource::new(OwnedRequest {
            label: "disk-λ".into(),
            lanes: vec![0, 0x1_0000_0001, u64::MAX],
            bytes: vec![0, 0x80, 0xff, 7],
            gate,
            lease,
        });
        let resource = if serialized {
            OwnedMessage::serialized(OwnedMessage::new(resource).serialize())
                .parse::<Resource<OwnedKind>>()
                .unwrap()
        } else {
            resource
        };
        ready.send(());
        let output = resolver.resolve(resource, &prefix).await.unwrap();
        assert_eq!(output.label, "disk-λ");
        assert_eq!(output.lanes, [0, 0x1_0000_0001, u64::MAX]);
        assert_eq!(output.bytes, [0, 0x80, 0xff, 7]);
        assert_eq!(output.prefix, "borrowed=");
        poll_fn(|cx| {
            assert!(std::pin::Pin::new(&mut released).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        output.lease.send(());
        assert_eq!(released.await.unwrap(), ());
    }
}

// Test: Cancel a pending serialized request while a cloned resolver serves peers.
// Expected: Cancellation closes both owned endpoints without changing peer
//       resolution; a fresh request of the cancelled type still resolves normally.
#[async_test]
async fn cancelled_resolution_releases_ownership_without_poisoning_peers() {
    let mut resolver = resolver();
    resolver.add_async_resolver(OwnedResolver);
    let peer_resolver = resolver.clone();
    let peer = Resource::new(AsyncValue { value: 9 });
    let (ready, gate) = mesh::oneshot();
    let (lease, mut released) = mesh::oneshot();
    let resource = OwnedMessage::serialized(
        OwnedMessage::new(Resource::new(OwnedRequest {
            label: "cancelled".into(),
            lanes: vec![11],
            bytes: vec![19],
            gate,
            lease,
        }))
        .serialize(),
    )
    .parse::<Resource<OwnedKind>>()
    .unwrap();
    let mut pending = Box::pin(resolver.resolve(resource, "cancel="));
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        assert!(std::pin::Pin::new(&mut released).poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(!ready.is_closed());
    assert_eq!(
        peer_resolver.resolve(peer, "peer=").await.unwrap(),
        "peer=27"
    );
    drop(pending);
    assert!(ready.is_closed());
    assert!(released.await.is_err());

    let (ready, gate) = mesh::oneshot();
    let (lease, released) = mesh::oneshot();
    ready.send(());
    let output = peer_resolver
        .resolve(
            Resource::new(OwnedRequest {
                label: "fresh".into(),
                lanes: vec![23, 29],
                bytes: vec![31, 37],
                gate,
                lease,
            }),
            "after=",
        )
        .await
        .unwrap();
    assert_eq!(output.label, "fresh");
    assert_eq!(output.lanes, [23, 29]);
    assert_eq!(output.bytes, [31, 37]);
    assert_eq!(output.prefix, "after=");
    output.lease.send(());
    assert_eq!(released.await.unwrap(), ());
    assert_eq!(
        resolver
            .resolve(Resource::<ValueKind>::new(Value { value: 5 }), "original=")
            .await
            .unwrap(),
        "original=15"
    );
}
