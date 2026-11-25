// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::TestNvmeMmioRegistration;
use super::test_helpers::test_memory;
use crate::resolver::NvmeControllerResolver;
use disk_backend::resolve::ResolveDiskParameters;
use disk_backend::resolve::ResolvedDisk;
use disklayer_ram::ram_disk;
use guid::Guid;
use mesh::rpc::RpcSend;
use nvme_resources::NamespaceDefinition;
use nvme_resources::NvmeControllerHandle;
use nvme_resources::NvmeControllerRequest;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pci_core::bus_range::AssignedBusRange;
use pci_core::dma::DmaTarget;
use pci_core::msi::MsiConnection;
use pci_resources::ResolvePciDeviceHandleParams;
use pci_resources::ResolvedPciDevice;
use test_with_tracing::test;
use vm_resource::IntoResource;
use vm_resource::ResolveResource;
use vm_resource::ResourceId;
use vm_resource::ResourceResolver;
use vm_resource::kind::DiskHandleKind;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;

#[derive(mesh::MeshPayload)]
struct TestDiskHandle {
    fail: bool,
}

impl ResourceId<DiskHandleKind> for TestDiskHandle {
    const ID: &'static str = "nvme-unit-test-ram";
}

struct TestDiskResolver;

impl ResolveResource<DiskHandleKind, TestDiskHandle> for TestDiskResolver {
    type Output = ResolvedDisk;
    type Error = std::io::Error;

    fn resolve(
        &self,
        resource: TestDiskHandle,
        input: ResolveDiskParameters<'_>,
    ) -> Result<Self::Output, Self::Error> {
        if resource.fail {
            return Err(std::io::Error::other("injected disk resolution failure"));
        }
        Ok(ResolvedDisk(ram_disk(0x10000, input.read_only).unwrap()))
    }
}

fn namespace(nsid: u32, fail: bool) -> NamespaceDefinition {
    NamespaceDefinition {
        nsid,
        read_only: false,
        disk: TestDiskHandle { fail }.into_resource(),
    }
}

fn handle(namespaces: Vec<NamespaceDefinition>) -> NvmeControllerHandle {
    NvmeControllerHandle {
        subsystem_id: Guid::ZERO,
        msix_count: 4,
        max_io_queues: 4,
        namespaces,
        requests: None,
    }
}

struct Resources {
    resolver: ResourceResolver,
    source: VmTaskDriverSource,
    dma: DmaTarget,
    mmio: TestNvmeMmioRegistration,
}

impl Resources {
    fn new(driver: DefaultDriver) -> Self {
        let mut resolver = ResourceResolver::new();
        resolver.add_async_resolver(NvmeControllerResolver);
        resolver.add_resolver(TestDiskResolver);
        Self {
            resolver,
            source: VmTaskDriverSource::new(SingleDriverBackend::new(driver)),
            dma: DmaTarget::new(
                AssignedBusRange::new(),
                0,
                test_memory(),
                &MsiConnection::new(),
            ),
            mmio: TestNvmeMmioRegistration {},
        }
    }

    async fn resolve(
        &mut self,
        handle: NvmeControllerHandle,
    ) -> Result<ResolvedPciDevice, vm_resource::ResolveError> {
        self.resolver
            .resolve(
                handle.into_resource(),
                ResolvePciDeviceHandleParams {
                    dma_target: &self.dma,
                    register_mmio: &mut self.mmio,
                    driver_source: &self.source,
                    doorbell_registration: None,
                    shared_mem_mapper: None,
                },
            )
            .await
    }
}

// Test: Resolve a controller with an initial namespace and use its public
//       resource request channel for hot-add, duplicate add, failed add and removal.
// Expected: Replies distinguish each failure, removal sees the initial namespace,
//       and a failed request does not stop later add/remove requests.
#[async_test]
async fn runtime_resource_requests_preserve_errors_and_allow_retry(driver: DefaultDriver) {
    let mut resources = Resources::new(driver);
    let (send, receive) = mesh::channel();
    let mut handle = handle(vec![namespace(1, false)]);
    handle.requests = Some(receive);
    let _device = resources.resolve(handle).await.unwrap();
    send.call_failable(NvmeControllerRequest::AddNamespace, namespace(2, false))
        .await
        .unwrap();
    let duplicate = send
        .call_failable(NvmeControllerRequest::AddNamespace, namespace(2, false))
        .await
        .unwrap_err();
    assert!(format!("{duplicate:#}").contains("failed to add namespace"));
    let failed = send
        .call_failable(NvmeControllerRequest::AddNamespace, namespace(3, true))
        .await
        .unwrap_err();
    assert!(format!("{failed:#}").contains("failed to resolve disk"));
    let missing = send
        .call_failable(NvmeControllerRequest::RemoveNamespace, 3)
        .await
        .unwrap_err();
    assert!(format!("{missing:#}").contains("namespace 3 not found"));
    send.call_failable(NvmeControllerRequest::AddNamespace, namespace(3, false))
        .await
        .unwrap();
    for nsid in [1, 2, 3] {
        send.call_failable(NvmeControllerRequest::RemoveNamespace, nsid)
            .await
            .unwrap();
    }
    drop(send);
}

// Test: Resolve initial configurations with a failed disk, invalid namespace
//       ID, duplicate ID and an empty namespace list.
// Expected: Configuration errors retain namespace context and their causes;
//       resolving a valid empty controller still succeeds afterward.
#[async_test]
async fn initial_resource_errors_keep_namespace_context(driver: DefaultDriver) {
    let mut resources = Resources::new(driver);
    let error = resources
        .resolve(handle(vec![namespace(7, true)]))
        .await
        .err()
        .unwrap();
    let error = anyhow::Error::new(error);
    let message = format!("{error:#}");
    assert!(
        message.contains("failed to resolve namespace 7"),
        "{message}"
    );
    assert!(
        message.contains("injected disk resolution failure"),
        "{message}"
    );
    for namespaces in [
        vec![namespace(0, false)],
        vec![namespace(1, false), namespace(1, false)],
    ] {
        assert!(resources.resolve(handle(namespaces)).await.is_err());
    }
    let _device = resources.resolve(handle(Vec::new())).await.unwrap();
}
