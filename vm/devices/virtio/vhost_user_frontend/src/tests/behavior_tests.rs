// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

mod resolver_tests;
mod wire_tests;

struct ConfigDevice {
    inner: MockBackendDevice,
    registers: Arc<[AtomicU32; 2]>,
}

impl InspectMut for ConfigDevice {
    fn inspect_mut(&mut self, _req: inspect::Request<'_>) {}
}
impl VirtioDevice for ConfigDevice {
    fn traits(&self) -> DeviceTraits {
        DeviceTraits {
            device_register_length: 8,
            ..self.inner.traits()
        }
    }
    async fn read_registers_u32(&mut self, offset: u16) -> u32 {
        self.registers[offset as usize / 4].load(Ordering::SeqCst)
    }
    async fn write_registers_u32(&mut self, offset: u16, value: u32) {
        self.registers[offset as usize / 4].store(value, Ordering::SeqCst);
    }
    async fn start_queue(
        &mut self,
        idx: u16,
        resources: QueueResources,
        features: &VirtioDeviceFeatures,
        state: Option<QueueState>,
    ) -> anyhow::Result<()> {
        self.inner
            .start_queue(idx, resources, features, state)
            .await
    }
    async fn stop_queue(&mut self, idx: u16) -> Option<QueueState> {
        self.inner.stop_queue(idx).await
    }
    async fn reset(&mut self) {
        self.inner.reset().await
    }
}

// Test: Read/write real backend config registers with a patch spanning two DWORDs, then disable backend config and repeat.
// Expected: Reads apply only overlapping patch bytes in little-endian order; enabled writes reach backend registers unchanged despite patches, while disabled reads start at zero and writes have no backend effect.
#[async_test]
async fn config_forwarding_and_cross_dword_patches_preserve_unpatched_data(driver: DefaultDriver) {
    for enabled in [true, false] {
        let registers = Arc::new([AtomicU32::new(0x44332211), AtomicU32::new(0x88776655)]);
        let (frontend_stream, backend_stream) = socket_pair();
        let backend_socket =
            VhostUserSocket::new(PolledSocket::new(&driver, backend_stream).unwrap());
        let server = VhostUserDeviceServer::new(Box::new(ConfigDevice {
            inner: MockBackendDevice::new(),
            registers: registers.clone(),
        }));
        let backend = driver.spawn("config-backend", async move {
            server.serve_connection(backend_socket).await.unwrap();
        });
        let socket = VhostUserSocket::new(PolledSocket::new(&driver, frontend_stream).unwrap());
        let vm_driver = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())).simple();
        let mut frontend = VhostUserFrontend::from_socket(
            vm_driver,
            socket,
            VhostUserConfig {
                device_id: VirtioDeviceType::BLK,
                use_backend_config: enabled,
                queue_sizes: vec![16],
                config_patches: vec![(2, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            frontend.read_registers_u32(0).await,
            if enabled { 0xbbaa2211 } else { 0xbbaa0000 }
        );
        assert_eq!(
            frontend.read_registers_u32(4).await,
            if enabled { 0x8877ddcc } else { 0x0000ddcc }
        );
        frontend.write_registers_u32(0, 0x91827364).await;
        frontend.write_registers_u32(4, 0x9876abcd).await;
        assert_eq!(
            frontend.read_registers_u32(0).await,
            if enabled { 0xbbaa7364 } else { 0xbbaa0000 }
        );
        assert_eq!(
            frontend.read_registers_u32(4).await,
            if enabled { 0x9876ddcc } else { 0x0000ddcc }
        );
        assert_eq!(
            registers[0].load(Ordering::SeqCst),
            if enabled { 0x91827364 } else { 0x44332211 }
        );
        assert_eq!(
            registers[1].load(Ordering::SeqCst),
            if enabled { 0x9876abcd } else { 0x88776655 }
        );
        drop(frontend);
        backend.await;
    }
}
