// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{
    MapVpciInterrupt, MsiAddressData, RegisterInterruptError, VpciInterruptMapper,
    VpciInterruptParameters,
};
use futures::executor::block_on;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use test_with_tracing::test;

#[derive(Default)]
struct RecordingMapper {
    registrations: Mutex<Vec<(u32, u32, bool, Vec<u32>)>>,
    removals: Mutex<Vec<(u64, u32)>>,
    fail: AtomicBool,
}

impl MapVpciInterrupt for RecordingMapper {
    async fn register_interrupt(
        &self,
        count: u32,
        params: &VpciInterruptParameters<'_>,
    ) -> Result<MsiAddressData, RegisterInterruptError> {
        self.registrations.lock().push((
            count,
            params.vector,
            params.multicast,
            params.target_processors.to_vec(),
        ));
        if self.fail.load(Ordering::SeqCst) {
            return Err(RegisterInterruptError::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "mapping denied",
            )));
        }
        Ok(MsiAddressData {
            address: 0x1234_5678_fee0_0000,
            data: 0x89ab_cdef,
        })
    }

    async fn unregister_interrupt(&self, address: u64, data: u32) {
        self.removals.lock().push((address, data));
    }
}

// Test: Register/unregister through cloned type-erased MSI mappers with multicast and unicast target sets.
// Expected: Every parameter and high address/data bit reaches the backend unchanged, returned mappings are exact, and backend error causes survive forwarding.
#[test]
fn erased_msi_mapper_preserves_parameters_results_and_error_sources() {
    block_on(async {
        let backend = Arc::new(RecordingMapper::default());
        let mapper = VpciInterruptMapper::new(backend.clone());
        let clone = mapper.clone();
        let expected = MsiAddressData {
            address: 0x1234_5678_fee0_0000,
            data: 0x89ab_cdef,
        };
        let mapped = mapper
            .register_interrupt(
                8,
                &VpciInterruptParameters {
                    vector: 0x81,
                    multicast: true,
                    target_processors: &[3, 17, 255],
                },
            )
            .await
            .unwrap();
        assert_eq!(mapped, expected);
        clone
            .unregister_interrupt(mapped.address, mapped.data)
            .await;
        backend.fail.store(true, Ordering::SeqCst);
        let error = clone
            .register_interrupt(
                1,
                &VpciInterruptParameters {
                    vector: 0x91,
                    multicast: false,
                    target_processors: &[7],
                },
            )
            .await
            .unwrap_err();
        let cause = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(cause.to_string(), "mapping denied");
        assert_eq!(
            *backend.registrations.lock(),
            [(8, 0x81, true, vec![3, 17, 255]), (1, 0x91, false, vec![7])]
        );
        assert_eq!(
            *backend.removals.lock(),
            [(expected.address, expected.data)]
        );
    });
}
