// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public partition-creation failure boundaries without a native MSHV device.

#![cfg(all(target_os = "linux", guest_arch = "x86_64"))]

use pal_async::DefaultDriver;
use pal_async::async_test;
use std::fs::File;
use std::io;
use test_with_tracing::test;
use virt::Hypervisor;
use virt::ProtoPartitionConfig;
use virt::ProtoPartitionIsolation;
use virt_mshv::LinuxMshv;
use vm_topology::processor::TopologyBuilder;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeKeeper;

fn native_errno(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return error.raw_os_error();
        }
        current = error.source();
    }
    None
}

// Test: Attempt public partition creation with a valid one-VP configuration
//       and an ordinary directory descriptor instead of /dev/mshv.
// Expected: The operation fails at native creation, preserving both its
//       create-VM context and the underlying ENOTTY in the public error chain.
#[async_test]
async fn native_creation_failure_retains_operation_and_errno(driver: DefaultDriver) {
    let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let time = keeper.builder().build(&driver).await.unwrap();
    let topology = TopologyBuilder::new_x86().build(1).unwrap();
    let mut backend = LinuxMshv::from(File::open(".").unwrap());
    let error = backend
        .new_partition(ProtoPartitionConfig {
            processor_topology: &topology,
            hv_config: None,
            vmtime: &time,
            isolation: ProtoPartitionIsolation::None,
            nested_virt: false,
        })
        .err()
        .expect("an ordinary directory cannot create a VM");
    assert_eq!(error.to_string(), "create_vm failed");
    assert_eq!(native_errno(&error), Some(libc::ENOTTY));
}

// Test: Request SNP-only offload configuration and nested virtualization
//       through the public constructor, then provide their required settings.
// Expected: Invalid combinations fail before native creation; corrected
//       combinations reach the unsupported endpoint and retain native errno.
#[async_test]
async fn public_creation_enforces_feature_prerequisites_before_native_io(driver: DefaultDriver) {
    let keeper = VmTimeKeeper::new(&driver, VmTime::from_100ns(0));
    let time = keeper.builder().build(&driver).await.unwrap();
    let topology = TopologyBuilder::new_x86().build(1).unwrap();
    let config = || ProtoPartitionConfig {
        processor_topology: &topology,
        hv_config: None,
        vmtime: &time,
        isolation: ProtoPartitionIsolation::None,
        nested_virt: false,
    };
    let mut backend =
        LinuxMshv::from(File::open(".").unwrap()).with_snp_cpuid_offload_disabled(true);
    let error = backend.new_partition(config()).err().unwrap();
    assert!(error.to_string().contains("requires SNP isolation"));
    assert_eq!(native_errno(&error), None);

    let error = backend
        .new_partition(ProtoPartitionConfig {
            isolation: ProtoPartitionIsolation::Snp(virt::SnpPartitionConfig::DirectBoot {
                restricted_injection: false,
            }),
            ..config()
        })
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "create_vm failed");
    assert_eq!(native_errno(&error), Some(libc::ENOTTY));

    let mut backend = backend.with_snp_cpuid_offload_disabled(false);
    let error = backend
        .new_partition(ProtoPartitionConfig {
            nested_virt: true,
            ..config()
        })
        .err()
        .unwrap();
    assert!(error.to_string().contains("nested_virt requires hv_config"));
    assert_eq!(native_errno(&error), None);

    let error = backend
        .new_partition(ProtoPartitionConfig {
            nested_virt: true,
            hv_config: Some(virt::HvConfig {
                allow_device_assignment: false,
                vtl2: None,
            }),
            ..config()
        })
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "create_vm failed");
    assert_eq!(native_errno(&error), Some(libc::ENOTTY));
}
