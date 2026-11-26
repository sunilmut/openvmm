// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native KVM error provenance using a harmless unsupported file descriptor.

#![cfg(target_os = "linux")]

use kvm::Error;
use kvm::Kvm;
use kvm::VmType;
use nix::errno::Errno;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use test_with_tracing::test;

// Test: Wrap an ordinary file as KVM, fail extension/VM ioctls, then recover the
//       owned file and continue reading at its original position.
// Expected: Native errors retain their operation and ENOTTY; failed probes
//       neither close the descriptor nor alter its seek position.
#[test]
fn rejected_vm_creation_preserves_error_and_descriptor_ownership() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let mut file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(directory.path().join("ordinary"))
        .unwrap();
    file.write_all(b"prefix-payload").unwrap();
    file.seek(SeekFrom::Start(7)).unwrap();
    let kvm = Kvm::from(file);
    assert_eq!(kvm.check_extension(0).unwrap_err(), Errno::ENOTTY);
    assert!(matches!(
        kvm.new_vm(VmType::Default),
        Err(Error::CreateVm(Errno::ENOTTY))
    ));
    let mut returned = File::from(kvm);
    let mut remaining = Vec::new();
    returned.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, b"payload");
}

// Test: Query native x86 CPU/MCE/SEV features and request an SNP VM through an
//       unsupported descriptor.
// Expected: Probe failures never become empty capability data or unsupported
//       VM-type answers; the typed operation and native errno remain intact.
#[cfg(target_arch = "x86_64")]
#[test]
fn failed_native_feature_queries_do_not_fabricate_capabilities() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let file = File::create(directory.path().join("ordinary")).unwrap();
    let kvm = Kvm::from(file);
    assert!(matches!(
        kvm.supported_cpuid(),
        Err(Error::GetSupportedCpuid(Errno::ENOTTY))
    ));
    assert!(matches!(
        kvm.supported_hv_cpuid(),
        Err(Error::GetSupportedCpuid(Errno::ENOTTY))
    ));
    assert!(matches!(
        kvm.supported_mce_cap(),
        Err(Error::GetMceCapSupported(Errno::ENOTTY))
    ));
    assert!(matches!(
        kvm.supported_sev_vmsa_features(),
        Err(Error::GetDeviceAttr(Errno::ENOTTY))
    ));
    assert!(matches!(
        kvm.new_vm(VmType::Snp),
        Err(Error::CheckExtension(Errno::ENOTTY))
    ));
}
