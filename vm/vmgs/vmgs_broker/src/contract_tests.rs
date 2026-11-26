// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use disk_hook::HookDisk;
use non_volatile_store::VmgsNonVolatileStore;
use pal_async::DefaultDriver;
use pal_async::async_test;
use resolver::VmgsFileResolver;
use resolver::VmgsFileResolverError;
use test_with_tracing::test;
use vm_resource::AsyncResolveResource;
use vm_resource::ResourceResolver;
use vmcore::non_volatile_store::NonVolatileStore;
use vmgs_format::FileId;
use vmgs_resources::VmgsFileHandle;

// Test: Two clients and a resolved NVRAM store share a broker and save its state.
// Expected: Missing files differ from empty files, writes replace exact bytes,
//       deletion is visible to clones, and saved metadata reopens the same data.
#[async_test]
async fn shared_store_persistence_delete_and_saved_metadata(driver: DefaultDriver) {
    let disk = HookDisk::new(4 * 1024 * 1024, 512).into_disk();
    let vmgs = vmgs::Vmgs::format_new(disk.clone(), None).await.unwrap();
    let (client, task) = spawn_vmgs_broker(driver, vmgs);
    let observer = client.clone();
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(client.clone());
    let mut store = VmgsFileResolver
        .resolve(
            &resolver,
            VmgsFileHandle {
                file_id: FileId::BIOS_NVRAM.0,
                encrypted: false,
            },
            &(),
        )
        .await
        .unwrap()
        .0;
    assert_eq!(store.restore().await.unwrap(), None);
    store.persist(vec![0, 0xff, 7, 0]).await.unwrap();
    assert_eq!(
        observer.read_file(FileId::BIOS_NVRAM).await.unwrap(),
        [0, 0xff, 7, 0]
    );
    let info = observer.get_file_info(FileId::BIOS_NVRAM).await.unwrap();
    assert_eq!(info.valid_bytes, 4);
    assert!(info.allocated_bytes >= info.valid_bytes);
    assert!(!info.encrypted);
    client
        .write_file(FileId::TPM_PPI, Vec::new())
        .await
        .unwrap();
    assert!(
        observer
            .read_file(FileId::TPM_PPI)
            .await
            .unwrap()
            .is_empty()
    );
    client.delete_file(FileId::TPM_PPI).await.unwrap();
    assert!(matches!(
        observer.read_file(FileId::TPM_PPI).await,
        Err(VmgsClientError::Vmgs(VmgsBrokerError::FileInfoNotAllocated))
    ));
    store.persist(b"replacement".to_vec()).await.unwrap();
    let thin = VmgsThinClient::new(observer);
    let saved = thin.save().await.unwrap();
    drop((thin, store, resolver, client));
    task.await;
    let mut reopened = vmgs::Vmgs::open_from_saved(disk, saved, None);
    assert_eq!(
        reopened.read_file(FileId::BIOS_NVRAM).await.unwrap(),
        b"replacement"
    );
}

// Test: Resolve a VMGS-backed store without its platform client.
// Expected: Resolution fails with the typed client error rather than producing
//       a store that silently discards persistent data.
#[async_test]
async fn store_resolution_requires_platform_client() {
    let error = VmgsFileResolver
        .resolve(
            &ResourceResolver::new(),
            VmgsFileHandle {
                file_id: FileId::BIOS_NVRAM.0,
                encrypted: false,
            },
            &(),
        )
        .await;
    assert!(matches!(error, Err(VmgsFileResolverError::Client(_))));
}

// Test: Shut down the broker while clients and a store remain alive.
// Expected: Read, write, delete, save and NVRAM operations report errors, not
//       successful writes or the missing-file initialization result.
#[async_test]
async fn disconnected_store_is_not_an_empty_store(driver: DefaultDriver) {
    let disk = HookDisk::new(4 * 1024 * 1024, 512).into_disk();
    let vmgs = vmgs::Vmgs::format_new(disk, None).await.unwrap();
    let (client, task) = spawn_vmgs_broker(driver, vmgs);
    let mut store = VmgsNonVolatileStore::new(client.clone(), FileId::BIOS_NVRAM, false).unwrap();
    task.cancel().await;
    assert!(matches!(
        client.read_file(FileId::BIOS_NVRAM).await,
        Err(VmgsClientError::BrokerOffline(_))
    ));
    assert!(matches!(
        client.get_file_info(FileId::BIOS_NVRAM).await,
        Err(VmgsClientError::BrokerOffline(_))
    ));
    assert!(matches!(
        client.write_file(FileId::BIOS_NVRAM, vec![1]).await,
        Err(VmgsClientError::BrokerOffline(_))
    ));
    assert!(matches!(
        client.delete_file(FileId::BIOS_NVRAM).await,
        Err(VmgsClientError::BrokerOffline(_))
    ));
    assert!(matches!(
        client.save().await,
        Err(VmgsClientError::BrokerOffline(_))
    ));
    assert!(store.restore().await.is_err());
    assert!(store.persist(vec![2]).await.is_err());
}

// Test: Request encrypted persistence from an encryption-enabled broker.
// Expected: NVRAM roundtrips as encrypted bytes and plaintext overwrites cannot
//       silently downgrade the existing file.
#[cfg(feature = "encryption")]
#[async_test]
async fn encrypted_store_prevents_plaintext_downgrade(driver: DefaultDriver) {
    let disk = HookDisk::new(4 * 1024 * 1024, 512).into_disk();
    let mut vmgs = vmgs::Vmgs::format_new(disk, None).await.unwrap();
    vmgs.update_encryption_key(&[0x43; 32], vmgs_format::EncryptionAlgorithm::AES_GCM)
        .await
        .unwrap();
    let (client, task) = spawn_vmgs_broker(driver, vmgs);
    let mut store = VmgsNonVolatileStore::new(client.clone(), FileId::BIOS_NVRAM, true).unwrap();
    store.persist(b"encrypted nvram".to_vec()).await.unwrap();
    assert!(
        client
            .get_file_info(FileId::BIOS_NVRAM)
            .await
            .unwrap()
            .encrypted
    );
    assert!(matches!(
        client
            .write_file(FileId::BIOS_NVRAM, b"downgrade".to_vec())
            .await,
        Err(VmgsClientError::Vmgs(_))
    ));
    assert_eq!(store.restore().await.unwrap().unwrap(), b"encrypted nvram");
    drop((store, client));
    task.await;
}

// Test: Request encrypted storage from a build without encryption support.
// Expected: Both direct construction and resource resolution reject it before
//       a caller can accidentally persist plaintext.
#[cfg(not(feature = "encryption"))]
#[async_test]
async fn unavailable_encryption_is_rejected(driver: DefaultDriver) {
    let disk = HookDisk::new(4 * 1024 * 1024, 512).into_disk();
    let vmgs = vmgs::Vmgs::format_new(disk, None).await.unwrap();
    let (client, task) = spawn_vmgs_broker(driver, vmgs);
    assert!(VmgsNonVolatileStore::new(client.clone(), FileId::BIOS_NVRAM, true).is_err());
    let mut resolver = ResourceResolver::new();
    resolver.add_resolver(client.clone());
    let result = VmgsFileResolver
        .resolve(
            &resolver,
            VmgsFileHandle {
                file_id: FileId::BIOS_NVRAM.0,
                encrypted: true,
            },
            &(),
        )
        .await;
    assert!(matches!(result, Err(VmgsFileResolverError::Store(_))));
    drop((resolver, client));
    task.await;
}
