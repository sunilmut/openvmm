// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Error;
use crate::FileId;
use crate::Vmgs;
use pal_async::async_test;
use test_with_tracing::test;

// Test: Reject a move over an allocated destination and mutations of metadata
//       files, then flush and reopen the same backing disk.
// Expected: Rejected operations preserve both payloads durably; a later allowed
//       overwrite moves the source and removes its old name after reopening.
#[async_test]
async fn rejected_moves_preserve_files_across_reopen() {
    let disk = disklayer_ram::ram_disk(4 * 1024 * 1024, false).unwrap();
    let mut store = Vmgs::format_new(disk.clone(), None).await.unwrap();
    store
        .write_file(FileId::TPM_NVRAM, b"source")
        .await
        .unwrap();
    store
        .write_file(FileId::BIOS_NVRAM, b"destination")
        .await
        .unwrap();
    assert!(matches!(
        store
            .move_file(FileId::TPM_NVRAM, FileId::BIOS_NVRAM, false)
            .await,
        Err(Error::OverwriteMove)
    ));
    for metadata in [FileId::FILE_TABLE, FileId::EXTENDED_FILE_TABLE] {
        assert!(matches!(
            store.delete_file(metadata).await,
            Err(Error::FileId)
        ));
        assert!(matches!(
            store.move_file(FileId::TPM_NVRAM, metadata, true).await,
            Err(Error::FileId)
        ));
        assert!(matches!(
            store.move_file(metadata, FileId::BIOS_NVRAM, true).await,
            Err(Error::FileId)
        ));
    }
    store.flush().await.unwrap();
    drop(store);

    let mut store = Vmgs::open(disk.clone(), None).await.unwrap();
    assert_eq!(store.read_file(FileId::TPM_NVRAM).await.unwrap(), b"source");
    assert_eq!(
        store.read_file(FileId::BIOS_NVRAM).await.unwrap(),
        b"destination"
    );
    store
        .move_file(FileId::TPM_NVRAM, FileId::BIOS_NVRAM, true)
        .await
        .unwrap();
    store.flush().await.unwrap();
    drop(store);

    let mut store = Vmgs::open(disk, None).await.unwrap();
    assert!(matches!(
        store.read_file(FileId::TPM_NVRAM).await,
        Err(Error::FileInfoNotAllocated(id)) if id == FileId::TPM_NVRAM
    ));
    assert_eq!(
        store.read_file(FileId::BIOS_NVRAM).await.unwrap(),
        b"source"
    );
}

// Test: Move an encrypted file over a plaintext destination, reopen and unlock,
//       then delete it and reopen once more.
// Expected: The moved payload stays encrypted and decryptable at its new ID;
//       deleting it persists without resurrecting either old file.
#[cfg(feature = "encryption")]
#[async_test]
async fn encrypted_move_and_delete_survive_reopen() {
    let disk = disklayer_ram::ram_disk(4 * 1024 * 1024, false).unwrap();
    let mut store = Vmgs::format_new(disk.clone(), None).await.unwrap();
    let key = [0x73; vmgs_format::VMGS_ENCRYPTION_KEY_SIZE];
    store
        .update_encryption_key(&key, crate::EncryptionAlgorithm::AES_GCM)
        .await
        .unwrap();
    let payload: Vec<u8> = (0..4357).map(|index| (index % 251) as u8).collect();
    store
        .write_file_encrypted(FileId::TPM_NVRAM, &payload)
        .await
        .unwrap();
    store
        .write_file(FileId::BIOS_NVRAM, b"old plaintext")
        .await
        .unwrap();
    store
        .move_file(FileId::TPM_NVRAM, FileId::BIOS_NVRAM, true)
        .await
        .unwrap();
    store.flush().await.unwrap();
    drop(store);

    let mut store = Vmgs::open(disk.clone(), None).await.unwrap();
    assert!(matches!(
        store.read_file(FileId::BIOS_NVRAM).await,
        Err(Error::NeedsUnlock)
    ));
    store.unlock_with_encryption_key(&key).await.unwrap();
    assert_eq!(store.read_file(FileId::BIOS_NVRAM).await.unwrap(), payload);
    assert!(matches!(
        store.write_file(FileId::BIOS_NVRAM, b"downgrade").await,
        Err(Error::OverwriteEncrypted)
    ));
    store.delete_file(FileId::BIOS_NVRAM).await.unwrap();
    store.flush().await.unwrap();
    drop(store);

    let mut store = Vmgs::open(disk, None).await.unwrap();
    store.unlock_with_encryption_key(&key).await.unwrap();
    for id in [FileId::TPM_NVRAM, FileId::BIOS_NVRAM] {
        assert!(matches!(
            store.read_file(id).await,
            Err(Error::FileInfoNotAllocated(missing)) if missing == id
        ));
    }
}
