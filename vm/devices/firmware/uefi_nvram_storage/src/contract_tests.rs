// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use in_memory::InMemoryNvram;
use pal_async::async_test;
use test_with_tracing::test;

async fn namespace_and_append_contract(store: &mut dyn NvramStorage) {
    let name = Ucs2LeVec::from("shared-λ".to_owned());
    let first = guid::guid!("01234567-89ab-cdef-0123-456789abcdef");
    let second = guid::guid!("12345678-9abc-def0-1234-56789abcdef0");
    let initial = EFI_TIME {
        year: 2025,
        month: 2,
        day: 3,
        ..Default::default()
    };
    let appended = EFI_TIME {
        second: 17,
        ..initial
    };
    assert!(store.is_empty().await.unwrap());
    assert!(
        !store
            .append_variable(&name, first, vec![1], initial)
            .await
            .unwrap()
    );
    assert!(!store.remove_variable(&name, first).await.unwrap());
    assert!(store.is_empty().await.unwrap());
    store
        .set_variable(&name, first, 0x8000_0042, vec![0x11, 0x00], initial)
        .await
        .unwrap();
    store
        .set_variable(&name, second, 0x1234, vec![0xff], initial)
        .await
        .unwrap();
    let (_, mut detached_data, _) = store.get_variable(&name, first).await.unwrap().unwrap();
    detached_data.fill(0xee);
    assert!(
        store
            .append_variable(&name, first, vec![0x80, 0x23], appended)
            .await
            .unwrap()
    );
    assert_eq!(
        store.get_variable(&name, first).await.unwrap(),
        Some((0x8000_0042, vec![0x11, 0x00, 0x80, 0x23], appended))
    );
    assert_eq!(
        store.get_variable(&name, second).await.unwrap(),
        Some((0x1234, vec![0xff], initial))
    );
    let mut keys = std::collections::BTreeSet::new();
    let mut cursor = None;
    loop {
        let next = store
            .next_variable(
                cursor
                    .as_ref()
                    .map(|(name, vendor): &(Ucs2LeVec, Guid)| (name.as_ref(), *vendor)),
            )
            .await
            .unwrap();
        match next {
            NextVariable::Exists {
                name: found_name,
                vendor,
                attr,
            } => {
                assert_eq!(found_name, name);
                assert!(keys.insert((vendor, attr)));
                cursor = Some((found_name, vendor));
            }
            NextVariable::EndOfList => break,
            NextVariable::InvalidKey => panic!("a returned variable key was rejected"),
        }
    }
    assert_eq!(keys, [(first, 0x8000_0042), (second, 0x1234)].into());
    assert!(store.remove_variable(&name, first).await.unwrap());
    assert!(store.get_variable(&name, first).await.unwrap().is_none());
    assert_eq!(
        store.get_variable(&name, second).await.unwrap(),
        Some((0x1234, vec![0xff], initial))
    );
    store
        .set_variable(&name, second, 0, Vec::new(), appended)
        .await
        .unwrap();
    assert_eq!(
        store.get_variable(&name, second).await.unwrap(),
        Some((0, Vec::new(), appended))
    );
    assert!(store.remove_variable(&name, second).await.unwrap());
    assert!(store.is_empty().await.unwrap());
}

// Test: Use a boxed NVRAM backend with identical names in distinct namespaces.
// Expected: Append preserves attributes, advances timestamps and cannot mutate
//       a namesake, while returned data is independent and deletion is scoped.
#[async_test]
async fn boxed_storage_preserves_namespaces_attributes_and_timestamps() {
    let mut store: Box<dyn NvramStorage> = Box::new(InMemoryNvram::new());
    namespace_and_append_contract(&mut store).await;
}

// Test: Save and restore a boxed VMM backend through its serialized public state.
// Expected: Delegated operations and restored bytes/metadata remain intact;
//       a serialized name without a UCS-2 terminator is rejected.
#[cfg(feature = "save_restore")]
#[async_test]
async fn boxed_vmm_storage_roundtrip_and_invalid_saved_name() {
    use vmcore::save_restore::SaveRestore;

    let mut store: Box<dyn VmmNvramStorage> = Box::new(InMemoryNvram::new());
    namespace_and_append_contract(&mut store).await;
    let name = Ucs2LeVec::from("saved-variable-λ".to_owned());
    let vendor = guid::guid!("89abcdef-0123-4567-89ab-cdef01234567");
    let timestamp = EFI_TIME {
        year: 2026,
        month: 11,
        day: 25,
        second: 39,
        ..Default::default()
    };
    store
        .set_variable(&name, vendor, 0x8123, vec![0x71, 0x00, 0xff], timestamp)
        .await
        .unwrap();
    let saved = mesh_protobuf::encode(store.save().unwrap());
    store.remove_variable(&name, vendor).await.unwrap();
    store
        .restore(mesh_protobuf::decode(&saved).unwrap())
        .unwrap();
    assert_eq!(
        store.get_variable(&name, vendor).await.unwrap(),
        Some((0x8123, vec![0x71, 0x00, 0xff], timestamp))
    );
    let name_bytes = name.clone().into_inner();
    let mut malformed = saved;
    let offset = malformed
        .windows(name_bytes.len())
        .position(|bytes| bytes == name_bytes)
        .unwrap();
    malformed[offset + name_bytes.len() - 2] = b'!';
    assert!(
        store
            .restore(mesh_protobuf::decode(&malformed).unwrap())
            .is_err()
    );
}
