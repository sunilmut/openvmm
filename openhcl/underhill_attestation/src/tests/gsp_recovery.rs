// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Resume an interrupted GSP-only rotation with either saved key active on disk.
// Expected: Saved seeds recover the correct keys, unlock VMGS and retain the saved egress protector.
#[async_test]
async fn interrupted_gsp_rotation_recovers_both_possible_disk_keys(driver: DefaultDriver) {
    // Independent SP800-108 known-answer vectors also used by crypto's KBKDF tests.
    let contexts = [
        hex::decode("2884186cfed2504110698b45d4807288df674c4826197a986988af960562f57f").unwrap(),
        hex::decode("d68a8d527c5ca59b195ae7456c3fef4d0eb0be16c78d77bd285aa1453e24eb3f").unwrap(),
    ];
    let expected: [[u8; 32]; 2] = [
        hex::decode("9db58bb70ca6cb6faae38174642176fa0ded28673076908383a01ad72ec3e23b")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("0ada5491d60992872fd71a157124823625b4b954c2f4eb470288427b1f8edf3d")
            .unwrap()
            .try_into()
            .unwrap(),
    ];
    for on_disk_key in expected {
        let mut vmgs = new_formatted_vmgs().await;
        let mut protector = KeyProtector::new_zeroed();
        let mut response = get_protocol::GuestStateProtectionResponse::new_zeroed();
        response.message_header =
            get_protocol::HeaderGeneric::new(get_protocol::HostRequests::GUEST_STATE_PROTECTION);
        response.encrypted_gsp.length = 32;
        response.encrypted_gsp.buffer[..32].fill(0x55);
        for (index, context) in contexts.iter().enumerate() {
            protector.gsp[index].gsp_length = 32;
            protector.gsp[index].gsp_buffer[..32].fill(0x81 + index as u8);
            response.decrypted_gsp[index].length = 32;
            response.decrypted_gsp[index].buffer[..32].copy_from_slice(context);
        }
        vmgs::write_key_protector(&protector, &mut vmgs)
            .await
            .unwrap();
        vmgs.test_add_new_encryption_key(&on_disk_key, EncryptionAlgorithm::AES_GCM)
            .await
            .unwrap();
        let get = guest_emulation_transport::test_utilities::new_transport_pair(
            driver.clone(),
            Some(vec![TestGetResponses::new(Event::Response(
                response.as_bytes().to_vec(),
            ))]),
            get_protocol::ProtocolVersion::NICKEL_REV2,
            None,
            None,
        )
        .await;
        let mut by_id = new_key_protector_by_id(None, None, false);
        let bios_guid = Guid::new_random();
        let result = get_derived_keys(
            &get.client,
            None,
            &mut vmgs,
            &mut protector,
            &mut by_id,
            bios_guid,
            &new_attestation_vm_config(),
            true,
            None,
            None,
            None,
            GuestStateEncryptionPolicy::GspKey,
            true,
            false,
            false,
        )
        .await
        .unwrap();
        let keys = result.derived_keys.as_ref().unwrap();
        assert_eq!(keys.ingress, expected[0]);
        assert_eq!(keys.decrypt_egress, Some(expected[1]));
        assert_eq!(keys.encrypt_egress, expected[1]);

        // Exercise actual disk unlock and persistence, not just the derived-key result.
        unlock_vmgs_data_store(
            &mut vmgs,
            true,
            &mut protector,
            &mut by_id,
            result.hardware_key_protector,
            result.derived_keys,
            result.key_protector_settings,
            bios_guid,
        )
        .await
        .unwrap();
        assert_eq!(vmgs.active_encryption_key().unwrap(), &expected[1]);
        let persisted = vmgs::read_key_protector(&mut vmgs, size_of::<KeyProtector>())
            .await
            .unwrap();
        assert_eq!(persisted.gsp[1].gsp_length, 32);
        assert_eq!(&persisted.gsp[1].gsp_buffer[..32], &[0x82; 32]);
    }
}
