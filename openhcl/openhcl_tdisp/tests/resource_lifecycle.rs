// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public resource-validation lifecycle without firmware or inspection APIs.

use futures::executor::block_on;
use hvdef::Vtl;
use openhcl_tdisp::TdispResourceValidationInterface;
#[cfg(target_os = "linux")]
use openhcl_tdisp::new_resource_validator;
use openhcl_tdisp::noop::TdispNoopResourceValidator;
use openhcl_tdisp::noop::UnblockedMmioRange;
use test_with_tracing::test;
#[cfg(target_os = "linux")]
use virt::IsolationType;

fn unblock(validator: &dyn TdispResourceValidationInterface, range: &UnblockedMmioRange) {
    block_on(validator.tdisp_unblock_mmio(
        range.target_vtl,
        range.device_id,
        range.base_gpa,
        range.base_offset,
        range.length_in_bytes,
        range.range_id,
    ))
    .unwrap();
}

fn block(validator: &dyn TdispResourceValidationInterface, range: &UnblockedMmioRange) {
    block_on(validator.tdisp_block_mmio(
        range.target_vtl,
        range.device_id,
        range.base_gpa,
        range.base_offset,
        range.length_in_bytes,
        range.range_id,
    ))
    .unwrap();
}

// Test: Grant two BARs and DMA, revoke/reassign one BAR, then tear down both
//       mappings before revoking DMA.
// Expected: Selected BAR removal preserves other mappings and independent DMA
//       state; reassignment retains only the new exact address/offset/length.
#[test]
fn selected_bar_revocation_preserves_other_resources_and_reassignment_order() {
    let validator = TdispNoopResourceValidator::new();
    let first = UnblockedMmioRange {
        target_vtl: Vtl::Vtl0,
        device_id: 0xbeef,
        base_gpa: 0x1_0000_1000,
        base_offset: 0x1000,
        length_in_bytes: 0x2000,
        range_id: 5,
    };
    let second = UnblockedMmioRange {
        base_gpa: 0x2_0000_0000,
        base_offset: 0,
        length_in_bytes: 0x4000,
        range_id: 1,
        ..first.clone()
    };
    unblock(&validator, &first);
    unblock(&validator, &second);
    validator
        .tdisp_unblock_dma(first.target_vtl, first.device_id)
        .unwrap();
    assert_eq!(
        validator.unblocked_mmio_ranges(),
        [first.clone(), second.clone()]
    );
    block(&validator, &first);
    assert_eq!(
        validator.unblocked_mmio_ranges().as_slice(),
        std::slice::from_ref(&second)
    );
    assert!(validator.dma_unblocked());

    let reassigned = UnblockedMmioRange {
        base_gpa: 0x3_0000_0000,
        base_offset: 0x3000,
        length_in_bytes: 0x1000,
        ..first
    };
    unblock(&validator, &reassigned);
    assert_eq!(
        validator.unblocked_mmio_ranges(),
        [second.clone(), reassigned.clone()]
    );
    block(&validator, &second);
    block(&validator, &reassigned);
    assert!(validator.unblocked_mmio_ranges().is_empty());
    assert!(validator.dma_unblocked());
    validator
        .tdisp_block_dma(reassigned.target_vtl, reassigned.device_id)
        .unwrap();
    assert!(!validator.dma_unblocked());
}

// Test: Select validation for SNP/TDX with no VTOM, in real and explicitly
//       mocked environments.
// Expected: Real isolated validation fails before opening firmware devices;
//       mock mode succeeds but never invents a firmware-confirmed TDI state.
#[cfg(target_os = "linux")]
#[test]
fn confidential_validation_only_bypasses_missing_vtom_in_explicit_mock_mode() {
    for isolation in [IsolationType::Snp, IsolationType::Tdx] {
        let error = new_resource_validator(isolation, None, false)
            .err()
            .expect("real confidential validation requires VTOM");
        assert!(error.to_string().contains("requires a VTOM"), "{error:#}");

        let mocked = new_resource_validator(isolation, None, true).unwrap();
        mocked.on_pre_bind(Vtl::Vtl0, 0xbeef).unwrap();
        mocked.on_pre_start(Vtl::Vtl0, 0xbeef).unwrap();
        mocked.on_post_start(Vtl::Vtl0, 0xbeef).unwrap();
        assert_eq!(mocked.get_tsm_tdi_state(Vtl::Vtl0, 0xbeef).unwrap(), None);
    }
}
