// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;
use zerocopy::FromZeros;

struct Stub<F>(F);

impl<F: FnMut(TdcallInput) -> TdcallOutput> Tdcall for Stub<F> {
    fn tdcall(&mut self, input: TdcallInput) -> TdcallOutput {
        self.0(input)
    }
}

fn output(code: TdCallResultCode) -> TdcallOutput {
    TdcallOutput {
        rax: TdCallResult::new().with_code(code).with_details(0x1234),
        rcx: 0,
        rdx: 0,
        r8: 0,
        r10: 0,
        r11: 0,
    }
}

fn registers(input: &TdcallInput) -> [u64; 10] {
    [
        input.rcx, input.rdx, input.r8, input.r9, input.r10, input.r11, input.r12, input.r13,
        input.r14, input.r15,
    ]
}

// Test: Forward hypercalls through the TDX register ABI.
// Expected: Control and buffer addresses reach the host unchanged and the full
//       hypercall result comes back from R11, not the module status register.
#[test]
fn hypercall_marshalling_preserves_control_buffers_and_result() {
    let mut call = Stub(|input: TdcallInput| {
        assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
        assert_eq!(
            registers(&input),
            [0xd04, 0x1234_5000, 0xabcd_6000, 0, 0x3456, 0, 0, 0, 0, 0]
        );
        let mut reply = output(TdCallResultCode::SUCCESS);
        reply.r11 = 0x0042_0000_0000_0005;
        reply
    });
    let result = tdcall_hypercall(
        &mut call,
        hvdef::hypercall::Control::from(0x3456),
        0x1234_5000,
        0xabcd_6000,
    );
    assert_eq!(u64::from(result), 0x0042_0000_0000_0005);
}

// Test: Read and write MSRs through a successful or rejected host VMCALL.
// Expected: Index/value registers and register masks match the ABI; host errors
//       are returned without being confused with the TDX module result.
#[test]
fn msr_access_marshals_values_and_propagates_host_errors() {
    for status in [
        TdVmCallR10Result::SUCCESS,
        TdVmCallR10Result::OPERAND_INVALID,
    ] {
        let mut read = Stub(|input: TdcallInput| {
            assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
            assert_eq!(
                registers(&input),
                [
                    0x1c00,
                    0,
                    0,
                    0,
                    0,
                    TdVmCallSubFunction::RdMsr as u64,
                    0xc000_0080,
                    0,
                    0,
                    0
                ]
            );
            let mut reply = output(TdCallResultCode::SUCCESS);
            reply.r10 = status.0;
            reply.r11 = 0xfedc_ba98_7654_3210;
            reply
        });
        let mut value = 0;
        let result = tdcall_rdmsr(&mut read, 0xc000_0080, &mut value);
        assert_eq!(
            result,
            if status == TdVmCallR10Result::SUCCESS {
                Ok(())
            } else {
                Err(status)
            }
        );
        assert_eq!(value, 0xfedc_ba98_7654_3210);
        let mut write = Stub(|input: TdcallInput| {
            assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
            assert_eq!(
                registers(&input),
                [
                    0x3c00,
                    0,
                    0,
                    0,
                    0,
                    TdVmCallSubFunction::WrMsr as u64,
                    0xc000_0080,
                    value,
                    0,
                    0
                ]
            );
            let mut reply = output(TdCallResultCode::SUCCESS);
            reply.r10 = status.0;
            reply
        });
        assert_eq!(tdcall_wrmsr(&mut write, 0xc000_0080, value), result);
    }
}

// Test: Perform byte, word and dword port IO with both host success and failure.
// Expected: Direction, size, port and write data reach the host; reads use the
//       low 32 result bits and both directions preserve host errors.
#[test]
fn port_io_marshals_width_direction_and_result() {
    for size in [1, 2, 4] {
        for status in [TdVmCallR10Result::SUCCESS, TdVmCallR10Result::ALIGN_ERROR] {
            for write in [false, true] {
                let mut call = Stub(|input: TdcallInput| {
                    assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
                    assert_eq!(
                        registers(&input),
                        [
                            0xff00,
                            0,
                            0,
                            0,
                            0,
                            30,
                            size.into(),
                            write.into(),
                            0x3f8,
                            if write { 0x1234_abcd } else { 0 }
                        ]
                    );
                    let mut reply = output(TdCallResultCode::SUCCESS);
                    reply.r10 = status.0;
                    reply.r11 = 0xffff_ffff_1234_abcd;
                    reply
                });
                let result = if write {
                    tdcall_io_out(&mut call, 0x3f8, 0x1234_abcd, size).map(|()| 0x1234_abcd)
                } else {
                    tdcall_io_in(&mut call, 0x3f8, size)
                };
                assert_eq!(
                    result,
                    if status == TdVmCallR10Result::SUCCESS {
                        Ok(0x1234_abcd)
                    } else {
                        Err(status)
                    }
                );
            }
        }
    }
}

// Test: Access VP, VM and global metadata with successful and failed module results.
// Expected: Read/write operands reach their leaf-specific registers, the old
//       value is returned on success, and failure retains result detail bits.
#[test]
fn metadata_calls_preserve_operands_values_and_detailed_errors() {
    for code in [TdCallResultCode::SUCCESS, TdCallResultCode::OPERAND_INVALID] {
        for leaf in [
            TdCallLeaf::VP_RD,
            TdCallLeaf::VP_WR,
            TdCallLeaf::VM_RD,
            TdCallLeaf::VM_WR,
            TdCallLeaf::SYS_RD,
        ] {
            let write = leaf == TdCallLeaf::VP_WR || leaf == TdCallLeaf::VM_WR;
            let mut call = Stub(|input: TdcallInput| {
                assert_eq!(input.leaf, leaf);
                assert_eq!(
                    registers(&input),
                    [
                        0,
                        0x1234,
                        if write { 0xabcd } else { 0 },
                        if write { 0xff00 } else { 0 },
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ]
                );
                let mut reply = output(code);
                reply.r8 = 0xfedc_ba98;
                reply
            });
            let field = TdxExtendedFieldCode::from(0x1234);
            let result = match leaf {
                TdCallLeaf::VP_RD => tdcall_vp_rd(&mut call, field),
                TdCallLeaf::VP_WR => tdcall_vp_wr(&mut call, field, 0xabcd, 0xff00),
                TdCallLeaf::VM_RD => tdcall_vm_rd(&mut call, field),
                TdCallLeaf::VM_WR => tdcall_vm_wr(&mut call, field, 0xabcd, 0xff00),
                TdCallLeaf::SYS_RD => tdcall_sys_rd(&mut call, 0x1234),
                _ => unreachable!(),
            };
            if code == TdCallResultCode::SUCCESS {
                assert_eq!(result.unwrap(), 0xfedc_ba98);
            } else {
                assert_eq!(u64::from(result.unwrap_err()), u64::from(output(code).rax));
            }
        }
    }
}

// Test: Request translation invalidation and an aligned attestation report.
// Expected: Both calls marshal their input buffers/flags correctly and preserve
//       complete module failure information.
#[test]
fn invalidation_and_report_calls_preserve_inputs_and_errors() {
    for code in [TdCallResultCode::SUCCESS, TdCallResultCode::OPERAND_INVALID] {
        let mut invalidation = Stub(|input: TdcallInput| {
            assert_eq!(input.leaf, TdCallLeaf::VP_INVGLA);
            assert_eq!(registers(&input), [1, 0x1234_5000, 0, 0, 0, 0, 0, 0, 0, 0]);
            output(code)
        });
        let result = tdcall_vp_invgla(
            &mut invalidation,
            TdGlaVmAndFlags::from(1),
            TdxGlaListInfo::from(0x1234_5000),
        );
        assert_eq!(result.is_ok(), code == TdCallResultCode::SUCCESS);
        let mut report = TdReport::new_zeroed();
        let address = core::ptr::from_mut(&mut report) as u64;
        let mut call = Stub(|input: TdcallInput| {
            assert_eq!(input.leaf, TdCallLeaf::MR_REPORT);
            assert_eq!(input.rcx, address);
            assert_ne!(input.r12, 0);
            assert_eq!(input.r12 % 64, 0);
            let mut regs = registers(&input);
            regs[0] = 0;
            regs[6] = 0;
            assert_eq!(regs, [0; 10]);
            output(code)
        });
        let result = tdcall_mr_report(&mut call, &mut report);
        if code == TdCallResultCode::SUCCESS {
            result.unwrap();
        } else {
            assert_eq!(u64::from(result.unwrap_err()), u64::from(output(code).rax));
        }
    }
}

// Test: Map visibility for a range whose host request needs partial-progress retry.
// Expected: Shared/private visibility is encoded in the GPA, retries resume at
//       the returned address, and empty ranges issue no host calls.
#[test]
fn visibility_changes_resume_after_partial_progress() {
    for shared in [false, true] {
        let bit = TDX_SHARED_GPA_BOUNDARY_ADDRESS_BIT;
        let start = 0x4000 | if shared { bit } else { 0 };
        let mut calls = 0;
        let mut call = Stub(|input: TdcallInput| {
            calls += 1;
            assert!(calls <= 2);
            assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
            assert_eq!(
                registers(&input),
                [
                    0x3c00,
                    0,
                    0,
                    0,
                    0,
                    TdVmCallSubFunction::MapGpa as u64,
                    start + if calls == 1 { 0 } else { 0x1000 },
                    if calls == 1 { 0x4000 } else { 0x3000 },
                    0,
                    0
                ]
            );
            let mut reply = output(TdCallResultCode::SUCCESS);
            if calls == 1 {
                reply.r10 = TdVmCallR10Result::RETRY.0;
                reply.r11 = start + 0x1000;
            }
            reply
        });
        tdcall_map_gpa(
            &mut call,
            MemoryRange::new((0x4000 | bit)..(0x8000 | bit)),
            shared,
        )
        .unwrap();
        tdcall_map_gpa(&mut call, MemoryRange::new(0..0), shared).unwrap();
        assert_eq!(calls, 2);
    }
    let mut call = Stub(|_| {
        let mut reply = output(TdCallResultCode::SUCCESS);
        reply.r10 = TdVmCallR10Result::GPA_INUSE.0;
        reply
    });
    assert_eq!(
        tdcall_map_gpa(&mut call, MemoryRange::new(0..0x1000), false),
        Err(TdVmCallR10Result::GPA_INUSE)
    );
}

// Test: Release pages with every documented module error classification.
// Expected: Structured errors retain page-state and size metadata; successful
//       calls use the requested GPA and page level without unrelated operands.
#[test]
fn page_release_returns_structured_error_information() {
    for code in [
        TdCallResultCode::SUCCESS,
        TdCallResultCode::EPT_ENTRY_FREE,
        TdCallResultCode::EPT_ENTRY_STATE_INCORRECT,
        TdCallResultCode::PAGE_SIZE_MISMATCH,
        TdCallResultCode::OPERAND_INVALID,
        TdCallResultCode::OPERAND_BUSY,
        TdCallResultCode::PAGE_ALREADY_ACCEPTED,
    ] {
        let mut call = Stub(|input: TdcallInput| {
            assert_eq!(input.leaf, TdCallLeaf::MEM_PAGE_RELEASE);
            assert_eq!(registers(&input), [0x200001, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let mut reply = output(code);
            reply.rcx = TdgMemPageReleaseRcxResult::new()
                .with_pending(true)
                .with_mmio(true)
                .with_level(TdgMemPageLevel::Size4k)
                .into();
            reply
        });
        let result = tdcall_release_page(&mut call, 0x200, true);
        match code {
            TdCallResultCode::SUCCESS => result.unwrap(),
            TdCallResultCode::EPT_ENTRY_FREE => {
                assert!(matches!(result, Err(TdgPageReleaseError::NotAllocated(c)) if c == code))
            }
            TdCallResultCode::EPT_ENTRY_STATE_INCORRECT => assert!(
                matches!(result, Err(TdgPageReleaseError::EntryStateInvalid { pending: true, mmio: true, result: c }) if c == code)
            ),
            TdCallResultCode::PAGE_SIZE_MISMATCH => assert!(
                matches!(result, Err(TdgPageReleaseError::PageSizeMismatch { expected_level: TdgMemPageLevel::Size4k, result: c }) if c == code)
            ),
            TdCallResultCode::OPERAND_INVALID => {
                assert!(matches!(result, Err(TdgPageReleaseError::Invalid(c)) if c == code))
            }
            TdCallResultCode::OPERAND_BUSY => {
                assert!(matches!(result, Err(TdgPageReleaseError::Busy(c)) if c == code))
            }
            _ => assert!(matches!(result, Err(TdgPageReleaseError::Unknown(c)) if c == code)),
        }
    }
}

// Test: Accept and release a mixed-size range with a rejected large-page attempt.
// Expected: A size mismatch retries the same GPA as small pages, then processing
//       covers the complete range without gaps or duplicate successful requests.
#[test]
fn page_ranges_fall_back_locally_from_large_to_small_pages() {
    for release in [false, true] {
        let mut calls = 0;
        let mut next = 0x200000;
        let mut rejected = false;
        let mut call = Stub(|input: TdcallInput| {
            calls += 1;
            assert!(calls <= 1027);
            assert_eq!(
                input.leaf,
                if release {
                    TdCallLeaf::MEM_PAGE_RELEASE
                } else {
                    TdCallLeaf::MEM_PAGE_ACCEPT
                }
            );
            assert_eq!(input.rcx & !0xfff, next);
            let large = input.rcx & 1 != 0;
            let mut reply = output(TdCallResultCode::SUCCESS);
            if next == 0x200000 && large && !rejected {
                rejected = true;
                reply.rax = TdCallResult::new().with_code(TdCallResultCode::PAGE_SIZE_MISMATCH);
            } else {
                if large {
                    assert_eq!(next % 0x200000, 0);
                }
                next += if large { 0x200000 } else { 0x1000 };
            }
            reply
        });
        let range = MemoryRange::new(0x200000..0x601000);
        if release {
            release_pages(&mut call, range).unwrap();
        } else {
            accept_pages(&mut call, range, AcceptPagesAttributes::None).unwrap();
        }
        assert_eq!(next, 0x601000);
        assert!(rejected);
    }
}

// Test: Accept a range when the module rejects its first page.
// Expected: Busy, invalid and unknown errors retain their category, and no
//       later page is accepted after the failed operation.
#[test]
fn page_accept_errors_stop_range_processing() {
    for code in [
        TdCallResultCode::OPERAND_BUSY,
        TdCallResultCode::OPERAND_INVALID,
        TdCallResultCode::EPT_ENTRY_FREE,
    ] {
        let mut calls = 0;
        let mut call = Stub(|input: TdcallInput| {
            calls += 1;
            assert_eq!(input.rcx, 0x1000);
            output(code)
        });
        let result = accept_pages(
            &mut call,
            MemoryRange::new(0x1000..0x3000),
            AcceptPagesAttributes::None,
        );
        match code {
            TdCallResultCode::OPERAND_BUSY => {
                assert!(matches!(result, Err(AcceptPagesError::Busy(c)) if c == code))
            }
            TdCallResultCode::OPERAND_INVALID => {
                assert!(matches!(result, Err(AcceptPagesError::Invalid(c)) if c == code))
            }
            _ => assert!(matches!(result, Err(AcceptPagesError::Unknown(c)) if c == code)),
        }
        assert_eq!(calls, 1);
    }
}

// Test: Set page attributes directly and while accepting newly private pages.
// Expected: Attribute operands and masks reach the module, readback matches the
//       accepted mapping, and attribute failures are returned to the caller.
#[test]
fn page_attributes_follow_acceptance_and_propagate_failures() {
    let attributes = TdgMemPageGpaAttr::from(0x800f_0000);
    let mask = TdgMemPageAttrWriteR8::from(0x000f_0000);
    for accept in [false, true] {
        for fail in [false, true] {
            let mut last_mapping = 0;
            let mut writes = 0;
            let mut call = Stub(|input: TdcallInput| {
                let mut reply = output(TdCallResultCode::SUCCESS);
                match input.leaf {
                    TdCallLeaf::MEM_PAGE_ACCEPT => assert!(accept),
                    TdCallLeaf::MEM_PAGE_ATTR_WR => {
                        writes += 1;
                        last_mapping = input.rcx;
                        assert_eq!(input.rdx, 0x800f_0000);
                        assert_eq!(input.r8, 0x000f_0000);
                        if fail {
                            reply.rax =
                                TdCallResult::new().with_code(TdCallResultCode::OPERAND_INVALID);
                        }
                    }
                    TdCallLeaf::MEM_PAGE_ATTR_RD => {
                        assert_eq!(input.rcx, last_mapping & !0xfff);
                        reply.rcx = last_mapping;
                        reply.rdx = 0x800f_0000;
                    }
                    _ => panic!("unexpected call: {input:?}"),
                }
                reply
            });
            let range = MemoryRange::new(0x200000..0x401000);
            if accept {
                let result = accept_pages(
                    &mut call,
                    range,
                    AcceptPagesAttributes::Set { attributes, mask },
                );
                if fail {
                    assert!(matches!(
                        result,
                        Err(AcceptPagesError::Attributes(
                            TdCallResultCode::OPERAND_INVALID
                        ))
                    ));
                } else {
                    result.unwrap();
                }
            } else {
                let result = set_page_attributes(&mut call, range, attributes, mask);
                assert_eq!(
                    result,
                    if fail {
                        Err(TdCallResultCode::OPERAND_INVALID)
                    } else {
                        Ok(())
                    }
                );
            }
            assert_eq!(writes, if fail { 1 } else { 2 });
        }
    }
}

// Test: Read page attributes when the module returns an operand error.
// Expected: The helper sends the requested GPA and returns the module error.
#[test]
fn page_attribute_read_surfaces_module_errors() {
    let mut call = Stub(|input: TdcallInput| {
        assert_eq!(input.leaf, TdCallLeaf::MEM_PAGE_ATTR_RD);
        assert_eq!(registers(&input), [0x9000, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        output(TdCallResultCode::OPERAND_INVALID)
    });
    assert!(matches!(
        tdcall_page_attr_rd(&mut call, 0x9000),
        Err(TdCallResultCode::OPERAND_INVALID)
    ));
}

// Test: Fail a visibility change after partial progress, then retry the range.
// Expected: The host error is returned unchanged and a fresh request starts
//       at the original GPA with the full length for either visibility.
#[test]
fn visibility_error_after_progress_allows_fresh_retry() {
    for shared in [false, true] {
        let start = 0x4000
            | if shared {
                TDX_SHARED_GPA_BOUNDARY_ADDRESS_BIT
            } else {
                0
            };
        let mut calls = 0;
        let mut call = Stub(|input: TdcallInput| {
            calls += 1;
            assert!(calls <= 3);
            assert_eq!(input.leaf, TdCallLeaf::VP_VMCALL);
            assert_eq!(input.r11, TdVmCallSubFunction::MapGpa as u64);
            assert_eq!(input.r12, start + if calls == 2 { 0x1000 } else { 0 });
            assert_eq!(input.r13, if calls == 2 { 0x3000 } else { 0x4000 });
            let mut reply = output(TdCallResultCode::SUCCESS);
            if calls == 1 {
                reply.r10 = TdVmCallR10Result::RETRY.0;
                reply.r11 = start + 0x1000;
            } else if calls == 2 {
                reply.r10 = TdVmCallR10Result::OPERAND_INVALID.0;
            }
            reply
        });
        assert_eq!(
            tdcall_map_gpa(&mut call, MemoryRange::new(0x4000..0x8000), shared),
            Err(TdVmCallR10Result::OPERAND_INVALID)
        );
        tdcall_map_gpa(&mut call, MemoryRange::new(0x4000..0x8000), shared).unwrap();
        assert_eq!(calls, 3);
    }
}

// IGNORED: An out-of-range retry GPA terminates the loop and returns success
//       even though the host did not report a successful visibility change.
//
// Test: Return a retry GPA at or beyond the requested visibility range's end.
// Expected: The helper rejects invalid progress instead of reporting success.
#[test]
#[ignore = "MapGPA accepts an out-of-range retry GPA as successful completion"]
fn visibility_retry_past_end_returns_an_error() {
    for shared in [false, true] {
        for invalid_offset in [0x4000, 0x5000] {
            let mut call = Stub(|input: TdcallInput| {
                let mut reply = output(TdCallResultCode::SUCCESS);
                reply.r10 = TdVmCallR10Result::RETRY.0;
                reply.r11 = input.r12 + invalid_offset;
                reply
            });
            assert!(
                tdcall_map_gpa(&mut call, MemoryRange::new(0x4000..0x8000), shared).is_err(),
                "invalid retry offset {invalid_offset:#x}, shared={shared}"
            );
        }
    }
}
