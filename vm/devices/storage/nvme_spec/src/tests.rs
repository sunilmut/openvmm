// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Decode command queue bytes with mixed-width fields and standard/vendor opcodes.
// Expected: IDs, addresses and command words survive re-encoding, and transfer
//       directions distinguish no-data, host-write, host-read and bidirectional commands.
#[test]
fn command_wire_identity_and_transfer_direction() {
    let mut bytes = [0; 64];
    bytes[2..8].copy_from_slice(&[0x34, 0x12, 0xef, 0xcd, 0xab, 0x89]);
    bytes[16..24].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&0xfedc_ba98_7654_3210_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&0x1234_5678_9abc_def0_u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&[0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76]);
    bytes[48..52].copy_from_slice(&[0xff, 0xff, 0, 0xc0]);
    for (opcode, from_host, to_host) in [
        (0x00, false, false), // Flush.
        (0x01, true, false),  // Write.
        (0x02, false, true),  // Read.
        (0x09, true, false),  // Dataset management.
        (0x81, true, false),  // Security send.
        (0x82, false, true),  // Security receive.
        (0xc3, true, true),   // Vendor-specific bidirectional command.
    ] {
        bytes[0] = opcode;
        let command = Command::read_from_bytes(&bytes).unwrap();
        assert_eq!(command.cdw0.cid(), 0x1234);
        assert_eq!(command.nsid, 0x89ab_cdef);
        assert_eq!(command.mptr, 0x0123_4567_89ab_cdef);
        assert_eq!(command.dptr, [0xfedc_ba98_7654_3210, 0x1234_5678_9abc_def0]);
        assert_eq!((command.cdw10, command.cdw11), (0xfedc_ba98, 0x7654_3210));
        let rw = nvm::Cdw12ReadWrite::from(command.cdw12);
        assert_eq!(rw.nlb_z(), 0xffff);
        assert!(rw.fua() && rw.lr());
        let direction = Opcode(command.cdw0.opcode());
        assert_eq!(direction.transfer_host_to_controller(), from_host);
        assert_eq!(direction.transfer_controller_to_host(), to_host);
        assert_eq!(command.as_bytes(), &bytes);
    }
}

// Test: Receive completions with independent phase/retry flags and known or unknown status types.
// Expected: Queue identities and status code/type remain distinct from the flags,
//       and unknown statuses preserve their exact wire representation.
#[test]
fn completion_wire_status_is_independent_of_flags() {
    for (wire_status, phase, code, kind, crd, more, dnr) in [
        (0x0001_u16, true, 0x00, 0, 0, false, false),
        (0xd503, true, 0x81, 2, 1, true, true),
        (0x7eaa, false, 0x55, 7, 3, true, false),
        (0x8d54, false, 0xaa, 6, 0, false, true),
    ] {
        let mut bytes = [
            0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0,
            0,
        ];
        bytes[14..].copy_from_slice(&wire_status.to_le_bytes());
        let completion = Completion::read_from_bytes(&bytes).unwrap();
        assert_eq!(
            (completion.sqhd, completion.sqid, completion.cid),
            (0x4321, 0x8765, 0xcba9)
        );
        assert_eq!((completion.dw0, completion.dw1), (0x1234_5678, 0x89ab_cdef));
        let status = Status(completion.status.status());
        assert_eq!(status.status_code(), code);
        assert_eq!(status.status_code_type(), StatusCodeType(kind));
        assert_eq!(completion.status.phase(), phase);
        assert_eq!(completion.status.crd(), crd);
        assert_eq!(completion.status.more(), more);
        assert_eq!(completion.status.dnr(), dnr);
        assert_eq!(completion.as_bytes(), &bytes);
    }
}

// Test: Decode a device-interface report with distinct controller fields and hash bytes.
// Expected: Reported TI fields retain their specified bit positions, while
//       queue registers and the complete SHA-384 digest remain intact.
#[test]
fn tdisp_report_wire_fields_do_not_overlap() {
    let mut bytes = [0; 128];
    bytes[..12].copy_from_slice(&[
        0x65, 0x4d, 0x56, 0x4e, 0x01, 0x5b, 0x43, 0x06, 0x9a, 0xbc, 0, 0,
    ]);
    bytes[12..16].copy_from_slice(&0x0123_0456_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&[0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89]);
    bytes[36..84].copy_from_slice(&[0xa5; 48]);
    let report = tdisp::NvmeTdispInfo::read_from_bytes(&bytes).unwrap();
    let ti = report.tdisp_information();
    assert_eq!(ti.ver(), 1);
    assert!(ti.acps() && ti.env() && ti.stv());
    assert_eq!((ti.shnv(), ti.shstv()), (2, 1));
    assert_eq!(
        (ti.cssv(), ti.mpsv(), ti.iosqesv(), ti.iocqesv()),
        (3, 4, 6, 0)
    );
    assert_eq!((report.cu, report.vu), (0x9a, 0xbc));
    assert_eq!(
        (report.aqa, report.asq, report.acq),
        (0x0123_0456, 0x1234_5678, 0x89ab_cdef)
    );
    assert_eq!(report.queue_hash, [0xa5; 48]);
    assert_eq!(report.as_bytes(), &bytes);
}
