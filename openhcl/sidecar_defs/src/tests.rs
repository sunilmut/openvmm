// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::CommandPage;
use super::GetSetVpRegisterRequest;
use super::SidecarCommand;
use super::required_memory;
use hvdef::HvStatus;
use test_with_tracing::test;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// Test: Decode independent command-page bytes at the client/kernel ABI offsets.
// Expected: Register context, intercept, error and request regions stay distinct,
//       and an unknown command value survives a byte-for-byte round trip.
#[test]
fn command_page_wire_regions_are_independent() {
    let mut wire = [0u8; 4096];
    wire[0..4].copy_from_slice(&0xfedc_ba98u32.to_le_bytes());
    wire[4] = 1;
    wire[16..24].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    wire[48..56].copy_from_slice(&0x8877_6655_4433_2211u64.to_le_bytes());
    wire[1040..1296].fill(0x35);
    wire[1296] = 255;
    wire[1297..1552].fill(0x47);
    wire[1552..2576].fill(0x59);
    wire[2576..4096].fill(0x6b);
    let mut command = CommandPage::read_from_bytes(&wire).unwrap();
    assert_eq!(command.command, SidecarCommand(0xfedc_ba98));
    assert_eq!(command.has_error, 1);
    assert_eq!(command.cpu_context.gps[0], 0x1122_3344_5566_7788);
    assert_eq!(command.cpu_context.gps[4], 0x8877_6655_4433_2211);
    assert_eq!(command.intercept_message.as_bytes(), &[0x35; 256]);
    assert_eq!(command.error.len, 255);
    assert_eq!(command.error.buf, [0x47; 255]);
    assert_eq!(command.request_data.as_bytes(), &[0x59; 1024]);
    assert_eq!(command.reserved.as_bytes(), &[0x6b; 1520]);
    assert_eq!(command.as_bytes(), &wire);

    command.command = SidecarCommand::SET_VP_REGISTERS;
    command.has_error = 0;
    wire[0..4].copy_from_slice(&3u32.to_le_bytes());
    wire[4] = 0;
    assert_eq!(command.as_bytes(), &wire);
}

// Test: Decode a maximum register-batch header and size multi-VP node memory.
// Expected: Count, VTL and full status do not overlap; the shared header leaves
//       room for the register records, and node sizing reserves every VP region.
#[test]
fn register_header_and_node_memory_contract() {
    let wire = [31, 0, 0x11, 0, 0xef, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let request = GetSetVpRegisterRequest::read_from_bytes(&wire).unwrap();
    assert_eq!(request.count, 31);
    assert_eq!(u8::from(request.target_vtl), 0x11);
    assert_eq!(request.status, HvStatus(0xbeef));
    assert_eq!(request.as_bytes(), &wire);
    assert_eq!(
        size_of::<GetSetVpRegisterRequest>()
            + usize::from(request.count) * size_of::<hvdef::hypercall::HvRegisterAssoc>(),
        1008,
        "the register batch must fit the 1024-byte request region"
    );
    for (vps, expected) in [(0, 4096), (1, 57_344), (2, 110_592), (400, 21_303_296)] {
        assert_eq!(required_memory(vps), expected, "{vps} VPs");
    }
}
