// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::tpm20proto::*;
use test_with_tracing::test;

pub(super) fn auth() -> common::CmdAuth {
    common::CmdAuth::new(TPM20_RS_PW, 0, 1, 0)
}
pub(super) fn expected_command(code: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 2];
    bytes.extend_from_slice(&(10u32 + body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}
fn fixed_reply<Command: TpmCommand>(size: usize) {
    let mut wire = vec![0; size];
    wire[..2].copy_from_slice(&[0x80, 2]);
    wire[2..6].copy_from_slice(&(size as u32).to_be_bytes());
    for len in 0..size {
        assert!(matches!(
            Command::base_validate_reply(&wire[..len], SessionTagEnum::Sessions),
            Err(ResponseValidationError::ResponseSizeTooSmall)
        ));
    }
    let (reply, success) = Command::base_validate_reply(&wire, SessionTagEnum::Sessions).unwrap();
    assert!(success);
    assert_eq!(reply.as_bytes(), wire);
    wire[1] = 1;
    assert!(matches!(
        Command::base_validate_reply(&wire, SessionTagEnum::Sessions),
        Err(ResponseValidationError::HeaderSessionTagMismatch {
            command_succeeded: true,
            ..
        })
    ));
    wire[1] = 2;
    wire[5] = (size - 1) as u8;
    assert!(matches!(
        Command::base_validate_reply(&wire, SessionTagEnum::Sessions),
        Err(ResponseValidationError::HeaderResponseSizeMismatch {
            command_succeeded: true,
            ..
        })
    ));
}

// Test: Serialize startup/self-test/clear/change-seed/NV-undefine commands and validate their complete fixed replies plus every truncation.
// Expected: Opcode, hierarchy, authorization bytes and boolean/startup parameters are exact, and fixed reply validation rejects short, wrong-tag and undersized-success headers.
#[test]
fn fixed_commands_and_replies_match_wire_contracts() {
    let common = [0x40, 0, 0, 1, 0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0];
    for flag in [false, true] {
        let mut body = common.to_vec();
        body.push(u8::from(flag));
        assert_eq!(
            ClearControlCmd::new(
                SessionTagEnum::Sessions.into(),
                TPM20_RH_OWNER,
                auth(),
                flag
            )
            .as_bytes(),
            expected_command(0x127, &body)
        );
        assert_eq!(
            SelfTestCmd::new(SessionTagEnum::Sessions.into(), flag).as_bytes(),
            expected_command(0x143, &[u8::from(flag)])
        );
    }
    for (startup, value) in [(StartupType::Clear, 0), (StartupType::State, 1)] {
        assert_eq!(
            StartupCmd::new(SessionTagEnum::Sessions.into(), startup).as_bytes(),
            expected_command(0x144, &[0, value])
        );
    }
    assert_eq!(
        ClearCmd::new(SessionTagEnum::Sessions.into(), TPM20_RH_OWNER, auth()).as_bytes(),
        expected_command(0x126, &common)
    );
    for code in [CommandCodeEnum::ChangeEPS, CommandCodeEnum::ChangePPS] {
        assert_eq!(
            ChangeSeedCmd::new(
                SessionTagEnum::Sessions.into(),
                TPM20_RH_OWNER,
                auth(),
                code
            )
            .as_bytes(),
            expected_command(code as u32, &common)
        );
    }
    let mut body = common[..4].to_vec();
    body.extend_from_slice(&[1, 0x40, 0, 2]);
    body.extend_from_slice(&common[4..]);
    assert_eq!(
        NvUndefineSpaceCmd::new(
            SessionTagEnum::Sessions.into(),
            TPM20_RH_OWNER,
            auth(),
            0x01400002
        )
        .as_bytes(),
        expected_command(0x122, &body)
    );
    fixed_reply::<ClearControlCmd>(19);
    fixed_reply::<ClearCmd>(19);
    fixed_reply::<StartupCmd>(10);
    fixed_reply::<SelfTestCmd>(10);
    fixed_reply::<ChangeSeedCmd>(19);
    fixed_reply::<NvUndefineSpaceCmd>(10);
    fixed_reply::<NvDefineSpaceCmd>(10);
    fixed_reply::<NvWriteCmd>(10);
    fixed_reply::<PcrAllocateCmd>(32);
}

// Test: Encode/decode PCR banks with every bitmap length, list counts zero through five, over-limit lists and truncated list elements.
// Expected: Bank IDs/bitmaps/counts are preserved without padding leakage; invalid counts/bitmap sizes and incomplete encodings fail, and allocation commands contain exactly the requested selection list.
#[test]
fn pcr_selection_lists_enforce_limits_and_preserve_wire_data() {
    let selections: Vec<_> = (0..5)
        .map(|index| PcrSelection {
            hash: AlgIdEnum::SHA256.into(),
            size_of_select: index % 4,
            bitmap: [0x81, 0x42, 0x24],
        })
        .collect();
    for selection in &selections {
        let mut expected = vec![0, 11, selection.size_of_select];
        expected.extend_from_slice(&[0x81, 0x42, 0x24][..selection.size_of_select as usize]);
        assert_eq!(selection.serialize(), expected);
        assert_eq!(selection.payload_size(), expected.len());
        let parsed = PcrSelection::deserialize(&expected).unwrap();
        assert_eq!(parsed.serialize(), expected);
        assert!(
            parsed.bitmap[parsed.size_of_select as usize..]
                .iter()
                .all(|byte| *byte == 0)
        );
        for len in 0..expected.len() {
            assert!(PcrSelection::deserialize(&expected[..len]).is_none());
        }
    }
    assert!(PcrSelection::deserialize(&[0, 11, 4, 0, 0, 0, 0]).is_none());
    for count in 0..=5 {
        let list = TpmlPcrSelection::new(&selections[..count]).unwrap();
        let mut expected = (count as u32).to_be_bytes().to_vec();
        for selection in &selections[..count] {
            expected.extend_from_slice(&selection.serialize());
        }
        assert_eq!(list.serialize(), expected);
        assert_eq!(list.payload_size(), expected.len());
        assert_eq!(
            TpmlPcrSelection::deserialize(&expected)
                .unwrap()
                .serialize(),
            expected
        );
        for len in 0..expected.len() {
            assert!(TpmlPcrSelection::deserialize(&expected[..len]).is_none());
        }
        let command = PcrAllocateCmd::new(
            SessionTagEnum::Sessions.into(),
            TPM20_RH_OWNER,
            auth(),
            &selections[..count],
        )
        .unwrap();
        let mut body = vec![0x40, 0, 0, 1, 0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0];
        body.extend_from_slice(&expected);
        assert_eq!(command.serialize(), expected_command(0x12b, &body));
        assert_eq!(command.payload_size(), 10 + body.len());
    }
    let too_many = [selections[0]; 6];
    assert!(matches!(
        TpmlPcrSelection::new(&too_many),
        Err(InvalidInput::PcrSelectionsLengthTooLong(6, 5))
    ));
    assert!(matches!(
        PcrAllocateCmd::new(
            SessionTagEnum::Sessions.into(),
            TPM20_RH_OWNER,
            auth(),
            &too_many
        ),
        Err(TpmProtoError::PcrAllocatePcrAllocation(
            InvalidInput::PcrSelectionsLengthTooLong(6, 5)
        ))
    ));
    assert!(TpmlPcrSelection::deserialize(&[0, 0, 0, 6]).is_none());
}
