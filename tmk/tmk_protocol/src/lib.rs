// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Definitions for the protocol between `tmk_vmm` and the test microkernel.

#![no_std]
#![forbid(unsafe_code)]

use bitfield_struct::bitfield;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

/// Start input from the VMM to the TMK.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct StartInput {
    /// The address to write commands to.
    pub command: u64,
    /// The test index.
    pub test_index: u64,
}

/// Test metadata flags.
#[bitfield(u64)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct TestFlags64 {
    #[bits(1)]
    pub expected_failure: bool,
    #[bits(1)]
    pub linux_only: bool,
    #[bits(62)]
    reserved: u64,
}

/// A 64-bit TMK test descriptor.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable)]
pub struct TestDescriptor64 {
    /// The address of the test's name.
    pub name: u64,
    /// The length of the test's name.
    pub name_len: u64,
    /// The test entry point.
    pub entrypoint: u64,
    /// Test metadata flags.
    pub flags: TestFlags64,
}

/// TMK command.
#[repr(u32)]
#[derive(TryFromBytes)]
pub enum Command {
    /// Log a UTF-8 message string.
    Log(StrDescriptor),
    /// The test panicked.
    Panic {
        /// The panic message.
        message: StrDescriptor,
        /// The file and line where the panic occurred.
        filename: StrDescriptor,
        /// The line where the panic occurred.
        line: u32,
    },
    /// Complete the test.
    Complete {
        /// Success status of the test.
        success: bool,
    },
}

/// A UTF-8 string in guest memory.
#[repr(C)]
#[derive(FromBytes)]
pub struct StrDescriptor {
    /// Pointer to the string.
    pub gpa: u64,
    /// Length of the string.
    pub len: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Decode the command frames written by the TMK and read by its VMM.
    // Expected: Each tag selects its payload at the established ABI offsets;
    //       wide guest addresses and both completion outcomes are preserved.
    #[test]
    fn command_frames_decode_at_wire_offsets() {
        let mut bytes = [0u8; 48];
        bytes[8..16].copy_from_slice(&0xfedc_ba98_7654_3210u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&37u64.to_ne_bytes());
        let Command::Log(message) = Command::try_read_from_bytes(&bytes).unwrap() else {
            panic!("log command expected");
        };
        assert_eq!(message.gpa, 0xfedc_ba98_7654_3210);
        assert_eq!(message.len, 37);

        bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
        bytes[24..32].copy_from_slice(&0x1234_5678_9abc_def0u64.to_ne_bytes());
        bytes[32..40].copy_from_slice(&19u64.to_ne_bytes());
        bytes[40..44].copy_from_slice(&1234u32.to_ne_bytes());
        let Command::Panic {
            message,
            filename,
            line,
        } = Command::try_read_from_bytes(&bytes).unwrap()
        else {
            panic!("panic command expected");
        };
        assert_eq!((message.gpa, message.len), (0xfedc_ba98_7654_3210, 37));
        assert_eq!((filename.gpa, filename.len), (0x1234_5678_9abc_def0, 19));
        assert_eq!(line, 1234);

        bytes[..4].copy_from_slice(&2u32.to_ne_bytes());
        for status in [0, 1] {
            bytes[4] = status;
            let Command::Complete { success } = Command::try_read_from_bytes(&bytes).unwrap()
            else {
                panic!("completion command expected");
            };
            assert_eq!(success, status == 1);
        }
    }

    // Test: Validate guest command tags, completion booleans and frame lengths.
    // Expected: Invalid active payloads are rejected; padding and bytes of
    //       inactive variants do not invalidate a legitimate log command.
    #[test]
    fn malformed_commands_are_rejected_without_validating_inactive_payloads() {
        let mut bytes = [0xffu8; 48];
        for tag in [3u32, u32::MAX] {
            bytes[..4].copy_from_slice(&tag.to_ne_bytes());
            assert!(Command::try_read_from_bytes(&bytes).is_err());
        }
        bytes[..4].copy_from_slice(&2u32.to_ne_bytes());
        for status in [2, 128, 255] {
            bytes[4] = status;
            assert!(Command::try_read_from_bytes(&bytes).is_err());
        }
        bytes[..4].copy_from_slice(&0u32.to_ne_bytes());
        assert!(matches!(
            Command::try_read_from_bytes(&bytes),
            Ok(Command::Log(_))
        ));
        for len in 0..bytes.len() {
            assert!(Command::try_read_from_bytes(&bytes[..len]).is_err());
        }
    }

    // Test: Transport boot input and test metadata as the loader's binary data.
    // Expected: Field order/width and descriptor stride are stable, and known
    //       flags can be changed without losing reserved metadata bits.
    #[test]
    fn loader_metadata_preserves_fields_and_reserved_flags() {
        let input = StartInput {
            command: 0x1122_3344_5566_7788,
            test_index: u64::MAX,
        };
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_ne_bytes());
        expected[8..].copy_from_slice(&u64::MAX.to_ne_bytes());
        assert_eq!(input.as_bytes(), expected);

        let mut bytes = [0u8; 64];
        for (i, value) in [0x1234u64, 7, 0x5678, u64::MAX, 0x9abc, 11, 0xdef0, 2]
            .into_iter()
            .enumerate()
        {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&value.to_ne_bytes());
        }
        let [first, second] = <[TestDescriptor64; 2]>::read_from_bytes(&bytes).unwrap();
        assert_eq!(
            (first.name, first.name_len, first.entrypoint),
            (0x1234, 7, 0x5678)
        );
        assert!(first.flags.expected_failure() && first.flags.linux_only());
        assert_eq!(
            u64::from(first.flags.with_expected_failure(false)),
            u64::MAX - 1
        );
        assert_eq!(
            (second.name, second.name_len, second.entrypoint),
            (0x9abc, 11, 0xdef0)
        );
        assert!(!second.flags.expected_failure() && second.flags.linux_only());
    }
}
