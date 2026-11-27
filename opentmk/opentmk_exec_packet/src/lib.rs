// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
#![no_std]
//! This contains the packet API library used for communication between a UM agent
//! and opentmk components.
//!
//! In general, a communication channel between the agent and opentmk works first by
//! establishing a three-way-handshake (SYN, SYN-ACK, ACK) which is entirely just a magic number
//! being exchanged between the two parties. Currently we assume that the agent would start the
//! communication.
//!
//! Then after that, packets of type [`OpenTMKPacket`], with corresponding magic header and footer
//! value (defined in [`COMMS_PACKET_HEADER_MAGIC`] and [`COMMS_PACKET_FOOTER_MAGIC`]) will be
//! exchanged as the agent executes test cases. Usually this is done with sending a single
//! configuration packet followed by a back and forth exchange of test case packets with the
//! opentmk ack'ing each packet.
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

/// Magic value used in the SYN packet
pub const COMMS_SYN_MAGIC: u64 = 0x4142434445464748;
/// Magic value used in the SYN-ACK packet (opentmk acknowledging SYN)
pub const COMMS_SYN_ACK_MAGIC: u64 = 0x5152535455565758;
/// Magic value used in the ACK packet (agent acknowledging SYN-ACK)
pub const COMMS_ACK_MAGIC: u64 = 0x6162636465666768;
/// Magic value used as the header of a regular packet
pub const COMMS_PACKET_HEADER_MAGIC: u64 = 0xf0f1f2f3f4f5f6f7;
/// Magic value used as the footer of a regular packet
pub const COMMS_PACKET_FOOTER_MAGIC: u64 = !COMMS_PACKET_HEADER_MAGIC;

/// Describes the specific serialization format used for encoding test cases to the opentmk
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum OpenTMKGrammarDeserializer {
    /// No encoding -- just use raw bytes
    None,
    /// syz-decoder. Used in conjunction of syzkaller fuzzers
    SyzDecoder,
}

/// Packet used to configure the opentmk instance with
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpenTMKConfigurationPacket {
    /// Specify the type of serialization format for future test cases
    pub deserializer: OpenTMKGrammarDeserializer,
    /// A serialization-specific mapping that describes how (if any) call codes
    /// will correspond to specific functions
    pub mapping: Vec<u8>,
}

/// Packet used to run a test case
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpenTMKFuzzTest {
    /// The encoded test case to run on the main thread
    pub testcase_vcpu0: Vec<u8>,
}

/// Packet used to relay error messages out
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpenTMKErrorPacket {
    /// The message string
    pub message: String,
}

/// Packet used to acknowledge the completion of a single fuzz test case
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpenTMKAckPacket {
    /// The error code (or zero if success)
    pub code: u64,
}

/// Represents any packets that may be transmitted to and from the TMK
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum OpenTMKPacket {
    /// An [`OpenTMKConfigurationPacket`] configuration packet
    Configuration(OpenTMKConfigurationPacket),
    /// An [`OpenTMKFuzzTest`] test case
    FuzzTest(OpenTMKFuzzTest),
    /// An [`OpenTMKAckPacket`] acknowledgement to a test case
    Ack(OpenTMKAckPacket),
    /// An [`OpenTMKErrorPacket`] error message for any other catch-all errors.
    Error(OpenTMKErrorPacket),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use test_with_tracing::test;

    // Test: Exchange each packet kind using the executor's postcard encoding.
    // Expected: Variant tags, lengths and acknowledgement integers match the
    //       established wire format, and decoding preserves the payload.
    #[test]
    fn packets_match_wire_encoding() {
        for (packet, bytes) in [
            (
                OpenTMKPacket::Configuration(OpenTMKConfigurationPacket {
                    deserializer: OpenTMKGrammarDeserializer::None,
                    mapping: vec![0, 255, 7],
                }),
                vec![0, 0, 3, 0, 255, 7],
            ),
            (
                OpenTMKPacket::Configuration(OpenTMKConfigurationPacket {
                    deserializer: OpenTMKGrammarDeserializer::SyzDecoder,
                    mapping: vec![],
                }),
                vec![0, 1, 0],
            ),
            (
                OpenTMKPacket::FuzzTest(OpenTMKFuzzTest {
                    testcase_vcpu0: vec![255, 0, 1],
                }),
                vec![1, 3, 255, 0, 1],
            ),
            (
                OpenTMKPacket::Ack(OpenTMKAckPacket { code: 128 }),
                vec![2, 128, 1],
            ),
            (
                OpenTMKPacket::Error(OpenTMKErrorPacket {
                    message: String::from("é"),
                }),
                vec![3, 2, 0xc3, 0xa9],
            ),
        ] {
            assert_eq!(postcard::to_allocvec(&packet).unwrap(), bytes);
            assert_eq!(
                postcard::from_bytes::<OpenTMKPacket>(&bytes).unwrap(),
                packet
            );
            for len in 0..bytes.len() {
                assert!(postcard::from_bytes::<OpenTMKPacket>(&bytes[..len]).is_err());
            }
        }
    }

    // Test: Transfer arbitrary binary testcases and the largest error code.
    // Expected: No byte is interpreted as text, and u64 acknowledgement codes
    //       survive serialization without narrowing.
    #[test]
    fn binary_payloads_and_wide_codes_roundtrip() {
        for packet in [
            OpenTMKPacket::FuzzTest(OpenTMKFuzzTest {
                testcase_vcpu0: (0..=255).collect(),
            }),
            OpenTMKPacket::FuzzTest(OpenTMKFuzzTest {
                testcase_vcpu0: vec![],
            }),
            OpenTMKPacket::Ack(OpenTMKAckPacket { code: u64::MAX }),
            OpenTMKPacket::Ack(OpenTMKAckPacket { code: 0 }),
            OpenTMKPacket::Error(OpenTMKErrorPacket {
                message: String::from("execution failed: \0 🦀"),
            }),
        ] {
            let bytes = postcard::to_allocvec(&packet).unwrap();
            assert_eq!(
                postcard::from_bytes::<OpenTMKPacket>(&bytes).unwrap(),
                packet
            );
        }
    }

    // Test: Receive unknown packet/grammar tags, invalid UTF-8 and bad lengths.
    // Expected: Deserialization returns an error instead of a usable packet.
    #[test]
    fn malformed_payloads_are_rejected() {
        for bytes in [
            &[4][..],
            &[0, 2, 0],
            &[3, 1, 255],
            &[1, 3, 0, 1],
            &[2, 128],
            &[2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
        ] {
            assert!(postcard::from_bytes::<OpenTMKPacket>(bytes).is_err());
        }
    }
}
