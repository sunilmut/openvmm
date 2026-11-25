// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate std;

use super::*;
use std::format;
use test_with_tracing::test;

// Test: Decode CPUID capability words, change selected capabilities, and encode them again.
// Expected: Register ordering, field positions, and unknown/reserved bits are preserved.
#[test]
fn cpuid_feature_and_enlightenment_updates_preserve_other_bits() {
    let words = [0x80000001, 0x12345678, 0xa5a50003, 0x80000001];
    let mut features = HvFeatures::from_cpuid(words);
    assert!(features.privileges().access_vp_runtime_msr());
    assert_eq!(features.max_supported_cstate(), 3);
    assert!(features.mwait_available_deprecated());
    assert_eq!(features.into_cpuid(), words);
    features.set_max_supported_cstate(5);
    features.set_guest_idle_available(true);
    assert_eq!(
        features.into_cpuid(),
        [words[0], words[1], 0xa5a50005, 0x80000021]
    );

    let words = [0xa5000009, 0x12345678, 0xface002f, 0xfedcba98];
    let mut enlightenments = HvEnlightenmentInformation::from_cpuid(words);
    assert!(enlightenments.use_hypercall_for_address_space_switch());
    assert!(enlightenments.use_apic_msrs());
    assert_eq!(enlightenments.long_spin_wait_count(), 0x12345678);
    assert_eq!(enlightenments.implemented_physical_address_bits(), 47);
    assert_eq!(enlightenments.into_cpuid(), words);
    enlightenments.set_implemented_physical_address_bits(52);
    enlightenments.set_long_spin_wait_count(u32::MAX);
    assert_eq!(
        enlightenments.into_cpuid(),
        [words[0], u32::MAX, 0xface0034, words[3]]
    );
}

// Test: Carry string/REP port I/O intercepts through the fixed-size SynIC message buffer.
// Expected: The byte-level ABI, packed CR8/length, typed views, and unused tail stay correct.
#[test]
fn synic_io_intercept_message_round_trips_typed_payload_and_wire_header() {
    for (size, string, rep, encoded) in [
        (1, false, false, 1),
        (2, true, false, 0xa),
        (4, false, true, 0x14),
        (0xfc, true, true, 0x1c),
    ] {
        let mut payload = HvX64IoPortInterceptMessage::new_zeroed();
        payload.header.vp_index = 7;
        payload.header.instruction_length_and_cr8 = 0xa3;
        payload.header.intercept_access_type = HvInterceptAccessType::WRITE;
        payload.port_number = 0x3f8;
        payload.access_info = HvX64IoPortAccessInfo::new(size, string, rep);
        payload.rax = 0x12345678;
        let mut message = HvMessage::new(
            HvMessageType::HvMessageTypeX64IoPortIntercept,
            0x1122334455667788,
            payload.as_bytes(),
        );
        assert_eq!(&message.as_bytes()[..4], &[0, 0, 1, 0x80]);
        assert_eq!(
            &message.as_bytes()[8..16],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(&message.payload()[..8], &[7, 0, 0, 0, 0xa3, 1, 0, 0]);
        assert_eq!(&message.payload()[40..44], &[0xf8, 3, encoded, 0]);
        assert!(
            message.payload_buffer[payload.as_bytes().len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
        let decoded = message.as_message::<HvX64IoPortInterceptMessage>();
        assert_eq!(decoded.header.instruction_len(), 3);
        assert_eq!(decoded.header.cr8(), 10);
        assert_eq!(decoded.access_info.access_size(), size & 7);
        assert_eq!(decoded.access_info.string_op(), string);
        assert_eq!(decoded.access_info.rep_prefix(), rep);
        assert_eq!(
            message.as_message_mut::<HvX64IoPortInterceptMessage>().rax,
            0x12345678
        );
        assert_eq!(message.payload()[48..56], 0x12345678u64.to_le_bytes());
    }
}

// Test: Construct empty and maximum-size messages using unknown future message types.
// Expected: Lengths, all payload bytes, and zero-filled transport padding remain intact.
#[test]
fn synic_message_payload_boundaries_preserve_unknown_types() {
    let empty = HvMessage::default();
    assert!(empty.as_bytes().iter().all(|byte| *byte == 0));
    assert!(empty.payload().is_empty());
    assert_eq!(HvMessageType::default(), empty.header.typ);
    let payload = core::array::from_fn::<_, 240, _>(|index| index as u8);
    let message = HvMessage::new(HvMessageType(0xdeadbeef), u64::MAX, &payload);
    assert_eq!(message.header.typ, HvMessageType(0xdeadbeef));
    assert_eq!(message.as_bytes()[4], 240);
    assert_eq!(message.payload(), payload);
    assert_eq!(&message.as_bytes()[16..], payload);
}

// Test: Encode a failed rep hypercall and render known and unknown hypervisor errors.
// Expected: The full status code and processed count survive, with actionable diagnostics.
#[test]
fn hypercall_outputs_preserve_status_and_error_diagnostics() {
    use hypercall::HypercallOutput;
    let error = HvError::from(core::num::NonZeroU16::new(0xabcd).unwrap());
    let output = HypercallOutput::from(error).with_elements_processed(0xabc);
    assert_eq!(u64::from(output), 0x00000abc0000abcd);
    assert_eq!(output.result(), Err(error));
    assert!(output.call_status().is_err());
    assert!(!output.call_status().is_ok());
    assert_eq!(format!("{error}"), "Hypervisor error 0xabcd");
    assert_eq!(format!("{error:?}"), "43981");
    assert_eq!(format!("{:?}", output.call_status()), "43981");
    assert_eq!(
        format!("{}", HvError::InvalidParameter),
        "Invalid parameter"
    );
    assert_eq!(
        format!("{:?}", HvError::InvalidParameter),
        "InvalidParameter"
    );
    assert_eq!(format!("{:?}", HvStatus::SUCCESS), "Success");
    assert_eq!(HypercallOutput::SUCCESS.result(), Ok(()));
    assert!(HypercallOutput::SUCCESS.call_status().is_ok());
    assert!(!HypercallOutput::SUCCESS.call_status().is_err());
}

// Test: Package a page fault in x64 pending-event registers and decode ARM event headers.
// Expected: Exception parameters retain all bits, the second x64 register is zero, and tags round-trip.
#[test]
fn pending_event_wire_formats_preserve_exception_details_and_future_tags() {
    let exception = HvX64PendingExceptionEvent::new()
        .with_event_pending(true)
        .with_deliver_error_code(true)
        .with_vector(14)
        .with_error_code(0x17)
        .with_exception_parameter(0x1122334455667788);
    let event = HvX64PendingEvent::from(exception);
    assert_eq!(
        &event.as_bytes()[..16],
        &[
            1, 1, 14, 0, 0x17, 0, 0, 0, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
        ]
    );
    assert_eq!(&event.as_bytes()[16..], &[0; 16]);
    for (typ, byte) in [
        (HvAarch64PendingEventType::EXCEPTION, 1),
        (HvAarch64PendingEventType::HYPERCALL_OUTPUT, 5),
        (HvAarch64PendingEventType(7), 15),
    ] {
        let header = HvAarch64PendingEventHeader::new()
            .with_event_pending(true)
            .with_event_type(typ);
        assert_eq!(header.as_bytes(), &[byte]);
        let decoded = HvAarch64PendingEventHeader::read_from_bytes(&[byte]).unwrap();
        assert!(decoded.event_pending());
        assert_eq!(decoded.event_type(), typ);
    }
}

// Test: Encode post-message hypercall inputs with empty, one-byte, and full
//       payloads using distinct connection and message-type identifiers.
// Expected: The hypercall header precedes every payload byte in TLFS order,
//       independently of the different SynIC delivery-header layout.
#[test]
fn post_message_hypercall_inputs_match_the_transport_wire_contract() {
    let payload: [u8; 240] = core::array::from_fn(|index| index as u8);
    for len in [0, 1, 240] {
        let mut input = hypercall::PostMessage {
            connection_id: 0x00123456,
            padding: 0,
            message_type: 0x80000042,
            payload_size: len as u32,
            payload: [0; 240],
        };
        input.payload[..len].copy_from_slice(&payload[..len]);
        let mut expected = [0; 256];
        expected[..16].copy_from_slice(&[
            0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0x42, 0, 0, 0x80, len as u8, 0, 0, 0,
        ]);
        expected[16..16 + len].copy_from_slice(&payload[..len]);
        assert_eq!(input.as_bytes(), expected);
    }
}
