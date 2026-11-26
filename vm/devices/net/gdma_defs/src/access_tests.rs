// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::bnic::{ManaCfgRxSteerReq, ManaQueryDeviceCfgResp, Tristate};
use crate::{Sge, Wqe, WqeHeader, WqeParams};
use guestmem::{AccessError, GuestMemory, MemoryRead, MemoryWrite};
use test_with_tracing::test;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

fn work_entry(oob: u8, segments: &[Sge]) -> Wqe {
    let mut wqe = Wqe {
        header: WqeHeader {
            reserved: [0; 3],
            last_vbytes: 0,
            params: WqeParams::new()
                .with_inline_client_oob_size(oob)
                .with_num_sgl_entries(u8::try_from(segments.len()).unwrap()),
        },
        data: [0xcc; 504],
    };
    let sgl_offset = match oob {
        6 => 24,
        7 => 40,
        _ => 8,
    };
    for (index, segment) in segments.iter().enumerate() {
        let offset = sgl_offset + index * 16;
        wqe.data[offset..offset + 16].copy_from_slice(segment.as_bytes());
    }
    wqe
}

fn segment(address: u64, size: u32) -> Sge {
    Sge {
        address,
        mem_key: 0x12345678,
        size,
    }
}

// Test: Decode producer-layout entries with every supported OOB size.
// Expected: OOB views exclude alignment padding, and the SGL preserves each
//       full-width address, memory key and independently sized fragment.
#[test]
fn work_entry_views_use_the_producer_sgl_boundary() {
    let segments = [
        segment(0x123456789abcdef0, 3),
        segment(0xfedcba9876543210, 5),
    ];
    for (oob, length) in [(2, 8), (6, 24), (7, 32), (0, 8)] {
        let wqe = work_entry(oob, &segments);
        assert_eq!(wqe.oob(), vec![0xcc; length]);
        let decoded = wqe.sgl();
        assert_eq!(decoded.len(), 2);
        for (actual, expected) in decoded.iter().zip(&segments) {
            assert_eq!(actual.address, expected.address);
            assert_eq!(actual.mem_key, expected.mem_key);
            assert_eq!(actual.size, expected.size);
        }
    }
}

// Test: Read, skip and clone a cursor across discontiguous and empty SG fragments.
// Expected: Reads preserve byte order, clones advance independently, and exhausted
//       reads report an error rather than returning stale data.
#[test]
fn scatter_gather_reads_and_clones_preserve_stream_position() {
    let gm = GuestMemory::allocate(4096);
    gm.write_at(16, &[0xa1, 0xa2, 0xa3]).unwrap();
    gm.write_at(64, &[0xb1, 0xb2, 0xb3, 0xb4]).unwrap();
    let wqe = work_entry(2, &[segment(16, 3), segment(0, 0), segment(64, 4)]);
    let mut read = wqe.access(&gm);
    let mut first = [0; 2];
    read.read(&mut first).unwrap();
    assert_eq!(first, [0xa1, 0xa2]);
    assert_eq!(MemoryRead::len(&read), 5);
    let mut cloned = read.clone();
    read.skip(2).unwrap();
    let mut rest = [0; 3];
    read.read(&mut rest).unwrap();
    assert_eq!(rest, [0xb2, 0xb3, 0xb4]);
    let mut cloned_rest = [0; 5];
    cloned.read(&mut cloned_rest).unwrap();
    assert_eq!(cloned_rest, [0xa3, 0xb1, 0xb2, 0xb3, 0xb4]);
    assert_eq!(MemoryRead::len(&read), 0);
    let mut beyond = [0xd5];
    assert!(matches!(
        read.read(&mut beyond),
        Err(AccessError::OutOfRange(_, _))
    ));
    assert_eq!(beyond, [0xd5]);
}

// Test: Write through multiple SG destinations and retry after a memory-boundary error.
// Expected: Only destination bytes change; a failed memory operation does not
//       advance its cursor, so a shorter valid retry starts at the same address.
#[test]
fn scatter_gather_writes_preserve_guards_and_failed_chunk_position() {
    let gm = GuestMemory::allocate(4096);
    gm.write_at(0, &[0xaa; 128]).unwrap();
    let wqe = work_entry(2, &[segment(12, 2), segment(64, 3)]);
    let mut write = wqe.access(&gm);
    write.write(&[0xd0, 0xd1, 0xd2, 0xd3]).unwrap();
    assert_eq!(MemoryWrite::len(&write), 1);
    write.write(&[0xd4]).unwrap();
    assert_eq!(MemoryWrite::len(&write), 0);
    let mut first = [0; 4];
    gm.read_at(11, &mut first).unwrap();
    assert_eq!(first, [0xaa, 0xd0, 0xd1, 0xaa]);
    let mut second = [0; 5];
    gm.read_at(63, &mut second).unwrap();
    assert_eq!(second, [0xaa, 0xd2, 0xd3, 0xd4, 0xaa]);
    let boundary = work_entry(2, &[segment(4094, 3)]);
    let mut write = boundary.access(&gm);
    assert!(matches!(
        write.write(&[1, 2, 3]),
        Err(AccessError::Memory(_))
    ));
    assert_eq!(MemoryWrite::len(&write), 3);
    write.write(&[4, 5]).unwrap();
    let mut end = [0; 2];
    gm.read_at(4094, &mut end).unwrap();
    assert_eq!(end, [4, 5]);
    assert_eq!(MemoryWrite::len(&write), 1);
    let mut read = boundary.access(&gm);
    assert!(matches!(
        read.read(&mut [0; 3]),
        Err(AccessError::Memory(_))
    ));
    assert_eq!(MemoryRead::len(&read), 3);
}

// Test: Read an inline direct payload, including a short final SGE.
// Expected: The cursor observes only valid bytes, rejects overreads without
//       changing output, and refuses writes into the immutable inline entry.
#[test]
fn inline_payload_reads_observe_valid_tail_and_reject_writes() {
    let gm = GuestMemory::allocate(4096);
    let mut wqe = work_entry(2, &[segment(0, 0), segment(0, 0)]);
    wqe.header.params.set_sgl_direct(true);
    wqe.header.last_vbytes = 5;
    let expected: Vec<u8> = (1..=21).collect();
    wqe.data[8..29].copy_from_slice(&expected);
    let mut read = wqe.access(&gm);
    assert_eq!(MemoryRead::len(&read), 21);
    let mut beyond = [0xe7; 22];
    assert!(read.read(&mut beyond).is_err());
    assert_eq!(beyond, [0xe7; 22]);
    assert_eq!(MemoryRead::len(&read), 21);
    let mut first = [0; 3];
    read.read(&mut first).unwrap();
    assert_eq!(first, [1, 2, 3]);
    assert!(read.write(&[0xff]).is_err());
    assert_eq!(MemoryRead::len(&read), 18);
    read.skip(5).unwrap();
    let mut rest = [0; 13];
    read.read(&mut rest).unwrap();
    assert_eq!(rest, expected[8..]);
    assert_eq!(MemoryRead::len(&read), 0);
    assert!(read.skip(1).is_err());
}

// Test: Interpret negotiated BNIC flags and raw Mbps link-speed responses.
// Expected: Reserved capability bits do not enable known features, speeds use
//       64-bit bits-per-second units, and an omitted speed uses the documented default.
#[test]
fn negotiated_device_response_preserves_feature_gates_and_link_speed_units() {
    for (flags, mbps, bps) in [
        (0xfa, 0u32, 200_000_000_000u64),
        (0xfd, 50_000, 50_000_000_000),
        (0xff, 400_000, 400_000_000_000),
    ] {
        let mut wire = [0; 48];
        wire[0] = flags;
        wire[44..48].copy_from_slice(&mbps.to_le_bytes());
        let response = ManaQueryDeviceCfgResp::read_from_bytes(&wire).unwrap();
        assert_eq!(response.cap_query_link_status(), flags & 1 != 0);
        assert_eq!(response.cap_ethertype_enforcement(), flags & 2 != 0);
        assert_eq!(response.cap_filter_state_query(), flags & 4 != 0);
        assert_eq!(response.link_speed_bps(), bps);
    }
}

// Test: Encode a partial RX steering update that disables RX but leaves RSS unchanged.
// Expected: False, true and no-change retain distinct wire values, so an omitted
//       update cannot accidentally disable an existing RSS configuration.
#[test]
fn rx_steering_updates_distinguish_disabled_enabled_and_unchanged() {
    let mut request = ManaCfgRxSteerReq::new_zeroed();
    request.rx_enable = Tristate::from(Some(false));
    request.rss_enable = Tristate::from(None);
    assert_eq!(
        &request.as_bytes()[12..20],
        &[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]
    );
    request.rx_enable = Tristate::from(Some(true));
    assert_eq!(
        &request.as_bytes()[12..20],
        &[1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]
    );
}

// IGNORED: MemoryWrite::zero calls WqeAccess::fill, which is unimplemented.
//       Reproduced enabled: even a valid destination panics instead of being cleared.
//
// Test: Zero a valid memory-backed destination spanning two SG entries.
// Expected: The MemoryWrite zero operation consumes the requested bytes and clears
//       only the SG destinations, preserving surrounding memory.
#[test]
#[ignore = "WqeAccess::fill panics for valid scatter/gather destinations"]
fn zeroing_scatter_gather_destination_preserves_surrounding_memory() {
    let gm = GuestMemory::allocate(4096);
    gm.write_at(0, &[0xaa; 128]).unwrap();
    let wqe = work_entry(2, &[segment(12, 2), segment(64, 3)]);
    let mut write = wqe.access(&gm);
    write.zero(5).unwrap();
    assert_eq!(MemoryWrite::len(&write), 0);
    let mut first = [0; 4];
    gm.read_at(11, &mut first).unwrap();
    assert_eq!(first, [0xaa, 0, 0, 0xaa]);
    let mut second = [0; 5];
    gm.read_at(63, &mut second).unwrap();
    assert_eq!(second, [0xaa, 0, 0, 0, 0xaa]);
}
