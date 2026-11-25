// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::test_helpers::{check_response, new_scsi_dvd};
use crate::{scsi, scsidvd::SimpleScsiDvd};
use guestmem::GuestMemory;
use pal_async::async_test;
use scsi_buffers::OwnedRequestBuffers;
use scsi_core::{AsyncScsiDisk, Request};

fn read_cdb(operation: u8, start: u64, blocks: u32) -> [u8; 16] {
    let mut cdb = [0; 16];
    cdb[0] = operation;
    match operation {
        0x28 => {
            cdb[2..6].copy_from_slice(&(start as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
        }
        0xa8 => {
            cdb[2..6].copy_from_slice(&(start as u32).to_be_bytes());
            cdb[6..10].copy_from_slice(&blocks.to_be_bytes());
        }
        0x88 => {
            cdb[2..10].copy_from_slice(&start.to_be_bytes());
            cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
        }
        _ => unreachable!(),
    }
    cdb
}

// Test: Read interior and final ISO blocks with READ10/12/16 over 512/1024/2048-byte backing sectors.
// Expected: ISO LBAs select the exact payload independent of backing geometry and preserve all guest guard/slack bytes.
#[async_test]
async fn dvd_reads_translate_iso_blocks_and_copy_only_the_requested_payload() {
    for backing in [512, 1024, 2048] {
        let (dvd, state) = new_scsi_dvd(backing, backing, 16 * (2048 / u64::from(backing)), true);
        for (block, chunk) in state.lock().storage.chunks_exact_mut(2048).enumerate() {
            chunk.fill(0x40 + block as u8);
        }
        for operation in [0x28, 0xa8, 0x88] {
            for (start, blocks) in [(3, 2), (15, 1)] {
                let memory = GuestMemory::allocate(8192);
                let mut expected = vec![0xa5; 8192];
                memory.write_at(0, &expected).unwrap();
                let buffers =
                    OwnedRequestBuffers::new_unaligned(&[0, 1], 64, blocks as usize * 2048 + 128);
                let cdb = read_cdb(operation, start, blocks);
                let result = dvd
                    .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
                    .await;
                assert_eq!(result.scsi_status, scsi::ScsiStatus::GOOD);
                assert_eq!(result.srb_status, scsi::srb::SrbStatus::SUCCESS);
                assert_eq!(result.tx, blocks as usize * 2048);
                for block in 0..blocks as usize {
                    expected[64 + block * 2048..64 + (block + 1) * 2048]
                        .fill(0x40 + start as u8 + block as u8);
                }
                let mut actual = vec![0; 8192];
                memory.read_at(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }
}

// Test: Read beyond the ISO capacity, across its end, or into an insufficient guest buffer in all read formats.
// Expected: ILLEGAL BLOCK is reported with zero transfer and no guest-memory changes; zero-block reads need no medium.
#[async_test]
async fn dvd_read_bounds_fail_without_writes_and_zero_blocks_are_media_independent() {
    let (dvd, _) = new_scsi_dvd(2048, 2048, 16, true);
    for operation in [0x28, 0xa8, 0x88] {
        for (start, blocks, buffer_len) in [
            (16, 1, 2048),
            (15, 2, 4096),
            (u64::MAX, 1, 2048),
            (0, 2, 2048),
        ] {
            let memory = GuestMemory::allocate(8192);
            memory.write_at(0, &[0xa5; 8192]).unwrap();
            let buffers = OwnedRequestBuffers::new_unaligned(&[0, 1], 64, buffer_len);
            let cdb = read_cdb(operation, start, blocks);
            let result = dvd
                .execute_scsi(&buffers.buffer(&memory), &Request { cdb, srb_flags: 0 })
                .await;
            assert_eq!(result.scsi_status, scsi::ScsiStatus::CHECK_CONDITION);
            assert_eq!(result.srb_status, scsi::srb::SrbStatus::ERROR);
            assert_eq!(result.tx, 0);
            let sense = result.sense_data.unwrap();
            assert_eq!(sense.header.sense_key, scsi::SenseKey::ILLEGAL_REQUEST);
            assert_eq!(
                sense.additional_sense_code,
                scsi::AdditionalSenseCode::ILLEGAL_BLOCK
            );
            let mut actual = [0; 8192];
            memory.read_at(0, &mut actual).unwrap();
            assert_eq!(actual, [0xa5; 8192]);
        }
        let empty = SimpleScsiDvd::new(None);
        check_response(&empty, read_cdb(operation, u64::MAX, 0), 0, &[]).await;
    }
}
