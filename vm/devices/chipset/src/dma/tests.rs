// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::executor::block_on;
use test_with_tracing::test;
use vmcore::save_restore::SaveRestore;

fn write(device: &mut DmaController, port: u16, value: u8) {
    device
        .supports_pio()
        .unwrap()
        .io_write(port, &[value])
        .unwrap();
}

fn read(device: &mut DmaController, port: u16) -> u8 {
    let mut value = [0];
    device.io_read(port, &mut value).unwrap();
    value[0]
}

fn bank(channel: usize) -> (u16, u16) {
    if channel < 4 { (0, 1) } else { (0xc0, 2) }
}

fn write_word(device: &mut DmaController, channel: usize, count: bool, value: u16) {
    let (base, stride) = bank(channel);
    let port = base + (channel as u16 % 4 * 2 + u16::from(count)) * stride;
    write(device, base + 12 * stride, 0);
    write(device, port, value as u8);
    write(device, port, (value >> 8) as u8);
}

fn read_word(device: &mut DmaController, channel: usize, count: bool) -> u16 {
    let (base, stride) = bank(channel);
    let port = base + (channel as u16 % 4 * 2 + u16::from(count)) * stride;
    write(device, base + 12 * stride, 0);
    u16::from(read(device, port)) | u16::from(read(device, port)) << 8
}

// Test: Program all channel address/count registers and all exposed page registers.
// Expected: Each value reads back independently and configured transfer counts match their channels.
#[test]
fn channel_and_page_registers_round_trip_without_aliasing() {
    let mut device = DmaController::new();
    for channel in 0..8 {
        write_word(&mut device, channel, false, 0x1234 + channel as u16 * 0x101);
        write_word(&mut device, channel, true, 0x5678 + channel as u16 * 0x101);
    }
    for channel in 0..8 {
        assert_eq!(
            read_word(&mut device, channel, false),
            0x1234 + channel as u16 * 0x101
        );
        assert_eq!(
            read_word(&mut device, channel, true),
            0x5678 + channel as u16 * 0x101
        );
        assert_eq!(
            device.check_transfer_size(channel),
            0x5678 + channel as u16 * 0x101
        );
    }
    for port in 0x81..=0x8f {
        write(&mut device, port, port as u8 ^ 0x5a);
    }
    for port in 0x81..=0x8f {
        assert_eq!(read(&mut device, port), port as u8 ^ 0x5a);
    }
}

// Test: Interleave low/high address bytes between the two DMA register banks.
// Expected: Each bank advances its own flip-flop without corrupting the other bank's word.
#[test]
fn controller_banks_have_independent_byte_flip_flops() {
    let mut device = DmaController::new();
    for (port, byte) in [(2, 0x34), (0xc4, 0x78), (2, 0x12), (0xc4, 0x56)] {
        write(&mut device, port, byte);
    }
    assert_eq!(read(&mut device, 2), 0x34);
    assert_eq!(read(&mut device, 0xc4), 0x78);
    assert_eq!(read(&mut device, 2), 0x12);
    assert_eq!(read(&mut device, 0xc4), 0x56);
}

// Test: Request a programmed channel under direction, mode, mask, and controller-disable changes.
// Expected: Only compatible enabled transfers succeed, with page/address composition preserved.
#[test]
fn mode_direction_and_masks_control_transfer_availability() {
    let mut device = DmaController::new();
    write_word(&mut device, 2, false, 0x1234);
    write_word(&mut device, 2, true, 0x2345);
    write(&mut device, 0x81, 0x56);
    write(&mut device, 0x0b, 0x0a);
    assert!(device.request(2, IsaDmaTransferDirection::Read).is_none());
    write(&mut device, 0x0a, 2);
    assert!(device.request(2, IsaDmaTransferDirection::Write).is_none());
    assert_eq!(
        device
            .request(2, IsaDmaTransferDirection::Read)
            .unwrap()
            .address,
        0x561234
    );
    write(&mut device, 8, 4);
    assert!(device.request(2, IsaDmaTransferDirection::Read).is_none());
    write(&mut device, 8, 0);
    write(&mut device, 0x0a, 6);
    assert!(device.request(2, IsaDmaTransferDirection::Read).is_none());
    write(&mut device, 0x0e, 0);
    assert!(device.request(2, IsaDmaTransferDirection::Read).is_some());
    for mode in [2, 0x0e] {
        write(&mut device, 0x0b, mode);
        assert!(device.request(2, IsaDmaTransferDirection::Read).is_none());
    }
    write(&mut device, 0x0b, 6);
    assert!(device.request(2, IsaDmaTransferDirection::Write).is_some());
    write(&mut device, 0x0f, 4);
    assert!(device.request(2, IsaDmaTransferDirection::Write).is_none());
    write(&mut device, 0x0f, 0);
    assert!(device.request(2, IsaDmaTransferDirection::Write).is_some());
}

// Test: Complete and re-request channels, issue software requests, and read status twice.
// Expected: Terminal-count bits identify the channel, clear on read/request, and stay bank-local.
#[test]
fn completion_and_software_requests_update_clear_on_read_status() {
    let mut device = DmaController::new();
    device.complete(2);
    device.complete(2);
    device.complete(6);
    assert_eq!(read(&mut device, 8), 4);
    assert_eq!(read(&mut device, 8), 0);
    assert_eq!(read(&mut device, 0xd0), 4);
    write(&mut device, 9, 1);
    assert_eq!(read(&mut device, 8), 2);
    write(&mut device, 0xd2, 3);
    assert_eq!(read(&mut device, 0xd0), 8);
    write(&mut device, 0x0b, 8);
    write(&mut device, 0x0a, 0);
    device.complete(0);
    assert!(device.request(0, IsaDmaTransferDirection::Read).is_some());
    assert_eq!(read(&mut device, 8), 0);
}

// Test: Reset one DMA bank through its command port, then reset the whole device.
// Expected: Bank reset preserves other-bank/page values; device reset clears both banks and pages.
#[test]
fn bank_reset_and_device_reset_have_distinct_scopes() {
    let mut device = DmaController::new();
    write_word(&mut device, 0, false, 0x1234);
    write_word(&mut device, 4, false, 0x5678);
    write(&mut device, 0x87, 0x9a);
    write(&mut device, 0x0d, 0);
    assert_eq!(read_word(&mut device, 0, false), 0);
    assert_eq!(read_word(&mut device, 4, false), 0x5678);
    assert_eq!(read(&mut device, 0x87), 0x9a);
    write(&mut device, 0xda, 0);
    assert_eq!(read_word(&mut device, 4, false), 0);
    block_on(device.reset());
    assert_eq!(read(&mut device, 0x87), 0);
    assert_eq!(device.check_transfer_size(0), 0);
    assert_eq!(device.check_transfer_size(4), 0);
    assert!(device.request(0, IsaDmaTransferDirection::Read).is_none());
}

// Test: Snapshot independent mid-read/mid-write byte phases across both DMA banks.
// Expected: Restored high-byte reads/writes complete the original words, with page/mode/masks intact.
#[test]
fn checkpoint_restores_latched_reads_partial_writes_and_transfer_configuration() {
    let mut device = DmaController::new();
    write_word(&mut device, 0, false, 0x1234);
    write_word(&mut device, 0, true, 0x5678);
    write(&mut device, 0x87, 0x9a);
    write(&mut device, 0x0b, 8);
    write(&mut device, 0x0a, 0);
    let mask = read(&mut device, 0x0f);
    assert_eq!(read(&mut device, 0), 0x34);
    write(&mut device, 0xc0, 0xbc);
    let saved = device.save().unwrap();
    block_on(device.reset());
    device.restore(saved).unwrap();
    assert_eq!(read(&mut device, 0), 0x12);
    write(&mut device, 0xc0, 0xde);
    assert_eq!(read_word(&mut device, 4, false), 0xdebc);
    assert_eq!(read_word(&mut device, 0, true), 0x5678);
    assert_eq!(read(&mut device, 0x0f), mask);
    assert_eq!(
        device
            .request(0, IsaDmaTransferDirection::Read)
            .unwrap()
            .address,
        0x9a1234
    );
}

// Test: Access invalid DMA channels, unmapped ports, and write-only control registers.
// Expected: Invalid channels remain unavailable and bad port accesses return InvalidRegister.
#[test]
fn invalid_channels_and_ports_are_rejected_without_panics() {
    let mut device = DmaController::new();
    for channel in [8, usize::MAX] {
        assert_eq!(device.check_transfer_size(channel), 0);
        assert!(
            device
                .request(channel, IsaDmaTransferDirection::Read)
                .is_none()
        );
        device.complete(channel);
    }
    for port in [0x10, 0x80, 0xe0, u16::MAX] {
        assert!(matches!(
            device.io_read(port, &mut [0]),
            IoResult::Err(IoError::InvalidRegister)
        ));
        assert!(matches!(
            device.io_write(port, &[0]),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    for port in [9, 0x0a, 0x0b, 0x0c, 0x0e, 0xd2] {
        assert!(matches!(
            device.io_read(port, &mut [0]),
            IoResult::Err(IoError::InvalidRegister)
        ));
    }
    assert_eq!(read(&mut device, 0x0d), 0);
    assert_eq!(
        device.get_static_regions(),
        &[
            ("page", 0x81..=0x8f),
            ("controller0", 0..=0xf),
            ("controller1", 0xc0..=0xdf)
        ]
    );
}
