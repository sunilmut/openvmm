// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::support::*;
use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::Wake;
use test_with_tracing::test;

#[derive(Default)]
struct PollWake(AtomicUsize);

impl Wake for PollWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn assert_success(result: [u8; 7]) {
    assert_eq!(result[0] & 0xc0, 0);
    assert_eq!(&result[1..3], &[0, 0]);
    assert_eq!(result[6], 2);
}

fn assert_io_error(result: [u8; 7]) {
    assert_eq!(result[0] & 0xc0, 0x40);
    assert_ne!(result[1] & 4, 0);
    assert_ne!(result[2] & 1, 0);
}

// Test: DMA-write two sectors at a nonzero CHS location and read them back.
// Expected: Only the selected sectors and DMA bytes change, with correct directions and completion.
#[test]
fn dma_round_trip_preserves_chs_addressing_neighbors_and_transfer_ownership() {
    let disk = TestDisk::new(IMAGE_SIZE);
    let mut rig = Rig::with_disk(disk.clone());
    rig.dma.lock().buffer.as_mut().unwrap().size = 1024;
    rig.dma.lock().size_hint = 1024;
    let payload: Vec<u8> = (0..1024).map(|index| (index % 251) as u8).collect();
    rig.memory.write_at(DMA_ADDRESS, &payload).unwrap();
    rig.transfer(0xc5, 3, 1, 5);
    assert_eq!(rig.read(0x3f4) & 0xd0, 0x10);
    rig.poll();
    assert_success(rig.result());
    let start = 130 * 512;
    {
        let state = disk.state.lock();
        assert_eq!(state.requests, [Request::Write(130, 1024), Request::Flush]);
        assert_eq!(&state.bytes[start..start + 1024], payload);
        assert!(state.bytes[..start].iter().all(|byte| *byte == 0x5a));
        assert!(state.bytes[start + 1024..].iter().all(|byte| *byte == 0x5a));
    }
    rig.memory
        .write_at(DMA_ADDRESS - 16, &vec![0xcc; 1056])
        .unwrap();
    rig.transfer(0xe6, 3, 1, 5);
    rig.poll();
    assert_success(rig.result());
    let mut actual = vec![0; 1056];
    rig.memory.read_at(DMA_ADDRESS - 16, &mut actual).unwrap();
    assert_eq!(&actual[..16], &[0xcc; 16]);
    assert_eq!(&actual[16..1040], payload);
    assert_eq!(&actual[1040..], &[0xcc; 16]);
    assert_eq!(
        rig.dma.lock().requests,
        [IsaDmaDirection::Read, IsaDmaDirection::Write]
    );
    assert_eq!(rig.dma.lock().completions, 2);
    assert_eq!(
        disk.state.lock().requests.last(),
        Some(&Request::Read(130, 1024))
    );
}

// Test: Start a disk read after the chipset has registered its poll waker.
// Expected: Starting I/O wakes the poller, completion raises IRQ, and sense status acknowledges it.
#[test]
fn asynchronous_read_wakes_poller_and_interrupt_is_acknowledged_by_sense() {
    let mut rig = Rig::with_disk(TestDisk::new(IMAGE_SIZE));
    let wake = Arc::new(PollWake::default());
    let waker = Waker::from(wake.clone());
    rig.device
        .supports_poll_device()
        .unwrap()
        .poll_device(&mut Context::from_waker(&waker));
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    rig.transfer(0xe6, 0, 0, 1);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
    rig.poll();
    assert!(rig.interrupt.0.load(Ordering::SeqCst));
    assert_success(rig.result());
    rig.issue(&[8]);
    assert_eq!(rig.read(0x3f5), 0x20);
    assert_eq!(rig.read(0x3f5), 0);
    assert!(!rig.interrupt.0.load(Ordering::SeqCst));
}

// Test: Format a selected track using each supported format command.
// Expected: The DMA-selected track is zeroed and flushed; neighboring tracks remain untouched.
#[test]
fn formatting_zeros_only_the_dma_selected_track() {
    for opcode in [0x4d, 0xcd] {
        let disk = TestDisk::new(IMAGE_SIZE);
        let mut rig = Rig::with_disk(disk.clone());
        rig.memory.write_at(DMA_ADDRESS, &[2, 1, 1, 2]).unwrap();
        rig.issue(&[opcode, 4, 2, 18, 0x1b, 0xf6]);
        rig.poll();
        assert_success(rig.result());
        let state = disk.state.lock();
        assert_eq!(
            state.requests,
            [Request::Write(90, 18 * 512), Request::Flush]
        );
        assert!(state.bytes[..90 * 512].iter().all(|byte| *byte == 0x5a));
        assert!(
            state.bytes[90 * 512..108 * 512]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(state.bytes[108 * 512..].iter().all(|byte| *byte == 0x5a));
        assert_eq!(rig.dma.lock().requests, [IsaDmaDirection::Read]);
        assert_eq!(rig.dma.lock().completions, 1);
    }
}

// Test: Fail disk reads, writes, and cache flushes, then retry after clearing the fault.
// Expected: Each failure produces error status and leaves the controller able to execute new I/O.
#[test]
fn backend_failures_report_error_and_do_not_wedge_following_commands() {
    for (fault, opcode) in [
        (Fault::Read, 0xe6),
        (Fault::Write, 0xc5),
        (Fault::Flush, 0xc5),
    ] {
        let disk = TestDisk::new(IMAGE_SIZE);
        disk.state.lock().fault = Some(fault);
        let mut rig = Rig::with_disk(disk.clone());
        rig.transfer(opcode, 0, 0, 1);
        rig.poll();
        assert_io_error(rig.result());
        disk.state.lock().fault = None;
        rig.transfer(opcode, 0, 0, 1);
        rig.poll();
        assert_success(rig.result());
    }
}

// Test: Fail writes or flushes during track formatting and retry on the same controller.
// Expected: Format reports the failure and accepts a subsequent successful format.
#[test]
fn format_backend_failures_leave_the_command_fifo_usable() {
    for fault in [Fault::Write, Fault::Flush] {
        let disk = TestDisk::new(IMAGE_SIZE);
        disk.state.lock().fault = Some(fault);
        let mut rig = Rig::with_disk(disk.clone());
        for should_fail in [true, false] {
            rig.issue(&[0x4d, 0, 2, 18, 0x1b, 0]);
            rig.poll();
            let result = rig.result();
            if should_fail {
                assert_io_error(result);
            } else {
                assert_success(result);
            }
            disk.state.lock().fault = None;
        }
    }
}

// Test: Read, write, and format when DMA is unavailable or points outside guest memory.
// Expected: Commands fail cleanly and DMA completion is reported only for accepted buffers.
#[test]
fn invalid_dma_buffers_report_io_error_without_spurious_completion() {
    for opcode in [0xe6, 0xc5, 0x4d] {
        for address in [None, Some(0x30000)] {
            let mut rig = Rig::with_disk(TestDisk::new(IMAGE_SIZE));
            rig.dma.lock().buffer =
                address.map(|address| vmcore::isa_dma_channel::IsaDmaBuffer { address, size: 512 });
            if opcode == 0x4d {
                rig.issue(&[opcode, 0, 2, 18, 0x1b, 0]);
            } else {
                rig.transfer(opcode, 0, 0, 1);
            }
            rig.poll();
            assert_io_error(rig.result());
            assert_eq!(rig.dma.lock().completions, usize::from(address.is_some()));
        }
    }
}

// Test: Attempt writes and format against write-protected media.
// Expected: Write-protect status is returned without backend writes or DMA consumption.
#[test]
fn write_protected_media_rejects_mutation_before_consuming_dma() {
    for opcode in [0xc5, 0x4d] {
        let disk = TestDisk::read_only(IMAGE_SIZE);
        let mut rig = Rig::with_disk(disk.clone());
        if opcode == 0x4d {
            rig.issue(&[opcode, 0, 2, 18, 0x1b, 0]);
        } else {
            rig.transfer(opcode, 0, 0, 1);
        }
        let result = rig.result();
        assert_eq!(result[0] & 0xc0, 0x40);
        assert_ne!(result[1] & 2, 0);
        assert!(disk.state.lock().requests.is_empty());
        assert!(rig.dma.lock().requests.is_empty());
        assert_eq!(rig.dma.lock().completions, 0);
    }
}
