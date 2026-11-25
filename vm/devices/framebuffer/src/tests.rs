// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use guestmem::MappedMemoryRegion;
use pal_async::local::block_on;
use sparse_mmap::AsMappableRef;
use sparse_mmap::alloc_shared_memory;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use test_with_tracing::test;

#[derive(Debug, PartialEq, Eq)]
enum MappingEvent {
    Create(usize, String),
    Back(usize, u64, usize, bool),
    Map(u64, bool),
    Unmap,
}

#[derive(Clone, Default)]
struct Mapper {
    events: Arc<Mutex<Vec<MappingEvent>>>,
    fault: Arc<AtomicU8>,
}

impl Mapper {
    fn take(&self) -> Vec<MappingEvent> {
        std::mem::take(&mut self.events.lock())
    }

    fn check(&self, stage: u8) -> io::Result<()> {
        if self.fault.load(Ordering::SeqCst) == stage {
            Err(io::Error::other(format!("injected mapping stage {stage}")))
        } else {
            Ok(())
        }
    }
}

struct Region {
    mapper: Mapper,
    mapping: SparseMapping,
}

impl MappedMemoryRegion for Region {
    fn map(
        &self,
        offset: usize,
        section: &dyn AsMappableRef,
        file_offset: u64,
        len: usize,
        writable: bool,
    ) -> io::Result<()> {
        self.mapper
            .events
            .lock()
            .push(MappingEvent::Back(offset, file_offset, len, writable));
        self.mapper.check(2)?;
        self.mapping
            .map_file(offset, len, section, file_offset, writable)
    }

    fn unmap(&self, offset: usize, len: usize) -> io::Result<()> {
        self.mapping.unmap(offset, len)
    }
}

impl MappableGuestMemory for Mapper {
    fn map_to_guest(&mut self, gpa: u64, writable: bool) -> io::Result<()> {
        self.events.lock().push(MappingEvent::Map(gpa, writable));
        self.check(3)
    }

    fn unmap_from_guest(&mut self) {
        self.events.lock().push(MappingEvent::Unmap);
    }
}

impl MemoryMapper for Mapper {
    fn new_region(
        &self,
        len: usize,
        debug_name: String,
    ) -> io::Result<(Box<dyn MappableGuestMemory>, Arc<dyn MappedMemoryRegion>)> {
        self.events
            .lock()
            .push(MappingEvent::Create(len, debug_name));
        self.check(1)?;
        Ok((
            Box::new(self.clone()),
            Arc::new(Region {
                mapper: self.clone(),
                mapping: SparseMapping::new(len)?,
            }),
        ))
    }
}

fn pair() -> (Framebuffer, FramebufferAccess) {
    framebuffer(
        alloc_shared_memory(FRAMEBUFFER_SIZE, "framebuffer-test").unwrap(),
        FRAMEBUFFER_SIZE,
        0,
    )
    .unwrap()
}

fn device() -> (FramebufferDevice, View, Mapper) {
    let (fb, access) = pair();
    let mapper = Mapper::default();
    let device = FramebufferDevice::new(Box::new(mapper.clone()), fb, None).unwrap();
    (device, access.view().unwrap(), mapper)
}

fn format() -> FramebufferFormat {
    FramebufferFormat {
        width: 3,
        height: 2,
        bytes_per_line: 32,
        offset: 64,
    }
}

fn mapped(gpa: u64, offset: u64, len: usize) -> Vec<MappingEvent> {
    vec![
        MappingEvent::Create(len, "framebuffer".to_owned()),
        MappingEvent::Back(0, offset, len, true),
        MappingEvent::Map(gpa, true),
    ]
}

// Test: Read a view before receiving a format, then publish strided pixel data.
// Expected: Unconfigured reads are black; formatted reads honor stride, offset,
//       and visible width without changing the caller's trailing bytes.
#[test]
fn views_read_shared_pixels_and_apply_format_updates() {
    let (fb, access) = pair();
    let mut view = access.view().unwrap();
    assert_eq!(view.resolution(), (1, 1));
    let mut pixels = [0xaa; 16];
    view.read_line(0, &mut pixels);
    assert_eq!(pixels, [0; 16]);
    let sender = fb.format_send();
    let memory = SparseMapping::new(FRAMEBUFFER_SIZE).unwrap();
    let access = view.access();
    memory
        .map_file(0, FRAMEBUFFER_SIZE, &access.vram, 0, true)
        .unwrap();
    memory.write_at(96, b"abcdefghijkl").unwrap();
    let mut view = access.view().unwrap();
    sender.send(format());
    assert_eq!(view.resolution(), (3, 2));
    pixels.fill(0xaa);
    view.read_line(1, &mut pixels);
    assert_eq!(&pixels[..12], b"abcdefghijkl");
    assert_eq!(&pixels[12..], &[0xaa; 4]);
    let mut short = [0; 3];
    view.read_line(1, &mut short);
    assert_eq!(&short, b"abc");
}

// Test: Round-trip an accessor with cached and queued formats and a file offset.
// Expected: The latest format wins, the original backing offset is preserved,
//       and closing the format sender does not erase the last image.
#[test]
fn accessor_round_trips_preserve_offsets_and_pending_updates() {
    let backing = alloc_shared_memory(FRAMEBUFFER_SIZE * 2, "offset-view").unwrap();
    let writer = SparseMapping::new(FRAMEBUFFER_SIZE * 2).unwrap();
    writer
        .map_file(0, FRAMEBUFFER_SIZE * 2, &backing, 0, true)
        .unwrap();
    writer
        .write_at(FRAMEBUFFER_SIZE + 96, b"offset image")
        .unwrap();
    let (fb, access) = framebuffer(backing, FRAMEBUFFER_SIZE, FRAMEBUFFER_SIZE as u64).unwrap();
    let sender = fb.format_send();
    let mut view = access.view().unwrap();
    sender.send(FramebufferFormat {
        width: 2,
        ..format()
    });
    assert_eq!(view.resolution(), (2, 2));
    sender.send(format());
    let mut restored = view.access().view().unwrap();
    assert_eq!(restored.resolution(), (3, 2));
    drop(sender);
    assert_eq!(restored.resolution(), (3, 2));
    let mut pixels = [0; 12];
    restored.read_line(1, &mut pixels);
    assert_eq!(&pixels, b"offset image");
}

// Test: Request a scanline whose stride multiplication or offset addition overflows.
// Expected: Each unrepresentable read produces black pixels without a panic.
#[test]
fn overflowing_scanline_addresses_are_black() {
    let (fb, access) = pair();
    let sender = fb.format_send();
    let mut view = access.view().unwrap();
    for (stride, offset) in [(usize::MAX, 0), (1, usize::MAX)] {
        sender.send(FramebufferFormat {
            bytes_per_line: stride,
            offset,
            ..format()
        });
        assert_eq!(view.resolution(), (3, 2));
        let mut pixels = [0xaa; 12];
        view.read_line(2, &mut pixels);
        assert_eq!(pixels, [0; 12]);
    }
}

// Test: Write through local guest memory, change format, and extract the framebuffer.
// Expected: The view sees shared writes and format changes; extracting the
//       framebuffer preserves its backing and disables obsolete mapping controls.
#[test]
fn local_controls_share_memory_and_publish_only_active_framebuffer_updates() {
    let (device, mut view, mapper) = device();
    let mut control = device.control();
    assert_eq!(view.resolution(), (1024, 768));
    control
        .memory()
        .unwrap()
        .write_at(96, b"shared image")
        .unwrap();
    control.set_format(format());
    control.set_format(format());
    assert_eq!(view.resolution(), (3, 2));
    let mut pixels = [0; 12];
    view.read_line(1, &mut pixels);
    assert_eq!(&pixels, b"shared image");
    let extracted = device.into_framebuffer();
    assert_eq!(extracted.len(), FRAMEBUFFER_SIZE);
    assert_eq!(control.len(), FRAMEBUFFER_SIZE);
    control.map(0x10000, None);
    control.set_format(FramebufferFormat {
        width: 2,
        ..format()
    });
    assert!(mapper.take().is_empty());
    assert_eq!(view.resolution(), (3, 2));
    extracted.format_send().send(format());
    assert_eq!(view.resolution(), (3, 2));
}

// Test: Remap a full framebuffer to a subrange, unmap twice, then reset a mapping.
// Expected: The memory mapper sees exact backing offsets and GPAs, each active
//       mapping is removed once, and reset preserves the visible format.
#[test]
fn mapping_lifecycle_uses_requested_guest_ranges() {
    let (mut device, mut view, mapper) = device();
    let mut control = device.control();
    control.map(0x10000, None);
    assert_eq!(mapper.take(), mapped(0x10000, 0, FRAMEBUFFER_SIZE));
    control.map(0x20000, Some(MemoryRange::new(4096..8192)));
    let mut expected = vec![MappingEvent::Unmap];
    expected.extend(mapped(0x20000, 4096, 4096));
    assert_eq!(mapper.take(), expected);
    control.unmap();
    control.unmap();
    assert_eq!(mapper.take(), [MappingEvent::Unmap]);
    control.set_format(format());
    control.map(0x30000, None);
    mapper.take();
    block_on(async {
        device.start();
        device.stop().await;
        device.reset().await;
        device.reset().await;
    });
    assert_eq!(mapper.take(), [MappingEvent::Unmap]);
    assert_eq!(view.resolution(), (3, 2));
}

// Test: Save a mapped device and restore it onto a fresh framebuffer.
// Expected: The destination recreates the guest mapping and publishes the saved
//       format, while an injected restore failure is returned and retry succeeds.
#[test]
fn snapshots_restore_mapping_and_format_and_report_mapping_failures() {
    let (mut source, _, _) = device();
    source
        .control()
        .map(0x20000, Some(MemoryRange::new(4096..8192)));
    source.control().set_format(format());
    let saved = source.save().unwrap();
    let (mut destination, mut view, mapper) = device();
    mapper.fault.store(3, Ordering::SeqCst);
    let error = destination.restore(saved.clone()).unwrap_err();
    assert!(error.to_string().contains("failed to map VRAM to guest"));
    mapper.take();
    mapper.fault.store(0, Ordering::SeqCst);
    destination.restore(saved).unwrap();
    assert_eq!(mapper.take(), mapped(0x20000, 4096, 4096));
    assert_eq!(view.resolution(), (3, 2));
}

// Test: Create a fixed VTL2 mapping alongside a movable guest mapping.
// Expected: Both use the shared VRAM; moving or resetting the guest mapping
//       does not explicitly unmap the fixed address.
#[test]
fn fixed_mapping_survives_movable_mapping_reset() {
    let (fb, access) = pair();
    let mapper = Mapper::default();
    let mut device = FramebufferDevice::new(Box::new(mapper.clone()), fb, Some(0x800000)).unwrap();
    assert_eq!(
        mapper.take(),
        [
            MappingEvent::Create(FRAMEBUFFER_SIZE, "framebuffer-vtl2".to_owned()),
            MappingEvent::Back(0, 0, FRAMEBUFFER_SIZE, true),
            MappingEvent::Map(0x800000, true),
        ]
    );
    device.control().map(0x10000, None);
    assert_eq!(mapper.take(), mapped(0x10000, 0, FRAMEBUFFER_SIZE));
    block_on(device.reset());
    assert_eq!(mapper.take(), [MappingEvent::Unmap]);
    assert_eq!(access.view().unwrap().resolution(), (1024, 768));
}

// Test: Fail each mapper stage during construction and during a guest remap.
// Expected: Fixed mapping construction fails explicitly; control remapping can
//       retry successfully after the backend recovers without stale unmaps.
#[test]
fn mapper_failures_propagate_or_allow_clean_retry() {
    for stage in 1..=3 {
        let (fb, _) = pair();
        let mapper = Mapper::default();
        mapper.fault.store(stage, Ordering::SeqCst);
        assert!(FramebufferDevice::new(Box::new(mapper), fb, Some(0x800000)).is_err());
        let (device, _, mapper) = device();
        let mut control = device.control();
        control.map(0x10000, None);
        mapper.take();
        mapper.fault.store(stage, Ordering::SeqCst);
        control.map(0x20000, None);
        let events = mapper.take();
        assert_eq!(events[0], MappingEvent::Unmap);
        assert_eq!(events.len(), stage as usize + 1);
        mapper.fault.store(0, Ordering::SeqCst);
        control.map(0x30000, None);
        assert_eq!(mapper.take(), mapped(0x30000, 0, FRAMEBUFFER_SIZE));
    }
}

// Test: Resolve a shared framebuffer resource and use its async control interface.
// Expected: The resolved control maps and unmaps the guest framebuffer and its
//       format updates reach the original view.
#[test]
fn resolved_controls_drive_the_same_framebuffer() {
    let (device, mut view, mapper) = device();
    let ResolvedFramebuffer(mut resolved) = device
        .control()
        .resolve(SharedFramebufferHandle, ())
        .unwrap();
    block_on(async {
        resolved.set_format(format()).await;
        resolved.map(0x40000).await;
        resolved.unmap().await;
    });
    let mut expected = mapped(0x40000, 0, FRAMEBUFFER_SIZE);
    expected.push(MappingEvent::Unmap);
    assert_eq!(mapper.take(), expected);
    assert_eq!(view.resolution(), (3, 2));
}

// Test: Restore an unmapped snapshot onto a fresh device with a different format.
// Expected: No guest mapping is created and the saved format reaches readers.
#[test]
fn unmapped_snapshots_restore_only_the_format() {
    let (mut source, _, _) = device();
    source.control().set_format(format());
    let (mut destination, mut view, mapper) = device();
    destination.restore(source.save().unwrap()).unwrap();
    assert!(mapper.take().is_empty());
    assert_eq!(view.resolution(), (3, 2));
}

// IGNORED: Restoring an unmapped snapshot leaves an existing destination mapping
// active because restore does not remove a mapping absent from the snapshot.
// Test: Restore an unmapped snapshot over a device with mapped VRAM.
// Expected: The destination removes its old mapping to match the snapshot.
#[test]
#[ignore = "product bug: restoring an unmapped snapshot keeps the old mapping"]
fn restoring_unmapped_snapshot_removes_destination_mapping() {
    let (mut source, _, _) = device();
    let (mut destination, _, mapper) = device();
    destination.control().map(0x10000, None);
    mapper.take();
    destination.restore(source.save().unwrap()).unwrap();
    assert_eq!(mapper.take(), [MappingEvent::Unmap]);
}
