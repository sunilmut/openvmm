// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::ControlWord;
use super::Mode;
use super::RwMode;
use super::Timer;
use super::to_bcd;
use super::{NANOS_PER_TICK, PitDevice};
use crate::pit::from_bcd;
use chipset_device::ChipsetDevice;
use chipset_device::io::{IoError, IoResult};
use chipset_device::pio::PortIoIntercept;
use chipset_device::poll_device::PollDevice;
use pal_async::{DefaultDriver, async_test};
use parking_lot::Mutex;
use std::sync::Arc;
use std::task::{Context, Waker};
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;
use vmcore::line_interrupt::LineInterrupt;
use vmcore::line_interrupt::LineSetTarget;
use vmcore::save_restore::SaveRestore;
use vmcore::vmtime::{VmTime, VmTimeKeeper};

#[derive(Default)]
struct RecordingTarget(Mutex<Vec<bool>>);

impl LineSetTarget for RecordingTarget {
    fn set_irq(&self, _vector: u32, high: bool) {
        self.0.lock().push(high);
    }
}

async fn new_pit(driver: &DefaultDriver) -> (VmTimeKeeper, PitDevice, Arc<RecordingTarget>) {
    let time = VmTimeKeeper::new(driver, VmTime::from_100ns(0));
    let source = time.builder().build(driver).await.unwrap();
    let target = Arc::new(RecordingTarget::default());
    let device = PitDevice::new(
        LineInterrupt::new_with_target("pit", target.clone(), 0),
        source.access("pit_test"),
    );
    (time, device, target)
}

async fn set_tick(time: &mut VmTimeKeeper, tick: u64) {
    time.restore(vmcore::vmtime::SavedState::from_vmtime(VmTime::from_100ns(
        (tick * NANOS_PER_TICK).div_ceil(100),
    )))
    .await;
}

fn port_write(device: &mut PitDevice, port: u16, value: u8) {
    device
        .supports_pio()
        .unwrap()
        .io_write(port, &[value])
        .unwrap();
}

fn port_read(device: &mut PitDevice, port: u16) -> u8 {
    let mut value = [0];
    device.io_read(port, &mut value).unwrap();
    value[0]
}

// Test: Program channel 0 terminal-count mode and advance stopped VM time to expiration.
// Expected: IRQ0 stays low through the count and rises only after the reload plus terminal tick.
#[async_test]
async fn channel0_terminal_count_drives_irq_at_the_programmed_boundary(driver: DefaultDriver) {
    let (mut time, mut device, target) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0x30);
    port_write(&mut device, 0x40, 100);
    port_write(&mut device, 0x40, 0);
    set_tick(&mut time, 100).await;
    port_read(&mut device, 0x61);
    assert!(!target.0.lock().last().copied().unwrap_or(false));
    set_tick(&mut time, 101).await;
    port_read(&mut device, 0x61);
    assert_eq!(target.0.lock().last().copied(), Some(true));
    device.reset().await;
    assert_eq!(target.0.lock().last().copied(), Some(false));
}

// Test: Snapshot a latched count after its low byte is read, then restore and advance time.
// Expected: The saved high byte stays latched while a subsequent latch reflects elapsed ticks.
#[async_test]
async fn checkpoint_preserves_latched_count_and_high_byte_read_phase(driver: DefaultDriver) {
    let (mut time, mut device, _) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0x30);
    port_write(&mut device, 0x40, 2);
    port_write(&mut device, 0x40, 1);
    set_tick(&mut time, 3).await;
    port_write(&mut device, 0x43, 0xc2);
    assert_eq!(port_read(&mut device, 0x40), 0x30);
    assert_eq!(port_read(&mut device, 0x40), 0);
    let saved = device.save().unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    set_tick(&mut time, 100).await;
    assert_eq!(port_read(&mut device, 0x40), 1);
    port_write(&mut device, 0x43, 0);
    assert_eq!(port_read(&mut device, 0x40), 0x9f);
    assert_eq!(port_read(&mut device, 0x40), 0);
}

// Test: Program channel 2 with its gate low, then raise it through port 0x61.
// Expected: Counting waits for the gate; terminal output and alternating refresh bits are readable.
#[async_test]
async fn channel2_gate_and_output_are_observable_through_port61(driver: DefaultDriver) {
    let (mut time, mut device, _) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0xb0);
    port_write(&mut device, 0x42, 3);
    port_write(&mut device, 0x42, 0);
    set_tick(&mut time, 10).await;
    assert_eq!(port_read(&mut device, 0x61) & 0x21, 0);
    port_write(&mut device, 0x61, 1);
    assert_eq!(port_read(&mut device, 0x61) & 1, 1);
    set_tick(&mut time, 20).await;
    let first = port_read(&mut device, 0x61);
    let second = port_read(&mut device, 0x61);
    assert_eq!(first & 0x21, 0x21);
    assert_eq!(second & 0x21, 0x21);
    assert_eq!(first ^ second, 0x10);
}

// Test: Advance channel 0 past its deadline and poll without doing guest port reads.
// Expected: Polling alone raises IRQ0 at expiration and a pending poll leaves it low beforehand.
#[async_test]
async fn timeout_poll_delivers_the_pit_interrupt_without_guest_io(driver: DefaultDriver) {
    let (mut time, mut device, target) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0x30);
    port_write(&mut device, 0x40, 100);
    port_write(&mut device, 0x40, 0);
    let mut context = Context::from_waker(Waker::noop());
    set_tick(&mut time, 100).await;
    device
        .supports_poll_device()
        .unwrap()
        .poll_device(&mut context);
    assert!(!target.0.lock().last().copied().unwrap_or(false));
    set_tick(&mut time, 101).await;
    device.poll_device(&mut context);
    assert_eq!(target.0.lock().last().copied(), Some(true));
}

// Test: Program channel 1 using low-only and high-only counter access modes.
// Expected: Each mode loads and returns the selected byte without requiring a second data write.
#[async_test]
async fn single_byte_counter_modes_load_and_read_the_selected_byte(driver: DefaultDriver) {
    let (mut time, mut device, _) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0x50);
    port_write(&mut device, 0x41, 0x56);
    set_tick(&mut time, 1).await;
    assert_eq!(port_read(&mut device, 0x41), 0x56);
    port_write(&mut device, 0x43, 0x60);
    port_write(&mut device, 0x41, 0x12);
    set_tick(&mut time, 2).await;
    assert_eq!(port_read(&mut device, 0x41), 0x12);
    assert_eq!(port_read(&mut device, 0x43), u8::MAX);
}

// Test: Snapshot a partial word write and perform malformed accesses before finishing it.
// Expected: Errors preserve the staged low byte; restore and the final high byte load the full word.
#[async_test]
async fn checkpoint_and_invalid_accesses_preserve_partial_counter_writes(driver: DefaultDriver) {
    let (mut time, mut device, _) = new_pit(&driver).await;
    port_write(&mut device, 0x43, 0x30);
    port_write(&mut device, 0x40, 0x34);
    let saved = device.save().unwrap();
    device.reset().await;
    device.restore(saved).unwrap();
    for size in [0, 2, 4] {
        let mut data = vec![0xa5; size];
        assert!(matches!(
            device.io_read(0x40, &mut data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
        assert_eq!(data, vec![0xa5; size]);
        assert!(matches!(
            device.io_write(0x40, &data),
            IoResult::Err(IoError::InvalidAccessSize)
        ));
    }
    assert!(matches!(
        device.io_read(0x44, &mut [0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    assert!(matches!(
        device.io_write(0x44, &[0]),
        IoResult::Err(IoError::InvalidRegister)
    ));
    port_write(&mut device, 0x40, 0x12);
    set_tick(&mut time, 1).await;
    assert_eq!(port_read(&mut device, 0x40), 0x34);
    assert_eq!(port_read(&mut device, 0x40), 0x12);
    assert_eq!(
        device.get_static_regions(),
        &[("main", 0x40..=0x43), ("port61", 0x61..=0x61)]
    );
}

// Test: Restore a PIT checkpoint whose last-tick timestamp is later than current VM time.
// Expected: Restore rejects the invalid time relationship with InvalidSavedState.
#[async_test]
async fn future_last_tick_checkpoint_is_rejected(driver: DefaultDriver) {
    let (_time, mut device, _) = new_pit(&driver).await;
    let mut saved = device.save().unwrap();
    saved.last = VmTime::from_100ns(1);
    assert!(matches!(
        device.restore(saved),
        Err(vmcore::save_restore::RestoreError::InvalidSavedState(_))
    ));
}

#[test]
fn test_bcd_comp() {
    for i in 0..=9999 {
        assert_eq!(from_bcd(to_bcd(i)), i, "{i} {}", to_bcd(i));
    }
}

fn set_timer(timer: &mut Timer, mode: Mode, mut cr: u16, bcd: bool) {
    timer.set_control(
        ControlWord::new()
            .with_mode(mode as u8)
            .with_rw(RwMode::LOW_HIGH.0)
            .with_bcd(bcd),
    );
    if bcd {
        cr = to_bcd(cr);
    }
    timer.write(cr as u8);
    timer.write((cr >> 8) as u8);
}

fn set_low_byte_timer(timer: &mut Timer, mode: Mode, cr: u8) {
    timer.set_control(
        ControlWord::new()
            .with_mode(mode as u8)
            .with_rw(RwMode::LOW.0),
    );
    timer.write(cr);
}

fn check_invert(timer: &mut Timer, initial_out: bool, expected_next: u64) {
    let mode = Mode::from(timer.state.control.mode());
    assert_eq!(timer.state.out, initial_out, "{mode:?}");
    let n = timer.state.next_wakeup().unwrap();
    assert_eq!(n, expected_next, "{mode:?}");
    for i in 0..n - 1 {
        timer.evaluate(1);
        assert_eq!(
            i + timer.state.next_wakeup().unwrap() + 1,
            n,
            "{mode:?}, {i}"
        );
        assert_eq!(timer.state.out, initial_out, "{mode:?}, {i}");
    }
    timer.evaluate(1);
    assert_eq!(timer.state.out, !initial_out, "{mode:?}, {n}");
}

fn check_done(timer: &mut Timer) {
    assert!(timer.state.next_wakeup().is_none());
    let out = timer.state.out;
    for _ in 0..65536 {
        timer.evaluate(1);
        assert_eq!(timer.state.out, out);
    }
}

fn test_output(bcd: bool) {
    let mut timer = Timer::new(true, None);
    let max = if bcd { 10000 } else { 0x10000 };

    set_timer(&mut timer, Mode::TerminalCount, 0, bcd);
    check_invert(&mut timer, false, max + 1);
    check_done(&mut timer);

    set_timer(&mut timer, Mode::HardwareOneShot, 0, bcd);
    check_done(&mut timer);
    timer.set_gate(false);
    timer.set_gate(true);
    check_invert(&mut timer, false, max + 1);
    check_done(&mut timer);

    set_timer(&mut timer, Mode::RateGenerator, 0, bcd);
    check_invert(&mut timer, true, max);
    check_invert(&mut timer, false, 1);
    check_invert(&mut timer, true, max - 1);

    set_timer(&mut timer, Mode::SquareWave, 0, bcd);
    check_invert(&mut timer, true, max / 2 + 1);
    check_invert(&mut timer, false, max / 2);
    check_invert(&mut timer, true, max / 2);

    set_timer(&mut timer, Mode::SquareWave, 1001, bcd);
    check_invert(&mut timer, true, 502);
    check_invert(&mut timer, false, 500);
    check_invert(&mut timer, true, 501);

    set_timer(&mut timer, Mode::SoftwareStrobe, 0, bcd);
    check_invert(&mut timer, true, max + 1);
    check_invert(&mut timer, false, 1);
    check_done(&mut timer);

    set_timer(&mut timer, Mode::HardwareStrobe, 0, bcd);
    check_done(&mut timer);
    timer.set_gate(false);
    timer.set_gate(true);
    check_invert(&mut timer, true, max + 1);
    check_invert(&mut timer, false, 1);
    check_done(&mut timer);
}

#[test]
fn test_binary() {
    test_output(false);
}

#[test]
fn test_bcd() {
    test_output(true);
}

#[test]
fn elapsed_interval_matches_incremental_pit_evaluation() {
    for mode in [
        Mode::TerminalCount,
        Mode::RateGenerator,
        Mode::SquareWave,
        Mode::SoftwareStrobe,
    ] {
        let mut elapsed = Timer::new(true, None);
        let mut incremental = Timer::new(true, None);
        set_timer(&mut elapsed, mode, 100, false);
        set_timer(&mut incremental, mode, 100, false);

        elapsed.evaluate(350);
        for _ in 0..350 {
            incremental.evaluate(1);
        }

        assert_eq!(elapsed.state, incremental.state, "{mode:?}");
    }
}

#[test]
fn elapsed_interval_preserves_periodic_phase() {
    let mut timer = Timer::new(true, None);
    set_timer(&mut timer, Mode::RateGenerator, 100, false);

    timer.evaluate(350);

    assert_eq!(timer.state.ce, 51);
    assert!(timer.state.out);
    assert_eq!(timer.state.next_wakeup(), Some(50));
}

#[test]
fn long_elapsed_interval_fast_forwards_periodic_pit() {
    for mode in [Mode::RateGenerator, Mode::SquareWave] {
        for (count, bcd) in [
            (100, false),
            (1234, true),
            (3, false),
            (3, true),
            (1001, false),
            (1001, true),
            (0, false),
            (0, true),
            (1, false),
            (1, true),
        ] {
            let counter_range = if bcd { 10_000 } else { 0x1_0000 };
            let period = if count == 0 {
                counter_range
            } else if count == 1 && mode == Mode::SquareWave {
                counter_range + 1
            } else {
                u64::from(count)
            };

            let mut elapsed = Timer::new(true, None);
            let mut incremental = Timer::new(true, None);
            set_timer(&mut elapsed, mode, count, bcd);
            set_timer(&mut incremental, mode, count, bcd);
            elapsed.evaluate(1);
            incremental.evaluate(1);

            let phased_ticks = period * 2 + period / 3;
            elapsed.evaluate(phased_ticks);
            for _ in 0..phased_ticks {
                incremental.evaluate(1);
            }
            assert_eq!(
                elapsed.state, incremental.state,
                "{mode:?}, count={count}, bcd={bcd}"
            );

            let mut elapsed = Timer::new(true, None);
            let mut remainder = Timer::new(true, None);
            set_timer(&mut elapsed, mode, count, bcd);
            set_timer(&mut remainder, mode, count, bcd);
            elapsed.evaluate(1);
            remainder.evaluate(1);

            elapsed.evaluate(u64::MAX);
            remainder.evaluate(u64::MAX % period);
            assert_eq!(
                elapsed.state, remainder.state,
                "{mode:?}, count={count}, bcd={bcd}"
            );
        }
    }
}

#[test]
fn periodic_fast_forward_matches_incremental_from_each_phase() {
    for mode in [Mode::RateGenerator, Mode::SquareWave] {
        for bcd in [false, true] {
            for count in [2, 3, 100, 1001] {
                let period = u64::from(count);
                for phase in [0, 1, period / 2, period / 2 + 1, period - 1] {
                    let mut initial = Timer::new(true, None);
                    set_timer(&mut initial, mode, count, bcd);
                    initial.evaluate(1);
                    for _ in 0..phase {
                        initial.evaluate(1);
                    }

                    for ticks in [
                        period - 1,
                        period,
                        period + 1,
                        period * 3 - 1,
                        period * 3,
                        period * 3 + 1,
                    ] {
                        let mut elapsed = Timer::new(true, None);
                        let mut incremental = Timer::new(true, None);
                        elapsed.state = initial.state;
                        incremental.state = initial.state;

                        elapsed.evaluate(ticks);
                        for _ in 0..ticks {
                            incremental.evaluate(1);
                        }

                        assert_eq!(
                            elapsed.state, incremental.state,
                            "{mode:?}, count={count}, bcd={bcd}, phase={phase}, ticks={ticks}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn count_one_rate_generator_does_not_emit_irq0_edges() {
    for bcd in [false, true] {
        let target = Arc::new(RecordingTarget::default());
        let interrupt = LineInterrupt::new_with_target("pit", target.clone(), 0);
        let mut timer = Timer::new(true, Some(interrupt));
        set_timer(&mut timer, Mode::RateGenerator, 1, bcd);
        timer.evaluate(1);
        target.0.lock().clear();
        let active_state = timer.state;

        timer.evaluate(u64::MAX);

        assert_eq!(timer.state, active_state, "bcd={bcd}");
        assert!(target.0.lock().is_empty(), "bcd={bcd}");
    }
}

#[test]
fn reprogrammed_periodic_count_loads_before_fast_forward() {
    for mode in [Mode::RateGenerator, Mode::SquareWave] {
        let mut elapsed = Timer::new(true, None);
        let mut incremental = Timer::new(true, None);
        set_low_byte_timer(&mut elapsed, mode, 100);
        set_low_byte_timer(&mut incremental, mode, 100);
        elapsed.evaluate(1);
        incremental.evaluate(1);
        elapsed.write(100);
        incremental.write(100);

        elapsed.evaluate(100);
        for _ in 0..100 {
            incremental.evaluate(1);
        }

        assert_eq!(elapsed.state, incremental.state, "{mode:?}");
        assert!(!elapsed.state.null, "{mode:?}");
    }

    let target = Arc::new(RecordingTarget::default());
    let interrupt = LineInterrupt::new_with_target("pit", target.clone(), 0);
    let mut timer = Timer::new(true, Some(interrupt));
    set_low_byte_timer(&mut timer, Mode::RateGenerator, 4);
    timer.evaluate(4);
    timer.write(1);
    target.0.lock().clear();
    assert!(timer.state.null);
    assert!(!timer.state.out);

    timer.evaluate(u64::MAX);

    assert!(!timer.state.null);
    assert!(timer.state.out);
    assert_eq!(*target.0.lock(), [true]);
}

#[test]
fn low_gate_pauses_periodic_fast_forward() {
    for mode in [Mode::RateGenerator, Mode::SquareWave] {
        let target = Arc::new(RecordingTarget::default());
        let interrupt = LineInterrupt::new_with_target("pit", target.clone(), 0);
        let mut timer = Timer::new(true, Some(interrupt));
        set_timer(&mut timer, mode, 100, false);
        timer.evaluate(1);
        timer.set_gate(false);
        target.0.lock().clear();
        let paused_state = timer.state;

        timer.evaluate(u64::MAX);

        assert_eq!(timer.state, paused_state, "{mode:?}");
        assert!(target.0.lock().is_empty(), "{mode:?}");
    }
}

#[test]
fn long_elapsed_interval_coalesces_periodic_irq0_edges() {
    let target = Arc::new(RecordingTarget::default());
    let interrupt = LineInterrupt::new_with_target("pit", target.clone(), 0);
    let mut timer = Timer::new(true, Some(interrupt));
    set_timer(&mut timer, Mode::RateGenerator, 2, false);
    timer.evaluate(1);
    target.0.lock().clear();

    timer.evaluate(u64::MAX - 1);

    assert_eq!(*target.0.lock(), [false, true]);
    assert!(timer.state.out);
}
