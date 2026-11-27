// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod resolver;

use bitfield_struct::bitfield;
use chipset_device::ChipsetDevice;
use chipset_device::interrupt::AcknowledgePicInterrupt;
use chipset_device::interrupt::LineInterruptTarget;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::pio::ControlPortIoIntercept;
use chipset_device::pio::PortIoIntercept;
use chipset_device::pio::RegisterPortIoIntercept;
use inspect::Inspect;
use inspect::InspectMut;
use inspect_counters::Counter;
use vmcore::device_state::ChangeDeviceState;
use vmcore::line_interrupt::LineInterrupt;

const PRIMARY_PIC_COMMAND_PORT: u16 = 0x20;
const PRIMARY_PIC_DATA_PORT: u16 = 0x21;
const SECONDARY_PIC_COMMAND_PORT: u16 = 0xa0;
const SECONDARY_PIC_DATA_PORT: u16 = 0xa1;
const PRIMARY_PIC_ELCR_PORT: u16 = 0x4d0;
const SECONDARY_PIC_ELCR_PORT: u16 = 0x4d1;

// x86 standard dictates we must use IRQ2 for cross-PIC communication.
const PIC_CHAIN_COMMUNICATION_IRQ: u8 = 2;

/// Mask for the IRQ vector within an individual PIC.
const IRQ_MASK: u8 = 0b111;

/// The spurious IRQ offset within an individual PIC.
const SPURIOUS_IRQ: u8 = 7;

#[derive(InspectMut)]
pub struct DualPic {
    // Runtime glue
    ready: LineInterrupt,
    #[inspect(iter_by_index)]
    port_io_regions: [Box<dyn ControlPortIoIntercept>; 3],

    // Runtime book-keeping
    stats: DualPicStats,

    // Volatile state
    #[inspect(flatten, with = r#"|x| inspect::iter_by_index(x).prefix("pic")"#)]
    pics: [Pic; 2],
}

#[derive(Inspect, Default)]
struct DualPicStats {
    #[inspect(iter_by_index)]
    interrupts_per_irq: [Counter; 16],
    interrupts: Counter,
}

impl DualPic {
    pub fn new(ready: LineInterrupt, port_io: &mut dyn RegisterPortIoIntercept) -> Self {
        let mut primary_region = port_io.new_io_region(
            "primary",
            (PRIMARY_PIC_COMMAND_PORT..=PRIMARY_PIC_DATA_PORT).len() as u16,
        );
        let mut secondary_region = port_io.new_io_region(
            "secondary",
            (SECONDARY_PIC_COMMAND_PORT..=SECONDARY_PIC_DATA_PORT).len() as u16,
        );
        let mut elcr_region = port_io.new_io_region(
            "edge_level_control",
            (PRIMARY_PIC_ELCR_PORT..=SECONDARY_PIC_ELCR_PORT).len() as u16,
        );

        primary_region.map(PRIMARY_PIC_COMMAND_PORT);
        secondary_region.map(SECONDARY_PIC_COMMAND_PORT);
        elcr_region.map(PRIMARY_PIC_ELCR_PORT);

        DualPic {
            pics: [Pic::new(true), Pic::new(false)],
            ready,
            port_io_regions: [primary_region, secondary_region, elcr_region],
            stats: Default::default(),
        }
    }

    /// Sync the interrupt outputs of each PIC with their connection (either the
    /// primary PIC or the CPU).
    fn sync_outputs(&mut self) {
        self.pics[0].set_irq(
            PIC_CHAIN_COMMUNICATION_IRQ,
            self.pics[1].interrupt_pending(),
        );
        self.ready.set_level(self.pics[0].interrupt_pending());
    }

    fn set_irq(&mut self, n: u8, high: bool) {
        if n >= 8 {
            self.pics[1].set_irq(n - 8, high);
        } else {
            self.pics[0].set_irq(n, high);
        }
        self.sync_outputs();
    }
}

impl AcknowledgePicInterrupt for DualPic {
    fn acknowledge_interrupt(&mut self) -> Option<u8> {
        let (requested, n) = self.pics[0].acknowledge_interrupt(&mut self.stats);
        let irq = requested.then(|| {
            if n & IRQ_MASK == PIC_CHAIN_COMMUNICATION_IRQ {
                let (requested, m) = self.pics[1].acknowledge_interrupt(&mut self.stats);
                assert!(requested, "pic1 ready was set");
                m
            } else {
                n
            }
        });
        // Sync to ensure the IRQ2 line gets lowered while the secondary PIC's
        // interrupt is in service.
        self.sync_outputs();
        irq
    }
}

impl LineInterruptTarget for DualPic {
    fn set_irq(&mut self, n: u32, high: bool) {
        self.set_irq(n as u8, high);
    }

    fn valid_lines(&self) -> &[std::ops::RangeInclusive<u32>] {
        // IRQ2 is used to cascade the secondary PIC to the primary PIC, so it
        // is not available for use.
        &[0..=1, 3..=15]
    }
}

impl ChangeDeviceState for DualPic {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {
        for pic in &mut self.pics {
            pic.reset(false);
        }
        self.sync_outputs();
    }
}

impl ChipsetDevice for DualPic {
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        Some(self)
    }

    fn supports_line_interrupt_target(&mut self) -> Option<&mut dyn LineInterruptTarget> {
        Some(self)
    }

    fn supports_acknowledge_pic_interrupt(&mut self) -> Option<&mut dyn AcknowledgePicInterrupt> {
        Some(self)
    }
}

impl PortIoIntercept for DualPic {
    fn io_read(&mut self, io_port: u16, data: &mut [u8]) -> IoResult {
        if data.len() != 1 {
            return IoResult::Err(IoError::InvalidAccessSize);
        }
        data[0] = match io_port {
            PRIMARY_PIC_COMMAND_PORT => self.pics[0].read_command(&mut self.stats),
            PRIMARY_PIC_DATA_PORT => self.pics[0].read_data(),
            SECONDARY_PIC_COMMAND_PORT => self.pics[1].read_command(&mut self.stats),
            SECONDARY_PIC_DATA_PORT => self.pics[1].read_data(),
            PRIMARY_PIC_ELCR_PORT => self.pics[0].elcr,
            SECONDARY_PIC_ELCR_PORT => self.pics[1].elcr,
            _ => return IoResult::Err(IoError::InvalidRegister),
        };
        // A poll read acknowledges an interrupt, which can change the outputs.
        self.sync_outputs();
        IoResult::Ok
    }

    fn io_write(&mut self, io_port: u16, data: &[u8]) -> IoResult {
        // Hyper-V-specific optimization: two-byte write to the command
        // port can be used to write to both command ports in a single
        // instruction.
        if data.len() == 2
            && (io_port == PRIMARY_PIC_COMMAND_PORT || io_port == SECONDARY_PIC_COMMAND_PORT)
        {
            let &[mut prim, mut sec] = data else {
                unreachable!()
            };
            if io_port == SECONDARY_PIC_COMMAND_PORT {
                (prim, sec) = (sec, prim);
            }
            self.pics[0].write_command(prim);
            self.pics[1].write_command(sec);
            self.sync_outputs();
            return IoResult::Ok;
        }

        if data.len() != 1 {
            return IoResult::Err(IoError::InvalidAccessSize);
        }

        match io_port {
            PRIMARY_PIC_COMMAND_PORT => self.pics[0].write_command(data[0]),
            PRIMARY_PIC_DATA_PORT => self.pics[0].write_data(data[0]),
            SECONDARY_PIC_COMMAND_PORT => self.pics[1].write_command(data[0]),
            SECONDARY_PIC_DATA_PORT => self.pics[1].write_data(data[0]),
            PRIMARY_PIC_ELCR_PORT => self.pics[0].elcr = data[0],
            SECONDARY_PIC_ELCR_PORT => self.pics[1].elcr = data[0],
            _ => return IoResult::Err(IoError::InvalidRegister),
        }

        self.sync_outputs();
        IoResult::Ok
    }
}

/// The PIC is controlled through two categories of commands:
/// ICWs: Initialization Control Words
/// OCWs: Operation Command Words
#[derive(Debug, Copy, Clone, Inspect)]
struct Pic {
    /// Our current stage of the initialization process.
    init: InitStage,

    /// Whether or not this PIC is the primary in the dual-pic chain.
    #[inspect(skip)]
    primary: bool,

    /// The Interrupt Vector base address, passed in ICW2.
    /// The least significant 3 bits must be 0.
    #[inspect(hex)]
    icw2: u8,

    /// Interrupt Mask Register, also called OCW1
    #[inspect(binary)]
    imr: u8,

    /// The most recently received OCW3
    ocw3: Ocw3,

    /// Interrupt Service Register
    #[inspect(binary)]
    isr: u8,

    /// Edge/Level Control Register
    #[inspect(binary)]
    elcr: u8,

    /// The current status of all the interrupt request lines
    #[inspect(binary)]
    lines: u8,

    /// Whether the line has been low since the last interrupt injection. Used
    /// to track whether an edge-triggered interrupt should be requested when
    /// its line is high.
    #[inspect(binary)]
    line_low_latch: u8,
}

#[derive(Copy, Clone, Debug, Inspect)]
enum InitStage {
    Uninitialized,
    ExpectingIcw2,
    ExpectingIcw3,
    ExpectingIcw4,
    Initialized,
}

impl Pic {
    fn new(primary: bool) -> Self {
        Pic {
            imr: 0,
            init: InitStage::Uninitialized,
            // This is a hack to help set_irq_in_service disambiguate pics before initialization.
            // Set this back to always 0 when that goes away.
            icw2: if primary { 0 } else { 8 },
            ocw3: Ocw3(0),
            isr: 0,
            elcr: 0,
            primary,
            lines: 0,
            line_low_latch: !0,
        }
    }

    /// Resets the PIC state, preserving the line state. If `during_icw1`,
    /// preserve ELCR.
    fn reset(&mut self, during_icw1: bool) {
        *self = Self {
            lines: self.lines,
            elcr: if during_icw1 { self.elcr } else { 0 },
            ..Self::new(self.primary)
        };
    }

    fn irr(&self) -> u8 {
        self.lines & (self.elcr | self.line_low_latch)
    }

    fn set_irq(&mut self, n: u8, high: bool) {
        let bit = 1 << n;
        if high {
            if !matches!(self.init, InitStage::Initialized) {
                tracelimit::warn_ratelimited!(
                    primary = self.primary,
                    ?n,
                    "interrupt request sent to uninitialized PIC"
                );
            }
            self.lines |= bit;
        } else {
            self.lines &= !bit;
            self.line_low_latch |= bit;
        }
    }

    fn ready_vec(&self) -> u8 {
        // Restrict to interrupts with higher priority than the highest priority
        // IRQ already being serviced.
        let highest_isr = self.isr.isolate_lowest_one();
        let higher_not_isr = highest_isr.wrapping_sub(1);
        // Restrict to requested interrupts that are not masked.
        self.irr() & !self.imr & higher_not_isr
    }

    fn interrupt_pending(&self) -> bool {
        self.ready_vec() != 0
    }

    fn pending_line(&self) -> Option<u8> {
        self.ready_vec().lowest_one().map(|n| n as u8)
    }

    fn acknowledge_interrupt(&mut self, stats: &mut DualPicStats) -> (bool, u8) {
        if !matches!(self.init, InitStage::Initialized) {
            tracelimit::warn_ratelimited!(
                primary = self.primary,
                "interrupt servicing sent to uninitialized PIC"
            );
        }

        let (requested, irq) = if let Some(n) = self.pending_line() {
            let bit = 1 << n;
            // Clear the edge latch so that the line must be low again before
            // another interrupt is injected.
            self.line_low_latch &= !bit;
            // Set in service.
            self.isr |= bit;
            stats.interrupts.increment();
            stats.interrupts_per_irq[if self.primary { 0 } else { 8 } + n as usize].increment();
            (true, n)
        } else {
            // spurious interrupt
            (false, SPURIOUS_IRQ)
        };

        // Combine the IRQ with the base address to construct the full interrupt
        // service routine address.
        assert!(self.icw2 & IRQ_MASK == 0);
        (requested, self.icw2 | irq)
    }

    fn eoi(&mut self, n: Option<u8>) {
        tracing::trace!(primary = self.primary, n, "eoi");
        let bit = match n {
            Some(level) => 1 << level,
            // On non-specific EOIs, find the highest priority interrupt in service
            None => self.isr.isolate_lowest_one(),
        };

        self.isr &= !bit;
    }

    fn read_command(&mut self, stats: &mut DualPicStats) -> u8 {
        if self.ocw3.p() {
            self.ocw3.set_p(false);
            let (int, irq) = self.acknowledge_interrupt(stats);
            ((int as u8) << 7) | (irq & IRQ_MASK)
        } else if self.ocw3.rr() {
            if self.ocw3.ris() {
                self.isr
            } else {
                self.irr()
            }
        } else {
            0
        }
    }

    fn read_data(&self) -> u8 {
        self.imr
    }

    fn write_command(&mut self, data: u8) {
        const INIT_BIT: u8 = 0b10000;
        const COMMAND_BIT: u8 = 0b1000;

        if data & INIT_BIT != 0 {
            // ICW1
            // We do not support Single PIC mode or Level Triggered mode.
            // We require IC4 to be set so we can be put in x86 mode in ICW4.
            if data != 0b00010001 {
                tracelimit::error_ratelimited!(primary = self.primary, ?data, "unsupported ICW1");
            }

            self.reset(true);
            self.init = InitStage::ExpectingIcw2;
        } else {
            if !matches!(self.init, InitStage::Initialized) {
                tracelimit::warn_ratelimited!(
                    primary = self.primary,
                    ?data,
                    "OCW sent to uninitialized PIC"
                );
            }
            if data & COMMAND_BIT == 0 {
                let ocw2 = Ocw2(data);

                match (ocw2.r(), ocw2.sl(), ocw2.eoi()) {
                    (true, _, _) | (false, false, false) => {
                        tracelimit::error_ratelimited!(
                            primary = self.primary,
                            ?data,
                            "unsupported OCW2"
                        )
                    }
                    (false, true, true) => self.eoi(Some(ocw2.level())),
                    (false, false, true) => self.eoi(None),
                    (false, true, false) => {} // No-op
                }
            } else {
                self.ocw3 = Ocw3(data);
                // We do not support Special Mask Mode.
                if self.ocw3.esmm() || self.ocw3.smm() {
                    tracelimit::error_ratelimited!(
                        primary = self.primary,
                        ?data,
                        "unsupported OCW3"
                    );
                }
            }
        }
    }

    fn write_data(&mut self, data: u8) {
        match self.init {
            InitStage::Uninitialized | InitStage::Initialized => {
                self.imr = data; // OCW1
            }
            InitStage::ExpectingIcw2 => {
                if data & IRQ_MASK != 0 {
                    tracelimit::error_ratelimited!(primary = self.primary, ?data, "invalid ICW2");
                }
                self.icw2 = data & !IRQ_MASK;
                self.init = InitStage::ExpectingIcw3;
            }
            InitStage::ExpectingIcw3 => {
                // x86 standard dictates we must use IRQ2 for cross-PIC communication.
                if self.primary {
                    if data != (1 << PIC_CHAIN_COMMUNICATION_IRQ) {
                        tracelimit::error_ratelimited!(
                            primary = self.primary,
                            ?data,
                            "invalid primary ICW3"
                        );
                    }
                } else {
                    if data != PIC_CHAIN_COMMUNICATION_IRQ {
                        tracelimit::error_ratelimited!(
                            primary = self.primary,
                            ?data,
                            "invalid secondary ICW3"
                        );
                    }
                }

                self.init = InitStage::ExpectingIcw4;
            }
            InitStage::ExpectingIcw4 => {
                // We do not support any advanced operating modes controlled by ICW4.
                // We require being put into x86 mode.
                if data != 1 {
                    // Linux sends an ICW4 of 3 during boot, then very quickly overwrites it
                    if data == 3 {
                        tracing::debug!(
                            primary = self.primary,
                            "got ICW4 of 3, this is expected for Linux boot but not any other time"
                        );
                    } else {
                        tracelimit::error_ratelimited!(
                            primary = self.primary,
                            ?data,
                            "unsupported ICW4"
                        );
                    }
                };
                self.init = InitStage::Initialized;
            }
        }
    }
}

#[bitfield(u8)]
/// Operation Command Word 2
struct Ocw2 {
    /// Interrupt level
    #[bits(3)]
    level: u8,

    #[bits(2)]
    _command: u8,

    /// End of Interrupt
    eoi: bool,

    /// Selection
    sl: bool,

    /// Rotation
    r: bool,
}

#[derive(Inspect)]
#[bitfield(u8)]
/// Operation Command Word 3
struct Ocw3 {
    /// Read Selector
    ris: bool,

    /// Read Register
    rr: bool,

    /// Polling
    p: bool,

    #[bits(2)]
    _command: u8,

    /// Special Mask Mode
    smm: bool,

    /// Enable Special Mask Mode
    esmm: bool,

    _reserved: bool,
}

mod save_restore {
    use super::DualPic;
    use super::IRQ_MASK;
    use super::InitStage;
    use super::Ocw3;
    use super::Pic;
    use thiserror::Error;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        #[derive(Protobuf, SavedStateRoot)]
        #[mesh(package = "chipset.pic")]
        pub struct SavedState {
            #[mesh(1)]
            pub(super) primary: SavedPic,
            #[mesh(2)]
            pub(super) secondary: SavedPic,
        }

        #[derive(Protobuf)]
        #[mesh(package = "chipset.pic")]
        pub struct SavedPic {
            #[mesh(1)]
            pub init: SavedInitStage,
            #[mesh(2)]
            pub icw2: u8,
            #[mesh(3)]
            pub imr: u8,
            #[mesh(4)]
            pub ocw3: u8,
            #[mesh(5)]
            pub isr: u8,
            #[mesh(6)]
            pub elcr: u8,
            #[mesh(7)]
            pub line_low_latch: u8,
            #[mesh(8)]
            pub lines: Option<u8>,
        }

        #[derive(Protobuf)]
        #[mesh(package = "chipset.pic")]
        pub enum SavedInitStage {
            #[mesh(1)]
            Uninitialized,
            #[mesh(2)]
            ExpectingIcw2,
            #[mesh(3)]
            ExpectingIcw3,
            #[mesh(4)]
            ExpectingIcw4,
            #[mesh(5)]
            Initialized,
        }
    }

    #[derive(Debug, Error)]
    enum Error {
        #[error("invalid icw2 value {0:#x}")]
        InvalidIcw2(u8),
    }

    impl state::SavedPic {
        fn restore(self, pic: &mut Pic) -> Result<(), Error> {
            let Self {
                init,
                icw2,
                imr,
                ocw3,
                isr,
                elcr,
                line_low_latch,
                lines,
            } = self;
            pic.init = match init {
                state::SavedInitStage::Uninitialized => InitStage::Uninitialized,
                state::SavedInitStage::ExpectingIcw2 => InitStage::ExpectingIcw2,
                state::SavedInitStage::ExpectingIcw3 => InitStage::ExpectingIcw3,
                state::SavedInitStage::ExpectingIcw4 => InitStage::ExpectingIcw4,
                state::SavedInitStage::Initialized => InitStage::Initialized,
            };
            if icw2 & IRQ_MASK != 0 {
                return Err(Error::InvalidIcw2(icw2));
            }
            pic.icw2 = icw2;
            pic.imr = imr;
            pic.ocw3 = Ocw3(ocw3);
            pic.isr = isr;
            pic.elcr = elcr;
            pic.line_low_latch = line_low_latch;
            if let Some(lines) = lines {
                pic.lines = lines;
            }
            Ok(())
        }

        fn save(pic: &Pic) -> Self {
            let &Pic {
                init,
                primary: _,
                icw2,
                imr,
                ocw3,
                isr,
                elcr,
                lines,
                line_low_latch,
            } = pic;
            Self {
                init: match init {
                    InitStage::Uninitialized => state::SavedInitStage::Uninitialized,
                    InitStage::ExpectingIcw2 => state::SavedInitStage::ExpectingIcw2,
                    InitStage::ExpectingIcw3 => state::SavedInitStage::ExpectingIcw3,
                    InitStage::ExpectingIcw4 => state::SavedInitStage::ExpectingIcw4,
                    InitStage::Initialized => state::SavedInitStage::Initialized,
                },
                icw2,
                imr,
                ocw3: ocw3.0,
                isr,
                elcr,
                line_low_latch,
                lines: Some(lines),
            }
        }
    }

    impl SaveRestore for DualPic {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            let Self {
                ready: _,
                stats: _,
                port_io_regions: _,
                pics: [primary, secondary],
            } = &self;

            Ok(state::SavedState {
                primary: state::SavedPic::save(primary),
                secondary: state::SavedPic::save(secondary),
            })
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            let state::SavedState { primary, secondary } = state;
            let has_inputs = primary.lines.is_some() && secondary.lines.is_some();
            primary
                .restore(&mut self.pics[0])
                .map_err(|err| RestoreError::Other(err.into()))?;
            secondary
                .restore(&mut self.pics[1])
                .map_err(|err| RestoreError::Other(err.into()))?;
            if has_inputs {
                // Restore the cascade's input history without recognizing a
                // transition. Subsequent input changes use normal recognition.
                self.ready.set_level(self.pics[0].interrupt_pending());
            } else {
                self.sync_outputs();
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::tests::create_pic;
        use super::super::tests::read_register;
        use super::super::*;
        use super::*;
        use pal_async::async_test;
        use test_with_tracing::test;
        use vmcore::save_restore::SavedStateBlob;

        fn consume_cascade(pic: &mut DualPic) {
            pic.set_irq(11, true);
            pic.io_write(PRIMARY_PIC_COMMAND_PORT, &[0x0c]).unwrap();
            let mut data = [0];
            pic.io_read(PRIMARY_PIC_COMMAND_PORT, &mut data).unwrap();
            assert_eq!(data[0], 0x82);
            assert_eq!(read_register(pic, 1, false), 1 << 3);
            assert_eq!(read_register(pic, 0, false), 0);
        }

        // Test: Restore consumed cascade history into fresh and reset controllers.
        // Expected: Input replay creates no IRQ; a later low/high edge does.
        #[async_test]
        async fn restore_preserves_consumed_cascade_on_fresh_and_reset_destinations() {
            let (_, mut source) = create_pic();
            consume_cascade(&mut source);
            let saved = SavedStateBlob::new(source.save().unwrap());
            for reset in [false, true] {
                let (ready, mut destination) = create_pic();
                if reset {
                    destination.set_irq(9, true);
                    destination.reset().await;
                }
                destination.restore(saved.parse().unwrap()).unwrap();
                assert_eq!(read_register(&mut destination, 0, false), 0);
                assert!(!ready());

                // Saving again before updating inputs must preserve the history.
                let saved_again = SavedStateBlob::new(destination.save().unwrap());
                destination.reset().await;
                destination.restore(saved_again.parse().unwrap()).unwrap();
                for n in (0..16).filter(|&n| n != 2) {
                    destination.set_irq(n, n == 11);
                    assert_eq!(read_register(&mut destination, 0, false), 0);
                }

                // EOI the primary before acknowledging the secondary: ISR2
                // must not be hiding a manufactured request.
                destination
                    .io_write(PRIMARY_PIC_COMMAND_PORT, &[0x62])
                    .unwrap();
                assert!(!ready());
                destination.set_irq(11, false);
                assert_eq!(read_register(&mut destination, 0, false), 0);
                destination.set_irq(11, true);
                assert!(ready());
                assert_eq!(destination.acknowledge_interrupt(), Some(0x3b));
            }
        }

        // Test: Restore primary and secondary input history, then update levels.
        // Expected: Ready reflects the restored request and subsequent input.
        #[test]
        fn restored_inputs_preserve_pending_outputs_and_recognize_changes() {
            for irq in [1, 11] {
                for history in [false, true] {
                    for current in [false, true] {
                        let (_, mut source) = create_pic();
                        source.set_irq(irq, history);
                        let saved = SavedStateBlob::new(source.save().unwrap());
                        let (ready, mut destination) = create_pic();
                        destination.restore(saved.parse().unwrap()).unwrap();
                        assert_eq!(ready(), history, "restore must establish the output");
                        destination.set_irq(irq, current);
                        assert_eq!(ready(), current);
                    }
                }
            }
        }

        // Test: Restore legacy checkpoints without recorded input levels.
        // Expected: Replayed cascade input creates a pending, deliverable request.
        #[test]
        fn legacy_restore_retains_provisional_cascade_behavior() {
            let (_, mut source) = create_pic();
            consume_cascade(&mut source);
            let mut saved = source.save().unwrap();
            saved.primary.lines = None;
            saved.secondary.lines = None;
            let saved = SavedStateBlob::new(saved);
            let (ready, mut destination) = create_pic();
            destination.restore(saved.parse().unwrap()).unwrap();
            assert_eq!(read_register(&mut destination, 0, false), 0);
            destination.set_irq(11, true);
            assert_eq!(read_register(&mut destination, 0, false), 4);
            destination
                .io_write(PRIMARY_PIC_COMMAND_PORT, &[0x62])
                .unwrap();
            assert!(ready());
            assert_eq!(destination.acknowledge_interrupt(), Some(0x3b));
        }
    }
}

#[cfg(test)]
mod tests;
