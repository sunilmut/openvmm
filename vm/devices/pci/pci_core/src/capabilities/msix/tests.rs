// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::msi::MsiConnection;
use crate::test_helpers::TestPciInterruptController;
use crate::test_helpers::read_cap_u32;
use crate::test_helpers::write_cap_u32;
use test_with_tracing::test;

// Test: Request irqfd events with fresh handles before backend setup, after failure, and after recovery.
// Expected: Userspace MSI delivery survives failure, a later route succeeds, and event handles alias.
#[test]
fn lazy_route_allocation_recovers_and_reuses_the_same_event() {
    struct FailingIrqFd;
    impl vmcore::irqfd::IrqFd for FailingIrqFd {
        fn new_irqfd_route(&self) -> anyhow::Result<Box<dyn vmcore::irqfd::IrqFdRoute>> {
            anyhow::bail!("injected irqfd allocation failure")
        }
    }
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut emulator, mut capability) = MsixEmulator::new(2, 1, &connection.target());
    emulator.write_u32(0, 0xfee04000);
    emulator.write_u32(8, 0x81);
    emulator.write_u32(12, 0);
    write_cap_u32(&mut capability, 0, 0x80000000);
    let interrupt = emulator.interrupt(0).unwrap();
    assert!(interrupt.event().is_none());
    connection.connect_irqfd(Arc::new(FailingIrqFd));
    let interrupt = emulator.interrupt(0).unwrap();
    assert!(interrupt.event().is_none());
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), Some((0xfee04000, 0x81)));
    let (irqfd, logs) = mock_irqfd(1);
    connection.connect_irqfd(irqfd);
    let first_interrupt = emulator.interrupt(0).unwrap();
    let second_interrupt = emulator.interrupt(0).unwrap();
    let first = first_interrupt.event().unwrap();
    let second = second_interrupt.event().unwrap();
    first.signal();
    assert!(second.try_wait());
    assert!(!first.try_wait());
    assert_eq!(
        *logs[0].lock(),
        [RouteCall::SetMsi {
            address: 0xfee04000,
            data: 0x81
        }]
    );
    assert_eq!(controller.get_next_interrupt(), None);
}

// Test: Attempt to overwrite the MSI-X table and pending-array location registers.
// Expected: Capability identity/size and both locations remain fixed, with pending bits accessible.
#[test]
fn table_and_pending_array_locations_are_read_only() {
    let connection = MsiConnection::new();
    let (emulator, mut capability) = MsixEmulator::new(2, 64, &connection.target());
    assert_eq!(capability.capability_id(), CapabilityId::MSIX);
    assert_eq!(capability.len(), 12);
    emulator.set_pending_bit(63);
    write_cap_u32(&mut capability, 4, u32::MAX);
    write_cap_u32(&mut capability, 8, 0);
    assert_eq!(read_cap_u32(&capability, 4), 2);
    assert_eq!(read_cap_u32(&capability, 8), 0x402);
    assert_eq!(emulator.read_u32(0x404), 0x80000000);
    assert_eq!(read_cap_u32(&capability, 0), 0x003f0011);
}

#[test]
fn msix_check() {
    let msi_conn = MsiConnection::new();
    let (mut msix, mut cap) = MsixEmulator::new(2, 64, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());
    // check capabilities
    assert_eq!(read_cap_u32(&cap, 0), 0x3f0011);
    assert_eq!(read_cap_u32(&cap, 4), 2);
    assert_eq!(read_cap_u32(&cap, 8), 0x402);
    write_cap_u32(&mut cap, 0, 0xffffffff);
    assert_eq!(read_cap_u32(&cap, 0), 0x803f0011);
    // check BAR
    // Vector[0]
    assert_eq!(msix.read_u32(0), 0);
    assert_eq!(msix.read_u32(4), 0);
    assert_eq!(msix.read_u32(8), 0);
    assert_eq!(msix.read_u32(12), 1);
    msix.write_u32(0, 0x12345678);
    msix.write_u32(4, 0x9abcdef0);
    msix.write_u32(8, 0x123);
    msix.write_u32(12, 0x456);
    assert_eq!(msix.read_u32(0), 0x12345678);
    assert_eq!(msix.read_u32(4), 0x9abcdef0);
    assert_eq!(msix.read_u32(8), 0x123);
    assert_eq!(msix.read_u32(12), 0x456);
    // Vector[63]
    assert_eq!(msix.read_u32(0x3f0), 0);
    assert_eq!(msix.read_u32(0x3f4), 0);
    assert_eq!(msix.read_u32(0x3f8), 0);
    assert_eq!(msix.read_u32(0x3fc), 1);
    msix.write_u32(0x3f0, 0x12345678);
    msix.write_u32(0x3f4, 0x9abcdef0);
    msix.write_u32(0x3f8, 0x123);
    msix.write_u32(0x3fc, 0x456);
    assert_eq!(msix.read_u32(0x3f0), 0x12345678);
    assert_eq!(msix.read_u32(0x3f4), 0x9abcdef0);
    assert_eq!(msix.read_u32(0x3f8), 0x123);
    assert_eq!(msix.read_u32(0x3fc), 0x456);
    // Pending Bit Array
    assert_eq!(msix.read_u32(0x400), 0);
    assert_eq!(msix.read_u32(0x404), 0);
    msix.set_pending_bit(1);
    assert_eq!(msix.read_u32(0x400), 2);
    assert_eq!(msix.read_u32(0x404), 0);
    msix.set_pending_bit(33);
    assert_eq!(msix.read_u32(0x400), 2);
    assert_eq!(msix.read_u32(0x404), 2);
    msix.set_pending_bit(63);
    msix.set_pending_bit(31);
    assert_eq!(msix.read_u32(0x400), 0x80000002);
    assert_eq!(msix.read_u32(0x404), 0x80000002);
    msix.clear_pending_bit(1);
    assert_eq!(msix.read_u32(0x400), 0x80000000);
    assert_eq!(msix.read_u32(0x404), 0x80000002);
}

use pal_event::Event;
use parking_lot::Mutex;

/// Record of a call made to a mock route.
#[derive(Debug, Clone, PartialEq)]
enum RouteCall {
    SetMsi { address: u64, data: u32 },
    ClearMsi,
}

/// Mock IrqFdRoute implementation that records calls.
struct MockIrqFdRoute {
    event: Event,
    calls: Arc<Mutex<Vec<RouteCall>>>,
}

impl vmcore::irqfd::IrqFdRoute for MockIrqFdRoute {
    fn event(&self) -> &Event {
        &self.event
    }

    fn enable(&self, address: u64, data: u32, _devid: Option<u32>) {
        self.calls.lock().push(RouteCall::SetMsi { address, data });
    }

    fn disable(&self) {
        self.calls.lock().push(RouteCall::ClearMsi);
    }
}

/// Build a mock IrqFd and shared call logs.
fn mock_irqfd(
    count: usize,
) -> (
    Arc<dyn vmcore::irqfd::IrqFd>,
    Vec<Arc<Mutex<Vec<RouteCall>>>>,
) {
    let mut call_logs = Vec::new();
    let route_params = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..count {
        let calls = Arc::new(Mutex::new(Vec::new()));
        call_logs.push(calls.clone());
        route_params.lock().push(calls);
    }

    struct MockIrqFd {
        routes: Mutex<Vec<Arc<Mutex<Vec<RouteCall>>>>>,
    }
    impl vmcore::irqfd::IrqFd for MockIrqFd {
        fn new_irqfd_route(&self) -> anyhow::Result<Box<dyn vmcore::irqfd::IrqFdRoute>> {
            let calls = self.routes.lock().remove(0);
            Ok(Box::new(MockIrqFdRoute {
                event: Event::new(),
                calls,
            }))
        }
    }

    (
        Arc::new(MockIrqFd {
            routes: Mutex::new(call_logs.clone()),
        }),
        call_logs,
    )
}

#[test]
fn route_set_msi_on_unmask() {
    let (irqfd, calls) = mock_irqfd(2);
    let msi_conn = MsiConnection::new();
    msi_conn.connect_irqfd(irqfd);
    let (mut msix, mut cap) = MsixEmulator::new(2, 2, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Trigger lazy irqfd route creation for all vectors.
    for i in 0..2 {
        msix.interrupt(i).unwrap().event();
    }

    // Enable MSI-X globally.
    write_cap_u32(&mut cap, 0, 0x80000000);

    // Program vector 0 addr/data (still masked — control starts at 1).
    msix.write_u32(0, 0xFEE00000); // addr_lo
    msix.write_u32(4, 0); // addr_hi
    msix.write_u32(8, 0x42); // data

    // No set_msi yet because vector is still masked.
    assert!(
        !calls[0]
            .lock()
            .iter()
            .any(|c| matches!(c, RouteCall::SetMsi { .. }))
    );

    // Unmask vector 0 (write control = 0).
    calls[0].lock().clear();
    msix.write_u32(12, 0);

    // Should have called set_msi to re-establish the route.
    let log = calls[0].lock().clone();
    assert!(log.contains(&RouteCall::SetMsi {
        address: 0xFEE00000,
        data: 0x42
    }));
}

#[test]
fn route_mask_on_vector_mask() {
    let (irqfd, calls) = mock_irqfd(2);
    let msi_conn = MsiConnection::new();
    msi_conn.connect_irqfd(irqfd);
    let (mut msix, mut cap) = MsixEmulator::new(2, 2, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Trigger lazy irqfd route creation for all vectors.
    for i in 0..2 {
        msix.interrupt(i).unwrap().event();
    }

    // Enable MSI-X, program and unmask vector 0.
    write_cap_u32(&mut cap, 0, 0x80000000);
    msix.write_u32(0, 0xFEE00000);
    msix.write_u32(8, 0x42);
    msix.write_u32(12, 0); // unmask

    calls[0].lock().clear();

    // Mask vector 0 (write control = 1).
    msix.write_u32(12, 1);

    let log = calls[0].lock().clone();
    assert!(log.contains(&RouteCall::ClearMsi));
}

#[test]
fn route_global_disable_masks_all() {
    let (irqfd, calls) = mock_irqfd(2);
    let msi_conn = MsiConnection::new();
    msi_conn.connect_irqfd(irqfd);
    let (mut msix, mut cap) = MsixEmulator::new(2, 2, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Trigger lazy irqfd route creation for all vectors.
    for i in 0..2 {
        msix.interrupt(i).unwrap().event();
    }

    // Enable, program, and unmask both vectors.
    write_cap_u32(&mut cap, 0, 0x80000000);
    for v in 0..2u64 {
        msix.write_u32(v * 16, 0xFEE00000);
        msix.write_u32(v * 16 + 8, (v + 1) as u32);
        msix.write_u32(v * 16 + 12, 0); // unmask
    }
    calls[0].lock().clear();
    calls[1].lock().clear();

    // Disable MSI-X globally.
    write_cap_u32(&mut cap, 0, 0);

    // Both vectors should have been disabled.
    assert!(calls[0].lock().contains(&RouteCall::ClearMsi));
    assert!(calls[1].lock().contains(&RouteCall::ClearMsi));
}

#[test]
fn route_consume_pending_on_pba_read() {
    let (irqfd, _calls) = mock_irqfd(2);
    let msi_conn = MsiConnection::new();
    msi_conn.connect_irqfd(irqfd);
    let (msix, mut cap) = MsixEmulator::new(2, 2, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Trigger lazy irqfd route creation for all vectors.
    let events: Vec<_> = (0..2)
        .map(|i| msix.interrupt(i).unwrap().event().unwrap().clone())
        .collect();

    // Enable MSI-X but leave vectors masked (control = 1 by default).
    write_cap_u32(&mut cap, 0, 0x80000000);

    // Simulate a pending interrupt on vector 0 by signaling the event.
    events[0].signal();

    // PBA is at offset = vector_count * 16 = 32.
    let pba = msix.read_u32(32);

    // consume_pending drains the event; PBA bit 0 should be set.
    assert_eq!(pba & 1, 1);
}

#[test]
fn route_set_msi_on_addr_data_change_while_unmasked() {
    let (irqfd, calls) = mock_irqfd(1);
    let msi_conn = MsiConnection::new();
    msi_conn.connect_irqfd(irqfd);
    let (mut msix, mut cap) = MsixEmulator::new(2, 1, &msi_conn.target());
    let msi_controller = TestPciInterruptController::new();
    msi_conn.connect(msi_controller.signal_msi());

    // Trigger lazy irqfd route creation.
    msix.interrupt(0).unwrap().event();

    // Enable, program, unmask.
    write_cap_u32(&mut cap, 0, 0x80000000);
    msix.write_u32(0, 0xFEE00000);
    msix.write_u32(8, 0x42);
    msix.write_u32(12, 0);
    calls[0].lock().clear();

    // Change data while still unmasked.
    msix.write_u32(8, 0x99);

    let log = calls[0].lock().clone();
    assert!(log.contains(&RouteCall::SetMsi {
        address: 0xFEE00000,
        data: 0x99
    }));
}

// Test: Trigger a masked vector repeatedly, unmask it, then disable and re-enable.
// Expected: Pending events coalesce and each enabling transition delivers exactly once.
#[test]
fn masked_pending_interrupts_coalesce_and_reenable_once() {
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut table, mut capability) = MsixEmulator::new(2, 2, &connection.target());
    table.write_u32(0, 0xfee00000);
    table.write_u32(4, 1);
    table.write_u32(8, 0x42);
    let interrupt = table.interrupt(0).unwrap();
    interrupt.deliver();
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), None);
    write_cap_u32(&mut capability, 0, 0x80000000);
    assert_eq!(controller.get_next_interrupt(), None);
    table.write_u32(12, 0);
    assert_eq!(controller.get_next_interrupt(), Some((0x1fee00000, 0x42)));
    assert_eq!(controller.get_next_interrupt(), None);
    write_cap_u32(&mut capability, 0, 0);
    interrupt.deliver();
    assert_eq!(controller.get_next_interrupt(), None);
    write_cap_u32(&mut capability, 0, 0x80000000);
    assert_eq!(controller.get_next_interrupt(), Some((0x1fee00000, 0x42)));
    assert_eq!(controller.get_next_interrupt(), None);
}

// Test: Reset configured vectors and access the PBA and vector boundaries.
// Expected: Registers reset, delivery is disabled, and out-of-range operations are inert.
#[test]
fn reset_clears_table_and_disables_delivery() {
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut table, mut capability) = MsixEmulator::new(2, 3, &connection.target());
    assert_eq!(table.bar_len(), 52);
    write_cap_u32(&mut capability, 0, 0x80000000);
    for index in 0..3 {
        table.write_u32(index * 16, 0xfee00000);
        table.write_u32(index * 16 + 8, 0x40 + index as u32);
        table.write_u32(index * 16 + 12, 0);
    }
    capability.reset();
    assert_eq!(read_cap_u32(&capability, 0), 0x00020011);
    for index in 0..3 {
        assert_eq!(table.read_u32(index * 16), 0);
        assert_eq!(table.read_u32(index * 16 + 4), 0);
        assert_eq!(table.read_u32(index * 16 + 8), 0);
        assert_eq!(table.read_u32(index * 16 + 12), 1);
    }
    table.interrupt(0).unwrap().deliver();
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(48), 1);
    table.write_u32(48, 0);
    assert_eq!(table.read_u32(48), 1);
    assert!(table.interrupt(3).is_none());
    table.set_pending_bit(3);
    assert_eq!(table.read_u32(48), 1);
    table.write_u32(52, u32::MAX);
    assert_eq!(table.read_u32(52), 0);
}

// Test: Save a disabled MSI-X table with a pending vector, reset, and restore it.
// Expected: Registers and PBA survive and enabling delivers the pending message once.
#[test]
fn checkpoint_restores_pending_vector_registers_and_delivery() {
    use vmcore::save_restore::ProtobufSaveRestore;
    let connection = MsiConnection::new();
    let controller = TestPciInterruptController::new();
    connection.connect(controller.signal_msi());
    let (mut table, mut capability) = MsixEmulator::new(2, 2, &connection.target());
    table.write_u32(16, 0xfee01000);
    table.write_u32(20, 2);
    table.write_u32(24, 0x51);
    table.write_u32(28, 0);
    table.set_pending_bit(1);
    let saved = ProtobufSaveRestore::save(&mut capability).unwrap();
    capability.reset();
    assert_eq!(table.read_u32(16), 0);
    ProtobufSaveRestore::restore(&mut capability, saved).unwrap();
    assert_eq!(table.read_u32(16), 0xfee01000);
    assert_eq!(table.read_u32(20), 2);
    assert_eq!(table.read_u32(24), 0x51);
    assert_eq!(table.read_u32(28), 0);
    assert_eq!(table.read_u32(32), 2);
    assert_eq!(controller.get_next_interrupt(), None);
    write_cap_u32(&mut capability, 0, 0x80000000);
    assert_eq!(controller.get_next_interrupt(), Some((0x2fee01000, 0x51)));
    assert_eq!(controller.get_next_interrupt(), None);
    assert_eq!(table.read_u32(32), 0);
}

// Test: Restore a saved MSI-X capability into a different vector count.
// Expected: The checkpoint is rejected as invalid saved state.
#[test]
fn checkpoint_rejects_mismatched_vector_count() {
    use vmcore::save_restore::ProtobufSaveRestore;
    let connection = MsiConnection::new();
    let (_, mut source) = MsixEmulator::new(2, 1, &connection.target());
    let saved = ProtobufSaveRestore::save(&mut source).unwrap();
    let (_, mut destination) = MsixEmulator::new(2, 2, &connection.target());
    assert!(matches!(
        ProtobufSaveRestore::restore(&mut destination, saved),
        Err(vmcore::save_restore::RestoreError::InvalidSavedState(_))
    ));
}

mod reference_tests;
