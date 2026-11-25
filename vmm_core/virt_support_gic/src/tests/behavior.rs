// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Distributor;
use crate::Redistributor;
use aarch64defs::SystemReg;
use aarch64defs::gic::GicdRegister as D;
use aarch64defs::gic::GicrRdRegister as R;
use aarch64defs::gic::GicrSgi;
use aarch64defs::gic::GicrSgiRegister as S;
use aarch64defs::gic::GicrTyper;
use memory_range::MemoryRange;
use test_with_tracing::test;
use vm_topology::processor::VpIndex;

const DIST: u64 = 0x10000;
const REDIST: u64 = 0x40000;
const STRIDE: u64 = aarch64defs::GIC_REDISTRIBUTOR_SIZE;

fn controller() -> (Distributor, [Redistributor; 3]) {
    let mut distributor =
        Distributor::new(DIST, MemoryRange::new(REDIST..REDIST + 4 * STRIDE), 160);
    let first = distributor.add_redistributor(0, false);
    let second = distributor.add_redistributor(1, false);
    let third = distributor.add_redistributor(0x0000_0002_0003_0402, true);
    (distributor, [first, second, third])
}

fn read32(distributor: &Distributor, address: u64) -> u32 {
    let mut bytes = [0; 4];
    assert!(distributor.read(address, &mut bytes));
    u32::from_le_bytes(bytes)
}

fn write32(distributor: &Distributor, address: u64, value: u32) {
    assert!(distributor.write(address, &value.to_le_bytes()));
}

fn read64(distributor: &Distributor, address: u64) -> u64 {
    let mut bytes = [0; 8];
    assert!(distributor.read(address, &mut bytes));
    u64::from_le_bytes(bytes)
}

fn sgi_address(vp: u64, register: S) -> u64 {
    REDIST + vp * STRIDE + 0x10000 + u64::from(register.0)
}

// Test: Program shared-interrupt grouping, enable, active, priority, trigger and affinity banks.
// Expected: Aliases implement set/clear semantics, reserved trigger bits clear, and banks stay distinct.
#[test]
fn distributor_mmio_bank_programming_and_aliases() {
    let (distributor, _) = controller();
    write32(&distributor, DIST + u64::from(D::CTLR.0), 3);
    assert_eq!(read32(&distributor, DIST + u64::from(D::CTLR.0)), 0x53);
    write32(&distributor, DIST + u64::from(D::CTLR.0), 0);
    assert_eq!(read32(&distributor, DIST + u64::from(D::CTLR.0)), 0x50);
    let group = DIST + u64::from(D::IGROUPR.start) + 4;
    write32(&distributor, group, 0x1234_5678);
    assert_eq!(read32(&distributor, group), 0x1234_5678);
    for (set, clear) in [
        (D::ISENABLER.start, D::ICENABLER.start),
        (D::ISACTIVER.start, D::ICACTIVER.start),
    ] {
        let set = DIST + u64::from(set) + 4;
        let clear = DIST + u64::from(clear) + 4;
        write32(&distributor, set, 0xa5);
        write32(&distributor, set, 0x0f);
        assert_eq!(read32(&distributor, set), 0xaf);
        assert_eq!(read32(&distributor, clear), 0xaf);
        write32(&distributor, clear, 0x0a);
        assert_eq!(read32(&distributor, set), 0xa5);
    }
    let config = DIST + u64::from(D::ICFGR.start) + 8;
    write32(&distributor, config, u32::MAX);
    assert_eq!(read32(&distributor, config), 0xaaaa_aaaa);
    let priority = DIST + u64::from(D::IPRIORITYR.start) + 32;
    write32(&distributor, priority, 0x1020_3040);
    assert_eq!(read32(&distributor, priority), 0x1020_3040);
    let route = DIST + u64::from(D::IROUTER.start) + 32 * 8;
    assert!(distributor.write(route, &0x0000_0002_0003_0402u64.to_le_bytes()));
    assert_eq!(read64(&distributor, route), 0x0000_0002_0003_0402);
    assert_eq!(read64(&distributor, route + 8), 0);
    distributor.set_pending(40, true);
    assert_eq!(
        read32(&distributor, DIST + u64::from(D::ISPENDR.start) + 4),
        1 << 8
    );
    assert_eq!(
        read32(&distributor, DIST + u64::from(D::ICPENDR.start) + 4),
        1 << 8
    );
}

// Test: Access private and unimplemented shared interrupt banks through distributor MMIO.
// Expected: These registers are read-as-zero/write-ignored and cannot change a valid neighboring bank.
#[test]
fn distributor_reserved_and_unimplemented_banks_do_not_alias() {
    let (distributor, _) = controller();
    for bank in [
        D::IGROUPR,
        D::ISENABLER,
        D::ICENABLER,
        D::ISACTIVER,
        D::ICACTIVER,
    ] {
        for offset in [bank.start, bank.end - 4] {
            let address = DIST + u64::from(offset);
            write32(&distributor, address, u32::MAX);
            assert_eq!(read32(&distributor, address), 0);
        }
    }
    for (start, private, missing) in [(D::ICFGR.start, 0, 0xfc), (D::IPRIORITYR.start, 0, 0x3fc)] {
        for offset in [private, missing] {
            let address = DIST + u64::from(start) + offset;
            write32(&distributor, address, u32::MAX);
            assert_eq!(read32(&distributor, address), 0);
        }
    }
    let private_route = DIST + u64::from(D::IROUTER.start);
    assert!(distributor.write(private_route, &u64::MAX.to_le_bytes()));
    assert_eq!(read64(&distributor, private_route), 0);
    assert_eq!(
        read32(&distributor, DIST + u64::from(D::IGROUPR.start) + 4),
        0
    );
}

// Test: Change per-CPU sleep, grouping, enable, active, priority and trigger registers.
// Expected: CPU banks are isolated, aliases clear selected bits, and MPIDR/last identification is stable.
#[test]
fn redistributor_register_banks_are_isolated_and_identify_affinity() {
    let (distributor, _) = controller();
    let third = REDIST + 2 * STRIDE;
    let typer = GicrTyper::from(read64(&distributor, third + u64::from(R::TYPER.0)));
    assert_eq!(
        (
            typer.aff3(),
            typer.aff2(),
            typer.aff1(),
            typer.aff0(),
            typer.last()
        ),
        (2, 3, 4, 2, true)
    );
    assert!(!GicrTyper::from(read64(&distributor, REDIST + u64::from(R::TYPER.0))).last());
    assert!(distributor.write(third + u64::from(R::TYPER.0), &u64::MAX.to_le_bytes()));
    assert_eq!(
        read64(&distributor, third + u64::from(R::TYPER.0)),
        u64::from(typer)
    );
    write32(&distributor, third + u64::from(R::WAKER.0), 2);
    assert_eq!(read32(&distributor, third + u64::from(R::WAKER.0)), 6);
    assert_eq!(read32(&distributor, REDIST + u64::from(R::WAKER.0)), 0);
    write32(&distributor, third + u64::from(R::WAKER.0), 0);
    assert_eq!(read32(&distributor, third + u64::from(R::WAKER.0)), 0);
    write32(&distributor, third + u64::from(R::CTLR.0), u32::MAX);
    assert_eq!(read32(&distributor, third + u64::from(R::CTLR.0)), 0);
    write32(&distributor, sgi_address(2, S::IGROUPR0), 0xa5a5_a5a5);
    assert_eq!(
        read32(&distributor, sgi_address(2, S::IGROUPR0)),
        0xa5a5_a5a5
    );
    assert_eq!(read32(&distributor, sgi_address(0, S::IGROUPR0)), 0);
    for (set, clear) in [
        (S::ISENABLER0, S::ICENABLER0),
        (S::ISACTIVER0, S::ICACTIVER0),
    ] {
        write32(&distributor, sgi_address(2, set), 0x0f);
        write32(&distributor, sgi_address(2, set), 0xa0);
        assert_eq!(read32(&distributor, sgi_address(2, clear)), 0xaf);
        write32(&distributor, sgi_address(2, clear), 0x0a);
        assert_eq!(read32(&distributor, sgi_address(2, set)), 0xa5);
        assert_eq!(read32(&distributor, sgi_address(1, set)), 0);
    }
    write32(&distributor, sgi_address(2, S::ICFGR0), 0);
    assert_eq!(read32(&distributor, sgi_address(2, S::ICFGR0)), 0xaaaa_aaaa);
    write32(&distributor, sgi_address(2, S::ICFGR1), 0xaaaa_0000);
    assert_eq!(read32(&distributor, sgi_address(2, S::ICFGR1)), 0xaaaa_0000);
    for index in 0..8 {
        let address = sgi_address(2, S::IPRIORITYR0) + index * 4;
        write32(&distributor, address, 0x1234_5600 + index as u32);
        assert_eq!(read32(&distributor, address), 0x1234_5600 + index as u32);
        assert_eq!(
            read32(&distributor, sgi_address(0, S::IPRIORITYR0) + index * 4),
            0
        );
    }
}

// Test: Raise a private interrupt twice and re-raise it while active on a non-primary CPU.
// Expected: Wake transitions coalesce, acknowledgement suppresses delivery until EOI, and CPUs stay isolated.
#[test]
fn private_interrupt_delivery_coalesces_until_end_of_interrupt() {
    let (distributor, [first, mut second, third]) = controller();
    write32(&distributor, sgi_address(1, S::IGROUPR0), 1 << 17);
    write32(&distributor, sgi_address(1, S::ISENABLER0), 1 << 17);
    assert!(distributor.raise_ppi(VpIndex::new(1), 17));
    assert!(!distributor.raise_ppi(VpIndex::new(1), 17));
    assert!(!distributor.raise_ppi(VpIndex::new(99), 17));
    assert!(distributor.irq_pending(&second));
    assert!(!distributor.irq_pending(&first));
    assert!(!distributor.irq_pending(&third));
    assert_eq!(read32(&distributor, sgi_address(1, S::ISPENDR0)), 1 << 17);
    assert_eq!(read32(&distributor, sgi_address(1, S::ICPENDR0)), 1 << 17);
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(17)
    );
    assert!(second.is_pending_or_active(17));
    assert!(distributor.raise_ppi(VpIndex::new(1), 17));
    assert!(!distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(1023)
    );
    assert!(
        distributor.write_sysreg(&mut second, SystemReg::ICC_EOIR1_EL1, 17, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert!(distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(17)
    );
    assert!(
        distributor.write_sysreg(&mut second, SystemReg::ICC_EOIR1_EL1, 17, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert!(!second.is_pending_or_active(17));
}

// Test: Target SGIs by affinity, broadcast to other CPUs, and repeat an already pending SGI.
// Expected: Only matching CPUs wake, duplicate notifications coalesce, and broadcast excludes its sender.
#[test]
fn software_interrupt_affinity_and_broadcast_select_recipients() {
    let (distributor, [mut first, mut second, mut third]) = controller();
    for vp in 0..3 {
        write32(&distributor, sgi_address(vp, S::IGROUPR0), !(1u32 << 9));
        write32(&distributor, sgi_address(vp, S::ISENABLER0), u32::MAX);
    }
    let mut wakes = Vec::new();
    let targeted = GicrSgi::new().with_intid(5).with_target_list(2);
    assert!(distributor.write_sysreg(
        &mut first,
        SystemReg::ICC_SGI1R_EL1,
        targeted.into(),
        |vp| wakes.push(vp)
    ));
    assert_eq!(wakes, [1]);
    wakes.clear();
    assert!(distributor.write_sysreg(
        &mut first,
        SystemReg::ICC_SGI1R_EL1,
        targeted.into(),
        |vp| wakes.push(vp)
    ));
    assert!(wakes.is_empty());
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(5)
    );
    let targeted = GicrSgi::new()
        .with_intid(7)
        .with_aff3(2)
        .with_aff2(3)
        .with_aff1(4)
        .with_target_list(4);
    assert!(distributor.write_sysreg(
        &mut first,
        SystemReg::ICC_SGI1R_EL1,
        targeted.into(),
        |vp| wakes.push(vp)
    ));
    assert_eq!(wakes, [2]);
    assert_eq!(
        distributor.read_sysreg(&mut third, SystemReg::ICC_IAR1_EL1),
        Some(7)
    );
    wakes.clear();
    let broadcast = GicrSgi::new().with_intid(9).with_irm(true);
    assert!(distributor.write_sysreg(
        &mut first,
        SystemReg::ICC_SGI0R_EL1,
        broadcast.into(),
        |vp| wakes.push(vp)
    ));
    assert_eq!(wakes, [1, 2]);
    assert!(!first.is_pending_or_active(9));
    assert!(second.is_pending_or_active(9));
    assert!(third.is_pending_or_active(9));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR0_EL1),
        Some(9)
    );
    assert_eq!(
        distributor.read_sysreg(&mut third, SystemReg::ICC_IAR0_EL1),
        Some(9)
    );
}

// Test: Read/EOI a shared interrupt from the wrong CPU and access unrelated system registers.
// Expected: Shared delivery stays on the primary CPU; unsupported system-register accesses are rejected.
#[test]
fn shared_interrupt_system_registers_retain_primary_cpu_ownership() {
    let (distributor, [mut first, mut second, _]) = controller();
    write32(
        &distributor,
        DIST + u64::from(D::ISENABLER.start) + 4,
        1 << 8,
    );
    distributor.set_pending(40, true);
    assert!(distributor.irq_pending(&first));
    assert!(!distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR0_EL1),
        Some(1023)
    );
    assert_eq!(
        distributor.read_sysreg(&mut first, SystemReg::ICC_IAR0_EL1),
        Some(40)
    );
    assert!(
        distributor.write_sysreg(&mut second, SystemReg::ICC_EOIR0_EL1, 40, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert_eq!(
        read32(&distributor, DIST + u64::from(D::ISACTIVER.start) + 4),
        1 << 8
    );
    assert!(
        distributor.write_sysreg(&mut first, SystemReg::ICC_EOIR0_EL1, 40, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert_eq!(
        read32(&distributor, DIST + u64::from(D::ICACTIVER.start) + 4),
        0
    );
    assert_eq!(
        distributor.read_sysreg(&mut first, SystemReg::ACTLR_EL1),
        None
    );
    assert!(
        !distributor.write_sysreg(&mut first, SystemReg::ACTLR_EL1, 0, |_| panic!(
            "unsupported register must not wake"
        ))
    );
}

// Test: Issue unaligned/unsupported MMIO and touch an unallocated redistributor or unrelated address.
// Expected: Unaligned reads return ones, unsupported/unallocated reads return zero, and valid state survives.
#[test]
fn invalid_mmio_is_contained_without_corrupting_neighboring_registers() {
    let (distributor, _) = controller();
    let mut outside = [0x55; 4];
    assert!(!distributor.read(DIST - 4, &mut outside));
    assert_eq!(outside, [0x55; 4]);
    assert!(!distributor.write(DIST - 4, &[0; 4]));
    for address in [DIST, REDIST, REDIST + 0x10000] {
        let mut bytes = [0; 4];
        assert!(distributor.read(address + 1, &mut bytes));
        assert_eq!(bytes, [0xff; 4]);
        assert!(distributor.write(address + 1, &[0xff; 4]));
        for len in [1, 2, 16] {
            let mut bytes = vec![0x55; len];
            assert!(distributor.read(address, &mut bytes));
            assert_eq!(bytes, vec![0; len]);
            assert!(distributor.write(address, &vec![0xff; len]));
        }
    }
    for address in [
        DIST + 0x80,
        REDIST + u64::from(R::STATUSR.0),
        sgi_address(0, S::IGRPMODR0),
        REDIST + 3 * STRIDE,
    ] {
        assert_eq!(read32(&distributor, address), 0);
        write32(&distributor, address, u32::MAX);
        assert_eq!(read32(&distributor, address), 0);
    }
    for address in [
        DIST + 0x80,
        REDIST + u64::from(R::SETLPIR.0),
        sgi_address(0, S::IGROUPR0),
    ] {
        assert_eq!(read64(&distributor, address), 0);
        assert!(distributor.write(address, &u64::MAX.to_le_bytes()));
    }
    assert_eq!(read32(&distributor, DIST + u64::from(D::CTLR.0)), 0x50);
    assert_eq!(read32(&distributor, sgi_address(0, S::IGROUPR0)), 0);
}

// IGNORED: Distributor storage omits the private-interrupt bank from its sizing.
//          Raising valid INTID 95 with 64 configured SPIs panics on a configuration-bank index.
// Test: Configure 64 SPIs and deliver the last advertised shared interrupt, INTID 95.
// Expected: The full configured interrupt range can be enabled, raised and acknowledged.
#[test]
#[ignore = "the last configured SPI bank indexes beyond allocated distributor state"]
fn last_configured_shared_interrupt_is_deliverable() {
    let mut distributor = Distributor::new(DIST, MemoryRange::new(REDIST..REDIST + STRIDE), 64);
    let mut redistributor = distributor.add_redistributor(0, true);
    write32(
        &distributor,
        DIST + u64::from(D::ISENABLER.start) + 8,
        1 << 31,
    );
    distributor.set_pending(95, true);
    assert!(distributor.irq_pending(&redistributor));
    assert_eq!(
        distributor.read_sysreg(&mut redistributor, SystemReg::ICC_IAR0_EL1),
        Some(95)
    );
}

// Test: Mask a pending private interrupt and then unmask it on its owning CPU.
// Expected: Masking suppresses IRQ without discarding pending state; unmasking
//       restores delivery once, with no pending interrupt on another CPU.
#[test]
fn private_interrupt_masking_preserves_pending_delivery() {
    let (distributor, [first, mut second, _]) = controller();
    write32(&distributor, sgi_address(1, S::IGROUPR0), 1 << 17);
    write32(&distributor, sgi_address(1, S::ISENABLER0), 1 << 17);
    distributor.raise_ppi(VpIndex::new(1), 17);
    assert!(distributor.irq_pending(&second));
    write32(&distributor, sgi_address(1, S::ICENABLER0), 1 << 17);
    assert!(!distributor.irq_pending(&second));
    assert_eq!(read32(&distributor, sgi_address(1, S::ISPENDR0)), 1 << 17);
    assert!(!distributor.irq_pending(&first));
    write32(&distributor, sgi_address(1, S::ISENABLER0), 1 << 17);
    assert!(distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(17)
    );
    assert!(
        distributor.write_sysreg(&mut second, SystemReg::ICC_EOIR1_EL1, 17, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert!(!distributor.irq_pending(&second));
    assert_eq!(read32(&distributor, sgi_address(1, S::ISPENDR0)), 0);
}

// IGNORED: Redistributor acknowledgement does not filter masked pending bits.
//          With PPI 19 masked and PPI 17 enabled, ICC_IAR1_EL1 returns 19.
// Test: Raise a masked private interrupt while another enabled interrupt
//       asserts the owning CPU's IRQ, then acknowledge that IRQ.
// Expected: Acknowledgement selects the enabled interrupt; the masked one
//       remains pending and becomes deliverable only after it is unmasked.
#[test]
#[ignore = "acknowledgement returns masked PPI 19 instead of enabled PPI 17"]
fn masked_private_interrupt_cannot_steal_another_interrupt_acknowledgement() {
    let (distributor, [_, mut second, _]) = controller();
    let both = (1 << 17) | (1 << 19);
    write32(&distributor, sgi_address(1, S::IGROUPR0), both);
    write32(&distributor, sgi_address(1, S::ISENABLER0), both);
    write32(&distributor, sgi_address(1, S::ICENABLER0), 1 << 19);
    distributor.raise_ppi(VpIndex::new(1), 19);
    distributor.raise_ppi(VpIndex::new(1), 17);
    assert!(distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(17)
    );
    assert_eq!(read32(&distributor, sgi_address(1, S::ISPENDR0)), 1 << 19);
    assert!(
        distributor.write_sysreg(&mut second, SystemReg::ICC_EOIR1_EL1, 17, |_| panic!(
            "EOI must not wake"
        ))
    );
    assert!(!distributor.irq_pending(&second));
    write32(&distributor, sgi_address(1, S::ISENABLER0), 1 << 19);
    assert!(distributor.irq_pending(&second));
    assert_eq!(
        distributor.read_sysreg(&mut second, SystemReg::ICC_IAR1_EL1),
        Some(19)
    );
}
