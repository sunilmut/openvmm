// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::create_pic;
use super::read_port;
use chipset_device::interrupt::AcknowledgePicInterrupt;
use chipset_device::pio::PortIoIntercept;
use test_with_tracing::test;

// Test: Nest a primary IRQ over a slave IRQ with a second slave request pending.
// Expected: Unrelated and slave EOIs cannot bypass the in-service cascade; both banks finish cleanly.
#[test]
fn specific_eois_preserve_nested_cascade_priority() {
    let (ready, mut pic) = create_pic();
    pic.set_irq(9, true);
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(0x39));
    pic.set_irq(10, true);
    assert!(!ready());
    pic.set_irq(1, true);
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(0x31));
    pic.io_write(0x20, &[0x0b]).unwrap();
    pic.io_write(0xa0, &[0x0b]).unwrap();
    assert_eq!(read_port(&mut pic, 0x20), 0x06);
    assert_eq!(read_port(&mut pic, 0xa0), 0x02);

    pic.io_write(0x20, &[0x61]).unwrap();
    assert!(!ready());
    assert_eq!(pic.acknowledge_interrupt(), None);
    assert_eq!(read_port(&mut pic, 0x20), 0x04);
    assert_eq!(read_port(&mut pic, 0xa0), 0x02);
    pic.io_write(0xa0, &[0x61]).unwrap();
    assert!(!ready());
    assert_eq!(read_port(&mut pic, 0xa0), 0);
    pic.io_write(0x20, &[0x62]).unwrap();
    assert!(ready());
    assert_eq!(pic.acknowledge_interrupt(), Some(0x3a));
    assert!(!ready());
    assert_eq!(read_port(&mut pic, 0x20), 0x04);
    assert_eq!(read_port(&mut pic, 0xa0), 0x04);
    pic.io_write(0xa0, &[0x62]).unwrap();
    pic.io_write(0x20, &[0x62]).unwrap();
    assert_eq!(read_port(&mut pic, 0x20), 0);
    assert_eq!(read_port(&mut pic, 0xa0), 0);
    assert_eq!(pic.acknowledge_interrupt(), None);
    assert!(!ready());
}
