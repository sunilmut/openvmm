// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::*;
use iommu_common::IommuTranslator;
use pal_async::async_test;
use parking_lot::Mutex;
use test_with_tracing::test;
use vmcore::device_state::ChangeDeviceState;

#[derive(Default)]
struct Interrupts(Mutex<Vec<(u64, u32)>>);

impl SignalMsi for Interrupts {
    fn signal_msi(&self, _devid: Option<u32>, address: u64, data: u32) {
        self.0.lock().push((address, data));
    }
}

fn write(device: &mut IntelVtdDevice, offset: u64, value: u32) {
    assert!(matches!(
        device.mmio_write(0xfed9_0000 + offset, &value.to_le_bytes()),
        IoResult::Ok
    ));
}

fn read(device: &mut IntelVtdDevice, offset: u64) -> u32 {
    let mut bytes = [0; 4];
    assert!(matches!(
        device.mmio_read(0xfed9_0000 + offset, &mut bytes),
        IoResult::Ok
    ));
    u32::from_le_bytes(bytes)
}

// Test: Disable and reset an active, faulting IOMMU while retaining a DMA handle.
// Expected: GCMD disables translation immediately; reset clears programmed and
//       fault state, restores masks, and the original handle follows new state.
#[async_test]
async fn retained_translator_observes_disable_reset_and_reenable() {
    let interrupts = Arc::new(Interrupts::default());
    let (mut device, shared) = IntelVtdDevice::new(
        GuestMemory::allocate(0x4000),
        IntelVtdConfig {
            mmio_base: 0xfed9_0000,
        },
        interrupts.clone(),
    );
    let translator = shared.translator();
    write(&mut device, 0x20, 0x1000);
    write(&mut device, 0x3c, 0x5a);
    write(&mut device, 0x40, 0xfee0_1000);
    write(&mut device, 0x38, 0);
    write(&mut device, 0x18, 0xc000_0000);
    assert!(
        translator
            .translate(0x1203, 0x2876, false, |gpa| gpa)
            .is_err()
    );
    assert_eq!(*interrupts.0.lock(), [(0xfee0_1000, 0x5a)]);
    assert_ne!(read(&mut device, 0x34), 0);

    write(&mut device, 0x18, 0);
    assert_eq!(read(&mut device, 0x1c) & (1 << 31), 0);
    assert_eq!(
        translator
            .translate(0x1203, 0x2876, true, |gpa| gpa)
            .unwrap(),
        0x2876
    );
    device.reset().await;
    for offset in [
        0x1c, 0x20, 0x24, 0x34, 0x3c, 0x40, 0x120, 0x124, 0x128, 0x12c,
    ] {
        assert_eq!(read(&mut device, offset), 0, "offset {offset:#x}");
    }
    assert_eq!(read(&mut device, 0x38), 1 << 31);
    assert_eq!(read(&mut device, 0xa0), 1 << 31);
    assert_eq!(
        translator
            .translate(0x1203, 0x2876, false, |gpa| gpa)
            .unwrap(),
        0x2876
    );
    write(&mut device, 0x20, 0x2000);
    write(&mut device, 0x18, 0xc000_0000);
    assert!(
        translator
            .translate(0x1203, 0x2876, true, |gpa| gpa)
            .is_err()
    );
    assert_ne!(read(&mut device, 0x34), 0);
    assert_eq!(*interrupts.0.lock(), [(0xfee0_1000, 0x5a)]);
}
