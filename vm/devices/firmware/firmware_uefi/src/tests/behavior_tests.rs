// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::async_test;
use uefi_specs::hyperv::time::VmEfiTime;
use uefi_specs::uefi::time::EFI_TIME;
use uefi_specs::uefi::time::EfiDaylight;
use uefi_specs::uefi::time::EfiTimezone;

pub(super) fn submit(dev: &mut UefiDevice, command: UefiCommand, value: u32) {
    select(dev, command);
    assert!(matches!(
        write_register(dev, REGISTER_DATA, &value.to_ne_bytes()),
        IoResult::Ok
    ));
}

// Test: Set and retrieve a leap-day EFI time through the ARM command set, repeat under x64, and submit invalid guest addresses.
// Expected: ARM preserves calendar/zone/daylight at the clock's millisecond precision without touching adjacent memory; x64 leaves buffers untouched, and bad addresses cannot corrupt valid time.
#[async_test]
async fn time_command_dispatch_respects_architecture_and_guest_memory_boundaries(
    driver: DefaultDriver,
) {
    for (command_set, enabled) in [
        (UefiCommandSet::Aarch64, true),
        (UefiCommandSet::X64, false),
    ] {
        let TestDevice { mut dev, gm, .. } = test_device(&driver, true).await;
        dev.command_set = command_set;
        let time = EFI_TIME {
            year: 2024,
            month: 2,
            day: 29,
            hour: 23,
            minute: 59,
            second: 58,
            pad1: 0,
            nanosecond: 123_456_700,
            timezone: EfiTimezone(-480),
            daylight: EfiDaylight::new().with_adjust_daylight(true),
            pad2: 0,
        };
        let set_gpa = 0x2008;
        let get_gpa = 0x3008;
        let record_size = size_of::<VmEfiTime>() as u64;
        for gpa in [set_gpa, get_gpa] {
            gm.write_at(gpa - 8, &[0xa5; 8]).unwrap();
            gm.write_at(gpa + record_size, &[0x5a; 8]).unwrap();
        }
        gm.write_plain(
            set_gpa,
            &VmEfiTime {
                status: EfiStatus::DEVICE_ERROR.into(),
                time,
            },
        )
        .unwrap();
        submit(&mut dev, UefiCommand::SET_TIME, set_gpa as u32);
        let set_result: VmEfiTime = gm.read_plain(set_gpa).unwrap();
        assert_eq!(
            EfiStatus::from(set_result.status),
            if enabled {
                EfiStatus::SUCCESS
            } else {
                EfiStatus::DEVICE_ERROR
            }
        );
        assert_eq!({ set_result.time }, time);
        for command in [UefiCommand::GET_TIME, UefiCommand::SET_TIME] {
            submit(&mut dev, command, u32::MAX);
        }
        gm.write_plain(
            get_gpa,
            &VmEfiTime {
                status: EfiStatus::DEVICE_ERROR.into(),
                time: EFI_TIME::default(),
            },
        )
        .unwrap();
        submit(&mut dev, UefiCommand::GET_TIME, get_gpa as u32);
        let get_result: VmEfiTime = gm.read_plain(get_gpa).unwrap();
        assert_eq!(
            EfiStatus::from(get_result.status),
            if enabled {
                EfiStatus::SUCCESS
            } else {
                EfiStatus::DEVICE_ERROR
            }
        );
        assert_eq!(
            { get_result.time },
            if enabled {
                EFI_TIME {
                    nanosecond: 123_000_000,
                    ..time
                }
            } else {
                EFI_TIME::default()
            }
        );
        for gpa in [set_gpa, get_gpa] {
            let mut guard = [0; 8];
            gm.read_at(gpa - 8, &mut guard).unwrap();
            assert_eq!(guard, [0xa5; 8]);
            gm.read_at(gpa + record_size, &mut guard).unwrap();
            assert_eq!(guard, [0x5a; 8]);
        }
    }
}

fn write_register(dev: &mut UefiDevice, offset: u16, bytes: &[u8]) -> IoResult {
    if dev.use_mmio {
        dev.mmio_write(MMIO_RANGE_BEGIN + u64::from(offset), bytes)
    } else {
        dev.io_write(IO_PORT_RANGE_BEGIN + offset, bytes)
    }
}

fn read_register(dev: &mut UefiDevice, offset: u16, bytes: &mut [u8]) -> IoResult {
    if dev.use_mmio {
        dev.mmio_read(MMIO_RANGE_BEGIN + u64::from(offset), bytes)
    } else {
        dev.io_read(IO_PORT_RANGE_BEGIN + offset, bytes)
    }
}

fn read_value(dev: &mut UefiDevice, offset: u16) -> u32 {
    let mut bytes = [0; 4];
    assert!(matches!(
        read_register(dev, offset, &mut bytes),
        IoResult::Ok
    ));
    u32::from_ne_bytes(bytes)
}

fn select(dev: &mut UefiDevice, command: UefiCommand) {
    assert!(matches!(
        write_register(dev, REGISTER_ADDRESS, &command.0.to_ne_bytes()),
        IoResult::Ok
    ));
}

// Test: Access the address/data register pair through each supported transport and issue NFIT and unknown commands.
// Expected: Only the configured transport is registered with its exact range; selectors round-trip, NFIT reports zero, and unknown reads return all ones without changing the selector.
#[async_test]
async fn register_transports_preserve_selectors_and_report_command_results(driver: DefaultDriver) {
    for use_mmio in [false, true] {
        let TestDevice { mut dev, .. } = test_device(&driver, use_mmio).await;
        assert_eq!(dev.supports_pio().is_some(), !use_mmio);
        assert_eq!(dev.supports_mmio().is_some(), use_mmio);
        assert!(dev.supports_poll_device().is_some());
        if use_mmio {
            assert_eq!(
                MmioIntercept::get_static_regions(&mut dev),
                &[("uefi", 0xeffed000..=0xeffedfff)]
            );
        } else {
            assert_eq!(
                PortIoIntercept::get_static_regions(&mut dev),
                &[("uefi", 0x28..=0x2d)]
            );
        }
        select(&mut dev, UefiCommand::NFIT_SIZE);
        assert_eq!(read_value(&mut dev, REGISTER_ADDRESS), 0x37);
        assert_eq!(read_value(&mut dev, REGISTER_DATA), 0);
        select(&mut dev, UefiCommand(0xfedcba98));
        assert_eq!(read_value(&mut dev, REGISTER_DATA), u32::MAX);
        assert!(matches!(
            write_register(&mut dev, REGISTER_DATA, &0x12345678_u32.to_ne_bytes()),
            IoResult::Ok
        ));
        assert_eq!(read_value(&mut dev, REGISTER_ADDRESS), 0xfedcba98);
        assert_eq!(read_value(&mut dev, REGISTER_DATA), u32::MAX);
    }
}

// Test: Read and write malformed access sizes and unimplemented offsets on both register transports.
// Expected: The precise access error is returned, read buffers remain untouched, and failed writes cannot change a previously selected command.
#[async_test]
async fn malformed_register_accesses_leave_buffers_and_selector_unchanged(driver: DefaultDriver) {
    for use_mmio in [false, true] {
        let TestDevice { mut dev, .. } = test_device(&driver, use_mmio).await;
        select(&mut dev, UefiCommand::NFIT_SIZE);
        for offset in [REGISTER_ADDRESS, REGISTER_DATA] {
            for size in [0, 1, 2, 3, 5, 8] {
                let mut bytes = vec![0xa5; size];
                assert!(matches!(
                    read_register(&mut dev, offset, &mut bytes),
                    IoResult::Err(IoError::InvalidAccessSize)
                ));
                assert_eq!(bytes, vec![0xa5; size]);
                assert!(matches!(
                    write_register(&mut dev, offset, &bytes),
                    IoResult::Err(IoError::InvalidAccessSize)
                ));
                assert_eq!(read_value(&mut dev, REGISTER_ADDRESS), 0x37);
            }
        }
        for offset in [1, 2, 3, 5] {
            let mut bytes = [0xa5; 4];
            assert!(matches!(
                read_register(&mut dev, offset, &mut bytes),
                IoResult::Err(IoError::InvalidRegister)
            ));
            assert_eq!(bytes, [0xa5; 4]);
            assert!(matches!(
                write_register(&mut dev, offset, &bytes),
                IoResult::Err(IoError::InvalidRegister)
            ));
            assert_eq!(read_value(&mut dev, REGISTER_ADDRESS), 0x37);
        }
    }
}
