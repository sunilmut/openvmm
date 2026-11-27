// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// UNSAFETY: This module contains unsafe code because we are doing raw I/O port via within a fuzzer
// context
#![expect(unsafe_code)]

use crate::functions::FuzzFunctionVariable;
use crate::functions::VerifyFuzzVariables;
use crate::prelude::*;

use opentmk_decoder::SafeMemoryMap;

use opentmk_core::arch;

fn validate_ioport(port: u16) -> Option<u16> {
    if (0x3E8..0x3F0).contains(&port) // COM3
        || /* COM4 */ (0x2E8..0x2F0).contains(&port)
        || /* COM2 */ (0x2F8..0x300).contains(&port)
    {
        // Ignores COM1 because we need that for fuzzer
        Some(port)
    } else {
        None
    }
}

pub fn write_ioport_u8(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as u8;

    if let Some(port) = port {
        unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::outb(port, value);
        }
    }
    Ok(FuzzFunctionVariable::Void)
}

pub fn read_ioport_u8(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as usize;
    if let Some(port) = port {
        // Perform and write inb result
        let res = unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::inb(port)
        };

        if let Err(e) = mem.try_write_mem(value, &[res]) {
            log::warn!("Failed to write inb output: {e}")
        }
    }
    Ok(FuzzFunctionVariable::Void)
}

pub fn write_ioport_u16(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as u16;

    if let Some(port) = port {
        unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::outw(port, value);
        }
    }

    Ok(FuzzFunctionVariable::Void)
}

pub fn read_ioport_u16(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as usize;
    if let Some(port) = port {
        // Perform and write inw result
        let res = unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::inw(port)
        };

        if let Err(e) = mem.try_write_mem(value, &res.to_le_bytes()) {
            log::warn!("Failed to write inw output: {e}")
        }
    }
    Ok(FuzzFunctionVariable::Void)
}

pub fn write_ioport_u32(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as u32;

    if let Some(port) = port {
        unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::outl(port, value);
        }
    }

    Ok(FuzzFunctionVariable::Void)
}

pub fn read_ioport_u32(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let [port, value] = vars.verify_num_params::<2>()?;
    let port = validate_ioport(port.expect_int("Port")? as u16);
    let value = value.expect_int("Value")? as usize;
    if let Some(port) = port {
        // Perform and write inl result
        let res = unsafe {
            // SAFETY: this is called within a fuzzer context. We assume all unsafe risks
            arch::io::inl(port)
        };

        if let Err(e) = mem.try_write_mem(value, &res.to_le_bytes()) {
            log::warn!("Failed to write inl output: {e}")
        }
    }
    Ok(FuzzFunctionVariable::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentmk_decoder::SingleMap;

    type PortFn = fn(
        &mut dyn SafeMemoryMap,
        Vec<FuzzFunctionVariable>,
    ) -> Result<FuzzFunctionVariable, String>;

    const ALL: [(&str, PortFn); 6] = [
        ("write_u8", write_ioport_u8),
        ("read_u8", read_ioport_u8),
        ("write_u16", write_ioport_u16),
        ("read_u16", read_ioport_u16),
        ("write_u32", write_ioport_u32),
        ("read_u32", read_ioport_u32),
    ];

    // Test: Check the port allow-list at every range boundary, including COM1
    //       and values that only match after truncation to 16 bits.
    // Expected: Only COM2-COM4 ports are allowed; COM1 (used by the fuzzer
    //       transport) and neighbouring ports are rejected.
    #[test]
    fn only_com2_through_com4_ports_are_allowed() {
        for port in [0x2e8, 0x2ef, 0x2f8, 0x2ff, 0x3e8, 0x3ef] {
            assert_eq!(validate_ioport(port), Some(port), "{port:#x}");
        }
        for port in [
            0,
            0x2e7,
            0x2f0,
            0x2f7,
            0x300,
            0x3e7,
            0x3f0,
            0x3f8,
            0x3ff,
            u16::MAX,
        ] {
            assert_eq!(validate_ioport(port), None, "{port:#x}");
        }
    }

    // Test: Call every port function with a disallowed port, with the wrong
    //       number of arguments, and with non-integer arguments.
    // Expected: Disallowed ports return Void without any port access or
    //       memory write; argument errors name the expected count or argument.
    #[test]
    fn port_functions_validate_arguments_and_skip_disallowed_ports() {
        let mut backing = [0xaau8; 8];
        for (name, f) in ALL {
            let mut mem = SingleMap::from_slice(&mut backing, 0x1000);
            let ok = f(
                &mut mem,
                vec![
                    FuzzFunctionVariable::Int(0x3f8),
                    FuzzFunctionVariable::Int(0x1000),
                ],
            );
            assert!(matches!(ok, Ok(FuzzFunctionVariable::Void)), "{name}");

            let error = f(&mut mem, vec![FuzzFunctionVariable::Int(0x2f8)]).unwrap_err();
            assert_eq!(error, "Expected 2 params, but received 1", "{name}");
            let error = f(
                &mut mem,
                vec![FuzzFunctionVariable::Void, FuzzFunctionVariable::Int(0)],
            )
            .unwrap_err();
            assert_eq!(error, "Port is not int but void", "{name}");
            let error = f(
                &mut mem,
                vec![
                    FuzzFunctionVariable::Int(0x3f8),
                    FuzzFunctionVariable::Error("e".into()),
                ],
            )
            .unwrap_err();
            assert_eq!(error, "Value is not int but error", "{name}");
        }
        assert_eq!(backing, [0xaa; 8]);
    }
}
