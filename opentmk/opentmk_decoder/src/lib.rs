// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decodes and executes syzkaller programs against a caller-provided memory map.
//!
//! # Encoded program format
//!
//! This crate consumes the fixed-width executor encoding used by the syzkaller
//! integration for OpenTMK. The decoding flow corresponds to the instruction
//! loop and argument readers in syzkaller's
//! [`executor.cc`](https://github.com/google/syzkaller/blob/master/executor/executor.cc),
//! but the upstream format evolves independently.
//!
//! All scalar fields are unsigned 64-bit little-endian words. Negative
//! instruction values are represented in two's complement. The input starts
//! with this 56-byte header:
//!
//! | Byte offset | Field | Meaning |
//! | ---: | --- | --- |
//! | 0 | `magic` | Must be `0xbadc0ffeebadface`. |
//! | 8 | `env_flags` | Environment flags; see below. |
//! | 16 | `exec_flags` | Executor flags; see below. |
//! | 24 | `pid` | Executor process identifier used by constant arguments. |
//! | 32 | `fault_call` | Call index selected for fault injection. |
//! | 40 | `fault_nth` | Invocation of `fault_call` selected for fault injection. |
//! | 48 | `prog_size` | Size in bytes of the instruction stream that follows. |
//!
//! The decoder currently uses `pid` and `prog_size`, validates `magic`, and
//! ignores the flag and fault-injection fields. In `env_flags`, bits 0 through
//! 7 respectively mean debug, coverage, setuid sandbox, namespace sandbox,
//! Android untrusted-app sandbox, TUN, network devices, and fault injection.
//! In `exec_flags`, bits 0 through 5 respectively mean collect coverage,
//! deduplicate coverage, inject fault, collect comparisons, threaded
//! execution, and collide calls.
//!
//! ## Instructions
//!
//! The instruction stream is a sequence of records beginning with an
//! instruction word:
//!
//! | Instruction word | Remaining words | Meaning |
//! | --- | --- | --- |
//! | `u64::MAX` (`-1`) | none | End of the program. |
//! | `u64::MAX - 1` (`-2`) | `addr`, argument | Copy the decoded argument to `addr`. |
//! | `u64::MAX - 2` (`-3`) | `index`, `addr`, `size` | After the preceding call succeeds, copy `size` bytes from `addr` into result `index`. |
//! | `0..=i64::MAX` | `copyout_index`, `num_args`, arguments | Invoke the function identified by the instruction word. |
//!
//! A `copyout_index` of `u64::MAX` means the call has no syzkaller-visible
//! result slot. At most [`MAX_ARGS`] arguments are passed to the execution
//! callback. Copyout instructions are associated with the call immediately
//! before them and are executed only when that call succeeds.
//!
//! ## Arguments
//!
//! Each argument starts with a type word:
//!
//! | Type | Remaining words | Meaning |
//! | ---: | --- | --- |
//! | 0 | `meta`, `value` | Constant value. |
//! | 1 | `meta`, `index`, `op_div`, `op_add`, `fallback` | Reference to an earlier result. |
//! | 2 | `size`, `data...` | Inline data, padded to `ceil(size / 8)` words. |
//!
//! Inline data is supported only as the source of a copy-in instruction.
//! Checksum arguments are reserved by the format but are not implemented by
//! this crate.
//!
//! The `meta` word packs constant-copying information:
//!
//! | Bits | Field |
//! | --- | --- |
//! | 0..=7 | Value size in bytes. |
//! | 8..=15 | Binary format: 0 native, 1 big-endian, 2 decimal string, 3 hexadecimal string, or 4 octal string. |
//! | 16..=23 | Destination bitfield offset. |
//! | 24..=31 | Destination bitfield length. |
//! | 32..=63 | PID stride. The effective constant is `value + pid_stride * pid`. |
//!
//! For a result argument, `index` selects an earlier result. If it is
//! available, its value is divided by `op_div` when that value is nonzero and
//! then incremented by `op_add`; otherwise copy-in uses `fallback`. Direct
//! calls whose result arguments are unavailable are skipped.
//!
//! Addresses refer to the executor memory supplied through [`SafeMemoryMap`].
//! The standard mapping is [`EXEC_INPUT_REQ_SIZE`] bytes beginning at
//! [`ADDR_SYZ_BEGIN`].

#![no_std]
#![forbid(unsafe_code)]

#[macro_use]
extern crate alloc;

mod decoder;
mod instr;
mod prog;
mod safememory;
mod wire;

pub use decoder::DecoderError;
use prog::DecodedProgram;
pub use prog::InputCase;
pub use prog::InputResult;
pub use prog::TestcaseResults;
pub use safememory::SafeMemoryMap;
pub use safememory::SingleMap;

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// Required size, in bytes, of the syzkaller executor memory region.
pub const EXEC_INPUT_REQ_SIZE: usize = 0x1000000;

/// Supported (min) input size (kMaxInput in executor.cc).
pub const SUPPORTED_INPUT_SIZE: usize = 8 << 20;

/// Max supported args
pub const MAX_ARGS: usize = 30;

/// All syzkaller pointers are offsets from this presumed base address
pub const ADDR_SYZ_BEGIN: u64 = 0x20000000;

/// Call failed
const _SYZKALLER_CALL_END_FAILED: u64 = 3;

/// Takes a syz_in buffer containing raw syzkaller data from TKO, parses
/// individual test cases from it into the provided addr buffer, and calls the
/// provided exec function with a single test case; then continues from the
/// beginning until all provided testcases have completed.
///
/// It is expected that addr_size is minimum 0x1000000 bytes (or 16MiB).
/// syz_exec_mem must be at least [`EXEC_INPUT_REQ_SIZE`] in size.
/// syz_input_buffer must be at least [`SUPPORTED_INPUT_SIZE`] in size.
pub fn exec_testcases_safe<M: SafeMemoryMap, F>(
    syz_exec_mem: M,
    syz_input_buffer: &mut [u8],
    exec: F,
) -> Result<TestcaseResults, DecoderError>
where
    F: Fn(&mut M, InputCase) -> InputResult + Send + Sync,
{
    let mut decoded = DecodedProgram::new(syz_exec_mem, syz_input_buffer, exec)?;
    decoded.exec_instrs()?;
    Ok(decoded.results.as_ref().clone())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use parking_lot::Mutex;

    const MAGIC: u64 = 0xbadc0ffeebadface;
    const BASE: u64 = ADDR_SYZ_BEGIN;

    /// Builds an input buffer from a PID and instruction words.
    fn program(pid: u64, words: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        let prog_size = (words.len() * 8) as u64;
        for w in [MAGIC, 0, 0, pid, 0, 0, prog_size].iter().chain(words) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    fn neg(n: i64) -> u64 {
        n as u64
    }

    type Calls = Mutex<Vec<(u64, Vec<u64>)>>;

    fn run(
        input: &mut [u8],
        calls: &Calls,
        succeed: impl Fn(u64) -> InputResult + Send + Sync,
    ) -> (Result<TestcaseResults, DecoderError>, Vec<u8>) {
        let mem = SingleMap::new(vec![0u8; 0x100], BASE as usize);
        let snapshot = Mutex::new(Vec::new());
        let result = exec_testcases_safe(mem, input, |mem, case| {
            calls
                .lock()
                .push((case.call_num, case.args[..case.num_args as usize].to_vec()));
            *snapshot.lock() = mem.to_vec();
            succeed(case.call_num)
        });
        let snapshot = snapshot.into_inner();
        (result, snapshot)
    }

    // Test: Execute a program that copies a PID-scaled constant into memory,
    //       calls with a PID-scaled argument, copies the call's memory result
    //       out, then makes a call that consumes it with op_div/op_add and fails,
    //       followed by a copyout and a call that depend on the failed call.
    // Expected: Calls see the exact computed arguments; the successful call's
    //       copyout stores the memory value; the failed call's copyout and its
    //       dependent call are skipped rather than reading invalid results.
    #[test]
    fn program_chains_results_and_skips_work_after_failures() {
        let mut input = program(
            3,
            &[
                neg(-2),
                BASE,
                0,
                (2 << 32) | 8,
                100, // copyin 100 + 2 * pid
                7,
                0,
                1,
                0,
                1 << 32,
                10, // call 7(10 + pid) -> result 0
                neg(-3),
                1,
                BASE,
                8, // copyout mem -> result 1
                8,
                u64::MAX,
                1,
                1,
                8,
                1,
                2,
                1,
                0, // call 8(result1 / 2 + 1)
                neg(-3),
                2,
                BASE,
                4, // copyout after failed call
                9,
                u64::MAX,
                1,
                1,
                8,
                2,
                0,
                0,
                0, // call 9 depends on result 2
                neg(-1),
            ],
        );
        let calls = Calls::default();
        let (results, memory) = run(&mut input, &calls, |n| InputResult {
            code: 500 + n,
            name: "call".into(),
            is_success: n == 7,
        });
        let results = results.unwrap();
        assert_eq!(calls.into_inner(), [(7, vec![13]), (8, vec![54])]);
        assert_eq!(u64::from_le_bytes(memory[..8].try_into().unwrap()), 106);
        assert!(results[0].was_successful());
        assert_eq!(results[0].value(), Some(507));
        assert_eq!(results[1].value(), Some(106));
        assert_eq!(results[2].value(), None);
    }

    // Test: Decode headers and instruction streams that are malformed in each
    //       separately reported way.
    // Expected: Every malformed input returns its specific decoder error and
    //       no call is executed.
    #[test]
    fn malformed_programs_report_specific_errors_without_calls() {
        let mut bad_magic = program(0, &[neg(-1)]);
        bad_magic[0] ^= 1;
        let mut too_big = program(0, &[neg(-1)]);
        too_big[48] = 16;
        let cases: Vec<(Vec<u8>, DecoderError)> = vec![
            (bad_magic, DecoderError::BadMagic(MAGIC ^ 1)),
            (program(0, &[]), DecoderError::ZeroProgSize),
            (too_big, DecoderError::ProgSizeExceedsBuffer),
            (
                program(0, &[])[..40].to_vec(),
                DecoderError::TruncRead {
                    context: "program header",
                    expected: 56,
                    got: 40,
                },
            ),
            (program(0, &[neg(-4)]), DecoderError::BadInstruction(-4)),
            (program(0, &[1, 0, 1, 5]), DecoderError::BadArgType(5)),
            (
                program(0, &[1, 0, 1, 3]),
                DecoderError::Other("unhandled: arg_csum is not supported".into()),
            ),
            (
                program(0, &[neg(-2), BASE, 2, 0]),
                DecoderError::ZeroDataSize,
            ),
            (
                program(0, &[neg(-2), BASE, 2, 9, 1]),
                DecoderError::TruncRead {
                    context: "argument data",
                    expected: 8,
                    got: 0,
                },
            ),
            (
                program(0, &[1, 0, 1, 2, 8, 1, neg(-1)]),
                DecoderError::UnsupportedArgData,
            ),
            (
                program(0, &[1, 0, 0, neg(-3), 0, BASE, 3, neg(-1)]),
                DecoderError::CopyOutBadSize(3),
            ),
            (
                program(0, &[1, 1000, 0, neg(-1)]),
                DecoderError::OverflowOutIndex(1000),
            ),
        ];
        for (mut input, expected) in cases {
            let calls = Calls::default();
            let (result, _) = run(&mut input, &calls, |_| InputResult {
                is_success: true,
                ..Default::default()
            });
            let executes_before_error = matches!(
                expected,
                DecoderError::CopyOutBadSize(_) | DecoderError::OverflowOutIndex(_)
            );
            let description = format!("{expected:?}");
            assert_eq!(result.err(), Some(expected), "{description}");
            let executed = calls.into_inner();
            assert_eq!(
                !executed.is_empty(),
                executes_before_error,
                "{description}: {executed:?}"
            );
        }
    }

    // Test: Pass more than the maximum number of call arguments.
    // Expected: The call is rejected with the actual count and never executed.
    #[test]
    fn calls_with_too_many_arguments_are_rejected() {
        let mut words = vec![1, 0, (MAX_ARGS + 1) as u64];
        for _ in 0..=MAX_ARGS {
            words.extend([0, 0, 0]);
        }
        words.push(neg(-1));
        let calls = Calls::default();
        let (result, _) = run(&mut program(0, &words), &calls, |_| InputResult::default());
        assert_eq!(result.err(), Some(DecoderError::TooManyArgs(MAX_ARGS + 1)));
        assert!(calls.into_inner().is_empty());
    }

    // IGNORED: entry332-bug1; the PID-scaled constant `val + stride * pid` uses
    //       checked (debug) arithmetic and panics on overflow, while syzkaller's
    //       executor uses wrapping 64-bit arithmetic. Keep until a fix.
    //
    // Test: Copy in a constant whose PID stride multiplied by a large PID wraps.
    // Expected: The decoder stores the wrapped 64-bit value instead of panicking
    //       on fuzzer-controlled header and argument fields.
    #[test]
    #[ignore = "entry332-bug1: PID-scaled constants overflow instead of wrapping"]
    fn pid_scaled_constants_wrap_like_the_executor() {
        let pid = u64::MAX / 2;
        let mut input = program(pid, &[neg(-2), BASE, 0, (4 << 32) | 8, 7, 1, 0, 0, neg(-1)]);
        let calls = Calls::default();
        let (result, memory) = run(&mut input, &calls, |_| InputResult::default());
        result.unwrap();
        let expected = 7u64.wrapping_add(4u64.wrapping_mul(pid));
        assert_eq!(
            u64::from_le_bytes(memory[..8].try_into().unwrap()),
            expected
        );
    }

    // IGNORED: entry332-bug2; a native bitfield whose length equals the value
    //       width (for example 8 bits of a byte) overflows `1 << bf_len` and
    //       panics instead of storing the masked value. Keep until a fix.
    //
    // Test: Copy in a one-byte constant through a full-width (8-bit) bitfield.
    // Expected: The whole byte is replaced by the value, matching the
    //       executor's 64-bit mask arithmetic, without panicking.
    #[test]
    #[ignore = "entry332-bug2: full-width bitfields overflow the mask shift"]
    fn full_width_bitfields_store_the_whole_value() {
        let mut input = program(
            0,
            &[neg(-2), BASE, 0, (8 << 24) | 1, 0xa5, 1, 0, 0, neg(-1)],
        );
        let calls = Calls::default();
        let (result, memory) = run(&mut input, &calls, |_| InputResult::default());
        result.unwrap();
        assert_eq!(memory[0], 0xa5);
    }
}
