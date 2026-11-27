// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use spin::mutex::Mutex;

use super::*;
use crate::functions::FunctionRegistry;
use crate::functions::FuzzFunctionVariable;
use opentmk_exec_packet::OpenTMKFuzzTest;

static SYZLANG_EXEC_TEST_LOCK: Mutex<()> = Mutex::new(());
static RECORDED_CALLS: Mutex<Vec<(String, Vec<u64>)>> = Mutex::new(Vec::new());

const PROGRAM_MAGIC: u64 = 0xbadc0ffeebadface;
const ARG_CONST: u64 = 0;
const ARG_DATA: u64 = 2;
const INSTR_EOF: u64 = u64::MAX;
const INSTR_COPYIN: u64 = u64::MAX - 1;
const COPYOUT_INDEX_INVALID: u64 = usize::MAX as u64;

const MAGIC: &[u8; 8] = b"Leetspek";

fn record_call(
    name: &str,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let args = vars
        .iter()
        .map(|var| var.expect_int(name))
        .collect::<Result<Vec<_>, _>>()?;
    RECORDED_CALLS.lock().push((String::from(name), args));
    Ok(FuzzFunctionVariable::Void)
}

fn chkmagic(
    mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    let ptr = vars[0].expect_int("Pointer")? as usize;
    let mut buf = [0; MAGIC.len()];
    mem.read_mem(ptr, &mut buf);
    assert_eq!(&buf, MAGIC);
    record_call("chkmagic", vec![])
}

fn record_func0(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    record_call("func0", vars)
}

fn record_func1(
    _mem: &mut dyn SafeMemoryMap,
    vars: Vec<FuzzFunctionVariable>,
) -> Result<FuzzFunctionVariable, String> {
    record_call("func1", vars)
}

fn clear_recorded_calls() {
    RECORDED_CALLS.lock().clear();
}

fn recorded_calls() -> Vec<(String, Vec<u64>)> {
    RECORDED_CALLS.lock().clone()
}

#[derive(Copy, Clone)]
enum Insn<'s> {
    Call(u64, &'s [u64]),
    WriteMem(u64, &'s [u64]),
}

fn build_testcase(insns: &[Insn<'_>]) -> OpenTMKFuzzTest {
    let mut instructions = Vec::new();
    for insn in insns {
        match *insn {
            Insn::Call(call_num, args) => {
                instructions.push(call_num);
                instructions.push(COPYOUT_INDEX_INVALID);
                instructions.push(args.len() as u64);

                for &arg in args {
                    instructions.push(ARG_CONST);
                    instructions.push(0u64);
                    instructions.push(arg);
                }
            }
            Insn::WriteMem(addr, buf) => {
                instructions.push(INSTR_COPYIN);
                instructions.push(addr);
                instructions.push(ARG_DATA);
                instructions.push(buf.len() as u64 * 8);
                instructions.extend_from_slice(buf);
            }
        }
    }
    instructions.push(INSTR_EOF);

    let mut prog = vec![
        PROGRAM_MAGIC,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        instructions.len() as u64 * 8,
    ];
    prog.append(&mut instructions);

    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for num in prog {
        bytes.extend_from_slice(&num.to_le_bytes());
    }

    OpenTMKFuzzTest {
        testcase_vcpu0: bytes,
    }
}

fn install_function_registry(deserializer: &mut SyzlangDeserializer) {
    let registry = Arc::new(Mutex::new(FunctionRegistry::default()));
    let mut registry_lock = registry.lock();
    registry_lock.register("func0", record_func0);
    registry_lock.register("func1", record_func1);
    registry_lock.register("chkmagic", chkmagic);
    drop(registry_lock);
    deserializer.set_function_registry(registry);
}

#[test]
fn deserialize_executes_functions_selected_by_mapping_and_call_number() {
    // Needed because of syzkaller actually writing to some value
    let _guard = SYZLANG_EXEC_TEST_LOCK.lock();

    // Case: a decoded syzlang program dispatches each call number to the mapped function with decoded args.
    clear_recorded_calls();

    let mut deserializer = SyzlangDeserializer::new();
    install_function_registry(&mut deserializer);
    deserializer
        .set_mappings(
            postcard::to_allocvec(&vec![String::from("func0"), String::from("func1")])
                .expect("mapping serialization should succeed"),
        )
        .expect("mapping should succeed");

    let mut testcase = build_testcase(&[Insn::Call(1, &[11, 22]), Insn::Call(0, &[99])]);
    let result = deserializer
        .deserialize_and_execute(&mut testcase)
        .expect("deserialization should succeed");

    assert_eq!(result, 0);
    assert_eq!(
        recorded_calls(),
        vec![
            (String::from("func1"), vec![11, 22]),
            (String::from("func0"), vec![99]),
        ]
    );
}

#[test]
fn deserialize_syzkaller_pointers() {
    // Needed because of syzkaller actually writing to some value
    let _guard = SYZLANG_EXEC_TEST_LOCK.lock();

    // Case: a decoded syzlang program with memory pointers
    clear_recorded_calls();

    let ptr = opentmk_decoder::ADDR_SYZ_BEGIN;
    let mut deserializer = SyzlangDeserializer::new();
    install_function_registry(&mut deserializer);
    deserializer
        .set_mappings(
            postcard::to_allocvec(&vec![String::from("chkmagic")])
                .expect("mapping serialization should succeed"),
        )
        .expect("mapping should succeed");

    let mut testcase = build_testcase(&[
        Insn::WriteMem(ptr + 0x3, &[u64::from_le_bytes(*MAGIC)]),
        Insn::Call(0, &[ptr + 3]),
    ]);
    let result = deserializer
        .deserialize_and_execute(&mut testcase)
        .expect("deserialization should succeed");

    assert_eq!(result, 0);
    assert_eq!(recorded_calls(), vec![(String::from("chkmagic"), vec![]),]);
}

fn mapped_deserializer(names: &[&str]) -> SyzlangDeserializer {
    let mut deserializer = SyzlangDeserializer::new();
    install_function_registry(&mut deserializer);
    let names: Vec<String> = names.iter().map(|&n| String::from(n)).collect();
    deserializer
        .set_mappings(postcard::to_allocvec(&names).unwrap())
        .unwrap();
    deserializer
}

fn failure_message(result: Result<u64, ExecutorError>) -> String {
    match result {
        Err(ExecutorError::SyzlangDeserializerFailed(message)) => message,
        other => panic!("expected a deserializer failure, got {other:?}"),
    }
}

// Test: Run a program whose call number is beyond the mapping table, then a
//       program that calls a mapped name with no registered function, then a
//       valid program on the same deserializer.
// Expected: Each bad call fails with its call number or handler name, the
//       collected errors are cleared after reporting, and the valid program
//       then succeeds without stale errors.
#[test]
fn bad_calls_report_and_clear_errors() {
    let _guard = SYZLANG_EXEC_TEST_LOCK.lock();
    clear_recorded_calls();
    let mut deserializer = mapped_deserializer(&["func0", "nosuch"]);

    let message = failure_message(
        deserializer.deserialize_and_execute(&mut build_testcase(&[Insn::Call(5, &[])])),
    );
    assert_eq!(message, "invalid call number 5 received from syzlang");
    let message = failure_message(
        deserializer.deserialize_and_execute(&mut build_testcase(&[Insn::Call(1, &[7])])),
    );
    assert_eq!(message, "nosuch: Invalid function name: nosuch");

    let result = deserializer.deserialize_and_execute(&mut build_testcase(&[Insn::Call(0, &[3])]));
    assert!(matches!(result, Ok(0)), "{result:?}");
    assert_eq!(recorded_calls(), vec![(String::from("func0"), vec![3])]);
}

// Test: Supply undecodable mappings, a testcase larger than the input buffer,
//       and a testcase with a corrupted program header.
// Expected: Mappings fail with the mapping error; the oversized and corrupted
//       testcases fail with size and decoder details instead of executing.
#[test]
fn invalid_mappings_and_testcases_are_rejected() {
    let _guard = SYZLANG_EXEC_TEST_LOCK.lock();
    clear_recorded_calls();
    let mut deserializer = SyzlangDeserializer::new();
    assert!(matches!(
        deserializer.set_mappings(vec![0xff, 0xff, 0xff]),
        Err(ExecutorError::DecoderMappingsDeserializeFailed)
    ));

    let mut deserializer = mapped_deserializer(&["func0"]);
    let mut oversized = OpenTMKFuzzTest {
        testcase_vcpu0: vec![0; opentmk_decoder::SUPPORTED_INPUT_SIZE + 1],
    };
    let message = failure_message(deserializer.deserialize_and_execute(&mut oversized));
    assert_eq!(
        message,
        format!(
            "Testcase input is too large: {} > {}",
            opentmk_decoder::SUPPORTED_INPUT_SIZE + 1,
            opentmk_decoder::SUPPORTED_INPUT_SIZE
        )
    );

    let mut corrupt = build_testcase(&[Insn::Call(0, &[1])]);
    corrupt.testcase_vcpu0[0] ^= 1;
    let message = failure_message(deserializer.deserialize_and_execute(&mut corrupt));
    assert!(message.starts_with("BadMagic("), "{message}");
    assert!(recorded_calls().is_empty());
}
