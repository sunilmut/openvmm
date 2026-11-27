// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use opentmk_decoder::SafeMemoryMap;

use crate::functions::FuzzFunction;
use crate::functions::FuzzFunctionVariable;
use crate::prelude::*;

struct RegisteredFn {
    name: String,
    call: FuzzFunction,
}

#[derive(Default)]
pub struct FunctionRegistry {
    fns: Vec<RegisteredFn>,
}

impl FunctionRegistry {
    pub fn register(&mut self, name: &str, f: FuzzFunction) {
        self.fns.push(RegisteredFn {
            name: String::from(name),
            call: f,
        });
    }

    pub fn exec<M: SafeMemoryMap>(
        &self,
        mut mem: M,
        function_name: &str,
        input: Vec<FuzzFunctionVariable>,
    ) -> FuzzFunctionVariable {
        let mut func: Option<&RegisteredFn> = None;

        for f in &self.fns {
            if f.name == function_name {
                func = Some(f);
                break;
            }
        }

        let func = match func {
            None => {
                return FuzzFunctionVariable::Error(format!(
                    "Invalid function name: {function_name}",
                ));
            }
            Some(f) => f,
        };

        (func.call)(&mut mem, input).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentmk_decoder::SingleMap;

    fn first(
        _: &mut dyn SafeMemoryMap,
        args: Vec<FuzzFunctionVariable>,
    ) -> Result<FuzzFunctionVariable, String> {
        Ok(FuzzFunctionVariable::Int(args.len() as u64))
    }

    fn second(
        _: &mut dyn SafeMemoryMap,
        _: Vec<FuzzFunctionVariable>,
    ) -> Result<FuzzFunctionVariable, String> {
        Ok(FuzzFunctionVariable::Int(99))
    }

    fn failing(
        mem: &mut dyn SafeMemoryMap,
        _: Vec<FuzzFunctionVariable>,
    ) -> Result<FuzzFunctionVariable, String> {
        mem.try_write_mem(0x2000, &[1])?;
        Ok(FuzzFunctionVariable::Void)
    }

    // Test: Execute registered, duplicate-named, failing and unknown functions.
    // Expected: The first registration of a name wins, arguments reach it,
    //       function errors become Error values, and unknown names report the
    //       requested name.
    #[test]
    fn registry_dispatches_first_match_and_maps_errors() {
        let mut registry = FunctionRegistry::default();
        registry.register("f", first);
        registry.register("f", second);
        registry.register("fail", failing);
        let mut backing = [0u8; 4];
        let args = vec![FuzzFunctionVariable::Int(1), FuzzFunctionVariable::Void];
        assert!(matches!(
            registry.exec(SingleMap::from_slice(&mut backing, 0x1000), "f", args),
            FuzzFunctionVariable::Int(2)
        ));
        assert!(matches!(
            registry.exec(SingleMap::from_slice(&mut backing, 0x1000), "fail", vec![]),
            FuzzFunctionVariable::Error(_)
        ));
        match registry.exec(
            SingleMap::from_slice(&mut backing, 0x1000),
            "missing",
            vec![],
        ) {
            FuzzFunctionVariable::Error(message) => {
                assert_eq!(message, "Invalid function name: missing")
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
