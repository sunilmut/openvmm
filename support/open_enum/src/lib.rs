// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![forbid(unsafe_code)]

//! Provides the [`open_enum`] macro.

/// This macro creates an underlying struct that behaves like an enum, without
/// the undefined behavior of trying to match with a value outside of the enum.
/// The actual object created is a `#[repr(transparent)]` struct with a `pub` const
/// value. See comment in example below for an example of the underlying
/// structure.
///
/// This macro implements the following traits: `Copy`, `Clone`, `Debug`, `Eq`,
/// `PartialEq`, `Hash`, `Ord`, `PartialOrd`.
///
/// An example usage case for this macro is for protocols, when you want to use
/// an enum as a field in a struct that represents a specific type, like u16 or
/// u32. You are also able to convert to/from bytes with this typed enum.
///
/// # Examples
///
/// ```
/// # #[macro_use] extern crate open_enum; fn main() {
/// use open_enum::open_enum;
/// open_enum! {
///     #[expect(dead_code)] // This will apply to the generated struct defn
///     pub enum ExampleEnumName: u32 {
///         #![expect(missing_docs)] // This will apply to all subfields of the enum
///         THIS_IS_AN_ENUM = 32,
///     }
/// }
/// // Expands to:
/// //
/// // #[repr(transparent)]
//  // #[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
/// // #[expect(dead_code)]
/// // struct ExampleEnumName(u32);
/// //
/// // #[expect(missing_docs)]
/// // impl ExampleEnumName {
/// //     pub const THIS_IS_AN_ENUM: ExampleEnumName = ExampleEnumName(0)
/// // }
///
/// // To access an element in ExampleEnumName
/// let example_enum = ExampleEnumName::THIS_IS_AN_ENUM;
///
/// assert_eq!(example_enum.0, 32);
///
/// let number: u32 = example_enum.0; // enum value is type u32
/// # }
/// ```
#[macro_export]
macro_rules! open_enum {
    (
        $(#[$a:meta])*
        $v:vis enum $name:ident : $storage:ty {
            $(#![$implattr:meta])*
            $(
                $(#[$vattr:meta])*
                $variant:ident = $value:expr,
            )*
        }
    ) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
        #[repr(transparent)]
        $(#[$a])*
        $v struct $name(pub $storage);
        $(#[$implattr])*
        impl $name {
            $(
                $(#[$vattr])*
                pub const $variant: $name = $name($value);
            )*
        }
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                #[allow(unreachable_patterns)]
                let s = match *self {
                    $( Self::$variant => stringify!($variant), )*
                    _ => {
                        return ::core::fmt::Debug::fmt(&self.0, fmt);
                    }
                };
                fmt.pad(s)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use test_with_tracing::test;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    open_enum! {
        #[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
        enum Operation: u32 {
            READY = 1,
            READY_ALIAS = 1,
            COMPLETE = 2,
        }
    }

    open_enum! {
        enum SignedStatus: i64 {
            FAILED = -1,
        }
    }

    open_enum! {
        enum FutureStatus: u8 {}
    }

    // Test: Decode and forward a protocol operation with an unknown value.
    // Expected: Known values match their variants; unknown bits survive a
    //       typed wire round trip instead of being rejected or normalized.
    #[test]
    fn wire_operations_preserve_unknown_values() {
        for raw in [1u32, 2, 0, 0x8000_0000, u32::MAX] {
            let bytes = raw.to_ne_bytes();
            let operation = Operation::read_from_bytes(&bytes).unwrap();
            let recognized = match operation {
                Operation::READY => Some("ready"),
                Operation::COMPLETE => Some("complete"),
                _ => None,
            };
            assert_eq!(
                recognized,
                match raw {
                    1 => Some("ready"),
                    2 => Some("complete"),
                    _ => None,
                }
            );
            assert_eq!(operation.as_bytes(), &bytes);
        }
    }

    // Test: Format named, aliased and unknown protocol values in diagnostics.
    // Expected: The first declared alias is named, string padding/precision
    //       are honored, and unknown values retain integer formatting.
    #[test]
    fn diagnostics_distinguish_known_and_unknown_values() {
        assert_eq!(format!("{:?}", Operation::READY_ALIAS), "READY");
        assert_eq!(format!("{:>8?}", Operation::COMPLETE), "COMPLETE");
        assert_eq!(format!("{:_^9.3?}", Operation::READY), "___REA___");
        assert_eq!(format!("{:?}", Operation(0x8000_0000)), "2147483648");
        assert_eq!(format!("{:08x?}", Operation(0xabcdef)), "00abcdef");
        assert_eq!(format!("{:?}", SignedStatus::FAILED), "FAILED");
        assert_eq!(
            format!("{:?}", SignedStatus(i64::MIN)),
            "-9223372036854775808"
        );
    }

    // Test: Use an open protocol enum before any values have been assigned.
    // Expected: Diagnostics can still represent every underlying byte.
    #[test]
    fn empty_enum_reports_future_values() {
        assert_eq!(format!("{:?}", FutureStatus(0)), "0");
        assert_eq!(format!("{:#x?}", FutureStatus(u8::MAX)), "0xff");
    }
}
