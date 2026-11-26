// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types to manage a filter on addresses.
//!
//! This is used to track the conditions under which a given PIO/MMIO access
//! or interrupt vector should be traced.
//!
//! See [`AddressFilter`] for more information, including the syntax used to
//! define the filter.

#![forbid(unsafe_code)]

use inspect::InspectMut;
use std::fmt::Display;
use std::fmt::LowerHex;
use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;

/// A trait for types that can be used as a range value in an [`AddressFilter`].
pub trait RangeKey: PartialOrd + Ord + PartialEq + Copy + LowerHex {
    /// The zero value for this type.
    const ZERO: Self;
    /// The maximum value for this type.
    const MAX: Self;
    /// Parse a hex string into this type.
    fn parse_hex(s: &str) -> Result<Self, ParseIntError>;
}

impl RangeKey for u8 {
    const ZERO: Self = 0;
    const MAX: Self = Self::MAX;
    fn parse_hex(s: &str) -> Result<Self, ParseIntError> {
        Self::from_str_radix(s, 16)
    }
}

impl RangeKey for u16 {
    const ZERO: Self = 0;
    const MAX: Self = Self::MAX;
    fn parse_hex(s: &str) -> Result<Self, ParseIntError> {
        Self::from_str_radix(s, 16)
    }
}

impl RangeKey for u32 {
    const ZERO: Self = 0;
    const MAX: Self = Self::MAX;
    fn parse_hex(s: &str) -> Result<Self, ParseIntError> {
        Self::from_str_radix(s, 16)
    }
}

impl RangeKey for u64 {
    const ZERO: Self = 0;
    const MAX: Self = Self::MAX;
    fn parse_hex(s: &str) -> Result<Self, ParseIntError> {
        Self::from_str_radix(s, 16)
    }
}

/// A filter over addresses.
///
/// These are primary constructed by parsing a filter string. The string is a
/// comma-delimited list of addresses (0x-prefixed hex values), inclusive ranges
/// (address1-address2), or the `?` character. `?` indicates that addresses that
/// are not recognized as part of the chipset should be filtered.
///
/// For example: `0x40-0x4f,0x63,?` would filter addresses 0x40 through 0x4f, address
/// 0x63, and any unknown addresses.
///
/// The string "all" is a special case that will match everything.
#[derive(Debug)]
pub struct AddressFilter<T> {
    unknown: bool,
    ranges: Vec<(T, T)>,
}

impl<T> AddressFilter<T>
where
    T: PartialOrd + Ord,
{
    /// Creates an empty filter.
    ///
    /// If `unknown` is true, then unknown addresses should be filtered.
    pub fn new(unknown: bool) -> Self {
        Self {
            ranges: Vec::new(),
            unknown,
        }
    }

    /// Returns whether `address` is in the filter.
    ///
    /// This is true when the address is in one of the ranges, or if `is_known`
    /// and the filter is configured for unknown addresses,
    pub fn filtered(&self, address: &T, is_known: bool) -> bool {
        if !is_known && self.unknown {
            return true;
        }
        // Fast path.
        if self.ranges.is_empty() {
            return false;
        }
        let i = self
            .ranges
            .binary_search_by(|(_start, end)| end.cmp(address))
            .unwrap_or_else(|x| x);
        self.ranges
            .get(i)
            .is_some_and(|(start, end)| address >= start && address <= end)
    }
}

impl<T: RangeKey> Display for AddressFilter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ranges == [(T::ZERO, T::MAX)] {
            return f.write_str("all");
        }
        let mut comma = "";
        for (start, end) in &self.ranges {
            if start == end {
                write!(f, "{comma}{start:#x}")?;
            } else {
                write!(f, "{comma}{start:#x}-{end:#x}")?;
            }
            comma = ",";
        }
        if self.unknown {
            write!(f, "{comma}?")?;
        }
        Ok(())
    }
}

/// Errors returned when trying to parse a full filter string
#[derive(Debug, Error)]
#[expect(missing_docs)]
pub enum InvalidRangeSet {
    #[error("invalid range value")]
    InvalidValue(#[from] InvalidRangeValue),
    #[error("end before start")]
    EndBeforeStart,
    #[error("overlapping ranges")]
    Overlapping,
}

/// Errors returned when trying to parse a single range value
#[derive(Debug, Error)]
#[expect(missing_docs)]
pub enum InvalidRangeValue {
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),
    #[error("value must begin with 0x")]
    NotHex,
}

fn parse_value<T: RangeKey>(s: &str) -> Result<T, InvalidRangeValue> {
    Ok(T::parse_hex(
        s.strip_prefix("0x").ok_or(InvalidRangeValue::NotHex)?,
    )?)
}

impl<T: RangeKey> FromStr for AddressFilter<T> {
    type Err = InvalidRangeSet;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = Vec::new();
        let mut unknown = false;

        if s == "all" {
            unknown = true;
            v.push((T::ZERO, T::MAX));
        } else {
            for range in s.split(',') {
                if range == "?" {
                    unknown = true;
                } else {
                    let (start, end) = if let Some((start, end)) = range.split_once('-') {
                        let start = parse_value(start)?;
                        let end = parse_value(end)?;
                        if end < start {
                            return Err(InvalidRangeSet::EndBeforeStart);
                        }
                        (start, end)
                    } else {
                        let start = parse_value(range)?;
                        (start, start)
                    };
                    v.push((start, end));
                }
            }
            v.sort();
            for [(_, end1), (start2, _)] in v.array_windows() {
                if end1 >= start2 {
                    return Err(InvalidRangeSet::Overlapping);
                }
            }
        }
        Ok(Self { ranges: v, unknown })
    }
}

impl<T: RangeKey> InspectMut for AddressFilter<T> {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        match req.update() {
            Ok(req) => match req.new_value().parse() {
                Ok(v) => {
                    *self = v;
                    req.succeed(self.to_string());
                }
                Err(err) => {
                    req.fail(err);
                }
            },
            Err(req) => req.value(self.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all() {
        let filter: AddressFilter<u32> = "all".parse().unwrap();
        assert!(filter.unknown);
        assert_eq!(filter.ranges, vec![(0, u32::MAX)]);
        assert_eq!(filter.to_string(), "all");
        assert!(filter.filtered(&0, true));
        assert!(filter.filtered(&0x1000, true));
        assert!(filter.filtered(&u32::MAX, true));
        assert!(filter.filtered(&0, false));
    }

    #[test]
    fn parse_unknown_only() {
        let filter: AddressFilter<u32> = "?".parse().unwrap();
        assert!(filter.unknown);
        assert!(filter.ranges.is_empty());
        assert!(!filter.filtered(&0x40, true));
        assert!(filter.filtered(&0x40, false));
    }

    #[test]
    fn parse_single_address() {
        let filter: AddressFilter<u32> = "0x63".parse().unwrap();
        assert!(!filter.unknown);
        assert_eq!(filter.ranges, vec![(0x63, 0x63)]);
        assert!(filter.filtered(&0x63, true));
        assert!(!filter.filtered(&0x64, true));
    }

    #[test]
    fn parse_range() {
        let filter: AddressFilter<u32> = "0x40-0x4f".parse().unwrap();
        assert!(filter.filtered(&0x40, true));
        assert!(filter.filtered(&0x45, true));
        assert!(filter.filtered(&0x4f, true));
        assert!(!filter.filtered(&0x3f, true));
        assert!(!filter.filtered(&0x50, true));
    }

    #[test]
    fn parse_compound() {
        let filter: AddressFilter<u32> = "0x40-0x4f,0x63,?".parse().unwrap();
        assert!(filter.unknown);
        assert_eq!(filter.ranges, vec![(0x40, 0x4f), (0x63, 0x63)]);
        assert!(filter.filtered(&0x45, true));
        assert!(filter.filtered(&0x63, true));
        assert!(!filter.filtered(&0x50, true));
        assert!(filter.filtered(&0x99, false));
        let reparsed: AddressFilter<u32> = filter.to_string().parse().unwrap();
        assert_eq!(filter.ranges, reparsed.ranges);
        assert_eq!(filter.unknown, reparsed.unknown);
    }

    #[test]
    fn parse_rejects_end_before_start() {
        let result: Result<AddressFilter<u32>, _> = "0x4f-0x40".parse();
        assert!(matches!(result, Err(InvalidRangeSet::EndBeforeStart)));
    }

    #[test]
    fn parse_rejects_overlapping() {
        let result: Result<AddressFilter<u32>, _> = "0x40-0x4f,0x45-0x50".parse();
        assert!(matches!(result, Err(InvalidRangeSet::Overlapping)));
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        let result: Result<AddressFilter<u32>, _> = "40".parse();
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_nested_all() {
        let result: Result<AddressFilter<u32>, _> = "0x40-0x4f,all".parse();
        assert!(result.is_err());
    }

    #[test]
    fn empty_filter_matches_nothing() {
        let filter = AddressFilter::<u32>::new(false);
        assert!(!filter.filtered(&0, true));
        assert!(!filter.filtered(&0, false));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Compare unsorted interrupt-vector intervals against every u8 value.
    // Expected: Both inclusive endpoints and isolated vectors match, holes do
    //       not, and the unknown-device selector is additive to explicit ranges.
    #[test]
    fn exhaustive_vector_membership_and_unknown_classification() {
        for unknown in [false, true] {
            let text = if unknown {
                "0xfe-0xff,0x21,0x40-0x4f,0x0,?"
            } else {
                "0xfe-0xff,0x21,0x40-0x4f,0x0"
            };
            let filter: AddressFilter<u8> = text.parse().unwrap();
            let restored: AddressFilter<u8> = filter.to_string().parse().unwrap();
            for value in 0..=u8::MAX {
                let expected =
                    value == 0 || value == 0x21 || (0x40..=0x4f).contains(&value) || value >= 0xfe;
                for known in [false, true] {
                    assert_eq!(
                        filter.filtered(&value, known),
                        expected || (!known && unknown)
                    );
                    assert_eq!(
                        restored.filtered(&value, known),
                        expected || (!known && unknown)
                    );
                }
            }
        }
    }

    // Test: Parse PIO and MMIO limits without truncating full-width endpoints.
    // Expected: Maximum addresses and adjacent ranges survive formatting, while
    //       width overflow, duplicate endpoints and reversed ranges are rejected.
    #[test]
    fn pio_and_high_mmio_boundaries_preserve_width_and_holes() {
        let pio: AddressFilter<u16> = "0xfff0-0xffff,0x0".parse().unwrap();
        assert!(pio.filtered(&0, true));
        assert!(!pio.filtered(&0xffef, true));
        assert!(pio.filtered(&0xffff, true));
        let mmio: AddressFilter<u64> = "0xffffffffffffffff,0x100000001-0x100000002,0x100000000"
            .parse()
            .unwrap();
        assert_eq!(
            mmio.to_string(),
            "0x100000000,0x100000001-0x100000002,0xffffffffffffffff"
        );
        let restored: AddressFilter<u64> = mmio.to_string().parse().unwrap();
        for value in [
            0,
            0xffff_ffff,
            0x1_0000_0000,
            0x1_0000_0001,
            0x1_0000_0002,
            0x1_0000_0003,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let expected = (0x1_0000_0000..=0x1_0000_0002).contains(&value) || value == u64::MAX;
            assert_eq!(mmio.filtered(&value, true), expected);
            assert_eq!(restored.filtered(&value, true), expected);
        }
        assert!("0x100".parse::<AddressFilter<u8>>().is_err());
        assert!("0x10000".parse::<AddressFilter<u16>>().is_err());
        assert!("0x100000000".parse::<AddressFilter<u32>>().is_err());
        assert!("0x10000000000000000".parse::<AddressFilter<u64>>().is_err());
        for text in [
            "0x0-0x10,0x10-0x20",
            "0xffffffffffffffff,0xffffffffffffffff",
        ] {
            assert!(matches!(
                text.parse::<AddressFilter<u64>>(),
                Err(InvalidRangeSet::Overlapping)
            ));
        }
        assert!(matches!(
            "0xffffffffffffffff-0x0".parse::<AddressFilter<u64>>(),
            Err(InvalidRangeSet::EndBeforeStart)
        ));
    }
}
