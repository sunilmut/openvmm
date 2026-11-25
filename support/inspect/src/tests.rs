// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AsDebug;
use crate::AsDisplay;
use crate::AtomicMut;
use crate::Error;
use crate::InspectMut;
use crate::InspectionBuilder;
use crate::Node;
use crate::SensitivityLevel;
use crate::Value;
use crate::ValueKind;
use crate::adhoc;
use crate::adhoc_mut;
use crate::inspect;
use crate::iter_by_index;
use crate::update;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use core::mem::ManuallyDrop;
use core::num::Wrapping;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::time::Duration;
use futures::FutureExt;

fn read(obj: impl InspectMut) -> Node {
    let mut inspection = inspect("", obj);
    assert!(inspection.resolve().now_or_never().is_some());
    inspection.results()
}

// Test: Request one lazy field while another field must not be evaluated.
// Expected: Only the selected producer runs and its value is returned.
#[test]
fn lazy_fields_only_evaluate_requested_paths() {
    let obj = adhoc(|req| {
        req.respond()
            .field_with("selected", || 42)
            .field_with("other", || -> u32 { panic!("unrequested field") });
    });
    assert_eq!(
        inspect("selected", &obj).results(),
        Node::Value(Value::new(42))
    );
}

// Test: Request a safe lazy field and a sensitive counter with safe filtering.
// Expected: The sensitive producer is skipped and the safe counter is retained.
#[test]
fn lazy_fields_respect_sensitivity() {
    let obj = adhoc(|req| {
        req.respond()
            .sensitivity_field_with("hidden", SensitivityLevel::Sensitive, || -> u32 {
                panic!("filtered field")
            })
            .sensitivity_counter("count", SensitivityLevel::Safe, 12u64);
    });
    let result = InspectionBuilder::new("")
        .sensitivity(Some(SensitivityLevel::Safe))
        .inspect(&obj)
        .results();
    assert_eq!(result.json().to_string(), r#"{"count":12}"#);
    assert_eq!(
        InspectionBuilder::new("count")
            .sensitivity(Some(SensitivityLevel::Safe))
            .inspect(&obj)
            .results(),
        Node::Value(Value::counter(12u64))
    );
}

// Test: Read and update a field implemented through a custom accessor.
// Expected: Reads return its value and successful updates change the backing value.
#[test]
fn custom_field_accessor_reads_and_updates() {
    let mut value = 5u32;
    let mut obj = adhoc_mut(|req| {
        req.respond().field_mut_with("value", |new| {
            if let Some(new) = new {
                value = new.parse::<u32>()?;
            }
            Ok::<_, core::num::ParseIntError>(value)
        });
    });
    assert_eq!(read(&mut obj).json().to_string(), r#"{"value":5}"#);
    assert_eq!(
        update("value", "19", &mut obj).now_or_never().unwrap(),
        Ok(Value::new(19u32))
    );
    assert_eq!(value, 19);
}

// Test: Send an invalid update through a custom field accessor.
// Expected: The caller receives an update error and the backing value is unchanged.
#[test]
fn custom_field_accessor_rejects_invalid_updates() {
    let mut value = 5u32;
    let mut obj = adhoc_mut(|req| {
        req.respond().field_mut_with("value", |new| {
            if let Some(new) = new {
                value = new.parse::<u32>()?;
            }
            Ok::<_, core::num::ParseIntError>(value)
        });
    });
    assert!(matches!(
        update("value", "bad", &mut obj).now_or_never().unwrap(),
        Err(Error::Update(_))
    ));
    assert_eq!(value, 5);
}

// Test: Update one child exposed through a mutable iterator.
// Expected: The named child changes while its neighbor retains its value.
#[test]
fn mutable_iterator_updates_only_the_selected_child() {
    let mut values = [10u32, 20];
    let mut obj = adhoc_mut(|req| {
        req.respond()
            .fields_mut("children", values.iter_mut().enumerate());
    });
    assert_eq!(
        update("children/1", "99", &mut obj).now_or_never().unwrap(),
        Ok(Value::new(99u32))
    );
    assert_eq!(
        read(&mut obj).json().to_string(),
        r#"{"children":{"0":10,"1":99}}"#
    );
    assert_eq!(values, [10, 99]);
}

// Test: Rename, prefix, and transform iterator entries before inspection.
// Expected: Lookup uses the transformed names and returns transformed values.
#[test]
fn iterator_mapping_and_prefix_define_public_paths() {
    let values = [3u32, 7];
    let obj = iter_by_index(&values)
        .map_key(|index| index + 10)
        .prefix("cpu")
        .map_value(|value| value * 2);
    assert_eq!(read(&obj).json().to_string(), r#"{"cpu10":6,"cpu11":14}"#);
    assert_eq!(
        inspect("cpu11", &obj).results(),
        Node::Value(Value::new(14u32))
    );
}

// Test: Render fields through the display and debug convenience methods.
// Expected: Both methods return strings using their requested formatting.
#[test]
fn formatted_fields_produce_strings() {
    let obj = adhoc(|req| {
        req.respond()
            .display("display", &42)
            .display_debug("debug", &Some(3));
    });
    assert_eq!(
        read(&obj).json().to_string(),
        r#"{"debug":"Some(3)","display":"42"}"#
    );
    assert_eq!(read(&AsDisplay(42)), Node::Value(Value::new("42")));
    assert_eq!(
        read(&mut AsDebug(Some(3))),
        Node::Value(Value::new("Some(3)"))
    );
}

// Test: Inspect byte sources and C strings, including non-UTF-8 input.
// Expected: Bytes use base64 JSON and C strings use lossy UTF-8 conversion.
#[test]
fn byte_and_c_string_encodings_are_preserved() {
    assert_eq!(read(&[0xffu8, 0x00]).json().to_string(), r#""/wA""#);
    assert_eq!(read(&vec![0xffu8, 0x00]).to_string(), "<ff00>");
    let c_string = std::ffi::CString::new(vec![b'a', 0xff]).unwrap();
    let expected = Node::Value(Value::new("a\u{fffd}"));
    assert_eq!(read(&c_string), expected);
    assert_eq!(read(c_string.as_c_str()), expected);
    assert_eq!(
        Value::new(c_string).kind,
        ValueKind::String("a\u{fffd}".into())
    );
}

// Test: Inspect common ownership and synchronization wrappers.
// Expected: Each wrapper exposes the wrapped value rather than wrapper metadata.
#[test]
fn ownership_wrappers_forward_inspection() {
    let expected = Node::Value(Value::new(27u32));
    assert_eq!(read(&Box::new(27u32)), expected);
    assert_eq!(read(&Rc::new(27u32)), expected);
    assert_eq!(read(&Arc::new(27u32)), expected);
    assert_eq!(read(&ManuallyDrop::new(27u32)), expected);
    assert_eq!(read(&parking_lot::Mutex::new(27u32)), expected);
    assert_eq!(read(&parking_lot::RwLock::new(27u32)), expected);
    assert_eq!(
        read(&Cow::Borrowed("hello")),
        Node::Value(Value::new("hello"))
    );
}

// Test: Inspect a one-time cell before and after initialization.
// Expected: An empty cell is unevaluated; initialization exposes its value.
#[test]
fn once_cell_exposes_only_initialized_values() {
    let cell = std::sync::OnceLock::new();
    assert_eq!(read(&cell), Node::Unevaluated);
    cell.set(27u32).unwrap();
    assert_eq!(read(&cell), Node::Value(Value::new(27u32)));
}

// Test: Update values through optional, boxed, and wrapping containers.
// Expected: Updates reach contained values; an empty option cannot resolve one.
#[test]
fn mutable_wrappers_forward_updates() {
    let mut value = Some(Box::new(Wrapping(4u32)));
    assert_eq!(
        update("", "12", &mut value).now_or_never().unwrap(),
        Ok(Value::new(12u32))
    );
    assert_eq!(value.unwrap().0, 12);
    let mut absent: Option<u32> = None;
    assert_eq!(
        update("", "12", &mut absent).now_or_never().unwrap(),
        Err(Error::Unresolved)
    );
    assert_eq!(absent, None);
}

// Test: Read and update signed and unsigned atomic values through AtomicMut.
// Expected: Valid updates are stored and invalid input preserves the last value.
#[test]
fn atomic_numeric_updates_validate_before_storing() {
    let signed = AtomicI64::new(-8);
    let unsigned = AtomicU64::new(8);
    assert_eq!(read(&signed), Node::Value(Value::new(-8i64)));
    assert_eq!(read(&unsigned), Node::Value(Value::new(8u64)));
    assert_eq!(
        update("", "-12", &AtomicMut(&signed))
            .now_or_never()
            .unwrap(),
        Ok(Value::new(-12i64))
    );
    assert_eq!(
        update("", "12", &AtomicMut(&unsigned))
            .now_or_never()
            .unwrap(),
        Ok(Value::new(12u64))
    );
    assert!(matches!(
        update("", "-1", &AtomicMut(&unsigned))
            .now_or_never()
            .unwrap(),
        Err(Error::Update(_))
    ));
    assert_eq!(signed.load(Ordering::Relaxed), -12);
    assert_eq!(unsigned.load(Ordering::Relaxed), 12);
}

// Test: Compare signed and floating-point counters over a partial second.
// Expected: Each counter becomes a per-second rate with fractional precision.
#[test]
fn counter_rates_support_signed_and_floating_point_values() {
    for (old, new) in [
        (Value::counter(-8i64), Value::counter(-5i64)),
        (Value::counter(1.0f32), Value::counter(4.0f32)),
        (Value::counter(1.0f64), Value::counter(4.0f64)),
    ] {
        let result = Node::Value(new).since(&Node::Value(old), Duration::from_millis(500));
        assert_eq!(result, Node::Value(Value::counter(6.0f64)));
    }
}

// Test: Inspect a signed binary value, a duration, and a raw pointer.
// Expected: Their public text and JSON representations retain their formats.
#[test]
fn specialized_values_keep_their_public_formats() {
    let binary = Node::Value(Value::binary(5i64));
    assert_eq!(binary.to_string(), "0b101");
    assert_eq!(binary.json().to_string(), r#""0b101""#);
    assert_eq!(
        read(&Duration::new(2, 3)),
        Node::Value(Value::new("2.000000003s"))
    );
    let pointer = core::ptr::null::<u32>();
    assert_eq!(read(&pointer).json().to_string(), r#""0x0""#);
    assert_eq!(read(&pointer.cast_mut()).json().to_string(), r#""0x0""#);
}
