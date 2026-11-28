// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AsDebug;
use crate::AsDisplay;
use crate::AtomicMut;
use crate::Entry;
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
use test_with_tracing::test;

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

// Test: Update a bounded value under one of two identically named subtrees.
// Expected: Overflow and negative input preserve both values; valid boundary
//       updates affect only the selected subtree and remain readable.
#[test]
fn nested_numeric_updates_preserve_bounds_and_sibling_values() {
    #[derive(crate::InspectMut)]
    struct Settings {
        #[inspect(mut)]
        limit: u8,
    }

    let mut left = Settings { limit: 7 };
    let mut right = Settings { limit: 17 };
    let mut obj = adhoc_mut(|req| {
        req.respond()
            .field_mut("left", &mut left)
            .field_mut("right", &mut right);
    });

    assert_eq!(
        update("left/limit", "255", &mut obj)
            .now_or_never()
            .unwrap(),
        Ok(Value::new(255u8))
    );
    for input in ["256", "-1", "18446744073709551616"] {
        assert!(matches!(
            update("left/limit", input, &mut obj)
                .now_or_never()
                .unwrap(),
            Err(Error::Update(_))
        ));
        assert_eq!(
            read(&mut obj).json().to_string(),
            r#"{"left":{"limit":255},"right":{"limit":17}}"#
        );
    }
    assert_eq!(
        update("right/limit", "0", &mut obj).now_or_never().unwrap(),
        Ok(Value::new(0u8))
    );
    assert_eq!(
        read(&mut obj).json().to_string(),
        r#"{"left":{"limit":255},"right":{"limit":0}}"#
    );
}

// Test: Cancel a pending resolver, poll a replacement, and complete its request.
// Expected: Completion wakes the current resolver and preserves the returned value.
#[test]
fn deferred_completion_wakes_replacement_resolver() {
    use core::future::Future;
    use core::sync::atomic::AtomicUsize;
    use core::task::Context;
    use futures::task::ArcWake;
    use futures::task::waker;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let first = Arc::new(WakeCount::default());
    let replacement = Arc::new(WakeCount::default());
    let mut pending = None;
    let mut inspection = inspect("", adhoc_mut(|req| pending = Some(req.defer())));
    for counter in [&first, &replacement] {
        let waker = waker(counter.clone());
        let mut context = Context::from_waker(&waker);
        let mut resolve = core::pin::pin!(inspection.resolve());
        assert!(resolve.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(replacement.0.load(Ordering::Relaxed), 0);
    pending.unwrap().value(37u32);
    assert!(replacement.0.load(Ordering::Relaxed) > 0);
    assert!(inspection.resolve().now_or_never().is_some());
    assert_eq!(inspection.results(), Node::Value(Value::new(37u32)));
}

// Test: Reject synchronous and deferred updates with a nested error cause.
// Expected: Both public errors and JSON retain the outer message and its cause.
#[test]
fn update_rejections_preserve_error_causes() {
    #[derive(Debug, thiserror::Error)]
    #[error("setting rejected")]
    struct Rejection(#[source] std::io::Error);

    for deferred in [false, true] {
        let result = update(
            "",
            "invalid",
            adhoc(|req| {
                let req = req.update().ok().unwrap();
                let error = Rejection(std::io::Error::other("invalid input"));
                if deferred {
                    req.defer().fail(error);
                } else {
                    req.fail(error);
                }
            }),
        )
        .now_or_never()
        .unwrap();
        let error = Error::Update("setting rejected: invalid input".into());
        assert_eq!(result, Err(error.clone()));
        assert_eq!(
            Node::Failed(error).json().to_string(),
            r#"{"$error":"update error: setting rejected: invalid input"}"#
        );
    }
}

// Test: Serialize and deserialize diagnostic bytes, formats, and sensitivity.
// Expected: A fresh decoded tree preserves metadata, payloads, and public JSON.
#[test]
fn serialized_tree_preserves_formats_bytes_and_sensitivity() {
    let tree = Node::Dir(vec![
        Entry {
            name: "payload".into(),
            node: Node::Value(Value::new([0xffu8, 0x00])),
            sensitivity: SensitivityLevel::Sensitive,
        },
        Entry {
            name: "address".into(),
            node: Node::Value(Value::hex(u64::MAX)),
            sensitivity: SensitivityLevel::Safe,
        },
        Entry {
            name: "count".into(),
            node: Node::Value(Value::counter(42u64)),
            sensitivity: SensitivityLevel::Unspecified,
        },
        Entry {
            name: "mask".into(),
            node: Node::Value(Value::binary(5u32)),
            sensitivity: SensitivityLevel::Safe,
        },
    ]);
    let (encoded, resources) = mesh::Message::new(tree.clone()).serialize();
    assert!(resources.is_empty());
    let decoded: Node = mesh::Message::serialized(&encoded, resources)
        .parse()
        .unwrap();
    assert_eq!(decoded, tree);
    assert_eq!(
        decoded.json().to_string(),
        r#"{"payload":"/wA","address":"0xffffffffffffffff","count":42,"mask":"0b101"}"#
    );
}

// Test: Inspect an open file through the optional filepath implementation.
// Expected: The public value identifies the actual file's canonical path.
#[cfg(feature = "filepath")]
#[test]
fn file_inspection_reports_open_file_path() {
    #[expect(
        clippy::disallowed_methods,
        reason = "The filepath API resolves symlinks, so the independent oracle must too."
    )]
    let path =
        std::fs::canonicalize(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
            .unwrap();
    let file = std::fs::File::open(&path).unwrap();
    assert_eq!(
        read(&file),
        Node::Value(Value::new(path.display().to_string()))
    );
}
