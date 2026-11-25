// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::SerializedMessage;
use crate::encoding::ResourceField;
use crate::merge;
use alloc::boxed::Box;
use core::num::*;
use test_with_tracing::test;

// Test: Decode map entries with omitted fields, unknown fields, and duplicate keys.
// Expected: Missing fields default, unknown fields are skipped, and the last key wins.
#[test]
fn map_entries_follow_protobuf_merge_rules() {
    let bytes = [
        0x0a, 0, // Empty entry: default key and value.
        0x0a, 2, 0x08, 7, // Key only.
        0x0a, 4, 0x10, 9, 0x18, 1, // Value and an unknown field.
        0x0a, 4, 0x08, 7, 0x10, 11, // Replace key 7.
    ];
    let (map,): (BTreeMap<u32, u32>,) = decode(&bytes).unwrap();
    assert_eq!(map, BTreeMap::from([(0, 9), (7, 11)]));
    let nested = (vec![map.clone(), BTreeMap::new()],);
    assert_eq!(
        decode::<(Vec<BTreeMap<u32, u32>>,)>(&encode(nested.clone())).unwrap(),
        nested
    );
    assert!(decode::<(BTreeMap<u32, u32>,)>(&[0x0a, 1, 0x08]).is_err());
}

// Test: Deserialize nonzero integer fields and packed lists for every integer width.
// Expected: Nonzero values round-trip, while explicit zero and missing fields fail.
#[test]
fn nonzero_numbers_reject_zero_in_fields_and_lists() {
    macro_rules! check {
        ($($nonzero:ty => $primitive:ty),* $(,)?) => {$({
            let one = <$nonzero>::new(1).unwrap();
            assert_eq!(decode::<($nonzero,)>(&encode((one,))).unwrap().0, one);
            assert_eq!(
                decode::<(Vec<$nonzero>,)>(&encode((vec![one, one],))).unwrap().0,
                [one, one]
            );
            assert!(decode::<($nonzero,)>(&[]).is_err());
            assert!(
                decode::<($nonzero,)>(&encode((Some(0 as $primitive),))).is_err()
            );
            assert!(
                decode::<(Vec<$nonzero>,)>(&encode((vec![1 as $primitive, 0],))).is_err()
            );
        })*};
    }
    check!(
        NonZeroU8 => u8, NonZeroU16 => u16, NonZeroU32 => u32,
        NonZeroU64 => u64, NonZeroUsize => usize,
        NonZeroI8 => i8, NonZeroI16 => i16, NonZeroI32 => i32,
        NonZeroI64 => i64, NonZeroIsize => isize,
    );
}

// Test: Merge boxed messages and serialize nested collections of boxed values.
// Expected: Boxes preserve the unboxed wire format and retain absent merged fields.
#[test]
fn boxed_messages_merge_without_losing_existing_fields() {
    let boxed = Box::new((7u32, String::from("retained")));
    let wire = encode(boxed.clone());
    assert_eq!(wire, encode((7u32, "retained")));
    let decoded: Box<(u32, String)> = decode(&wire).unwrap();
    assert_eq!(
        *merge(decoded, &encode((11u32, ""))).unwrap(),
        (11, String::from("retained"))
    );
    let nested = (vec![Box::new(vec![1u32, 2]), Box::new(Vec::new())],);
    assert_eq!(
        decode::<(Vec<Box<Vec<u32>>>,)>(&encode(nested.clone())).unwrap(),
        nested
    );
    let (empty,): (Box<String>,) = decode(&[]).unwrap();
    assert!(empty.is_empty());
}

// Test: Transfer resource fields and reject missing or incompatible resource values.
// Expected: Valid resources survive nesting; missing resources and narrowing fail.
#[test]
fn resource_fields_validate_presence_and_conversion() {
    #[derive(Protobuf, Debug, PartialEq, Eq)]
    #[mesh(resource = "u32")]
    struct Resource(#[mesh(encoding = "ResourceField<u32>")] u32);
    #[derive(Protobuf, Debug)]
    #[mesh(resource = "u32")]
    struct Narrow(#[mesh(encoding = "ResourceField<u8>")] u8);

    let wire = SerializedMessage::<u32>::from_message((vec![Resource(7), Resource(9)],));
    assert_eq!(
        wire.into_message::<(Vec<Resource>,)>().unwrap().0,
        [Resource(7), Resource(9)]
    );
    assert!(
        SerializedMessage::<u32>::default()
            .into_message::<Resource>()
            .is_err()
    );
    assert!(
        SerializedMessage::<u32>::from_message(Resource(256))
            .into_message::<Narrow>()
            .is_err()
    );
}

// Test: Decode absent Cow fields and serialize borrowed and owned variants.
// Expected: Defaults are empty, wire bytes do not depend on ownership, and bad UTF-8 fails.
#[test]
fn cow_fields_preserve_content_across_ownership_modes() {
    #[derive(Protobuf)]
    struct Borrowed<'a>(
        #[mesh(encoding = "BorrowedCowField")] Cow<'a, str>,
        #[mesh(encoding = "BorrowedCowField")] Cow<'a, [u8]>,
    );
    #[derive(Protobuf)]
    struct Owned<'a>(
        #[mesh(encoding = "OwningCowField")] Cow<'a, str>,
        #[mesh(encoding = "OwningCowField")] Cow<'a, [u8]>,
    );

    let empty: Borrowed<'_> = decode(&[]).unwrap();
    assert!(empty.0.is_empty() && empty.1.is_empty());
    let empty: Owned<'_> = decode(&[]).unwrap();
    assert!(empty.0.is_empty() && empty.1.is_empty());
    let expected = encode(("ab", vec![0u8, 0xff]));
    assert_eq!(
        encode(Borrowed(Cow::Borrowed("ab"), Cow::Borrowed(&[0, 0xff]))),
        expected
    );
    assert_eq!(
        encode(Owned(Cow::Owned("ab".into()), Cow::Owned(vec![0, 0xff]))),
        expected
    );
    let bad_utf8 = [0x0a, 1, 0xff];
    assert!(decode::<Borrowed<'_>>(&bad_utf8).is_err());
    assert!(decode::<Owned<'_>>(&bad_utf8).is_err());
}

// Test: Decode empty nested messages and merge them into an existing optional value.
// Expected: New values receive defaults; empty updates preserve existing fields.
#[test]
fn nested_empty_messages_default_without_erasing_merged_values() {
    type Nested = (Option<(String, u32)>,);
    assert_eq!(
        decode::<Nested>(&[0x0a, 0]).unwrap(),
        (Some((String::new(), 0)),)
    );
    assert_eq!(
        merge((Some((String::from("retained"), 17u32)),), &[0x0a, 0]).unwrap(),
        (Some((String::from("retained"), 17)),)
    );
    assert!(decode::<(Option<(String, NonZeroU32)>,)>(&[0x0a, 0]).is_err());
}

// Test: Decode custom numeric encodings with wrapping integers and Unicode scalars.
// Expected: Integer boundaries round-trip, nonzero booleans are true, and invalid
//       Unicode code points are rejected rather than truncated.
#[test]
fn explicit_numeric_codecs_validate_their_value_domains() {
    use crate::encoding::Fixed32Field;
    use crate::encoding::Fixed64Field;
    use crate::encoding::SignedVarintField;
    use crate::encoding::VarintField;
    use core::num::Wrapping;

    #[derive(Protobuf, Debug, PartialEq, Eq)]
    struct Numbers(
        #[mesh(encoding = "VarintField")] Wrapping<u64>,
        #[mesh(encoding = "SignedVarintField")] Wrapping<i64>,
        #[mesh(encoding = "SignedVarintField")] char,
        #[mesh(encoding = "SignedVarintField")] bool,
        #[mesh(encoding = "Fixed32Field")] i32,
        #[mesh(encoding = "Fixed64Field")] i64,
    );
    let value = Numbers(
        Wrapping(u64::MAX),
        Wrapping(i64::MIN),
        '\u{10ffff}',
        true,
        i32::MIN,
        i64::MIN,
    );
    let wire = encode(value);
    assert_eq!(
        decode::<Numbers>(&wire).unwrap(),
        Numbers(
            Wrapping(u64::MAX),
            Wrapping(i64::MIN),
            '\u{10ffff}',
            true,
            i32::MIN,
            i64::MIN
        )
    );
    assert_eq!(
        decode::<Numbers>(&[]).unwrap(),
        Numbers(Wrapping(0), Wrapping(0), '\0', false, 0, 0)
    );
    for invalid in [-1i64, 0xd800, 0xdfff, 0x110000] {
        assert!(decode::<Numbers>(&encode((0u64, 0i64, invalid))).is_err());
    }
    let decoded: Numbers = decode(&encode((0u64, 0i64, 0i64, -7i64))).unwrap();
    assert!(decoded.3);
}

// Test: Deserialize a borrowed byte field from valid, absent, and wrongly typed data.
// Expected: Bytes are preserved without ownership requirements; wrong wire types fail.
#[test]
fn borrowed_byte_fields_follow_wire_type_and_default_rules() {
    use crate::encoding::BytesField;

    #[derive(Protobuf, Debug, PartialEq, Eq)]
    struct Bytes<'a>(#[mesh(encoding = "BytesField")] &'a [u8]);
    let value = Bytes(&[0, 0x7f, 0xff]);
    let encoded = encode(value);
    assert_eq!(encoded, [0x0a, 3, 0, 0x7f, 0xff]);
    assert_eq!(
        decode::<Bytes<'_>>(&encoded).unwrap(),
        Bytes(&[0, 0x7f, 0xff])
    );
    assert_eq!(decode::<Bytes<'_>>(&[]).unwrap(), Bytes(&[]));
    assert!(decode::<Bytes<'_>>(&[0x08, 1]).is_err());
}

// Test: Fail decoding after receiving a resource but before the message is complete.
// Expected: The transferred resource is dropped exactly once on each failure path.
#[test]
fn partially_decoded_messages_release_resources() {
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    #[derive(Debug)]
    struct Tracked(Arc<AtomicUsize>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[derive(Protobuf)]
    #[mesh(resource = "Tracked")]
    struct Wire(
        #[mesh(encoding = "ResourceField<Tracked>")] Tracked,
        Option<u32>,
    );
    #[derive(Protobuf)]
    #[mesh(resource = "Tracked")]
    struct Required(
        #[mesh(encoding = "ResourceField<Tracked>")] Tracked,
        NonZeroU32,
    );
    for required in [None, Some(0)] {
        let drops = Arc::new(AtomicUsize::new(0));
        let wire =
            SerializedMessage::<Tracked>::from_message(Wire(Tracked(drops.clone()), required));
        assert!(wire.into_message::<Required>().is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

// Test: Default a derived message directly into empty and previously filled storage.
// Expected: The public field decoder constructs the same defaults as an empty message.
#[test]
fn field_defaults_match_empty_message_decoding() {
    #[derive(Protobuf, Debug, PartialEq, Eq)]
    struct Value(String, u32, Box<u32>);
    type Encoding = <Value as crate::DefaultEncoding>::Encoding;

    crate::inplace_none!(value: Value);
    <Encoding as FieldDecode<'_, Value, NoResources>>::default_field(&mut value).unwrap();
    assert_eq!(value.take().unwrap(), decode::<Value>(&[]).unwrap());
    value.set(Value("old".into(), 17, Box::new(23)));
    <Encoding as FieldDecode<'_, Value, NoResources>>::default_field(&mut value).unwrap();
    assert_eq!(
        value.take().unwrap(),
        Value(String::new(), 0, Box::default())
    );
}

// Test: Fail default construction with storage empty and with an owned tail value.
// Expected: Partial construction is invalidated and existing ownership never leaks.
#[test]
fn failed_field_defaults_clean_up_initialized_fields() {
    #[derive(Protobuf)]
    struct Required(String, NonZeroU32, Arc<String>);
    type Encoding = <Required as crate::DefaultEncoding>::Encoding;

    crate::inplace_none!(value: Required);
    assert!(
        <Encoding as FieldDecode<'_, Required, NoResources>>::default_field(&mut value).is_err()
    );
    assert!(value.is_none());
    let tail = Arc::new(String::from("owned"));
    value.set(Required(
        "old".into(),
        NonZeroU32::new(1).unwrap(),
        tail.clone(),
    ));
    assert!(
        <Encoding as FieldDecode<'_, Required, NoResources>>::default_field(&mut value).is_err()
    );
    drop(value);
    assert_eq!(Arc::strong_count(&tail), 1);
}

// Test: Decode known fields with wire types that do not match their schema.
// Expected: Each failure retains the specific wire-type error for callers.
#[test]
fn mismatched_wire_types_report_the_expected_payload_kind() {
    let bytes = [0x0a, 0];
    let varint = [0x08, 1];
    for (error, expected) in [
        (decode::<(u32,)>(&bytes).unwrap_err(), "expected a varint"),
        (decode::<(f32,)>(&varint).unwrap_err(), "expected a fixed32"),
        (decode::<(f64,)>(&varint).unwrap_err(), "expected a fixed64"),
        (
            decode::<(String,)>(&varint).unwrap_err(),
            "expected a byte array",
        ),
        (
            decode::<((u32,),)>(&varint).unwrap_err(),
            "expected a message",
        ),
    ] {
        assert_eq!(error.source().unwrap().to_string(), expected);
        assert!(!error.to_string().is_empty());
    }
}

// Test: Merge an Arc field with a live alias and round-trip nested Arc sequences.
// Expected: Updates do not alter the alias, and default or empty elements survive.
#[test]
fn shared_fields_merge_without_changing_live_aliases() {
    let original = Arc::new(String::from("old"));
    let updated = merge((original.clone(),), &encode(("new",))).unwrap();
    assert_eq!(updated.0.as_str(), "new");
    assert_eq!(original.as_str(), "old");
    let (empty,): (Arc<String>,) = decode(&[]).unwrap();
    assert!(empty.is_empty());
    let nested = (vec![Arc::new(vec![1u32, 2]), Arc::new(Vec::new())],);
    assert_eq!(
        decode::<(Vec<Arc<Vec<u32>>>,)>(&encode(nested.clone())).unwrap(),
        nested
    );
}
