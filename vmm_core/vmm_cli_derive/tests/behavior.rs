// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end behavior of parsers generated for an external consumer.

mod fixtures;

use fixtures::*;
use test_with_tracing::test;
use vmm_cli::KeyValueFields;

// Test: Parse a positional disk path with nested keys, renamed values and all flag modes.
// Expected: Every supplied value reaches its field, including explicit false and mapped flags.
#[test]
fn positional_flattened_values_and_flags_are_preserved() {
    let disk: Disk =
        "disk0,size=4096,count=7,label=backup,serial=abc,readonly,cache=off,policy,host-file=image"
            .parse()
            .unwrap();
    assert_eq!(
        disk,
        Disk {
            path: "disk0".into(),
            common: Common {
                size: 4096,
                queues: 7,
                label: "backup".into(),
                serial: Some("abc".into()),
                readonly: true,
                cache: Some(false),
                policy: 8,
            },
            backend: Backend::File("image".into()),
        }
    );
}

// Test: Omit defaulted, optional and flag keys while supplying the required scalar.
// Expected: Nested parsers use declared defaults, None for absent options and the unit backend.
#[test]
fn nested_defaults_and_absent_flags_are_applied() {
    let disk: Disk = "disk0,size=512".parse().unwrap();
    let expected = Common {
        size: 512,
        queues: 4,
        label: String::new(),
        serial: None,
        readonly: false,
        cache: None,
        policy: 3,
    };
    assert_eq!(disk.path, "disk0");
    assert_eq!(disk.common, expected);
    assert_eq!(disk.backend, Backend::Memory);
    let flattened: FlatOnly = "size=512".parse().unwrap();
    assert_eq!(flattened.common, expected);
    assert_eq!("".parse::<Empty>().unwrap(), Empty {});
    assert!("unknown=1".parse::<Empty>().is_err());
}

// Test: Select an optional-value group key with and without its value, or a required group.
// Expected: Omitted optional values remain None; explicit values and required choices survive.
#[test]
fn group_payloads_and_required_choices_are_preserved() {
    for (argument, expected) in [("raw_device", None), ("raw_device=17", Some(17))] {
        let disk: Disk = format!("disk0,size=512,{argument}").parse().unwrap();
        assert_eq!(disk.backend, Backend::RawDevice(expected));
    }
    assert_eq!("uefi".parse::<RequiredBoot>().unwrap().boot, Boot::Uefi);
    assert_eq!(
        "grub=boot.cfg".parse::<RequiredBoot>().unwrap().boot,
        Boot::Grub("boot.cfg".into())
    );
    let error = "".parse::<RequiredBoot>().unwrap_err();
    assert_eq!(error.to_string(), "one of 'uefi', 'grub' is required");
}

// Test: Supply duplicate, unknown, missing, malformed or mutually exclusive option values.
// Expected: Invalid input is rejected rather than overwritten, defaulted or partially accepted.
#[test]
fn invalid_user_input_is_rejected() {
    for text in [
        "",
        "disk0",
        "disk0,size=1,size=2",
        "disk0,size=bad",
        "disk0,size=1,readonly=maybe",
        "disk0,size=1,cache,cache",
        "disk0,size=1,mem,host-file=image",
        "disk0,size=1,mem=value",
        "disk0,size=1,raw_device=invalid",
        "disk0,size=1,unknown=value",
        "disk0,size=1,queues=7",
    ] {
        assert!(
            text.parse::<Disk>().is_err(),
            "unexpectedly accepted {text:?}"
        );
    }
    assert!("size=1,unknown=2".parse::<FlatOnly>().is_err());
}

// Test: Read nested completion keys and help text from the generated public trait.
// Expected: Flattening preserves key order, renames, snake case and trimmed multiline docs.
#[test]
fn completion_metadata_matches_the_accepted_option_names() {
    let expected = [
        "size",
        "count",
        "label",
        "serial",
        "readonly",
        "cache",
        "policy",
        "mem",
        "host-file",
        "raw_device",
    ];
    let mut keys = Vec::new();
    Disk::append_keys(&mut keys);
    assert_eq!(keys, expected);
    let options = Disk::options();
    assert_eq!(
        options.iter().map(|option| option.key).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(options[0].help, "Required byte size.");
    assert_eq!(
        options[4].help,
        "Allow read-only access.\nNever writes guest data."
    );
    assert_eq!(options[7].help, "Use guest memory.");
    assert_eq!(options[1].help, "");
}

// Test: Parse paths and scalar/group values containing additional equals signs.
// Expected: The positional token stays verbatim, only the first option equals sign
//       separates its key, and explicit off still selects the mapped absent value.
#[test]
fn generated_parser_preserves_equals_inside_user_values() {
    let disk: Disk = concat!(
        "disk=nightly.raw,size=4096,label=mode=rw,serial==token==,",
        "host-file=backing=2026.raw,readonly=off,cache=off,policy=off"
    )
    .parse()
    .unwrap();
    assert_eq!(
        disk,
        Disk {
            path: "disk=nightly.raw".into(),
            common: Common {
                size: 4096,
                queues: 4,
                label: "mode=rw".into(),
                serial: Some("=token==".into()),
                readonly: false,
                cache: Some(false),
                policy: 3,
            },
            backend: Backend::File("backing=2026.raw".into()),
        }
    );
}
