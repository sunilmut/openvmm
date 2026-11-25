// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn arguments(command: &Command) -> Vec<OsString> {
    command.get_args().map(OsStr::to_owned).collect()
}

// Test: Assign a cmdlet result, filter it through a pipeline, then start a second statement.
// Expected: Optional arguments retain order, absent values disappear and script syntax stays raw.
#[test]
fn assignments_pipelines_and_optional_arguments_compose_without_extra_quoting() {
    let variable = Variable::new("items");
    let command = PowerShellBuilder::new()
        .cmdlet_to_var("Get-Item", &variable)
        .flag("Literal")
        .flag_opt(Some("Force"))
        .flag_opt(None::<&str>)
        .arg("Path", r"C:\some path\it's.txt")
        .arg_opt("Depth", Some(3u32))
        .arg_opt("Unused", None::<u32>)
        .positional_opt(Some("tail"))
        .positional_opt(None::<&str>)
        .pipeline()
        .cmdlet("Where-Object")
        .positional(Script::new("$_.Enabled"))
        .next()
        .cmdlet("Write-Output")
        .positional(&variable)
        .finish()
        .build();
    assert!(matches!(
        command.get_program().to_str(),
        Some("pwsh.exe" | "powershell.exe")
    ));
    assert_eq!(
        arguments(&command),
        [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$items",
            "=",
            "Get-Item",
            "-Literal",
            "-Force",
            "-Path",
            r"'C:\some path\it''s.txt'",
            "-Depth",
            "3",
            "'tail'",
            "|",
            "Where-Object",
            "{ $_.Enabled }",
            ";",
            "Write-Output",
            "$items",
        ]
        .map(OsString::from)
    );
}

// Test: Nest arrays, dictionaries, booleans and trusted expressions as values in one command.
// Expected: Nesting preserves PowerShell types, empty collections and dictionary entry order.
#[test]
fn nested_collections_and_owned_values_preserve_expression_boundaries() {
    let entries = HashTable::new([
        ("labels", Value::new(Array::new(["a'b", "second"]))),
        ("enabled", Value::new(true)),
        ("disabled", Value::new(false)),
        ("empty", Value::new(Array::new(Vec::<u32>::new()))),
        ("expression", Value::new(RawVal::new("$env:TEMP"))),
    ]);
    let command = PowerShellBuilder::new()
        .cmdlet("Write-Output")
        .positional(Array::new([
            Value::new(entries),
            Value::new(HashTable::<String, String>::new([])),
        ]))
        .finish()
        .build();
    assert_eq!(
        arguments(&command),
        [
            "-NoProfile", "-NonInteractive", "-Command", "Write-Output",
            "@(@{'labels'=@('a''b'; 'second'); 'enabled'=$true; 'disabled'=$false; 'empty'=@(); 'expression'=$env:TEMP}; @{})",
        ].map(OsString::from)
    );
}

// Test: Pass numeric boundary values and fractional values alongside each other in one array.
// Expected: Numeric values stay unquoted and retain their sign, precision and integer width.
#[test]
fn numeric_arrays_keep_values_as_powershell_numbers() {
    let values = [
        Value::new(u8::MAX),
        Value::new(u16::MAX),
        Value::new(u32::MAX),
        Value::new(u64::MAX),
        Value::new(i8::MIN),
        Value::new(i16::MIN),
        Value::new(i32::MIN),
        Value::new(i64::MIN),
        Value::new(-1.25f32),
        Value::new(0.125f64),
    ];
    let command = PowerShellBuilder::new()
        .cmdlet("Measure-Object")
        .arg("InputObject", Array::new(values))
        .finish()
        .build();
    assert_eq!(
        arguments(&command),
        [
            "-NoProfile", "-NonInteractive", "-Command", "Measure-Object", "-InputObject",
            "@(255; 65535; 4294967295; 18446744073709551615; -128; -32768; -2147483648; -9223372036854775808; -1.25; 0.125)",
        ].map(OsString::from)
    );
}

// Test: Build a command from borrowed/owned paths, a GUID, a timestamp and an owned string value.
// Expected: Display values and path arguments are literal strings and never become script syntax.
#[test]
fn paths_display_types_and_owned_strings_remain_literal_arguments() {
    let path = PathBuf::from(r"C:\some dir\$name's.txt");
    let guid: guid::Guid = "01234567-89ab-cdef-0123-456789abcdef".parse().unwrap();
    let timestamp: jiff::Timestamp = "2026-01-02T03:04:05Z".parse().unwrap();
    let label = Value::new(String::from("a'$(value)"));
    let command = PowerShellBuilder::new()
        .cmdlet("Set-Item")
        .arg("Path", path.as_path())
        .arg("Destination", path)
        .arg("Id", guid)
        .arg("Time", timestamp)
        .positional(label)
        .finish()
        .build();
    assert_eq!(
        arguments(&command),
        [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Set-Item",
            "-Path",
            r"'C:\some dir\$name''s.txt'",
            "-Destination",
            r"'C:\some dir\$name''s.txt'",
            "-Id",
            "'01234567-89ab-cdef-0123-456789abcdef'",
            "-Time",
            "'2026-01-02T03:04:05Z'",
            "'a''$(value)'",
        ]
        .map(OsString::from)
    );
}
