// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use clap::{Arg, ArgAction, Command, CommandFactory};
use futures::executor::block_on;
use test_with_tracing::test;

struct Cli;

impl CommandFactory for Cli {
    fn command() -> Command {
        Command::new("vmctl")
            .disable_help_flag(true)
            .arg(
                Arg::new("mode")
                    .long("mode")
                    .short('m')
                    .value_parser(["fast", "safe"]),
            )
            .arg(
                Arg::new("port")
                    .long("port")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .short('v')
                    .action(ArgAction::SetTrue),
            )
            .subcommand(
                Command::new("disk").subcommand(Command::new("create").arg(Arg::new("image"))),
            )
            .subcommand(
                Command::new("network")
                    .disable_help_flag(true)
                    .disable_help_subcommand(true),
            )
    }

    fn command_for_update() -> Command {
        Self::command()
    }
}

struct Positionals;

impl CommandFactory for Positionals {
    fn command() -> Command {
        Command::new("vmctl")
            .disable_help_flag(true)
            .arg(Arg::new("target").value_parser(["alpha", "alpine", "beta"]))
            .arg(Arg::new("image").value_parser(["disk", "floppy"]))
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .action(ArgAction::SetTrue),
            )
            .subcommand(Command::new("create"))
    }

    fn command_for_update() -> Command {
        Self::command()
    }
}

// Construct a shell request without relying on process arguments or environment changes.
fn request(tokens: &[&str]) -> Complete {
    Complete {
        raw: None,
        position: None,
        cmd: tokens.iter().map(|token| (*token).to_owned()).collect(),
    }
}

// Run a completion request without a custom value provider.
fn complete<C: CommandFactory>(tokens: &[&str]) -> Vec<String> {
    block_on(request(tokens).generate_completions::<C>(None, ()))
}

// Test: Complete root commands, partial names and flag prefixes.
// Expected: Whole words precede flags, each section is sorted, and only matching words remain.
#[test]
fn root_suggestions_are_sorted_and_prefix_filtered() {
    let expected = [
        "disk",
        "help",
        "network",
        "--mode",
        "--port",
        "--verbose",
        "-m",
        "-v",
    ];
    assert_eq!(complete::<Cli>(&["vmctl", ""]), expected);
    assert_eq!(complete::<Cli>(&["vmctl", "d"]), ["disk"]);
    assert_eq!(complete::<Cli>(&["vmctl", "--v"]), ["--verbose"]);
}

// Test: Complete partial values following either spelling of an enumerated option.
// Expected: Only the option's matching values are offered, never unrelated flags or commands.
#[test]
fn option_values_are_completed_before_other_arguments() {
    for flag in ["--mode", "-m"] {
        assert_eq!(complete::<Cli>(&["vmctl", flag, "s"]), ["safe"]);
        assert_eq!(complete::<Cli>(&["vmctl", flag, ""]), ["fast", "safe"]);
    }
}

// Test: Complete an invocation with explicitly supplied flags and an already-filled option.
// Expected: Used option spellings are not offered again; unset options remain available.
#[test]
fn supplied_options_are_not_suggested_again() {
    assert_eq!(
        complete::<Cli>(&["vmctl", "--verbose", "--mode", "fast", ""]),
        ["disk", "help", "network", "--port"]
    );
}

// Test: Complete and then advance through two positional values beside a subcommand.
// Expected: Partial values stay editable, only the next positional is offered, and
//       positional suggestions do not include subcommands or completed earlier values.
#[test]
fn positional_values_advance_without_losing_partial_edits() {
    assert_eq!(
        complete::<Positionals>(&["vmctl", "al"]),
        ["alpha", "alpine"]
    );
    assert_eq!(
        complete::<Positionals>(&["vmctl", "alpha", "f"]),
        ["floppy"]
    );
    assert_eq!(
        complete::<Positionals>(&["vmctl", "alpha", "--"]),
        ["--verbose"]
    );
}

// Test: Use a raw cursor in the middle of a word, at whitespace, or beyond a nonempty argv.
// Expected: Completion uses text left of the cursor and safely falls back to the last option.
#[test]
fn raw_cursor_and_whitespace_determine_the_active_value() {
    let mut args = request(&["vmctl", "--mode", "safe"]);
    args.raw = Some("vmctl --mode safe ignored".into());
    args.position = Some("vmctl --mode s".len());
    assert_eq!(
        block_on(args.generate_completions::<Cli>(None, ())),
        ["safe"]
    );
    for (raw, position, tokens) in [
        ("vmctl --mode ", 13, vec!["vmctl", "--mode"]),
        ("vmctl --mode", 99, vec!["vmctl", "--mode"]),
    ] {
        let mut args = request(&tokens);
        args.raw = Some(raw.into());
        args.position = Some(position);
        assert_eq!(
            block_on(args.generate_completions::<Cli>(None, ())),
            ["fast", "safe"]
        );
    }
    let mut args = request(&["vmctl"]);
    args.raw = Some("vmctl".into());
    args.position = Some(5);
    assert!(block_on(args.generate_completions::<Cli>(None, ())).is_empty());
}

// Test: Invoke the same completion as a standalone tool or as a cargo-style subcommand.
// Expected: Only an actually matching parent executable is removed.
#[test]
fn parent_command_stripping_preserves_the_actual_tool_arguments() {
    for tokens in [
        vec!["cargo", "vmctl", "--mode", "s"],
        vec!["vmctl", "--mode", "s"],
    ] {
        assert_eq!(
            block_on(request(&tokens).generate_completions::<Cli>(Some("cargo"), ())),
            ["safe"]
        );
    }
}

struct ImageCompleter;

impl CustomCompleterFactory for ImageCompleter {
    type CustomCompleter = Self;

    async fn build(&self, ctx: &RootCtx<'_>) -> Self {
        assert_eq!(ctx.command.get_name(), "vmctl");
        assert_eq!((ctx.prev_arg, ctx.to_complete), ("create", "u"));
        let (_, disk) = ctx.matches.subcommand().unwrap();
        let (_, create) = disk.subcommand().unwrap();
        assert_eq!(create.get_one::<String>("image").unwrap(), "u");
        Self
    }
}

impl CustomCompleter for ImageCompleter {
    async fn complete(&self, _: &RootCtx<'_>, path: &[&str], arg: &str) -> Vec<String> {
        assert_eq!(path, ["vmctl", "disk", "create"]);
        assert_eq!(arg, "image");
        vec!["ubuntu".into(), "debian".into(), "utility".into()]
    }
}

// Test: Complete a dynamic image name inside two nested subcommands.
// Expected: The provider receives root matches and the full path; results are filtered/sorted.
#[test]
fn nested_custom_completion_receives_the_full_public_context() {
    assert_eq!(
        block_on(
            request(&["vmctl", "disk", "create", "u"])
                .generate_completions::<Cli>(None, ImageCompleter)
        ),
        ["ubuntu", "utility"]
    );
    assert_eq!(complete::<Cli>(&["vmctl", "disk", "--h"]), ["--help"]);
    assert!(complete::<Cli>(&["vmctl", "network", "--h"]).is_empty());
}

struct PortCompleter;

impl CustomCompleterFactory for PortCompleter {
    type CustomCompleter = Self;

    async fn build(&self, ctx: &RootCtx<'_>) -> Self {
        assert_eq!(ctx.matches.get_one::<String>("port").unwrap(), "6bad");
        Self
    }
}

impl CustomCompleter for PortCompleter {
    async fn complete(&self, _: &RootCtx<'_>, path: &[&str], arg: &str) -> Vec<String> {
        assert_eq!(path, ["vmctl"]);
        assert_eq!(arg, "port");
        vec!["6bad-port".into(), "67".into()]
    }
}

// Test: Complete an unfinished value that the original numeric parser would reject.
// Expected: Raw input reaches the custom provider and only its matching candidate is returned.
#[test]
fn typed_value_parsers_are_loosened_for_custom_completion() {
    assert_eq!(
        block_on(
            request(&["vmctl", "--port", "6bad"]).generate_completions::<Cli>(None, PortCompleter)
        ),
        ["6bad-port"]
    );
}

// Test: Parse the public completion request with one or both raw cursor arguments.
// Expected: Raw text and position require each other; trailing hyphenated argv remains intact.
#[test]
fn completion_request_parser_requires_paired_cursor_arguments() {
    assert!(Complete::try_parse_from(["complete", "--raw", "vmctl"]).is_err());
    assert!(Complete::try_parse_from(["complete", "--position", "0"]).is_err());
    let args = Complete::try_parse_from([
        "complete",
        "--raw",
        "vmctl --mode s",
        "--position",
        "14",
        "--",
        "vmctl",
        "--mode",
        "s",
    ])
    .unwrap();
    assert_eq!(args.raw.as_deref(), Some("vmctl --mode s"));
    assert_eq!(args.position, Some(14));
    assert_eq!(args.cmd, ["vmctl", "--mode", "s"]);
}

// Test: Generate each shell adapter for a hyphenated binary and nested completion command.
// Expected: All placeholders are replaced and shell-specific names retain the right spelling.
#[test]
fn shell_adapters_substitute_binary_and_nested_subcommand() {
    for (shell, declaration) in [
        (Shell::Fish, "function _vm_ctl_complete"),
        (Shell::Powershell, "-CommandName 'vm-ctl'"),
        (Shell::Zsh, "#compdef vm-ctl"),
    ] {
        let mut bytes = Vec::new();
        emit_completion_stub(shell, "vm-ctl", "dev complete", &mut bytes).unwrap();
        let script = String::from_utf8(bytes).unwrap();
        assert!(script.contains(declaration));
        assert!(script.contains("dev complete"));
        assert!(!script.contains("__COMMAND_NAME"));
        assert!(!script.contains("__COMPLETION_SUBCOMMAND__"));
    }
}

struct ClosedWriter;

impl std::io::Write for ClosedWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "adapter sink closed",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Test: Emit a completion adapter to a writer whose pipe has closed.
// Expected: The original typed I/O error is returned, not reported as successful output.
#[test]
fn adapter_write_errors_are_propagated() {
    let error =
        emit_completion_stub(Shell::Fish, "vmctl", "complete", &mut ClosedWriter).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "adapter sink closed");
}

// IGNORED: The raw cursor is passed directly to str::split_at without checking
//       a UTF-8 byte boundary, so this valid shell character offset panics.
//
// Test: Complete a raw cursor supplied as a character offset inside multibyte text.
// Expected: An invalid byte boundary does not panic.
#[test]
#[ignore = "product bug: raw cursor inside UTF-8 text panics in split_at"]
fn multibyte_raw_cursor_does_not_panic() {
    let mut args = request(&["vmctl", "\u{e9}"]);
    args.raw = Some("vmctl \u{e9}".into());
    args.position = Some(7);
    assert!(block_on(args.generate_completions::<Cli>(None, ())).is_empty());
}

// IGNORED: The out-of-range fallback unwraps cmd.last() even when argv is empty.
//
// Test: Supply a raw cursor beyond the line when no shell-tokenized argv was provided.
// Expected: The empty argv fallback does not panic and still offers root candidates.
#[test]
#[ignore = "product bug: out-of-range cursor unwraps an empty argv"]
fn out_of_range_raw_cursor_with_empty_argv_does_not_panic() {
    let mut args = request(&[]);
    args.raw = Some("vmctl".into());
    args.position = Some(99);
    assert_eq!(
        block_on(args.generate_completions::<Cli>(None, ())),
        complete::<Cli>(&["vmctl", ""])
    );
}

// IGNORED: The help-flag transformation visits subcommands but not the root,
//       so its built-in help argument is absent from completion suggestions.
//
// Test: Ask for the built-in help flag of an otherwise empty root command.
// Expected: The root command offers its help option just like nested subcommands.
#[test]
#[ignore = "product bug: root built-in help is not included in completion suggestions"]
fn root_builtin_help_remains_completable() {
    struct DefaultHelp;

    impl CommandFactory for DefaultHelp {
        fn command() -> Command {
            Command::new("vmctl")
        }

        fn command_for_update() -> Command {
            Self::command()
        }
    }

    assert_eq!(complete::<DefaultHelp>(&["vmctl", "--h"]), ["--help"]);
}

// IGNORED: An empty previous token matches an option's missing short spelling,
//       so an empty request incorrectly completes port values instead of root candidates.
//
// Test: Complete with empty tokenized argv or an empty raw command line.
// Expected: Both representations offer the same root candidates as an empty word.
#[test]
#[ignore = "product bug: empty previous token matches a missing flag spelling"]
fn empty_requests_offer_root_candidates() {
    let expected = complete::<Cli>(&["vmctl", ""]);
    assert_eq!(complete::<Cli>(&[]), expected);
    let mut args = request(&["vmctl"]);
    args.raw = Some(String::new());
    args.position = Some(0);
    assert_eq!(
        block_on(args.generate_completions::<Cli>(None, ())),
        expected
    );
}

// IGNORED: The shell's empty final token is recorded as an already-filled positional,
//       causing the next positional to be skipped and subcommands to be offered.
//
// Test: Complete an empty second positional after selecting the first value.
// Expected: Only the second positional's values and available flags are offered.
#[test]
#[ignore = "product bug: empty final token suppresses the next positional's candidates"]
fn empty_next_positional_offers_its_values() {
    assert_eq!(
        complete::<Positionals>(&["vmctl", "alpha", ""]),
        ["disk", "floppy", "--verbose"]
    );
}
