// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side command-line utilities built on the Petri test framework.
//!
//! The current `cloud-init` command creates a raw Linux cloud-init disk with a
//! Petri user and an architecture-matched Pipette guest agent. It resolves the
//! required artifacts from the repository's known VMM-test paths and is useful
//! when preparing guest images outside a full test run.
//!
//! Invoke it as `petri-tool cloud-init --arch <arch> <output>` or through
//! `cargo run -p petri-tool -- ...`.

#![forbid(unsafe_code)]

use anyhow::Context as _;
use clap::Parser;
use petri::ArtifactResolver;
use petri::TestArtifactRequirements;

/// Command line interface for petri-related tasks.
#[derive(Parser)]
struct CliArgs {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Builds a cloud-init disk image for a Linux VM image.
    ///
    /// This image creates a petri user with the password "petri".
    CloudInit {
        /// The architecture of the VM image.
        #[clap(long)]
        arch: MachineArch,

        /// Path to the output disk image.
        output: std::path::PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum MachineArch {
    #[clap(name = "x86_64")]
    X86_64,
    Aarch64,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    match args.command {
        Command::CloudInit { output, arch } => {
            let image = build_with_artifacts(|resolver: ArtifactResolver<'_>| {
                petri::disk_image::AgentImage::new(petri_artifacts_common::tags::OsFlavor::Linux)
                    .with_pipette(
                        &resolver,
                        match arch {
                            MachineArch::X86_64 => {
                                petri_artifacts_common::tags::MachineArch::X86_64
                            }
                            MachineArch::Aarch64 => {
                                petri_artifacts_common::tags::MachineArch::Aarch64
                            }
                        },
                    )
            })?;

            let disk = image
                .build(petri::disk_image::ImageType::Raw)
                .context("failed to build disk image")?
                .context("no files for the this platform")?;
            disk.persist(output)
                .context("failed to persist disk image")?;

            Ok(())
        }
    }
}

fn build_with_artifacts<R>(mut f: impl FnMut(ArtifactResolver<'_>) -> R) -> anyhow::Result<R> {
    let resolver =
        petri_artifact_resolver_openvmm_known_paths::OpenvmmKnownPathsTestArtifactResolver::new("");
    let mut requirements = TestArtifactRequirements::new();
    f(ArtifactResolver::collector(&mut requirements));
    let artifacts = requirements.resolve(&resolver)?;
    Ok(f(ArtifactResolver::resolver(&artifacts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
        CliArgs::try_parse_from(std::iter::once("petri-tool").chain(args.iter().copied()))
    }

    // Test: Validate the command definition and parse cloud-init invocations
    //       for both architectures, with an unknown spelling and missing values.
    // Expected: The definition is consistent; `x86_64` and `aarch64` select
    //       their architecture with the output path; other spellings and a
    //       missing arch or output are rejected.
    #[test]
    fn cloud_init_arguments_are_validated() {
        CliArgs::command().debug_assert();
        for (arch, expected) in [("x86_64", "X86_64"), ("aarch64", "Aarch64")] {
            match parse(&["cloud-init", "--arch", arch, "out.img"])
                .unwrap()
                .command
            {
                Command::CloudInit { arch, output } => {
                    assert_eq!(format!("{arch:?}"), expected);
                    assert_eq!(output, std::path::Path::new("out.img"));
                }
            }
        }
        for bad in [
            &["cloud-init", "--arch", "x86-64", "out.img"][..],
            &["cloud-init", "--arch", "x86_64"],
            &["cloud-init", "out.img"],
            &[],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    // Test: Run the two-phase artifact helper with a closure that requires no
    //       artifacts.
    // Expected: The closure runs once to collect requirements and once to
    //       resolve them, and the resolving call's result is returned.
    #[test]
    fn artifact_helper_collects_then_resolves() {
        let mut calls = 0;
        let result = build_with_artifacts(|_resolver: ArtifactResolver<'_>| {
            calls += 1;
            calls
        })
        .unwrap();
        assert_eq!((calls, result), (2, 2));
    }
}
