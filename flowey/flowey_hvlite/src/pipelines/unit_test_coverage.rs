// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Opt-in local unit coverage, independent of PR CI publication.

use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_hvlite::build_nextest_unit_tests::BuildNextestUnitTestMode;
use flowey_lib_hvlite::collect_unit_test_coverage::Options;
use flowey_lib_hvlite::common::CommonProfile;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct UnitTestCoverageCli {
    /// Exact workspace package names to test (repeat for multiple packages).
    #[clap(short = 'p', long = "package", required = true)]
    packages: Vec<String>,

    /// Nextest filter expression, within the selected packages.
    #[clap(short = 'E', long)]
    filter: Option<String>,

    /// Also report changed-line coverage against the merge base of this revision and HEAD.
    #[clap(long)]
    base: Option<String>,

    /// Fresh result directory. Defaults to a unique directory under target/unit-coverage.
    #[clap(long)]
    output: Option<PathBuf>,

    /// Install missing build dependencies and Rust components using Flowey's normal setup.
    #[clap(long)]
    install_missing_deps: bool,
}

impl IntoPipeline for UnitTestCoverageCli {
    fn into_pipeline(self, backend: PipelineBackendHint) -> anyhow::Result<Pipeline> {
        anyhow::ensure!(
            matches!(backend, PipelineBackendHint::Local)
                && matches!(FlowPlatform::host(backend), FlowPlatform::Linux(_)),
            "unit-test-coverage currently requires local x64 or ARM64 Linux"
        );
        let target = match FlowArch::host(backend) {
            FlowArch::X86_64 => target_lexicon::triple!("x86_64-unknown-linux-gnu"),
            FlowArch::Aarch64 => target_lexicon::triple!("aarch64-unknown-linux-gnu"),
            arch => anyhow::bail!("unsupported Linux unit coverage architecture: {arch:?}"),
        };
        for package in &self.packages {
            anyhow::ensure!(
                !package.is_empty()
                    && package
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
                "use an exact workspace package name, not a package pattern: {package}"
            );
        }
        let output = std::path::absolute(self.output.unwrap_or_else(|| {
            crate::repo_root()
                .join("target/unit-coverage")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                ))
        }))?;
        anyhow::ensure!(
            !output.exists(),
            "coverage output already exists; choose a fresh directory: {}",
            output.display()
        );
        let mut pipeline = Pipeline::new();
        let begin = pipeline
            .new_job(
                FlowPlatform::host(backend),
                FlowArch::host(backend),
                "begin unit test coverage",
            )
            .dep_on(
                |ctx| flowey_lib_hvlite::collect_unit_test_coverage::Request::Begin {
                    repo_root: crate::repo_root(),
                    done: ctx.new_done_handle(),
                },
            )
            .finish();
        let collect = pipeline
            .new_job(
                FlowPlatform::host(backend),
                FlowArch::host(backend),
                "local unit test coverage",
            )
            .dep_on(|_| flowey_lib_hvlite::_jobs::cfg_versions::Request::Init)
            .dep_on(
                |_| flowey_lib_hvlite::_jobs::cfg_hvlite_reposource::Params {
                    hvlite_repo_source: flowey_lib_common::git_checkout::RepoSource::ExistingClone(
                        ReadVar::from_static(crate::repo_root()),
                    ),
                },
            )
            .dep_on(|_| flowey_lib_hvlite::_jobs::cfg_common::Params {
                local_only: Some(flowey_lib_hvlite::_jobs::cfg_common::LocalOnlyParams {
                    interactive: true,
                    auto_install: self.install_missing_deps,
                    ignore_rust_version: true,
                }),
                verbose: ReadVar::from_static(false),
                locked: true,
                deny_warnings: false,
                no_incremental: false,
            })
            .dep_on(|ctx| flowey_lib_hvlite::build_nextest_unit_tests::Request {
                target,
                profile: CommonProfile::Debug,
                build_mode: BuildNextestUnitTestMode::Coverage {
                    packages: self.packages,
                    options: Options {
                        output,
                        filter: self.filter,
                        base: self.base,
                    },
                    done: ctx.new_done_handle(),
                },
            })
            .finish();
        pipeline.non_artifact_dep(&collect, &begin);
        Ok(pipeline)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn coverage_cli(packages: &[&str]) -> UnitTestCoverageCli {
        UnitTestCoverageCli {
            packages: packages.iter().map(|s| (*s).into()).collect(),
            filter: None,
            base: None,
            output: None,
            install_missing_deps: false,
        }
    }

    // Test: Request local unit coverage through either cloud pipeline backend.
    // Expected: Both backends are rejected before creating coverage jobs, with
    //       the supported local Linux scope explained in the error.
    #[test]
    fn coverage_pipeline_rejects_cloud_backends() {
        for backend in [PipelineBackendHint::Github, PipelineBackendHint::Ado] {
            let error = match coverage_cli(&["flowey_hvlite"]).into_pipeline(backend) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("local coverage unexpectedly accepted a cloud backend"),
            };
            assert!(
                error.contains("requires local x64 or ARM64 Linux"),
                "{error}"
            );
        }
    }

    // Test: Supply package globs, version selectors, paths, punctuation and empty
    //       names to the native local coverage pipeline.
    // Expected: Each non-exact package selector is rejected explicitly before
    //       constructing a successful coverage job for the wrong package scope.
    #[test]
    fn coverage_pipeline_rejects_non_exact_package_selectors() {
        for package in ["pkg*", "pkg@1", "../pkg", "pkg.name", "pkg name", ""] {
            let error = match coverage_cli(&[package]).into_pipeline(PipelineBackendHint::Local) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("non-exact package selector unexpectedly succeeded: {package:?}"),
            };
            assert!(
                error.contains("use an exact workspace package name"),
                "{error}"
            );
        }
    }

    // Test: Request coverage output in the already-existing package directory.
    // Expected: The existing directory is rejected with a freshness error rather
    //       than yielding jobs that could overwrite prior coverage or source data.
    #[test]
    fn coverage_pipeline_rejects_existing_output_directory() {
        let mut cli = coverage_cli(&["flowey_hvlite"]);
        cli.output = Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        let error = match cli.into_pipeline(PipelineBackendHint::Local) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("coverage unexpectedly accepted an existing output directory"),
        };
        assert!(error.contains("coverage output already exists"), "{error}");
        assert!(error.contains(env!("CARGO_MANIFEST_DIR")), "{error}");
    }
}
