// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`OpenvmmKnownPathsTestArtifactResolver`].

#![forbid(unsafe_code)]

use anyhow::Context;
use petri_artifacts_common::artifacts::*;
use petri_artifacts_core::ArtifactId;
use petri_artifacts_core::ArtifactSource;
use petri_artifacts_core::ErasedArtifactHandle;
use petri_artifacts_vmm_test::artifacts::*;
use petri_artifacts_vmm_test::env::*;
use petri_artifacts_vmm_test::vmm_test_image_from_id;
use std::env::consts::EXE_EXTENSION;
use std::path::Path;
use std::path::PathBuf;

/// An implementation of [`petri_artifacts_core::ResolveTestArtifact`]
/// that resolves artifacts to various "known paths" within the context of
/// the OpenVMM repository.
pub struct OpenvmmKnownPathsTestArtifactResolver<'a>(&'a str);

impl<'a> OpenvmmKnownPathsTestArtifactResolver<'a> {
    /// Creates a new resolver for a test with the given name.
    pub fn new(test_name: &'a str) -> Self {
        Self(test_name)
    }
}

impl petri_artifacts_core::ResolveTestArtifact for OpenvmmKnownPathsTestArtifactResolver<'_> {
    fn resolve(&self, handle: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
        match handle.global_unique_id() {
            TEST_LOG_DIRECTORY::GLOBAL_UNIQUE_ID => test_log_directory_path(self.0),
            _ => resolve_artifact(handle),
        }
    }

    fn resolve_source(&self, handle: ErasedArtifactHandle) -> anyhow::Result<ArtifactSource> {
        // Try local resolution first.
        let local_err = match self.resolve(handle) {
            Ok(path) => return Ok(ArtifactSource::Local(path)),
            Err(e) => e,
        };

        // Fall back to remote URL for artifacts hosted on Azure Blob Storage,
        // but only for formats the blob disk backend supports (fixed VHD1 and flat).
        if let Some(url) = vmm_test_image_from_id(handle.global_unique_id()).and_then(|i| i.url()) {
            return Ok(ArtifactSource::Remote { url });
        }

        // No local path and no remote URL available — return the original error.
        Err(local_err)
    }
}

/// Get the path to an artifact from its erased artifact handle
pub fn resolve_artifact(handle: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
    if handle.is_image() {
        return get_vmm_test_image_path(handle.relative_path(), handle.global_unique_id());
    }

    let test_content_dir_path = test_content_dir_artifact_path(handle.relative_path());

    if test_content_dir_path.is_ok() {
        return test_content_dir_path;
    }

    let magic_path = resolve_magic_path_artifact(handle);

    if magic_path.is_ok() {
        return magic_path;
    }

    let target = handle.target_triple();
    let exe_artifact_path = target
        .as_ref()
        .context("no associated triple for artifact")
        .and_then(|t| get_executable_path_artifact(t, None, handle.filename()));

    if exe_artifact_path.is_ok() {
        return exe_artifact_path;
    }

    let relative_path = get_executable_path_relative(handle.filename());

    if relative_path.is_ok() {
        return relative_path;
    }

    // also look for the other environment target, since it may work as well
    let fallback_target = handle.target_triple().and_then(|mut target| {
        matches!(
            target,
            target_lexicon::Triple {
                operating_system: target_lexicon::OperatingSystem::Linux,
                environment: target_lexicon::Environment::Gnu | target_lexicon::Environment::Musl,
                ..
            }
        )
        .then(|| {
            if target.environment == target_lexicon::Environment::Gnu {
                target.environment = target_lexicon::Environment::Musl;
            } else {
                target.environment = target_lexicon::Environment::Gnu;
            }
            target
        })
    });

    let fallback_test_content_dir_path = fallback_target
        .as_ref()
        .context("no fallback target")
        .and_then(|t| {
            test_content_dir_artifact_path(PathBuf::from(t.to_string()).join(handle.filename()))
        });

    if fallback_test_content_dir_path.is_ok() {
        return fallback_test_content_dir_path;
    }

    let fallback_exe_artifact_path = fallback_target
        .as_ref()
        .context("no associated triple for artifact")
        .and_then(|t| get_executable_path_artifact(t, None, handle.filename()));

    if fallback_exe_artifact_path.is_ok() {
        return fallback_exe_artifact_path;
    }

    Err(anyhow::anyhow!(
        "unable to locate {}:\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}",
        handle.global_unique_id(),
        test_content_dir_path.unwrap_err(),
        magic_path.unwrap_err(),
        exe_artifact_path.unwrap_err(),
        relative_path.unwrap_err(),
        fallback_test_content_dir_path.unwrap_err(),
        fallback_exe_artifact_path.unwrap_err(),
    ))
}

fn test_content_dir_artifact_path(relative_path: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    let test_content_dir =
        std::env::var(VMM_TESTS_CONTENT_DIR).context("test content dir env var not set")?;
    let path = PathBuf::from(test_content_dir).join(relative_path.as_ref());
    if !path.exists() {
        anyhow::bail!("{} not found", path.display())
    }
    Ok(path)
}

/// Path to the per-test test output directory.
fn test_log_directory_path(test_name: &str) -> anyhow::Result<PathBuf> {
    let root = std::env::var_os(TEST_OUTPUT_PATH)
        .map_or_else(|| get_repo_root().join("vmm_test_results"), PathBuf::from);
    let test_name =
        std::env::var(PETRI_NESTED_TEST_PARENT).unwrap_or_else(|_| test_name.to_string());
    // Use a per-test subdirectory, replacing `::` with `__` to avoid issues
    // with filesystems that don't support `::` in filenames.
    let path = root.join(test_name.replace("::", "__"));
    fs_err::create_dir_all(&path)?;
    Ok(path)
}

/// Gets a path to the root of the repo.
pub fn get_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Returns the Cargo build profile directory name for cross-compiled
/// artifacts (e.g., pipette).
///
/// Infers the profile from the currently running binary's path (looking
/// for a `release` component in the executable path). Defaults to `"debug"`.
// DEVNOTE: `pub` in order to re-use in perf_tests and other crates.
pub fn cargo_build_profile() -> &'static str {
    static PROFILE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PROFILE.get_or_init(|| {
        if let Ok(exe) = std::env::current_exe() {
            if exe.components().any(|c| c.as_os_str() == "release") {
                return "release".to_string();
            }
        }
        "debug".to_string()
    })
}

/// Attempts to find the path to a rust executable built by Cargo using the path
/// to the current executable to find the base path.
pub fn get_executable_path_relative(name: &str) -> anyhow::Result<PathBuf> {
    let mut current_exe = std::env::current_exe().context("unable to get current exe")?;
    // Sometimes we end up inside deps instead of the output dir, but if we
    // are we can just go up a level.
    if current_exe.parent().and_then(|x| x.file_name()).unwrap() == "deps" {
        current_exe.pop();
    }

    let exe_path = current_exe
        .parent()
        .context("current exe has no parent")?
        .join(Path::new(name).with_extension(EXE_EXTENSION));
    if !exe_path.exists() {
        anyhow::bail!("{} not found", exe_path.display());
    }
    Ok(exe_path)
}

/// Attempts to find the path to a rust executable built by Cargo using a path
/// constructed from the repo root and the default target directory. The build
/// profile is inferred from the current exe path if not specified.
pub fn get_executable_path_artifact(
    target: &target_lexicon::Triple,
    build_profile: Option<&str>,
    filename: &str,
) -> anyhow::Result<PathBuf> {
    let exe_path = get_repo_root()
        .join("target")
        .join(target.to_string())
        .join(build_profile.unwrap_or_else(|| cargo_build_profile()))
        .join(filename);
    if !exe_path.exists() {
        anyhow::bail!("{} not found", exe_path.display());
    }
    Ok(exe_path)
}

fn get_vmm_test_image_path(
    relative_path: impl AsRef<Path>,
    name: &str,
) -> Result<PathBuf, anyhow::Error> {
    let test_images_dir =
        std::env::var(VMM_TEST_IMAGES).context("test images dir env var not set")?;
    let path = PathBuf::from(test_images_dir).join(relative_path.as_ref());
    if !path.exists() {
        anyhow::bail!("missing {} at {}", name, path.display())
    }
    Ok(path)
}

// TODO: refactor flowey/openvmm to have a common source of truth for these
// magic paths. VMM tests run via flowey no longer use them.
fn resolve_magic_path_artifact(handle: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
    let package_dir = match handle.global_unique_id() {
        loadable::LINUX_DIRECT_TEST_KERNEL_X64::GLOBAL_UNIQUE_ID
        | loadable::LINUX_DIRECT_TEST_BZIMAGE_X64::GLOBAL_UNIQUE_ID
        | loadable::LINUX_DIRECT_TEST_INITRD_X64::GLOBAL_UNIQUE_ID
        | petritools::PETRITOOLS_EROFS_X64::GLOBAL_UNIQUE_ID => "underhill-deps-private/x64",
        loadable::LINUX_DIRECT_TEST_KERNEL_AARCH64::GLOBAL_UNIQUE_ID
        | loadable::LINUX_DIRECT_TEST_INITRD_AARCH64::GLOBAL_UNIQUE_ID
        | petritools::PETRITOOLS_EROFS_AARCH64::GLOBAL_UNIQUE_ID => {
            "underhill-deps-private/aarch64"
        }
        loadable::UEFI_FIRMWARE_X64::GLOBAL_UNIQUE_ID => {
            "hyperv.uefi.mscoreuefi.x64.RELEASE/MsvmX64/RELEASE_VS2022/FV"
        }
        loadable::UEFI_FIRMWARE_AARCH64::GLOBAL_UNIQUE_ID => {
            "hyperv.uefi.mscoreuefi.AARCH64.RELEASE/MsvmAARCH64/RELEASE_CLANGPDB/FV"
        }
        loadable::PCAT_FIRMWARE_X64::GLOBAL_UNIQUE_ID => {
            "Microsoft.Windows.VmFirmware.Pcat.amd64fre/content"
        }
        loadable::SVGA_FIRMWARE_X64::GLOBAL_UNIQUE_ID => {
            "Microsoft.Windows.VmEmulatedDevices.amd64fre/content"
        }
        virtio_win::VIRTIO_WINDOWS_DRIVERS::GLOBAL_UNIQUE_ID => "",

        _ => anyhow::bail!("not a magic path artifact"),
    };

    let magic_path = get_repo_root()
        .join(".packages")
        .join(package_dir)
        .join(handle.filename());
    if !magic_path.exists() {
        anyhow::bail!("{} not found", magic_path.display());
    }
    Ok(magic_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use petri_artifacts_core::ArtifactHandle;
    use petri_artifacts_core::ResolveTestArtifact;
    use petri_artifacts_vmm_test::artifacts::test_vhd::GEN2_WINDOWS_DATA_CENTER_CORE2025_X64;
    use petri_artifacts_vmm_test::artifacts::test_vhd::GEN2_WINDOWS_DATA_CENTER_CORE2025_X64_PREPPED;
    use test_with_tracing::test;

    fn local_image(handle: ErasedArtifactHandle) -> Option<PathBuf> {
        let dir = std::env::var_os(VMM_TEST_IMAGES)?;
        Some(PathBuf::from(dir).join(handle.relative_path())).filter(|p| p.exists())
    }

    // Test: Resolve the source of a blob-hosted image and of a prepared image
    //       that has no remote URL, under the process's existing environment.
    // Expected: A missing local blob image falls back to its exact remote URL;
    //       a missing prepared image keeps the local error instead of inventing
    //       a URL. Local copies, when present, take precedence.
    #[test]
    fn image_sources_prefer_local_then_blob_url_only_when_hosted() {
        let resolver = OpenvmmKnownPathsTestArtifactResolver::new("suite::test");
        let hosted = ArtifactHandle::<GEN2_WINDOWS_DATA_CENTER_CORE2025_X64>::new().erase();
        match (
            local_image(hosted),
            resolver.resolve_source(hosted).unwrap(),
        ) {
            (Some(path), ArtifactSource::Local(got)) => assert_eq!(got, path),
            (None, ArtifactSource::Remote { url }) => assert_eq!(
                url,
                format!(
                    "https://hvlitetestvhds.blob.core.windows.net/vhds/{}",
                    hosted.filename()
                )
            ),
            (local, other) => panic!("unexpected source {other:?} for local {local:?}"),
        }

        let prepped =
            ArtifactHandle::<GEN2_WINDOWS_DATA_CENTER_CORE2025_X64_PREPPED>::new().erase();
        if local_image(prepped).is_none() {
            let error = format!("{:#}", resolver.resolve_source(prepped).unwrap_err());
            assert!(
                error.contains("test images dir env var not set") || error.contains("missing"),
                "{error}"
            );
        }
    }

    // Test: Resolve a Linux GNU executable for a foreign architecture that is
    //       not built on this host.
    // Expected: Resolution either finds an existing file or reports every
    //       attempted location, including the Musl fallback for the GNU triple.
    #[test]
    fn missing_executable_error_lists_gnu_and_musl_fallback_attempts() {
        let handle = ArtifactHandle::<OPENVMM_LINUX_AARCH64>::new().erase();
        match resolve_artifact(handle) {
            Ok(path) => assert!(path.exists() && path.ends_with(handle.filename())),
            Err(error) => {
                let error = error.to_string();
                assert!(
                    error.starts_with(&format!("unable to locate {}:", handle.global_unique_id())),
                    "{error}"
                );
                assert!(error.contains("aarch64-unknown-linux-gnu"), "{error}");
                assert!(error.contains("aarch64-unknown-linux-musl"), "{error}");
                assert!(error.contains("not a magic path artifact"), "{error}");
                assert_eq!(error.matches("\n\t").count(), 6, "{error}");
            }
        }
    }

    // Test: Resolve a magic package artifact and a non-magic artifact directly.
    // Expected: The magic artifact maps to the repository .packages directory
    //       for its firmware package; the other artifact is rejected as non-magic.
    #[test]
    fn magic_paths_map_only_known_packages() {
        let firmware = ArtifactHandle::<loadable::UEFI_FIRMWARE_X64>::new().erase();
        let expected = get_repo_root()
            .join(".packages/hyperv.uefi.mscoreuefi.x64.RELEASE/MsvmX64/RELEASE_VS2022/FV")
            .join(firmware.filename());
        match resolve_magic_path_artifact(firmware) {
            Ok(path) => assert_eq!(path, expected),
            Err(error) => assert_eq!(
                error.to_string(),
                format!("{} not found", expected.display())
            ),
        }
        let other = ArtifactHandle::<OPENVMM_LINUX_AARCH64>::new().erase();
        assert_eq!(
            resolve_magic_path_artifact(other).unwrap_err().to_string(),
            "not a magic path artifact"
        );
    }

    // Test: Look up missing executables relative to the running test binary and
    //       under an explicit build profile in the repository target directory.
    // Expected: Relative lookup escapes the `deps` directory, and an explicit
    //       profile is used verbatim in the reported target path.
    #[test]
    fn executable_lookups_report_resolved_search_paths() {
        let name = "definitely_missing_known_paths_fixture";
        let error = get_executable_path_relative(name).unwrap_err().to_string();
        let exe = std::env::current_exe().unwrap();
        let mut dir = exe.parent().unwrap();
        if dir.file_name().unwrap() == "deps" {
            dir = dir.parent().unwrap();
        }
        let expected = dir.join(Path::new(name).with_extension(EXE_EXTENSION));
        assert_eq!(error, format!("{} not found", expected.display()));

        let triple: target_lexicon::Triple = "x86_64-unknown-linux-gnu".parse().unwrap();
        let error = get_executable_path_artifact(&triple, Some("fixture-profile"), name)
            .unwrap_err()
            .to_string();
        let expected = get_repo_root()
            .join("target/x86_64-unknown-linux-gnu/fixture-profile")
            .join(name);
        assert_eq!(error, format!("{} not found", expected.display()));
        assert!(matches!(cargo_build_profile(), "debug" | "release"));
    }
}
