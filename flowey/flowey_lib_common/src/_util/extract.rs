// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use flowey::node::prelude::*;

const FLOWEY_INFO_DIR: &str = ".flowey_info";
const FLOWEY_EXTRACT_DIR: &str = "extracted";

#[derive(Clone)]
#[non_exhaustive]
pub struct ExtractZipDeps<C = VarNotClaimed> {
    persistent_dir: Option<ReadVar<PathBuf, C>>,
    bsdtar_installed: ReadVar<SideEffect, C>,
}

impl ClaimVar for ExtractZipDeps {
    type Claimed = ExtractZipDeps<VarClaimed>;

    fn claim(self, ctx: &mut StepCtx<'_>) -> Self::Claimed {
        let Self {
            persistent_dir,
            bsdtar_installed,
        } = self;
        ExtractZipDeps {
            persistent_dir: persistent_dir.claim(ctx),
            bsdtar_installed: bsdtar_installed.claim(ctx),
        }
    }
}

#[track_caller]
pub fn extract_zip_if_new_deps(ctx: &mut NodeCtx<'_>) -> ExtractZipDeps {
    let platform = ctx.platform();
    ExtractZipDeps {
        persistent_dir: ctx.persistent_dir(),
        bsdtar_installed: ctx.reqv(|v| crate::install_dist_pkg::Request::Install {
            package_names: match platform {
                FlowPlatform::Linux(linux_distribution) => match linux_distribution {
                    FlowPlatformLinuxDistro::Fedora | FlowPlatformLinuxDistro::OpenSuse => {
                        vec!["bsdtar".into()]
                    }
                    FlowPlatformLinuxDistro::Ubuntu => vec!["libarchive-tools".into()],
                    FlowPlatformLinuxDistro::AzureLinux | FlowPlatformLinuxDistro::Arch => {
                        vec!["libarchive".into()]
                    }
                    FlowPlatformLinuxDistro::Nix => vec![],
                    FlowPlatformLinuxDistro::Unknown => vec![],
                },
                _ => {
                    vec![]
                }
            },
            done: v,
        }),
    }
}

/// Extracts the given `file` into `persistent_dir` (or into
/// [`std::env::current_dir()`], if no persistent dir is available).
///
/// To avoid redundant unzips between pipeline runs, callers must provide a
/// `file_version` string that identifies the current file. If the
/// previous run already unzipped a zip with the given `file_version`, this
/// function will return nearly instantaneously.
pub fn extract_zip_if_new(
    rt: &mut RustRuntimeServices<'_>,
    deps: ExtractZipDeps<VarClaimed>,
    file: &Path,
    file_version: &str,
) -> anyhow::Result<PathBuf> {
    let ExtractZipDeps {
        persistent_dir,
        bsdtar_installed: _,
    } = deps;

    let root_dir = match persistent_dir {
        Some(dir) => rt.read(dir),
        None => rt.sh.current_dir(),
    };

    let bsdtar = crate::_util::bsdtar_name(rt);
    extract_archive_if_new(rt, &root_dir, file, file_version, bsdtar)
}

/// Extracts the given `.tar.gz` `file` into `persistent_dir` (or into
/// [`std::env::current_dir()`], if no persistent dir is available).
///
/// Unlike `.tar.bz2`, `.tar.gz` is handled natively by every platform's `tar`,
/// so this helper has no install-package dependency to track. The caller
/// resolves the persistent dir itself and passes it (already read) as
/// `persistent_dir` — no `Deps` struct needed.
///
/// To avoid redundant extracts between pipeline runs, callers must provide a
/// `file_version` string that identifies the current file. If the previous
/// run already extracted an archive with the given `file_version`, this
/// function will return nearly instantaneously.
pub fn extract_tar_gz_if_new(
    rt: &mut RustRuntimeServices<'_>,
    persistent_dir: Option<&Path>,
    file: &Path,
    file_version: &str,
) -> anyhow::Result<PathBuf> {
    let root_dir = match persistent_dir {
        Some(dir) => dir.to_path_buf(),
        None => rt.sh.current_dir(),
    };

    extract_archive_if_new(rt, &root_dir, file, file_version, "tar")
}

#[derive(Clone)]
#[non_exhaustive]
pub struct ExtractTarBz2Deps<C = VarNotClaimed> {
    persistent_dir: Option<ReadVar<PathBuf, C>>,
    bzip2_installed: ReadVar<SideEffect, C>,
}

impl ClaimVar for ExtractTarBz2Deps {
    type Claimed = ExtractTarBz2Deps<VarClaimed>;

    fn claim(self, ctx: &mut StepCtx<'_>) -> Self::Claimed {
        let Self {
            persistent_dir,
            bzip2_installed,
        } = self;
        ExtractTarBz2Deps {
            persistent_dir: persistent_dir.claim(ctx),
            bzip2_installed: bzip2_installed.claim(ctx),
        }
    }
}

#[track_caller]
pub fn extract_tar_bz2_if_new_deps(ctx: &mut NodeCtx<'_>) -> ExtractTarBz2Deps {
    ExtractTarBz2Deps {
        persistent_dir: ctx.persistent_dir(),
        bzip2_installed: ctx.reqv(|v| crate::install_dist_pkg::Request::Install {
            package_names: vec!["bzip2".into()],
            done: v,
        }),
    }
}

/// Extracts the given `file` into `persistent_dir` (or into
/// [`std::env::current_dir()`], if no persistent dir is available).
///
/// To avoid redundant extractions between pipeline runs, callers must provide a
/// `file_version` string that identifies the current file. If the previous run
/// already extracted an archive with the given `file_version`, this function will
/// return nearly instantaneously.
pub fn extract_tar_bz2_if_new(
    rt: &mut RustRuntimeServices<'_>,
    deps: ExtractTarBz2Deps<VarClaimed>,
    file: &Path,
    file_version: &str,
) -> anyhow::Result<PathBuf> {
    let ExtractTarBz2Deps {
        persistent_dir,
        bzip2_installed: _,
    } = deps;

    let root_dir = match persistent_dir {
        Some(dir) => rt.read(dir),
        None => rt.sh.current_dir(),
    };

    extract_archive_if_new(rt, &root_dir, file, file_version, "tar")
}

fn extract_archive_if_new(
    rt: &mut RustRuntimeServices<'_>,
    root_dir: &Path,
    file: &Path,
    file_version: &str,
    tar: &str,
) -> anyhow::Result<PathBuf> {
    let current_dir = rt.sh.current_dir();
    let file = current_dir.join(file).absolute()?;
    let root_dir = current_dir.join(root_dir).absolute()?;
    extract_if_new(&root_dir, &file, file_version, |extract_dir| {
        let _dir = rt.sh.push_dir(extract_dir);
        flowey::shell_cmd!(rt, "{tar} -xf {file}").run()?;
        Ok(())
    })
}

fn extract_if_new(
    root_dir: &Path,
    file: &Path,
    file_version: &str,
    extract: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let filename = file
        .file_name()
        .with_context(|| format!("archive path has no filename: {}", file.display()))?;
    let extract_dir = root_dir.join(FLOWEY_EXTRACT_DIR).join(filename);
    let pkg_info_dir = root_dir.join(FLOWEY_INFO_DIR);
    let pkg_info_file = pkg_info_dir.join(filename);

    let cached_version = match fs_err::read_to_string(&pkg_info_file) {
        Ok(info) => Some(info),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("failed to read archive extraction version"),
    };
    let extracted = match fs_err::metadata(&extract_dir) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir(),
                "archive extraction path is not a directory: {}",
                extract_dir.display()
            );
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err).context("failed to inspect archive extraction directory"),
    };

    if extracted && cached_version.as_deref() == Some(file_version) {
        log::info!("already extracted!");
        return Ok(extract_dir);
    }

    // Invalidate the old marker before replacing files, so a failed extraction
    // cannot leave a partial directory that looks like a cache hit.
    if cached_version.is_some() {
        fs_err::remove_file(&pkg_info_file)?;
    }
    if extracted {
        fs_err::remove_dir_all(&extract_dir)?;
    }
    fs_err::create_dir_all(&extract_dir)?;
    extract(&extract_dir)
        .with_context(|| format!("failed to extract archive {}", file.display()))?;
    fs_err::create_dir_all(&pkg_info_dir)?;
    fs_err::write(pkg_info_file, file_version)?;

    Ok(extract_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Populate an extraction cache, then request the same archive version.
    // Expected: The existing payload and marker remain intact and a cache hit
    //       does not attempt extraction again.
    #[test]
    fn same_version_reuses_the_existing_extraction() {
        let root = tempfile::tempdir().unwrap();
        let archive = Path::new("bundle.tar.gz");
        let first = extract_if_new(root.path(), archive, "v1", |dir| {
            fs_err::write(dir.join("payload"), b"original")?;
            Ok(())
        })
        .unwrap();
        let second = extract_if_new(root.path(), archive, "v1", |_| {
            anyhow::bail!("cache hit unexpectedly attempted extraction")
        })
        .unwrap();
        assert_eq!(second, first);
        assert_eq!(fs_err::read(second.join("payload")).unwrap(), b"original");
        assert_eq!(
            fs_err::read_to_string(root.path().join(".flowey_info/bundle.tar.gz")).unwrap(),
            "v1"
        );
    }

    // Test: Replace a cached archive with a newer version containing different files.
    // Expected: Obsolete payloads are removed and the cache marker describes
    //       the newly extracted contents, not the previous version.
    #[test]
    fn newer_version_removes_obsolete_files_before_publishing() {
        let root = tempfile::tempdir().unwrap();
        let archive = Path::new("bundle.tar.gz");
        extract_if_new(root.path(), archive, "v1", |dir| {
            fs_err::write(dir.join("obsolete"), b"old")?;
            Ok(())
        })
        .unwrap();
        let path = extract_if_new(root.path(), archive, "v2", |dir| {
            assert!(!dir.join("obsolete").exists());
            fs_err::write(dir.join("current"), b"new")?;
            Ok(())
        })
        .unwrap();
        assert!(!path.join("obsolete").exists());
        assert_eq!(fs_err::read(path.join("current")).unwrap(), b"new");
        assert_eq!(
            fs_err::read_to_string(root.path().join(".flowey_info/bundle.tar.gz")).unwrap(),
            "v2"
        );
    }

    // Test: Fail an upgrade after writing a partial payload, then retry that version.
    // Expected: Failure removes the old success marker and preserves error context;
    //       retry replaces partial files before publishing a new success marker.
    #[test]
    fn failed_upgrade_is_not_a_cache_hit_and_retry_discards_partial_files() {
        let root = tempfile::tempdir().unwrap();
        let archive = Path::new("bundle.tar.gz");
        extract_if_new(root.path(), archive, "v1", |_| Ok(())).unwrap();
        let error = extract_if_new(root.path(), archive, "v2", |dir| {
            fs_err::write(dir.join("partial"), b"incomplete")?;
            anyhow::bail!("planned extraction failure")
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("failed to extract archive"));
        assert!(message.contains("planned extraction failure"));
        let marker = root.path().join(".flowey_info/bundle.tar.gz");
        assert!(!marker.exists());
        let path = extract_if_new(root.path(), archive, "v2", |dir| {
            assert!(!dir.join("partial").exists());
            fs_err::write(dir.join("complete"), b"ready")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(fs_err::read(path.join("complete")).unwrap(), b"ready");
        assert_eq!(fs_err::read_to_string(marker).unwrap(), "v2");
    }

    // Test: Request a cached version after its extracted directory disappears.
    // Expected: A matching marker alone is not a cache hit; extraction restores
    //       the requested payload before returning a usable output path.
    #[test]
    fn matching_marker_without_output_requires_extraction() {
        let root = tempfile::tempdir().unwrap();
        let archive = Path::new("bundle.tar.gz");
        let first = extract_if_new(root.path(), archive, "v1", |dir| {
            fs_err::write(dir.join("payload"), b"original")?;
            Ok(())
        })
        .unwrap();
        fs_err::rename(&first, root.path().join("retired")).unwrap();
        let restored = extract_if_new(root.path(), archive, "v1", |dir| {
            fs_err::write(dir.join("payload"), b"restored")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(restored, first);
        assert_eq!(fs_err::read(restored.join("payload")).unwrap(), b"restored");
        assert_eq!(
            fs_err::read_to_string(root.path().join(".flowey_info/bundle.tar.gz")).unwrap(),
            "v1"
        );
    }

    // Test: Encounter a directory where the version file belongs, or a regular
    //       file where the extraction directory belongs.
    // Expected: Both errors are reported before extraction and existing data
    //       is preserved, rather than treating corrupt state as a cache miss.
    #[test]
    fn invalid_cache_paths_fail_without_extracting_or_removing_data() {
        let root = tempfile::tempdir().unwrap();
        let archive = Path::new("bundle.tar.gz");
        let marker = root.path().join(".flowey_info/bundle.tar.gz");
        fs_err::create_dir_all(&marker).unwrap();
        let error = extract_if_new(root.path(), archive, "v1", |_| {
            panic!("invalid version marker reached extraction")
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to read archive extraction version")
        );
        assert!(marker.is_dir());

        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("extracted/bundle.tar.gz");
        fs_err::create_dir_all(output.parent().unwrap()).unwrap();
        fs_err::write(&output, b"preserve this file").unwrap();
        let error = extract_if_new(root.path(), archive, "v1", |_| {
            panic!("invalid extraction path reached extraction")
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("archive extraction path is not a directory")
        );
        assert_eq!(fs_err::read(output).unwrap(), b"preserve this file");
    }
}
