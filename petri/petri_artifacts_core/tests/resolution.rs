// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native public-API tests for artifact requirements and binary queries.

use petri_artifacts_core::*;
use std::path::Path;
use std::path::PathBuf;
use test_with_tracing::test;

declare_artifacts!(
    /// First fixture identity sharing a filename with another artifact.
    FIRST("shared.bin", ANY),
    /// Second fixture identity sharing a filename with another artifact.
    SECOND("shared.bin", ANY),
);
const FIXTURE_BLOB: Option<ArtifactBlobStorage> = Some(ArtifactBlobStorage {
    storage_account: "unusedfixture",
    container: "unusedfixture",
});
declare_artifacts_inner!(
    /// Fixture identity permitting a remote source.
    REMOTE(crate::FIXTURE_BLOB, "remote.bin", IMAGE),
);

struct RemoteOnly;

impl ResolveTestArtifact for RemoteOnly {
    fn resolve(&self, _id: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
        anyhow::bail!("fixture unavailable locally")
    }

    fn resolve_source(&self, _id: ErasedArtifactHandle) -> anyhow::Result<ArtifactSource> {
        Ok(ArtifactSource::Remote {
            url: "https://example.invalid/owned-fixture.bin".into(),
        })
    }
}

struct LocalFiles;

impl ResolveTestArtifact for LocalFiles {
    fn resolve(&self, id: ErasedArtifactHandle) -> anyhow::Result<PathBuf> {
        if id == FIRST {
            Ok(PathBuf::from("first/shared.bin"))
        } else if id == SECOND {
            Ok(PathBuf::from("second/shared.bin"))
        } else {
            anyhow::bail!("fixture unavailable locally")
        }
    }
}

// Test: Merge required remote-capable and optional local-only registrations
//       of the same artifact in both possible registration orders.
// Expected: The combined requirement is required and local-only, so a
//       remote-only provider reports failure instead of weakening either policy.
#[test]
fn duplicate_requirements_combine_strictness_independently_of_order() {
    for registrations in [
        [
            (RemoteAccess::Allow, false),
            (RemoteAccess::LocalOnly, true),
        ],
        [
            (RemoteAccess::LocalOnly, true),
            (RemoteAccess::Allow, false),
        ],
    ] {
        let mut requirements = TestArtifactRequirements::new();
        for (remote, optional) in registrations {
            requirements.require(REMOTE, remote, optional, None);
        }
        let error = match requirements.resolve(RemoteOnly) {
            Err(error) => error,
            Ok(_) => panic!("required local-only artifact unexpectedly resolved remotely"),
        };
        assert!(error.to_string().contains("fixture unavailable locally"));
        assert!(error.to_string().contains(&format!("{:?}", REMOTE)));
    }
}

// Test: Merge two optional registrations with conflicting remote access policies.
// Expected: Local-only still wins in either order, but an unavailable optional
//       artifact is absent from the resolved set without failing the whole set.
#[test]
fn optional_duplicates_remain_optional_without_remote_downgrade() {
    for registrations in [
        [RemoteAccess::Allow, RemoteAccess::LocalOnly],
        [RemoteAccess::LocalOnly, RemoteAccess::Allow],
    ] {
        let mut requirements = TestArtifactRequirements::new();
        for remote in registrations {
            requirements.require(REMOTE, remote, true, None);
        }
        let artifacts = requirements.resolve(RemoteOnly).unwrap();
        assert!(artifacts.try_get_source(REMOTE).is_none());
    }
}

// Test: Resolve two declared artifacts sharing a filename and target.
// Expected: Their distinct typed identities retain different provider paths,
//       including through the public resolving phase and optional lookup.
#[test]
fn same_filename_artifacts_preserve_distinct_resolved_identities() {
    let mut requirements = TestArtifactRequirements::new();
    {
        let collector = ArtifactResolver::collector(&mut requirements);
        collector.require(FIRST);
        collector.try_require(SECOND);
    }
    let artifacts = requirements.resolve(LocalFiles).unwrap();
    let resolver = ArtifactResolver::resolver(&artifacts);
    assert_eq!(resolver.require(FIRST).get(), Path::new("first/shared.bin"));
    assert_eq!(
        resolver.try_require(SECOND).get(),
        Some(Path::new("second/shared.bin"))
    );
    assert!(resolver.try_require(REMOTE).get().is_none());
}

// Test: Collect a remote-capable request for a non-blob artifact under the public
//       remote policy, without changing process-wide environment settings.
// Expected: A non-blob artifact remains local-only even when its caller allows
//       remote access, and failure identifies the missing local artifact.
#[test]
fn collector_does_not_grant_remote_access_to_non_blob_artifacts() {
    let mut requirements = TestArtifactRequirements::new();
    {
        let mut collector = ArtifactResolver::collector(&mut requirements);
        collector.set_remote_policy(RemoteAccess::Allow);
        collector.require_source(FIRST, RemoteAccess::Allow);
    }
    let error = match requirements.resolve(RemoteOnly) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("non-blob artifact unexpectedly resolved remotely"),
    };
    assert!(error.contains(&format!("{:?}", FIRST)));
}

// Test: Resolve a required artifact explicitly allowed to use a remote provider.
// Expected: Resolution retains its remote source and exact URL without attempting
//       a local-only resolution or converting the URL into a filesystem path.
#[test]
fn remote_requirement_retains_its_source_without_local_resolution() {
    let mut requirements = TestArtifactRequirements::new();
    requirements.require(REMOTE, RemoteAccess::Allow, false, None);
    let artifacts = requirements.resolve(RemoteOnly).unwrap();
    match artifacts.get_source(REMOTE) {
        ArtifactSource::Remote { url } => {
            assert_eq!(url, "https://example.invalid/owned-fixture.bin")
        }
        ArtifactSource::Local(_) => panic!("remote provider unexpectedly became a local path"),
    }
}

// Test: Resolve a set containing two unavailable required artifact identities.
// Expected: One aggregate error retains both identities and provider context
//       regardless of hash iteration order, rather than stopping at the first miss.
#[test]
fn required_resolution_errors_retain_every_failed_identity() {
    let mut requirements = TestArtifactRequirements::new();
    requirements.require(FIRST, RemoteAccess::LocalOnly, false, None);
    requirements.require(SECOND, RemoteAccess::LocalOnly, false, None);
    let error = match requirements.resolve(RemoteOnly) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("missing required artifacts unexpectedly resolved"),
    };
    assert!(error.contains(&format!("{:?}", FIRST)));
    assert!(error.contains(&format!("{:?}", SECOND)));
    assert!(error.contains("fixture unavailable locally"));
}

#[cfg(unix)]
fn query_binary(body: &str) -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("query-fixture");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (root, path)
}

// Test: Query an owned executable that validates the command flags, two test
//       names and stdin EOF before returning a nested artifact-list response.
// Expected: The exact request protocol reaches the child and every response
//       category is decoded without dropping nested test requirements.
#[cfg(unix)]
#[test]
fn binary_query_transmits_names_and_decodes_all_requirement_categories() {
    let (_root, path) = query_binary(
        r#"
[ "$#" -eq 2 ] && [ "$1" = "--list-required-artifacts" ] && [ "$2" = "--tests-from-stdin" ] || exit 31
IFS= read -r first && [ "$first" = "suite::first" ] || exit 32
IFS= read -r second && [ "$second" = "suite::second" ] || exit 33
if IFS= read -r extra; then exit 34; fi
printf '%s' '{"required":["required-id"],"optional":["optional-id"],"nested":[["nested-test",["archive-id"]]]}'
"#,
    );
    let output = query_test_binary_artifacts(&path, &["suite::first", "suite::second"]).unwrap();
    assert_eq!(output.required, ["required-id"]);
    assert_eq!(output.optional, ["optional-id"]);
    assert_eq!(
        output.nested,
        vec![("nested-test".into(), vec!["archive-id".into()])]
    );
}

// Test: Query owned executables that fail, emit invalid UTF-8 or invalid JSON,
//       and query an executable path that does not exist.
// Expected: Launch, exit, encoding and parsing failures remain distinguishable
//       errors with context; none becomes an empty successful artifact list.
#[cfg(unix)]
#[test]
fn binary_query_preserves_distinct_launch_exit_encoding_and_parse_failures() {
    let no_tests: [&str; 0] = [];
    for (body, expected) in [
        (
            "printf 'fixture exit failure' >&2; exit 7",
            "test binary failed: fixture exit failure",
        ),
        ("printf '\\377'", "test output is not valid UTF-8"),
        ("printf 'not-json'", "failed to parse test output JSON"),
    ] {
        let (_root, path) = query_binary(body);
        let error = match query_test_binary_artifacts(&path, &no_tests) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("failed binary query unexpectedly returned artifacts"),
        };
        assert!(error.contains(expected), "{error}");
    }
    let root = tempfile::tempdir().unwrap();
    let error =
        match query_test_binary_artifacts(&root.path().join("missing-executable"), &no_tests) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("missing query executable unexpectedly launched"),
        };
    assert!(error.contains("failed to spawn test binary"));
}
