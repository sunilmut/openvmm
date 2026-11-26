// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;
use std::process::Command;
use test_with_tracing::test;

struct Repository(PathBuf);

impl Repository {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::current_dir().unwrap().join(format!(
            ".git-info-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(&self.0)
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    fn emit(&self) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .current_dir(&self.0)
            .args(["--exact", "tests::emit_fixture", "--ignored", "--nocapture"])
            .env("GIT_INFO_FIXTURE", "1")
            .env("GIT_CEILING_DIRECTORIES", self.0.parent().unwrap())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn watched_paths(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("cargo:rerun-if-changed="))
        .map(PathBuf::from)
        .collect()
}

// Test: Emit metadata from a named branch, advance it, then detach HEAD.
// Expected: SHA/branch reflect each revision, paths are absolute, branch builds
//       watch HEAD and the branch ref, and detached builds watch HEAD only.
#[test]
fn branch_updates_and_detached_head_emit_current_identity() {
    let repo = Repository::new();
    repo.git(&["init", "-q", "--initial-branch=fixture-topic"]);
    repo.git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "first",
    ]);
    let first = repo.git(&["rev-parse", "HEAD"]);
    let output = repo.emit();
    assert!(output.contains(&format!("cargo:rustc-env=BUILD_GIT_SHA={first}\n")));
    assert!(output.contains("cargo:rustc-env=BUILD_GIT_BRANCH=fixture-topic\n"));
    let paths = watched_paths(&output);
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().all(|path| path.is_absolute()));
    assert_eq!(paths[0], repo.0.join(".git/HEAD"));
    assert_eq!(paths[1], repo.0.join(".git/refs/heads/fixture-topic"));
    repo.git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "second",
    ]);
    let second = repo.git(&["rev-parse", "HEAD"]);
    assert_ne!(first, second);
    let output = repo.emit();
    assert!(output.contains(&format!("cargo:rustc-env=BUILD_GIT_SHA={second}\n")));
    repo.git(&["checkout", "-q", "--detach", &first]);
    let output = repo.emit();
    assert!(output.contains(&format!("cargo:rustc-env=BUILD_GIT_SHA={first}\n")));
    assert!(output.contains("cargo:rustc-env=BUILD_GIT_BRANCH=HEAD\n"));
    assert_eq!(watched_paths(&output), [repo.0.join(".git/HEAD")]);
}

// Test: Emit metadata outside a repository and before an initial commit.
// Expected: Failed git commands return actionable errors, never invented SHA
//       or branch metadata.
#[test]
fn invalid_repository_context_does_not_publish_identity() {
    let repo = Repository::new();
    for initialized in [false, true] {
        if initialized {
            repo.git(&["init", "-q", "--initial-branch=unborn"]);
        }
        let output = repo.emit();
        assert!(output.contains("fixture-error:"));
        assert!(output.contains("rev-parse"));
        assert!(!output.contains("cargo:rustc-env=BUILD_GIT_SHA="));
        assert!(!output.contains("cargo:rustc-env=BUILD_GIT_BRANCH="));
    }
}

// Test: Invoke the public build-script helper in an isolated child process.
// Expected: Cargo directives or a returned diagnostic are observable on stdout.
// IGNORED: This subprocess fixture needs a parent-owned repository directory.
//       Parent tests invoke it explicitly; it is not a product failure.
#[test]
#[ignore = "subprocess fixture invoked by parent tests"]
fn emit_fixture() {
    assert_eq!(std::env::var("GIT_INFO_FIXTURE").unwrap(), "1");
    if let Err(error) = crate::emit_git_info() {
        println!("fixture-error:{error:#}");
    }
}
