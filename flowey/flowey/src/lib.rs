// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

//! The user-facing flowey API.
//!
//! Relying on `flowey_core` directly is not advised, as many APIs exposed at
//! that level are only supposed to be used by flowey _infrastructure_ (e.g: in
//! `flowey_cli`).

pub use flowey_core::shell_cmd;

/// Shell abstractions for flowey command execution.
pub mod shell {
    pub use flowey_core::shell::*;
}

/// Types and traits for implementing flowey nodes.
pub mod node {
    pub mod prelude {
        // include all user-facing types in the prelude
        pub use flowey_core::claim_vars;
        pub use flowey_core::match_arch;
        pub use flowey_core::node::user_facing::*;
        pub use flowey_core::read_vars;

        // ...in addition, export various types/traits that node impls are
        // almost certainly going to require
        pub use anyhow;
        pub use anyhow::Context;
        pub use fs_err;
        pub use log;
        pub use serde::Deserialize;
        pub use serde::Serialize;
        pub use std::path::Path;
        pub use std::path::PathBuf;

        /// Extension trait to streamline working with [`Path`] in flowey.
        pub trait FloweyPathExt {
            /// Alias for [`std::path::absolute`]
            fn absolute(&self) -> std::io::Result<PathBuf>;

            /// Helper to make files executable on unix-like platforms
            fn make_executable(&self) -> std::io::Result<()>;

            /// Helper to check if a file is executable on unix-like platforms
            fn is_executable(&self) -> std::io::Result<bool>;
        }

        impl<T> FloweyPathExt for T
        where
            T: AsRef<Path>,
        {
            fn absolute(&self) -> std::io::Result<PathBuf> {
                std::path::absolute(self)
            }

            fn make_executable(&self) -> std::io::Result<()> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let path = self.as_ref();
                    let old_mode = path.metadata()?.permissions().mode();
                    fs_err::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(old_mode | 0o111),
                    )?;
                }
                Ok(())
            }

            fn is_executable(&self) -> std::io::Result<bool> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let path = self.as_ref();
                    let mode = path.metadata()?.permissions().mode();
                    Ok(mode & 0o111 != 0)
                }

                // TODO: Implement for windows. Tracked by https://github.com/microsoft/openvmm/issues/2622
                #[cfg(not(unix))]
                {
                    Ok(true)
                }
            }
        }
    }
}

/// Types and traits for implementing flowey pipelines.
pub mod pipeline {
    pub mod prelude {
        pub use flowey_core::pipeline::user_facing::*;
    }
}

/// Types and traits for implementing flowey patch functions.
pub mod patch {
    pub use flowey_core::patch::*;
    pub use flowey_core::register_patch;
}

/// Utility functions.
pub mod util {
    pub use flowey_core::util::*;
}

#[cfg(test)]
mod tests {
    use super::node::prelude::FloweyPathExt;
    use std::path::Path;

    // Test: Make owned files executable from several starting modes and check
    //       executability before and after, plus a missing path.
    // Expected: All three execute bits are added while read/write and special
    //       bits are kept; any execute bit counts as executable; a missing path
    //       is an error.
    #[cfg(unix)]
    #[test]
    fn make_executable_adds_execute_bits_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").unwrap();
        for (start, expected, was_executable) in [
            (0o600, 0o711, false),
            (0o644, 0o755, false),
            (0o4640, 0o4751, false),
            (0o610, 0o711, true),
            (0o755, 0o755, true),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(start)).unwrap();
            assert_eq!(file.is_executable().unwrap(), was_executable, "{start:o}");
            file.make_executable().unwrap();
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, expected, "{start:o}");
            assert!(file.is_executable().unwrap());
        }
        let missing = dir.path().join("missing");
        assert!(missing.make_executable().is_err());
        assert!(missing.is_executable().is_err());
    }

    // Test: Make relative and already-absolute paths absolute.
    // Expected: Relative paths are joined to the current directory without
    //       resolving `..`, and absolute paths are returned unchanged.
    #[test]
    fn absolute_joins_relative_paths_to_current_dir() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            FloweyPathExt::absolute(&Path::new("a/../b")).unwrap(),
            cwd.join("a/../b")
        );
        let abs = cwd.join("x");
        assert_eq!(FloweyPathExt::absolute(&abs).unwrap(), abs);
    }
}
