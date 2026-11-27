// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A dead simple runtime variable db, backed by a single JSON file.

use anyhow::Context;
use fs_err::File;
use serde::Deserialize;
use serde::Serialize;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

/// On-disk format for the var db
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct VarDb<'a> {
    vars: BTreeMap<String, (bool, Cow<'a, RawValue>)>,
}

/// Implements [`flowey_core::node::RuntimeVarDb`] backed by a JSON file.
pub struct SingleJsonFileVarDb {
    file: File,
}

impl SingleJsonFileVarDb {
    pub fn new(backing_file: impl AsRef<Path>) -> anyhow::Result<Self> {
        let backing_file = backing_file.as_ref();
        let exists = backing_file.exists();
        let mut file = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(backing_file)
            .context("failed to open/create database file")?;

        // seed the database file with an empty json map
        if !exists {
            eprintln!(
                "seeding new empty database file: {}",
                backing_file.display()
            );
            file.write_all(b"{}")?;
        }

        Ok(Self { file })
    }

    fn load_db(&mut self) -> VarDb<'static> {
        self.file.rewind().unwrap();
        serde_json::from_reader(&self.file).expect("corrupt runtime variable db")
    }
}

impl flowey_core::node::RuntimeVarDb for SingleJsonFileVarDb {
    fn try_get_var(&mut self, var_name: &str) -> Option<(Vec<u8>, bool)> {
        let db = self.load_db();
        let (is_secret, ref val) = *db.vars.get(var_name)?;
        if is_secret {
            log::debug!("[db] read var: {} = <secret>", var_name);
        } else {
            log::debug!("[db] read var: {} = {}", var_name, val);
        }
        Some((val.get().into(), is_secret))
    }

    fn set_var(&mut self, var_name: &str, is_secret: bool, value: Vec<u8>) {
        let value: &RawValue = serde_json::from_slice(&value)
            .unwrap_or_else(|err| panic!("invalid JSON for var {}: {}", var_name, err));
        if is_secret {
            log::debug!("[db] set var: {} = <secret>", var_name)
        } else {
            log::debug!("[db] set var: {} = {}", var_name, value)
        };
        let mut db = self.load_db();
        let existing = db
            .vars
            .insert(var_name.into(), (is_secret, Cow::Borrowed(value)));
        assert!(existing.is_none()); // all vars are one-time-write
        self.file.set_len(0).unwrap();
        self.file.rewind().unwrap();
        serde_json::to_writer(&self.file, &db).expect("failed to write to db JSON");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowey_core::node::RuntimeVarDb;
    use test_with_tracing::test;

    // Test: Persist public and secret-marked structured values, reopen the
    //       database, then append another variable through the reopened handle.
    // Expected: The independent on-disk schema, payloads and secrecy flags
    //       survive reopening and appending; missing variables remain absent.
    #[test]
    fn reopening_and_appending_preserves_values_and_secret_metadata() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("variables.json");
        let mut db = SingleJsonFileVarDb::new(&path).unwrap();
        assert!(db.try_get_var("missing").is_none());
        db.set_var("z_public", false, br#"[1,true,"two"]"#.to_vec());
        db.set_var("a_private", true, br#"{"nested":{"x":null}}"#.to_vec());
        drop(db);
        let expected = serde_json::json!({
            "z_public": [false, [1, true, "two"]],
            "a_private": [true, {"nested": {"x": null}}],
        });
        let stored: serde_json::Value =
            serde_json::from_slice(&fs_err::read(&path).unwrap()).unwrap();
        assert_eq!(stored, expected);

        let mut db = SingleJsonFileVarDb::new(&path).unwrap();
        assert_eq!(
            db.try_get_var("a_private"),
            Some((br#"{"nested":{"x":null}}"#.to_vec(), true))
        );
        assert_eq!(
            db.try_get_var("z_public"),
            Some((br#"[1,true,"two"]"#.to_vec(), false))
        );
        db.set_var("0_added", false, b"42".to_vec());
        drop(db);
        let mut expected = expected;
        expected["0_added"] = serde_json::json!([false, 42]);
        let stored: serde_json::Value =
            serde_json::from_slice(&fs_err::read(&path).unwrap()).unwrap();
        assert_eq!(stored, expected);
        let mut db = SingleJsonFileVarDb::new(&path).unwrap();
        assert_eq!(db.try_get_var("0_added"), Some((b"42".to_vec(), false)));
        assert!(db.try_get_var("missing").is_none());
    }

    // Test: Attempt to overwrite a variable after closing and reopening its database.
    // Expected: The one-time-write invariant rejects the second assignment,
    //       rather than silently replacing a value from an earlier invocation.
    #[test]
    #[should_panic(expected = "existing.is_none()")]
    fn one_time_write_is_enforced_across_reopening() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("variables.json");
        let mut db = SingleJsonFileVarDb::new(&path).unwrap();
        db.set_var("existing", false, b"1".to_vec());
        drop(db);
        let mut db = SingleJsonFileVarDb::new(path).unwrap();
        db.set_var("existing", false, b"2".to_vec());
    }

    // Test: Open a database beneath a missing parent or at an existing directory.
    // Expected: Both I/O failures retain database-opening context and do not
    //       manufacture an empty database or replace the existing directory.
    #[test]
    fn invalid_database_paths_report_opening_errors_without_replacing_data() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("directory");
        fs_err::create_dir(&directory).unwrap();
        for path in [
            root.path().join("missing/variables.json"),
            directory.clone(),
        ] {
            let error = match SingleJsonFileVarDb::new(path) {
                Err(error) => error,
                Ok(_) => panic!("invalid database path unexpectedly opened"),
            };
            assert!(
                error
                    .to_string()
                    .contains("failed to open/create database file")
            );
        }
        assert!(directory.is_dir());
        assert!(!root.path().join("missing").exists());
    }
}
