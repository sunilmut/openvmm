// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for file-backed shared guest memory.

use anyhow::Context;
use openvmm_defs::worker::SharedMemoryFd;

/// Open (or create) a file to back guest RAM, and return the appropriate
/// fd/handle for use as shared memory.
///
/// If the file is newly created (size 0), it is extended to `size` bytes.
/// If it already exists with a different size, an error is returned.
pub fn open_memory_backing_file(
    path: &std::path::Path,
    size: u64,
) -> anyhow::Result<SharedMemoryFd> {
    let file = fs_err::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;

    let existing_len = file.metadata()?.len();
    if existing_len == 0 {
        file.set_len(size)
            .context("failed to set memory backing file size")?;
    } else if existing_len != size {
        anyhow::bail!(
            "memory backing file {} has size {} bytes, expected {} bytes",
            path.display(),
            existing_len,
            size,
        );
    }

    file_to_shared_memory_fd(file.into())
}

/// Convert a `std::fs::File` to the platform-appropriate shared memory handle.
pub fn file_to_shared_memory_fd(file: std::fs::File) -> anyhow::Result<SharedMemoryFd> {
    Ok(cfg_select! {
        unix => std::os::unix::io::OwnedFd::from(file),
        // On Windows, MapViewOfFile needs a section handle, not a raw file
        // handle. sparse_mmap has a helper that calls CreateFileMappingW.
        windows => sparse_mmap::new_mappable_from_file(&file, true, false)?,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use test_with_tracing::test;

    // Test: Create guest RAM backing, write across a page boundary and reopen it.
    // Expected: New RAM is zero-filled, and reopening preserves size and guest bytes.
    #[test]
    fn backing_file_is_zero_filled_and_reused_without_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("memory.bin");
        let mut file = std::fs::File::from(open_memory_backing_file(&path, 8192).unwrap());
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, vec![0; 8192]);
        file.seek(SeekFrom::Start(4090)).unwrap();
        file.write_all(b"guest memory").unwrap();
        drop(file);

        let mut reopened = std::fs::File::from(open_memory_backing_file(&path, 8192).unwrap());
        contents.clear();
        reopened.read_to_end(&mut contents).unwrap();
        let mut expected = vec![0; 8192];
        expected[4090..4102].copy_from_slice(b"guest memory");
        assert_eq!(contents, expected);
    }

    // Test: Open an existing backing file with a different requested RAM size.
    // Expected: The error identifies both sizes and the path, without changing its bytes.
    #[test]
    fn size_mismatch_preserves_existing_backing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("memory.bin");
        std::fs::write(&path, b"saved RAM").unwrap();
        let error = open_memory_backing_file(&path, 8192).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "memory backing file {} has size 9 bytes, expected 8192 bytes",
                path.display()
            )
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"saved RAM");
    }

    // Test: Request a memory backing file below a nonexistent directory.
    // Expected: The original NotFound error is returned and no directory is created.
    #[test]
    fn missing_parent_reports_open_error() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("missing");
        let error = open_memory_backing_file(&parent.join("memory.bin"), 8192).unwrap_err();
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!parent.exists());
    }
}
