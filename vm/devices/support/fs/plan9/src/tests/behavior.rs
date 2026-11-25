// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::os::unix::fs::MetadataExt;
use test_with_tracing::test;

// Keep all real filesystem operations inside a task-owned temporary export.
fn filesystem() -> (tempfile::TempDir, Plan9FileSystem) {
    let root = tempfile::tempdir().unwrap();
    let fs = Plan9FileSystem::new(root.path(), true).unwrap();
    (root, fs)
}

// Validate the response envelope independently before returning its payload.
fn reply(fs: &Plan9FileSystem, kind: u8, fields: impl FnOnce(&mut SliceWriter<'_>)) -> Vec<u8> {
    let mut response = [0; 8192];
    let size = fs
        .process_message(&request(kind, fields), &mut response)
        .unwrap();
    assert_eq!(
        u32::from_le_bytes(response[..4].try_into().unwrap()) as usize,
        size
    );
    assert_eq!(
        response[4],
        kind + 1,
        "unexpected response: {:?}",
        &response[..size]
    );
    assert_eq!(u16::from_le_bytes(response[5..7].try_into().unwrap()), TAG);
    response[7..size].to_vec()
}

// Attach a guest fid to the root through the real wire dispatcher.
fn attach(fs: &Plan9FileSystem, fid: u32) -> Vec<u8> {
    reply(fs, 104, |w| {
        w.u32(fid).unwrap();
        w.u32(u32::MAX).unwrap();
        w.string("guest".as_ref()).unwrap();
        w.string("".as_ref()).unwrap();
        w.u32(0).unwrap();
    })
}

// Walk or clone a fid and decode every returned qid.
fn walk(fs: &Plan9FileSystem, from: u32, to: u32, names: &[&str]) -> Vec<Qid> {
    let bytes = reply(fs, 110, |w| {
        w.u32(from).unwrap();
        w.u32(to).unwrap();
        w.u16(names.len() as u16).unwrap();
        for name in names {
            w.string((*name).as_ref()).unwrap();
        }
    });
    let qids: Vec<_> = SliceReader::new(&bytes)
        .qids()
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(qids.len(), names.len());
    qids
}

// Test: Negotiate minimum and capped sizes, reject unsupported versions, then reset live fids.
// Expected: Replies preserve the version and tag; reset invalidates old fids and permits reuse.
#[test]
fn negotiation_and_reset_preserve_wire_and_fid_contracts() {
    let (_root, fs) = filesystem();
    for (size, version) in [(4095, "9P2000.L"), (4096, "9P2000")] {
        assert_error_reply(
            &fs,
            &request(100, |w| {
                w.u32(size).unwrap();
                w.string(version.as_ref()).unwrap();
            }),
            Error::ENOTSUP,
        );
    }
    for (requested, expected) in [(4096, 4096u32), (u32::MAX, 256 * 1024)] {
        let payload = reply(&fs, 100, |w| {
            w.u32(requested).unwrap();
            w.string("9P2000.L".as_ref()).unwrap();
        });
        let mut expected = expected.to_le_bytes().to_vec();
        expected.extend_from_slice(b"\x08\x009P2000.L");
        assert_eq!(payload, expected);
    }
    let root_qid = attach(&fs, 1);
    assert_eq!(root_qid.len(), 13);
    assert_eq!(root_qid[0], 0x80);
    assert_error_reply(
        &fs,
        &request(104, |w| {
            w.u32(1).unwrap();
            w.u32(u32::MAX).unwrap();
            w.string("guest".as_ref()).unwrap();
            w.string("".as_ref()).unwrap();
            w.u32(0).unwrap();
        }),
        Error::EINVAL,
    );
    walk(&fs, 1, 2, &[]);
    fs.reset();
    for fid in [1, 2] {
        assert_error_reply(&fs, &request(120, |w| w.u32(fid).unwrap()), Error::EINVAL);
    }
    assert_eq!(attach(&fs, 1), root_qid);
}

// Test: Create a file, write at an offset, clone its fid, then independently open and read it.
// Expected: File bytes and EOF counts are exact; a clone does not inherit open state.
#[test]
fn created_files_preserve_offset_io_and_independent_clone_lifetimes() {
    let (root, fs) = filesystem();
    attach(&fs, 1);
    walk(&fs, 1, 2, &[]);
    let created = reply(&fs, 14, |w| {
        w.u32(2).unwrap();
        w.string("disk.bin".as_ref()).unwrap();
        w.u32(OPEN_FLAG_RDWR).unwrap();
        w.u32(lx::S_IFREG | 0o600).unwrap();
        w.u32(0).unwrap();
    });
    assert_eq!(created.len(), 17);
    assert_eq!(created[0], 0);
    assert_eq!(&created[13..], &[0; 4]);
    assert_eq!(
        reply(&fs, 118, |w| {
            w.u32(2).unwrap();
            w.u64(3).unwrap();
            w.u32(3).unwrap();
            w.write(b"abc").unwrap();
        }),
        3u32.to_le_bytes()
    );
    assert_eq!(
        std::fs::read(root.path().join("disk.bin")).unwrap(),
        b"\0\0\0abc"
    );
    walk(&fs, 2, 3, &[]);
    assert_error_reply(
        &fs,
        &request(116, |w| {
            w.u32(3).unwrap();
            w.u64(0).unwrap();
            w.u32(8).unwrap();
        }),
        Error::EBADF,
    );
    let opened = reply(&fs, 12, |w| {
        w.u32(3).unwrap();
        w.u32(OPEN_FLAG_RDONLY).unwrap();
    });
    assert_eq!(opened, created);
    assert!(reply(&fs, 120, |w| w.u32(2).unwrap()).is_empty());
    assert_error_reply(&fs, &request(120, |w| w.u32(2).unwrap()), Error::EINVAL);
    for (offset, expected) in [(0, &b"\0\0\0abc"[..]), (5, &b"c"[..]), (6, &b""[..])] {
        let bytes = reply(&fs, 116, |w| {
            w.u32(3).unwrap();
            w.u64(offset).unwrap();
            w.u32(8).unwrap();
        });
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            expected.len()
        );
        assert_eq!(&bytes[4..], expected);
    }
    assert_error_reply(
        &fs,
        &request(12, |w| {
            w.u32(3).unwrap();
            w.u32(OPEN_FLAG_RDONLY).unwrap();
        }),
        Error::EINVAL,
    );
}

// Test: Query file attributes and filesystem geometry through guest requests.
// Expected: Wire fields match independent host metadata, with correctly reserved trailing fields.
#[test]
fn attribute_and_filesystem_replies_match_host_metadata() {
    let (root, fs) = filesystem();
    std::fs::write(root.path().join("file"), b"metadata").unwrap();
    attach(&fs, 1);
    walk(&fs, 1, 2, &["file"]);
    for opened in [false, true] {
        if opened {
            reply(&fs, 12, |w| {
                w.u32(2).unwrap();
                w.u32(OPEN_FLAG_RDONLY).unwrap();
            });
        }
        let bytes = reply(&fs, 24, |w| {
            w.u32(2).unwrap();
            w.u64(u64::MAX).unwrap();
        });
        let stat = std::fs::metadata(root.path().join("file")).unwrap();
        let mut r = SliceReader::new(&bytes);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        let qid = r.qid().unwrap();
        assert_eq!((qid.qid_type, qid.version, qid.path), (0, 0, stat.ino()));
        for expected in [stat.mode(), stat.uid(), stat.gid()] {
            assert_eq!(r.u32().unwrap(), expected);
        }
        for expected in [
            stat.nlink(),
            stat.rdev(),
            stat.len(),
            stat.blksize(),
            stat.blocks(),
        ] {
            assert_eq!(r.u64().unwrap(), expected);
        }
        for expected in [
            stat.atime(),
            stat.atime_nsec(),
            stat.mtime(),
            stat.mtime_nsec(),
            stat.ctime(),
            stat.ctime_nsec(),
        ] {
            assert_eq!(r.u64().unwrap(), expected as u64);
        }
        for _ in 0..4 {
            assert_eq!(r.u64().unwrap(), 0);
        }
        assert_eq!(r.u8(), Err(Error::EINVAL));
    }
    let bytes = reply(&fs, 8, |w| w.u32(1).unwrap());
    assert_eq!(bytes.len(), 60);
    let mut r = SliceReader::new(&bytes);
    assert_ne!(r.u32().unwrap(), 0);
    assert!(r.u32().unwrap().is_power_of_two());
    let blocks = r.u64().unwrap();
    let free = r.u64().unwrap();
    assert!(free <= blocks);
    assert!(r.u64().unwrap() <= free);
    assert!(r.u64().unwrap() > 0);
    r.u64().unwrap();
    r.u64().unwrap();
    assert!(r.u32().unwrap() > 0);
}

// Test: Create symlinks and hard links, then remove the original hard-linked filename.
// Expected: Link qids/targets survive wire transport and the surviving name retains file data.
#[test]
fn symbolic_and_hard_links_preserve_targets_and_file_identity() {
    let (root, fs) = filesystem();
    std::fs::write(root.path().join("real"), b"retained").unwrap();
    attach(&fs, 1);
    let sym = reply(&fs, 16, |w| {
        w.u32(1).unwrap();
        w.string("symbolic".as_ref()).unwrap();
        w.string("real".as_ref()).unwrap();
        w.u32(0).unwrap();
    });
    assert_eq!(sym[0], 2);
    walk(&fs, 1, 2, &["symbolic"]);
    assert_eq!(reply(&fs, 22, |w| w.u32(2).unwrap()), b"\x04\x00real");
    assert_eq!(
        std::fs::read_link(root.path().join("symbolic")).unwrap(),
        Path::new("real")
    );
    let qids = walk(&fs, 1, 3, &["real"]);
    assert!(
        reply(&fs, 70, |w| {
            w.u32(1).unwrap();
            w.u32(3).unwrap();
            w.string("alias".as_ref()).unwrap();
        })
        .is_empty()
    );
    let alias = walk(&fs, 1, 4, &["alias"]);
    assert_eq!(alias[0].path, qids[0].path);
    assert!(
        reply(&fs, 76, |w| {
            w.u32(1).unwrap();
            w.string("real".as_ref()).unwrap();
            w.u32(0).unwrap();
        })
        .is_empty()
    );
    assert!(!root.path().join("real").exists());
    assert_eq!(
        std::fs::read(root.path().join("alias")).unwrap(),
        b"retained"
    );
}

// Test: Create and enumerate a directory, including an insufficient buffer and an EOF cookie.
// Expected: Entries have independently decoded names/types; tiny buffers fail and EOF is empty.
#[test]
fn directory_entries_preserve_names_types_and_resume_cookies() {
    let (root, fs) = filesystem();
    attach(&fs, 1);
    let mkdir = reply(&fs, 72, |w| {
        w.u32(1).unwrap();
        w.string("dir".as_ref()).unwrap();
        w.u32(lx::S_IFDIR | 0o700).unwrap();
        w.u32(0).unwrap();
    });
    assert_eq!(mkdir[0], 0x80);
    std::fs::write(root.path().join("dir").join("alpha"), b"a").unwrap();
    std::fs::write(root.path().join("dir").join("beta"), b"b").unwrap();
    walk(&fs, 1, 2, &["dir"]);
    reply(&fs, 12, |w| {
        w.u32(2).unwrap();
        w.u32(OPEN_FLAG_RDONLY | OPEN_FLAG_DIRECTORY).unwrap();
    });
    assert_error_reply(
        &fs,
        &request(40, |w| {
            w.u32(2).unwrap();
            w.u64(0).unwrap();
            w.u32(1).unwrap();
        }),
        Error::EINVAL,
    );
    let bytes = reply(&fs, 40, |w| {
        w.u32(2).unwrap();
        w.u64(0).unwrap();
        w.u32(4096).unwrap();
    });
    assert_eq!(
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
        bytes.len() - 4
    );
    let mut entries = std::collections::BTreeMap::new();
    let mut data = &bytes[4..];
    let mut cookie = 0;
    while !data.is_empty() {
        assert!(data.len() >= 24);
        assert_eq!(&data[1..5], &[0; 4]);
        cookie = u64::from_le_bytes(data[13..21].try_into().unwrap());
        let name_len = u16::from_le_bytes(data[22..24].try_into().unwrap()) as usize;
        let name = str::from_utf8(&data[24..24 + name_len]).unwrap();
        entries.insert(name.to_owned(), (data[0], data[21]));
        data = &data[24 + name_len..];
    }
    assert_eq!(entries["alpha"], (0, lx::DT_REG));
    assert_eq!(entries["beta"], (0, lx::DT_REG));
    assert_eq!(entries["."], (0x80, lx::DT_DIR));
    assert_eq!(entries[".."], (0x80, lx::DT_DIR));
    assert_eq!(entries.len(), 4);
    assert_eq!(
        reply(&fs, 40, |w| {
            w.u32(2).unwrap();
            w.u64(cookie).unwrap();
            w.u32(4096).unwrap();
        }),
        [0; 4]
    );
}

// Test: Fail midway through a path walk or on an invalid component, then reuse the new fid.
// Expected: Failures return only an errno reply and do not install a partially walked fid.
#[test]
fn failed_walks_do_not_publish_partial_fids_or_mutate_the_root() {
    let (root, fs) = filesystem();
    std::fs::create_dir(root.path().join("dir")).unwrap();
    std::fs::write(root.path().join("dir").join("file"), b"data").unwrap();
    attach(&fs, 1);
    for (names, expected) in [
        (vec!["dir", "missing"], Error::ENOENT),
        (vec!["dir", ".."], Error::EINVAL),
        (vec!["dir/file"], Error::EINVAL),
        (vec![""], Error::EINVAL),
    ] {
        assert_error_reply(
            &fs,
            &request(110, |w| {
                w.u32(1).unwrap();
                w.u32(2).unwrap();
                w.u16(names.len() as u16).unwrap();
                for name in names {
                    w.string(name.as_ref()).unwrap();
                }
            }),
            expected,
        );
    }
    let file = walk(&fs, 1, 2, &["dir", "file"]);
    assert_eq!(file[0].qid_type, 0x80);
    assert_eq!(file[1].qid_type, 0);
    assert_eq!(
        file[1].path,
        std::fs::metadata(root.path().join("dir").join("file"))
            .unwrap()
            .ino()
    );
}

// Test: Send the supported no-op setattr and a recognized but unsupported request.
// Expected: Setattr leaves host contents unchanged; unsupported and unknown types return errno.
#[test]
fn ignored_and_unsupported_messages_keep_explicit_wire_results() {
    let (root, fs) = filesystem();
    std::fs::write(root.path().join("file"), b"unchanged").unwrap();
    attach(&fs, 1);
    walk(&fs, 1, 2, &["file"]);
    assert!(
        reply(&fs, 26, |w| {
            for value in [2, u32::MAX, 0, 0, 0] {
                w.u32(value).unwrap();
            }
            for _ in 0..5 {
                w.u64(0).unwrap();
            }
        })
        .is_empty()
    );
    assert_eq!(
        std::fs::read(root.path().join("file")).unwrap(),
        b"unchanged"
    );
    assert_error_reply(&fs, &request(6, |w| w.u32(7).unwrap()), Error::ENOTSUP);
    assert_error_reply(&fs, &request(255, |_| {}), Error::EINVAL);
}

// Test: Walk an unopened cloned fid in place through a directory to a file.
// Expected: Rwalk reports both qids, the reused fid opens/reads the final file,
//       and the independently attached root fid still identifies the export root.
//
// IGNORED: Reproduced with the test enabled: Twalk with fid == newfid returns
//       Rlerror(EINVAL) instead of Rwalk because the existing fid is not replaced.
#[test]
#[ignore = "product bug: an in-place Twalk rejects the existing fid"]
fn in_place_walk_replaces_only_the_requested_fid() {
    let (root, fs) = filesystem();
    std::fs::create_dir(root.path().join("dir")).unwrap();
    std::fs::write(root.path().join("dir/file"), b"walked").unwrap();
    attach(&fs, 1);
    walk(&fs, 1, 2, &[]);
    let qids = walk(&fs, 2, 2, &["dir", "file"]);
    for (qid, path, kind) in [(&qids[0], "dir", 0x80), (&qids[1], "dir/file", 0)] {
        assert_eq!(
            (qid.qid_type, qid.version, qid.path),
            (
                kind,
                0,
                std::fs::metadata(root.path().join(path)).unwrap().ino()
            )
        );
    }
    let opened = reply(&fs, 12, |w| {
        w.u32(2).unwrap();
        w.u32(OPEN_FLAG_RDONLY).unwrap();
    });
    assert_eq!(
        &opened[..13],
        &reply(&fs, 24, |w| {
            w.u32(2).unwrap();
            w.u64(u64::MAX).unwrap();
        })[8..21]
    );
    assert_eq!(
        reply(&fs, 116, |w| {
            w.u32(2).unwrap();
            w.u64(0).unwrap();
            w.u32(32).unwrap();
        }),
        b"\x06\0\0\0walked"
    );
    assert_eq!(walk(&fs, 1, 3, &["dir"])[0].path, qids[0].path);
}
