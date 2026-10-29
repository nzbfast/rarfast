//! Names a Windows target cannot store as written (SPEC-API-rarkit.md
//! question 20, `src/safepath.rs` rule 5), extracted for real on Windows.
//!
//! The 24 Sep rivals round found 12 members of a macOS tree whose names
//! end in a dot written WITHOUT it by rarkit-cli on NTFS, where the
//! reference writes the dot as `_`. The fixture is built here in code,
//! because Windows cannot create a file named `a.` to archive from the
//! disk; the round's own archive is never copied across boxes.
//!
//! Windows only: on every other target these names are ordinary and the
//! unit tests in `src/safepath.rs` pin that nothing is mapped there.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use rarkit::{MemberSpec, Payload, WriteOptions, Writer};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-winnames-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar.exe`, the whole of how the binary
/// picks that dialect.
fn ours_as_unrar(dir: &Path) -> PathBuf {
    let named = dir.join("unrar.exe");
    std::fs::copy(rarfast(), &named).unwrap();
    named
}

/// The stored names and their bodies. `a.` and `a` are the collision the
/// round named; the rest are the family the rule states.
const MEMBERS: &[(&str, &[u8])] = &[
    ("Zq7hTn2LxWm4RvB9sKdP.", b"generative\n"),
    ("a.", b"dot\n"),
    ("a", b"plain\n"),
    ("trail ", b"space\n"),
    ("CON", b"device\n"),
    ("x:y.txt", b"colon\n"),
    ("dir./inner.txt", b"nested\n"),
    ("b..", b"dots\n"),
];

fn build_archive(path: &Path) {
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    for (name, body) in MEMBERS {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    std::fs::write(path, out).unwrap();
}

/// Every file under `root`, by its path relative to `root` with `/`.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                let key = relative.to_string_lossy().replace('\\', "/");
                found.insert(key, std::fs::read(&path).unwrap());
            }
        }
    }
    found
}

#[test]
fn names_windows_cannot_store_are_mapped_and_nothing_collides() {
    let dir = work("x");
    let unrar = ours_as_unrar(&dir);
    build_archive(&dir.join("arc.rar"));
    let status = Command::new(&unrar)
        .args(["x", "-y", "arc.rar", "out\\"])
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(status.success(), "extract exited {status:?}");

    let expected: BTreeMap<String, Vec<u8>> = [
        ("Zq7hTn2LxWm4RvB9sKdP_", &b"generative\n"[..]),
        ("a_", b"dot\n"),
        ("a", b"plain\n"),
        ("trail_", b"space\n"),
        ("_CON", b"device\n"),
        ("x_y.txt", b"colon\n"),
        ("dir_/inner.txt", b"nested\n"),
        // Only the last dot of a run: UnRAR 7.23 on Windows, 25 Sep 2026.
        ("b._", b"dots\n"),
    ]
    .into_iter()
    .map(|(name, body)| (name.to_owned(), body.to_vec()))
    .collect();
    assert_eq!(tree(&dir.join("out")), expected);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The progress line names the file WRITTEN, as the reference does
/// (`outU\a_` for `a.`, measured on a Windows desktop 25 Sep 2026), never the
/// stored name Win32 would have rewritten.
#[test]
fn the_progress_line_shows_the_mapped_name() {
    let dir = work("progress");
    let unrar = ours_as_unrar(&dir);
    build_archive(&dir.join("arc.rar"));
    let out = Command::new(&unrar)
        .args(["x", "-y", "arc.rar", "out\\"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "extract exited {:?}", out.status);
    let shown = String::from_utf8_lossy(&out.stdout);
    for written in [
        "out\\a_ ",
        "out\\b._ ",
        "out\\_CON ",
        "out\\x_y.txt ",
        "out\\trail_ ",
    ] {
        assert!(
            shown.contains(written),
            "{written:?} not shown in:\n{shown}"
        );
    }
    for stored in ["out\\a. ", "out\\b.. ", "out\\CON ", "out\\x:y.txt"] {
        assert!(!shown.contains(stored), "{stored:?} shown in:\n{shown}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The listing shows the stored name unchanged: only the written path is
/// mapped.
#[test]
fn the_bare_listing_shows_the_stored_names() {
    let dir = work("lb");
    let unrar = ours_as_unrar(&dir);
    build_archive(&dir.join("arc.rar"));
    let out = Command::new(&unrar)
        .args(["lb", "arc.rar"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&out.stdout);
    for (name, _) in MEMBERS {
        let shown = name.replace('/', "\\");
        assert!(
            listed.lines().any(|line| line == *name || line == shown),
            "{name:?} not listed as stored in:\n{listed}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
