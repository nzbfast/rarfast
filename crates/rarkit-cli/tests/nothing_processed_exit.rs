//! A run that processes no member: `No files to extract`, exit 10.
//!
//! THE RULES, each from measured rows:
//!
//! 1. A member whose name is EMPTY is passed over by `x`, `e`, `t` and
//!    `p`: no line, no byte printed, nothing made, and it is not counted
//!    as processed. An archive of such members alone closes with `No
//!    files to extract`, exit 10 (`p` says nothing and exits 10).
//! 2. A DIRECTORY member is not processed by `e` or by `p`, which have
//!    nothing to do with one: an archive of directories alone exits 10
//!    under them, and 0 under `x` and `t`.
//!
//! Before 10 Oct 2026 both counted as processed: `All OK`, exit 0; `t`
//! printed a `Testing` line with no name, and `p` printed the nameless
//! member's bytes.
//!
//! MEASURED against unrar 7.23 on macOS (arm64), 10 Oct 2026: hand-built
//! RAR 5 archives (a nameless file, a nameless directory, each beside a
//! named file or a directory, directories alone) under `x`, `e`, `t` and
//! `p`, and `tests/listing-names/r4-two.rar`, whose one name is two
//! bytes that are not UTF-8 and so is empty on macOS (on Linux it is a
//! name, and the member is extracted: that row is macOS's alone). Linux
//! and Windows rows of the hand-built archives are owed.
//!
//! NOT this file's: a name the reference REDUCES to nothing (`/`, `./`,
//! `a/..`), which it passes over the same way and rarfast refuses or
//! tests under its own rule for a path that leaves the destination.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; stored members of
//! a few bytes, so the test needs no memory to speak of and passes on a
//! runner two threads wide.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is deleted.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-nothing-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// What a member of the archive is.
#[derive(Clone, Copy)]
enum Kind {
    File(&'static [u8]),
    Dir,
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of stored members, in the order given, built from
/// spec F 3.2.2 and 3.2.6. A name may be empty.
fn archive(members: &[(&str, Kind)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, kind) in members {
        let (data, file_flags, attributes): (&[u8], u64, u64) = match kind {
            Kind::File(data) => (data, 0x4, 0o100_644),
            Kind::Dir => (b"", 0x5, 0o040_755),
        };
        let mut body = rewrite::vint(2);
        body.extend(rewrite::vint(if data.is_empty() { 0 } else { 0x2 }));
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        body.extend(rewrite::vint(file_flags));
        body.extend(rewrite::vint(data.len() as u64));
        body.extend(rewrite::vint(attributes));
        body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        block(&body, &mut out);
        out.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut out);
    out
}

fn run(dir: &Path, command: &str, width: &str) -> Output {
    let _ = std::fs::remove_dir_all(dir.join("out"));
    let mut args = vec![command, width, "-o+", "a.rar"];
    if matches!(command, "x" | "e") {
        args.push("out/");
    }
    Command::new(rarfast())
        .current_dir(dir)
        .args(&args)
        .output()
        .unwrap()
}

/// One archive under one command at both widths: its exit, and where
/// nothing was processed the closing line (`p` prints none) with not one
/// byte of a member on the standard output.
fn row(tag: &str, bytes: &[u8], command: &str, exit: i32) {
    let (dir, _watch) = work(&format!("{tag}-{command}"));
    std::fs::write(dir.join("a.rar"), bytes).unwrap();
    for width in ["-mt1", "-mt4"] {
        let done = run(&dir, command, width);
        let what = format!("{tag} {command} {width}: {done:?}");
        assert_eq!(done.status.code(), Some(exit), "{what}");
        let said = String::from_utf8_lossy(&done.stdout).into_owned();
        if command == "p" {
            if exit == 10 {
                assert!(done.stdout.is_empty(), "{what}");
            }
            continue;
        }
        let closing = if exit == 10 {
            "No files to extract"
        } else {
            "All OK"
        };
        assert_eq!(said.lines().last(), Some(closing), "{what}");
        if exit == 10 {
            assert!(!dir.join("out").exists(), "{what}");
        }
    }
}

#[test]
fn a_nameless_member_is_not_processed() {
    let file = archive(&[("", Kind::File(b"hello"))]);
    let dir = archive(&[("", Kind::Dir)]);
    for command in ["x", "e", "t", "p"] {
        row("nameless-file", &file, command, 10);
        row("nameless-dir", &dir, command, 10);
    }
}

#[test]
fn a_nameless_member_beside_a_named_one_has_no_line_and_prints_no_byte() {
    let bytes = archive(&[("", Kind::File(b"hello")), ("m1", Kind::File(b"second"))]);
    for command in ["x", "e", "t", "p"] {
        row("nameless-and-file", &bytes, command, 0);
    }
    let (dir, _watch) = work("nameless-lines");
    std::fs::write(dir.join("a.rar"), &bytes).unwrap();
    for width in ["-mt1", "-mt4"] {
        let tested = run(&dir, "t", width);
        let said = String::from_utf8_lossy(&tested.stdout).into_owned();
        let lines: Vec<Vec<&str>> = said
            .lines()
            .filter(|line| line.starts_with("Testing "))
            .map(|line| line.split_whitespace().collect())
            .collect();
        // The archive's own line, then the named member's, and no other.
        assert_eq!(lines.len(), 2, "{width}: {said:?}");
        assert_eq!(lines[1][..2], ["Testing", "m1"], "{width}: {said:?}");
        let printed = run(&dir, "p", width);
        assert_eq!(printed.stdout, b"second", "{width}: {printed:?}");
    }
}

#[test]
fn a_directory_is_not_processed_by_e_or_p() {
    let alone = archive(&[("d", Kind::Dir), ("d/e", Kind::Dir)]);
    let nameless_too = archive(&[("d", Kind::Dir), ("", Kind::File(b"hello"))]);
    let with_file = archive(&[("d", Kind::Dir), ("m1", Kind::File(b"second"))]);
    for (command, exit) in [("x", 0), ("t", 0), ("e", 10), ("p", 10)] {
        row("directories", &alone, command, exit);
        row("directory-and-nameless", &nameless_too, command, exit);
    }
    for command in ["x", "e", "t", "p"] {
        row("directory-and-file", &with_file, command, 0);
    }
}

/// The case that first showed it: one RAR 4 member whose name is the two
/// bytes E9 E8, which macOS reads as no name at all.
#[cfg(target_os = "macos")]
#[test]
fn the_rar4_member_whose_name_macos_cannot_read_is_not_processed() {
    let bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listing-names/r4-two.rar"))
            .unwrap();
    for command in ["x", "e", "t", "p"] {
        row("r4-two", &bytes, command, 10);
    }
}
