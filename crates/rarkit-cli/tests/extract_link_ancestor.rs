//! `x` below a destination that already holds a symbolic link where a
//! member's path wants a directory, and a destination whose name ends in
//! a backslash.
//!
//! THE RULE: below the destination the caller named, no member is
//! created, written over, or has its mode or times set THROUGH a link.
//! Every component between the destination and the member is a real
//! directory, judged from the destination outward; a link standing in a
//! component's place is removed and a real directory made there (spec F
//! 3.8.3). The destination itself may be a link: the caller chose it.
//!
//! Before 10 Oct 2026 the record of what was there before the run asked
//! each path on its own, and the system follows every component but the
//! last: with `out/link -> ../outside` and a real `outside/sub`, the path
//! `out/link/sub` passed for a real directory already there, nothing was
//! replaced, and `link/sub/victim` was written over `outside/sub/victim`
//! with `All OK`, exit 0. A directory member `link/sub` set its mode on
//! `outside/sub` the same way.
//!
//! MEASURED against unrar 7.23 on macOS (arm64), 10 Oct 2026, same trees:
//! it removes `out/link`, makes a real directory there and extracts under
//! it; `outside` keeps its file and its mode. And it extracts `out\/`
//! into the directory named `out\`, a backslash being a character of a
//! name on Unix.
//!
//! Unix only: the links are made with `symlink`, and the backslash rows
//! are about a system where `\` separates nothing.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; the archives are
//! stored members of a few bytes, so the test needs no memory to speak of
//! and passes on a runner two threads wide.
#![cfg(unix)]

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own that is removed when this value is
/// dropped, so a failed assert clears it away as a pass does.
struct DirWatch(PathBuf);

impl DirWatch {
    fn over(tag: &str, width: &str) -> (PathBuf, DirWatch) {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-linkanc-{}-{tag}-{}",
            std::process::id(),
            width.trim_start_matches('-')
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), DirWatch(dir))
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a member of the archive is.
enum Kind<'a> {
    File(&'a [u8]),
    Dir(u64),
    Link(&'a [u8]),
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of stored members, in the order given, built from
/// spec F 3.2.2 and 3.2.6 (a link's record from 3.2.6.2).
fn archive(members: &[(&str, Kind)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, kind) in members {
        let (data, file_flags, attr, extra): (&[u8], u64, u64, Vec<u8>) = match kind {
            Kind::File(data) => (data, 0x4, 0o100_644, Vec::new()),
            Kind::Dir(mode) => (b"", 0x5, 0o040_000 | mode, Vec::new()),
            Kind::Link(target) => (
                b"",
                0x4,
                0o120_777,
                rewrite::area(&[(5, rewrite::redirect(1, 0, target))]),
            ),
        };
        // A file header; an extra area where there is one, a data area
        // where there are bytes.
        let mut flags = 0;
        if !extra.is_empty() {
            flags |= 0x1;
        }
        if !data.is_empty() {
            flags |= 0x2;
        }
        let mut body = rewrite::vint(2);
        body.extend(rewrite::vint(flags));
        if !extra.is_empty() {
            body.extend(rewrite::vint(extra.len() as u64));
        }
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        body.extend(rewrite::vint(file_flags));
        body.extend(rewrite::vint(data.len() as u64));
        body.extend(rewrite::vint(attr));
        body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        body.extend(extra);
        block(&body, &mut out);
        out.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut out);
    out
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn text(done: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

#[test]
fn a_file_is_not_written_through_a_link_above_a_real_directory() {
    let arc = archive(&[("link/sub/victim", Kind::File(b"ARCHIVE CONTENT"))]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("file", width);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(dir.join("outside/sub")).unwrap();
        std::fs::write(dir.join("outside/sub/victim"), b"KEEP ME").unwrap();
        symlink("../outside", dir.join("out/link")).unwrap();
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let done = run(&dir, &["x", "-o+", width, "a.rar", "out/"]);
        assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
        assert_eq!(
            std::fs::read(dir.join("outside/sub/victim")).unwrap(),
            b"KEEP ME",
            "{width}: the file outside the destination was written over"
        );
        assert!(is_real_dir(&dir.join("out/link")), "{width}: out/link");
        assert!(is_real_dir(&dir.join("out/link/sub")), "{width}");
        assert_eq!(
            std::fs::read(dir.join("out/link/sub/victim")).unwrap(),
            b"ARCHIVE CONTENT",
            "{width}"
        );
        assert_eq!(
            std::fs::read_dir(dir.join("outside/sub")).unwrap().count(),
            1,
            "{width}: nothing new outside"
        );
    }
}

#[test]
fn a_directory_member_sets_no_mode_through_a_link() {
    let arc = archive(&[("link/sub", Kind::Dir(0o755))]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("dirmeta", width);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(dir.join("outside/sub")).unwrap();
        std::fs::set_permissions(
            dir.join("outside/sub"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        symlink("../outside", dir.join("out/link")).unwrap();
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let done = run(&dir, &["x", width, "a.rar", "out/"]);
        assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
        assert_eq!(
            mode_of(&dir.join("outside/sub")),
            0o700,
            "{width}: the mode of a directory outside the destination changed"
        );
        assert!(is_real_dir(&dir.join("out/link")), "{width}: out/link");
        assert!(is_real_dir(&dir.join("out/link/sub")), "{width}");
        assert_eq!(mode_of(&dir.join("out/link/sub")), 0o755, "{width}");
    }
}

/// The link sits two levels below the destination, under a real
/// directory that was there, and the member's path runs two real
/// directories past it.
#[test]
fn a_link_two_levels_down_is_replaced_too() {
    let arc = archive(&[
        ("a/b/c/d", Kind::Dir(0o755)),
        ("a/b/c/d/victim", Kind::File(b"ARCHIVE CONTENT")),
        ("a/beside", Kind::File(b"BESIDE")),
    ]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("deep", width);
        std::fs::create_dir_all(dir.join("out/a")).unwrap();
        std::fs::create_dir_all(dir.join("outside/c/d")).unwrap();
        std::fs::set_permissions(
            dir.join("outside/c/d"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(dir.join("outside/c/d/victim"), b"KEEP ME").unwrap();
        symlink("../../outside", dir.join("out/a/b")).unwrap();
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let done = run(&dir, &["x", "-o+", width, "a.rar", "out/"]);
        assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
        assert_eq!(
            std::fs::read(dir.join("outside/c/d/victim")).unwrap(),
            b"KEEP ME",
            "{width}"
        );
        assert_eq!(mode_of(&dir.join("outside/c/d")), 0o700, "{width}");
        for real in ["out/a", "out/a/b", "out/a/b/c", "out/a/b/c/d"] {
            assert!(is_real_dir(&dir.join(real)), "{width}: {real}");
        }
        assert_eq!(
            std::fs::read(dir.join("out/a/b/c/d/victim")).unwrap(),
            b"ARCHIVE CONTENT",
            "{width}"
        );
        assert_eq!(
            std::fs::read(dir.join("out/a/beside")).unwrap(),
            b"BESIDE",
            "{width}"
        );
    }
}

/// The link is not there before the run: an EARLIER MEMBER of the same
/// archive makes it (`-ola`, or the link would be skipped for leaving
/// the destination, exit 1), and later members' paths run through it.
/// The link is replaced by a real directory and what it pointed at is
/// untouched (spec F 3.8.3). rarfast did this before 10 Oct 2026 too; the
/// row keeps it. NOT what unrar 7.23 does (macOS arm64, 10 Oct 2026): it
/// keeps the link, writes `outside/sub/victim` over through it and sets
/// the directory member's mode on `outside/sub`.
#[test]
fn a_link_made_by_an_earlier_member_is_not_written_through() {
    let arc = archive(&[
        ("link", Kind::Link(b"../outside")),
        ("link/sub/victim", Kind::File(b"ARCHIVE CONTENT")),
        ("link/sub", Kind::Dir(0o755)),
    ]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("earlier", width);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(dir.join("outside/sub")).unwrap();
        std::fs::set_permissions(
            dir.join("outside/sub"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(dir.join("outside/sub/victim"), b"KEEP ME").unwrap();
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let done = run(&dir, &["x", "-o+", "-ola", width, "a.rar", "out/"]);
        assert_eq!(
            std::fs::read(dir.join("outside/sub/victim")).unwrap(),
            b"KEEP ME",
            "{width}: {}",
            text(&done)
        );
        assert_eq!(mode_of(&dir.join("outside/sub")), 0o700, "{width}");
        assert_eq!(
            std::fs::read_dir(dir.join("outside/sub")).unwrap().count(),
            1,
            "{width}: nothing new outside"
        );
        assert!(is_real_dir(&dir.join("out/link")), "{width}: out/link");
        assert_eq!(
            std::fs::read(dir.join("out/link/sub/victim")).unwrap(),
            b"ARCHIVE CONTENT",
            "{width}"
        );
        assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
    }
}

/// The destination the caller names is a link, and so is a directory
/// above it: both are his, and the members go where they lead. A real
/// directory that was there below it is used as it is.
#[test]
fn a_destination_that_is_a_link_is_followed() {
    let arc = archive(&[
        ("sub/file", Kind::File(b"ARCHIVE CONTENT")),
        ("sub/deep", Kind::Dir(0o750)),
    ]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("destlink", width);
        std::fs::create_dir_all(dir.join("real/sub")).unwrap();
        std::fs::create_dir_all(dir.join("realup/inner")).unwrap();
        symlink("real", dir.join("out")).unwrap();
        symlink("realup", dir.join("up")).unwrap();
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        for (dest, lands) in [("out/", "real"), ("up/inner/", "realup/inner")] {
            let done = run(&dir, &["x", "-o+", width, "a.rar", dest]);
            assert_eq!(
                done.status.code(),
                Some(0),
                "{width} {dest}: {}",
                text(&done)
            );
            assert_eq!(
                std::fs::read(dir.join(lands).join("sub/file")).unwrap(),
                b"ARCHIVE CONTENT",
                "{width} {dest}"
            );
            assert_eq!(
                mode_of(&dir.join(lands).join("sub/deep")),
                0o750,
                "{width} {dest}"
            );
        }
        assert!(
            std::fs::symlink_metadata(dir.join("out"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{width}: the destination is still the caller's link"
        );
        assert!(
            std::fs::symlink_metadata(dir.join("up"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{width}: the link above the destination is still there"
        );
    }
}

/// On Unix a backslash is a character of a name: the destination `out\/`
/// is the directory named `out\`, there already or not.
#[test]
fn a_destination_ending_in_a_backslash_is_that_directory() {
    let arc = archive(&[
        ("payload", Kind::File(b"PAYLOAD")),
        ("d/inner", Kind::File(b"INNER")),
    ]);
    for width in WIDTHS {
        for there in [true, false] {
            let (dir, _watch) = DirWatch::over(if there { "bs" } else { "bsnew" }, width);
            if there {
                std::fs::create_dir_all(dir.join("out\\")).unwrap();
            }
            std::fs::write(dir.join("a.rar"), &arc).unwrap();
            let done = run(&dir, &["x", width, "a.rar", "out\\/"]);
            assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
            assert_eq!(
                std::fs::read(dir.join("out\\/payload")).unwrap(),
                b"PAYLOAD",
                "{width} there={there}: {}",
                text(&done)
            );
            assert_eq!(
                std::fs::read(dir.join("out\\/d/inner")).unwrap(),
                b"INNER",
                "{width} there={there}"
            );
            assert!(
                !dir.join("out").exists(),
                "{width} there={there}: a directory the caller did not name was made"
            );
        }
    }
}
