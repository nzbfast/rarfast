//! `x` below a destination that already holds a directory JUNCTION (or a
//! directory symbolic link) where a member's path wants a directory, on
//! Windows; and a destination spelled with a trailing backslash there.
//!
//! THE RULE is spec F 3.8.3's: no member is created, written over, or has
//! its times set through a link in any directory component of its output
//! path below the destination; the link is removed (the link, never what
//! it points at) and a real directory made. A junction is a link for this
//! purpose: it needs no privilege to make, and it keeps the directory
//! attribute, so a test that asked only "is it a directory" of the
//! attribute word would take it for a real one.
//!
//! `extract_link_ancestor.rs` holds the same rows for Unix symbolic
//! links. On Windows a `\` IS a separator, so `out\` and `out/` both name
//! `out`, and an absolute destination ending in `\` is that directory.
//!
//! Windows only. A junction is made with `cmd /C mklink /J`, which any
//! user may run. The directory symbolic link row needs the privilege (or
//! developer mode): without it the row SAYS so and passes, having tested
//! nothing.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; the archives are
//! stored members of a few bytes, so no memory to speak of, and a runner
//! two threads wide passes.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own that is removed when this value is
/// dropped, so a failed assert clears it away as a pass does. A
/// junction in it goes as a link and what it points at stays:
/// `remove_dir_all` does not walk through one.
struct DirWatch(PathBuf);

impl DirWatch {
    fn over(tag: &str, width: &str) -> (PathBuf, DirWatch) {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-winanc-{}-{tag}-{}",
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

/// What a member of the archive is: a file's bytes, or a directory with
/// the time it was last written, in seconds.
enum Kind<'a> {
    File(&'a [u8]),
    Dir(u32),
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of stored members, in the order given, built from
/// spec F 3.2.2 and 3.2.6.
fn archive(members: &[(&str, Kind)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, kind) in members {
        let (data, mtime): (&[u8], Option<u32>) = match kind {
            Kind::File(data) => (data, None),
            Kind::Dir(mtime) => (b"", Some(*mtime)),
        };
        let mut body = rewrite::vint(2); // file header
        body.extend(rewrite::vint(if data.is_empty() { 0 } else { 0x2 }));
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        // CRC32 present; a directory, with its time in Unix seconds.
        body.extend(rewrite::vint(if mtime.is_some() { 0x7 } else { 0x4 }));
        body.extend(rewrite::vint(data.len() as u64));
        body.extend(rewrite::vint(if mtime.is_some() {
            0o040_755
        } else {
            0o100_644
        }));
        if let Some(mtime) = mtime {
            body.extend_from_slice(&mtime.to_le_bytes());
        }
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

/// A directory itself: not a junction and not a symbolic link to one.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
}

/// How a link is planted at `at`, pointing at the directory `to`.
#[derive(Clone, Copy, Debug)]
enum Planted {
    Junction,
    DirSymlink,
}

/// Plants the link; `false` where this user may not make one of the kind.
fn plant(kind: Planted, to: &Path, at: &Path) -> bool {
    match kind {
        Planted::Junction => {
            let made = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(at)
                .arg(to)
                .output()
                .unwrap();
            assert!(
                made.status.success(),
                "mklink /J: {}{}",
                String::from_utf8_lossy(&made.stdout),
                String::from_utf8_lossy(&made.stderr)
            );
            true
        }
        Planted::DirSymlink => match std::os::windows::fs::symlink_dir(to, at) {
            Ok(()) => true,
            Err(err) => {
                eprintln!("NOT TESTED: a directory symbolic link cannot be made here: {err}");
                false
            }
        },
    }
}

const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];
const KINDS: [Planted; 2] = [Planted::Junction, Planted::DirSymlink];

#[test]
fn a_file_is_not_written_through_a_junction_above_a_real_directory() {
    let arc = archive(&[("link/sub/victim", Kind::File(b"ARCHIVE CONTENT"))]);
    for kind in KINDS {
        for width in WIDTHS {
            let (dir, _watch) = DirWatch::over(&format!("file-{kind:?}"), width);
            std::fs::create_dir_all(dir.join("out")).unwrap();
            std::fs::create_dir_all(dir.join("outside\\sub")).unwrap();
            std::fs::write(dir.join("outside\\sub\\victim"), b"KEEP ME").unwrap();
            if !plant(kind, &dir.join("outside"), &dir.join("out\\link")) {
                continue;
            }
            // The planted link does lead outside: the file is seen
            // through it before the run.
            assert_eq!(
                std::fs::read(dir.join("out\\link\\sub\\victim")).unwrap(),
                b"KEEP ME",
                "{kind:?} {width}: the planted link does not lead outside"
            );
            std::fs::write(dir.join("a.rar"), &arc).unwrap();
            let done = run(&dir, &["x", "-o+", width, "a.rar", "out\\"]);
            let said = text(&done);
            assert_eq!(
                std::fs::read(dir.join("outside\\sub\\victim")).unwrap(),
                b"KEEP ME",
                "{kind:?} {width}: the file outside the destination was written over: {said}"
            );
            assert_eq!(done.status.code(), Some(0), "{kind:?} {width}: {said}");
            assert!(
                is_real_dir(&dir.join("out\\link")),
                "{kind:?} {width}: out\\link is still a link: {said}"
            );
            assert_eq!(
                std::fs::read(dir.join("out\\link\\sub\\victim")).unwrap(),
                b"ARCHIVE CONTENT",
                "{kind:?} {width}: {said}"
            );
            assert_eq!(
                std::fs::read_dir(dir.join("outside\\sub")).unwrap().count(),
                1,
                "{kind:?} {width}: nothing new outside"
            );
            assert!(
                dir.join("outside").is_dir(),
                "{kind:?} {width}: what the link pointed at is still there"
            );
        }
    }
}

/// A directory member below the junction: its time is set on the real
/// directory made inside the destination, and the directory outside
/// keeps the time it had.
#[test]
fn a_directory_member_sets_no_time_through_a_junction() {
    let stored = 1_000_000_000_u32;
    let arc = archive(&[("link/sub", Kind::Dir(stored))]);
    let member_time = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(stored));
    for kind in KINDS {
        for width in WIDTHS {
            let (dir, _watch) = DirWatch::over(&format!("dir-{kind:?}"), width);
            std::fs::create_dir_all(dir.join("out")).unwrap();
            let outside_sub = dir.join("outside\\sub");
            std::fs::create_dir_all(&outside_sub).unwrap();
            if !plant(kind, &dir.join("outside"), &dir.join("out\\link")) {
                continue;
            }
            // Whatever time the directory outside has now, it is not the
            // member's (2001), so a time set through the link would show.
            let kept = std::fs::metadata(&outside_sub).unwrap().modified().unwrap();
            assert_ne!(kept, member_time, "{kind:?} {width}");
            std::fs::write(dir.join("a.rar"), &arc).unwrap();
            let done = run(&dir, &["x", width, "a.rar", "out\\"]);
            let said = text(&done);
            assert_eq!(
                std::fs::metadata(&outside_sub).unwrap().modified().unwrap(),
                kept,
                "{kind:?} {width}: the time of a directory outside the destination changed: {said}"
            );
            assert_eq!(done.status.code(), Some(0), "{kind:?} {width}: {said}");
            assert!(
                is_real_dir(&dir.join("out\\link")),
                "{kind:?} {width}: out\\link is still a link: {said}"
            );
            assert!(
                is_real_dir(&dir.join("out\\link\\sub")),
                "{kind:?} {width}: {said}"
            );
            // Said, not judged: whether a directory member's time is set at
            // all on this system is not this row's question.
            let own = std::fs::metadata(dir.join("out\\link\\sub"))
                .unwrap()
                .modified()
                .unwrap();
            eprintln!(
                "{kind:?} {width}: the member's own directory {} its stored time",
                if own == member_time {
                    "took"
                } else {
                    "did not take"
                }
            );
        }
    }
}

/// The destination the caller names is itself a junction: it is his, and
/// the members go where it leads.
#[test]
fn a_destination_that_is_a_junction_is_followed() {
    let arc = archive(&[("sub/file", Kind::File(b"ARCHIVE CONTENT"))]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("destjunction", width);
        std::fs::create_dir_all(dir.join("real\\sub")).unwrap();
        assert!(plant(
            Planted::Junction,
            &dir.join("real"),
            &dir.join("out")
        ));
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let done = run(&dir, &["x", "-o+", width, "a.rar", "out\\"]);
        assert_eq!(done.status.code(), Some(0), "{width}: {}", text(&done));
        assert_eq!(
            std::fs::read(dir.join("real\\sub\\file")).unwrap(),
            b"ARCHIVE CONTENT",
            "{width}: {}",
            text(&done)
        );
        assert!(
            !is_real_dir(&dir.join("out")) && dir.join("out").is_dir(),
            "{width}: the destination is still the caller's junction"
        );
    }
}

/// On Windows a backslash separates: `out\`, `out/` and an absolute path
/// ending in `\` each name the directory itself, there already or not.
#[test]
fn a_destination_ending_in_a_backslash_is_the_directory_it_names() {
    let arc = archive(&[
        ("payload", Kind::File(b"PAYLOAD")),
        ("d/inner", Kind::File(b"INNER")),
    ]);
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over("bs", width);
        std::fs::write(dir.join("a.rar"), &arc).unwrap();
        let absolute = format!("{}\\", dir.join("abs").display());
        for (dest, lands) in [
            ("out\\", "out"),
            ("fwd/", "fwd"),
            ("deep\\er\\", "deep\\er"),
            (absolute.as_str(), "abs"),
        ] {
            let done = run(&dir, &["x", width, "a.rar", dest]);
            let said = text(&done);
            assert_eq!(done.status.code(), Some(0), "{width} {dest}: {said}");
            assert_eq!(
                std::fs::read(dir.join(lands).join("payload")).unwrap(),
                b"PAYLOAD",
                "{width} {dest}: {said}"
            );
            assert_eq!(
                std::fs::read(dir.join(lands).join("d\\inner")).unwrap(),
                b"INNER",
                "{width} {dest}: {said}"
            );
        }
        // Nothing but the archive and the four destinations was made.
        let mut made: Vec<String> = std::fs::read_dir(&*dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        made.sort();
        assert_eq!(made, ["a.rar", "abs", "deep", "fwd", "out"], "{width}");
    }
}
