//! A directory member that cannot be created is a create error: said,
//! counted, and the run does not exit 0.
//!
//! Found by an outside review on 10 Oct 2026, by running the tool: a
//! directory member `dir` whose path holds a regular file gave `All OK`,
//! exit 0, an empty stderr and no directory. The failed create fell
//! through to the member being counted as done.
//!
//! unrar 7.23 (homebrew's, aarch64 macOS, 10 Oct 2026):
//!
//! - a directory under a regular file (`dir/sub`, `dir` a file), with and
//!   without `-o+`: stderr `\nCannot create directory out/dir/sub\nNot a
//!   directory`, `Total errors: 1`, exit 9, the members after it still
//!   extracted, and the same layout as its `Cannot create <file>` (one
//!   more newline under `-idq`; on one stream, `-ierr`, the two lines end
//!   themselves where the member's line would have been). Followed here.
//! - a directory whose OWN path is a regular file (measured again 11 Oct
//!   2026): under `-o+` and `-y` it REMOVES the file and makes the
//!   directory (`Creating    out/dir  OK`, exit 0); with no switch it ASKS
//!   whether to replace the file, with no `[R]ename` among the choices:
//!   `y` and `a` replace it, `n` and `e` leave it and say `Cannot create
//!   directory out/dir`, `File exists`, exit 9, `q` ends the run with
//!   exit 255, an empty standard input with exit 12; under `-o-` it says
//!   those two lines, exit 9, the file left alone. FOLLOWED HERE since 11
//!   Oct 2026 (until then rarfast left the file under every switch and
//!   exited 9). The file is removed as the entry it is; a link is never
//!   followed.
//! - under `-or` it makes the directory under the next free NUMBERED
//!   name (`dir(1)`, then `dir(2)`), `Creating    out/dir(1)  OK`, exit
//!   0, the file left as it was. Followed.
//! - A LINK at the directory's own path (measured 11 Oct 2026, a link to
//!   nothing, to a file and to a directory, under every switch). ONE RULE
//!   here, spec F 3.8.3's, settled the same day: a link standing where a
//!   directory is wanted is NEVER FOLLOWED and is handled as a FILE
//!   standing in the way, under the overwrite rule: `-o+` and `-y`
//!   replace the LINK by a real directory, the default asks, `-o-` keeps
//!   it (the directory is then a create error, exit 9), `-or` numbers.
//!   What the link names is never touched. Against the reference:
//!   - a link to a FILE: the same. Followed.
//!   - a link to a DIRECTORY: where the directory member stands alone
//!     the reference takes the link for the directory (`All OK`, the
//!     link left). NOT followed: a stated difference. (What it does when
//!     a member lies beneath the path was not measured here; the
//!     specification's rows, SPEC-CLI 9.2 O19, say it then replaces the
//!     link by a real directory and never writes through it.)
//!   - a link to NOTHING: the reference refuses it under every switch,
//!     `-o+` too (`Cannot create directory`, `File exists`, exit 9). NOT
//!     followed: a second stated difference.
//!
//! WIDTHS: every member here is a directory or a file of three bytes, so
//! the walk writes them all on its own thread at any width; the rows run
//! at the default width and at `-mt1`. MEMORY: the tool's floor.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-blocked-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// One block: CRC32, size, then `body` (spec F 3.2.2), then `data`.
fn block(body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
}

/// A stored RAR 5 archive, written by a Unix host: a member with `None`
/// is a directory, one with bytes a file.
fn rar5(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    for &(name, data) in entries {
        let bytes = data.unwrap_or(b"");
        let mut body = Vec::new();
        vint(2, &mut body); // a file header
        vint(2, &mut body); // with a data area
        vint(bytes.len() as u64, &mut body);
        // CRC32 present; a directory has the directory bit too.
        vint(if data.is_some() { 4 } else { 5 }, &mut body);
        vint(bytes.len() as u64, &mut body);
        vint(
            if data.is_some() { 0o100_644 } else { 0o040_755 },
            &mut body,
        );
        body.extend_from_slice(&crc32(bytes).to_le_bytes());
        vint(0, &mut body); // stored
        vint(1, &mut body); // Unix
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        block(&body, bytes, &mut out);
    }
    block(&[5, 0, 0], &[], &mut out);
    out
}

const KEPT: &[u8] = b"KEEP ME";

/// One `x` into a fresh `out/` whose `dir` is a regular file, standard
/// input empty.
fn run(dir: &Path, switches: &[&str]) -> Output {
    run_answering(dir, switches, "")
}

/// [`run`] with `answers` on standard input.
fn run_answering(dir: &Path, switches: &[&str], answers: &str) -> Output {
    use std::io::Write;
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("dir"), KEPT).unwrap();
    let mut child = Command::new(rarfast())
        .current_dir(dir)
        .arg("x")
        .args(switches)
        .arg("a.rar")
        .arg("out/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The file in the way is still the caller's: a file, with its bytes.
fn assert_kept(dir: &Path, row: &str) {
    let blocking = dir.join("out/dir");
    let meta = std::fs::symlink_metadata(&blocking).unwrap();
    assert!(meta.is_file(), "{row}: the file in the way is gone");
    assert_eq!(std::fs::read(&blocking).unwrap(), KEPT, "{row}");
}

/// A directory member whose own path is a regular file, selected alone:
/// replaced under `-o+` and `-y`, as the reference replaces it.
#[test]
fn a_file_at_a_directorys_path_is_replaced_when_the_run_may_overwrite() {
    let dir = work("own");
    std::fs::write(dir.join("a.rar"), rar5(&[("dir", None)])).unwrap();
    for switches in [&["-o+"][..], &["-o+", "-mt1"], &["-y"], &["-y", "-mt1"]] {
        let row = format!("x {switches:?}");
        let output = run(&dir, switches);
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(0), "{row}\n{stdout}\n{stderr}");
        assert!(stderr.is_empty(), "{row}: {stderr:?}");
        assert!(stdout.contains("Creating    out/dir"), "{row}: {stdout}");
        assert!(stdout.ends_with("All OK\n"), "{row}: {stdout}");
        let made = std::fs::symlink_metadata(dir.join("out/dir")).unwrap();
        assert!(made.is_dir(), "{row}: the file was not replaced");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no switch the run ASKS, as for a file that is there, with no
/// `[R]ename` on offer: `y` and `a` replace the file by the directory;
/// `n` and `e` leave it and the directory is a create error, exit 9; `q`
/// ends the run, exit 255; an input at its end, exit 12.
#[test]
fn a_file_at_a_directorys_path_is_asked_about() {
    let dir = work("ask");
    std::fs::write(dir.join("a.rar"), rar5(&[("dir", None)])).unwrap();
    for (answers, code, replaced) in [
        ("y\n", 0, true),
        ("a\n", 0, true),
        ("n\n", 9, false),
        ("e\n", 9, false),
        ("q\n", 255, false),
        ("", 12, false),
    ] {
        for width in [&[][..], &["-mt1"]] {
            let row = format!("answers {answers:?}, {width:?}");
            let output = run_answering(&dir, width, answers);
            let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
            assert_eq!(
                output.status.code(),
                Some(code),
                "{row}\n{stdout}\n{stderr}"
            );
            assert!(
                stderr.contains("Would you like to replace the existing file out/dir"),
                "{row}: {stderr:?}"
            );
            assert!(
                stderr.contains("[Y]es, [N]o, [A]ll, n[E]ver, [Q]uit"),
                "{row}: {stderr:?}"
            );
            assert!(!stderr.contains("[R]ename"), "{row}: {stderr:?}");
            if replaced {
                let made = std::fs::symlink_metadata(dir.join("out/dir")).unwrap();
                assert!(made.is_dir(), "{row}: the file was not replaced");
                assert!(stdout.ends_with("All OK\n"), "{row}: {stdout}");
            } else {
                assert_kept(&dir, &row);
                assert!(!stdout.contains("All OK"), "{row}: {stdout}");
            }
            if code == 9 {
                assert!(
                    stderr.contains("Cannot create directory out/dir\n"),
                    "{row}: {stderr:?}"
                );
                assert!(stdout.ends_with("Total errors: 1\n"), "{row}: {stdout}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `-or` the directory takes the next free numbered name and the
/// file stays, as the reference has it: `dir(1)`, and `dir(2)` where
/// `dir(1)` is taken too.
#[test]
fn a_file_at_a_directorys_path_sends_the_directory_to_a_numbered_name() {
    let dir = work("numbered");
    std::fs::write(dir.join("a.rar"), rar5(&[("dir", None)])).unwrap();
    for width in [&["-or"][..], &["-or", "-mt1"]] {
        let row = format!("x {width:?}");
        let output = run(&dir, width);
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(0), "{row}\n{stdout}\n{stderr}");
        assert!(stdout.contains("Creating    out/dir(1)"), "{row}: {stdout}");
        assert!(stdout.ends_with("All OK\n"), "{row}: {stdout}");
        assert!(dir.join("out/dir(1)").is_dir(), "{row}");
        assert_kept(&dir, &row);
        // again, with dir(1) there: dir(2)
        let again = Command::new(rarfast())
            .current_dir(&dir)
            .arg("x")
            .args(width)
            .args(["a.rar", "out/"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            again.status.code(),
            Some(0),
            "{row}: {}",
            text(&again.stdout)
        );
        assert!(dir.join("out/dir(2)").is_dir(), "{row}");
        assert_kept(&dir, &row);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A LINK at a directory member's own path is never followed and is
/// handled as a file standing in the way, whatever it leads to (a file,
/// a directory, nothing): `-o+` and `-y` replace the LINK by a real
/// directory; with no switch the run asks (exit 12 here, the input being
/// at its end); `-o-` keeps the link and the directory is a create error,
/// exit 9; `-or` makes `dir(1)` and leaves the link. In every case WHAT
/// THE LINK NAMES is untouched: a file's bytes and time, a directory's
/// emptiness and time, and nothing made where a link to nothing led.
#[cfg(unix)]
#[test]
fn a_link_at_a_directorys_path_is_a_file_in_the_way_and_never_followed() {
    use std::time::{Duration, SystemTime};
    let dir = work("link");
    std::fs::write(dir.join("a.rar"), rar5(&[("dir", None)])).unwrap();
    let outside = dir.join("outside");
    let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_262_304_000);
    for leads_to in ["a file", "a directory", "nothing"] {
        for (switches, code, what) in [
            (&["-o+"][..], 0, "replaced"),
            (&["-y"], 0, "replaced"),
            (&["-o+", "-mt1"], 0, "replaced"),
            (&[], 12, "left"),
            (&["-o-"], 9, "left"),
            (&["-or"], 0, "numbered"),
        ] {
            let row = format!("a link to {leads_to}, x {switches:?}");
            let _ = std::fs::remove_dir_all(&outside);
            let _ = std::fs::remove_file(&outside);
            match leads_to {
                "a file" => std::fs::write(&outside, KEPT).unwrap(),
                "a directory" => std::fs::create_dir(&outside).unwrap(),
                _ => {}
            }
            if leads_to != "nothing" {
                std::fs::File::open(&outside)
                    .unwrap()
                    .set_modified(then)
                    .unwrap();
            }
            let out = dir.join("out");
            let _ = std::fs::remove_dir_all(&out);
            std::fs::create_dir_all(&out).unwrap();
            std::os::unix::fs::symlink(&outside, out.join("dir")).unwrap();
            let output = Command::new(rarfast())
                .current_dir(&dir)
                .arg("x")
                .args(switches)
                .args(["a.rar", "out/"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
            assert_eq!(
                output.status.code(),
                Some(code),
                "{row}\n{stdout}\n{stderr}"
            );
            let at = std::fs::symlink_metadata(out.join("dir")).unwrap();
            match what {
                "replaced" => {
                    assert!(at.is_dir() && !at.file_type().is_symlink(), "{row}");
                    assert!(stdout.contains("Creating    out/dir"), "{row}: {stdout}");
                }
                "numbered" => {
                    assert!(at.file_type().is_symlink(), "{row}: the link is gone");
                    assert!(out.join("dir(1)").is_dir(), "{row}");
                }
                _ => assert!(at.file_type().is_symlink(), "{row}: the link is gone"),
            }
            if code == 12 {
                assert!(
                    stderr.contains("Would you like to replace the existing file out/dir"),
                    "{row}: {stderr:?}"
                );
            }
            if code == 9 {
                assert!(
                    stderr.contains("Cannot create directory out/dir\n"),
                    "{row}: {stderr:?}"
                );
            }
            // What the link names, as it was.
            match leads_to {
                "a file" => {
                    assert_eq!(std::fs::read(&outside).unwrap(), KEPT, "{row}");
                    assert_eq!(
                        std::fs::metadata(&outside).unwrap().modified().unwrap(),
                        then,
                        "{row}: the target's time"
                    );
                }
                "a directory" => {
                    assert_eq!(
                        std::fs::read_dir(&outside).unwrap().count(),
                        0,
                        "{row}: something was written through the link"
                    );
                    assert_eq!(
                        std::fs::metadata(&outside).unwrap().modified().unwrap(),
                        then,
                        "{row}: the target's time"
                    );
                }
                _ => assert!(std::fs::symlink_metadata(&outside).is_err(), "{row}"),
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `-o-` the file is left alone and the directory is a create
/// error, exit 9, as the reference has it.
#[test]
fn a_file_at_a_directorys_path_is_kept_when_the_run_may_not_overwrite() {
    let dir = work("keep");
    std::fs::write(dir.join("a.rar"), rar5(&[("dir", None)])).unwrap();
    for switches in [&["-o-"][..], &["-o-", "-mt1"]] {
        let row = format!("x {switches:?}");
        let output = run(&dir, switches);
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(9), "{row}\n{stdout}\n{stderr}");
        assert!(
            stderr.starts_with("\nCannot create directory out/dir\n"),
            "{row}: {stderr:?}"
        );
        assert!(!stdout.contains("All OK"), "{row}: {stdout}");
        assert!(stdout.ends_with("Total errors: 1\n"), "{row}: {stdout}");
        assert!(!stdout.contains("Creating"), "{row}: {stdout}");
        assert_kept(&dir, &row);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file in the way, where it is kept (`-o-`), keeps its mode: the
/// directory's is not queued to be set on it when the walk ends.
#[test]
fn nothing_is_set_on_the_file_in_the_way() {
    let dir = work("times");
    std::fs::write(
        dir.join("a.rar"),
        rar5(&[("dir", None), ("b.txt", Some(b"bbb"))]),
    )
    .unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let output = run(&dir, &["-o-"]);
    assert_eq!(output.status.code(), Some(9));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(out.join("dir"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0, "the directory's mode was set on the file");
    }
    assert_eq!(std::fs::read(out.join("dir")).unwrap(), KEPT);
    assert_eq!(std::fs::read(out.join("b.txt")).unwrap(), b"bbb");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A directory under a regular file, and a file under it, between members
/// that extract: unrar 7.23's lines, counts and exit code.
#[test]
fn a_directory_under_a_file_is_said_as_the_reference_says_it() {
    let dir = work("under");
    let archive = rar5(&[
        ("a.txt", Some(b"aaa")),
        ("dir/sub", None),
        ("b.txt", Some(b"bbb")),
        ("dir/f.txt", Some(b"fff")),
        ("c.txt", Some(b"ccc")),
    ]);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    // The archived part of a shown name takes the host's separator.
    let sep = std::path::MAIN_SEPARATOR;
    let first = format!("Cannot create directory out/dir{sep}sub\n");
    let second = format!("Cannot create out/dir{sep}f.txt\n");
    for switches in [&[][..], &["-o+"], &["-mt1"]] {
        let row = format!("x {switches:?}");
        let output = run(&dir, switches);
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(9), "{row}\n{stdout}\n{stderr}");
        // Two complaints of two lines each, run together, the first
        // opened by a newline and the last not ended.
        assert!(
            stderr.starts_with(&format!("\n{first}")),
            "{row}: {stderr:?}"
        );
        let rest = &stderr[1 + first.len()..];
        let (reason, rest) = rest.split_once('\n').unwrap();
        // The system's reason for a path through a file, as the
        // reference has it; Windows words its own.
        if cfg!(unix) {
            assert_eq!(reason, "Not a directory", "{row}: {stderr:?}");
        }
        assert!(!reason.is_empty(), "{row}: {stderr:?}");
        assert!(rest.starts_with(&second), "{row}: {stderr:?}");
        assert!(!rest[second.len()..].contains('\n'), "{row}: {stderr:?}");
        assert!(stdout.ends_with("Total errors: 2\n"), "{row}: {stdout}");
        assert_eq!(stdout.matches("  OK ").count(), 3, "{row}: {stdout}");
        for (name, bytes) in [("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")] {
            assert_eq!(std::fs::read(dir.join("out").join(name)).unwrap(), bytes);
        }
        assert_eq!(std::fs::read(dir.join("out/dir")).unwrap(), KEPT, "{row}");
    }
    // `-idq`: nothing on stdout, and stderr ends its last line.
    let output = run(&dir, &["-idq"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(9));
    assert!(output.stdout.is_empty());
    assert!(stderr.starts_with(&format!("\n{first}")), "{stderr:?}");
    assert!(stderr.ends_with('\n'), "{stderr:?}");
    // `-ierr`: one stream, each complaint where its member's line would be.
    let output = run(&dir, &["-ierr"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(9));
    let at = |needle: &str| {
        stderr
            .find(needle)
            .unwrap_or_else(|| panic!("{needle}: {stderr:?}"))
    };
    assert!(at("a.txt") < at(&format!("OK \n{first}")), "{stderr:?}");
    assert!(at(&first) < at("b.txt"), "{stderr:?}");
    assert!(at("b.txt") < at(&second), "{stderr:?}");
    assert!(stderr.ends_with("Total errors: 2\n"), "{stderr:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A directory that CAN be made still is, with its line, beside one that
/// cannot; and one already there is no error.
#[test]
fn directories_that_can_be_made_are_made() {
    let dir = work("made");
    let archive = rar5(&[("ok", None), ("dir", None), ("ok/deep", None)]);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    // `-o-`: the one rule under which a file at a directory's path is
    // left and the directory cannot be made (with no switch the run now
    // asks about it, as the reference does).
    let output = run(&dir, &["-o-"]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(9), "{stdout}");
    assert!(dir.join("out/ok/deep").is_dir());
    assert_eq!(stdout.matches("Creating").count(), 2, "{stdout}");
    assert!(stdout.ends_with("Total errors: 1\n"), "{stdout}");

    std::fs::write(dir.join("a.rar"), rar5(&[("ok", None), ("ok/deep", None)])).unwrap();
    for _ in 0..2 {
        let out = dir.join("out");
        let output = Command::new(rarfast())
            .current_dir(&dir)
            .args(["x", "a.rar", "out/"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
        assert!(out.join("ok/deep").is_dir());
        assert!(text(&output.stdout).ends_with("All OK\n"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A real FILE standing where a member's PARENT must be is refused under
/// every switch, `-o+` and `-y` too, as the reference refuses it: nobody's
/// file is deleted to make a directory that no member names. The members
/// under it fail (a file member and a directory member alike), exit 9;
/// the file is as it was; a member elsewhere is still extracted.
#[test]
fn a_file_where_a_parent_must_be_is_never_removed() {
    let dir = work("parent");
    let archive = rar5(&[
        ("p/q/x.txt", Some(b"xxx")),
        ("p/q/d", None),
        ("ok.txt", Some(b"ooo")),
    ]);
    std::fs::write(dir.join("a.rar"), archive).unwrap();
    // The archived part of a shown name takes the host's separator.
    let sep = std::path::MAIN_SEPARATOR;
    let file_line = format!("Cannot create out/p{sep}q{sep}x.txt\n");
    let directory_line = format!("Cannot create directory out/p{sep}q{sep}d\n");
    for switches in [
        &["-o+"][..],
        &["-y"],
        &[],
        &["-o-"],
        &["-or"],
        &["-o+", "-mt1"],
    ] {
        let row = format!("x {switches:?}");
        let out = dir.join("out");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("p"), KEPT).unwrap();
        let output = Command::new(rarfast())
            .current_dir(&dir)
            .arg("x")
            .args(switches)
            .args(["a.rar", "out/"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(9), "{row}\n{stdout}\n{stderr}");
        let p = std::fs::symlink_metadata(out.join("p")).unwrap();
        assert!(p.is_file(), "{row}: the file in a parent's place is gone");
        assert_eq!(std::fs::read(out.join("p")).unwrap(), KEPT, "{row}");
        assert!(stderr.contains(&file_line), "{row}: {stderr:?}");
        assert!(stderr.contains(&directory_line), "{row}: {stderr:?}");
        assert!(!stderr.contains("Would you like"), "{row}: {stderr:?}");
        assert_eq!(std::fs::read(out.join("ok.txt")).unwrap(), b"ooo", "{row}");
        assert!(stdout.ends_with("Total errors: 2\n"), "{row}: {stdout}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
