//! A failed write ENDS an extraction, as it ends the reference's.
//!
//! Measured on 9 Oct 2026 with unrar 7.23 (an Apple silicon Mac), `x` and
//! `e` of five members (`a.txt` 100 KB, `big.bin` 5 MB, `c.txt` 100 KB,
//! `e.bin` 4 MB, `z.txt` 50 KB) onto a 3 MB volume, and under a file size
//! limit, solid and not, plain and under `-idq`, `-idd`, `-idp`, `-idn`
//! and `-ierr`. The reference stops at the first write that fails:
//!
//! ```text
//! Extracting  mnt/a.txt                                                 OK
//! Extracting  mnt/big.bin
//! Program aborted                                  <- stdout, exit 5
//! Write error in the file mnt/big.bin              <- stderr, no newline before it
//! No space left on device                          <- stderr, no newline after it
//! ```
//!
//! `a.txt` is kept, the partial `big.bin` is removed, and `c.txt`, `e.bin`
//! and `z.txt` are never begun. Under `-ierr` the complaint follows the
//! member's open line ON that line and `Program aborted` ends the stream;
//! under `-idq` stderr is those two lines and nothing after them; `-idd`
//! keeps `Program aborted`.
//!
//! Until this day rarfast closed such a run with `Total errors: 1`, put a
//! newline before the complaint, and at any width over one went on: later
//! members the concurrent walk had in flight were written and said `OK`,
//! and one it abandoned was left as an open line with no word (two of
//! them ran together on one line at `-mt2`).
//!
//! **At `-mt1` rarfast now does what the reference does, byte for byte**
//! but for the reason line, which is the real reason (`File too large`
//! here, `No space left on device` on a full volume) where the
//! reference's under a file size limit is an unrelated errno.
//!
//! **Wider, a NAMED DIFFERENCE stays**, kept on purpose (9 Oct 2026): the walk has
//! later members in flight when the write fails. One already written
//! whole stays, with its `OK`: a right, complete file is never deleted.
//! One whose line was said and which did not finish is named `<name> -
//! not extracted` before `Program aborted`, its partial removed. One that
//! had not been said is not said, and what was made for it is removed.
//! No order is imposed on delivery to prevent any of this. And `-kb`
//! keeps the bytes of the failed member that fitted, where the reference
//! keeps an empty file.
//!
//! The write is cut short by `ulimit -f`, set in a child shell as
//! `walk_error_settles.rs` sets its own: the shell ignores `SIGXFSZ`, so
//! the write fails with `EFBIG`. `ulimit -f` counts 512 byte blocks in a
//! POSIX shell and 1024 byte blocks in plain bash; 4,000 blocks is 2 MB
//! or 4 MB, between the small members (100 KB) and the large (6 MB)
//! either way.
//!
//! Width and memory: `-mt1` and `-mt4`, stated on each run; 12 MB of
//! members, held once to write them.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

const LIMIT_BLOCKS: u32 = 4000;

/// In archive order: a small member, one over the limit, a small one, a
/// second over the limit, a small one.
const MEMBERS: [(&str, usize); 5] = [
    ("a.txt", 100_000),
    ("big.bin", 6_000_000),
    ("c.txt", 100_000),
    ("e.bin", 6_000_000),
    ("z.txt", 50_000),
];

fn payload(seed: usize, len: usize) -> Vec<u8> {
    let mut state = (seed as u32 + 1).wrapping_mul(0x9e37_79b9) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// A scratch directory holding `arc.rar`, the five members stored, and
/// an empty `out`.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-wabort-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let mut args = vec!["a", "-idq", "-m0", "-mt1", "arc.rar"];
    for (seed, (name, len)) in MEMBERS.iter().enumerate() {
        std::fs::write(dir.join(name), payload(seed, *len)).unwrap();
        args.push(name);
    }
    let made = Command::new(rarfast())
        .current_dir(&dir)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(
        made.status.code(),
        Some(0),
        "building the archive: {made:?}"
    );
    for (name, _) in MEMBERS {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
    dir
}

/// `rarfast <args>` in `dir` under the file size limit: the exit, stdout
/// and stderr as they came.
fn run_limited(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new("/bin/sh")
        .current_dir(dir)
        .arg("-c")
        .arg(format!(
            "trap '' XFSZ; ulimit -f {LIMIT_BLOCKS} || exit 99; exec \"$0\" \"$@\""
        ))
        .arg(rarfast())
        .args(args)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(99), "the shell refused the limit");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The lines of `text` that hold anything, each as its words.
fn words(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|line| !line.is_empty())
        .collect()
}

fn present(dir: &Path) -> Vec<&'static str> {
    MEMBERS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| dir.join("out").join(name).exists())
        .collect()
}

/// The complaint: the write error and a reason, nothing before the first
/// line and no newline after the second.
fn is_the_complaint(stderr: &str) {
    let (first, reason) = stderr.split_once('\n').expect("two lines");
    assert_eq!(first, "Write error in the file out/big.bin", "{stderr:?}");
    assert!(!reason.is_empty() && !reason.contains('\n'), "{stderr:?}");
}

#[test]
fn at_one_thread_the_run_stops_as_the_reference_stops() {
    let dir = work("one");
    // `-idp` takes the counter out, so the lines are the reference's own.
    let (code, stdout, stderr) =
        run_limited(&dir, &["x", "-mt1", "-y", "-o+", "-idp", "arc.rar", "out/"]);
    assert_eq!(code, Some(5), "{stdout}{stderr}");
    assert_eq!(
        words(&stdout),
        [
            vec!["Extracting", "from", "arc.rar"],
            vec!["Extracting", "out/a.txt", "OK"],
            vec!["Extracting", "out/big.bin"],
            vec!["Program", "aborted"],
        ],
        "{stdout:?}"
    );
    assert!(stdout.ends_with(" \nProgram aborted\n"), "{stdout:?}");
    is_the_complaint(&stderr);
    assert_eq!(present(&dir), ["a.txt"]);

    // Where stdout is not shown, stderr is the same two lines, unended.
    std::fs::remove_file(dir.join("out/a.txt")).unwrap();
    let (code, stdout, stderr) =
        run_limited(&dir, &["x", "-mt1", "-y", "-o+", "-idq", "arc.rar", "out/"]);
    assert_eq!((code, stdout.as_str()), (Some(5), ""));
    is_the_complaint(&stderr);

    // On one stream the complaint follows the member's open line on that
    // line, and `Program aborted` ends the stream.
    std::fs::remove_file(dir.join("out/a.txt")).unwrap();
    let (code, stdout, stderr) = run_limited(
        &dir,
        &["x", "-mt1", "-y", "-o+", "-idp", "-ierr", "arc.rar", "out/"],
    );
    assert_eq!((code, stdout.as_str()), (Some(5), ""));
    let lines = words(&stderr);
    assert_eq!(
        lines[lines.len() - 3][..7],
        [
            "Extracting",
            "out/big.bin",
            "Write",
            "error",
            "in",
            "the",
            "file"
        ],
        "{stderr:?}"
    );
    assert_eq!(lines[lines.len() - 1], ["Program", "aborted"], "{stderr:?}");
    assert!(stderr.ends_with("\nProgram aborted\n"), "{stderr:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The NAMED DIFFERENCE, pinned as a shape: at four threads the members
/// after the failed one may be written, abandoned or never begun, by
/// timing, and each of the three is told truly.
#[test]
fn wider_the_run_still_aborts_and_every_member_is_told_truly() {
    let dir = work("four");
    for _ in 0..4 {
        for (name, _) in MEMBERS {
            let _ = std::fs::remove_file(dir.join("out").join(name));
        }
        let (code, stdout, stderr) =
            run_limited(&dir, &["x", "-mt4", "-y", "-o+", "-idp", "arc.rar", "out/"]);
        let said = format!("{stdout:?} {stderr:?}");
        assert_eq!(code, Some(5), "{said}");
        is_the_complaint(&stderr);
        assert!(stdout.ends_with("\nProgram aborted\n"), "{said}");
        assert!(!stdout.contains("Total errors"), "{said}");
        let lines = words(&stdout);
        // No two members' lines run together.
        for line in &lines {
            assert!(
                line.iter().filter(|word| **word == "Extracting").count() <= 1,
                "{said}"
            );
        }
        let has = |line: &[&str]| lines.iter().any(|said| said.as_slice() == line);
        assert!(has(&["Extracting", "out/a.txt", "OK"]), "{said}");
        assert!(has(&["Extracting", "out/big.bin"]), "{said}");
        assert!(!dir.join("out/big.bin").exists(), "{said}");
        assert!(dir.join("out/a.txt").exists(), "{said}");
        for (seed, (name, len)) in MEMBERS.iter().enumerate().skip(2) {
            let shown = format!("out/{name}");
            let ok = has(&["Extracting", &shown, "OK"]);
            let open = has(&["Extracting", &shown]);
            let abandoned = has(&[&shown, "-", "not", "extracted"]);
            match std::fs::read(dir.join("out").join(name)) {
                // Written whole and right, and said so.
                Ok(bytes) => {
                    assert!(bytes == payload(seed, *len), "{name}: {said}");
                    assert!(ok && !abandoned, "{name}: {said}");
                }
                // Not there: said as not extracted, or never said.
                Err(_) => {
                    assert!(!ok, "{name}: {said}");
                    assert_eq!(open, abandoned, "{name}: {said}");
                }
            }
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
