//! What `rarfast` prints for a member whose password is REFUSED by its
//! check record
//! (spec K 3.7.3's verdict, SPEC-API 4.4's `password_refused`).
//!
//! Measured against `unrar` 7.23 on 30 Sep 2026 over `rar -p` sets (one
//! archive of two members; one member over three volumes, stored and
//! `-m3`; two members over four), `t`, `x` and `p`, plain, `-ierr` and
//! `-mt1`, exit code, stdout, stderr and the files left, 36 of 36 cells
//! byte-identical after this change and none before it:
//!
//! - NO progress line for the refused member (`Testing`, `Extracting`,
//!   `------ Printing`), and under `x` no `Creating` line and no directory
//!   made for it: the reference judges the password before it says or
//!   makes anything for the member, where the engine judges it after the
//!   sink's `open`, so the dialect holds what an encrypted member's `open`
//!   says and makes until the member is known not to be refused;
//! - `Incorrect password for <name>` once for EVERY volume the member
//!   spans, each after that volume's banner (`p` prints no later banner),
//!   and each counted in `Total errors`;
//! - on one stream (`-ierr`) each line ends itself; apart, each opens with
//!   a newline, and `p` ends its stderr with ONE newline for the run, as
//!   it does after checksum complaints (two damaged members give
//!   `\nb.bin ... error\na.bin ... error\n`, not a newline each).
//!
//! **Fixtures.** Written by `rarfast a -p`, whose RAR 5 members carry check
//! records, from pinned PRNG bytes, so nothing need be on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-refused-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::scramble(0x7077_0000 + seed, len)
}

/// Writes `b.bin` (200 KB) and `a.bin` (3 MB) and archives `members` of
/// them with `-psecret` and `extra`; the archive's volumes, sorted.
fn make(dir: &Path, members: &[&str], extra: &[&str]) -> Vec<String> {
    std::fs::write(dir.join("b.bin"), noise(200_000, 2)).unwrap();
    std::fs::write(dir.join("a.bin"), noise(3_000_000, 1)).unwrap();
    let mut args = vec!["a", "-ma5", "-psecret", "-y", "-idq"];
    args.extend_from_slice(extra);
    args.push("s.rar");
    args.extend_from_slice(members);
    let made = run(dir, &args);
    assert_eq!(made.code, Some(0), "rarfast a: {}", made.stderr);
    std::fs::remove_file(dir.join("b.bin")).unwrap();
    std::fs::remove_file(dir.join("a.bin")).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("s.") && n.ends_with(".rar"))
        .collect();
    names.sort();
    names
}

fn refusal(name: &str) -> String {
    format!("\nIncorrect password for {name}")
}

/// One archive, two members, both refused: no member line, one refusal
/// each, `Total errors: 2`, exit 11, under `t` and `x`; `x` leaves no file.
#[test]
fn a_refused_member_prints_no_line_of_its_own() {
    let dir = work("single");
    let vols = make(&dir, &["b.bin", "a.bin"], &["-m0"]);
    assert_eq!(vols, ["s.rar"]);
    for (cmd, banner) in [("t", "Testing archive"), ("x", "Extracting from")] {
        let mut args = vec![cmd, "-pwrong", "s.rar"];
        if cmd == "x" {
            args.push("out/");
        }
        let ran = run(&dir, &args);
        assert_eq!(ran.code, Some(11), "{cmd}: {}", ran.stderr);
        assert_eq!(
            text(&ran.stdout),
            format!("\n{banner} s.rar\n\nTotal errors: 2\n"),
            "{cmd}"
        );
        assert_eq!(ran.stderr, refusal("b.bin") + &refusal("a.bin"), "{cmd}");
    }
    // Nor a directory: the reference makes nothing for a refused member,
    // not even the destination it would have made for it.
    assert!(!dir.join("out").exists(), "x left its destination behind");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A member over several volumes: one refusal per volume, each after its
/// volume's banner, every one counted.
#[test]
fn a_split_member_is_refused_once_per_volume() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("split{method}"));
        let vols = make(&dir, &["a.bin"], &[method, "-v1m"]);
        assert!(vols.len() >= 3, "{method}: {vols:?}");
        let n = vols.len();
        for width in [None, Some("-mt1")] {
            let mut args = vec!["t", "-pwrong"];
            args.extend(width);
            args.push(&vols[0]);
            let ran = run(&dir, &args);
            assert_eq!(ran.code, Some(11), "{method} {width:?}: {}", ran.stderr);
            let banners: String = vols
                .iter()
                .map(|v| format!("\nTesting archive {v}\n\n"))
                .collect();
            assert_eq!(
                text(&ran.stdout),
                format!("{banners}Total errors: {n}\n"),
                "{method} {width:?}"
            );
            assert_eq!(ran.stderr, refusal("a.bin").repeat(n), "{method} {width:?}");
        }
        // On one stream each refusal follows its own banner and ends itself.
        let ran = run(&dir, &["t", "-ierr", "-pwrong", &vols[0]]);
        let expected: String = vols
            .iter()
            .map(|v| format!("\nTesting archive {v}\n\nIncorrect password for a.bin\n"))
            .collect();
        assert_eq!(
            ran.stderr,
            format!("{expected}Total errors: {n}\n"),
            "{method}"
        );
        assert!(ran.stdout.is_empty(), "{method}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `p`: no heading for a refused member, no later banner, the refusals on
/// stderr and ONE newline ending that stream; nothing on stdout.
#[test]
fn print_says_each_refusal_and_ends_its_stream_once() {
    let dir = work("print");
    let vols = make(&dir, &["b.bin", "a.bin"], &["-m0", "-v1m"]);
    let n = vols.len();
    let ran = run(&dir, &["p", "-pwrong", &vols[0]]);
    assert_eq!(ran.code, Some(11), "{}", ran.stderr);
    assert!(ran.stdout.is_empty());
    // b.bin sits in the first volume alone; a.bin spans all of them.
    assert_eq!(
        ran.stderr,
        format!("{}{}\n", refusal("b.bin"), refusal("a.bin").repeat(n))
    );
    let ran = run(&dir, &["p", "-ierr", "-pwrong", &vols[0]]);
    assert_eq!(
        ran.stderr,
        format!(
            "\nExtracting from {}\n\nIncorrect password for b.bin\n{}Total errors: {}\n",
            vols[0],
            "Incorrect password for a.bin\n".repeat(n),
            n + 1
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The RIGHT password: the held line is printed after all, and the run is
/// as it was: `t` shows each member's line and `All OK`; `p` heads each
/// member on stderr and writes the payload whole.
#[test]
fn a_member_that_is_not_refused_keeps_its_line() {
    let dir = work("right");
    let vols = make(&dir, &["b.bin", "a.bin"], &["-m0"]);
    let ran = run(&dir, &["t", "-psecret", &vols[0]]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let out = text(&ran.stdout);
    for name in ["b.bin", "a.bin"] {
        assert!(out.contains(&format!("Testing     {name}")), "{out:?}");
    }
    assert!(out.ends_with("  OK \nAll OK\n"), "{out:?}");
    let ran = run(&dir, &["p", "-ierr", "-psecret", &vols[0]]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("------ Printing b.bin"),
        "{:?}",
        ran.stderr
    );
    assert!(
        ran.stderr.contains("------ Printing a.bin"),
        "{:?}",
        ran.stderr
    );
    let mut payload = noise(200_000, 2);
    payload.extend(noise(3_000_000, 1));
    assert!(ran.stdout == payload, "p's payload");
    let _ = std::fs::remove_dir_all(&dir);
}
