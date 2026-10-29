//! `rn` with several pairs: which pair names a member.
//!
//! THE RULE (SPEC-CLI 11.1, B11): every member's new name is built from
//! its ORIGINAL name, and a member is renamed by ONE pair. A pair whose
//! mask selects the member DIRECTLY (its whole name, or a wildcard in its
//! own directory) is the one that names it, over a pair that reaches it
//! only as beneath a directory, whatever their order. Among pairs of one
//! kind the FIRST is the one.
//!
//! Before 10 Oct 2026 a member took the first pair that named it in
//! either way: `rn s t s/a.txt z` left `t/a.txt` where the reference
//! leaves `z`.
//!
//! MEASURED on rar 7.23 for macOS (arm64), 10 Oct 2026, the same tree,
//! 38 argument lines; the rows below are nine of them. The archive here
//! is written by rarfast itself and listed by it; no reference tool is
//! called.
//!
//! ON WINDOWS every listing shows a name with a backslash (`t\b.txt`):
//! MEASURED with the genuine rar and unrar on a hosted Windows runner,
//! 11 Oct 2026 (`unrar l`, `lb`, `vb`; `rar lb`). The rows below are
//! written with `/`; the listing is read with this system's separator
//! made `/` ([`after`]), and on Windows it is asked first that the
//! separator shown IS the backslash. Until then the test compared the
//! Windows listing with the Unix spelling and was red there, the tool's
//! line being the reference's.
//!
//! Width and memory: `rn` and `lb` take no `-mt` here; six stored members
//! of a few bytes, so the test needs no memory to speak of.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    let dir = std::env::temp_dir().join(format!("rarfast-rnpairs-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

/// The tree `a.txt noext s s/a.txt s/b.txt s/d s/d/c.txt s/d/e
/// s/d/e/f.dat` in `arc.rar`.
fn fresh(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("arc.rar"));
    std::fs::create_dir_all(dir.join("s/d/e")).unwrap();
    for file in [
        "a.txt",
        "noext",
        "s/a.txt",
        "s/b.txt",
        "s/d/c.txt",
        "s/d/e/f.dat",
    ] {
        std::fs::write(dir.join(file), file).unwrap();
    }
    let made = run(
        dir,
        &["a", "-idq", "-m0", "-r", "arc.rar", "a.txt", "noext", "s"],
    );
    assert!(made.status.success(), "{made:?}");
}

/// The archive's names after `rn` with these arguments, sorted, each
/// with `/` between its parts whatever this system's listing shows.
fn after(dir: &Path, pairs: &[&str]) -> String {
    fresh(dir);
    let mut typed = vec!["rn", "arc.rar"];
    typed.extend(pairs);
    let ran = run(dir, &typed);
    assert_eq!(ran.status.code(), Some(0), "rn {pairs:?}: {ran:?}");
    let listed = run(dir, &["lb", "arc.rar"]);
    let shown = String::from_utf8_lossy(&listed.stdout).into_owned();
    if cfg!(windows) {
        // A Windows listing separates with a backslash and never with a
        // slash (the reference's, measured 11 Oct 2026).
        assert!(!shown.contains('/'), "rn {pairs:?}: {shown:?}");
    }
    let mut names: Vec<String> = shown
        .lines()
        .map(|name| {
            if cfg!(windows) {
                name.replace('\\', "/")
            } else {
                name.to_owned()
            }
        })
        .collect();
    names.sort();
    names.join(" ")
}

#[test]
fn a_pair_that_names_a_member_directly_is_the_one_that_names_it() {
    let (dir, _watch) = work("direct");
    // (the arguments, the names rar 7.23 leaves)
    let rows: [(&[&str], &str); 9] = [
        // A whole name over a directory above it, in either order.
        (
            &["s", "t", "s/a.txt", "z"],
            "a.txt noext t t/b.txt t/d t/d/c.txt t/d/e t/d/e/f.dat z",
        ),
        (
            &["s/a.txt", "z", "s", "t"],
            "a.txt noext t t/b.txt t/d t/d/c.txt t/d/e t/d/e/f.dat z",
        ),
        // A directory named whole is named directly; what is beneath it
        // is reached beneath by both pairs, and takes the first.
        (
            &["s", "t", "s/d", "u"],
            "a.txt noext t t/a.txt t/b.txt t/d/c.txt t/d/e t/d/e/f.dat u",
        ),
        (
            &["s/d", "u", "s", "t"],
            "a.txt noext t t/a.txt t/b.txt u u/c.txt u/e u/e/f.dat",
        ),
        // A wildcard in a member's own directory names it directly.
        (
            &["s", "t", "s/*", "q/*"],
            "a.txt noext q/a.txt q/b.txt q/d t t/d/c.txt t/d/e t/d/e/f.dat",
        ),
        (
            &["s/*", "q/*", "s", "t"],
            "a.txt noext q/a.txt q/b.txt q/d t t/d/c.txt t/d/e t/d/e/f.dat",
        ),
        // Among pairs of one kind the first.
        (
            &["a.txt", "z.txt", "a.txt", "y.txt"],
            "noext s s/a.txt s/b.txt s/d s/d/c.txt s/d/e s/d/e/f.dat z.txt",
        ),
        (
            &["*.txt", "*.bak", "a.txt", "z.txt"],
            "a.bak noext s s/a.txt s/b.txt s/d s/d/c.txt s/d/e s/d/e/f.dat",
        ),
        // Pairs do not chain: each name is built from the original.
        (
            &["a.txt", "noext", "noext", "a.txt"],
            "a.txt noext s s/a.txt s/b.txt s/d s/d/c.txt s/d/e s/d/e/f.dat",
        ),
    ];
    for (pairs, owed) in rows {
        assert_eq!(after(&dir, pairs), owed, "rn {pairs:?}");
    }
}
