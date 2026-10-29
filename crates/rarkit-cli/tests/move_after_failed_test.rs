//! A move keeps its sources when the archive it wrote did not pass.
//!
//! `m`, `mf`, `-df` and `-dw` delete the sources once the archive is
//! written. Until 4 Oct 2026 they deleted them whatever `-t` and `-k`
//! had just answered: the follow-up's code was folded into the exit and
//! the deletion ran regardless, so `rarfast m -t arc.rar data` unlinked
//! `data` after the test of `arc.rar` had FAILED. The only reason to
//! give `-t` beside a move is to make the deletion wait on the test.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac; a
//! second process overwrote 16 bytes of the stored data area while the
//! reference was still adding, so its own `-t` met a checksum error):
//! `rar m -m0 -t`, `rar a -m0 -df -t` and `rar a -m0 -dw -t` each exit
//! 3, keep every source, print NO `Deleting` line and NO `Done`, and say
//! nothing about the deletion they skipped: stdout ends at
//! `Total errors: 1`. `rar a -m0 -t` with no deletion asked for ends the
//! same way, with no `Done`. With `-k` the reference locks BEFORE it
//! tests (`Locking archive` precedes `Testing archive`).
//!
//! A FAILED `-k` could not be produced in the reference, which locks in
//! place through the handle it already holds. rarfast locks by a rewrite
//! that can fail, and there the sources are kept too: the archive is not
//! the one the command line asked for, and keeping a file loses nothing.
//!
//! The failure is forced without privileges and without a race: the
//! archive is written into a folder, `shut`, where a file the run
//! creates cannot be opened again, so the run writes it through the
//! handle it holds and the `-t` or `-k` that follows cannot open it.
//!
//! - On unix the run is given a create mask of 777. Run as root the mask
//!   stops nothing, and the rows that need it return early.
//! - On Windows `shut` is given, with `icacls`, an entry its files
//!   inherit that denies everyone the reading of their data. It is set
//!   on a folder this file made and goes with it.
//!
//! **Measured on Windows too**, 4 Oct 2026, Rar.exe 7.23 x64 on a Ryzen
//! 7 9800X3D PC under Windows 11, over that same folder: `rar m -t
//! shut\arc.rar data` and `rar a -df -t shut\arc.rar data` write the
//! archive, answer `Cannot open shut\arc.rar` and `Access is denied.`,
//! exit 6, keep every source and print no `Deleting` and no `Done`. `rar
//! m -k shut\arc.rar data` locks in place and deletes, exit 0, which is
//! the lock rarfast cannot make there and so keeps the sources for. The
//! same day, on that PC, rarfast before this file's fix deleted `data`
//! in every one of these rows and rarfast with it kept `data` in each.
//!
//! `mf` has no row: under the name `rarfast` that command word is not
//! routed to the creator today (it answers with the usage text, exit 7),
//! which is reported as owed and is not this file's ground. It shares
//! the code path of `m`.
//!
//! Every run here is `-mt2` over two files of a few bytes: a pool two
//! threads wide and a few MiB of memory.

#![cfg(any(unix, windows))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with `data/a.txt`, `data/b.txt` and an empty directory `shut`.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-move-kept-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::create_dir_all(dir.join("shut")).unwrap();
    std::fs::write(dir.join("data/a.txt"), b"first\n").unwrap();
    std::fs::write(dir.join("data/b.txt"), b"second\n").unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

/// The archive the masked rows write: `arc.rar` inside `shut`, spelled
/// with the system's separator.
fn shut_archive() -> String {
    format!("shut{}arc.rar", std::path::MAIN_SEPARATOR)
}

/// The same run, with the archive it writes into `shut` impossible to
/// open again: under a create mask of 777.
#[cfg(unix)]
fn run_masked(dir: &Path, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg("umask 777; exec \"$0\" \"$@\"")
        .arg(rarfast())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("sh could not be run: {err}"))
}

/// The same run, with the archive it writes into `shut` impossible to
/// open again: `shut` first gets an entry, inherited by its files only,
/// that denies everyone (`S-1-1-0`) the reading of their data.
#[cfg(windows)]
fn run_masked(dir: &Path, args: &[&str]) -> Output {
    let denied = Command::new("icacls")
        .arg(dir.join("shut"))
        .args(["/deny", "*S-1-1-0:(OI)(IO)(RD)"])
        .output()
        .unwrap_or_else(|err| panic!("icacls could not be run: {err}"));
    assert!(
        denied.status.success(),
        "icacls: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    run(dir, args)
}

/// `args` with the archive they name moved into `shut`.
fn into_shut<'a>(args: &[&'a str], shut: &'a str) -> Vec<&'a str> {
    args.iter()
        .map(|arg| if *arg == "arc.rar" { shut } else { *arg })
        .collect()
}

/// Whether the mask did its work: the archive is there and this user
/// cannot open it. False under root on unix, where the row proves
/// nothing.
fn archive_is_shut(dir: &Path) -> bool {
    let archive = dir.join("shut").join("arc.rar");
    archive.exists() && std::fs::File::open(&archive).is_err()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One row: the follow-up fails, so both sources stay with their bytes,
/// the exit is not 0, and nothing is said about deleting.
fn sources_are_kept(tag: &str, args: &[&str]) {
    let dir = work(tag);
    let out = run_masked(&dir, &into_shut(args, &shut_archive()));
    if !archive_is_shut(&dir) {
        eprintln!("skipped {tag}: the create mask did not shut the archive (root?)");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failed follow-up exited 0; stdout: {stdout}"
    );
    assert_eq!(
        std::fs::read(dir.join("data/a.txt")).ok().as_deref(),
        Some(&b"first\n"[..]),
        "data/a.txt went, or was wiped, after a failed follow-up; \
         stdout: {stdout} stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read(dir.join("data/b.txt")).ok().as_deref(),
        Some(&b"second\n"[..]),
        "data/b.txt went, or was wiped, after a failed follow-up; \
         stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Deleting"),
        "a deletion was reported after a failed follow-up: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m_keeps_the_sources_when_the_test_fails() {
    sources_are_kept("m-t", &["m", "-mt2", "-t", "arc.rar", "data"]);
}

#[test]
fn df_keeps_the_sources_when_the_test_fails() {
    sources_are_kept("df-t", &["a", "-mt2", "-df", "-t", "arc.rar", "data"]);
}

/// `-dw` must not even overwrite them.
#[test]
fn dw_keeps_the_sources_when_the_test_fails() {
    sources_are_kept("dw-t", &["a", "-mt2", "-dw", "-t", "arc.rar", "data"]);
}

/// Unmeasurable in the reference (see the module text); kept all the
/// same.
#[test]
fn m_keeps_the_sources_when_the_lock_fails() {
    sources_are_kept("m-k", &["m", "-mt2", "-k", "arc.rar", "data"]);
}

#[test]
fn m_keeps_the_sources_when_the_lock_and_the_test_fail() {
    sources_are_kept("m-k-t", &["m", "-mt2", "-k", "-t", "arc.rar", "data"]);
}

/// Measured: a failed test is the last thing the reference says. No
/// `Done` follows it, with a deletion asked for or without.
#[test]
fn a_failed_test_is_not_followed_by_done() {
    for (tag, args) in [
        ("done-m", &["m", "-mt2", "-t", "arc.rar", "data"][..]),
        ("done-a", &["a", "-mt2", "-t", "arc.rar", "data"][..]),
    ] {
        let dir = work(tag);
        let out = run_masked(&dir, &into_shut(args, &shut_archive()));
        if !archive_is_shut(&dir) {
            eprintln!("skipped {tag}: the create mask did not shut the archive (root?)");
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        let stdout = text(&out.stdout);
        assert!(
            !stdout.contains("Done"),
            "{tag}: `Done` after a failed test: {stdout}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The control: a lock and a test that pass still let the move delete,
/// and the deletion and `Done` come after the test's verdict.
#[test]
fn m_still_deletes_when_the_lock_and_the_test_pass() {
    let dir = work("pass");
    let out = run(&dir, &["m", "-mt2", "-k", "-t", "arc.rar", "data"]);
    let stdout = text(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout} stderr: {}",
        text(&out.stderr)
    );
    assert!(!dir.join("data").exists(), "the sources stayed: {stdout}");
    assert!(dir.join("arc.rar").is_file());
    let listed = text(&run(&dir, &["lt", "arc.rar"]).stdout);
    assert!(
        listed.contains("lock"),
        "the archive is not locked: {listed}"
    );
    let at = |needle: &str| {
        stdout
            .find(needle)
            .unwrap_or_else(|| panic!("no `{needle}` in: {stdout}"))
    };
    assert!(at("All OK") < at("Deleting"), "{stdout}");
    assert!(at("Deleting") < at("Done"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
