//! A list file that cannot be read stops a create; it is not an empty
//! list.
//!
//! Until 4 Oct 2026 `-n@<list>`, `-x@<list>` and an `@<list>` argument
//! whose file could not be read were taken as lists with nothing in
//! them. A missing include list then meant "include everything" and a
//! missing exclude list "exclude nothing": `rarfast m -n@keeplist
//! arc.rar *` with a mistyped `keeplist` archived and deleted every
//! file and exited 0.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac),
//! none of the three list files being there:
//!
//! | run                                  | stderr                 | stdout            | exit |
//! |--------------------------------------|------------------------|-------------------|------|
//! | `rar a -n@keeplist arc.rar a.txt b.txt` | `Cannot open keeplist`, `No such file or directory` | `Program aborted` | 6 |
//! | `rar m -n@keeplist arc.rar a.txt b.txt` | the same            | the same          | 6    |
//! | `rar a -x@skiplist arc.rar a.txt b.txt` | `Cannot open skiplist`, ... | the same  | 6    |
//! | `rar a arc.rar @nameslist`           | `Cannot open nameslist`, ... | the same    | 6    |
//! | `rar a arc.rar a.txt @nameslist`     | the same               | the same          | 6    |
//!
//! No archive is written and no source is touched in any of them. (The
//! measured lists were named with a `.lst` ending; the names here have
//! none, and the reference's answer does not turn on the name.)
//!
//! **On Windows the reason is the system's own.** Measured against
//! Rar.exe 7.23 x64 on 4 Oct 2026 (a Ryzen 7 9800X3D PC, Windows 11), the
//! same five runs: the same `Cannot open <list>`, `Program aborted` and
//! exit 6, nothing written, and the line under the complaint reads `The
//! system cannot find the file specified.` rarfast prints the same
//! there (the two were run side by side that day), so what differs by
//! system below is the expectation and not the product.
//!
//! Every run here is `-mt2` over two files of a few bytes: a pool two
//! threads wide and a few MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with `a.txt` and `b.txt` written into it.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-list-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), b"one\n").unwrap();
    std::fs::write(dir.join("b.txt"), b"two\n").unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

/// What the system says of a file that is not there, as the reference
/// prints it under `Cannot open`.
const NOT_THERE: &str = if cfg!(windows) {
    "The system cannot find the file specified."
} else {
    "No such file or directory"
};

/// One row of the table: the reference's words and code, no archive,
/// both sources where they were.
fn is_stopped(tag: &str, args: &[&str], list: &str) {
    let dir = work(tag);
    let out = run(&dir, args);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(6),
        "{args:?}; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("Cannot open {list}\n{NOT_THERE}")),
        "{args:?}; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Program aborted"),
        "{args:?}; stdout: {stdout}"
    );
    assert!(!stdout.contains("Adding"), "{args:?}; stdout: {stdout}");
    assert!(!dir.join("arc.rar").exists(), "{args:?} wrote an archive");
    assert!(dir.join("a.txt").is_file(), "{args:?} took a.txt");
    assert!(dir.join("b.txt").is_file(), "{args:?} took b.txt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The scenario the sweep named.
#[test]
fn a_move_with_a_missing_include_list_moves_nothing() {
    is_stopped(
        "m-n",
        &["m", "-mt2", "-n@keeplist", "arc.rar", "a.txt", "b.txt"],
        "keeplist",
    );
}

#[test]
fn an_add_with_a_missing_include_list_is_stopped() {
    is_stopped(
        "a-n",
        &["a", "-mt2", "-n@keeplist", "arc.rar", "a.txt", "b.txt"],
        "keeplist",
    );
}

#[test]
fn a_missing_exclude_list_is_stopped() {
    is_stopped(
        "a-x",
        &["a", "-mt2", "-x@skiplist", "arc.rar", "a.txt", "b.txt"],
        "skiplist",
    );
    is_stopped(
        "m-x",
        &["m", "-mt2", "-x@skiplist", "arc.rar", "a.txt", "b.txt"],
        "skiplist",
    );
}

#[test]
fn a_missing_list_of_names_is_stopped() {
    is_stopped("a-at", &["a", "-mt2", "arc.rar", "@nameslist"], "nameslist");
    is_stopped(
        "a-at-beside",
        &["a", "-mt2", "arc.rar", "a.txt", "@nameslist"],
        "nameslist",
    );
}

/// The control: a list that is there is still read, in all three places.
#[test]
fn a_list_that_is_there_is_still_read() {
    let members = |dir: &Path| {
        let mut names: Vec<String> = text(&run(dir, &["lb", "arc.rar"]).stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        names.sort();
        names
    };

    let dir = work("ok-n");
    std::fs::write(dir.join("keeplist"), "a.txt\n").unwrap();
    let out = run(
        &dir,
        &["a", "-mt2", "-n@keeplist", "arc.rar", "a.txt", "b.txt"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(members(&dir), ["a.txt"]);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = work("ok-x");
    std::fs::write(dir.join("skiplist"), "a.txt\n").unwrap();
    let out = run(
        &dir,
        &["a", "-mt2", "-x@skiplist", "arc.rar", "a.txt", "b.txt"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(members(&dir), ["b.txt"]);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = work("ok-at");
    std::fs::write(dir.join("nameslist"), "b.txt\n").unwrap();
    let out = run(&dir, &["a", "-mt2", "arc.rar", "@nameslist"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(members(&dir), ["b.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}
