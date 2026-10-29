//! Rows measured against rar 7.23, run against rarfast.
//!
//! A table under `tests/create-selection/` holds one run a line, as the
//! reference answered it on 8 Oct 2026 (an Apple silicon Mac):
//!
//! ```text
//! <command and arguments> => <exit> | <members, sorted> | <paths left on disk, sorted>
//! ```
//!
//! Every run is made in a fresh copy of ONE tree, [`TREE`], with the
//! archive beside it (`../o.rar`), as `rar <command> -idq -mt2 -m0
//! ../o.rar <arguments>`. The order of the members is not compared: the
//! reference stores in the order the file system hands names back, and
//! rarfast in sorted order. An archive that was not written reads as no
//! members.
//!
//! A pool two threads wide and a few KiB of memory a run.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The tree every row runs over: a name at two depths and at the top
/// (`a.txt`), a directory whose name looks like a file's (`dd.txt`), a
/// file and a directory that share a first letter (`dx`, `d`), and three
/// levels of nesting.
const TREE: [(&str, &[u8]); 9] = [
    ("a.txt", b"top\n"),
    ("s/a.txt", b"aaa\n"),
    ("s/b.txt", b"bbb\n"),
    ("s/dx", b"q\n"),
    ("s/d/a.txt", b"dd\n"),
    ("s/d/c.txt", b"ccc\n"),
    ("s/d/e/f.dat", &[7_u8; 3000]),
    ("s/d/e/e/z.txt", b"z\n"),
    ("s/dd.txt/k.bin", b"k\n"),
];

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A fresh scratch directory holding the tree under `w`.
fn build(tag: &str, row: usize) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "rarfast-selection-{tag}-{}-{row}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    for (name, bytes) in TREE {
        let path = root.join("w").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    root
}

/// Every path below `dir`, relative to it, sorted.
fn paths_below(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &format!("{name}/"), out);
            }
            out.push(name);
        }
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out);
    out.sort();
    out
}

/// What one run left: its exit code, the archive's members and the tree.
fn outcome(root: &Path, arguments: &str) -> String {
    let mut words = arguments.split_whitespace();
    let command = words.next().unwrap();
    let run = Command::new(rarfast())
        .args([command, "-idq", "-mt2", "-m0", "../o.rar"])
        .args(words)
        .current_dir(root.join("w"))
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"));
    let mut members: Vec<String> = Vec::new();
    if root.join("o.rar").exists() {
        let listed = Command::new(rarfast())
            .args(["lb", "o.rar"])
            .current_dir(root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        members = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        members.sort();
    }
    format!(
        "{} | {} | {}",
        run.status.code().unwrap_or(-1),
        members.join(" "),
        paths_below(&root.join("w")).join(" ")
    )
}

/// Runs every row of `table` and fails with all the rows that differ
/// from the reference's answer, each beside what rarfast gave.
pub(crate) fn agree_with_the_reference(tag: &str, table: &str) {
    let mut wrong = Vec::new();
    let mut rows = 0;
    for (at, line) in table.lines().enumerate() {
        let Some((arguments, expected)) = line.split_once(" => ") else {
            continue;
        };
        rows += 1;
        let root = build(tag, at);
        let got = outcome(&root, arguments);
        if got != expected {
            wrong.push(format!(
                "rar {arguments}\n  rar 7.23: {expected}\n  rarfast:  {got}"
            ));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
    assert!(rows > 0, "the table holds no rows");
    assert!(
        wrong.is_empty(),
        "{} of {rows} rows differ from rar 7.23:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
