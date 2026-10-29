//! `rar a` names a source outside the current directory as reference
//! `rar` 7.23 does. Before this, rarfast refused every absolute, `../` or
//! mid-path `..` source with `malformed archive: MemberName` (exit 2)
//! unless `-ep1` or `-ep` stripped it first, refused `-ep2` and `-ep3`
//! outright, walked a `dir/` mask's subdirectories without `-r`, and,
//! under `-ep`, silently dropped the second of two files that share a
//! base name.
//!
//! Every table below was MEASURED on 30 Sep 2026 by listing (`rar lb`)
//! the archive `rar` 7.23 wrote on macOS over the same tree. The rules:
//!
//! - a leading `/` is dropped, and so is everything up to and including
//!   the LAST `..` component, which is not otherwise resolved
//!   (`src/d/../full.mkv` stores `full.mkv`);
//! - `-ep2` and `-ep3` store the current directory joined to the path as
//!   typed, then strip the same way (`./full.mkv` stores
//!   `<cwd>/./full.mkv` less its leading `/`);
//! - `dir/`, `dir/.`, `dir/..`, `.` and `..` name a directory's contents,
//!   and without `-r` only the files directly inside;
//! - a file chosen twice under ONE spelling is stored once, but two
//!   spellings (`a/x ./a/x`) or two files that strip to one name (`-ep
//!   a/x b/x`) are ALL stored, exit 0, no warning: the archive then holds
//!   two members of one name, as `rar`'s does.
//!
//! The pinned tables stand alone; a live `rar` on the PATH is checked
//! against them too. The writer's refusal of an absolute or climbing
//! name and the reader's `would be written outside the destination` are
//! untouched: no cell below stores such a name.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn live_rar() -> Option<&'static Path> {
    let rar = Path::new("rar");
    Command::new(rar).arg("-?").output().ok().map(|_| rar)
}

/// A fresh directory, canonical, since `-ep2` joins the current directory
/// as the platform reports it and macOS's temporary directory is reached
/// through a symbolic link.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-srcpath-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

/// `src/{full.mkv, d/{x.txt, sub/y.txt}}`, an empty `cwd/` and `link`, a
/// symbolic link to `src/d`.
fn tree(tag: &str) -> PathBuf {
    let root = work(tag);
    std::fs::create_dir_all(root.join("src/d/sub")).unwrap();
    std::fs::create_dir_all(root.join("cwd")).unwrap();
    std::fs::write(root.join("src/full.mkv"), "a\n").unwrap();
    std::fs::write(root.join("src/d/x.txt"), "b\n").unwrap();
    std::fs::write(root.join("src/d/sub/y.txt"), "c\n").unwrap();
    std::os::unix::fs::symlink("src/d", root.join("link")).unwrap();
    root
}

/// Where a case runs and the source it names, `<W>` being the tree.
fn source(label: &str) -> (&'static str, &'static str) {
    match label {
        "abs-file" => ("cwd", "<W>/src/full.mkv"),
        "abs-dir" => ("cwd", "<W>/src/d"),
        "abs-dir-slash" => ("cwd", "<W>/src/d/"),
        "dotdot-file" => ("cwd", "../src/full.mkv"),
        "dotdot-dir" => ("cwd", "../src/d"),
        "mid-dotdot-file" => ("", "src/../src/full.mkv"),
        "dot-file" => ("src", "./full.mkv"),
        "dot-dir" => ("src", "./d"),
        "rel-file" => ("", "src/full.mkv"),
        "rel-dir" => ("", "src/d"),
        "rel-dir-slash" => ("", "src/d/"),
        "symlink-dir" => ("", "link"),
        "symlink-dir-slash" => ("", "link/"),
        "abs-symlink-dir" => ("cwd", "<W>/link"),
        other => panic!("no case {other}"),
    }
}

fn add(program: &Path, cwd: &Path, archive: &Path, switches: &[&str], masks: &[&str]) -> Output {
    Command::new(program)
        .current_dir(cwd)
        .args(["a", "-idq"])
        .args(switches)
        .arg(archive)
        .args(masks)
        .output()
        .unwrap()
}

/// The stored names, sorted: the walk ORDER is not what these tests pin.
fn names(archive: &Path) -> Vec<String> {
    let out = Command::new(rarfast())
        .arg("lb")
        .arg(archive)
        .output()
        .unwrap();
    let mut names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

/// (name, size) of every member, in archive order, from `lt`; a
/// directory, which `lt` gives no size, is recorded at size 0.
fn sized(archive: &Path) -> Vec<(String, u64)> {
    let out = Command::new(rarfast())
        .arg("lt")
        .arg(archive)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut members = Vec::new();
    let mut name = None;
    for line in text.lines().map(str::trim) {
        if let Some(n) = line.strip_prefix("Name: ") {
            name = Some(n.to_owned());
        } else if line == "Type: Directory" {
            members.push((name.take().unwrap(), 0));
        } else if let Some(size) = line.strip_prefix("Size: ") {
            members.push((name.take().unwrap(), size.parse().unwrap()));
        }
    }
    members
}

/// (case, switches, the names `rar` 7.23 stored). `<w>` is the tree's
/// path less its leading `/`.
const CELLS: &[(&str, &[&str], &[&str])] = &[
    ("abs-file", &[], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &[],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    ("abs-dir-slash", &[], &["<w>/src/d/x.txt"]),
    ("dotdot-file", &[], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &[],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &[], &["src/full.mkv"]),
    ("dot-file", &[], &["full.mkv"]),
    ("dot-dir", &[], &["d", "d/sub", "d/sub/y.txt", "d/x.txt"]),
    ("rel-file", &[], &["src/full.mkv"]),
    (
        "rel-dir",
        &[],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("rel-dir-slash", &[], &["src/d/x.txt"]),
    (
        "symlink-dir",
        &[],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    ("symlink-dir-slash", &[], &["link/x.txt"]),
    (
        "abs-symlink-dir",
        &[],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("abs-file", &["-r"], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &["-r"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    (
        "abs-dir-slash",
        &["-r"],
        &["<w>/src/d/sub", "<w>/src/d/sub/y.txt", "<w>/src/d/x.txt"],
    ),
    ("dotdot-file", &["-r"], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &["-r"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &["-r"], &["src/full.mkv"]),
    ("dot-file", &["-r"], &["full.mkv"]),
    (
        "dot-dir",
        &["-r"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("rel-file", &["-r"], &["src/full.mkv"]),
    (
        "rel-dir",
        &["-r"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    (
        "rel-dir-slash",
        &["-r"],
        &["src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    (
        "symlink-dir",
        &["-r"],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    (
        "symlink-dir-slash",
        &["-r"],
        &["link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    (
        "abs-symlink-dir",
        &["-r"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("abs-file", &["-ep"], &["full.mkv"]),
    ("abs-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("abs-dir-slash", &["-ep"], &["x.txt"]),
    ("dotdot-file", &["-ep"], &["full.mkv"]),
    ("dotdot-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("mid-dotdot-file", &["-ep"], &["full.mkv"]),
    ("dot-file", &["-ep"], &["full.mkv"]),
    ("dot-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("rel-file", &["-ep"], &["full.mkv"]),
    ("rel-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("rel-dir-slash", &["-ep"], &["x.txt"]),
    ("symlink-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("symlink-dir-slash", &["-ep"], &["x.txt"]),
    ("abs-symlink-dir", &["-ep"], &["x.txt", "y.txt"]),
    ("abs-file", &["-ep", "-r"], &["full.mkv"]),
    ("abs-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("abs-dir-slash", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("dotdot-file", &["-ep", "-r"], &["full.mkv"]),
    ("dotdot-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("mid-dotdot-file", &["-ep", "-r"], &["full.mkv"]),
    ("dot-file", &["-ep", "-r"], &["full.mkv"]),
    ("dot-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("rel-file", &["-ep", "-r"], &["full.mkv"]),
    ("rel-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("rel-dir-slash", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("symlink-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("symlink-dir-slash", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("abs-symlink-dir", &["-ep", "-r"], &["x.txt", "y.txt"]),
    ("abs-file", &["-ep1"], &["full.mkv"]),
    (
        "abs-dir",
        &["-ep1"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("abs-dir-slash", &["-ep1"], &["x.txt"]),
    ("dotdot-file", &["-ep1"], &["full.mkv"]),
    (
        "dotdot-dir",
        &["-ep1"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep1"], &["full.mkv"]),
    ("dot-file", &["-ep1"], &["full.mkv"]),
    (
        "dot-dir",
        &["-ep1"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("rel-file", &["-ep1"], &["full.mkv"]),
    (
        "rel-dir",
        &["-ep1"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("rel-dir-slash", &["-ep1"], &["x.txt"]),
    (
        "symlink-dir",
        &["-ep1"],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    ("symlink-dir-slash", &["-ep1"], &["x.txt"]),
    (
        "abs-symlink-dir",
        &["-ep1"],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    ("abs-file", &["-ep1", "-r"], &["full.mkv"]),
    (
        "abs-dir",
        &["-ep1", "-r"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    (
        "abs-dir-slash",
        &["-ep1", "-r"],
        &["sub", "sub/y.txt", "x.txt"],
    ),
    ("dotdot-file", &["-ep1", "-r"], &["full.mkv"]),
    (
        "dotdot-dir",
        &["-ep1", "-r"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep1", "-r"], &["full.mkv"]),
    ("dot-file", &["-ep1", "-r"], &["full.mkv"]),
    (
        "dot-dir",
        &["-ep1", "-r"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    ("rel-file", &["-ep1", "-r"], &["full.mkv"]),
    (
        "rel-dir",
        &["-ep1", "-r"],
        &["d", "d/sub", "d/sub/y.txt", "d/x.txt"],
    ),
    (
        "rel-dir-slash",
        &["-ep1", "-r"],
        &["sub", "sub/y.txt", "x.txt"],
    ),
    (
        "symlink-dir",
        &["-ep1", "-r"],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    (
        "symlink-dir-slash",
        &["-ep1", "-r"],
        &["sub", "sub/y.txt", "x.txt"],
    ),
    (
        "abs-symlink-dir",
        &["-ep1", "-r"],
        &["link", "link/sub", "link/sub/y.txt", "link/x.txt"],
    ),
    ("abs-file", &["-ep2"], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &["-ep2"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    ("abs-dir-slash", &["-ep2"], &["<w>/src/d/x.txt"]),
    ("dotdot-file", &["-ep2"], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &["-ep2"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep2"], &["src/full.mkv"]),
    ("dot-file", &["-ep2"], &["<w>/src/./full.mkv"]),
    (
        "dot-dir",
        &["-ep2"],
        &[
            "<w>/src/./d",
            "<w>/src/./d/sub",
            "<w>/src/./d/sub/y.txt",
            "<w>/src/./d/x.txt",
        ],
    ),
    ("rel-file", &["-ep2"], &["<w>/src/full.mkv"]),
    (
        "rel-dir",
        &["-ep2"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    ("rel-dir-slash", &["-ep2"], &["<w>/src/d/x.txt"]),
    (
        "symlink-dir",
        &["-ep2"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("symlink-dir-slash", &["-ep2"], &["<w>/link/x.txt"]),
    (
        "abs-symlink-dir",
        &["-ep2"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("abs-file", &["-ep2", "-r"], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &["-ep2", "-r"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    (
        "abs-dir-slash",
        &["-ep2", "-r"],
        &["<w>/src/d/sub", "<w>/src/d/sub/y.txt", "<w>/src/d/x.txt"],
    ),
    ("dotdot-file", &["-ep2", "-r"], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &["-ep2", "-r"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep2", "-r"], &["src/full.mkv"]),
    ("dot-file", &["-ep2", "-r"], &["<w>/src/./full.mkv"]),
    (
        "dot-dir",
        &["-ep2", "-r"],
        &[
            "<w>/src/./d",
            "<w>/src/./d/sub",
            "<w>/src/./d/sub/y.txt",
            "<w>/src/./d/x.txt",
        ],
    ),
    ("rel-file", &["-ep2", "-r"], &["<w>/src/full.mkv"]),
    (
        "rel-dir",
        &["-ep2", "-r"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    (
        "rel-dir-slash",
        &["-ep2", "-r"],
        &["<w>/src/d/sub", "<w>/src/d/sub/y.txt", "<w>/src/d/x.txt"],
    ),
    (
        "symlink-dir",
        &["-ep2", "-r"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    (
        "symlink-dir-slash",
        &["-ep2", "-r"],
        &["<w>/link/sub", "<w>/link/sub/y.txt", "<w>/link/x.txt"],
    ),
    (
        "abs-symlink-dir",
        &["-ep2", "-r"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("abs-file", &["-ep3"], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &["-ep3"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    ("abs-dir-slash", &["-ep3"], &["<w>/src/d/x.txt"]),
    ("dotdot-file", &["-ep3"], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &["-ep3"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep3"], &["src/full.mkv"]),
    ("dot-file", &["-ep3"], &["<w>/src/./full.mkv"]),
    (
        "dot-dir",
        &["-ep3"],
        &[
            "<w>/src/./d",
            "<w>/src/./d/sub",
            "<w>/src/./d/sub/y.txt",
            "<w>/src/./d/x.txt",
        ],
    ),
    ("rel-file", &["-ep3"], &["<w>/src/full.mkv"]),
    (
        "rel-dir",
        &["-ep3"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    ("rel-dir-slash", &["-ep3"], &["<w>/src/d/x.txt"]),
    (
        "symlink-dir",
        &["-ep3"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("symlink-dir-slash", &["-ep3"], &["<w>/link/x.txt"]),
    (
        "abs-symlink-dir",
        &["-ep3"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    ("abs-file", &["-ep3", "-r"], &["<w>/src/full.mkv"]),
    (
        "abs-dir",
        &["-ep3", "-r"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    (
        "abs-dir-slash",
        &["-ep3", "-r"],
        &["<w>/src/d/sub", "<w>/src/d/sub/y.txt", "<w>/src/d/x.txt"],
    ),
    ("dotdot-file", &["-ep3", "-r"], &["src/full.mkv"]),
    (
        "dotdot-dir",
        &["-ep3", "-r"],
        &["src/d", "src/d/sub", "src/d/sub/y.txt", "src/d/x.txt"],
    ),
    ("mid-dotdot-file", &["-ep3", "-r"], &["src/full.mkv"]),
    ("dot-file", &["-ep3", "-r"], &["<w>/src/./full.mkv"]),
    (
        "dot-dir",
        &["-ep3", "-r"],
        &[
            "<w>/src/./d",
            "<w>/src/./d/sub",
            "<w>/src/./d/sub/y.txt",
            "<w>/src/./d/x.txt",
        ],
    ),
    ("rel-file", &["-ep3", "-r"], &["<w>/src/full.mkv"]),
    (
        "rel-dir",
        &["-ep3", "-r"],
        &[
            "<w>/src/d",
            "<w>/src/d/sub",
            "<w>/src/d/sub/y.txt",
            "<w>/src/d/x.txt",
        ],
    ),
    (
        "rel-dir-slash",
        &["-ep3", "-r"],
        &["<w>/src/d/sub", "<w>/src/d/sub/y.txt", "<w>/src/d/x.txt"],
    ),
    (
        "symlink-dir",
        &["-ep3", "-r"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
    (
        "symlink-dir-slash",
        &["-ep3", "-r"],
        &["<w>/link/sub", "<w>/link/sub/y.txt", "<w>/link/x.txt"],
    ),
    (
        "abs-symlink-dir",
        &["-ep3", "-r"],
        &[
            "<w>/link",
            "<w>/link/sub",
            "<w>/link/sub/y.txt",
            "<w>/link/x.txt",
        ],
    ),
];

/// Runs one cell under `program`: its exit status, stderr and names, with
/// the tree's path put back as `<w>`.
fn cell(program: &Path, n: usize, tag: &str) -> (Option<i32>, String, Vec<String>) {
    let (label, switches, _) = CELLS[n];
    let root = tree(&format!("{tag}{n}"));
    let (dir, mask) = source(label);
    let mask = mask.replace("<W>", &root.to_string_lossy());
    let archive = root.join("out.rar");
    let out = add(program, &root.join(dir), &archive, switches, &[&mask]);
    let bare = root.to_string_lossy().trim_start_matches('/').to_owned();
    let got = names(&archive)
        .into_iter()
        .map(|name| name.replace(&bare, "<w>"))
        .collect();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&root);
    (out.status.code(), err, got)
}

#[test]
fn every_path_switch_names_a_source_as_reference_rar_did() {
    for (n, (label, switches, expected)) in CELLS.iter().enumerate() {
        let (code, err, got) = cell(&rarfast(), n, "cell");
        assert_eq!(code, Some(0), "a {switches:?} {label}: {err}");
        assert_eq!(err, "", "a {switches:?} {label}");
        assert_eq!(got, *expected, "a {switches:?} {label}");
        for name in &got {
            assert!(
                !name.starts_with('/') && !name.split('/').any(|part| part == ".."),
                "a {switches:?} {label} stored {name}, which no archive name may be"
            );
        }
    }
}

#[test]
fn every_cell_equals_a_live_rar_when_one_is_installed() {
    let Some(rar) = live_rar() else {
        eprintln!("no `rar` on the PATH: the pinned table stands alone");
        return;
    };
    for (n, (label, switches, _)) in CELLS.iter().enumerate() {
        let theirs = cell(rar, n, "live");
        let ours = cell(&rarfast(), n, "livef");
        assert_eq!(ours.0, theirs.0, "a {switches:?} {label}");
        assert_eq!(ours.2, theirs.2, "a {switches:?} {label}");
    }
}

/// The three bench drivers' forms, exactly: `rarfast a -ep1 out.rar
/// /abs/path/to/full.mkv`, the same over an absolute directory, and a
/// plain absolute source, each of which exited 2 with `malformed archive:
/// MemberName`.
#[test]
fn the_bench_drivers_absolute_forms_are_accepted() {
    let root = tree("drivers");
    let big = root.join("src/full.mkv");
    let dir = root.join("src/d");
    let bare = root.to_string_lossy().trim_start_matches('/').to_owned();
    for (switches, source, expected) in [
        (&["-ep1"][..], &big, vec!["full.mkv".to_owned()]),
        (
            &["-ep1"][..],
            &dir,
            vec!["d", "d/sub", "d/sub/y.txt", "d/x.txt"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        (&["-m0"][..], &big, vec![format!("{bare}/src/full.mkv")]),
        (&["-m0", "-ep"][..], &big, vec!["full.mkv".to_owned()]),
    ] {
        let archive = root.join("out.rar");
        let _ = std::fs::remove_file(&archive);
        let out = add(
            &rarfast(),
            &root.join("cwd"),
            &archive,
            switches,
            &[&source.to_string_lossy()],
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "a {switches:?} {}: {}",
            source.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            names(&archive),
            expected,
            "a {switches:?} {}",
            source.display()
        );
    }
}

/// (switches, masks, what `rar` 7.23 stored as (name, size), in archive
/// order save that the walk order of a directory is the platform's).
/// Run from a tree holding `a/same.txt` (5 bytes), `b/same.txt` (9),
/// `a/k/z.txt` (3) and `b/k/z.txt` (4).
#[allow(clippy::type_complexity)]
fn duplicate_cases() -> Vec<(
    &'static [&'static str],
    &'static [&'static str],
    Vec<(&'static str, u64)>,
)> {
    vec![
        (&[], &["a/same.txt", "a/same.txt"], vec![("a/same.txt", 5)]),
        (
            &[],
            &["a/same.txt", "./a/same.txt", "./a/same.txt"],
            vec![("a/same.txt", 5), ("a/same.txt", 5)],
        ),
        (
            &["-ep"],
            &["a/same.txt", "b/same.txt"],
            vec![("same.txt", 5), ("same.txt", 9)],
        ),
        (
            &["-ep1"],
            &["a/same.txt", "b/same.txt"],
            vec![("same.txt", 5), ("same.txt", 9)],
        ),
        (
            &["-ep"],
            &["a/same.txt", "a/k/../same.txt"],
            vec![("same.txt", 5), ("same.txt", 5)],
        ),
        (
            &["-ep"],
            &["a", "b"],
            vec![("same.txt", 5), ("z.txt", 3), ("same.txt", 9), ("z.txt", 4)],
        ),
        (
            &["-ep1"],
            &["a/", "b/"],
            vec![("same.txt", 5), ("same.txt", 9)],
        ),
        (
            &["-ep1", "-r"],
            &["a/", "b/"],
            vec![
                ("same.txt", 5),
                ("k/z.txt", 3),
                ("k", 0),
                ("same.txt", 9),
                ("k/z.txt", 4),
                ("k", 0),
            ],
        ),
    ]
}

fn duplicate_tree(tag: &str) -> PathBuf {
    let root = work(tag);
    for (dir, same, z) in [("a", "AAAA\n", "k1\n"), ("b", "BBBBBBBB\n", "k22\n")] {
        std::fs::create_dir_all(root.join(dir).join("k")).unwrap();
        std::fs::write(root.join(dir).join("same.txt"), same).unwrap();
        std::fs::write(root.join(dir).join("k/z.txt"), z).unwrap();
    }
    root
}

/// Under `-ep` two files of one base name are BOTH stored, exit 0, with
/// nothing said, exactly as `rar` 7.23 stores them; before this the
/// second was dropped without a word, which is how a `-m0 -ep` bench over
/// tree5k wrote 56 MB from 95 MB of input. A file named twice under ONE
/// spelling is still stored once.
#[test]
fn duplicate_names_are_all_stored_as_reference_rar_stores_them() {
    for (n, (switches, masks, expected)) in duplicate_cases().into_iter().enumerate() {
        let root = duplicate_tree(&format!("dup{n}"));
        let archive = root.join("out.rar");
        let out = add(&rarfast(), &root, &archive, switches, masks);
        assert_eq!(out.status.code(), Some(0), "a {switches:?} {masks:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "",
            "a {switches:?} {masks:?}"
        );
        let mut got = sized(&archive);
        let mut want: Vec<(String, u64)> = expected
            .iter()
            .map(|(name, size)| ((*name).to_owned(), *size))
            .collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "a {switches:?} {masks:?}");
        let test = Command::new(rarfast())
            .arg("t")
            .arg(&archive)
            .output()
            .unwrap();
        assert_eq!(
            test.status.code(),
            Some(0),
            "t after a {switches:?} {masks:?}"
        );
        if let Some(rar) = live_rar() {
            let theirs = root.join("rar.rar");
            add(rar, &root, &theirs, switches, masks);
            let mut reference = sized(&theirs);
            reference.sort();
            assert_eq!(got, reference, "live rar: a {switches:?} {masks:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Contents masks and climbs the matrix above does not reach, measured
/// the same night: run from `src`, `..`-ended masks from inside it, and
/// `-r0`, which recurses into a contents mask as `-r` does.
#[test]
fn contents_masks_and_climbs_match_reference_rar() {
    #[allow(clippy::type_complexity)]
    let cases: &[(&str, &[&str], &str, &[&str])] = &[
        ("src", &[], ".", &["full.mkv"]),
        ("src", &[], "./", &["full.mkv"]),
        ("src", &[], "d/.", &["d/./x.txt"]),
        ("src", &["-ep1"], "d/.", &["x.txt"]),
        ("src", &["-ep"], "d/", &["x.txt"]),
        ("src", &["-r0"], "d/", &["d/sub", "d/sub/y.txt", "d/x.txt"]),
        ("", &[], "src/./full.mkv", &["src/./full.mkv"]),
        ("", &[], "src//full.mkv", &["src//full.mkv"]),
        ("", &[], "src/d/../full.mkv", &["full.mkv"]),
        ("", &[], "src/d/sub/../../full.mkv", &["full.mkv"]),
        ("", &[], "src/d/..", &["full.mkv"]),
        (
            "",
            &["-r"],
            "src/d/..",
            &["d", "d/sub", "d/sub/y.txt", "d/x.txt", "full.mkv"],
        ),
        ("", &["-ep1"], "src/d/..", &["full.mkv"]),
        ("", &[], "src/d/sub/..", &["x.txt"]),
        ("", &[], "src/d/sub/../", &["x.txt"]),
        ("", &["-r"], "src/d/sub/..", &["sub", "sub/y.txt", "x.txt"]),
        ("cwd", &[], "..", &["top.txt"]),
        ("cwd", &[], "../", &["top.txt"]),
    ];
    for (n, (dir, switches, mask, expected)) in cases.iter().enumerate() {
        let root = tree(&format!("contents{n}"));
        std::fs::write(root.join("top.txt"), "t\n").unwrap();
        // Outside the tree, so that `..` does not pick up the archive.
        let archive = work(&format!("contents-out{n}")).join("out.rar");
        let out = add(&rarfast(), &root.join(dir), &archive, switches, &[mask]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "a {switches:?} {mask}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(names(&archive), *expected, "a {switches:?} {mask}");
        if let Some(rar) = live_rar() {
            let theirs = archive.with_file_name("rar.rar");
            add(rar, &root.join(dir), &theirs, switches, &[mask]);
            assert_eq!(names(&theirs), *expected, "live rar: a {switches:?} {mask}");
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(archive.parent().unwrap());
    }
}
