//! `a -r arc.rar .` names members the way reference `rar` 7.23 does: no
//! member for the root, every other name relative to it. Before this,
//! rarfast stored a member called `.`, and its own `x` then refused the
//! archive (the line that now reads `would be written outside the
//! destination`); a trailing `/` on the mask was taken for an extraction
//! destination and added nothing.
//!
//! Every name list below was MEASURED, 28 Sep 2026, by listing (`rar lb`)
//! the archive `rar` 7.23 wrote over the same tree, and is checked
//! against a live `rar` too when one is on the PATH:
//!
//! - `.`, `./` and `.//` are the tree's contents, `./` prefix dropped;
//! - `dir/` and `dir/.` are the contents of `dir`, no entry for `dir`
//!   itself, and the mask's spelling stays in the names (`dir/./b.txt`
//!   for `dir/.`, never for `dir/`);
//! - `-ep1` strips the mask's directory part: nothing for `.`, all of
//!   `sub/` for `sub/` and `sub/.`, `sub/` alone for `sub/deep`.
//!
//! The reader's refusal of an unsafe path is unchanged and held here by
//! a `rar`-written archive whose one member is `../a.txt`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-dotmember-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `src/{a.txt, empty/, sub/{b.txt, deep/c.txt}}` under a fresh directory.
fn tree(tag: &str) -> PathBuf {
    let root = work(tag);
    let src = root.join("src");
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::create_dir_all(src.join("sub/deep")).unwrap();
    std::fs::write(src.join("a.txt"), "a\n").unwrap();
    std::fs::write(src.join("sub/b.txt"), "b\n").unwrap();
    std::fs::write(src.join("sub/deep/c.txt"), "c\n").unwrap();
    root
}

/// A stored name as a listing shows it: with the system's separator,
/// which is what the reference's builds print on each system.
fn listed(name: &str) -> String {
    name.replace('/', std::path::MAIN_SEPARATOR_STR)
}

fn names(program: &Path, archive: &Path) -> Vec<String> {
    let out = Command::new(program)
        .arg("lb")
        .arg(archive)
        .output()
        .unwrap();
    let mut names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|l| !l.is_empty())
        .collect();
    names.sort();
    names
}

fn add(program: &Path, cwd: &Path, archive: &Path, switches: &[&str], mask: &str) -> Output {
    Command::new(program)
        .current_dir(cwd)
        .arg("a")
        .args(switches)
        .arg(archive)
        .arg(mask)
        .output()
        .unwrap()
}

const ALL: &[&str] = &[
    "a.txt",
    "empty",
    "sub",
    "sub/b.txt",
    "sub/deep",
    "sub/deep/c.txt",
];

/// (switches, mask, the names `rar` 7.23 stores).
fn cases() -> Vec<(&'static [&'static str], &'static str, Vec<&'static str>)> {
    vec![
        (&["-r"], ".", ALL.to_vec()),
        (&["-r"], "./", ALL.to_vec()),
        (&["-r"], ".//", ALL.to_vec()),
        (&["-r", "-ep1"], ".", ALL.to_vec()),
        (&["-r", "-ep1"], "./", ALL.to_vec()),
        (&["-r", "-ep"], ".", vec!["a.txt", "b.txt", "c.txt"]),
        (
            &["-r"],
            "sub",
            vec!["sub", "sub/b.txt", "sub/deep", "sub/deep/c.txt"],
        ),
        (
            &["-r"],
            "sub/",
            vec!["sub/b.txt", "sub/deep", "sub/deep/c.txt"],
        ),
        (&["-r", "-ep1"], "sub/", vec!["b.txt", "deep", "deep/c.txt"]),
        (&["-r", "-ep"], "sub/", vec!["b.txt", "c.txt"]),
        (
            &["-r"],
            "sub/.",
            vec!["sub/./b.txt", "sub/./deep", "sub/./deep/c.txt"],
        ),
        (
            &["-r", "-ep1"],
            "sub/.",
            vec!["b.txt", "deep", "deep/c.txt"],
        ),
        (
            &["-r", "-ep1"],
            "sub",
            vec!["sub", "sub/b.txt", "sub/deep", "sub/deep/c.txt"],
        ),
        (&["-r", "-ep1"], "sub/deep", vec!["deep", "deep/c.txt"]),
        (
            &["-r", "-ep1"],
            "sub/*",
            vec!["b.txt", "deep", "deep/c.txt"],
        ),
        (&["-r", "-ep1"], "sub/b.txt", vec!["b.txt"]),
    ]
}

#[test]
fn names_are_the_ones_reference_rar_stored() {
    for (n, (switches, mask, expected)) in cases().into_iter().enumerate() {
        let root = tree(&format!("names{n}"));
        let archive = root.join("f.rar");
        let out = add(&rarfast(), &root.join("src"), &archive, switches, mask);
        assert!(
            out.status.success(),
            "a {switches:?} {mask}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let mut expected: Vec<String> = expected.into_iter().map(listed).collect();
        expected.sort();
        assert_eq!(
            names(&rarfast(), &archive),
            expected,
            "a {switches:?} {mask}"
        );
    }
}

#[test]
fn names_equal_a_live_rar_when_one_is_installed() {
    let rar = Path::new("rar");
    if Command::new(rar).arg("-?").output().is_err() {
        eprintln!("no `rar` on the PATH: the pinned lists above stand alone");
        return;
    }
    for (n, (switches, mask, _)) in cases().into_iter().enumerate() {
        let root = tree(&format!("live{n}"));
        let (theirs, ours) = (root.join("r.rar"), root.join("f.rar"));
        add(rar, &root.join("src"), &theirs, switches, mask);
        add(&rarfast(), &root.join("src"), &ours, switches, mask);
        assert_eq!(
            names(&rarfast(), &ours),
            names(rar, &theirs),
            "a {switches:?} {mask}"
        );
    }
}

#[test]
fn a_dot_add_extracts_with_exit_zero_and_restores_the_tree() {
    for mask in [".", "./", "sub/."] {
        let root = tree("roundtrip");
        let archive = root.join("f.rar");
        assert!(add(&rarfast(), &root.join("src"), &archive, &["-r"], mask)
            .status
            .success());
        let dest = root.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let out = Command::new(rarfast())
            .current_dir(&dest)
            .args(["x", "-y"])
            .arg(&archive)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "x of a -r {mask}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let base = if mask == "sub/." {
            dest.join("sub")
        } else {
            dest.clone()
        };
        let file = if mask == "sub/." {
            "b.txt"
        } else {
            "sub/b.txt"
        };
        assert_eq!(std::fs::read_to_string(base.join(file)).unwrap(), "b\n");
    }
}

#[test]
fn the_reader_still_refuses_a_genuinely_unsafe_name() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dotmember/dotdot.rar");
    let root = work("unsafe");
    let dest = root.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    let out = Command::new(rarfast())
        .current_dir(&dest)
        .args(["x", "-y"])
        .arg(&fixture)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains(&listed("../a.txt")), "{text}");
    assert!(
        text.contains("- would be written outside the destination"),
        "{text}"
    );
    assert!(!root.join("a.txt").exists());
}
