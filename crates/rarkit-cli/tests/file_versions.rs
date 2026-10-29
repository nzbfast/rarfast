//! Spec F 3.2.6.4: the older versions of files an archive keeps (`rar a
//! -ver`) are listed as `name;n`, are passed over by `t`, `x` and `p`
//! without a line and without an error, and are processed under `-ver`
//! with that name.
//!
//! The expectations are reference unrar 7.23's own lines for the genuine
//! `specs/vectors-F/evidence-06oct/rar5-genuine/ver.rar` (three headers
//! named `v.txt`, the first two carrying versions 1 and 2), read on macOS
//! aarch64 on 6 Oct 2026. Before this, rarfast listed three `v.txt`,
//! tested all three, and extracted them to ONE name: with no terminal to
//! answer its question it left the oldest version there and exited 0.
//!
//! Each run is one process on one small archive; nothing here depends on
//! the pool's width or on memory.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn archive() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/evidence-06oct/rar5-genuine/ver.rar"
    ))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-versions-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The exit code and both streams of `rarfast <args> <the archive>`.
fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .arg(archive())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), text)
}

/// The names on the lines that begin with `verb`, in order.
fn named(text: &str, verb: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix(verb))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_listing_shows_each_version_under_its_number() {
    let dir = work("list");
    let (code, text) = run(&dir, &["l"]);
    assert_eq!(code, Some(0), "{text}");
    let rows: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("v.txt"))
        .map(|line| line.rsplit(' ').next().unwrap_or(""))
        .collect();
    assert_eq!(rows, ["v.txt;1", "v.txt;2", "v.txt"], "{text}");

    let (code, text) = run(&dir, &["lt"]);
    assert_eq!(code, Some(0), "{text}");
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Name:") || line.starts_with("File version:"))
        .collect();
    assert_eq!(
        lines,
        [
            "Name: v.txt;1",
            "File version: 1",
            "Name: v.txt;2",
            "File version: 2",
            "Name: v.txt",
        ],
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_test_passes_over_the_versions_and_ver_names_them() {
    let dir = work("test");
    let (code, text) = run(&dir, &["t"]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(named(&text, "Testing     "), ["v.txt"], "{text}");
    assert!(text.contains("All OK"), "{text}");

    let (code, text) = run(&dir, &["t", "-ver"]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        named(&text, "Testing     "),
        ["v.txt;1", "v.txt;2", "v.txt"],
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_extraction_writes_the_current_file_and_nothing_over_it() {
    let dir = work("extract");
    let (code, text) = run(&dir, &["x"]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(named(&text, "Extracting  "), ["v.txt"], "{text}");
    assert_eq!(files(&dir), ["v.txt"]);
    assert_eq!(
        std::fs::read_to_string(dir.join("v.txt")).unwrap(),
        "version 3 of the file\n"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = work("extract-ver");
    let (code, text) = run(&dir, &["x", "-ver"]);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        named(&text, "Extracting  "),
        ["v.txt;1", "v.txt;2", "v.txt"],
        "{text}"
    );
    assert_eq!(files(&dir), ["v.txt", "v.txt;1", "v.txt;2"]);
    for (name, number) in [("v.txt;1", 1), ("v.txt;2", 2), ("v.txt", 3)] {
        assert_eq!(
            std::fs::read_to_string(dir.join(name)).unwrap(),
            format!("version {number} of the file\n"),
            "{name}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
