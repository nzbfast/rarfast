//! A mask's `*` is a wildcard whatever the NAME holds at that point.
//!
//! MEASURED against unrar 7.23 on macOS (an arm64 Mac), 4 Oct 2026, over
//! an archive rar 7.23 made of files named `plain.tmp`, `*ab`, `zab`,
//! `a*.txt`, `*x.tmp` and `**x**`: `lb arc '*b'` lists `*ab` and `zab`,
//! `lb arc '*'` lists all six, `lb arc '*.tmp'` lists `plain.tmp` and
//! `*x.tmp`, `lb arc '?ab'` lists `*ab` and `zab`, `lb arc 'a*'` lists
//! `a*.txt`, and `lb arc '-x*.tmp'` drops both `.tmp` names.
//!
//! The matcher tried character equality before the star, so a `*` in the
//! mask was spent as a literal wherever the name had one too: `*b` missed
//! `*ab`, and `-x*.tmp` left `*x.tmp` selected, to be extracted.
//!
//! Unix only: a `*` cannot be in a file name on Windows, and the
//! reference was measured on Unix. Each run states `-mt1`; the archive is
//! six one-byte members, so no memory to speak of.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use rarkit::{MemberSpec, Payload, WriteOptions, Writer};

const NAMES: [&str; 6] = ["plain.tmp", "*ab", "zab", "a*.txt", "*x.tmp", "**x**"];

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn archive(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-maskstar-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    for name in NAMES {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(b"x"),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    let path = dir.join("a.rar");
    std::fs::write(&path, out).unwrap();
    path
}

fn listed(archive: &Path, rest: &[&str]) -> Vec<String> {
    let done = Command::new(rarfast())
        .args(["lb", "-mt1"])
        .arg(archive)
        .args(rest)
        .output()
        .unwrap();
    String::from_utf8_lossy(&done.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_mask_star_matches_a_name_that_holds_a_star() {
    let archive = archive("list");
    for (rest, expected) in [
        (&["*b"][..], &["*ab", "zab"][..]),
        (&["*"], &NAMES[..]),
        (&["*.tmp"], &["plain.tmp", "*x.tmp"]),
        (&["?ab"], &["*ab", "zab"]),
        (&["*.txt"], &["a*.txt"]),
        (&["*x*"], &["a*.txt", "*x.tmp", "**x**"]),
        (&["a*"], &["a*.txt"]),
        (&["-x*.tmp"], &["*ab", "zab", "a*.txt", "**x**"]),
        (&["-n*b"], &["*ab", "zab"]),
    ] {
        assert_eq!(listed(&archive, rest), expected, "{rest:?}");
    }
    let _ = std::fs::remove_dir_all(archive.parent().unwrap());
}

/// `x -x'*.tmp'` must not write the excluded `*x.tmp`.
#[test]
fn an_excluded_name_that_holds_a_star_is_not_extracted() {
    let archive = archive("extract");
    let out = archive.parent().unwrap().join("o");
    std::fs::create_dir_all(&out).unwrap();
    let done = Command::new(rarfast())
        .args(["x", "-mt1", "-idq", "-x*.tmp"])
        .arg(&archive)
        .arg(format!("{}/", out.display()))
        .output()
        .unwrap();
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    let mut found: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, ["**x**", "*ab", "a*.txt", "zab"]);
    let _ = std::fs::remove_dir_all(archive.parent().unwrap());
}
