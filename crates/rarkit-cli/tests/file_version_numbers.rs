//! `-ver<n>` and a `name;n` argument select ONE numbered version of a
//! file, as reference unrar 7.23 does.
//!
//! Sweep 2 item 34, 8 Oct 2026. Plain `-ver` was honoured; the numbered
//! forms were read and nothing was done, so `x -ver1` wrote the CURRENT
//! version, `x -ver9` (no such version) wrote it too, both exit 0, and
//! `x arc name;1` found nothing.
//!
//! The reference, measured on macOS arm64 the same day over the genuine
//! `specs/vectors-F/evidence-06oct/rar5-genuine/ver.rar` that
//! `tests/file_versions.rs` reads too (three headers named `v.txt`, the
//! first two carrying versions 1 and 2):
//!
//! * `-ver<n>`, n of 1 and up: only the files whose version is n, written
//!   and named WITHOUT the `;n`; a file with no version number is passed
//!   over, a directory is not; a mask is compared with the name that still
//!   has its `;n`. The number is read as C reads one: `-ver01` and
//!   `-ver1x` are 1, and `-ver0` and `-verx` are plain `-ver`.
//! * an argument that is exactly `name;n` selects that version with or
//!   without `-ver`, whatever number `-ver<n>` gave, and it keeps its
//!   `;n` on disk.
//! * a listing shows every version whatever `-ver<n>` says.
//!
//! Measured as well and NOT pinned here, for want of an archive this tree
//! can make (its writer writes no version record): under `-ver<n>` a
//! directory is still created, a file with no version number beside the
//! versions is passed over, and a directory argument takes the versions
//! beneath it. The code holds all three; a test of them is owed.
//!
//! Each run is one process on one small archive; nothing here depends on
//! the pool's width or on memory (every run states `-mt1`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

fn archive() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/evidence-06oct/rar5-genuine/ver.rar"
    ))
}

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-s34-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The name picks the dialect.
        let exe = std::env::consts::EXE_SUFFIX;
        let unrar = dir.join(format!("unrar{exe}"));
        let own = dir.join(format!("rarfast{exe}"));
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        Bench { dir, unrar, own }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// `<exe> <command> -mt1 <args>` in a fresh directory: the exit code,
    /// both streams, and what was left there as `path=contents` (a
    /// directory as `path/`), sorted.
    fn run(&self, exe: &Path, command: &str, args: &[&str]) -> (Option<i32>, String, Vec<String>) {
        let room = self.dir.join("room");
        let _ = std::fs::remove_dir_all(&room);
        std::fs::create_dir_all(&room).unwrap();
        let set = archive();
        let mut line: Vec<&std::ffi::OsStr> = vec![command.as_ref(), "-mt1".as_ref()];
        for arg in args {
            line.push(match *arg {
                "set.rar" => set.as_os_str(),
                other => other.as_ref(),
            });
        }
        let out = output_of(
            Command::new(exe)
                .args(line)
                .current_dir(&room)
                .stdin(Stdio::null()),
        )
        .expect("the command runs");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        let mut left = Vec::new();
        walk(&room, &room, &mut left);
        left.sort();
        (out.status.code(), text, left)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn walk(root: &Path, at: &Path, into: &mut Vec<String>) {
    for entry in std::fs::read_dir(at).unwrap() {
        let path = entry.unwrap().path();
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            into.push(format!("{name}/"));
            walk(root, &path, into);
        } else {
            let text = std::fs::read_to_string(&path).unwrap();
            into.push(format!("{name}={}", text.trim_end()));
        }
    }
}

/// The names on the lines that begin with `verb`, in order, with `/`.
fn named(text: &str, verb: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix(verb))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| name.replace('\\', "/"))
        .collect()
}

/// The arguments after `x -mt1 -o+`, the exit code, and what is written.
const ROWS: &[(&[&str], i32, &[&str])] = &[
    (&["set.rar"], 0, &["v.txt=version 3 of the file"]),
    (
        &["-ver", "set.rar"],
        0,
        &[
            "v.txt;1=version 1 of the file",
            "v.txt;2=version 2 of the file",
            "v.txt=version 3 of the file",
        ],
    ),
    (&["-ver1", "set.rar"], 0, &["v.txt=version 1 of the file"]),
    (&["-ver2", "set.rar"], 0, &["v.txt=version 2 of the file"]),
    (&["-ver3", "set.rar"], 10, &[]),
    (&["-ver9", "set.rar"], 10, &[]),
    (&["-ver01", "set.rar"], 0, &["v.txt=version 1 of the file"]),
    (&["-ver2x", "set.rar"], 0, &["v.txt=version 2 of the file"]),
    (
        &["-ver0", "set.rar"],
        0,
        &[
            "v.txt;1=version 1 of the file",
            "v.txt;2=version 2 of the file",
            "v.txt=version 3 of the file",
        ],
    ),
    (&["-ver1", "set.rar", "v.txt"], 10, &[]),
    (&["-ver1", "set.rar", "*.txt"], 10, &[]),
    (
        &["-ver1", "set.rar", "*;1"],
        0,
        &["v.txt=version 1 of the file"],
    ),
    (&["-ver1", "-xv.txt;1", "set.rar"], 10, &[]),
    (
        &["set.rar", "v.txt;1"],
        0,
        &["v.txt;1=version 1 of the file"],
    ),
    (
        &["set.rar", "v.txt;2"],
        0,
        &["v.txt;2=version 2 of the file"],
    ),
    (&["set.rar", "v.txt;9"], 10, &[]),
    (
        &["-ver1", "set.rar", "v.txt;1"],
        0,
        &["v.txt;1=version 1 of the file"],
    ),
    (
        &["-ver2", "set.rar", "v.txt;1"],
        0,
        &["v.txt;1=version 1 of the file"],
    ),
    (&["set.rar", "*;1"], 10, &[]),
];

#[test]
fn a_numbered_version_is_the_one_extracted() {
    let bench = Bench::new("extract");
    for (name, exe) in bench.names() {
        for (args, code, expected) in ROWS {
            let mut line = vec!["-o+"];
            line.extend_from_slice(args);
            let (got, text, left) = bench.run(exe, "x", &line);
            assert_eq!(got, Some(*code), "{name} x {args:?}: {text}");
            assert_eq!(left, *expected, "{name} x {args:?}: {text}");
        }
    }
}

#[test]
fn the_lines_name_a_numbered_version_as_it_is_written() {
    let bench = Bench::new("lines");
    for (name, exe) in bench.names() {
        let (code, text, _) = bench.run(exe, "t", &["-ver1", "set.rar"]);
        assert_eq!(code, Some(0), "{name}: {text}");
        assert_eq!(named(&text, "Testing     "), ["v.txt"], "{name}: {text}");
        let (code, text, _) = bench.run(exe, "t", &["set.rar", "v.txt;2"]);
        assert_eq!(code, Some(0), "{name}: {text}");
        assert_eq!(named(&text, "Testing     "), ["v.txt;2"], "{name}: {text}");
    }
}

#[test]
fn a_listing_shows_every_version_whatever_the_number() {
    let bench = Bench::new("list");
    for (name, exe) in bench.names() {
        for switch in ["-ver", "-ver1", "-ver9"] {
            let (code, text, _) = bench.run(exe, "lb", &[switch, "set.rar"]);
            assert_eq!(code, Some(0), "{name}: {text}");
            let listed: Vec<&str> = text.lines().collect();
            assert_eq!(
                listed,
                ["v.txt;1", "v.txt;2", "v.txt"],
                "{name} lb {switch}"
            );
        }
        let (code, text, _) = bench.run(exe, "lb", &["set.rar", "v.txt;1"]);
        assert_eq!(code, Some(0), "{name}: {text}");
        assert_eq!(text.trim_end(), "v.txt;1", "{name} lb v.txt;1");
    }
}
