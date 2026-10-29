//! A directory that cannot be read is reported, and the run is not a
//! success.
//!
//! Until 4 Oct 2026 the creator's walk skipped a directory it could not
//! list without a word: `rarfast a arc.rar proj`, where `proj/secret`
//! is mode 000, wrote an archive with none of `proj/secret`'s files in
//! it, printed nothing about it and exited 0.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac),
//! over `proj/top.txt`, `proj/open/o.txt` and `proj/secret/s.txt` with
//! `proj/secret` at mode 000. `<cwd>` is the current directory, and the
//! path after it is the path as the walk spelled it, unchanged (`./proj`
//! gives `<cwd>/./proj/secret`):
//!
//! | run                        | stderr                                   | written | exit |
//! |----------------------------|------------------------------------------|---------|------|
//! | `rar a arc.rar proj`       | `Cannot read contents of <cwd>/proj/secret`, `Permission denied` | the rest, and `proj/secret` as an entry | 6 |
//! | `rar a -r arc.rar proj`    | the same                                 | the same | 6   |
//! | `rar a -r arc.rar proj/*.txt` | the same                              | the two `.txt` it could reach | 6 |
//! | `rar a arc.rar proj/secret` | the same                                | `proj/secret` as an entry | 6 |
//! | `rar a arc.rar proj/secret/` | the same                               | nothing: `WARNING: No files` | 10 |
//! | `rar a arc.rar proj/secret/*` | the same                              | nothing: `WARNING: No files` | 10 |
//! | `rar a arc.rar nodir/*`    | nothing                                  | nothing: `WARNING: No files` | 10 |
//!
//! On one stream (`-ierr`) the complaint comes before `Creating
//! archive`. `rar m -r arc.rar proj` complains the same way, exits 6,
//! and still deletes what it archived.
//!
//! Run as root nothing is unreadable, and the rows return early.
//!
//! **Unix only, and why.** On Windows a folder is shut by an access
//! control entry, and the one this file could set on a folder of its own
//! (a deny of listing for everyone) did not shut it to the reference:
//! measured against Rar.exe 7.23 x64 on 4 Oct 2026 (Windows 11, the
//! session an administrator's), all seven runs of the table over such a
//! folder archived `proj\secret\s.txt` with the rest and exited 0, with
//! nothing on stderr. With no run in which the reference fails to read a
//! folder there, there is nothing to hold rarfast to, and making one
//! would mean changing a setting of the machine and not of the folder.
//!
//! Every run here is `-mt2` over three files of a few bytes: a pool two
//! threads wide and a few MiB of memory.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A scratch tree with one directory shut, opened again when dropped so
/// that it can be removed.
struct Tree {
    dir: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-unread-{}-{tag}", std::process::id()));
        if dir.exists() {
            let _ = std::fs::set_permissions(
                dir.join("proj/secret"),
                std::fs::Permissions::from_mode(0o755),
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::create_dir_all(dir.join("proj/secret")).unwrap();
        std::fs::create_dir_all(dir.join("proj/open")).unwrap();
        std::fs::write(dir.join("proj/top.txt"), b"top\n").unwrap();
        std::fs::write(dir.join("proj/open/o.txt"), b"open\n").unwrap();
        std::fs::write(dir.join("proj/secret/s.txt"), b"secret\n").unwrap();
        std::fs::set_permissions(
            dir.join("proj/secret"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        Self { dir }
    }

    /// Whether the mode shut the directory. False under root.
    fn is_shut(&self) -> bool {
        std::fs::read_dir(self.dir.join("proj/secret")).is_err()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(rarfast())
            .args(args)
            .current_dir(&self.dir)
            .output()
            .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
    }

    /// The members of `arc.rar`, sorted.
    fn members(&self) -> Vec<String> {
        let mut names: Vec<String> = text(&self.run(&["lb", "arc.rar"]).stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        names.sort();
        names
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(
            self.dir.join("proj/secret"),
            std::fs::Permissions::from_mode(0o755),
        );
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The complaint, whatever the current directory is spelled as: the
/// reference's words, an absolute path, the walked path at its end, and
/// the reason on the next line. (The reason is matched by its start: a
/// creator complaint ends without a newline, and the move's own `Cannot
/// delete` lines follow it on the same line today, which is reported as
/// owed and is not this file's ground.)
fn complains(stderr: &str, walked: &str) -> bool {
    stderr
        .lines()
        .zip(stderr.lines().skip(1))
        .any(|(line, next)| {
            line.starts_with("Cannot read contents of /")
                && line.ends_with(&format!("/{walked}"))
                && next.starts_with("Permission denied")
        })
}

/// A run that still writes an archive: exit 6, the complaint, and the
/// members the walk could reach.
fn writes_the_rest(tag: &str, args: &[&str], members: &[&str]) {
    let tree = Tree::new(tag);
    if !tree.is_shut() {
        eprintln!("skipped {tag}: mode 000 did not shut the directory (root?)");
        return;
    }
    let out = tree.run(args);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(6),
        "{args:?}; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        complains(&stderr, "proj/secret"),
        "{args:?}; stderr: {stderr}"
    );
    assert_eq!(tree.members(), members, "{args:?}; stdout: {stdout}");
    assert!(stdout.contains("Done"), "{args:?}; stdout: {stdout}");
}

/// A run with nothing left to write: exit 10, `WARNING: No files`, and
/// the complaint all the same.
fn writes_nothing(tag: &str, args: &[&str]) {
    let tree = Tree::new(tag);
    if !tree.is_shut() {
        eprintln!("skipped {tag}: mode 000 did not shut the directory (root?)");
        return;
    }
    let out = tree.run(args);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(10),
        "{args:?}; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        complains(&stderr, "proj/secret"),
        "{args:?}; stderr: {stderr}"
    );
    assert!(stdout.contains("WARNING: No files"), "{args:?}; {stdout}");
    assert!(
        !tree.dir.join("arc.rar").exists(),
        "{args:?} wrote an archive"
    );
}

const THE_REST: [&str; 5] = [
    "proj",
    "proj/open",
    "proj/open/o.txt",
    "proj/secret",
    "proj/top.txt",
];

/// The scenario the sweep named.
#[test]
fn a_named_directory_with_an_unreadable_one_below_it() {
    writes_the_rest("plain", &["a", "-mt2", "arc.rar", "proj"], &THE_REST);
    writes_the_rest("deep", &["a", "-mt2", "-r", "arc.rar", "proj"], &THE_REST);
}

#[test]
fn a_pattern_searched_below_an_unreadable_directory() {
    writes_the_rest(
        "pattern",
        &["a", "-mt2", "-r", "arc.rar", "proj/*.txt"],
        &["proj/open/o.txt", "proj/top.txt"],
    );
}

#[test]
fn the_unreadable_directory_named_itself() {
    writes_the_rest(
        "itself",
        &["a", "-mt2", "arc.rar", "proj/secret"],
        &["proj/secret"],
    );
}

#[test]
fn the_contents_of_the_unreadable_directory() {
    writes_nothing("contents", &["a", "-mt2", "arc.rar", "proj/secret/"]);
    writes_nothing("star", &["a", "-mt2", "arc.rar", "proj/secret/*"]);
}

/// A directory that is NOT THERE is not one that cannot be read: the
/// reference says nothing about it under a wildcard.
#[test]
fn a_missing_directory_under_a_wildcard_says_nothing() {
    let tree = Tree::new("nodir");
    let out = tree.run(&["a", "-mt2", "arc.rar", "nodir/*"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(10), "{stdout} {stderr}");
    assert!(!stderr.contains("Cannot read contents"), "{stderr}");
}

/// On one stream the complaint comes before the header.
#[test]
fn the_complaint_comes_before_the_header() {
    let tree = Tree::new("ierr");
    if !tree.is_shut() {
        eprintln!("skipped ierr: mode 000 did not shut the directory (root?)");
        return;
    }
    let out = tree.run(&["a", "-mt2", "-ierr", "arc.rar", "proj"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{stderr}");
    let complaint = stderr
        .find("Cannot read contents of ")
        .unwrap_or_else(|| panic!("no complaint: {stderr}"));
    let header = stderr
        .find("Creating archive")
        .unwrap_or_else(|| panic!("no header: {stderr}"));
    assert!(complaint < header, "{stderr}");
}

/// A move still deletes what it archived, as the reference does, and
/// the directory it could not read stays with its file.
#[test]
fn a_move_keeps_what_it_could_not_read() {
    let tree = Tree::new("move");
    if !tree.is_shut() {
        eprintln!("skipped move: mode 000 did not shut the directory (root?)");
        return;
    }
    let out = tree.run(&["m", "-mt2", "-r", "arc.rar", "proj"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(6), "{stdout} {stderr}");
    assert!(complains(&stderr, "proj/secret"), "{stderr}");
    assert!(!tree.dir.join("proj/top.txt").exists(), "{stdout}");
    assert!(tree.dir.join("proj/secret").is_dir(), "{stdout}");
    std::fs::set_permissions(
        tree.dir.join("proj/secret"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(tree.dir.join("proj/secret/s.txt").is_file(), "{stdout}");
}
