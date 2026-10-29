//! `d` and `rn` on a directory's name and on wildcards (bug sweep of 8 Oct
//! 2026, item 05).
//!
//! Measured on 8 Oct 2026 with `rar` 7.23 (macOS, aarch64) over the
//! archive this file builds, which rarfast writes (`a -r -m0` of a tree
//! `s`), every row exit 0:
//!
//! - `d arc.rar s/d` drops `s/d` AND every member beneath it, one
//!   `Deleting` line each, in the archive's order;
//! - a `d` that leaves no member prints `Erasing empty archive arc.rar`
//!   before `Done` and removes the file;
//! - `rn arc.rar s/d s/D2` renames `s/d` and every member beneath it, and
//!   its line for each is `Renaming s/d to <the member's new name>`;
//! - `rn arc.rar 's/*.bin' 's/*.dat'` renames each member the old mask
//!   matches (`Renaming s/dup.bin to s/dup.dat`); the mask's path is the
//!   member's own path, so `'s/d/*'` does not reach `s/d/e/f.dat` and
//!   `'*.txt'` matches nothing in `s`; a pair that matches nothing is
//!   `Processing archive` and `Done`;
//! - the `Renaming` lines come in the archive's order, not the pairs'.
//!
//! Before this `d` and `rn` acted on the directory's own entry alone, a
//! wildcard pair renamed nothing, and a `d` of every member left a 24
//! byte archive behind.
//!
//! Width and memory: every rarfast call states `-mt1`; the archive is
//! under 20 KiB.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// The members, in the order rarfast stores them.
const STORED: [&str; 9] = [
    "s/a.txt",
    "s/b.txt",
    "s/d/c.txt",
    "s/d/e/f.dat",
    "s/d/e",
    "s/d",
    "s/dup.bin",
    "s/r.bin",
    "s",
];

struct Work(PathBuf);

impl Work {
    /// A fresh directory holding `arc.rar`, the tree `s` stored.
    fn new(tag: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-dirs-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("s/d/e")).unwrap();
        let work = Work(dir);
        for (seed, name) in STORED.iter().filter(|n| n.contains('.')).enumerate() {
            let bytes: Vec<u8> = (0..3_000u32).map(|i| (i * 7 + seed as u32) as u8).collect();
            std::fs::write(work.0.join(name), bytes).unwrap();
        }
        work.ok(&["a", "-idq", "-r", "-m0", "arc.rar", "s"]);
        assert_eq!(work.names(), STORED);
        work
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(rarfast())
            .current_dir(&self.0)
            .arg(args[0])
            .arg("-mt1")
            .args(&args[1..])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// Stdout of a run that must exit 0.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "rarfast {args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The members as `lb` lists them, with `/` between the parts: the
    /// listing prints the system's own separator, which on Windows is
    /// `\` (as `tests/create_sweep.rs` reads it), and the names under
    /// test are the archive's.
    fn names(&self) -> Vec<String> {
        self.ok(&["lb", "arc.rar"])
            .lines()
            .map(|line| {
                if cfg!(windows) {
                    line.replace('\\', "/")
                } else {
                    line.to_owned()
                }
            })
            .collect()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn d_of_a_directory_drops_what_is_beneath_it() {
    let work = Work::new("d-dir");
    let stdout = work.ok(&["d", "arc.rar", "s/d"]);
    assert_eq!(
        stdout,
        "\nDeleting from arc.rar\nDeleting s/d/c.txt\nDeleting s/d/e/f.dat\nDeleting s/d/e\n\
         Deleting s/d\nDone\n"
    );
    assert_eq!(
        work.names(),
        ["s/a.txt", "s/b.txt", "s/dup.bin", "s/r.bin", "s"]
    );
    work.ok(&["t", "-idq", "arc.rar"]);

    // A directory and a file in one call; a name that only BEGINS like a
    // directory's (`s/d` and `s/dup.bin`) is not beneath it.
    let work = Work::new("d-two");
    let stdout = work.ok(&["d", "arc.rar", "s/d/e", "s/a.txt"]);
    assert_eq!(
        stdout,
        "\nDeleting from arc.rar\nDeleting s/a.txt\nDeleting s/d/e/f.dat\nDeleting s/d/e\nDone\n"
    );
    assert_eq!(
        work.names(),
        ["s/b.txt", "s/d/c.txt", "s/d", "s/dup.bin", "s/r.bin", "s"]
    );
}

#[test]
fn d_of_every_member_removes_the_archive() {
    for mask in ["*", "s"] {
        let work = Work::new("d-all");
        let stdout = work.ok(&["d", "arc.rar", mask]);
        let mut expected = String::from("\nDeleting from arc.rar\n");
        for name in STORED {
            expected.push_str(&format!("Deleting {name}\n"));
        }
        expected.push_str("Erasing empty archive arc.rar\nDone\n");
        assert_eq!(stdout, expected, "d {mask}");
        assert!(
            !work.0.join("arc.rar").exists(),
            "d {mask} left the archive"
        );
        // And nothing else of the run's is left beside where it was.
        let left: Vec<_> = std::fs::read_dir(&work.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["s"], "d {mask}");
    }
}

/// One volume of a set is not erased by a `d` of all it holds: the
/// engine refuses a member-level edit of a volume by name, and every
/// volume is left as it was. The exit is the reference's, 4 (rar 7.23,
/// 11 Oct 2026: `rar d set.part1.rar '*'` says `Cannot modify volume`,
/// exits 4 and leaves the volume as it was).
#[test]
fn d_of_every_member_does_not_erase_a_volume() {
    let work = Work::new("d-volume");
    work.ok(&["a", "-idq", "-r", "-m0", "-v8k", "set.rar", "s"]);
    let first = work.0.join("set.part1.rar");
    let before = std::fs::read(&first).expect("a first volume");
    let output = work.run(&["d", "set.part1.rar", "*"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(std::fs::read(&first).expect("the volume is still there") == before);
}

#[test]
fn rn_of_a_directory_renames_what_is_beneath_it() {
    let work = Work::new("rn-dir");
    let stdout = work.ok(&["rn", "arc.rar", "s/d", "s/D2"]);
    assert_eq!(
        stdout,
        "\nProcessing archive arc.rar\nRenaming s/d to s/D2/c.txt\n\
         Renaming s/d to s/D2/e/f.dat\nRenaming s/d to s/D2/e\nRenaming s/d to s/D2\nDone\n"
    );
    assert_eq!(
        work.names(),
        [
            "s/a.txt",
            "s/b.txt",
            "s/D2/c.txt",
            "s/D2/e/f.dat",
            "s/D2/e",
            "s/D2",
            "s/dup.bin",
            "s/r.bin",
            "s"
        ]
    );
    work.ok(&["t", "-idq", "arc.rar"]);

    // Two pairs: the lines are in the archive's order.
    let work = Work::new("rn-two");
    let stdout = work.ok(&["rn", "arc.rar", "s/d/e", "s/d/E9", "s/a.txt", "s/A.txt"]);
    assert_eq!(
        stdout,
        "\nProcessing archive arc.rar\nRenaming s/a.txt to s/A.txt\n\
         Renaming s/d/e to s/d/E9/f.dat\nRenaming s/d/e to s/d/E9\nDone\n"
    );
    assert_eq!(
        work.names(),
        [
            "s/A.txt",
            "s/b.txt",
            "s/d/c.txt",
            "s/d/E9/f.dat",
            "s/d/E9",
            "s/d",
            "s/dup.bin",
            "s/r.bin",
            "s"
        ]
    );
}

#[test]
fn rn_with_wildcards_renames_what_the_mask_matches() {
    let work = Work::new("rn-ext");
    let stdout = work.ok(&["rn", "arc.rar", "s/*.bin", "s/*.dat"]);
    assert_eq!(
        stdout,
        "\nProcessing archive arc.rar\nRenaming s/dup.bin to s/dup.dat\n\
         Renaming s/r.bin to s/r.dat\nDone\n"
    );
    let names = work.names();
    assert_eq!(names[6..8], ["s/dup.dat", "s/r.dat"]);
    assert_eq!(names[..6], STORED[..6]);

    // The whole name kept and the path changed; the mask's path is the
    // member's own, so what lies deeper is not reached.
    let work = Work::new("rn-path");
    let stdout = work.ok(&["rn", "arc.rar", "s/d/*", "s/q/*"]);
    assert_eq!(
        stdout,
        "\nProcessing archive arc.rar\nRenaming s/d/c.txt to s/q/c.txt\n\
         Renaming s/d/e to s/q/e\nDone\n"
    );
    assert_eq!(
        work.names(),
        [
            "s/a.txt",
            "s/b.txt",
            "s/q/c.txt",
            "s/d/e/f.dat",
            "s/q/e",
            "s/d",
            "s/dup.bin",
            "s/r.bin",
            "s"
        ]
    );

    // A mask with no path matches nothing inside `s`.
    let work = Work::new("rn-none");
    let before = std::fs::read(work.0.join("arc.rar")).unwrap();
    let stdout = work.ok(&["rn", "arc.rar", "*.txt", "*.md"]);
    assert_eq!(stdout, "\nProcessing archive arc.rar\nDone\n");
    assert_eq!(work.names(), STORED);
    assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
}
