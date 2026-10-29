//! `rv` beside a volume set that was RENAMED after it was written.
//!
//! THE RULES (SPEC-L 3.6.4, V1 to V6): a recovery volume's name is the
//! FIRST volume's name as it is on disk with two things changed, the
//! number in it and the extension, which is `.rev` in lower case (V1,
//! V2). The number keeps the first volume's own count of digits and
//! grows only where it must (V3), and runs from 1 (V4). A set whose
//! names do not agree gets no recovery volume and exit 0 (V6); there
//! rarfast says one line on the standard error, where the reference
//! says nothing.
//!
//! Before 10 Oct 2026 the name was the set's stem, `.part`, and the
//! number at the width of the count of data volumes: `set.part01.rar`
//! of six gave `set.part1.rev`, `SET.PART1.RAR` gave `SET.part1.rev`,
//! and a set named `set.p1.rar` was not walked at all: its first volume
//! alone was taken for the set, and recovery volumes were written for
//! it. So were they for a set whose names do not agree.
//!
//! MEASURED on rar 7.23 for macOS (arm64), 10 Oct 2026: the 70 rows of
//! the specification's table, the fourteen rows this crate's unit test
//! held as the reference's answer, and fourteen more made beside them.
//! Each set here is written by rarfast itself (stored, `-v`), renamed by
//! one rule, and given to `rv<N>`; no reference tool is called. The
//! names are compared as the directory lists them, so a file system
//! that folds case must still have kept the case they were made with.
//!
//! Width and memory: `rv` takes no `-mt`; each set is 30,000 random
//! bytes in volumes of 5,120 or 2,500 bytes, so the test needs no memory
//! to speak of and passes on a runner two threads wide.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is deleted.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-revnames-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// Bytes no stored volume can shrink, the same every run.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Writes a stored set `set.partN.rar` in `dir` with volumes of
/// `volume` (a `-v` size) and answers how many volumes it made.
fn write_set(dir: &Path, volume: &str) -> usize {
    std::fs::write(dir.join("data"), noise(30_000)).unwrap();
    let done = Command::new(rarfast())
        .current_dir(dir)
        .args(["a", "-idq", "-m0", "-ep", volume, "set.rar", "data"])
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
    std::fs::remove_file(dir.join("data")).unwrap();
    std::fs::read_dir(dir).unwrap().count()
}

/// The set's volume names as rarfast wrote them, in order: one digit for
/// fewer than ten volumes, two for more.
fn written(count: usize) -> Vec<String> {
    let width = count.to_string().len();
    (1..=count)
        .map(|n| format!("set.part{n:0width$}.rar"))
        .collect()
}

fn run_rv(dir: &Path, command: &str, first: &str) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args([command, first])
        .output()
        .unwrap()
}

/// The `.rev` files in `dir`, sorted, exactly as the directory spells
/// them.
fn rev_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.to_ascii_lowercase().ends_with(".rev"))
        .collect();
    names.sort();
    names
}

/// One set of volumes of `volume`, each renamed by `to` (which is given
/// the volume's number from 1), then `command` on the first: the `.rev`
/// names it leaves.
fn renamed(
    tag: &str,
    volume: &str,
    command: &str,
    to: &dyn Fn(usize) -> String,
) -> (Output, Vec<String>) {
    let (dir, _watch) = work(tag);
    let count = write_set(&dir, volume);
    for (index, old) in written(count).iter().enumerate() {
        let new = to(index + 1);
        if *old != new {
            std::fs::rename(dir.join(old), dir.join(&new)).unwrap();
        }
    }
    let done = run_rv(&dir, command, &to(1));
    let names = rev_files(&dir);
    (done, names)
}

#[test]
fn the_recovery_names_are_the_first_volume_s_with_the_number_and_the_extension_changed() {
    // (tag, volume size, command, the name of volume n, the names owed)
    type Row = (
        &'static str,
        &'static str,
        &'static str,
        fn(usize) -> String,
        &'static [&'static str],
    );
    let rows: [Row; 13] = [
        (
            "written",
            "-v5k",
            "rv2",
            |n| format!("set.part{n}.rar"),
            &["set.part1.rev", "set.part2.rev"],
        ),
        // V3: the first volume's own count of digits.
        (
            "two",
            "-v5k",
            "rv2",
            |n| format!("set.part{n:02}.rar"),
            &["set.part01.rev", "set.part02.rev"],
        ),
        (
            "three",
            "-v5k",
            "rv1",
            |n| format!("set.part{n:03}.rar"),
            &["set.part001.rev"],
        ),
        (
            "unpadded",
            "-v2500b",
            "rv2",
            |n| format!("big.part{n}.rar"),
            &["big.part1.rev", "big.part2.rev"],
        ),
        // V3: the width grows where it must and is not made even.
        (
            "twelve",
            "-v5k",
            "rv12",
            |n| format!("set.part{n}.rar"),
            &[
                "set.part1.rev",
                "set.part10.rev",
                "set.part11.rev",
                "set.part12.rev",
                "set.part2.rev",
                "set.part3.rev",
                "set.part4.rev",
                "set.part5.rev",
                "set.part6.rev",
                "set.part7.rev",
                "set.part8.rev",
                "set.part9.rev",
            ],
        ),
        // V1 and V2: the base and the word kept as spelt, `.rev` in lower
        // case.
        (
            "upper",
            "-v5k",
            "rv2",
            |n| format!("SET.PART{n}.RAR"),
            &["SET.PART1.rev", "SET.PART2.rev"],
        ),
        (
            "capital",
            "-v5k",
            "rv1",
            |n| format!("set.Part{n}.rar"),
            &["set.Part1.rev"],
        ),
        (
            "ext",
            "-v5k",
            "rv1",
            |n| format!("set.part{n}.RAR"),
            &["set.part1.rev"],
        ),
        (
            "field",
            "-v5k",
            "rv1",
            |n| format!("a.part7.part{n}.rar"),
            &["a.part7.part1.rev"],
        ),
        (
            "space",
            "-v5k",
            "rv1",
            |n| format!("my set.part{n}.rar"),
            &["my set.part1.rev"],
        ),
        (
            "p",
            "-v5k",
            "rv2",
            |n| format!("set.p{n}.rar"),
            &["set.p1.rev", "set.p2.rev"],
        ),
        (
            "vol",
            "-v5k",
            "rv1",
            |n| format!("set.vol{n}.rar"),
            &["set.vol1.rev"],
        ),
        (
            "bare",
            "-v5k",
            "rv1",
            |n| format!("set.{n}.rar"),
            &["set.1.rev"],
        ),
    ];
    for (tag, volume, command, to, owed) in rows {
        let (done, names) = renamed(tag, volume, command, &to);
        assert!(done.status.success(), "{tag}: {done:?}");
        assert_eq!(names, owed, "{tag}: {done:?}");
    }
}

#[test]
fn a_set_whose_names_do_not_agree_gets_no_recovery_volume() {
    type Row = (&'static str, fn(usize) -> String);
    let rows: [Row; 4] = [
        // The first volume alone at another count of digits.
        ("first-two", |n| match n {
            1 => "set.part01.rar".to_owned(),
            n => format!("set.part{n}.rar"),
        }),
        // Every volume but the first.
        ("rest-two", |n| match n {
            1 => "set.part1.rar".to_owned(),
            n => format!("set.part{n:02}.rar"),
        }),
        // The first volume alone under another base.
        ("first-base", |n| match n {
            1 => "other.name.part1.rar".to_owned(),
            n => format!("set.part{n}.rar"),
        }),
        ("rest-base", |n| match n {
            1 => "set.part1.rar".to_owned(),
            n => format!("other.name.part{n}.rar"),
        }),
    ];
    for (tag, to) in rows {
        let (done, names) = renamed(tag, "-v5k", "rv2", &to);
        assert_eq!(done.status.code(), Some(0), "{tag}: {done:?}");
        assert!(names.is_empty(), "{tag}: {names:?}");
        let said = String::from_utf8_lossy(&done.stderr);
        assert!(
            said.contains("no recovery volume"),
            "{tag}: it says that nothing was written: {done:?}"
        );
    }
}
