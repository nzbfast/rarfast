//! `t` and `x` over a volume set whose NEXT volume is not a RAR archive at
//! all (its name is the set's, its bytes are plain text): the run must
//! name THAT volume and end with the reference's exit for a bad archive.
//!
//! MEASURED against unrar 7.23 on macOS arm64, 27 Oct 2026, on a stored
//! RAR 5 set of four volumes (rar's own and rarfast's alike) whose
//! `set.part2.rar` was replaced by plain text: `t set.part1.rar` and
//! `x -o+ set.part1.rar out/` each reach the second volume
//! (`Testing archive set.part2.rar`, `Extracting from set.part2.rar`), say
//! `ERROR: Bad archive set.part2.rar` on stderr and `Program aborted` on
//! stdout, exit 13, and `x` leaves no `data.bin` in `out`. Until this
//! file, rarfast said `no RAR archive here (volume 1)`, naming no file and
//! counting the volumes from 0, and exited 2.
//!
//! The set is written by this crate's own `rar` dialect, so the rows need
//! nothing on PATH. Width and memory: each run states `-mt1` or `-mt4`;
//! the set is 300,000 stored bytes in four volumes, so the test needs no
//! memory to speak of and passes on a runner two threads wide.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own that is removed when this value is
/// dropped, so a failed assert clears it away as a pass does.
struct DirWatch(PathBuf);

impl DirWatch {
    fn new(tag: &str) -> (PathBuf, DirWatch) {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-nextvol-notrar-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), DirWatch(dir))
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Bytes a stored member cannot shrink, the same on every run.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn text(done: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        done.status.code(),
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

/// A stored RAR 5 set of `data.bin` in `dir` (`set.part1.rar` on), with
/// its second volume replaced by plain text of the same length.
fn set_with_a_text_second_volume(dir: &Path) {
    std::fs::write(dir.join("data.bin"), noise(300_000)).unwrap();
    let made = run(
        dir,
        &[
            "a",
            "-ma5",
            "-m0",
            "-y",
            "-idq",
            "-v100000b",
            "set.rar",
            "data.bin",
        ],
    );
    assert_eq!(made.status.code(), Some(0), "{}", text(&made));
    std::fs::remove_file(dir.join("data.bin")).unwrap();
    assert!(dir.join("set.part3.rar").exists(), "the set is too short");
    let second = dir.join("set.part2.rar");
    let len = std::fs::metadata(&second).unwrap().len() as usize;
    let line = b"this volume is plain text, not a RAR archive\n";
    let plain: Vec<u8> = line.iter().copied().cycle().take(len).collect();
    std::fs::write(&second, plain).unwrap();
}

/// What every row owes: the second volume named as a bad archive, never
/// a volume by a number, and the reference's exit.
fn assert_named(done: &Output, row: &str) {
    let stdout = String::from_utf8_lossy(&done.stdout);
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(
        done.status.code(),
        Some(13),
        "{row}: the wrong exit for a volume that is not a RAR\n{}",
        text(done)
    );
    assert!(
        stderr.contains("Bad archive set.part2.rar"),
        "{row}: the volume that is not a RAR is not named\n{}",
        text(done)
    );
    assert!(
        !stderr.contains("(volume 1)"),
        "{row}: a volume named by a number\n{}",
        text(done)
    );
    assert!(
        stdout.contains("Program aborted"),
        "{row}: the run was not ended as aborted\n{}",
        text(done)
    );
}

#[test]
fn t_names_a_next_volume_that_is_not_a_rar() {
    for width in ["-mt1", "-mt4"] {
        let (dir, _watch) = DirWatch::new(&format!("t{width}"));
        set_with_a_text_second_volume(&dir);
        let done = run(&dir, &["t", width, "set.part1.rar"]);
        assert_named(&done, &format!("t {width}"));
    }
}

#[test]
fn x_names_a_next_volume_that_is_not_a_rar_and_leaves_no_member() {
    for width in ["-mt1", "-mt4"] {
        let (dir, _watch) = DirWatch::new(&format!("x{width}"));
        set_with_a_text_second_volume(&dir);
        let done = run(&dir, &["x", "-o+", width, "set.part1.rar", "out/"]);
        assert_named(&done, &format!("x {width}"));
        assert!(
            !dir.join("out/data.bin").exists(),
            "x {width}: a member cut short at a bad volume was left\n{}",
            text(&done)
        );
    }
}
