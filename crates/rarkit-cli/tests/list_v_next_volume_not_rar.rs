//! `l -v` over a volume set whose NEXT volume is not a RAR archive at all
//! (its name is the set's, its bytes are plain text): the listing must
//! not call the set finished.
//!
//! MEASURED against unrar 7.23 on macOS arm64, 27 Oct 2026, on a stored
//! RAR 5 set of four volumes (rar's own and rarfast's alike) whose
//! `set.part2.rar` was replaced by plain text: `l -v set.part1.rar` lists
//! the first volume, then says `ERROR: Bad archive set.part2.rar` on
//! stderr and `Program aborted` on stdout, and exits 13. Until this file,
//! rarfast listed the first volume with its totals as if the set ended
//! there, said nothing and exited 0: a success exit over a broken set.
//!
//! The set is written by this crate's own `rar` dialect, so the row needs
//! nothing on PATH. Width and memory: `l` decodes nothing; the set is
//! 300,000 bytes in four volumes, so the test needs no memory to speak of.

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
        let dir =
            std::env::temp_dir().join(format!("rarfast-listv-notrar-{}-{tag}", std::process::id()));
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

#[test]
fn list_v_names_a_next_volume_that_is_not_a_rar_and_fails() {
    let (dir, _watch) = DirWatch::new("listv");
    set_with_a_text_second_volume(&dir);
    let done = run(&dir, &["l", "-v", "set.part1.rar"]);
    let stdout = String::from_utf8_lossy(&done.stdout);
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(
        done.status.code(),
        Some(13),
        "a broken set was listed with a success exit\n{}",
        text(&done)
    );
    assert!(
        stderr.contains("Bad archive set.part2.rar"),
        "the volume that is not a RAR is not named\n{}",
        text(&done)
    );
    assert!(
        stdout.contains("Program aborted"),
        "the listing was not ended as aborted\n{}",
        text(&done)
    );
    // The first volume's member is still listed before the stop.
    assert!(stdout.contains("data.bin"), "{}", text(&done));
}
