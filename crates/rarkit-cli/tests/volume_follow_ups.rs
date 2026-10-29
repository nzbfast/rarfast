//! `-t` and `-k` after a volume create follow the volumes, not the name.
//!
//! With `-v<size>` the creator writes `arc.part1.rar`, `arc.part2.rar`
//! and on, and no `arc.rar`. Until 4 Oct 2026 the `-t` and `-k` that
//! follow the write opened the name the command line gave: `rarfast a
//! -m0 -v100k -t arc.rar big.bin` wrote a sound set, then said `Cannot
//! open arc.rar` and exited 10, with `-k` it exited 6 and locked no
//! volume, and `m -v100k -t` went on to delete the source with no test
//! having run.
//!
//! **Measured against rar 7.23 on 4 Oct 2026** (an Apple silicon Mac):
//! `rar a -m0 -v100k -k -t arc.rar big.bin` over 300,000 random bytes
//! exits 0, writes three volumes, tests the set from `arc.part1.rar`
//! (`Testing archive arc.part1.rar`, then parts 2 and 3, `All OK`) and
//! locks EVERY volume: `rar lt` of each says `lock`.
//!
//! Every run here is `-mt2 -m0` over one file of 300,000 bytes: a pool
//! two threads wide and a few MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Bytes a stored member cannot shrink.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with 300,000 bytes of noise in `big.bin`.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-vol-follow-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), noise(300_000, 7)).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

const PARTS: [&str; 3] = ["arc.part1.rar", "arc.part2.rar", "arc.part3.rar"];

fn assert_the_set_is_there(dir: &Path) {
    for part in PARTS {
        assert!(dir.join(part).is_file(), "{part} was not written");
    }
    assert!(
        !dir.join("arc.rar").exists(),
        "a volume create wrote arc.rar"
    );
}

#[test]
fn t_after_a_volume_create_tests_the_set() {
    let dir = work("t");
    let out = run(
        &dir,
        &["a", "-mt2", "-m0", "-v100k", "-t", "arc.rar", "big.bin"],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout} stderr: {stderr}"
    );
    assert_the_set_is_there(&dir);
    for part in PARTS {
        assert!(
            stdout.contains(&format!("Testing archive {part}")),
            "{part} was not tested: {stdout}"
        );
    }
    assert!(stdout.contains("All OK"), "{stdout}");
    assert!(!stderr.contains("Cannot open"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn k_after_a_volume_create_locks_every_volume() {
    let dir = work("k");
    let out = run(
        &dir,
        &["a", "-mt2", "-m0", "-v100k", "-k", "arc.rar", "big.bin"],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout} stderr: {stderr}"
    );
    assert_the_set_is_there(&dir);
    for part in PARTS {
        let listed = text(&run(&dir, &["lt", part]).stdout);
        assert!(listed.contains("lock"), "{part} is not locked: {listed}");
    }
    // The locked set still tests sound.
    let tested = run(&dir, &["t", "arc.part1.rar"]);
    assert_eq!(tested.status.code(), Some(0), "{}", text(&tested.stdout));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The move that deleted its source with no test having run: now the
/// test runs, passes, and only then the source goes.
#[test]
fn m_with_volumes_deletes_only_after_the_set_tested() {
    let dir = work("m");
    let out = run(
        &dir,
        &["m", "-mt2", "-m0", "-v100k", "-t", "arc.rar", "big.bin"],
    );
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout} stderr: {stderr}"
    );
    assert_the_set_is_there(&dir);
    let at = |needle: &str| {
        stdout
            .find(needle)
            .unwrap_or_else(|| panic!("no `{needle}` in: {stdout}"))
    };
    assert!(at("All OK") < at("Deleting"), "{stdout}");
    assert!(!dir.join("big.bin").exists(), "the source stayed: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
