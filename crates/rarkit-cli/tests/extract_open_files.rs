//! `x` of 20,000 small files inside a small descriptor limit
//! (FROM-STUDIO 443 C, a release blocker).
//!
//! On an Apple M1 Ultra at macOS's default soft limit of 256, `x` of 20,000
//! small files in 200 directories exited 9 with `Too many open files` at
//! 17,948 files written (15 Oct 2026, main 2159f8158). Create ahead's close
//! queue (`extract::ahead`) was bounded by a constant 256 whatever the
//! limit, beside its window of files made ahead: once the helpers' closes
//! lagged the walk, the queue alone held every descriptor the process had.
//! Counted on an Apple M5 Max the same day with 100 us planted per close:
//! every run at 256 failed with the queue at 252. The queue and the window
//! now share what the soft limit leaves (`workers::ahead_descriptors`);
//! `ahead`'s own unit test pins the bound with helpers that never run, and
//! this one runs the whole extract under 256 and under 64.
//!
//! The limit is lowered in a child shell (`ulimit -n`, as `descriptors.rs`
//! does, for the reason it gives: the workspace forbids `unsafe`). The run
//! takes the box's own width under both limits. Under 64 the engine's own
//! writers (twice the pool's breadth) would outgrow the limit past about
//! 26 threads whatever create ahead holds (counted 15 Oct 2026: about
//! 2 x width + 9 descriptors live), so a default width past what the
//! limit holds is narrowed to it and said so once (FROM-STUDIO 453 D,
//! `workers::extract_width_fit`: 8 at 64, 56 at 256), and a stated
//! `-mt<n>` past it is refused before anything is written. About 12 MB of
//! files on disk, and a few hundred MB of memory at most.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Directories, and files in each: 20,000 in all, the row's shape.
const DIRS: usize = 200;
const FILES_PER_DIR: usize = 100;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of this test's own under the system's temporary directory,
/// emptied first.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-open-files-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// File `file` of directory `dir`'s bytes: 100 to 1,300 of text, seeded
/// by its place, so every file differs and compresses.
fn content(dir: usize, file: usize) -> Vec<u8> {
    let mut state = ((dir * FILES_PER_DIR + file) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let len = 100 + (next() % 1_200) as usize;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        let word = 2 + (next() % 7) as usize;
        for _ in 0..word {
            bytes.push(b'a' + (next() % 26) as u8);
        }
        bytes.push(b' ');
    }
    bytes.truncate(len);
    bytes
}

fn relative(dir: usize, file: usize) -> PathBuf {
    Path::new(&format!("d{dir:03}")).join(format!("f{file:03}.txt"))
}

/// Runs `rarfast` in `dir` with the descriptor limit lowered to `limit`
/// for the run: its exit code and stderr.
fn run_with_limit(dir: &Path, limit: usize, args: &[&str]) -> (Option<i32>, String) {
    let line = format!(
        "ulimit -n {limit} && exec {} {}",
        shell_word(&rarfast().to_string_lossy()),
        args.iter()
            .map(|arg| shell_word(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&line)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("the shell could not be run: {err}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Every member written, whole, under each limit.
#[test]
fn x_of_20000_small_files_holds_inside_256_and_64_descriptors() {
    let dir = work("x20k");
    let tree = dir.join("tree");
    for d in 0..DIRS {
        std::fs::create_dir_all(tree.join(format!("d{d:03}"))).unwrap();
        for f in 0..FILES_PER_DIR {
            std::fs::write(tree.join(relative(d, f)), content(d, f)).unwrap();
        }
    }
    let made = Command::new(rarfast())
        .args(["a", "-idq", "-y", "-m3", "-r", "../x20k.rar", "."])
        .current_dir(&tree)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "the archive could not be made: {}",
        String::from_utf8_lossy(&made.stderr)
    );
    std::fs::remove_dir_all(&tree).unwrap();

    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    for (limit, fit) in [(256, 56), (64, 8)] {
        let out = dir.join(format!("out{limit}"));
        std::fs::create_dir_all(&out).unwrap();
        let target = format!("out{limit}/");
        let (exit, stderr) =
            run_with_limit(&dir, limit, &["x", "-idq", "-o+", "x20k.rar", &target]);
        assert_eq!(
            exit,
            Some(0),
            "x of {} files under a limit of {limit} descriptors failed: {}",
            DIRS * FILES_PER_DIR,
            stderr.lines().take(5).collect::<Vec<_>>().join(" / ")
        );
        for d in 0..DIRS {
            for f in 0..FILES_PER_DIR {
                let path = out.join(relative(d, f));
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|err| panic!("{} under {limit}: {err}", path.display()));
                assert!(
                    bytes == content(d, f),
                    "{} under {limit} differs",
                    path.display()
                );
            }
        }
        // Narrowed where the box is wider than the limit holds, and said.
        let note = format!("Extracting with {fit} threads, not {cores}");
        assert_eq!(
            stderr.contains(&note),
            cores > fit,
            "under {limit} on {cores} threads: {stderr:?}"
        );
        std::fs::remove_dir_all(&out).unwrap();
    }

    // A stated width the limit cannot hold is refused at the start: under
    // 36 descriptors one thread fits, and nothing is written.
    if cores >= 2 {
        let out = dir.join("out36");
        std::fs::create_dir_all(&out).unwrap();
        let (exit, stderr) = run_with_limit(&dir, 36, &["x", "-o+", "-mt2", "x20k.rar", "out36/"]);
        assert_ne!(exit, Some(0), "-mt2 under 36 descriptors ran: {stderr:?}");
        assert!(
            stderr.contains("Cannot extract with -mt2: the open file limit of 36 holds 1 thread"),
            "{stderr:?}"
        );
        assert_eq!(
            std::fs::read_dir(&out).unwrap().count(),
            0,
            "a file was written"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
