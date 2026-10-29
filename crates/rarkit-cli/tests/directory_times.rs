//! Extracted DIRECTORIES carry the archive's times.
//!
//! Before 26 Sep 2026 `x` created each directory member and never set its
//! time, and every file written under it afterwards moved it again, so
//! every extracted directory carried the run's own time: 1,722 of 1,722
//! over `small-r.rar`, on the concurrent path. The times are now set once
//! every member is written. Both paths are held here,
//! `-mt1` (sequential) and `-mt4` (concurrent), each run twice.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-dir-times-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The tree's directories, parents first, each with the time set on it.
const DIRS: [(&str, u64); 4] = [
    ("tree", 1_000_000_000),
    ("tree/a", 1_100_000_000),
    ("tree/a/deep", 1_200_000_000),
    ("tree/b", 1_300_000_000),
];

/// Sets a directory's time. Windows opens a directory only when asked
/// for backup semantics (`FILE_FLAG_BACKUP_SEMANTICS`, 0x0200_0000), and
/// sets a time only through a handle with write access.
fn set_time(path: &Path, seconds: u64) {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.write(true).custom_flags(0x0200_0000);
    }
    #[cfg(not(windows))]
    options.read(true);
    let dir = options.open(path).unwrap();
    dir.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

fn mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn extracted_directories_keep_the_archived_times_on_both_paths() {
    let root = work("x");
    for (dir, _) in DIRS {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    for (dir, _) in DIRS {
        for n in 0..3 {
            std::fs::write(root.join(dir).join(format!("f{n}.txt")), dir.repeat(n + 1)).unwrap();
        }
    }
    // Deepest first, once every file is in place.
    for (dir, seconds) in DIRS.iter().rev() {
        set_time(&root.join(dir), *seconds);
    }
    let made = Command::new(rarfast())
        .current_dir(&root)
        .args(["a", "-r", "-idq", "arc.rar", "tree"])
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    for threads in ["-mt1", "-mt4"] {
        for run in 0..2 {
            let out = root.join(format!("out{threads}{run}"));
            std::fs::create_dir_all(&out).unwrap();
            let done = Command::new(rarfast())
                .args(["x", "-y", "-idq", threads, "arc.rar"])
                .arg(format!("{}/", out.display()))
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(done.status.success(), "{done:?}");
            for (dir, seconds) in DIRS {
                assert_eq!(
                    mtime(&out.join(dir)),
                    seconds,
                    "{dir} after x {threads}, run {run}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}
