//! `lt` and `vt` print a member's own fraction of a second.
//!
//! Until 9 Oct 2026 the technical listing broke a time down from whole
//! seconds and printed `,000000000` for every member, whatever the
//! archive stored. Measured on 9 Oct 2026 with rar and unrar 7.23 (an
//! Apple silicon Mac) over a file whose modification time ends
//! `.099958648`, archived by `rar a -ma5` and by `rarfast a`: both
//! reference tools list
//!
//! ```text
//!        mtime: 2025-10-08 20:00:00,099958648
//! ```
//!
//! for both archives (so the create always stored the fraction), and
//! rarfast listed `,000000000` for both. Over archives `rar a` wrote
//! with each of `-tsm0` to `-tsm4`, `-tsm-` and no switch, three members
//! each, the `mtime` lines of `lt` and `vt` are now the reference's on
//! every one: `-tsm1` stores whole seconds and lists `,000000000`,
//! `-tsm-` lists no `mtime` line.
//!
//! `lt-nanoseconds/rar723.rar` is the archive `rar a -r -ma5` wrote of
//! that day: `n.txt` (`,099958648`), `d/m.txt` (`,999999999`) and the
//! directory `d` (`,000000001`). The date and the hour are the reader's
//! own zone's and are not compared.
//!
//! Width and memory: `-mt1` on every call; the archives are under 1 KiB.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// The nine digits after the comma of every `mtime` line, in the order
/// listed.
fn fractions(command: &str, archive: &Path) -> Vec<String> {
    let ran = Command::new(rarfast())
        .args([command, "-mt1"])
        .arg(archive)
        .output()
        .unwrap();
    assert_eq!(ran.status.code(), Some(0), "{command}: {ran:?}");
    String::from_utf8_lossy(&ran.stdout)
        .lines()
        .filter(|line| line.trim_start().starts_with("mtime: "))
        .map(|line| {
            let (time, fraction) = line.rsplit_once(',').expect("a comma before the fraction");
            assert_eq!(time.trim_start().len(), "mtime: 2025-10-08 20:00:00".len());
            fraction.to_owned()
        })
        .collect()
}

#[test]
fn the_fraction_the_reference_stored_is_the_fraction_listed() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/lt-nanoseconds/rar723.rar");
    for command in ["lt", "vt"] {
        assert_eq!(
            fractions(command, &archive),
            ["099958648", "999999999", "000000001"],
            "{command}"
        );
    }
}

#[test]
fn the_fraction_a_create_stored_is_the_fraction_listed() {
    let dir = std::env::temp_dir().join(format!("rarfast-lt-nanos-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("n.txt");
    std::fs::write(&file, b"hello\n").unwrap();
    let when = SystemTime::UNIX_EPOCH + Duration::new(1_759_968_000, 99_958_648);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(when)
        .unwrap();
    // A file system that keeps less than a nanosecond has nothing to show.
    let kept = std::fs::metadata(&file).unwrap().modified().unwrap();
    if kept != when {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let made = Command::new(rarfast())
        .current_dir(&dir)
        .args(["a", "-idq", "-mt1", "arc.rar", "n.txt"])
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    for command in ["lt", "vt"] {
        assert_eq!(
            fractions(command, &dir.join("arc.rar")),
            ["099958648"],
            "{command}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
