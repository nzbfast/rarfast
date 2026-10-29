//! `-dw` wipes and removes a source that is read-only.
//!
//! Until 8 Oct 2026 the wipe opened each source for writing and stopped
//! at one of mode 0444: `Cannot delete s/d/c.txt`, `Permission denied`,
//! the file and the directories above it left on disk, and the bytes
//! that were to be wiped still readable.
//!
//! Measured against rar 7.23 on 8 Oct 2026 (an Apple silicon Mac): `rar
//! a -r -idq -dw o.rar s` over `s/a.txt` and a read-only `s/d/c.txt`
//! wipes and removes everything, says nothing on stderr and exits 0. (A
//! plain `-df` removed such a file already: an unlink asks the
//! directory, not the file.)
//!
//! Each run is `-mt2` over two files of four bytes: a pool two threads
//! wide and a few KiB of memory.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-wipe-ro-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("s/d")).unwrap();
    std::fs::write(dir.join("s/a.txt"), b"aaa\n").unwrap();
    std::fs::write(dir.join("s/d/c.txt"), b"ccc\n").unwrap();
    std::fs::set_permissions(
        dir.join("s/d/c.txt"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    dir
}

#[test]
fn a_wipe_removes_a_read_only_source() {
    for command in [["a", "-dw"], ["m", "-dw"]] {
        let dir = work(command[0]);
        let run = Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(command)
            .args(["-r", "-idq", "-mt2", "o.rar", "s"])
            .current_dir(&dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let warned = String::from_utf8_lossy(&run.stderr);
        assert_eq!(run.status.code(), Some(0), "{command:?}: {warned}");
        assert_eq!(warned, "", "{command:?}");
        assert!(!dir.join("s").exists(), "{command:?} left the sources");
        let listed = Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(["lb", "o.rar"])
            .current_dir(&dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let mut members: Vec<&str> = std::str::from_utf8(&listed.stdout)
            .unwrap()
            .lines()
            .collect();
        members.sort_unstable();
        assert_eq!(members, ["s", "s/a.txt", "s/d", "s/d/c.txt"], "{command:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
