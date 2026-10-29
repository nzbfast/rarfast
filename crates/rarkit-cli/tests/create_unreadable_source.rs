//! A source its owner may not read is left out, and the rest is archived.
//!
//! Until 8 Oct 2026 one such file ended the whole create: `Cannot open
//! s/a.txt`, `Permission denied`, `../o.rar was not written`, exit 6 and
//! no archive.
//!
//! Measured against rar 7.23 on 8 Oct 2026 (an Apple silicon Mac),
//! `s/a.txt` at mode 000 beside `s/d/c.txt`:
//!
//! - `rar a -r o.rar s` complains `Cannot open s/a.txt` and `Permission
//!   denied` on stderr, stores `s/d/c.txt`, `s/d` and `s`, says `WARNING:
//!   Cannot open 1 file` after the last `Adding` line and before `Done`,
//!   and exits 6;
//! - `rar m` and `rar a -df` then delete what was archived and leave
//!   `s/a.txt`, and so `s`, where they were;
//! - with nothing else to add it says `WARNING: Cannot open 1 file`,
//!   `WARNING: No files`, writes no archive and exits 6.
//!
//! rarfast finds such a file from the mode the walk has read already,
//! and asks the system only about a file whose owner may not read it. A
//! file that is unreadable for another reason (another user's, with no
//! read bit for the rest) still ends the create with no archive.
//!
//! Each run is `-mt2` over two files of four bytes: a pool two threads
//! wide and a few KiB of memory.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// `s/a.txt` at mode 000 and `s/d/c.txt`, or `None` for a user every
/// file opens for whatever its mode.
fn work(tag: &str) -> Option<PathBuf> {
    let id = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&id.stdout).trim() == "0" {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("rarfast-unreadable-{}-{tag}", std::process::id()));
    if dir.exists() {
        let _ =
            std::fs::set_permissions(dir.join("s/a.txt"), std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(dir.join("s/d")).unwrap();
    std::fs::write(dir.join("s/a.txt"), b"aaa\n").unwrap();
    std::fs::write(dir.join("s/d/c.txt"), b"ccc\n").unwrap();
    std::fs::set_permissions(dir.join("s/a.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
    Some(dir)
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn members(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = text(&run(dir, &["lb", "o.rar"]).stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

#[test]
fn the_other_files_are_archived_and_the_run_exits_6() {
    let Some(dir) = work("add") else { return };
    let out = run(&dir, &["a", "-r", "-idq", "-mt2", "o.rar", "s"]);
    let warned = text(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{warned}");
    assert_eq!(warned, "\nCannot open s/a.txt\nPermission denied\n");
    assert_eq!(members(&dir), ["s", "s/d", "s/d/c.txt"]);

    // Said in full, the count comes after the files and before `Done`.
    std::fs::remove_file(dir.join("o.rar")).unwrap();
    let out = run(&dir, &["a", "-r", "-mt2", "o.rar", "s"]);
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(6), "{said}");
    assert!(
        said.ends_with("WARNING: Cannot open 1 file\nDone\n"),
        "{said}"
    );
    assert_eq!(members(&dir), ["s", "s/d", "s/d/c.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_move_and_a_delete_leave_the_unreadable_file_where_it_was() {
    for command in [vec!["m"], vec!["a", "-df"]] {
        let Some(dir) = work(&command.join("")) else {
            return;
        };
        let mut args = command.clone();
        args.extend_from_slice(&["-r", "-idq", "-mt2", "o.rar", "s"]);
        let out = run(&dir, &args);
        assert_eq!(out.status.code(), Some(6), "{command:?}");
        assert_eq!(members(&dir), ["s", "s/d", "s/d/c.txt"], "{command:?}");
        assert!(dir.join("s/a.txt").is_file(), "{command:?} took s/a.txt");
        assert!(!dir.join("s/d").exists(), "{command:?} left s/d");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn with_nothing_else_to_add_no_archive_is_written() {
    let Some(dir) = work("alone") else { return };
    let out = run(&dir, &["a", "-mt2", "o.rar", "s/a.txt"]);
    let (said, warned) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(6), "{said}{warned}");
    assert!(
        said.ends_with("WARNING: Cannot open 1 file\nWARNING: No files\n"),
        "{said}"
    );
    assert!(
        warned.contains("Cannot open s/a.txt\nPermission denied"),
        "{warned}"
    );
    assert!(!dir.join("o.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
