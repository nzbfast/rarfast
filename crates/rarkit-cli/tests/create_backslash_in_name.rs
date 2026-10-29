//! On a unix host a backslash in a file's name is a character of the
//! name, and is stored as one.
//!
//! Until 8 Oct 2026 a create turned every backslash of a walked path
//! into a separator, on every host. `n/back\slash.txt` was stored as
//! `n/back/slash.txt`, and `n/x\..\..\..\escaped.txt`, whose dot-dot
//! parts were then cut as a climb out of the archive, as `escaped.txt`:
//! a member outside its own directory, under a name another member may
//! hold already.
//!
//! Measured against rar 7.23 on 8 Oct 2026 (an Apple silicon Mac): `rar
//! a -r o.rar n` stores `n/x\..\..\..\escaped.txt`, `n/back\slash.txt`
//! and `n`, the names byte for byte. On Windows a backslash is the
//! separator, and is still read as one there.
//!
//! **What rarfast does now.** `n/back\slash.txt` is stored under that
//! name, as the reference stores it. A name with a dot-dot part between
//! backslashes is handed to the writer as it is too, and the WRITER
//! refuses it by its own rule for member names: the create stops, names
//! the file and writes nothing. That is not the reference's answer (it
//! stores the name), and it is no longer a member stored somewhere else
//! under another name. Storing it would be a change to the writer's rule
//! for names, not to this command line.
//!
//! The names are read back from the archive's own bytes, where a stored
//! name stands as it was given, so that no lister's rendering of a
//! backslash stands between the create and this test.
//!
//! One run, `-mt2` over two files of two bytes: a pool two threads wide
//! and a few KiB of memory.

#![cfg(unix)]

use std::process::{Command, Stdio};

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|part| part == needle)
}

fn work(tag: &str, names: &[&str]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-backslash-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("n")).unwrap();
    for name in names {
        std::fs::write(dir.join("n").join(name), b"y\n").unwrap();
    }
    dir
}

fn create(dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(["a", "-r", "-idq", "-mt2", "-m0", "o.rar", "n"])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_backslash_in_a_name_is_stored_as_it_is() {
    let dir = work("plain", &[r"back\slash.txt", "plain.txt"]);
    let run = create(&dir);
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let archive = std::fs::read(dir.join("o.rar")).unwrap();
    assert!(holds(&archive, br"n/back\slash.txt"));
    assert!(!holds(&archive, b"n/back/slash.txt"));
    assert!(holds(&archive, b"n/plain.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The item's own name. Until 8 Oct 2026 it was stored as `escaped.txt`,
/// outside `n`, exit 0. The reference stores it as it is; here the
/// writer's rule for names refuses it, by name, and nothing is written.
#[test]
fn a_dot_dot_part_between_backslashes_is_never_stored_elsewhere() {
    let dir = work("climb", &[r"x\..\..\..\escaped.txt", "plain.txt"]);
    let run = create(&dir);
    let warned = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(2), "{warned}");
    assert!(warned.contains(r"n/x\..\..\..\escaped.txt"), "{warned}");
    assert!(!dir.join("o.rar").exists(), "an archive was written");
    let _ = std::fs::remove_dir_all(&dir);
}
