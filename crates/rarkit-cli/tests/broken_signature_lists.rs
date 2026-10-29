//! `l`, `v` and `lt` over a file whose RAR signature has one byte changed.
//!
//! unrar 7.23, run whole on 28 Oct 2026 over a RAR 5 archive and a RAR 4
//! archive with each signature byte changed in turn (XOR 1, and set to
//! zero where that is a change): `<path> is not RAR archive` on standard
//! output, nothing on standard error, exit 0, under all three commands.
//! rarfast does the same, and this file pins it: the listing commands
//! report a file that is not an archive and finish without an error code
//! (the table in `malformed_input_robustness.rs` says so for `l` and `v`).
//!
//! One byte is another thing: the seventh of a RAR 5 signature set to 0x00
//! is the RAR 1.5 signature, so the file IS an archive, whose main header
//! is damaged. unrar says `Main archive header is corrupt` with two
//! `Unexpected end of archive` lines, rarfast `Corrupt header is found`;
//! both exit 3, and the exit is the row here.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-sig-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One small RAR 5 archive, made by rarfast.
fn rar5(dir: &Path) -> Vec<u8> {
    std::fs::write(dir.join("a.txt"), rarkit_testdata::chatter(7, 4 << 10)).unwrap();
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(["a", "-idq", "-ep", "src.rar", "a.txt"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    let bytes = std::fs::read(dir.join("src.rar")).unwrap();
    std::fs::remove_file(dir.join("src.rar")).unwrap();
    std::fs::remove_file(dir.join("a.txt")).unwrap();
    bytes
}

/// A genuine rar 4.2.0 archive from the committed vectors.
fn rar4() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/vectors-J/archives/r420_mixed_nonsolid.rar"),
    )
    .unwrap()
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn list(dir: &Path, command: &str, name: &str) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args([command, name])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Every one byte change of the signature: the byte XOR 1, and zero where
/// that differs from it.
fn broken(bytes: &[u8], len: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for at in 0..len {
        for (how, value) in [("x1", bytes[at] ^ 1), ("zero", 0)] {
            if value == bytes[at] {
                continue;
            }
            let mut changed = bytes.to_vec();
            changed[at] = value;
            out.push((format!("{at}-{how}"), changed));
        }
    }
    out
}

#[test]
fn a_broken_signature_is_not_an_archive_and_lists_exit_0() {
    let dir = work("lists");
    for (family, bytes, len) in [("r5", rar5(&dir), 8), ("r4", rar4(), 7)] {
        for (case, changed) in broken(&bytes, len) {
            let name = format!("{family}-{case}.rar");
            std::fs::write(dir.join(&name), &changed).unwrap();
            let rar15 = changed.starts_with(b"Rar!\x1a\x07\x00");
            for command in ["l", "v", "lt"] {
                let ran = list(&dir, command, &name);
                if rar15 {
                    assert_eq!(ran.code, Some(3), "{name} {command}: {}", ran.stderr);
                    continue;
                }
                assert_eq!(
                    ran.code,
                    Some(0),
                    "{name} {command}: {}{}",
                    ran.stdout,
                    ran.stderr
                );
                assert_eq!(
                    ran.stdout.trim(),
                    format!("{name} is not RAR archive"),
                    "{name} {command}"
                );
                assert_eq!(ran.stderr, "", "{name} {command}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
