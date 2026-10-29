//! `rarfast` over a RAR 5 member whose encryption record flags a password
//! check record that the record no longer holds: the check is ABSENT
//! (SPEC-K 3.7.3 step 1), the member is read with the password given and
//! its own data checksum judges it.
//!
//! Every input is made here: `rarfast a -pPASS` writes a sound archive of
//! two members and the test drops the twelve bytes of a member's check
//! record, the flag left set, with the record's, the extra area's and the
//! header's sizes and the header's checksum redone. What the reference
//! does was measured with unrar 7.23 on a Mac on 9 Oct 2026 over genuine
//! `rar` archives edited the same way:
//!
//! | The edit | right password | wrong password |
//! |---|---|---|
//! | one member's check record dropped | every member `OK`, exit 0 | `Incorrect password`, exit 11 (the other member's check refuses it) |
//! | every member's dropped | every member `OK`, exit 0 | `Checksum error in the encrypted file <name>. Corrupt file or wrong password.` for each, nothing written, exit 3 |
//!
//! Before, the member under the short record was refused under the right
//! password and the run exited 3.
//!
//! Every run is `-mt2` (a pool two threads wide) under the default memory
//! policy; the archive is under 64 KiB.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-checkcut-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const MEMBERS: [(&str, usize); 2] = [("a.txt", 3_000), ("b.txt", 40_000)];

/// Text that compresses, different for each seed.
fn body(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(format!("w{:03} ", state % 700).as_bytes());
    }
    out.truncate(len);
    out
}

/// `rarfast a -pPASS` over the two members: the archive's bytes.
fn archive(dir: &Path) -> Vec<u8> {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for (index, (name, len)) in MEMBERS.iter().enumerate() {
        std::fs::write(src.join(name), body(index as u32 + 1, *len)).unwrap();
    }
    let made = dir.join("made.rar");
    let out = Command::new(rarfast())
        .current_dir(&src)
        .args(["a", "-idq", "-ma5", "-m3", "-pPASS"])
        .arg(&made)
        .args(MEMBERS.iter().map(|(name, _)| *name))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    let bytes = std::fs::read(&made).unwrap();
    std::fs::remove_file(&made).unwrap();
    std::fs::remove_dir_all(&src).unwrap();
    bytes
}

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    value
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |mut crc, &byte| {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
        crc
    })
}

/// `archive` with the check record dropped from the encryption record of
/// each FILE header numbered in `which`, its flag left set, and every
/// size and the header checksum redone.
fn cut(archive: &[u8], which: &[usize]) -> Vec<u8> {
    let mut out = archive[..8].to_vec();
    let (mut at, mut file, mut edits) = (8, 0, 0);
    while at < archive.len() {
        at += 4;
        let size = vint(archive, &mut at) as usize;
        let head = &archive[at..at + size];
        at += size;
        let mut p = 0;
        let kind = vint(head, &mut p);
        let flags = vint(head, &mut p);
        let extra = if flags & 1 != 0 {
            vint(head, &mut p) as usize
        } else {
            0
        };
        let data = if flags & 2 != 0 {
            vint(head, &mut p) as usize
        } else {
            0
        };
        let fields = &head[p..head.len() - extra];
        let mut records = head[head.len() - extra..].to_vec();
        if kind == 2 {
            if which.contains(&file) {
                let old = std::mem::take(&mut records);
                let mut q = 0;
                while q < old.len() {
                    let len = vint(&old, &mut q) as usize;
                    let mut record = &old[q..q + len];
                    q += len;
                    // Type 1, version 0, a flags byte with the check bit,
                    // the count, the salt, the IV and the check record.
                    if record[0] == 1 {
                        assert_eq!(record[1], 0, "the record's version");
                        assert_eq!(record[2] & 1, 1, "the check flag");
                        assert_eq!(record.len(), 4 + 16 + 16 + 12);
                        record = &record[..record.len() - 12];
                        edits += 1;
                    }
                    put_vint(&mut records, record.len() as u64);
                    records.extend_from_slice(record);
                }
            }
            file += 1;
        }
        let mut body = Vec::new();
        put_vint(&mut body, kind);
        put_vint(&mut body, flags);
        if flags & 1 != 0 {
            put_vint(&mut body, records.len() as u64);
        }
        if flags & 2 != 0 {
            put_vint(&mut body, data as u64);
        }
        body.extend_from_slice(fields);
        body.extend_from_slice(&records);
        let mut sized = Vec::new();
        put_vint(&mut sized, body.len() as u64);
        sized.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
        out.extend_from_slice(&archive[at..at + data]);
        at += data;
    }
    assert_eq!(file, MEMBERS.len(), "the FILE headers walked");
    assert_eq!(edits, which.len(), "the records cut");
    out
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Which members `t` called `OK`.
fn oks(stdout: &str) -> Vec<&'static str> {
    MEMBERS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| {
            stdout
                .lines()
                .any(|line| line.contains(name) && line.trim_end().ends_with("OK"))
        })
        .collect()
}

/// Which members `out` holds whole and right.
fn delivered(out: &Path) -> Vec<&'static str> {
    MEMBERS
        .iter()
        .enumerate()
        .filter(|(index, (name, len))| {
            std::fs::read(out.join(name)).ok() == Some(body(*index as u32 + 1, *len))
        })
        .map(|(_, (name, _))| *name)
        .collect()
}

/// Under the right password a member whose check record is gone is
/// listed, tested `OK` and extracted right, and the run exits 0.
#[test]
fn a_dropped_check_record_is_absent_and_the_member_is_read() {
    let dir = work("right");
    let sound = archive(&dir);
    for which in [&[1][..], &[0, 1][..]] {
        std::fs::write(dir.join("a.rar"), cut(&sound, which)).unwrap();
        let ran = run(&dir, &["l", "-pPASS", "a.rar"]);
        assert_eq!(
            ran.code,
            Some(0),
            "{which:?}: {} {}",
            ran.stdout,
            ran.stderr
        );
        for (name, _) in MEMBERS {
            assert!(ran.stdout.contains(name), "{which:?}: {}", ran.stdout);
        }
        let ran = run(&dir, &["t", "-mt2", "-pPASS", "a.rar"]);
        assert_eq!(
            ran.code,
            Some(0),
            "{which:?}: {} {}",
            ran.stdout,
            ran.stderr
        );
        assert_eq!(oks(&ran.stdout), ["a.txt", "b.txt"], "{which:?}");
        let _ = std::fs::remove_dir_all(dir.join("out"));
        let ran = run(&dir, &["x", "-mt2", "-pPASS", "-o+", "a.rar", "out/"]);
        assert_eq!(
            ran.code,
            Some(0),
            "{which:?}: {} {}",
            ran.stdout,
            ran.stderr
        );
        assert_eq!(delivered(&dir.join("out")), ["a.txt", "b.txt"], "{which:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under a wrong password no member is called `OK` and none is written.
/// With every check record gone the data checksums alone say so, in the
/// words that name both causes, exit 3; with one left, that one refuses
/// the password, exit 11.
#[test]
fn a_wrong_password_on_a_dropped_check_record_is_never_ok() {
    let dir = work("wrong");
    let sound = archive(&dir);

    std::fs::write(dir.join("a.rar"), cut(&sound, &[0, 1])).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-pWRONG", "a.rar"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    assert!(oks(&ran.stdout).is_empty(), "{}", ran.stdout);
    for (name, _) in MEMBERS {
        let line =
            format!("Checksum error in the encrypted file {name}. Corrupt file or wrong password.");
        assert!(ran.stderr.contains(&line), "{}", ran.stderr);
    }
    let ran = run(&dir, &["x", "-mt2", "-pWRONG", "-o+", "a.rar", "out/"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    for (name, _) in MEMBERS {
        assert!(!dir.join("out").join(name).exists(), "{name} was left");
    }

    std::fs::write(dir.join("a.rar"), cut(&sound, &[1])).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-pWRONG", "a.rar"]);
    assert_eq!(ran.code, Some(11), "{} {}", ran.stdout, ran.stderr);
    assert!(oks(&ran.stdout).is_empty(), "{}", ran.stdout);
    let ran = run(&dir, &["x", "-mt2", "-pWRONG", "-o+", "a.rar", "out/"]);
    assert_eq!(ran.code, Some(11), "{} {}", ran.stdout, ran.stderr);
    for (name, _) in MEMBERS {
        assert!(!dir.join("out").join(name).exists(), "{name} was left");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
