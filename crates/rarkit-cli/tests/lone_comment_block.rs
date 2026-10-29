//! A block of type 0x75 standing between blocks of the older container
//! (SPEC-F 3.3.3 B2; SWEEP2-08OCT-15).
//!
//! One whose header is 13 bytes or more and whose checksum fits its
//! offsets 2 to 12 is passed over: `t`, `x` and `lb` read every member and
//! exit 0, as the reference does. Any other is a header whose checksum
//! failed (rule 2, as restated on 9 Oct 2026): it is reported, the walk
//! goes on at the block's offset plus its header size, and the members
//! after it are tested, written and listed, as the reference reads them;
//! the run exits 3, the reference's code, and never says the engine's own
//! name for the block. Until that day the walk stopped at the block and
//! the members after it were lost. Where the block's header is followed by
//! data bytes the next block is read from the first of them and the walk
//! loses its place there, as the reference's does: the member before the
//! block, exit 3.
//!
//! Every archive is built here: three stored members of 6, 12 and 8 bytes.
//! One process at a time, `-mt1`; nothing here holds a megabyte.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-lone-comment-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The standard CRC32, bit by bit: these inputs are a few dozen bytes.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// A block of the older container: its CRC16 is the low half of the
/// CRC32 of everything after the checksum field.
fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, kind];
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
    out.extend_from_slice(body);
    let sum = (crc32(&out[2..]) & 0xffff) as u16;
    out[..2].copy_from_slice(&sum.to_le_bytes());
    out
}

/// A stored member of unpack version 20, header and data.
fn stored(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.push(0);
    body.extend_from_slice(&crc32(data).to_le_bytes());
    body.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
    body.push(20);
    body.push(0x30);
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(&0x20u32.to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    let mut out = block(0x74, 0x8000, &body);
    out.extend_from_slice(data);
    out
}

const MEMBERS: [(&str, &[u8]); 3] = [
    ("a.txt", b"alpha\n"),
    ("b.txt", b"bravo bravo\n"),
    ("c.txt", b"charlie\n"),
];

/// The three members with `comment` between `a.txt` and `b.txt`.
fn archive(comment: &[u8]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend_from_slice(&block(0x73, 0, &[0; 6]));
    for (at, (name, data)) in MEMBERS.iter().enumerate() {
        if at == 1 {
            out.extend_from_slice(comment);
        }
        out.extend_from_slice(&stored(name, data));
    }
    out.extend_from_slice(&block(0x7b, 0x4000, &[]));
    out
}

/// A 13 byte block of type 0x75 holding the six comment fields, its
/// checksum over the eleven bytes after the checksum field.
fn fitting() -> Vec<u8> {
    block(0x75, 0, &[0, 0, 15, 0x30, 0, 0])
}

/// The blocks whose checksum does not fit, each with whether the walk can
/// go on behind it: 9 bytes with flag 0x4000 and without, and 16 bytes
/// with flag 0xC000 and a data length followed by five data bytes, which
/// are the three tracked evidence arms' shapes; and the fitting block with
/// its checksum wrong. Behind the data bytes no header stands.
fn unfitting() -> Vec<(&'static str, Vec<u8>, bool)> {
    let mut wrong = fitting();
    wrong[1] ^= 0x40;
    let mut data = block(0x75, 0xc000, &[5, 0, 0, 0]);
    data.extend_from_slice(b"hello");
    vec![
        ("skip", block(0x75, 0x4000, &[0, 0]), true),
        ("noskip", block(0x75, 0, &[0, 0]), true),
        ("data", data, false),
        ("wrong-checksum", wrong, true),
    ]
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("rarfast runs")
}

fn said(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn a_lone_comment_block_whose_checksum_does_not_fit_is_reported_and_passed_over() {
    for (tag, comment, goes_on) in unfitting() {
        let dir = work(tag);
        std::fs::write(dir.join("x.rar"), archive(&comment)).unwrap();
        // The members the walk reaches: all three behind a block it can
        // pass over, the first alone where data bytes follow the block.
        let reached = if goes_on { 3 } else { 1 };
        for command in ["t", "x"] {
            let out = run(&dir, &[command, "-y", "-mt1", "x.rar"]);
            let text = said(&out);
            assert_eq!(out.status.code(), Some(3), "{tag} {command}: {text}");
            assert!(
                !text.contains("CommentOutsideHeader") && !text.contains("malformed"),
                "{tag} {command}: the engine's own name for it is not said: {text}"
            );
            assert!(!text.contains("All OK"), "{tag} {command}: {text}");
            if goes_on {
                assert!(
                    text.contains("Total errors: 1"),
                    "{tag} {command}: one error counted: {text}"
                );
            }
            for (at, (name, _)) in MEMBERS.iter().enumerate() {
                let ok = text
                    .lines()
                    .any(|line| line.contains(name) && line.trim_end().ends_with("OK"));
                assert_eq!(ok, at < reached, "{tag} {command} {name}: {text}");
            }
        }
        for (at, (name, data)) in MEMBERS.iter().enumerate() {
            let written = std::fs::read(dir.join(name)).ok();
            if at < reached {
                assert_eq!(written.as_deref(), Some(*data), "{tag}: {name}");
            } else {
                assert!(written.is_none(), "{tag}: {name} is not reached");
            }
        }
        let listed = run(&dir, &["lb", "x.rar"]);
        let text = said(&listed);
        assert_eq!(listed.status.code(), Some(3), "{tag} lb: {text}");
        assert!(!text.contains("CommentOutsideHeader"), "{tag} lb: {text}");
        for (at, (name, _)) in MEMBERS.iter().enumerate() {
            assert_eq!(
                text.lines().any(|line| line.trim() == *name),
                at < reached,
                "{tag} lb {name}: {text}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_lone_comment_block_whose_checksum_fits_is_passed_over_with_exit_0() {
    let dir = work("fits");
    std::fs::write(dir.join("x.rar"), archive(&fitting())).unwrap();
    let tested = run(&dir, &["t", "-mt1", "x.rar"]);
    assert_eq!(tested.status.code(), Some(0), "t: {}", said(&tested));
    assert!(said(&tested).contains("All OK"), "t: {}", said(&tested));
    let extracted = run(&dir, &["x", "-y", "-mt1", "x.rar"]);
    assert_eq!(extracted.status.code(), Some(0), "x: {}", said(&extracted));
    for (name, data) in MEMBERS {
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), data, "{name}");
    }
    let listed = run(&dir, &["lb", "x.rar"]);
    assert_eq!(listed.status.code(), Some(0), "lb: {}", said(&listed));
    let names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(names, ["a.txt", "b.txt", "c.txt"], "lb");
    let _ = std::fs::remove_dir_all(&dir);
}
