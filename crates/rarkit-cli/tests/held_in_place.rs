//! A held member written IN PLACE over a file of its name (`Run::write_held`,
//! `-o+`, a member of at most `HOLD_BOUND`) on Windows does not EMPTY that
//! file first (FROM-STUDIO 552 A, 553: the x-audio2 form). It writes its
//! bytes from offset 0 over what is there and cuts the file to its length
//! only where the old file was longer; the file ends holding exactly the
//! member's bytes, on every system.
//!
//! The shape is x-audio2's, small: `e` of eight members of one name, 16,000
//! bytes each, so every member after the first lands on the file the one
//! before it wrote and closed. Counted on a Windows PC (the eighth reading
//! lane, 17 Oct 2026), emptying that just-closed file cost 941 us a member.
//!
//! It reads `RARFAST_IN_PLACE_SAY=1`, which only an `h2-probes` build says
//! (`safepath::say_in_place`): `held` for each held member written in place
//! (every system), `emptied` where the Windows in-place open empties the
//! file, and `cut` where the held write cuts a longer old file to its
//! length. Any box width; under a megabyte of disk and memory.

#![cfg(feature = "h2-probes")]

use std::path::{Path, PathBuf};
use std::process::Command;

const MEMBERS: usize = 8;
const SIZE: usize = 16_000;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-held-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic incompressible bytes, one stream a seed.
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// `arc.rar` in `dir`: [`MEMBERS`] members `d<i>/a.bin` of [`SIZE`] bytes,
/// stored; returns the last member's bytes, which `e` leaves at `a.bin`.
fn archive(dir: &Path) -> Vec<u8> {
    let src = dir.join("src");
    let mut names = Vec::new();
    let mut last = Vec::new();
    for i in 0..MEMBERS {
        let sub = src.join(format!("d{i}"));
        std::fs::create_dir_all(&sub).unwrap();
        last = bytes(SIZE, 0x2026_1017 + i as u64);
        std::fs::write(sub.join("a.bin"), &last).unwrap();
        names.push(format!("d{i}/a.bin"));
    }
    let mut args = vec!["a", "-idq", "-y", "-m0", "../arc.rar"];
    args.extend(names.iter().map(String::as_str));
    let made = Command::new(rarfast())
        .args(&args)
        .current_dir(&src)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    std::fs::remove_dir_all(&src).unwrap();
    last
}

/// `e -o+` of `arc.rar` into `out/`, which holds `a.bin` of `before` bytes
/// first where given; the counts of each `rarfast in place:` line.
fn extract(dir: &Path, before: Option<usize>) -> (usize, usize, usize) {
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    if let Some(len) = before {
        std::fs::write(out.join("a.bin"), bytes(len, 7)).unwrap();
    }
    let ran = Command::new(rarfast())
        .args(["e", "-idq", "-o+", "-y", "arc.rar", "out/"])
        .env("RARFAST_IN_PLACE_SAY", "1")
        .current_dir(dir)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&ran.stderr);
    assert!(ran.status.success(), "{before:?}: {said}");
    let count = |what: &str| {
        said.lines()
            .filter(|line| *line == format!("rarfast in place: {what}"))
            .count()
    };
    (count("held"), count("emptied"), count("cut"))
}

#[test]
fn a_held_member_is_written_over_its_name_without_emptying_it_first() {
    let dir = work("one-name");
    let last = archive(&dir);
    // `before`: no file (the first member is a fresh create, the other
    // seven are held), an old file LONGER than a member, a shorter one.
    for (before, held, cut) in [
        (None, MEMBERS - 1, 0),
        (Some(40_000), MEMBERS, 1),
        (Some(100), MEMBERS, 0),
    ] {
        let (said_held, emptied, said_cut) = extract(&dir, before);
        // Every system: the held path is the one taken, and the file ends
        // holding exactly the last member's bytes at exactly its length.
        assert_eq!(said_held, held, "{before:?}: members written in place");
        let got = std::fs::read(dir.join("out").join("a.bin")).unwrap();
        assert_eq!(got.len(), SIZE, "{before:?}: the length");
        assert!(got == last, "{before:?}: the bytes");
        // Windows: the in-place open empties nothing, and the held write
        // cuts only the one old file that was longer than its member.
        if cfg!(windows) {
            assert_eq!(emptied, 0, "{before:?}: files emptied before the write");
            assert_eq!(said_cut, cut, "{before:?}: files cut to the member");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
