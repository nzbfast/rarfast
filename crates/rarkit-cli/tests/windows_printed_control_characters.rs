//! What a Windows build prints for archive-supplied text that holds a
//! control character: nothing an archive supplies may drive a console.
//!
//! Read from the tool's own printing code and SPEC-CLI section 7, not
//! measured against any other program:
//!
//! - a member NAME, in every listing (`lb`, `l`, `v`, `lt`), on the `t`
//!   and `x` progress lines and on a member's error line, shows each
//!   control character as its stand-in, the eight characters `<U+XXXX>`
//!   of SPEC-CLI section 7, and it does so into a pipe, which is where
//!   a test reads it. Pinned on 10 Oct 2026 as it stood;
//! - the same holds for a name on the `Deleting`, `Renaming` and `Found`
//!   lines of `d`, `rn` and `r` and on the `Unknown method` line, which
//!   until the commit after this test's went out as the name's own
//!   bytes, an ESC included;
//! - an archive COMMENT, in a listing and from `cw`, keeps its line
//!   ends and its tabs and shows every other control character as its
//!   stand-in; until the same commit it too went out as its own bytes.
//!
//! The rows that were raw run on every system, and say what each
//! prints: on macOS and Linux a name and a comment are still their own
//! bytes but for an ESC, written as the six characters `'\033'`.
//!
//! Each run is one process of one thread's work on a two-byte member;
//! no pool width and no memory beyond the tool's floor is assumed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// One block: CRC32, size, then `body` (spec F 3.2.2), then `data`.
fn block(body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
}

/// A stored RAR 5 archive of one two-byte file named `name`, written
/// from a Unix host (spec F 3.2). `sound` false stores a CRC32 the data
/// does not have, so the member fails its check.
fn rar5(name: &[u8], sound: bool) -> Vec<u8> {
    rar5_packed(name, sound, 0)
}

/// [`rar5`] with `packing` as the header's compression word: 0 is
/// stored, its low six bits are the version of the algorithm and bits
/// 7 to 9 the method.
fn rar5_packed(name: &[u8], sound: bool, packing: u64) -> Vec<u8> {
    let data = b"0\n";
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    let mut body = Vec::new();
    vint(2, &mut body); // file header
    vint(0x0002, &mut body); // a data area follows
    vint(data.len() as u64, &mut body);
    vint(0x0006, &mut body); // mtime and CRC32 present
    vint(data.len() as u64, &mut body);
    vint(0o100_644, &mut body);
    body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
    let check = if sound { crc32(data) } else { !crc32(data) };
    body.extend_from_slice(&check.to_le_bytes());
    vint(packing, &mut body);
    vint(1, &mut body); // host: Unix
    vint(name.len() as u64, &mut body);
    body.extend_from_slice(name);
    block(&body, data, &mut out);
    block(&[5, 0, 0], &[], &mut out);
    out
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-winctl-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast <args>` run in `dir`, both streams taken through pipes.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

fn holds(all: &[u8], part: &[u8]) -> bool {
    all.windows(part.len()).any(|w| w == part)
}

/// Both streams of `out` end to end.
fn said(out: &Output) -> Vec<u8> {
    [&out.stdout[..], &out.stderr[..]].concat()
}

/// Every listing and the `t` line show a name's control character as
/// its stand-in and never as the byte, for one character of each kind
/// section 7 names: C0 (a tab, an ESC), DEL, and C1 (U+0085).
#[cfg(windows)]
#[test]
fn a_listed_or_tested_name_shows_a_stand_in_and_never_the_byte() {
    for (tag, name, shown, raw) in [
        ("tab", &b"a\tb"[..], &b"a<U+0009>b"[..], &b"a\tb"[..]),
        ("esc", b"a\x1bb", b"a<U+001B>b", b"\x1b"),
        ("del", b"a\x7fb", b"a<U+007F>b", b"\x7f"),
        ("c1", b"a\xc2\x85b", b"a<U+0085>b", b"\xc2\x85"),
    ] {
        let dir = work(tag);
        std::fs::write(dir.join("arc.rar"), rar5(name, true)).unwrap();
        for cmd in ["lb", "l", "v", "lt", "t"] {
            let out = run(&dir, &[cmd, "arc.rar"]);
            assert!(out.status.success(), "{cmd} {tag}: {out:?}");
            assert!(holds(&out.stdout, shown), "{cmd} {tag}: {out:?}");
            assert!(!holds(&said(&out), raw), "{cmd} {tag}: {out:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The `x` progress line shows the name WRITTEN. A DEL is a character a
/// Windows name may hold, so it is written and shown as its stand-in.
#[cfg(windows)]
#[test]
fn an_extracted_name_shows_a_stand_in_and_never_the_byte() {
    let dir = work("x-del");
    std::fs::write(dir.join("arc.rar"), rar5(b"a\x7fb", true)).unwrap();
    let out = run(&dir, &["x", "arc.rar"]);
    assert!(holds(&out.stdout, b"a<U+007F>b"), "{out:?}");
    assert!(!holds(&said(&out), b"\x7f"), "{out:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A member that fails its check is named on its error line the same
/// way, on whichever stream the line goes to.
#[cfg(windows)]
#[test]
fn an_error_line_names_its_member_with_a_stand_in() {
    let dir = work("bad");
    std::fs::write(dir.join("arc.rar"), rar5(b"a\x1bb", false)).unwrap();
    let out = run(&dir, &["t", "arc.rar"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(holds(&said(&out), b"a<U+001B>b"), "{out:?}");
    assert!(!holds(&said(&out), b"\x1b"), "{out:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `win` on Windows, `other` on every other system.
fn by_system<'a>(win: &'a [u8], other: &'a [u8]) -> &'a [u8] {
    if cfg!(windows) {
        win
    } else {
        other
    }
}

/// The fixture's comment is `cmt`, ESC, `[31mred`, U+0001, a tab, `x`
/// and a line feed. Its tab and its line end stay; on Windows the ESC
/// and the U+0001 are stand-ins, in a listing and from `cw` alike.
#[test]
fn a_comment_keeps_its_lines_and_tabs_and_nothing_else_that_acts() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listing-names/cmt-esc.rar");
    let dir = work("cmt");
    std::fs::copy(fixture, dir.join("arc.rar")).unwrap();
    let shown = by_system(
        b"cmt<U+001B>[31mred<U+0001>\tx\n",
        b"cmt'\\033'[31mred\x01\tx\n",
    );
    for cmd in ["l", "cw"] {
        let out = run(&dir, &[cmd, "arc.rar"]);
        assert!(out.status.success(), "{cmd}: {out:?}");
        assert!(holds(&out.stdout, shown), "{cmd}: {out:?}");
        assert!(!holds(&said(&out), b"\x1b"), "{cmd}: {out:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `d`, `rn` and `r` name a member on a line of their own, and none of
/// them prints the name's ESC.
#[test]
fn the_deleting_renaming_and_found_lines_name_a_member_without_its_esc() {
    let name = by_system(b"a<U+001B>b", b"a'\\033'b");
    for (cmd, args, line) in [
        ("d", &["a*"][..], "Deleting "),
        ("rn", &["a*", "q*"][..], "Renaming "),
        ("r", &[][..], "Found  "),
    ] {
        let dir = work(cmd);
        std::fs::write(dir.join("arc.rar"), rar5(b"a\x1bb", true)).unwrap();
        let out = run(&dir, &[&[cmd, "arc.rar"][..], args].concat());
        let want = [line.as_bytes(), name].concat();
        assert!(holds(&said(&out), &want), "{cmd}: {out:?}");
        assert!(!holds(&said(&out), b"\x1b"), "{cmd}: {out:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A member packed by a version of the algorithm no reader knows is
/// named on its `Unknown method` line the same way.
#[test]
fn the_unknown_method_line_names_its_member_without_its_esc() {
    let dir = work("method");
    std::fs::write(dir.join("arc.rar"), rar5_packed(b"a\x1bb", true, 0x80 | 63)).unwrap();
    let out = run(&dir, &["t", "arc.rar"]);
    assert!(!out.status.success(), "{out:?}");
    let want = [
        &b"Unknown method in "[..],
        by_system(b"a<U+001B>b", b"a'\\033'b"),
    ]
    .concat();
    assert!(holds(&said(&out), &want), "{out:?}");
    assert!(!holds(&said(&out), b"\x1b"), "{out:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
