//! How the unrar dialect SHOWS a member name holding a backslash, a NUL,
//! a control character or bytes that are not UTF-8, in every listing
//! (`l`, `v`, `lt`, `lb`) and on the `t` progress line.
//!
//! Every expectation here was MEASURED against reference unrar 7.23 in a
//! UTF-8 locale on Linux (a small x86-64 VPS) and macOS (an M3 Mac), 27 Sep
//! 2026, over archives built exactly as [`rar5`] builds them and over the RAR 4
//! archives in `tests/listing-names/`, written by rar 4.2.0 from real
//! files (`make.sh` there). Where the two hosts differ the test says
//! which it expects. The whole sweep was measured against the reference first.

#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WINDOWS: u8 = 0;
const UNIX: u8 = 1;
/// A host byte RAR 5 does not name.
const OTHER: u8 = 3;
const HOSTS: [u8; 3] = [WINDOWS, UNIX, OTHER];

/// The two measured hosts part ways only where the C library converts
/// text: macOS gives up on what it cannot convert, glibc replaces it.
const APPLE: bool = cfg!(any(target_os = "macos", target_os = "ios"));

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

/// A stored RAR 5 archive of one two-byte file named `name` under `host`
/// (spec F 3.2): the archive the measurements used.
fn rar5(host: u8, name: &[u8]) -> Vec<u8> {
    let data = b"0\n";
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    let mut body = Vec::new();
    vint(2, &mut body); // file header
    vint(0x0002, &mut body); // a data area follows
    vint(data.len() as u64, &mut body);
    vint(0x0006, &mut body); // mtime and CRC32 present
    vint(data.len() as u64, &mut body);
    vint(if host == UNIX { 0o100_644 } else { 0x20 }, &mut body);
    body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
    body.extend_from_slice(&crc32(data).to_le_bytes());
    vint(0, &mut body); // stored
    vint(u64::from(host), &mut body);
    vint(name.len() as u64, &mut body);
    body.extend_from_slice(name);
    block(&body, data, &mut out);
    block(&[5, 0, 0], &[], &mut out);
    out
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/listing-names")
        .join(name)
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-lnames-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast <cmd> <archive>`, in the zone the measurements were read in.
fn run(cmd: &str, archive: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .arg(cmd)
        .arg(archive)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

/// The bytes between the `start` rule and the one after it, less the
/// `skip` bytes of columns before the name.
fn row_name(out: &[u8], rule: &[u8], skip: usize) -> Vec<u8> {
    let find = |from: usize, what: &[u8]| {
        out[from..]
            .windows(what.len())
            .position(|w| w == what)
            .map(|at| at + from)
    };
    let start = find(0, rule).expect("a rule") + rule.len() + 1;
    let end = find(start, &[b"\n", rule].concat()).expect("a closing rule");
    out[start..end][skip..].to_vec()
}

/// The name each of `lb`, `l`, `v` and `lt` shows for the one member of
/// `archive`, `None` where the layout printed no name at all.
fn shown(archive: &Path) -> [Option<Vec<u8>>; 4] {
    let lb = run("lb", archive).stdout;
    let lb = lb.strip_suffix(b"\n").map(<[u8]>::to_vec);
    let l = row_name(
        &run("l", archive).stdout,
        b"----------- ----------  ---------- -----  ----",
        // Marker, attributes, size, two spaces, a 16-character stamp and
        // two more spaces.
        42,
    );
    let v = row_name(
        &run("v", archive).stdout,
        b"----------- ---------- ---------- ----- ---------- -----  --------  ----",
        68,
    );
    let lt = run("lt", archive).stdout;
    let label = b"        Name: ";
    let lt = lt.windows(label.len()).position(|w| w == label).map(|at| {
        let rest = &lt[at + label.len()..];
        let end = rest
            .windows(15)
            .position(|w| w == b"\n        Type: ")
            .unwrap();
        rest[..end].to_vec()
    });
    // `l` and `v` print a row whatever the name; an unprintable one is an
    // empty name there.
    [lb, Some(l), Some(v), lt]
}

/// Lists one member named `raw` under `host` in every layout and holds
/// each to `want` (`None`: the reference printed no name).
fn check(tag: &str, host: u8, raw: &[u8], want: Option<&[u8]>) {
    let dir = work(tag);
    let arc = dir.join("arc.rar");
    std::fs::write(&arc, rar5(host, raw)).unwrap();
    let [lb, l, v, lt] = shown(&arc);
    let want = want.map(<[u8]>::to_vec);
    let empty = Some(want.clone().unwrap_or_default());
    assert_eq!(lb, want, "lb, host {host}, {raw:?}");
    assert_eq!(l, empty, "l, host {host}, {raw:?}");
    assert_eq!(v, empty, "v, host {host}, {raw:?}");
    assert_eq!(lt, want, "lt, host {host}, {raw:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every control character lists as the byte it is, under every host,
/// except ESC, which the reference writes as the six characters `'\033'`
/// wherever it prints one. Before this, rarfast listed `a\tb` as the four
/// characters `a\tb` and ESC as `\u{1b}`.
#[test]
fn every_control_character_but_esc_lists_as_the_byte_it_is() {
    for c in (0x01..0x20_u8).chain([0x7F]) {
        let raw = [b'a', c, b'b'];
        let want: Vec<u8> = if c == 0x1B {
            b"a'\\033'b".to_vec()
        } else {
            raw.to_vec()
        };
        for host in HOSTS {
            check(&format!("c{c:02x}-{host}"), host, &raw, Some(&want));
        }
    }
    // Two in a row, and one ending the name, keep their places.
    check("esc-seq", UNIX, b"a\x1b[31mred", Some(b"a'\\033'[31mred"));
    check("ctl-dir", UNIX, b"d\x01/f", Some(b"d\x01/f"));
    check("tab-alone", UNIX, b"\t", Some(b"\t"));
}

/// A RAR 5 name's `\` lists as the `\` it is, except under host byte 0
/// (Windows), where it lists as `_`: the name it is written under. Before
/// this, rarfast listed every `\` as `/`.
#[test]
fn a_backslash_lists_as_itself_except_from_windows() {
    for (raw, unix, windows) in [
        (&b"a\\b"[..], &b"a\\b"[..], &b"a_b"[..]),
        (b"\\", b"\\", b"_"),
        (b"a\\", b"a\\", b"a_"),
        (b"a/b\\c", b"a/b\\c", b"a/b_c"),
    ] {
        check("bs-u", UNIX, raw, Some(unix));
        check("bs-o", OTHER, raw, Some(unix));
        check("bs-w", WINDOWS, raw, Some(windows));
    }
}

/// A RAR 5 name is decoded as the reference decodes UTF-8: an overlong
/// form is the character it spells, a code point above U+10FFFF is
/// dropped and the name goes on, and the name ends at a NUL or at a byte
/// that starts nothing the decoder takes. Everything else, noncharacters
/// and C1 controls included, lists as it is. Before this, rarfast showed a
/// NUL as `\0` and a bad byte as U+FFFD and went on.
#[test]
fn a_rar5_name_lists_up_to_where_the_reference_decoder_stops() {
    for (raw, want) in [
        (&b"a\x00b"[..], &b"a"[..]),
        (b"\x00x", b""),
        (b"d\x00/x", b"d"),
        (b"a\xffb", b"a"),
        (b"\xc3", b""),
        (b"caf\xe9", b"caf"),
        (b"a\x80b", b"a"),
        (b"a\xc3bc", b"a"),
        (b"a\xe2\x82b", b"a"),
        (b"a\xf8\x88\x80\x80\x80b", b"a"),
        (b"a\xfc\x84\x80\x80\x80\x80b", b"a"),
        (b"d\xff/f", b"d"),
        (b"a\xc0\xafb", b"a/b"),
        (b"a\xe0\x80\xafb", b"a/b"),
        (b"a\xf0\x80\x80\xafb", b"a/b"),
        (b"a\xc1\x81b", b"aAb"),
        (b"a\xc0\x80b", b"a"),
        (b"a\xf4\x90\x80\x80b", b"ab"),
        (b"a\xf5\x80\x80\x80b", b"ab"),
        (b"a\xf4\x8f\xbf\xbfb", b"a\xf4\x8f\xbf\xbfb"),
        (b"a\xef\xbf\xbeb", b"a\xef\xbf\xbeb"),
        (b"a\xef\xbf\xbfb", b"a\xef\xbf\xbfb"),
        (b"a\xc2\x80b", b"a\xc2\x80b"),
        (b"a\xc2\x85b", b"a\xc2\x85b"),
        (b"a\xc2\x9bb", b"a\xc2\x9bb"),
        (b"a\xe2\x80\xaeb", b"a\xe2\x80\xaeb"),
        (b"caf\xc3\xa9", b"caf\xc3\xa9"),
        (b"\xe6\x96\x87\xe5\xad\x97", b"\xe6\x96\x87\xe5\xad\x97"),
        (b"a\xf0\x9f\x98\x80b", b"a\xf0\x9f\x98\x80b"),
    ] {
        check("dec", UNIX, raw, Some(want));
    }
}

/// A UTF-16 surrogate (as UTF-8 would spell one, which the reference's
/// decoder takes) lists as `?` on Linux. On macOS the reference cannot
/// print the name at all: `lt` loses its `Name:` line, `lb` its line, and
/// `l` and `v` show the row with no name.
#[test]
fn a_surrogate_lists_as_a_question_mark_on_linux_and_not_at_all_on_macos() {
    for (raw, linux) in [
        (&b"a\xed\xa0\x80b"[..], &b"a?b"[..]),
        (b"a\xed\xb0\x80b", b"a?b"),
        (b"a\xed\xa0\xbd\xed\xb8\x80b", b"a??b"),
        (b"a\xed\xa0\x80", b"a?"),
        (b"d\xed\xa0\x80/f", b"d?/f"),
    ] {
        check("sur", UNIX, raw, (!APPLE).then_some(linux));
    }
}

/// A RAR 4 name (rar 4.2.0, from real files on Linux) lists with its `\`
/// as the separator it is there, its control characters as in RAR 5, and
/// its bytes that are not UTF-8 read through the C library: on Linux each
/// is U+E000 plus the byte, with one U+FFFE before the first; on macOS
/// the name ends at the first. Before this, rarfast showed U+FFFD and
/// went on, on both.
#[test]
fn a_rar4_name_lists_as_the_reference_reads_its_bytes() {
    let fffe = "\u{FFFE}";
    let byte = |b: u32| char::from_u32(0xE000 + b).unwrap().to_string();
    for (file, linux, macos) in [
        ("r4-tab.rar", "a\tb".to_owned(), "a\tb"),
        ("r4-esc.rar", "a'\\033'b".to_owned(), "a'\\033'b"),
        ("r4-bs.rar", "a/b".to_owned(), "a/b"),
        ("r4-utf8.rar", "caf\u{e9}".to_owned(), "caf\u{e9}"),
        ("r4-latin1.rar", format!("caf{fffe}{}", byte(0xE9)), "caf"),
        (
            "r4-two.rar",
            format!("{fffe}{}{}", byte(0xE9), byte(0xE8)),
            "",
        ),
        (
            "r4-split.rar",
            format!("a{fffe}{}b{}c", byte(0xE9), byte(0xE8)),
            "a",
        ),
        (
            "r4-mixed.rar",
            format!("a{fffe}{}b\u{e9}c", byte(0xE9)),
            "a",
        ),
        ("r4-cont.rar", format!("a{fffe}{}b", byte(0x80)), "a"),
    ] {
        let want = if APPLE { macos.to_owned() } else { linux };
        let [lb, l, v, lt] = shown(&fixture(file));
        for (layout, got) in [("lb", lb), ("l", l), ("v", v), ("lt", lt)] {
            assert_eq!(
                got.as_deref(),
                Some(want.as_bytes()),
                "{layout} of {file}: {:?}",
                got.as_deref().map(String::from_utf8_lossy)
            );
        }
    }
}

/// The `t` line shows the name the listing shows, and pads it counting
/// an ESC as ONE character: the reference writes `'\033'` after laying
/// the line out, so `a<ESC>b` and `a<TAB>b` pad alike.
#[test]
fn the_test_line_shows_the_listed_name_and_pads_an_esc_as_one_character() {
    let dir = work("tline");
    let line = |raw: &[u8]| {
        let arc = dir.join("arc.rar");
        std::fs::write(&arc, rar5(UNIX, raw)).unwrap();
        let out = run("t", &arc);
        assert!(out.status.success(), "{out:?}");
        let text = out.stdout;
        let at = text
            .windows(8)
            .position(|w| w == b"Testing ")
            .map(|at| at + 1)
            .and_then(|from| {
                text[from..]
                    .windows(8)
                    .position(|w| w == b"Testing ")
                    .map(|at| at + from)
            })
            .expect("a member line");
        let end = at + text[at..].iter().position(|&b| b == 0x08).unwrap();
        text[at..end].to_vec()
    };
    let tab = line(b"a\tb");
    let esc = line(b"a\x1bb");
    assert!(tab.starts_with(b"Testing     a\tb "), "{tab:?}");
    assert_eq!(
        esc,
        [&b"Testing     a'\\033'b"[..], &tab[15..]].concat(),
        "{:?}",
        String::from_utf8_lossy(&esc)
    );
    assert!(line(b"a\\b").starts_with(b"Testing     a\\b "));
    let _ = std::fs::remove_dir_all(&dir);
}

/// ESC is written out in whatever the reference prints, not only in
/// names: an archive comment, the archive's own path on the `Archive:`
/// line, and the stderr line for an archive that is not there. Every
/// other control character in the comment goes out as it is.
#[test]
fn an_esc_is_written_out_in_a_comment_and_in_the_archive_s_path() {
    let listed = run("l", &fixture("cmt-esc.rar"));
    assert!(listed.status.success(), "{listed:?}");
    let text = listed.stdout;
    let comment = b"\nArchive comment:\ncmt'\\033'[31mred\x01\tx\n\n\nArchive: ";
    assert!(
        text.windows(comment.len()).any(|w| w == comment),
        "{:?}",
        String::from_utf8_lossy(&text)
    );

    let dir = work("escpath");
    let named = dir.join(OsStr::from_bytes(b"e\x1bx.rar"));
    std::fs::copy(fixture("r4-tab.rar"), &named).unwrap();
    let listed = run("l", &named);
    assert!(listed.status.success(), "{listed:?}");
    assert!(!listed.stdout.contains(&0x1B), "{listed:?}");
    let header = b"e'\\033'x.rar\nDetails: ";
    assert!(
        listed.stdout.windows(header.len()).any(|w| w == header),
        "{:?}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let missing = dir.join(OsStr::from_bytes(b"nope\x1by.rar"));
    let refused = run("l", &missing);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!refused.stderr.contains(&0x1B), "{refused:?}");
    let named = b"nope'\\033'y.rar";
    assert!(
        refused.stderr.windows(named.len()).any(|w| w == named),
        "{:?}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
