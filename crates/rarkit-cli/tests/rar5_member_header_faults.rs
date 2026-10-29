//! A RAR 5 file header with a RIGHT checksum whose records, name length
//! or encryption record are not what a writer makes (SWEEP3-08OCT-06 and
//! SWEEP3-08OCT-14): the fault is that member's, never the archive's.
//!
//! Every input is made here: `rarfast a` writes a sound archive of three
//! members and the test rebuilds the second member's header, its size
//! fields and its checksum redone. What the reference does was measured
//! with unrar 7.23 on a Mac on 9 Oct 2026 over the sweep's own inputs
//! (genuine `rar` archives edited the same way):
//!
//! | The second member's header | unrar 7.23 `t` |
//! |---|---|
//! | an extra record of size 0 | all three `OK`, exit 0 |
//! | an extra record whose size runs past the area | the same |
//! | a stray byte behind the records | the same |
//! | an extra area size a few bytes short | the same |
//! | a name length of 200 on a five byte name | the same; the name is read as far as the header goes |
//! | a version record with no number | the same |
//! | a BLAKE2sp hash record cut short | `<name> - checksum error`, the others `OK`, exit 3 |
//! | an encryption record cut short | `Checksum error in the encrypted file <name>. Corrupt file or wrong password.`, the others `OK`, exit 3 |
//! | an encryption record of version 1, or a count of 25 | the others extracted, `Unknown encryption method in f: x1` (`xc25`), `Unknown method in <name>`, `You may need a newer version of RAR.`, exit 2 |
//! | the count of 25 in a LATER fragment's header of a set | every member extracted, `Unknown encryption method in f: xc25`, exit 2 |
//!
//! Before, rarfast ended the walk at such a header (`Corrupt header is
//! found`, that member and every later one lost) or refused the whole
//! archive (`is not RAR archive`, exit 10).
//!
//! One difference is chosen, for safety, and pinned by the last test: a
//! member under a header that is read although its records or name do
//! not fit it is good only by its own data checksum, and with none it
//! fails. A record lost behind the fault could have been the one that
//! carries the member's hash or says it is enciphered.
//!
//! Every run is `-mt2` (a pool two threads wide) under the default memory
//! policy; no archive is over 1 MiB.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-hdrfault-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Half text that compresses, half bytes that do not.
fn body(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len / 2 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(format!("w{:03} ", state % 700).as_bytes());
    }
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state >> 11) as u8);
    }
    out.truncate(len);
    out
}

const MEMBERS: [(&str, usize); 3] = [("a.txt", 3_000), ("b.bin", 90_000), ("c.txt", 4_000)];

/// `rarfast a` over the three members with `switches`; every file written,
/// by name, sorted.
fn archive(dir: &Path, switches: &[&str]) -> Vec<(String, Vec<u8>)> {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for (index, (name, len)) in MEMBERS.iter().enumerate() {
        std::fs::write(src.join(name), body(index as u32 + 1, *len)).unwrap();
    }
    let made = dir.join("made");
    std::fs::create_dir_all(&made).unwrap();
    let mut args = vec!["a".to_owned(), "-idq".to_owned(), "-ma5".to_owned()];
    args.extend(switches.iter().map(|s| (*s).to_owned()));
    args.push(made.join("a.rar").to_str().unwrap().to_owned());
    args.extend(MEMBERS.iter().map(|(name, _)| (*name).to_owned()));
    let out = Command::new(rarfast())
        .current_dir(&src)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&made)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    std::fs::remove_dir_all(&made).unwrap();
    std::fs::remove_dir_all(&src).unwrap();
    files
}

fn vint(bytes: &[u8], mut at: usize) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[at];
        at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, at);
        }
    }
}

fn put_vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

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

/// One RAR 5 file header, taken apart: where it sits, the bytes of its
/// type-specific fields and of its extra area.
struct Header {
    start: usize,
    end: usize,
    flags: u64,
    /// The data size vint as stored, or nothing.
    data_size: Vec<u8>,
    fields: Vec<u8>,
    extra: Vec<u8>,
}

/// Every file header (type 2) of a clear RAR 5 archive, in order.
fn file_headers(bytes: &[u8]) -> Vec<Header> {
    let mut at = 8;
    let mut out = Vec::new();
    while at < bytes.len() {
        let (size, body) = vint(bytes, at + 4);
        let end = body + size as usize;
        let (kind, next) = vint(bytes, body);
        let (flags, mut next) = vint(bytes, next);
        let mut extra = 0usize;
        if flags & 1 != 0 {
            let (value, after) = vint(bytes, next);
            extra = value as usize;
            next = after;
        }
        let data_at = next;
        let mut data = 0usize;
        if flags & 2 != 0 {
            let (value, after) = vint(bytes, next);
            data = value as usize;
            next = after;
        }
        if kind == 2 {
            out.push(Header {
                start: at,
                end,
                flags,
                data_size: bytes[data_at..next].to_vec(),
                fields: bytes[next..end - extra].to_vec(),
                extra: bytes[end - extra..end].to_vec(),
            });
        }
        at = end + data;
    }
    out
}

/// `bytes` with `header` written again from `fields` and `extra`, and an
/// extra area size of `extra_size` (the area's own length unless a test
/// says otherwise): sizes and checksum redone.
fn rebuilt(
    bytes: &[u8],
    header: &Header,
    fields: &[u8],
    extra: &[u8],
    extra_size: usize,
) -> Vec<u8> {
    let mut body = Vec::new();
    put_vint(2, &mut body);
    put_vint(header.flags | 1, &mut body);
    put_vint(extra_size as u64, &mut body);
    body.extend_from_slice(&header.data_size);
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);
    let mut sized = Vec::new();
    put_vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(&body);
    let mut out = bytes[..header.start].to_vec();
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(&bytes[header.end..]);
    out
}

/// The second member's header with `more` put behind its extra records.
fn with_record(bytes: &[u8], more: &[u8]) -> Vec<u8> {
    let header = &file_headers(bytes)[1];
    let mut extra = header.extra.clone();
    extra.extend_from_slice(more);
    rebuilt(bytes, header, &header.fields, &extra, extra.len())
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

/// The six shapes the reference reads as though nothing were wrong.
#[test]
fn a_header_whose_records_or_name_do_not_fit_is_read_and_the_walk_goes_on() {
    let dir = work("soft");
    let sound = archive(&dir, &["-m3"]).remove(0).1;
    let header = &file_headers(&sound)[1];
    assert!(
        header.fields.ends_with(b"\x05b.bin"),
        "the name ends the fields"
    );

    let mut shapes: Vec<(&str, Vec<u8>)> = vec![
        ("a record of size 0", with_record(&sound, &[0x00])),
        ("a record past the area", with_record(&sound, &[0x7f, 0x03])),
        ("a stray byte", with_record(&sound, &[0x80])),
        (
            "a version record with no number",
            with_record(&sound, &[0x02, 0x04, 0x00]),
        ),
    ];
    // The area's size three short: its first three bytes are read as
    // fields, and the records from the fourth.
    let (lost, kept) = header.extra.split_at(3);
    let mut fields = header.fields.clone();
    fields.extend_from_slice(lost);
    shapes.push((
        "an area size three short",
        rebuilt(&sound, header, &fields, kept, kept.len()),
    ));
    // A name length of 200 where five bytes of name are held.
    let mut fields = header.fields[..header.fields.len() - 6].to_vec();
    put_vint(200, &mut fields);
    fields.extend_from_slice(b"b.bin");
    let long_name = rebuilt(&sound, header, &fields, &header.extra, header.extra.len());

    for (what, bytes) in &shapes {
        std::fs::write(dir.join("a.rar"), bytes).unwrap();
        let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
        assert_eq!(ran.code, Some(0), "{what}: {} {}", ran.stdout, ran.stderr);
        assert_eq!(oks(&ran.stdout), ["a.txt", "b.bin", "c.txt"], "{what}");
        assert!(ran.stdout.contains("All OK"), "{what}: {}", ran.stdout);
        assert_eq!(ran.stderr, "", "{what}");
        let _ = std::fs::remove_dir_all(dir.join("out"));
        let ran = run(&dir, &["x", "-mt2", "-p-", "-o+", "a.rar", "out/"]);
        assert_eq!(ran.code, Some(0), "{what}: {} {}", ran.stdout, ran.stderr);
        assert_eq!(
            delivered(&dir.join("out")),
            ["a.txt", "b.bin", "c.txt"],
            "{what}"
        );
    }

    // The long name: three members tested and listed, the second under
    // the name the header's bytes give it as far as the header goes.
    std::fs::write(dir.join("a.rar"), &long_name).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
    assert_eq!(ran.code, Some(0), "{} {}", ran.stdout, ran.stderr);
    assert!(ran.stdout.contains("All OK"), "{}", ran.stdout);
    assert_eq!(ran.stdout.matches("  OK").count(), 3, "{}", ran.stdout);
    let ran = run(&dir, &["lb", "a.rar"]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert!(ran.stdout.starts_with("a.txt\nb.bin"), "{:?}", ran.stdout);
    assert!(ran.stdout.ends_with("c.txt\n"), "{:?}", ran.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two shapes that fail their own member, and no other.
#[test]
fn a_hash_or_encryption_record_cut_short_fails_its_member_alone() {
    let dir = work("short");
    let sound = archive(&dir, &["-m3"]).remove(0).1;

    // A BLAKE2sp hash record (type 2, kind 0) holding ten bytes of 32.
    let mut record = vec![12, 0x02, 0x00];
    record.extend_from_slice(&[0xa5; 10]);
    std::fs::write(dir.join("a.rar"), with_record(&sound, &record)).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    assert_eq!(oks(&ran.stdout), ["a.txt", "c.txt"]);
    assert!(
        ran.stderr.contains("b.bin") && ran.stderr.contains("checksum error"),
        "{}",
        ran.stderr
    );

    // An encryption record (type 1): version 0, flags 0, a count of 15
    // and five bytes of a salt of 16.
    let mut record = vec![9, 0x01, 0x00, 0x00, 15];
    record.extend_from_slice(&[0x5a; 5]);
    std::fs::write(dir.join("a.rar"), with_record(&sound, &record)).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    assert_eq!(oks(&ran.stdout), ["a.txt", "c.txt"]);
    assert!(
        ran.stderr.contains(
            "Checksum error in the encrypted file b.bin. Corrupt file or wrong password."
        ),
        "{}",
        ran.stderr
    );
    let _ = std::fs::remove_dir_all(dir.join("out"));
    let ran = run(&dir, &["x", "-mt2", "-p-", "-o+", "a.rar", "out/"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    assert_eq!(delivered(&dir.join("out")), ["a.txt", "c.txt"]);
    assert!(
        !dir.join("out/b.bin").exists(),
        "nothing is left of the member"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where the count byte of the encryption record (type 1) sits in an
/// extra area: behind the record's size, its type, the version and the
/// flags.
fn count_at(extra: &[u8]) -> usize {
    let mut at = 0;
    loop {
        let (size, body) = vint(extra, at);
        let (kind, fields) = vint(extra, body);
        if kind == 1 {
            let (version, flags) = vint(extra, fields);
            assert_eq!(version, 0);
            return vint(extra, flags).1;
        }
        at = body + size as usize;
    }
}

/// SWEEP3-08OCT-06: a version or a key derivation count the engine does
/// not know refuses that member, with the reference's words and its exit.
#[test]
fn an_unknown_encryption_record_refuses_its_member_alone() {
    let dir = work("unknown");
    let sound = archive(&dir, &["-m3", "-psecret"]).remove(0).1;
    let header = &file_headers(&sound)[1];
    let count = count_at(&header.extra);

    let mut by_count = header.extra.clone();
    by_count[count] = 25;
    let mut by_version = header.extra.clone();
    // The version is the byte two in front of the count (flags between).
    by_version[count - 2] = 1;
    for (what, extra) in [("xc25", by_count), ("x1", by_version)] {
        let bytes = rebuilt(&sound, header, &header.fields, &extra, extra.len());
        std::fs::write(dir.join("a.rar"), bytes).unwrap();
        for command in ["x", "t"] {
            let _ = std::fs::remove_dir_all(dir.join("out"));
            let ran = run(&dir, &[command, "-mt2", "-psecret", "-o+", "a.rar", "out/"]);
            assert_eq!(
                ran.code,
                Some(2),
                "{what} {command}: {} {}",
                ran.stdout,
                ran.stderr
            );
            assert_eq!(oks(&ran.stdout), ["a.txt", "c.txt"], "{what} {command}");
            assert!(
                ran.stdout.contains("Total errors: 3"),
                "{what}: {}",
                ran.stdout
            );
            assert!(
                ran.stderr.ends_with(&format!(
                    "\nUnknown encryption method in f: {what}\nUnknown method in b.bin\nYou may need a newer version of RAR."
                )),
                "{what} {command}: {}",
                ran.stderr
            );
            if command == "x" {
                assert_eq!(delivered(&dir.join("out")), ["a.txt", "c.txt"], "{what}");
                assert!(!dir.join("out/b.bin").exists(), "{what}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same record in a LATER fragment's header keys nothing: the member
/// is delivered whole from its first fragment's record, and the run is
/// still not a success.
#[test]
fn an_unknown_encryption_record_in_a_later_fragment_delivers_the_member_and_exits_2() {
    let dir = work("fragment");
    let set = archive(&dir, &["-m0", "-psecret", "-v40k"]);
    assert!(set.len() >= 3, "{} volumes", set.len());
    for (index, (name, bytes)) in set.iter().enumerate() {
        let mut bytes = bytes.clone();
        if index == 1 {
            let header = &file_headers(&bytes)[0];
            let mut extra = header.extra.clone();
            let count = count_at(&extra);
            extra[count] = 25;
            bytes = rebuilt(&bytes, header, &header.fields, &extra, extra.len());
        }
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    let first = set[0].0.as_str();
    for width in ["-mt2", "-mt1"] {
        let _ = std::fs::remove_dir_all(dir.join("out"));
        let ran = run(&dir, &["x", width, "-psecret", "-o+", first, "out/"]);
        assert_eq!(ran.code, Some(2), "{width}: {} {}", ran.stdout, ran.stderr);
        assert_eq!(
            delivered(&dir.join("out")),
            ["a.txt", "b.bin", "c.txt"],
            "{width}"
        );
        assert!(
            ran.stderr.contains("Unknown encryption method in f: xc25"),
            "{width}: {}",
            ran.stderr
        );
        assert!(
            !ran.stderr.contains("Unknown method in"),
            "{width}: {}",
            ran.stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The chosen difference: under a header read although its records do
/// not fit it, a member with NO data checksum fails. The same member
/// under a header whose records fit does not fail: its line closes with
/// the question mark of a member nothing vouches for, never `OK`, and the
/// run is `All OK`, exit 0, as the reference has it (unrar 7.23, 10 Oct
/// 2026; `tests/no_checksum_member_mark.rs`).
#[test]
fn a_member_with_no_checksum_under_such_a_header_fails() {
    let dir = work("unvouched");
    // No quick open record, so the main header's locator names no offset:
    // the header rebuilt below is four bytes shorter, every block behind
    // it moves, and a locator left as written would name an offset at
    // which no block begins, which is an error of its own (spec F 3.2.8
    // rule 2 case c) and not what this test is about.
    let sound = archive(&dir, &["-m0", "-qo-"]).remove(0).1;
    let header = &file_headers(&sound)[1];
    // File flags, unpacked size, attributes, then the times and the
    // CRC32 the flags declare: clear flag 0x0004 and drop its four bytes.
    let (file_flags, at) = vint(&header.fields, 0);
    assert!(
        file_flags & 4 != 0 && file_flags < 0x80,
        "a CRC32 is declared"
    );
    let (_, at) = vint(&header.fields, at);
    let (_, mut at) = vint(&header.fields, at);
    if file_flags & 2 != 0 {
        at += 4;
    }
    let mut fields = vec![(file_flags & !4) as u8];
    fields.extend_from_slice(&header.fields[1..at]);
    fields.extend_from_slice(&header.fields[at + 4..]);

    let fits = rebuilt(&sound, header, &fields, &header.extra, header.extra.len());
    std::fs::write(dir.join("a.rar"), fits).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
    assert_eq!(ran.code, Some(0), "{} {}", ran.stdout, ran.stderr);
    assert_eq!(oks(&ran.stdout), ["a.txt", "c.txt"]);
    assert!(
        ran.stdout
            .lines()
            .any(|line| line.contains("b.bin") && line.ends_with("   ? ")),
        "{}",
        ran.stdout
    );
    assert!(ran.stdout.ends_with("All OK\n"), "{}", ran.stdout);

    let mut extra = header.extra.clone();
    extra.push(0x80);
    let stray = rebuilt(&sound, header, &fields, &extra, extra.len());
    std::fs::write(dir.join("a.rar"), stray).unwrap();
    let ran = run(&dir, &["t", "-mt2", "-p-", "a.rar"]);
    assert_eq!(ran.code, Some(3), "{} {}", ran.stdout, ran.stderr);
    assert_eq!(oks(&ran.stdout), ["a.txt", "c.txt"]);
    assert!(ran.stderr.contains("b.bin"), "{}", ran.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}
