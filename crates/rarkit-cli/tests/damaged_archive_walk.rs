//! The reader's walk over DAMAGED archives: what `unrar t` and `unrar x`
//! deliver from an archive that arrived damaged or cut short, and what
//! they exit with.
//!
//! Every input is made here: `rarfast a` writes a sound archive and the
//! test damages its bytes. The expected words and exit codes are the
//! reference's, measured with unrar 7.23 on a Mac on 8 Oct 2026 over the
//! very archives these helpers make (rarfast's own, four members, `-m0`
//! and `-m3`, with a quick open record and without):
//!
//! | Shape | unrar 7.23 |
//! |---|---|
//! | quick open record, cut where a member header would begin | the members in front `OK`, `Unexpected end of archive`, exit 1 |
//! | quick open record, cut where the quick open header would begin | all four `OK`, `Unexpected end of archive`, exit 1 |
//! | quick open record, cut where the end record would begin | all four `OK`, `All OK`, exit 0 |
//! | no quick open record, cut where a member header would begin | the members in front `OK`, `All OK`, exit 0 |
//! | a member header whose checksum is wrong, no quick open record | `Corrupt header is found`, `<name> - the file header is corrupt`, all four `OK`, exit 3 |
//! | the same with a quick open record | all four `OK`, `All OK`, exit 0 (rarfast: reported, exit 3, below) |
//! | the main header's checksum wrong | `Corrupt header is found`, `Main archive header is corrupt`, all four `OK`, exit 3 |
//! | a middle volume one byte short (its end record) | every member `OK`, `All OK`, exit 0 |
//! | a middle volume's end record with a wrong checksum | every member `OK`, `All OK`, exit 0 (rarfast: reported, exit 3, below) |
//! | `lb` over a member header whose checksum is wrong | every name listed, the same two lines, exit 3 |
//! | the last member's packed size 7 too small, checksum redone | three `OK`, `<name> - checksum error`, `Unexpected end of archive`, exit 3 |
//!
//! Where rarfast differs, by spec F 4.6 and 3.2.9.1 as restated on 8 Oct
//! 2026, each difference chosen for safety and pinned here:
//!
//! - a run that read ANY header through a failed checksum is never a
//!   success and names the header: exit 3, also where a sound quick open
//!   copy stood in for it (the reference: exit 0) and where the header is
//!   a middle volume's end record (the reference does not read it);
//! - a member under such a header is good only by its own data checksum,
//!   and with none it fails (the reference does not judge it);
//! - a sound header is never answered from a quick open copy (the
//!   library's `tests/read_damaged.rs` pins that one).
//!
//! Every run here is `-mt2` (a pool two threads wide) under the default
//! memory policy: no archive is over 1 MiB and no member needs a window
//! above 1 MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-dmgwalk-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const NAMES: [&str; 4] = [
    "f1_first.txt",
    "f2_middle.bin",
    "d/f3_inner.txt",
    "f4_last.txt",
];

/// The four members, in archive order. The text is of 4,096 words, which
/// packs to about half, so that `-v100k` cuts the set into four volumes
/// and more.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (NAMES[0], rarkit_testdata::chatter_of(1, 1 << 12, 180_000)),
        (NAMES[1], rarkit_testdata::scramble(2, 200_000)),
        (NAMES[2], rarkit_testdata::chatter_of(3, 1 << 12, 220_000)),
        (NAMES[3], rarkit_testdata::chatter_of(4, 1 << 12, 150_000)),
    ]
}

/// Archive the four members with `rarfast a` and the given switches, and
/// return every file it wrote, by name, sorted.
fn archive(dir: &Path, switches: &[&str]) -> Vec<(String, Vec<u8>)> {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    for (name, bytes) in members() {
        std::fs::write(src.join(name), bytes).unwrap();
    }
    let made = dir.join("made");
    std::fs::create_dir_all(&made).unwrap();
    let mut args = vec!["a".to_owned(), "-idq".to_owned()];
    args.extend(switches.iter().map(|s| (*s).to_owned()));
    args.push(made.join("a.rar").to_str().unwrap().to_owned());
    args.extend(NAMES.iter().map(|s| (*s).to_owned()));
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

/// One archive file.
fn single(dir: &Path, switches: &[&str]) -> Vec<u8> {
    let mut files = archive(dir, switches);
    assert_eq!(files.len(), 1, "one archive file");
    files.remove(0).1
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

/// One RAR 5 block.
#[derive(Clone, Copy, Debug)]
struct Block {
    start: usize,
    header_end: usize,
    kind: u64,
}

/// The blocks of a sound RAR 5 archive.
fn blocks(bytes: &[u8]) -> Vec<Block> {
    assert_eq!(&bytes[..8], b"Rar!\x1a\x07\x01\x00", "a RAR 5 archive");
    let mut at = 8;
    let mut out = Vec::new();
    while at < bytes.len() {
        let (size, body) = vint(bytes, at + 4);
        let header_end = body + size as usize;
        let (kind, next) = vint(bytes, body);
        let (flags, mut next) = vint(bytes, next);
        if flags & 1 != 0 {
            next = vint(bytes, next).1;
        }
        let data = if flags & 2 != 0 {
            vint(bytes, next).0 as usize
        } else {
            0
        };
        out.push(Block {
            start: at,
            header_end,
            kind,
        });
        at = header_end + data;
    }
    out
}

const MAIN: u64 = 1;
const FILE: u64 = 2;
const SERVICE: u64 = 3;
const END: u64 = 5;

/// The file blocks, in order.
fn files_of(all: &[Block]) -> Vec<Block> {
    all.iter().copied().filter(|b| b.kind == FILE).collect()
}

/// Whether the archive carries a quick open record: a service block
/// behind the last member.
fn has_quick_open(bytes: &[u8]) -> bool {
    blocks(bytes).iter().any(|b| b.kind == SERVICE)
}

/// Break a header's checksum and nothing else.
fn break_checksum(bytes: &mut [u8], block: Block) {
    bytes[block.start] ^= 0xff;
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// What a run said, with `/` between the parts of a name: the tool shows
/// an archived name with the system's own separator, which on Windows is
/// `\` (`d\f3_inner.txt`, as `tests/create_sweep.rs` reads it), and the
/// names compared here are the archive's. Until 9 Oct 2026 the text was
/// compared as it came, and on Windows the one member in a directory was
/// never found in it: seven tests failed there on their first look at a
/// listing, before anything the tool wrote was looked at.
fn ran(out: Output) -> Ran {
    let said = |bytes: &[u8]| {
        let text = String::from_utf8_lossy(bytes).into_owned();
        if cfg!(windows) {
            text.replace('\\', "/")
        } else {
            text
        }
    };
    Ran {
        code: out.status.code(),
        stdout: said(&out.stdout),
        stderr: said(&out.stderr),
    }
}

/// `rarfast t` in the unrar dialect, two threads wide.
fn test(archive: &Path) -> Ran {
    ran(Command::new(rarfast())
        .args(["t", "-mt2"])
        .arg(archive)
        .output()
        .unwrap())
}

/// `rarfast x` in the unrar dialect into a fresh directory, two threads
/// wide; returns the run and the directory.
fn extract(dir: &Path, archive: &Path) -> (Ran, PathBuf) {
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let run = ran(Command::new(rarfast())
        .args(["x", "-mt2", "-o+"])
        .arg(archive)
        .arg(format!("{}/", out.display()))
        .output()
        .unwrap());
    (run, out)
}

/// Which of the four members `out` holds WHOLE AND RIGHT, and which names
/// are there at all.
fn delivered(out: &Path) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut right = Vec::new();
    let mut present = Vec::new();
    for (name, bytes) in members() {
        if let Ok(found) = std::fs::read(out.join(name)) {
            present.push(name);
            if found == bytes {
                right.push(name);
            }
        }
    }
    (right, present)
}

fn ok_lines(run: &Ran) -> Vec<&'static str> {
    NAMES
        .iter()
        .copied()
        .filter(|name| {
            run.stdout
                .lines()
                .any(|line| line.contains(name) && line.trim_end().ends_with("OK"))
        })
        .collect()
}

/// SWEEP2-08OCT-23. A RAR 5 archive with a quick open record, cut exactly
/// where a member header would begin, has lost members and says so: its
/// main header's locator names a quick open record the file does not
/// reach. Until 8 Oct 2026 this tested and extracted `All OK`, exit 0.
#[test]
fn a_quick_open_archive_cut_at_a_member_header_is_not_all_ok() {
    let dir = work("qo-cut");
    let bytes = single(&dir, &["-m0"]);
    assert!(has_quick_open(&bytes), "rarfast wrote a quick open record");
    let all = blocks(&bytes);
    let files = files_of(&all);
    assert_eq!(files.len(), 4);
    let path = dir.join("cut.rar");

    // Cut where the third member's header would begin.
    std::fs::write(&path, &bytes[..files[2].start]).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(1), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("Unexpected end of archive"),
        "{}",
        run.stderr
    );
    assert!(!run.stdout.contains("All OK"), "{}", run.stdout);
    assert_eq!(ok_lines(&run), NAMES[..2]);
    let (run, out) = extract(&dir, &path);
    assert_eq!(run.code, Some(1), "x: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("Unexpected end of archive"),
        "{}",
        run.stderr
    );
    assert_eq!(delivered(&out), (NAMES[..2].to_vec(), NAMES[..2].to_vec()));

    // Cut where the quick open header would begin: every member is there,
    // and the archive is still short of what its locator names.
    let service = all.iter().find(|b| b.kind == SERVICE).unwrap();
    std::fs::write(&path, &bytes[..service.start]).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(1), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("Unexpected end of archive"),
        "{}",
        run.stderr
    );
    assert_eq!(ok_lines(&run), NAMES);

    // Cut where the END record would begin: the quick open record is
    // whole, nothing a reader uses is missing, and the reference says
    // `All OK` (spec F 3.5.5 K4).
    let end = all.iter().find(|b| b.kind == END).unwrap();
    std::fs::write(&path, &bytes[..end.start]).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(0), "t: {} {}", run.stdout, run.stderr);
    assert!(run.stdout.contains("All OK"), "{}", run.stdout);
    assert_eq!(ok_lines(&run), NAMES);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The control of the test above: with NO quick open record a cut at a
/// member header is a complete read, at the reference too (spec F 3.5.5
/// K4): nothing in the file says more was ever there.
#[test]
fn without_a_quick_open_record_a_cut_at_a_member_header_is_a_complete_read() {
    let dir = work("noqo-cut");
    let bytes = single(&dir, &["-m0", "-qo-"]);
    assert!(!has_quick_open(&bytes));
    let files = files_of(&blocks(&bytes));
    let path = dir.join("cut.rar");
    std::fs::write(&path, &bytes[..files[2].start]).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(0), "t: {} {}", run.stdout, run.stderr);
    assert!(run.stdout.contains("All OK"), "{}", run.stdout);
    assert_eq!(ok_lines(&run), NAMES[..2]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SWEEP2-08OCT-26, scenario 1. A member header whose checksum is wrong
/// is reported and READ: its member and every later one is delivered,
/// each checked against its own checksum. Until 8 Oct 2026 the walk
/// stopped at the header and nothing from it on was extracted.
#[test]
fn a_member_header_with_a_bad_checksum_does_not_end_the_walk() {
    let dir = work("hdrcrc");
    let bytes = single(&dir, &["-m0", "-qo-"]);
    assert!(!has_quick_open(&bytes));
    let files = files_of(&blocks(&bytes));
    let path = dir.join("bad.rar");
    for (which, name) in [(0, NAMES[0]), (2, NAMES[2])] {
        let mut damaged = bytes.clone();
        break_checksum(&mut damaged, files[which]);
        std::fs::write(&path, &damaged).unwrap();
        let run = test(&path);
        assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
        assert!(
            run.stderr.contains("Corrupt header is found"),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr
                .contains(&format!("{name} - the file header is corrupt")),
            "{}",
            run.stderr
        );
        assert!(!run.stdout.contains("All OK"), "{}", run.stdout);
        assert_eq!(ok_lines(&run), NAMES, "{}", run.stdout);
        let (run, out) = extract(&dir, &path);
        assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));
        // A mask that matches nothing is not silent about it either.
        let run = ran(Command::new(rarfast())
            .args(["t", "-mt2"])
            .arg(&path)
            .arg("no-such-member")
            .output()
            .unwrap());
        assert_eq!(run.code, Some(3), "mask: {} {}", run.stdout, run.stderr);
        assert!(
            run.stderr
                .contains(&format!("{name} - the file header is corrupt")),
            "{}",
            run.stderr
        );
        // A listing names every member too, and exits 3.
        let run = ran(Command::new(rarfast())
            .arg("lb")
            .arg(&path)
            .output()
            .unwrap());
        assert_eq!(run.code, Some(3), "lb: {} {}", run.stdout, run.stderr);
        assert_eq!(run.stdout.lines().collect::<Vec<_>>(), NAMES);
        assert_eq!(
            run.stderr,
            format!("\nCorrupt header is found\n{name} - the file header is corrupt")
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SWEEP2-08OCT-26, scenario 2. With a quick open record the damaged
/// header has a sound copy there, entry checksum and header checksum
/// both good, and the copy's fields are read in its place: every member
/// is delivered even where the header's own SIZE field is what was
/// damaged. The header's failure is reported all the same and the run
/// exits 3 (spec F 3.2.9.1 rule 4; the reference says nothing and exits
/// 0). The copy is used ONLY where the real header failed its checksum.
#[test]
fn a_bad_member_header_with_a_sound_quick_open_copy_is_read_from_the_copy() {
    let dir = work("hdrcrc-qo");
    let bytes = single(&dir, &["-m0"]);
    assert!(has_quick_open(&bytes));
    let all = blocks(&bytes);
    let files = files_of(&all);
    let path = dir.join("bad.rar");
    // The checksum field, then the header's own size field: without the
    // copy the second does not frame at all.
    for (which, at) in [(0, 0), (2, 0), (2, 4)] {
        let mut damaged = bytes.clone();
        damaged[files[which].start + at] ^= if at == 0 { 0xff } else { 0x01 };
        std::fs::write(&path, &damaged).unwrap();
        let run = test(&path);
        assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
        assert!(!run.stdout.contains("All OK"), "{}", run.stdout);
        assert!(
            run.stderr
                .contains(&format!("{} - the file header is corrupt", NAMES[which])),
            "{}",
            run.stderr
        );
        assert_eq!(ok_lines(&run), NAMES);
        let (run, out) = extract(&dir, &path);
        assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));
    }

    // The copy is damaged too (its entry's checksum fails): the header is
    // read as the archive without a record reads it, reported, exit 3.
    let service = all.iter().find(|b| b.kind == SERVICE).unwrap();
    let mut damaged = bytes.clone();
    break_checksum(&mut damaged, files[0]);
    // The first entry is the first member's: its checksum field.
    damaged[service.header_end] ^= 0xff;
    std::fs::write(&path, &damaged).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("Corrupt header is found"),
        "{}",
        run.stderr
    );
    assert_eq!(ok_lines(&run), NAMES);

    // The quick open header's own checksum: named, exit 3, every member.
    let mut damaged = bytes.clone();
    break_checksum(&mut damaged, *service);
    std::fs::write(&path, &damaged).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("QO - the file header is corrupt"),
        "{}",
        run.stderr
    );
    assert_eq!(ok_lines(&run), NAMES);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SWEEP2-08OCT-25. A middle volume one byte short has lost a byte of its
/// END record and nothing else: the member that continues across it and
/// every later member is whole. Until 8 Oct 2026 the member spanning it
/// failed and no later member was extracted.
#[test]
fn a_middle_volume_short_in_its_end_record_loses_no_member() {
    let dir = work("midvol");
    let files = archive(&dir, &["-m3", "-v100k"]);
    assert!(files.len() >= 4, "a set of {} volumes", files.len());
    let set = dir.join("set");
    // Each middle volume in turn, where a member continues across it.
    let mut tried = 0;
    for short in 1..files.len() - 1 {
        let last = *blocks(&files[short].1).last().unwrap();
        assert_eq!(last.kind, END, "the volume ends with its end record");
        let _ = std::fs::remove_dir_all(&set);
        std::fs::create_dir_all(&set).unwrap();
        for (index, (name, bytes)) in files.iter().enumerate() {
            let keep = if index == short {
                bytes.len() - 1
            } else {
                bytes.len()
            };
            std::fs::write(set.join(name), &bytes[..keep]).unwrap();
        }
        let first = set.join(&files[0].0);
        let run = test(&first);
        assert_eq!(
            run.code,
            Some(0),
            "t, volume {short} short: {} {}",
            run.stdout,
            run.stderr
        );
        assert!(run.stdout.contains("All OK"), "{}", run.stdout);
        let (run, out) = extract(&dir, &first);
        assert_eq!(run.code, Some(0), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));

        // The same volume whole, its end record's checksum wrong. The
        // reference does not read a record behind a member that
        // continues; rarfast reads it, so it is reported and named and
        // the run is not a success (spec F 4.6 rule 1), with every
        // member delivered.
        let mut unsound = files[short].1.clone();
        break_checksum(&mut unsound, last);
        std::fs::write(set.join(&files[short].0), &unsound).unwrap();
        let run = test(&first);
        assert_eq!(
            run.code,
            Some(3),
            "t, volume {short} end record: {} {}",
            run.stdout,
            run.stderr
        );
        assert!(
            run.stderr.contains("End of archive header is corrupt"),
            "{}",
            run.stderr
        );
        assert!(!run.stdout.contains("All OK"), "{}", run.stdout);
        assert_eq!(ok_lines(&run), NAMES);
        let (run, out) = extract(&dir, &first);
        assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));
        tried += 1;
    }
    assert!(tried >= 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SWEEP2-08OCT-27. A main archive header whose checksum is wrong is
/// reported and read: every member is delivered, exit 3. Until 8 Oct
/// 2026 the archive was refused whole, `is not RAR archive`, exit 10.
#[test]
fn a_damaged_main_header_does_not_refuse_the_archive() {
    let dir = work("mainhdr");
    for switches in [&["-m0", "-qo-"][..], &["-m0"][..]] {
        let bytes = single(&dir, switches);
        let all = blocks(&bytes);
        assert_eq!(all[0].kind, MAIN);
        let mut damaged = bytes.clone();
        break_checksum(&mut damaged, all[0]);
        let path = dir.join("bad.rar");
        std::fs::write(&path, &damaged).unwrap();
        let run = test(&path);
        assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
        assert!(
            run.stderr.contains("Corrupt header is found"),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr.contains("Main archive header is corrupt"),
            "{}",
            run.stderr
        );
        assert!(!run.stderr.contains("is not RAR archive"), "{}", run.stderr);
        assert_eq!(ok_lines(&run), NAMES);
        let (run, out) = extract(&dir, &path);
        assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SWEEP2-08OCT-28. A last member whose declared packed size is 7 too
/// small (header checksum redone) fails ITS checksum, and the walk then
/// lands 7 bytes early on what is no header: the three members in front
/// are delivered and the run exits 3. Until 8 Oct 2026 the archive was
/// refused whole, `is not RAR archive`, exit 10.
#[test]
fn a_last_member_declaring_too_few_packed_bytes_fails_alone() {
    let dir = work("psize");
    let bytes = single(&dir, &["-m3", "-qo-"]);
    let last = *files_of(&blocks(&bytes)).last().unwrap();
    // Rebuild the header with its data size 7 smaller: the size vint,
    // type, flags, [extra size], data size, then the rest unchanged.
    let (_, body) = vint(&bytes, last.start + 4);
    let (_, at) = vint(&bytes, body);
    let (flags, mut at) = vint(&bytes, at);
    assert!(flags & 2 != 0, "the member has a data area");
    if flags & 1 != 0 {
        at = vint(&bytes, at).1;
    }
    let (packed, after) = vint(&bytes, at);
    let mut fields = bytes[body..at].to_vec();
    put_vint(packed - 7, &mut fields);
    fields.extend_from_slice(&bytes[after..last.header_end]);
    let mut header = Vec::new();
    put_vint(fields.len() as u64, &mut header);
    header.extend_from_slice(&fields);
    let mut damaged = bytes[..last.start].to_vec();
    damaged.extend_from_slice(&crc32(&header).to_le_bytes());
    damaged.extend_from_slice(&header);
    damaged.extend_from_slice(&bytes[last.header_end..]);
    let path = dir.join("bad.rar");
    std::fs::write(&path, &damaged).unwrap();

    let run = test(&path);
    assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
    assert!(!run.stderr.contains("is not RAR archive"), "{}", run.stderr);
    assert!(
        run.stderr.contains("f4_last.txt") && run.stderr.contains("checksum error"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("Unexpected end of archive"),
        "{}",
        run.stderr
    );
    assert_eq!(ok_lines(&run), NAMES[..3]);
    let (run, out) = extract(&dir, &path);
    assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
    assert_eq!(delivered(&out).0, NAMES[..3].to_vec());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Spec F 4.6 rule 4. A member under a header whose checksum failed is
/// good only by its own data checksum: with NONE it fails, and it alone.
/// The second member's header is rebuilt without its CRC32 field and
/// left with the checksum of the header it was.
#[test]
fn a_member_under_a_damaged_header_with_no_data_checksum_fails() {
    let dir = work("nocrc");
    let bytes = single(&dir, &["-m0", "-qo-"]);
    let block = files_of(&blocks(&bytes))[1];
    let (size, body) = vint(&bytes, block.start + 4);
    assert!(size < 128 && size - 4 >= 1, "a one byte size field");
    let (_, at) = vint(&bytes, body);
    let (flags, mut at) = vint(&bytes, at);
    if flags & 1 != 0 {
        at = vint(&bytes, at).1;
    }
    if flags & 2 != 0 {
        at = vint(&bytes, at).1;
    }
    // The file flags, the unpacked size, the attributes, the optional
    // mtime, then the CRC32 this drops.
    let file_flags_at = at;
    let (file_flags, at) = vint(&bytes, at);
    assert!(
        file_flags < 128 && file_flags & 4 != 0,
        "the member has a CRC32"
    );
    let (_, at) = vint(&bytes, at);
    let (_, mut at) = vint(&bytes, at);
    if file_flags & 2 != 0 {
        at += 4;
    }
    let mut damaged = bytes[..at].to_vec();
    damaged.extend_from_slice(&bytes[at + 4..]);
    damaged[file_flags_at] = (file_flags & !4) as u8;
    damaged[block.start + 4] = (size - 4) as u8;
    let header_end = block.header_end - 4;
    assert_ne!(
        crc32(&damaged[block.start + 4..header_end]).to_le_bytes(),
        damaged[block.start..block.start + 4],
        "the header's checksum is left wrong"
    );
    let path = dir.join("bad.rar");
    std::fs::write(&path, &damaged).unwrap();

    let run = test(&path);
    assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr
            .contains("f2_middle.bin - the file header is corrupt"),
        "{}",
        run.stderr
    );
    assert_eq!(
        ok_lines(&run),
        [NAMES[0], NAMES[2], NAMES[3]],
        "{} {}",
        run.stdout,
        run.stderr
    );
    let (run, out) = extract(&dir, &path);
    assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
    let (right, _) = delivered(&out);
    assert!(
        [NAMES[0], NAMES[2], NAMES[3]]
            .iter()
            .all(|name| right.contains(name)),
        "{right:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Spec F 4.6 rule 2. A field read from a header whose checksum failed
/// is held to what a sound header's field is held to: a name that climbs
/// out of the destination is refused as it is anywhere, nothing is
/// written outside it, and the other members are delivered.
#[test]
fn a_name_from_a_damaged_header_cannot_leave_the_destination() {
    let dir = work("escape");
    let bytes = single(&dir, &["-m0", "-qo-"]);
    let block = files_of(&blocks(&bytes))[0];
    let at = (block.start..block.header_end)
        .find(|&i| bytes[i..].starts_with(b"f1_first.txt"))
        .expect("the first member's name");
    let mut damaged = bytes.clone();
    damaged[at..at + 12].copy_from_slice(b"../escape.tx");
    let path = dir.join("bad.rar");
    std::fs::write(&path, &damaged).unwrap();
    let (run, out) = extract(&dir, &path);
    assert!(
        matches!(run.code, Some(code) if code != 0),
        "x: {} {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stderr.contains("the file header is corrupt"),
        "{}",
        run.stderr
    );
    assert!(
        !dir.join("escape.tx").exists(),
        "a file outside the destination"
    );
    assert_eq!(delivered(&out).0, NAMES[1..].to_vec());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Write another quick open offset into the main header's locator, in the
/// bytes the old one took (a writer reserves the field at a fixed width),
/// and redo the header's checksum.
fn set_quick_open_offset(bytes: &mut [u8], from: u64, to: u64) {
    let main = blocks(bytes)[0];
    assert_eq!(main.kind, MAIN);
    // Checksum, header size, type, header flags, extra size, archive flags
    // and, in a later volume, its number; then the extra area, whose first
    // record is the locator: its size, type 1, its flags, the offset.
    let (_, at) = vint(bytes, main.start + 4);
    let (_, at) = vint(bytes, at);
    let (header_flags, at) = vint(bytes, at);
    assert_eq!(header_flags & 1, 1, "the main header has an extra area");
    let (_, at) = vint(bytes, at);
    let (archive_flags, mut at) = vint(bytes, at);
    if archive_flags & 2 != 0 {
        at = vint(bytes, at).1;
    }
    let (_, at) = vint(bytes, at);
    let (record, at) = vint(bytes, at);
    let (locator_flags, at) = vint(bytes, at);
    assert_eq!((record, locator_flags & 1), (1, 1), "a quick open locator");
    let (held, end) = vint(bytes, at);
    assert_eq!(held, from, "the offset the writer gave");
    assert!(to >> (7 * (end - at)) == 0, "the new offset fits the field");
    for (index, byte) in bytes[at..end].iter_mut().enumerate() {
        let more = if index + 1 < end - at { 0x80 } else { 0 };
        *byte = ((to >> (7 * index)) & 0x7f) as u8 | more;
    }
    let sum = crc32(&bytes[main.start + 4..main.header_end]);
    bytes[main.start..main.start + 4].copy_from_slice(&sum.to_le_bytes());
}

/// Spec F 3.2.8 rule 2 case c. The main header is sound and its locator
/// names a quick open offset inside the file at which no block begins:
/// the locator is wrong. Every member is tested and written as usual, and
/// the run is then not a success: exit 3, the reference's code for such an
/// offset with clear headers (11 of its 13 arms; `vectors-F/locator-offset`).
/// Until 9 Oct 2026 an offset on no block was ignored: `All OK`, exit 0.
#[test]
fn a_locator_offset_on_no_block_is_an_error_after_every_member() {
    let dir = work("qo-wrong");
    let bytes = single(&dir, &["-m0"]);
    let all = blocks(&bytes);
    let service = all.iter().find(|b| b.kind == SERVICE).unwrap();
    let files = files_of(&all);
    // The offset the writer gave, counted from the main header.
    let right = (service.start - all[0].start) as u64;
    let path = dir.join("wrong.rar");
    for to in [
        // One byte on, inside the quick open header.
        right + 1,
        // Inside the first member's data.
        (files[0].header_end - all[0].start) as u64 + 100,
    ] {
        let mut wrong = bytes.clone();
        set_quick_open_offset(&mut wrong, right, to);
        std::fs::write(&path, &wrong).unwrap();
        let run = test(&path);
        assert_eq!(run.code, Some(3), "t: {} {}", run.stdout, run.stderr);
        assert!(!run.stdout.contains("All OK"), "{}", run.stdout);
        assert_eq!(ok_lines(&run), NAMES);
        let (run, out) = extract(&dir, &path);
        assert_eq!(run.code, Some(3), "x: {} {}", run.stdout, run.stderr);
        assert_eq!(delivered(&out), (NAMES.to_vec(), NAMES.to_vec()));
    }

    // The controls: the writer's own offset written back, and an offset on
    // another sound header (the second member's), which is case a and is
    // ignored as the reference ignores it.
    for to in [right, (files[1].start - all[0].start) as u64] {
        let mut same = bytes.clone();
        set_quick_open_offset(&mut same, right, to);
        std::fs::write(&path, &same).unwrap();
        let run = test(&path);
        assert_eq!(run.code, Some(0), "t: {} {}", run.stdout, run.stderr);
        assert!(run.stdout.contains("All OK"), "{}", run.stdout);
    }

    // Case b with the end record read: an offset past the end of the file
    // is a lost tail, exit 1, every member tested.
    let mut past = bytes.clone();
    set_quick_open_offset(&mut past, right, bytes.len() as u64 + 1_000);
    std::fs::write(&path, &past).unwrap();
    let run = test(&path);
    assert_eq!(run.code, Some(1), "t: {} {}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("Unexpected end of archive"),
        "{}",
        run.stderr
    );
    assert_eq!(ok_lines(&run), NAMES);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The archives rarfast itself writes behind `-hp`, one file and a set of
/// volumes, each with a quick open record: their locators count from the
/// main header as stored (spec F 3.2.8), so the reader that now judges an
/// offset on no block passes them whole.
#[test]
fn rarfast_own_archives_with_encrypted_headers_have_a_right_locator() {
    let dir = work("hp-own");
    for switches in [
        &["-m0", "-hpSecret"][..],
        &["-m0", "-hpSecret", "-v100k"][..],
    ] {
        let files = archive(&dir, switches);
        let held = dir.join("held");
        std::fs::create_dir_all(&held).unwrap();
        for (name, bytes) in &files {
            std::fs::write(held.join(name), bytes).unwrap();
        }
        let first = held.join(&files[0].0);
        let run = ran(Command::new(rarfast())
            .args(["t", "-mt2", "-pSecret"])
            .arg(&first)
            .output()
            .unwrap());
        assert_eq!(
            run.code,
            Some(0),
            "{switches:?}: {} {}",
            run.stdout,
            run.stderr
        );
        assert!(run.stdout.contains("All OK"), "{}", run.stdout);
        assert_eq!(ok_lines(&run), NAMES, "{switches:?}");
        std::fs::remove_dir_all(&held).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
