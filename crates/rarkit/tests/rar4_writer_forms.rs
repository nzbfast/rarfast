//! Spec G 3.14.4, 3.14.8 and section 4, the RAR 4 family writer:
//!
//! - a modification time's fraction is a three byte little endian count
//!   of 100 ns units, and where fewer bytes are present they are its HIGH
//!   order bytes. rarkit writes all three whenever there is a fraction, so
//!   it never writes a short form at all;
//! - a comment is a STORED sub block whose checksum field is the whole
//!   CRC32 of the comment's bytes, placed before the first file header;
//! - a time outside what the header's field can say (1980 to 2107) is
//!   written as the nearest time it can say.
//!
//! The headers are read back out of rarkit's own output by the layout of
//! 3.14.1 and 3.14.3. One thread; every archive is under 1 KiB.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    Archive, FilterPolicy, HostOs, MemberSpec, Payload, RangeSource, Rar4Version, ReadOptions,
    Timestamp, WriteFormat, WriteOptions, Writer,
};

/// 2020-09-13 12:26:40 UTC, the kept archives' own time (3.14.4).
const WHEN: i64 = 1_600_000_000;
const WHEN_DOS: u32 = 0x512d_6354;

fn write(mtime: Option<Timestamp>, comment: Option<&[u8]>) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V40),
        filters: FilterPolicy::Off,
        host_os: HostOs::Unix,
        comment: comment.map(<[u8]>::to_vec),
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"hello.txt",
            payload: Payload::Bytes(b"hello\n"),
            mtime,
            attributes: 0o100644,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// One block of a RAR 4 family archive (3.14.1, 3.14.3).
#[derive(Debug, Default)]
struct Block {
    kind: u8,
    flags: u16,
    packed: u32,
    unpacked: u32,
    host: u8,
    checksum: u32,
    dos_time: u32,
    version: u8,
    method: u8,
    attributes: u32,
    name: Vec<u8>,
    /// Whatever follows the name inside the header.
    after_name: Vec<u8>,
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn blocks(archive: &[u8]) -> Vec<Block> {
    assert_eq!(&archive[..7], b"Rar!\x1a\x07\x00");
    let mut out = Vec::new();
    let mut at = 7;
    while at < archive.len() {
        let head = &archive[at..];
        let size = usize::from(le16(head, 5));
        let head = &head[..size];
        assert_eq!(
            rarkit::checksum::crc32(&head[2..]) as u16,
            le16(head, 0),
            "the header checksum of the block at {at}"
        );
        let mut block = Block {
            kind: head[2],
            flags: le16(head, 3),
            ..Block::default()
        };
        if block.kind == 0x74 || block.kind == 0x7a {
            block.packed = le32(head, 7);
            block.unpacked = le32(head, 11);
            block.host = head[15];
            block.checksum = le32(head, 16);
            block.dos_time = le32(head, 20);
            block.version = head[24];
            block.method = head[25];
            let name_len = usize::from(le16(head, 26));
            block.attributes = le32(head, 28);
            block.name = head[32..32 + name_len].to_vec();
            block.after_name = head[32 + name_len..].to_vec();
        }
        at += size + block.packed as usize;
        out.push(block);
    }
    out
}

fn member(archive: &[u8]) -> Block {
    blocks(archive)
        .into_iter()
        .find(|block| block.kind == 0x74)
        .expect("a file header")
}

/// The time rarkit's own reader gives the member back as.
fn read_back(archive: &[u8]) -> Option<Timestamp> {
    let opened = Archive::open(
        Arc::new(archive.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .expect("the archive opens");
    let mtime = opened.members().next().expect("a member").mtime;
    mtime
}

fn at(unix_seconds: i64, nanos: u32) -> Option<Timestamp> {
    Some(Timestamp {
        unix_seconds,
        nanos,
    })
}

/// 3.14.4. The reader arms' own values: 0x6b6f73 units is `73 6f 6b`, on
/// an odd second the word is `f000`, and `unrar lt` prints
/// `12:26:41,704088300` for exactly these bytes.
#[test]
fn a_time_fraction_is_three_bytes_least_significant_first() {
    let archive = write(at(WHEN + 1, 704_088_300), None);
    let file = member(&archive);
    assert_eq!(file.flags, 0x9020, "a file with an extended time");
    assert_eq!(file.dos_time, WHEN_DOS);
    assert_eq!(file.after_name, [0x00, 0xf0, 0x73, 0x6f, 0x6b]);
    assert_eq!(read_back(&archive), at(WHEN + 1, 704_088_300));

    // An even whole second needs no extended time at all.
    let file = member(&write(at(WHEN, 0), None));
    assert_eq!((file.flags, file.dos_time), (0x8020, WHEN_DOS));
    assert!(file.after_name.is_empty());

    // An odd whole second: the one second bit and no fraction bytes.
    let file = member(&write(at(WHEN + 1, 0), None));
    assert_eq!(file.after_name, [0x00, 0xc0]);

    // A fraction whose low bytes are zero is still written as its three
    // bytes: 0x6b0000 units is `00 00 6b`, never the one byte `6b`. So
    // rarkit writes no short form, and the question of which bytes a
    // short form holds does not arise for an archive it wrote.
    let archive = write(at(WHEN, 701_235_200), None);
    let file = member(&archive);
    assert_eq!(file.after_name, [0x00, 0xb0, 0x00, 0x00, 0x6b]);
    assert_eq!(read_back(&archive), at(WHEN, 701_235_200));
}

/// 3.14.8: the comment's sub block, field for field.
#[test]
fn a_stored_comment_carries_its_whole_crc32_before_the_first_file() {
    let comment = b"a rarkit comment\n";
    let all = blocks(&write(at(WHEN, 0), Some(comment)));
    let kinds: Vec<u8> = all.iter().map(|block| block.kind).collect();
    assert_eq!(kinds, [0x73, 0x7a, 0x74, 0x7b], "main, comment, file, end");
    let block = &all[1];
    assert_eq!(block.name, b"CMT");
    assert_eq!(block.flags, 0x8000);
    assert_eq!((block.version, block.method), (29, 0x30), "stored");
    assert_eq!((block.packed, block.unpacked), (17, 17));
    let whole = rarkit::checksum::crc32(comment);
    assert!(whole > 0xffff, "a CRC32 the low 16 bits would not equal");
    assert_eq!(block.checksum, whole, "the whole CRC32, not its low half");
    assert_eq!((block.host, block.attributes, block.dos_time), (3, 0, 0));
    assert!(block.after_name.is_empty());
}

/// Section 4: 1980 to 2107 is what the field's seven bits of year can
/// say. Below it the nearest time is the first instant of 1980; above it,
/// the last instant the header can state, which is the field's last even
/// second with the one second bit and the largest fraction below a second.
#[test]
fn a_time_outside_the_fields_range_is_written_as_the_nearest_it_can_say() {
    const FIRST: i64 = 315_532_800; // 1980-01-01 00:00:00
    const LAST: i64 = 4_354_819_199; // 2107-12-31 23:59:59
    let first_dos = (1 << 21) | (1 << 16);
    let last_dos = (127 << 25) | (12 << 21) | (31 << 16) | (23 << 11) | (59 << 5) | 29;

    // Below: whatever the time's own second and fraction were, they are
    // not added on top of the bound.
    for early in [
        at(FIRST - 1, 500_000_000),
        at(FIRST - 1, 0),
        at(0, 0),
        at(-86_400 * 365 * 300, 123_456_700),
    ] {
        let archive = write(early, None);
        let file = member(&archive);
        assert_eq!(file.dos_time, first_dos, "{early:?}");
        assert_eq!(file.flags, 0x8020, "{early:?}: no extended time");
        assert_eq!(read_back(&archive), at(FIRST, 0), "{early:?}");
    }
    // The bounds themselves are said exactly.
    let archive = write(at(FIRST, 0), None);
    assert_eq!(member(&archive).dos_time, first_dos);
    assert_eq!(read_back(&archive), at(FIRST, 0));
    let archive = write(at(LAST, 999_999_900), None);
    let file = member(&archive);
    assert_eq!(file.dos_time, last_dos);
    assert_eq!(
        file.after_name,
        [0x00, 0xf0, 0x7f, 0x96, 0x98],
        "9,999,999 units"
    );
    assert_eq!(read_back(&archive), at(LAST, 999_999_900));

    // Above: the same last instant, whatever the time was.
    for late in [
        at(LAST + 1, 0),
        at(LAST + 2, 250_000_000),
        at(i64::from(u32::MAX) * 4, 0),
    ] {
        let archive = write(late, None);
        let file = member(&archive);
        assert_eq!(file.dos_time, last_dos, "{late:?}");
        assert_eq!(file.after_name, [0x00, 0xf0, 0x7f, 0x96, 0x98], "{late:?}");
        assert_eq!(read_back(&archive), at(LAST, 999_999_900), "{late:?}");
    }
}

/// A reference binary: a path named in the environment, then `PATH`, then
/// two usual install places.
fn reference(name: &str, env: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os(env) {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(PathBuf::from(name));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(Path::new(&home).join("bin").join(name));
    }
    candidates.push(Path::new("/opt/homebrew/bin").join(name));
    candidates
        .into_iter()
        .find(|path| Command::new(path).output().is_ok())
}

/// What reference `unrar` 7.23 makes of the three: it lists the fraction
/// as written, shows the comment, and tests each archive clean.
#[test]
fn reference_unrar_reads_the_three_forms() {
    let Some(unrar) = reference("unrar", "RARKIT_REF_UNRAR") else {
        eprintln!("SKIPPED: no reference unrar");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-r4forms-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let run = |verb: &str, archive: &[u8]| {
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        let out = Command::new(&unrar)
            .args([verb, "a.rar"])
            .current_dir(&dir)
            // The listing is in local time; UTC makes it the time written.
            .env("TZ", "UTC")
            .output()
            .expect("unrar runs");
        assert!(out.status.success(), "unrar {verb}: {out:?}");
        assert!(out.stderr.is_empty(), "unrar {verb}: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let fraction = write(at(WHEN + 1, 704_088_300), None);
    assert!(run("t", &fraction).contains("All OK"));
    let listed = run("lt", &fraction);
    assert!(listed.contains("12:26:41,704088300"), "{listed}");

    let commented = write(at(WHEN, 0), Some(b"a rarkit comment\n"));
    assert!(run("t", &commented).contains("All OK"));
    let listed = run("l", &commented);
    assert!(listed.contains("a rarkit comment"), "{listed}");

    let early = write(at(0, 0), None);
    assert!(run("t", &early).contains("All OK"));
    let listed = run("lt", &early);
    assert!(listed.contains("1980-01-01 00:00:00,000000000"), "{listed}");
    let late = write(at(i64::from(u32::MAX) * 4, 0), None);
    assert!(run("t", &late).contains("All OK"));
    let listed = run("lt", &late);
    assert!(listed.contains("2107-12-31 23:59:59,999999900"), "{listed}");

    let _ = std::fs::remove_dir_all(&dir);
}

fn with_record(len: usize, percent: u32) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V40),
        filters: FilterPolicy::Off,
        host_os: HostOs::Unix,
        recovery_percent: Some(percent),
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    // No two sectors alike: the reference's repair also looks for sectors
    // that have moved, by their tags, and takes one of two equal sectors
    // for the other.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    writer
        .add(MemberSpec {
            name: b"payload.bin",
            payload: Payload::Bytes(&data),
            mtime: at(WHEN, 0),
            attributes: 0o100644,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// 3.14.8 and SPEC-L 3.7: the `RR` sub block, field for field. After the
/// name come 20 bytes: `Protect+`, the count of parity sectors, the count
/// of protected sectors (the header's offset in 512 byte sectors, rounded
/// up), each 4 bytes little endian, and 4 zero bytes. The header is 54
/// bytes, as in every genuine file.
#[test]
fn the_recovery_sub_block_carries_protect_and_its_two_counts() {
    for (len, percent) in [(69_000usize, 5u32), (300, 1), (20_000, 100)] {
        let archive = with_record(len, percent);
        let all = blocks(&archive);
        let kinds: Vec<u8> = all.iter().map(|block| block.kind).collect();
        assert_eq!(kinds, [0x73, 0x74, 0x7a, 0x7b], "main, file, record, end");
        let record = &all[2];
        assert_eq!(record.name, b"RR");
        assert_eq!(record.flags, 0xc000);
        assert_eq!((record.version, record.method), (29, 0x30));
        assert_eq!(record.packed, record.unpacked);
        assert_eq!((record.host, record.attributes, record.dos_time), (3, 0, 0));

        // Where the record's header starts: after the marker, the main
        // header, and the member's header and data.
        let header_at = 7 + 13 + (32 + 11) + len;
        let sectors = header_at.div_ceil(512) as u32;
        let parity = (record.packed - 2 * sectors) / 512;
        assert!(parity >= 1, "{len} bytes at {percent}%");
        assert_eq!(record.packed, 2 * sectors + 512 * parity);
        let mut after = b"Protect+".to_vec();
        after.extend(parity.to_le_bytes());
        after.extend(sectors.to_le_bytes());
        after.extend([0u8; 4]);
        assert_eq!(record.after_name, after, "{len} bytes at {percent}%");
        assert_eq!(7 + 4 + 21 + 2 + 20, 54, "the header's length");

        // rarkit's own repair still finds and uses it.
        let mut damaged = archive.clone();
        for byte in &mut damaged[100..140] {
            *byte ^= 0x77;
        }
        let mut mended = Vec::new();
        rarkit::recovery::repair_inline(&damaged, &ReadOptions::default(), &mut mended)
            .expect("a repair");
        assert!(mended == archive, "{len} bytes at {percent}%");
    }
}

/// SPEC-L 3.7's repair arms `one-sector` and `two-sectors-two-classes`,
/// with rarkit as the writer: reference `rar r` rebuilds the damaged
/// sectors of a RAR 4 family archive, byte for byte, from the record
/// rarkit wrote. It reads the two counts after `Protect+` to do so: the
/// same archive with nothing after the name made it stop without an
/// answer (measured on rar 7.23 for macOS, 6 Oct 2026).
#[test]
fn the_reference_repairs_from_a_rar4_record_rarkit_wrote() {
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("SKIPPED: no reference rar");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-r4repair-{}", std::process::id()));
    let archive = with_record(69_000, 5);
    let protected = 7 + 13 + 43 + 69_000;
    for damage in [&[30_000usize][..], &[5_000, 40_000]] {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut damaged = archive.clone();
        for at in damage {
            for byte in &mut damaged[*at..*at + 40] {
                *byte ^= 0x77;
            }
        }
        std::fs::write(dir.join("d.rar"), &damaged).unwrap();
        let ran = Command::new(&rar)
            .args(["r", "-y", "d.rar"])
            .current_dir(&dir)
            .output()
            .expect("rar r");
        let said = String::from_utf8_lossy(&ran.stdout).replace('\r', "\n");
        assert!(ran.status.success(), "{damage:?}: {said}");
        let fixed = std::fs::read(dir.join("fixed.d.rar"))
            .unwrap_or_else(|_| panic!("{damage:?}: no fixed file: {said}"));
        assert!(
            fixed[..protected] == archive[..protected],
            "{damage:?}: the protected bytes were not rebuilt: {said}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
