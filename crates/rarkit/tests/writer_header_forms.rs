//! Spec G, the forms of the RAR 5 headers rarkit writes, read back out of
//! its own output by a walker written here from 3.2 and 3.3 (the block
//! frame, the file and service header, the extra records), so that each
//! holds where no reference program is at hand:
//!
//! - 3.6.5 and 3.15, a rewrite: the members come out with their two size
//!   fields at the shortest width and everything else as it was, a
//!   whole-second time still in the header field.
//!
//! - 3.2 and 3.3, the header flags by block; 3.11, the recovery flag.
//! - 3.15, an edit: the locator and the quick-open block are right in
//!   the output or are not there, and an archive that came in the
//!   reference layout goes out in it.
//!
//! One thread; every archive here is under 400 KiB.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    Archive, HostOs, Layout, MemberSpec, Payload, RangeSource, ReadOptions, Timestamp,
    WriteOptions, Writer,
};

const WHEN: i64 = 1_600_000_000;

/// One vint at `*at`: its value and how many bytes it took.
fn vint(bytes: &[u8], at: &mut usize) -> (u64, usize) {
    let start = *at;
    let mut value = 0u64;
    loop {
        let byte = bytes[*at];
        value |= u64::from(byte & 0x7f) << (7 * (*at - start));
        *at += 1;
        if byte & 0x80 == 0 {
            return (value, *at - start);
        }
    }
}

/// What a block's header says, with the widths its padded fields took.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Block {
    kind: u64,
    flags: u64,
    /// The data area's size and the width of its field, with flag 0x0002.
    data: Option<(u64, usize)>,
    // File and service headers only, from here down.
    file_flags: u64,
    unpacked: (u64, usize),
    time_field: Option<u32>,
    has_crc_field: bool,
    compression: (u64, usize),
    host: u64,
    name: Vec<u8>,
    /// The extra records' types, in order.
    records: Vec<u64>,
    /// Each extra record's body, after its type.
    bodies: Vec<Vec<u8>>,
    /// Where the block's header starts in the archive, and its length.
    start: usize,
    header_len: usize,
    // Main header only.
    archive_flags: u64,
}

/// Every block of a RAR 5 archive that begins at byte 0.
fn blocks(archive: &[u8]) -> Vec<Block> {
    assert_eq!(&archive[..8], b"Rar!\x1a\x07\x01\x00");
    let mut out = Vec::new();
    let mut at = 8;
    while at < archive.len() {
        let mut cursor = at + 4;
        let (size, _) = vint(archive, &mut cursor);
        let end = cursor + size as usize;
        assert_eq!(
            rarkit::checksum::crc32(&archive[at + 4..end]),
            u32::from_le_bytes(archive[at..at + 4].try_into().unwrap()),
            "the header checksum of the block at {at}"
        );
        let mut block = Block {
            kind: vint(archive, &mut cursor).0,
            flags: vint(archive, &mut cursor).0,
            ..Block::default()
        };
        let extra = if block.flags & 0x0001 != 0 {
            vint(archive, &mut cursor).0 as usize
        } else {
            0
        };
        if block.flags & 0x0002 != 0 {
            block.data = Some(vint(archive, &mut cursor));
        }
        match block.kind {
            1 => block.archive_flags = vint(archive, &mut cursor).0,
            2 | 3 => {
                block.file_flags = vint(archive, &mut cursor).0;
                block.unpacked = vint(archive, &mut cursor);
                let _attributes = vint(archive, &mut cursor);
                if block.file_flags & 0x0002 != 0 {
                    block.time_field = Some(u32::from_le_bytes(
                        archive[cursor..cursor + 4].try_into().unwrap(),
                    ));
                    cursor += 4;
                }
                if block.file_flags & 0x0004 != 0 {
                    block.has_crc_field = true;
                    cursor += 4;
                }
                block.compression = vint(archive, &mut cursor);
                block.host = vint(archive, &mut cursor).0;
                let (len, _) = vint(archive, &mut cursor);
                block.name = archive[cursor..cursor + len as usize].to_vec();
                cursor += len as usize;
            }
            _ => {}
        }
        if block.kind != 1 && block.kind != 5 {
            assert_eq!(
                cursor,
                end - extra,
                "the fields end where the extra area begins"
            );
        }
        let mut record = end - extra;
        while record < end {
            let (len, _) = vint(archive, &mut record);
            let mut inside = record;
            block.records.push(vint(archive, &mut inside).0);
            record += len as usize;
            block.bodies.push(archive[inside..record].to_vec());
        }
        block.start = at;
        block.header_len = end - at;
        at = end + block.data.map_or(0, |(size, _)| size as usize);
        out.push(block);
    }
    out
}

fn files(all: &[Block]) -> Vec<&Block> {
    all.iter().filter(|block| block.kind == 2).collect()
}

fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// `(name, length, nanoseconds)`: a small member, one that earns a
/// quick-open entry, one whose time has a fraction, and one whose two size
/// fields the reference layout pads past their shortest form.
const MEMBERS: [(&str, usize, u32); 4] = [
    ("hello.txt", 6, 0),
    ("a.bin", 9_000, 0),
    ("frac.txt", 300, 123_456_789),
    ("big.bin", 70_000, 0),
];

fn written(layout: Layout) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        layout,
        host_os: HostOs::Unix,
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    let payloads: Vec<Vec<u8>> = MEMBERS
        .iter()
        .map(|(_, len, _)| filler(*len, *len as u64))
        .collect();
    for ((name, _, nanos), data) in MEMBERS.iter().zip(&payloads) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: Some(Timestamp {
                    unix_seconds: WHEN,
                    nanos: *nanos,
                }),
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn open(archive: &[u8]) -> Archive {
    Archive::open(
        Arc::new(archive.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .expect("the archive opens")
}

/// The shortest vint width of a member's length.
fn shortest(len: usize) -> usize {
    match len {
        0..=127 => 1,
        128..=16_383 => 2,
        _ => 3,
    }
}

/// 3.6.5: what a rewrite does to the members it copies. The source is in
/// the reference layout, which pads the size fields of `hello.txt` (two
/// bytes for 6) and of `a.bin` (three for 9,000).
#[test]
fn a_rewrite_keeps_a_whole_second_time_in_the_header_field() {
    let source = written(Layout::Reference { quick_open: true });
    let before = blocks(&source);
    let padded = files(&before)
        .iter()
        .filter(|file| file.data.unwrap().1 > shortest(file.data.unwrap().0 as usize))
        .count();
    assert_eq!(padded, 2, "the source's padded size fields: {before:?}");

    let mut locked = Vec::new();
    rarkit::edit::lock(&open(&source), &mut locked).expect("lock");
    let after = blocks(&locked);
    assert_eq!(after[0].archive_flags & 0x0010, 0x0010, "the lock flag");
    assert!(
        locked.len() < source.len(),
        "the size fields did not shrink"
    );

    let (was, now) = (files(&before), files(&after));
    assert_eq!(was.len(), MEMBERS.len());
    assert_eq!(now.len(), MEMBERS.len());
    for ((old, new), (name, len, nanos)) in was.iter().zip(&now).zip(MEMBERS) {
        assert_eq!(new.name, name.as_bytes());
        // The two size fields at their shortest width.
        let width = shortest(len);
        assert_eq!(new.data, Some((len as u64, width)), "{name}: data size");
        assert_eq!(new.unpacked, (len as u64, width), "{name}: unpacked size");
        // Everything else as it was: the compression information still two
        // bytes wide, and the time where it was held.
        assert_eq!(new.compression, old.compression, "{name}");
        assert_eq!(
            new.compression.1, 2,
            "{name}: compression information width"
        );
        assert_eq!(new.time_field, old.time_field, "{name}");
        assert_eq!(new.records, old.records, "{name}");
        assert_eq!(new.file_flags, old.file_flags, "{name}");
        if nanos == 0 {
            assert_eq!(
                new.time_field,
                Some(WHEN as u32),
                "{name}: the header field"
            );
            assert!(!new.records.contains(&3), "{name}: a time record");
        } else {
            assert_eq!(new.time_field, None, "{name}: no header field");
            assert_eq!(new.records, [3], "{name}: the time record");
        }
    }
    // The rewritten archive reads back to the same members.
    assert_eq!(open(&locked).members().count(), MEMBERS.len());
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

/// A genuine archive of [`MEMBERS`] in a fresh directory: the directory,
/// and the archive's bytes.
fn genuine(rar: &Path, tag: &str) -> (PathBuf, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("rarkit-forms-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, len, nanos) in MEMBERS {
        let path = dir.join(name);
        std::fs::write(&path, filler(len, len as u64)).unwrap();
        let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(WHEN as u64, nanos);
        std::fs::File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap();
    }
    let made = Command::new(rar)
        .args(["a", "-idq", "-m0", "-ep1", "src.rar"])
        .args(MEMBERS.iter().map(|member| member.0))
        .current_dir(&dir)
        .output()
        .expect("rar a");
    assert!(made.status.success(), "rar a: {made:?}");
    let bytes = std::fs::read(dir.join("src.rar")).unwrap();
    (dir, bytes)
}

/// What the reference makes of `source` under `command`.
fn reference_rewrite(rar: &Path, dir: &Path, source: &[u8], command: &[&str]) -> Vec<u8> {
    let work = dir.join("work.rar");
    std::fs::write(&work, source).unwrap();
    let (verb, rest) = command.split_first().unwrap();
    let ran = Command::new(rar)
        .arg(verb)
        .args(["-idq", "-cfg-", "-y"])
        .args(rest.iter().filter(|arg| arg.starts_with('-')))
        .arg(&work)
        .args(rest.iter().filter(|arg| !arg.starts_with('-')))
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the reference runs");
    assert!(ran.status.success(), "rar {command:?}: {ran:?}");
    std::fs::read(&work).unwrap()
}

/// 3.6.5's probe as a comparison: on a genuine archive, `rar k` and
/// `rar d` and rarkit's `lock` and `remove` write the same bytes.
#[test]
fn a_rewrite_of_a_genuine_archive_is_the_references_rewrite() {
    if cfg!(not(unix)) {
        eprintln!("SKIPPED: the comparison is of reference rar output for a Unix host");
        return;
    }
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("SKIPPED: no reference rar");
        return;
    };
    let (dir, source) = genuine(&rar, "rewrite");

    let theirs = reference_rewrite(&rar, &dir, &source, &["k"]);
    let mut ours = Vec::new();
    rarkit::edit::lock(&open(&source), &mut ours).expect("lock");
    assert!(
        ours == theirs,
        "lock: {} and {} bytes",
        ours.len(),
        theirs.len()
    );

    let theirs = reference_rewrite(&rar, &dir, &source, &["d", "hello.txt"]);
    let mut ours = Vec::new();
    rarkit::edit::remove(&open(&source), &[b"hello.txt"], &mut ours).expect("remove");
    assert!(
        ours == theirs,
        "remove: {} and {} bytes",
        ours.len(),
        theirs.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An archive with one of everything 3.2's table of header flags names: a
/// comment, a directory, an empty file, a member that earns a quick-open
/// entry, and a recovery record.
fn one_of_each(layout: Layout) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        layout,
        host_os: HostOs::Unix,
        comment: Some(b"a rarkit comment\n".to_vec()),
        recovery_percent: Some(5),
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    let full = filler(9_000, 9);
    for (name, data, directory) in [
        ("d", &[][..], true),
        ("e.dat", &[][..], false),
        ("d/a.bin", &full[..], false),
    ] {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: Some(Timestamp {
                    unix_seconds: WHEN,
                    nanos: 0,
                }),
                attributes: if directory { 0o040755 } else { 0o100644 },
                host_os: HostOs::Unix,
                is_directory: directory,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// 3.2's table "what the reference sets, by block", and 3.3.4's table of
/// the service headers, row for row, in the reference layout: a comment
/// header has the data flag alone, and a directory and an empty file have
/// the data flag with a data size of 0.
#[test]
fn the_header_flags_are_the_references_in_the_reference_layout() {
    let all = blocks(&one_of_each(Layout::Reference { quick_open: true }));
    let names: Vec<&[u8]> = all.iter().map(|block| &block.name[..]).collect();
    assert_eq!(
        names,
        [
            &b""[..],
            b"CMT",
            b"d",
            b"e.dat",
            b"d/a.bin",
            b"QO",
            b"RR",
            b""
        ],
        "the order of the blocks (3.6.1)"
    );
    let [main, comment, directory, empty, full, quick_open, recovery, end] = &all[..] else {
        unreachable!()
    };

    // Main: 0x0004, and 0x0001 for its locator; the recovery flag.
    assert_eq!((main.kind, main.flags), (1, 0x0005));
    assert_eq!(main.records, [1]);
    assert_eq!(main.archive_flags, 0x0008);

    // The comment: the data flag ONLY, file flags 0x0004 with the CRC32
    // of the data, no time, compression information 0, host 1, no record.
    assert_eq!((comment.kind, comment.flags), (3, 0x0002));
    assert_eq!(comment.file_flags, 0x0004);
    assert!(comment.has_crc_field && comment.time_field.is_none());
    assert_eq!(comment.data.unwrap().0, 17);
    assert_eq!(comment.unpacked.0, 17);
    assert_eq!((comment.compression.0, comment.host), (0, 1));
    assert!(comment.records.is_empty());

    // A directory and an empty file: the data flag, with a size of 0.
    assert_eq!((directory.kind, directory.flags), (2, 0x0002));
    assert_eq!(directory.data, Some((0, 1)));
    assert_eq!(directory.unpacked, (0, 1));
    assert_eq!(
        directory.file_flags,
        0x0001 | 0x0002,
        "a directory, with a time"
    );
    assert!(!directory.has_crc_field && directory.records.is_empty());
    assert_eq!((empty.kind, empty.flags), (2, 0x0002));
    assert_eq!(empty.data.unwrap().0, 0);
    assert_eq!(
        empty.file_flags,
        0x0002 | 0x0004,
        "a file: a time and a CRC32"
    );
    assert_eq!((full.kind, full.flags), (2, 0x0002));

    // Quick-open: data and skip, no extra area. Recovery: all three.
    assert_eq!((quick_open.kind, quick_open.flags), (3, 0x0006));
    assert_eq!(quick_open.file_flags, 0);
    assert!(quick_open.records.is_empty());
    assert_eq!((recovery.kind, recovery.flags), (3, 0x0007));
    assert_eq!(recovery.file_flags, 0, "no CRC32 field in this layout");
    assert_eq!(recovery.records, [7]);
    assert_eq!(recovery.unpacked.0, recovery.data.unwrap().0);

    // End: 0x0004 and nothing else.
    assert_eq!(
        (end.kind, end.flags, &end.records[..]),
        (5, 0x0004, &[][..])
    );
}

/// The same rows in the default layout, which 3.2 gives the same flags
/// ("rarkit sets the flags as the reference does, row for row"): its own
/// forms are the missing quick-open block (3.5 rule 1) and the CRC32
/// field the recovery header may carry (3.11).
#[test]
fn the_header_flags_are_the_references_in_the_default_layout() {
    let all = blocks(&one_of_each(Layout::Default));
    let names: Vec<&[u8]> = all.iter().map(|block| &block.name[..]).collect();
    assert_eq!(
        names,
        [&b""[..], b"CMT", b"d", b"e.dat", b"d/a.bin", b"RR", b""]
    );
    let [main, comment, directory, empty, full, recovery, end] = &all[..] else {
        unreachable!()
    };
    // No locator: this output is only written to and cannot be patched
    // (3.11, rarkit's own departure), so the main header has no extra
    // area and 0x0004 alone.
    assert_eq!((main.flags, main.archive_flags), (0x0004, 0x0008));
    assert!(main.records.is_empty());
    assert_eq!((comment.flags, comment.file_flags), (0x0002, 0x0004));
    assert_eq!((directory.flags, directory.data), (0x0002, Some((0, 1))));
    assert_eq!((empty.flags, empty.data), (0x0002, Some((0, 1))));
    assert_eq!(full.flags, 0x0002);
    assert_eq!(recovery.flags, 0x0007);
    assert_eq!(recovery.records, [7]);
    assert_eq!(end.flags, 0x0004);
}

fn one_member(options: WriteOptions, len: usize) -> Writer<'static> {
    let mut writer = Writer::new(options).expect("options");
    let data: &'static [u8] = Vec::leak(filler(len, len as u64));
    writer
        .add(MemberSpec {
            name: b"payload.bin",
            payload: Payload::Bytes(data),
            mtime: Some(Timestamp {
                unix_seconds: WHEN,
                nanos: 0,
            }),
            attributes: 0o100644,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    writer
}

fn finished(writer: Writer<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// The flags word of a RAR 4 family main header, which follows the seven
/// byte marker block: checksum (2), type 0x73, then the flags.
fn rar4_main_flags(archive: &[u8]) -> u16 {
    assert_eq!(&archive[..7], b"Rar!\x1a\x07\x00");
    assert_eq!(archive[9], 0x73);
    u16::from_le_bytes([archive[10], archive[11]])
}

/// 3.11, what repair needs of the archive: `rar r` looks for a recovery
/// record only when the main header says there is one (archive flag
/// 0x0008; main flag 0x0040 in the RAR 4 family, 3.14.10), so every
/// archive rarkit gives a record says so, and one it gives none does not.
#[test]
fn an_archive_with_a_recovery_record_says_so_in_its_main_header() {
    let with = |layout, percent| WriteOptions {
        layout,
        recovery_percent: percent,
        host_os: HostOs::Unix,
        workers: Some(1),
        ..WriteOptions::default()
    };
    let reference = Layout::Reference { quick_open: true };

    // A single archive, both layouts, with and without.
    for layout in [Layout::Default, reference] {
        let archive = finished(one_member(with(layout, Some(5)), 20_000));
        assert_eq!(blocks(&archive)[0].archive_flags, 0x0008, "{layout:?}");
        let archive = finished(one_member(with(layout, None), 20_000));
        assert_eq!(blocks(&archive)[0].archive_flags, 0, "{layout:?}");
    }

    // Every volume of a set has its own record and its own flag (beside
    // the volume flag, and the volume number flag after the first).
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    one_member(
        WriteOptions {
            volume_file_size: Some(16_384),
            ..with(Layout::Default, Some(10))
        },
        40_000,
    )
    .finish_volumes(&mut volumes)
    .expect("a set");
    assert!(volumes.len() >= 3, "{} volumes", volumes.len());
    for (index, volume) in volumes.iter().enumerate() {
        let all = blocks(volume);
        let expected = if index == 0 { 0x0009 } else { 0x000b };
        assert_eq!(all[0].archive_flags, expected, "volume {index}");
        assert_eq!(
            all.iter().filter(|block| block.name == b"RR").count(),
            1,
            "volume {index}"
        );
    }

    // An edit that adds a record sets the flag, and one that drops the
    // record clears it.
    let plain = finished(one_member(with(Layout::Default, None), 20_000));
    let mut added = Vec::new();
    rarkit::edit::set_recovery(&open(&plain), Some(5), &mut added).expect("add a record");
    assert_eq!(blocks(&added)[0].archive_flags, 0x0008);
    let mut dropped = Vec::new();
    rarkit::edit::set_recovery(&open(&added), None, &mut dropped).expect("drop the record");
    let all = blocks(&dropped);
    assert_eq!(all[0].archive_flags, 0);
    assert!(all.iter().all(|block| block.name != b"RR"));
    // And one that keeps it (a lock) keeps the flag beside its own.
    let mut locked = Vec::new();
    rarkit::edit::lock(&open(&added), &mut locked).expect("lock");
    assert_eq!(blocks(&locked)[0].archive_flags, 0x0008 | 0x0010);

    // The RAR 4 family: main flag 0x0040.
    let rar4 = |percent| WriteOptions {
        format: rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
        filters: rarkit::FilterPolicy::Off,
        ..with(Layout::Default, percent)
    };
    let archive = finished(one_member(rar4(Some(5)), 20_000));
    assert_eq!(rar4_main_flags(&archive) & 0x0040, 0x0040);
    let archive = finished(one_member(rar4(None), 20_000));
    assert_eq!(rar4_main_flags(&archive) & 0x0040, 0);
}

/// The section's repair probe, with rarkit as the writer: 600 bytes of a
/// 350,000 byte stored member are overwritten and reference `rar r` is
/// asked to repair. It finds the record and writes back the archive,
/// byte for byte, from each form rarkit writes a RAR 5 record in.
#[test]
fn the_reference_repairs_from_a_record_rarkit_wrote() {
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("SKIPPED: no reference rar");
        return;
    };
    let with = |layout| WriteOptions {
        layout,
        recovery_percent: Some(5),
        host_os: HostOs::Unix,
        workers: Some(1),
        ..WriteOptions::default()
    };
    let plain = finished(one_member(
        WriteOptions {
            recovery_percent: None,
            ..with(Layout::Default)
        },
        350_000,
    ));
    let mut by_edit = Vec::new();
    rarkit::edit::set_recovery(&open(&plain), Some(5), &mut by_edit).expect("add a record");
    let mut patched = std::io::Cursor::new(Vec::new());
    one_member(with(Layout::Default), 350_000)
        .finish_seek(&mut patched)
        .expect("finish_seek");

    let dir = std::env::temp_dir().join(format!("rarkit-forms-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (label, archive) in [
        (
            "default",
            finished(one_member(with(Layout::Default), 350_000)),
        ),
        ("default-with-locator", patched.into_inner()),
        (
            "reference",
            finished(one_member(
                with(Layout::Reference { quick_open: true }),
                350_000,
            )),
        ),
        ("edit", by_edit),
    ] {
        let mut damaged = archive.clone();
        for byte in &mut damaged[100_000..100_600] {
            *byte ^= 0x77;
        }
        let name = format!("{label}.rar");
        std::fs::write(dir.join(&name), &damaged).unwrap();
        let ran = Command::new(&rar)
            .args(["r", "-y", &name])
            .current_dir(&dir)
            .output()
            .expect("rar r");
        let said = String::from_utf8_lossy(&ran.stdout).replace('\r', "\n");
        assert!(
            said.contains("Data recovery record found"),
            "{label}: {said}"
        );
        let fixed = std::fs::read(dir.join(format!("fixed.{name}")))
            .unwrap_or_else(|_| panic!("{label}: no fixed file: {said}"));
        assert!(
            fixed == archive,
            "{label}: the repaired file differs: {said}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The main header's locator as `(quick-open offset, recovery offset)`,
/// each `None` without its flag (3.3.2).
fn locator(main: &Block) -> (Option<u64>, Option<u64>) {
    let Some(index) = main.records.iter().position(|kind| *kind == 1) else {
        return (None, None);
    };
    let body = &main.bodies[index];
    let mut at = 0;
    let flags = vint(body, &mut at).0;
    let quick_open = (flags & 0x0001 != 0).then(|| vint(body, &mut at).0);
    let recovery = (flags & 0x0002 != 0).then(|| vint(body, &mut at).0);
    assert_eq!(at, body.len(), "nothing after the locator's offsets");
    (quick_open, recovery)
}

/// 3.15's two requirements of an edit's output, checked from its bytes:
/// each locator offset names the block that is there, measured from the
/// first byte of the main header, or is zero; and a quick-open block
/// holds, for exactly the members whose data is longer than 4,096 bytes
/// and in their order, a copy of the header as it now is at the distance
/// it now is (3.6.6).
fn locator_and_quick_open_are_right(what: &str, archive: &[u8]) {
    let all = blocks(archive);
    let main = &all[0];
    let named = |name: &[u8]| {
        all.iter()
            .find(|block| block.kind == 3 && block.name == name)
    };
    let (quick_open_at, recovery_at) = locator(main);
    for (offset, name) in [(quick_open_at, &b"QO"[..]), (recovery_at, &b"RR"[..])] {
        match (offset, named(name)) {
            (Some(0), _) | (None, _) => {}
            (Some(offset), Some(block)) => {
                assert_eq!(
                    main.start + offset as usize,
                    block.start,
                    "{what}: the offset"
                )
            }
            (Some(offset), None) => panic!("{what}: an offset of {offset} and no block"),
        }
    }
    assert_eq!(
        main.archive_flags & 0x0008 != 0,
        named(b"RR").is_some(),
        "{what}: the recovery flag and the block"
    );

    let earning: Vec<&Block> = files(&all)
        .into_iter()
        .filter(|file| file.data.unwrap().0 > 4_096)
        .collect();
    let Some(index) = named(b"QO") else {
        // No block: then no locator claims one.
        assert!(matches!(quick_open_at, None | Some(0)), "{what}");
        return;
    };
    assert_eq!(
        quick_open_at,
        Some((index.start - main.start) as u64),
        "{what}"
    );
    let data = &archive[index.start + index.header_len..][..index.data.unwrap().0 as usize];
    let mut at = 0;
    let mut seen = 0;
    while at < data.len() {
        let sum = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        let mut cursor = at + 4;
        let (size, _) = vint(data, &mut cursor);
        let end = cursor + size as usize;
        assert_eq!(
            rarkit::checksum::crc32(&data[at + 4..end]),
            sum,
            "{what}: entry"
        );
        assert_eq!(vint(data, &mut cursor).0, 0, "{what}: entry flags");
        let back = vint(data, &mut cursor).0 as usize;
        let len = vint(data, &mut cursor).0 as usize;
        let member = earning
            .get(seen)
            .unwrap_or_else(|| panic!("{what}: an entry too many"));
        assert_eq!(
            index.start - back,
            member.start,
            "{what}: entry {seen}'s distance"
        );
        assert_eq!(len, member.header_len, "{what}: entry {seen}'s length");
        assert!(
            data[cursor..end] == archive[member.start..member.start + len],
            "{what}: entry {seen} is not the header as it now is"
        );
        seen += 1;
        at = end;
    }
    assert_eq!(
        seen,
        earning.len(),
        "{what}: an entry for every earning member"
    );
}

/// Every edit there is, on an archive in the reference layout: the
/// output's locator and quick-open block are right. Headers grow and
/// shrink (a rename), members go (a remove), a block is put in front of
/// them all (a comment) and one behind (a record).
#[test]
fn an_edit_leaves_the_locator_and_the_quick_open_block_right() {
    let source = written(Layout::Reference { quick_open: true });
    locator_and_quick_open_are_right("the source", &source);
    let src = open(&source);

    let mut edits: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut out = Vec::new();
    rarkit::edit::lock(&src, &mut out).expect("lock");
    edits.push(("lock", std::mem::take(&mut out)));
    rarkit::edit::set_comment(&src, Some(b"a rarkit comment\n"), &mut out).expect("comment");
    edits.push(("comment", std::mem::take(&mut out)));
    rarkit::edit::remove(&src, &[b"hello.txt"], &mut out).expect("remove");
    edits.push(("remove a small member", std::mem::take(&mut out)));
    rarkit::edit::remove(&src, &[b"a.bin"], &mut out).expect("remove");
    edits.push(("remove an earning member", std::mem::take(&mut out)));
    rarkit::edit::rename(
        &src,
        b"a.bin",
        b"a-much-longer-name-than-before.bin",
        &mut out,
    )
    .expect("rename");
    edits.push(("rename longer", std::mem::take(&mut out)));
    rarkit::edit::rename(&src, b"big.bin", b"b", &mut out).expect("rename");
    edits.push(("rename shorter", std::mem::take(&mut out)));
    rarkit::edit::set_recovery(&src, Some(5), &mut out).expect("record");
    edits.push(("add a record", std::mem::take(&mut out)));

    for (what, archive) in &edits {
        locator_and_quick_open_are_right(what, archive);
        // And each is an archive: it opens, and an edit of it is right too.
        let again = open(archive);
        assert!(again.members().count() >= MEMBERS.len() - 1, "{what}");
        let mut twice = Vec::new();
        rarkit::edit::set_comment(&again, Some(b"twice"), &mut twice).expect("a second edit");
        locator_and_quick_open_are_right(&format!("{what}, then a comment"), &twice);
        let mut none = Vec::new();
        rarkit::edit::set_recovery(&open(&twice), None, &mut none).expect("a third edit");
        locator_and_quick_open_are_right(&format!("{what}, then no record"), &none);
    }

    // With both earning members gone no entry is left: the block is
    // dropped, and so is the locator that would have named it.
    rarkit::edit::remove(&src, &[b"a.bin", b"big.bin"], &mut out).expect("remove");
    let all = blocks(&out);
    locator_and_quick_open_are_right("no earning member left", &out);
    assert!(all.iter().all(|block| block.name != b"QO"));
    assert_eq!((all[0].flags, &all[0].records[..]), (0x0004, &[][..]));

    // The default layout has neither (3.5 rule 1), and an edit adds none.
    let plain = written(Layout::Default);
    let mut out = Vec::new();
    rarkit::edit::lock(&open(&plain), &mut out).expect("lock");
    let all = blocks(&out);
    assert!(all.iter().all(|block| block.name != b"QO"));
    assert_eq!(locator(&all[0]), (None, None));
}

/// Zeroes what 3.6.1 allows to differ in a recovery record: each record's
/// tag and its own checksum over it.
fn without_tags(archive: &[u8]) -> Vec<u8> {
    let mut out = archive.to_vec();
    let mut at = 0;
    while let Some(found) = out[at..].windows(4).position(|w| w == b"{RB}") {
        let start = at + found;
        let shards = usize::from(u16::from_le_bytes([out[start + 0x3a], out[start + 0x3b]]));
        out[start + 4..start + 12].fill(0);
        out[start + 0x40 + 8 * shards..start + 0x48 + 8 * shards].fill(0);
        at = start + 4;
    }
    out
}

/// 3.15's last paragraph: when the input is in the reference layout the
/// output is the reference's, in that same form. On a genuine archive,
/// `rar c` and `rar rr5` and rarkit's `set_comment` and `set_recovery`
/// write the same bytes (but for each record's tag, 3.6.1), and both
/// reference readers accept every edit with nothing on stderr.
#[test]
fn an_edit_of_a_genuine_archive_stays_in_the_reference_layout() {
    if cfg!(not(unix)) {
        eprintln!("SKIPPED: the comparison is of reference rar output for a Unix host");
        return;
    }
    let (Some(rar), Some(unrar)) = (
        reference("rar", "RARKIT_REF_RAR"),
        reference("unrar", "RARKIT_REF_UNRAR"),
    ) else {
        eprintln!("SKIPPED: no reference rar and unrar");
        return;
    };
    let (dir, source) = genuine(&rar, "edit");
    let src = open(&source);
    std::fs::write(dir.join("comment.txt"), b"a rarkit comment\n").unwrap();

    let theirs = reference_rewrite(&rar, &dir, &source, &["c", "-zcomment.txt"]);
    let mut commented = Vec::new();
    rarkit::edit::set_comment(&src, Some(b"a rarkit comment\n"), &mut commented).expect("comment");
    assert!(
        commented == theirs,
        "comment: {} and {} bytes",
        commented.len(),
        theirs.len()
    );

    let theirs = reference_rewrite(&rar, &dir, &source, &["rr5"]);
    let mut recorded = Vec::new();
    rarkit::edit::set_recovery(&src, Some(5), &mut recorded).expect("record");
    assert_eq!(recorded.len(), theirs.len(), "record: lengths");
    assert!(
        without_tags(&recorded) == without_tags(&theirs),
        "record: bytes other than the tags differ"
    );

    let mut renamed = Vec::new();
    rarkit::edit::rename(
        &src,
        b"a.bin",
        b"a-much-longer-name-than-before.bin",
        &mut renamed,
    )
    .expect("rename");
    for (what, archive) in [
        ("comment", &commented),
        ("record", &recorded),
        ("rename", &renamed),
    ] {
        std::fs::write(dir.join("ours.rar"), archive).unwrap();
        for tool in [&rar, &unrar] {
            let tested = Command::new(tool)
                .args(["t", "ours.rar"])
                .current_dir(&dir)
                .output()
                .expect("a test run");
            assert!(
                tested.status.success() && tested.stderr.is_empty(),
                "{what}: {tested:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 3.3.4: the service headers an edit builds name the system the CALLER
/// says the edit is made on (`EditOptions::host_os`), on any machine, and
/// a member's own host field stays what it was. With no option the
/// functions of `rarkit::edit` name the system the build runs on, as they
/// did.
#[test]
fn an_edit_names_the_host_its_caller_names() {
    use rarkit::edit::EditOptions;

    let comment: &[u8] = b"a rarkit comment\n";
    // RAR 5, a source in the reference layout: the comment, the rebuilt
    // quick-open index and the record are all the edit's own headers.
    let source = written(Layout::Reference { quick_open: true });
    let src = open(&source);
    for (host, byte) in [(HostOs::Unix, 1u64), (HostOs::Windows, 0)] {
        let options = EditOptions { host_os: host };
        let mut commented = Vec::new();
        options
            .set_comment(&src, Some(comment), &mut commented)
            .expect("comment");
        let mut recorded = Vec::new();
        options
            .set_recovery(&open(&commented), Some(5), &mut recorded)
            .expect("record");
        let all = blocks(&recorded);
        let services: Vec<(&[u8], u64)> = all
            .iter()
            .filter(|block| block.kind == 3)
            .map(|block| (&block.name[..], block.host))
            .collect();
        assert_eq!(
            services,
            [(&b"CMT"[..], byte), (b"QO", byte), (b"RR", byte)],
            "{host:?}"
        );
        // The members came from a Unix system and still say so.
        assert!(files(&all).iter().all(|file| file.host == 1), "{host:?}");
        locator_and_quick_open_are_right(&format!("{host:?}"), &recorded);
    }

    // The RAR 4 family: 3 is Unix and 2 is Windows there (3.14.3).
    let rar4 = finished(one_member(
        WriteOptions {
            format: rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
            filters: rarkit::FilterPolicy::Off,
            host_os: HostOs::Unix,
            workers: Some(1),
            ..WriteOptions::default()
        },
        20_000,
    ));
    for (host, byte) in [(HostOs::Unix, 3u8), (HostOs::Windows, 2)] {
        let options = EditOptions { host_os: host };
        let mut commented = Vec::new();
        options
            .set_comment(&open(&rar4), Some(comment), &mut commented)
            .expect("comment");
        let mut recorded = Vec::new();
        options
            .set_recovery(&open(&commented), Some(5), &mut recorded)
            .expect("record");
        // Every sub block (type 0x7a) by the frame of 3.14.1; its name
        // is 32 bytes into the block and its host byte 15 (3.14.3).
        let mut hosts = Vec::new();
        let mut at = 7;
        while at < recorded.len() {
            let block = &recorded[at..];
            let flags = u16::from_le_bytes([block[3], block[4]]);
            let size = usize::from(u16::from_le_bytes([block[5], block[6]]));
            let data = if flags & 0x8000 != 0 {
                u32::from_le_bytes(block[7..11].try_into().unwrap()) as usize
            } else {
                0
            };
            if block[2] == 0x7a {
                let name = usize::from(u16::from_le_bytes([block[26], block[27]]));
                hosts.push((block[32..32 + name].to_vec(), block[15]));
            }
            at += size + data;
        }
        assert_eq!(
            hosts,
            [(b"CMT".to_vec(), byte), (b"RR".to_vec(), byte)],
            "{host:?}"
        );
    }

    // No option is the build's own system, which is what the plain
    // functions wrote before there was one.
    let build = if cfg!(windows) {
        HostOs::Windows
    } else {
        HostOs::Unix
    };
    assert_eq!(EditOptions::default(), EditOptions { host_os: build });
    let mut plain = Vec::new();
    rarkit::edit::set_comment(&src, Some(comment), &mut plain).expect("comment");
    let mut named = Vec::new();
    EditOptions { host_os: build }
        .set_comment(&src, Some(comment), &mut named)
        .expect("comment");
    assert!(plain == named);
}
