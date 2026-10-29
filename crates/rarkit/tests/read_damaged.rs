//! `ReadOptions::read_damaged`: reading on through the damage the
//! reference reads through, and what stays as spec F 4.6 has it.
//!
//! Every archive is written here, by this crate's writer (RAR 5, stored,
//! the reference layout with and without a quick open record), and
//! damaged in memory. What the reference does with each shape was
//! measured with unrar 7.23 on 8 Oct 2026 and is pinned end to end in
//! `rarkit-cli`'s `tests/damaged_archive_walk.rs`; this file holds the
//! library's half: what the option changes, what it reports, and that a
//! sound header is never answered from a quick open copy.
//!
//! One thread throughout (the sequential driver, `workers` 1); every
//! archive is under 64 KiB and held in memory, so no test needs more than
//! a few MiB.

use std::sync::Arc;

use rarkit::{
    extract, Archive, BlockKind, Disposition, ErrorKind, Layout, MemberInfo, MemberOutcome,
    MemberSpec, Payload, RangeSource, ReadOptions, Sink, WriteOptions, Writer,
};

const NAMES: [&str; 4] = ["one.txt", "two.bin", "dir/three.txt", "four.txt"];

fn body(index: usize) -> Vec<u8> {
    let mut state = (index as u32 + 1).wrapping_mul(0x9e37_79b9) | 1;
    (0..9_000 + index * 1_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b'a' + (state % 23) as u8
        })
        .collect()
}

/// Four stored members in the reference layout.
fn archive(quick_open: bool) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        layout: Layout::Reference { quick_open },
        ..WriteOptions::default()
    })
    .expect("options");
    let bodies: Vec<Vec<u8>> = (0..NAMES.len()).map(body).collect();
    for (name, bytes) in NAMES.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
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

/// (start, header end, kind) of every block of a sound RAR 5 archive.
fn blocks(bytes: &[u8]) -> Vec<(usize, usize, u64)> {
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
        out.push((at, header_end, kind));
        at = header_end + data;
    }
    out
}

fn files(bytes: &[u8]) -> Vec<(usize, usize, u64)> {
    blocks(bytes).into_iter().filter(|b| b.2 == 2).collect()
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

fn source(bytes: &[u8]) -> Arc<dyn RangeSource> {
    Arc::new(bytes.to_vec())
}

fn lenient() -> ReadOptions {
    ReadOptions::default()
        .with_tolerant_tail(true)
        .with_read_damaged(true)
        .with_workers(Some(1))
}

/// (name, bytes, checksum verdict) of every member closed.
#[derive(Default)]
struct Keep(Vec<(String, Vec<u8>, Option<bool>)>);

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.push((
            member.name_lossy().into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

fn names_of(archive: &Archive) -> Vec<String> {
    archive
        .members()
        .map(|m| m.name_lossy().into_owned())
        .collect()
}

/// Every member, whole, with its checksum good.
fn all_good() -> Vec<(String, Vec<u8>, Option<bool>)> {
    NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| ((*name).to_owned(), body(index), Some(true)))
        .collect()
}

/// Without the option a header whose checksum fails ends the walk, as
/// spec F 4.6 has it. With it the header is read, named by
/// `damaged_headers`, and its member and every later one is delivered
/// and checked.
#[test]
fn a_member_header_with_a_bad_checksum_is_read_only_when_asked() {
    let sound = archive(false);
    for which in 0..NAMES.len() {
        let at = files(&sound)[which];
        let mut bytes = sound.clone();
        bytes[at.0] ^= 0x55;

        let strict = Archive::open(source(&bytes), &ReadOptions::default());
        assert!(
            matches!(
                strict.as_ref().err().map(rarkit::Error::kind),
                Some(ErrorKind::HeaderChecksum)
            ),
            "member {which}: {:?}",
            strict.err()
        );
        let tolerant = ReadOptions::default().with_tolerant_tail(true);
        let kept = Archive::open(source(&bytes), &tolerant).expect("tolerant");
        assert_eq!(names_of(&kept), NAMES[..which], "member {which}");
        assert!(kept.damaged_headers().is_empty());

        let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
        assert_eq!(names_of(&archive), NAMES, "member {which}");
        assert!(archive.tail().is_none(), "member {which}");
        let damaged = archive.damaged_headers();
        assert_eq!(damaged.len(), 1, "member {which}");
        assert_eq!(damaged[0].kind, BlockKind::File);
        assert_eq!(damaged[0].member, Some(which));
        assert_eq!(damaged[0].range, at.0 as u64..at.1 as u64);

        let mut sink = Keep::default();
        extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
        assert_eq!(sink.0, all_good(), "member {which}");
    }
}

/// The main header: refused without the option, read and named with it.
#[test]
fn a_main_header_with_a_bad_checksum_is_read_only_when_asked() {
    let mut bytes = archive(false);
    let main = blocks(&bytes)[0];
    assert_eq!(main.2, 1);
    bytes[main.0] ^= 0x55;
    assert!(Archive::open(source(&bytes), &ReadOptions::default()).is_err());

    let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES);
    let damaged = archive.damaged_headers();
    assert_eq!(damaged.len(), 1);
    assert_eq!(
        (damaged[0].kind, damaged[0].member),
        (BlockKind::Main, None)
    );
    let mut sink = Keep::default();
    extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
    assert_eq!(sink.0, all_good());
}

/// A header read through its failed checksum is believed no further than
/// its own fields go: the member behind it is still judged by the
/// checksum that header states for its data, so a header damaged IN that
/// field fails its member, and that member alone.
#[test]
fn a_member_read_from_a_damaged_header_is_still_checked() {
    let sound = archive(false);
    let at = files(&sound)[1];
    // The data CRC32 follows the header's fixed fields; find it by value.
    let stated = crc32(&body(1)).to_le_bytes();
    let field = (at.0..at.1 - 4)
        .find(|&i| sound[i..i + 4] == stated)
        .expect("the member's CRC32 field");
    let mut bytes = sound.clone();
    bytes[field] ^= 0x01;

    let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
    assert_eq!(archive.damaged_headers().len(), 1);
    let mut sink = Keep::default();
    extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
    let verdicts: Vec<Option<bool>> = sink.0.iter().map(|m| m.2).collect();
    assert_eq!(
        verdicts,
        [Some(true), Some(false), Some(true), Some(true)],
        "only the member whose stated checksum was damaged fails"
    );
}

/// With a quick open record, a member header whose checksum fails is read
/// from the record's sound copy, and reported all the same; an entry
/// whose own checksum fails is not used, and the header is read as it
/// stands.
#[test]
fn a_damaged_member_header_is_read_from_a_sound_quick_open_copy() {
    let sound = archive(true);
    let all = blocks(&sound);
    let service = *all.iter().find(|b| b.2 == 3).expect("a quick open record");
    for which in 0..NAMES.len() {
        let at = files(&sound)[which];
        let mut bytes = sound.clone();
        // The header's own size field: without the copy this header does
        // not frame at all.
        bytes[at.0 + 4] ^= 0x01;
        let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
        assert_eq!(names_of(&archive), NAMES, "member {which}");
        assert!(archive.tail().is_none(), "member {which}");
        // Reported all the same: spec F 3.2.9.1 rule 4.
        let damaged = archive.damaged_headers();
        assert_eq!(damaged.len(), 1, "member {which}");
        assert_eq!(
            (damaged[0].member, damaged[0].from_copy),
            (Some(which), true),
            "member {which}"
        );
        let mut sink = Keep::default();
        extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
        assert_eq!(sink.0, all_good(), "member {which}");
    }

    // The first entry's checksum field is the record's first data byte.
    let at = files(&sound)[0];
    let mut bytes = sound.clone();
    bytes[at.0] ^= 0x55;
    bytes[service.1] ^= 0x55;
    let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES);
    assert_eq!(archive.damaged_headers().len(), 1);
    assert_eq!(archive.damaged_headers()[0].member, Some(0));
    assert!(!archive.damaged_headers()[0].from_copy);
}

/// Spec F section 8 item 7 stands: a header that is SOUND is never
/// answered from a quick open copy, with the option or without it. The
/// first entry's copy is rewritten to name the member `ZZZ.txt`, its own
/// checksum and the entry's redone, so the copy is as sound as a copy
/// can be: the member is still listed and extracted under its real name.
#[test]
fn a_sound_header_is_never_read_from_a_quick_open_copy() {
    let mut bytes = archive(true);
    let service = *blocks(&bytes)
        .iter()
        .find(|b| b.2 == 3)
        .expect("a quick open record");
    // One entry: CRC32, size, flags, distance back, cached size, header.
    let entry = service.1;
    let (size, fields) = vint(&bytes, entry + 4);
    let entry_end = fields + size as usize;
    let (_, at) = vint(&bytes, fields);
    let (_, at) = vint(&bytes, at);
    let (cached, copy) = vint(&bytes, at);
    let copy_end = copy + cached as usize;
    assert_eq!(copy_end, entry_end, "the copy fills the entry");
    let name = (copy..=copy_end - 7)
        .find(|&i| &bytes[i..i + 7] == b"one.txt")
        .expect("the copied name");
    bytes[name..name + 3].copy_from_slice(b"ZZZ");
    let header = crc32(&bytes[copy + 4..copy_end]).to_le_bytes();
    bytes[copy..copy + 4].copy_from_slice(&header);
    let whole = crc32(&bytes[entry + 4..entry_end]).to_le_bytes();
    bytes[entry..entry + 4].copy_from_slice(&whole);

    for options in [ReadOptions::default().with_workers(Some(1)), lenient()] {
        let archive = Archive::open(source(&bytes), &options).expect("open");
        assert_eq!(names_of(&archive), NAMES);
        assert!(archive.damaged_headers().is_empty());
        let mut sink = Keep::default();
        extract(vec![source(&bytes)], &options, &mut sink, &mut ()).expect("extract");
        assert_eq!(sink.0, all_good());
    }
}

/// A volume that ends at a block boundary with no end record is a
/// complete read (spec F 3.5.5 K4), unless its main header's locator
/// names a quick open record the source does not reach and the caller
/// asked: then it is `Truncated`, with the members in front kept.
#[test]
fn a_cut_short_of_the_quick_open_record_is_truncated_only_when_asked() {
    let sound = archive(true);
    let third = files(&sound)[2].0;
    let cut = &sound[..third];

    let strict = Archive::open(source(cut), &ReadOptions::default()).expect("a complete read");
    assert_eq!(names_of(&strict), NAMES[..2]);

    let archive = Archive::open(source(cut), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES[..2]);
    assert!(matches!(
        archive.tail().map(rarkit::Error::kind),
        Some(ErrorKind::Truncated)
    ));
    let mut sink = Keep::default();
    let ended = extract(vec![source(cut)], &lenient(), &mut sink, &mut ());
    assert!(
        matches!(
            ended.as_ref().err().map(rarkit::Error::kind),
            Some(ErrorKind::Truncated)
        ),
        "{:?}",
        ended.err()
    );
    assert_eq!(sink.0, all_good()[..2]);

    // The locator of a main header whose own checksum failed is not used
    // (3.2.8 rule 1): the same cut is then a complete read, with the main
    // header reported.
    let mut unsound = cut.to_vec();
    unsound[blocks(&sound)[0].0] ^= 0x55;
    let archive = Archive::open(source(&unsound), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES[..2]);
    assert!(archive.tail().is_none());
    assert_eq!(archive.damaged_headers().len(), 1);

    // The record's own header is not sound: the walk is made to the end
    // record and the header is reported (4.6). A block the walk read
    // begins at the offset, so nothing more is said of the locator (3.2.8
    // rule 2 case a, as settled on 9 Oct 2026; until then the volume was
    // also reported as having lost its tail).
    let mut unsound = sound.clone();
    let service = blocks(&sound).into_iter().find(|b| b.2 == 3).unwrap();
    unsound[service.0] ^= 0x55;
    let archive = Archive::open(source(&unsound), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES);
    assert_eq!(archive.damaged_headers().len(), 1);
    assert!(archive.tail().is_none());

    // With no record there is no locator to it, and the same cut is a
    // complete read either way.
    let plain = archive_without_record();
    let cut = &plain[..files(&plain)[2].0];
    let archive = Archive::open(source(cut), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), NAMES[..2]);
    assert!(archive.tail().is_none());
}

fn archive_without_record() -> Vec<u8> {
    let bytes = archive(false);
    assert!(blocks(&bytes).iter().all(|b| b.2 != 3));
    bytes
}

/// The table of damaged headers is a report with a bound: a volume in
/// which EVERY header's checksum fails is read to its end all the same,
/// every member delivered and checked, and the table keeps the first
/// `DAMAGED_HEADERS_KEPT`.
#[test]
fn the_table_of_damaged_headers_is_bounded() {
    let count = rarkit::DAMAGED_HEADERS_KEPT + 44;
    let mut writer = Writer::new(WriteOptions {
        layout: Layout::Reference { quick_open: false },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<String> = (0..count).map(|i| format!("m{i:03}.txt")).collect();
    for name in &names {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(name.as_bytes()),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).expect("finish");
    for (start, _, _) in blocks(&bytes) {
        bytes[start] ^= 0x55;
    }

    let archive = Archive::open(source(&bytes), &lenient()).expect("lenient");
    assert_eq!(names_of(&archive), names);
    let damaged = archive.damaged_headers();
    assert_eq!(damaged.len(), rarkit::DAMAGED_HEADERS_KEPT);
    assert_eq!(damaged[0].kind, BlockKind::Main);
    assert_eq!(damaged[1].member, Some(0));

    let mut sink = Keep::default();
    extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
    assert_eq!(sink.0.len(), count);
    assert!(sink
        .0
        .iter()
        .zip(&names)
        .all(|(got, name)| got.0 == *name && got.1 == name.as_bytes() && got.2 == Some(true)));
}

/// `extract`'s own report counts every header read through a failed
/// checksum (spec F 4.6 rule 1): a caller of the free function holds no
/// `Archive` to ask, and a report whose members are all good by their
/// data checksums would otherwise read as a success. Zero on a sound
/// archive; one for each such header, in whichever volume it sits.
/// One thread but where it says four; under 100 KiB of archive in memory.
#[test]
fn the_extract_report_counts_a_header_read_through_a_failed_checksum() {
    let sound = archive(false);
    let mut sink = Keep::default();
    let report = extract(vec![source(&sound)], &lenient(), &mut sink, &mut ()).expect("sound");
    assert_eq!((report.members, report.damaged_headers), (4, 0));

    for which in 0..NAMES.len() {
        let at = files(&sound)[which];
        let mut bytes = sound.clone();
        bytes[at.0] ^= 0x55;
        let mut sink = Keep::default();
        let report =
            extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
        assert_eq!(sink.0, all_good(), "member {which}");
        assert_eq!(
            (
                report.members,
                report.checksum_failures,
                report.damaged_headers
            ),
            (4, 0, 1),
            "member {which}"
        );
    }

    // The same count behind the decode-ahead driver: a pool of four
    // threads here, where every other test of this file states one.
    let mut bytes = sound.clone();
    bytes[files(&sound)[2].0] ^= 0x55;
    let mut sink = Keep::default();
    let wide = lenient().with_workers(Some(4));
    let report = extract(vec![source(&bytes)], &wide, &mut sink, &mut ()).expect("wide");
    assert_eq!(sink.0, all_good());
    assert_eq!((report.members, report.damaged_headers), (4, 1));

    // Two of them, and one that is no member's: the end record.
    let all = blocks(&sound);
    let end = all.iter().find(|b| b.2 == 5).expect("an end record");
    let mut bytes = sound.clone();
    bytes[files(&sound)[1].0] ^= 0x55;
    bytes[files(&sound)[3].0] ^= 0x55;
    bytes[end.0] ^= 0x55;
    let mut sink = Keep::default();
    let report = extract(vec![source(&bytes)], &lenient(), &mut sink, &mut ()).expect("extract");
    assert_eq!(sink.0, all_good());
    assert_eq!((report.members, report.damaged_headers), (4, 3));

    // A set: one such header in each of two volumes.
    let mut writer = Writer::new(WriteOptions {
        volume_file_size: Some(16_000),
        ..WriteOptions::default()
    })
    .expect("options");
    let bodies: Vec<Vec<u8>> = (0..NAMES.len()).map(body).collect();
    for (name, bytes) in NAMES.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut set: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut set).expect("finish");
    assert!(set.len() >= 3, "{} volumes", set.len());
    let whole = |set: &[Vec<u8>]| -> Vec<Arc<dyn RangeSource>> {
        set.iter().map(|volume| source(volume)).collect()
    };
    let mut sink = Keep::default();
    let report = extract(whole(&set), &lenient(), &mut sink, &mut ()).expect("sound set");
    assert_eq!(sink.0, all_good());
    assert_eq!((report.members, report.damaged_headers), (4, 0));
    for volume in [0, 2] {
        let at = files(&set[volume])[0].0;
        set[volume][at] ^= 0x55;
    }
    let mut sink = Keep::default();
    let report = extract(whole(&set), &lenient(), &mut sink, &mut ()).expect("damaged set");
    assert_eq!(sink.0, all_good());
    assert_eq!((report.members, report.damaged_headers), (4, 2));
}
