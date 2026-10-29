//! A rewrite keeps what it was not asked to change, or refuses by name.
//!
//! Each test here is one item of the bug sweep of 4 Oct 2026 over
//! `rarkit::edit`, written to fail on the code as it stood: a rewrite
//! that returned Ok over an output that had silently lost something.
//!
//! Width and memory: every archive here is STORED and a few kilobytes, a
//! rewrite copies bytes on the calling thread, and the reads use the
//! default memory policy except where a test names another. Nothing
//! follows the machine's thread count.

use std::sync::Arc;

use rarkit::{
    edit, extract, Archive, BlockKind, Disposition, HostOs, MemberInfo, MemberSpec, MemoryPolicy,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, ServiceKind, Sink, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)];

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 7 + usize::from(seed) * 31 + 3) % 251) as u8)
        .collect()
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(b), Some(last)) = (out, self.members.last_mut()) {
            last.1 = b;
        }
        Ok(())
    }
}

fn read_back(archive: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back an edited archive: {e}"));
    sink.members
}

fn open_with(archive: &[u8], options: &ReadOptions) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    Archive::open(src, options).expect("open")
}

fn open(archive: &[u8]) -> Archive {
    open_with(archive, &ReadOptions::default())
}

/// What an archive of these members is written with.
#[derive(Default)]
struct Shape<'a> {
    comment: Option<&'a [u8]>,
    recovery_percent: Option<u32>,
}

fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b"a.txt".to_vec(), bytes(3_000, 1)),
        (b"b.txt".to_vec(), bytes(3_000, 2)),
        (b"c.txt".to_vec(), bytes(3_000, 3)),
    ]
}

fn archive(format: WriteFormat, shape: &Shape<'_>) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        order: rarkit::MemberOrder::AsAdded,
        host_os: HostOs::Unix,
        comment: shape.comment.map(|c| c.to_vec()),
        recovery_percent: shape.recovery_percent,
        ..WriteOptions::default()
    })
    .expect("options");
    let members = members();
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn has_record(archive: &Archive) -> bool {
    archive
        .services()
        .any(|svc| svc.kind == ServiceKind::RecoveryRecord)
}

/// M-21: an edit that says nothing about the recovery record keeps one,
/// in the RAR 4 family as in RAR 5.
#[test]
fn an_edit_that_does_not_name_the_recovery_record_keeps_it() {
    for format in FORMATS {
        let source = archive(
            format,
            &Shape {
                recovery_percent: Some(10),
                ..Shape::default()
            },
        );
        let src = open(&source);
        assert!(has_record(&src), "{format:?}: the fixture has no record");

        let mut locked = Vec::new();
        edit::lock(&src, &mut locked).expect("lock");
        let after = open(&locked);
        assert!(
            has_record(&after) && after.has_recovery_record(),
            "{format:?}: lock dropped the recovery record"
        );
        assert_eq!(read_back(&locked), members(), "{format:?}: lock");

        let mut renamed = Vec::new();
        let report = edit::rename(&src, b"a.txt", b"z.txt", &mut renamed).expect("rename");
        assert!(report.recovery, "{format:?}: the report says no record");
        assert!(
            has_record(&open(&renamed)),
            "{format:?}: rename dropped the recovery record"
        );
        // The record that came back is one the repair path accepts: the
        // archive verifies against it.
        let mut fixed = Vec::new();
        rarkit::recovery::repair_inline(&renamed, &ReadOptions::default(), &mut fixed)
            .unwrap_or_else(|e| panic!("{format:?}: the rebuilt record does not verify: {e}"));
    }
}

fn read_vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return value;
        }
    }
}

fn put_vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// M-21, the RAR 5 half: a record whose header carries no percentage (its
/// extra area taken out here, the header resealed) cannot be rebuilt "at
/// the same percentage", and the rewrite says so instead of dropping it.
#[test]
fn a_rar5_record_that_states_no_percentage_is_refused_not_dropped() {
    let source = archive(
        WriteFormat::Rar5,
        &Shape {
            recovery_percent: Some(10),
            ..Shape::default()
        },
    );
    let record = open(&source)
        .blocks()
        .find(|b| b.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
        .expect("the record")
        .range;
    let start = record.start as usize;
    let mut at = start + 4;
    let size = read_vint(&source, &mut at) as usize;
    let end = at + size;
    let kind = read_vint(&source, &mut at);
    let flags = read_vint(&source, &mut at);
    assert_eq!(flags & 1, 1, "the fixture's record has no extra area");
    let extra = read_vint(&source, &mut at) as usize;
    let mut body = Vec::new();
    put_vint(kind, &mut body);
    put_vint(flags & !1, &mut body);
    body.extend_from_slice(&source[at..end - extra]);
    let mut sized = Vec::new();
    put_vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(&body);
    let mut bare = source[..start].to_vec();
    bare.extend_from_slice(&rarkit::checksum::crc32(&sized).to_le_bytes());
    bare.extend_from_slice(&sized);
    bare.extend_from_slice(&source[end..]);

    let src = open(&bare);
    let silent = src
        .services()
        .find(|svc| svc.kind == ServiceKind::RecoveryRecord)
        .expect("the record is still read as one");
    assert_eq!(silent.recovery_percent, None);

    let mut out = Vec::new();
    assert!(
        edit::lock(&src, &mut out).is_err(),
        "the record was dropped and the call returned Ok"
    );
    assert!(out.is_empty(), "bytes were written before the refusal");

    // A caller that says what it wants is served either way.
    let mut named = Vec::new();
    let report = edit::set_recovery(&src, Some(5), &mut named).expect("a named percentage");
    assert!(report.recovery && has_record(&open(&named)));
    let mut dropped = Vec::new();
    edit::set_recovery(&src, None, &mut dropped).expect("dropping it");
    assert!(!has_record(&open(&dropped)));
}

/// M-22: an edit that does not touch the comment keeps it, whatever the
/// read's memory policy made of it. A 100,000 byte comment read under a
/// policy whose comment limit is 64 KiB is not decoded (`comment()` is
/// `None`), and the rewrite used to drop its block and return Ok.
#[test]
fn an_edit_that_does_not_touch_the_comment_keeps_one_the_read_did_not_decode() {
    let comment: Vec<u8> = (0..100_000u32).map(|i| b'a' + (i % 23) as u8).collect();
    let tight = ReadOptions::default().with_memory(MemoryPolicy::from_limit(16 << 20));
    assert!(
        tight.memory.max_comment < comment.len() as u64,
        "the policy this test names reads a comment of {} bytes",
        comment.len()
    );
    for format in FORMATS {
        let source = archive(
            format,
            &Shape {
                comment: Some(&comment),
                ..Shape::default()
            },
        );
        assert!(
            open(&source).comment() == Some(&comment[..]),
            "{format:?}: the fixture"
        );
        let src = open_with(&source, &tight);
        assert_eq!(src.comment(), None, "{format:?}: the tight read decoded it");

        let mut locked = Vec::new();
        edit::lock(&src, &mut locked).expect("lock");
        assert!(
            open(&locked).comment() == Some(&comment[..]),
            "{format:?}: lock lost the comment"
        );
        assert!(open(&locked).is_locked(), "{format:?}: not locked");

        let mut removed = Vec::new();
        edit::remove(&src, &[b"b.txt"], &mut removed).expect("remove");
        assert!(
            open(&removed).comment() == Some(&comment[..]),
            "{format:?}: remove lost the comment"
        );

        // An edit that DOES name the comment still replaces or removes it.
        let mut cleared = Vec::new();
        edit::set_comment(&src, None, &mut cleared).expect("clear");
        assert_eq!(open(&cleared).comment(), None, "{format:?}: not cleared");
        let mut replaced = Vec::new();
        edit::set_comment(&src, Some(b"new"), &mut replaced).expect("replace");
        assert_eq!(
            open(&replaced).comment(),
            Some(&b"new"[..]),
            "{format:?}: not replaced"
        );
    }
}

/// A RAR 5 service block named `name` carrying `data`, with block flag
/// 0x0020 ("depends on the block before it") when `depends`.
fn rar5_service(name: &[u8], data: &[u8], depends: bool) -> Vec<u8> {
    let mut body = Vec::new();
    put_vint(3, &mut body); // a service header
    put_vint(0x0002 | if depends { 0x0020 } else { 0 }, &mut body);
    put_vint(data.len() as u64, &mut body); // the data area
    put_vint(0, &mut body); // file flags
    put_vint(data.len() as u64, &mut body); // unpacked size
    put_vint(0, &mut body); // attributes
    put_vint(0, &mut body); // compression: stored
    put_vint(1, &mut body); // host
    put_vint(name.len() as u64, &mut body);
    body.extend_from_slice(name);
    let mut sized = Vec::new();
    put_vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(&body);
    let mut block = rarkit::checksum::crc32(&sized).to_le_bytes().to_vec();
    block.extend_from_slice(&sized);
    block.extend_from_slice(data);
    block
}

/// A RAR 4 family sub block (type 0x7A) named `name` carrying `data`.
fn rar4_sub(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut rest = vec![0x7A];
    rest.extend_from_slice(&0x8000u16.to_le_bytes());
    let head_size = (7 + 4 + 21 + name.len()) as u16;
    rest.extend_from_slice(&head_size.to_le_bytes());
    rest.extend_from_slice(&(data.len() as u32).to_le_bytes()); // data size
    rest.extend_from_slice(&(data.len() as u32).to_le_bytes()); // unpacked
    rest.push(3); // host
    rest.extend_from_slice(&rarkit::checksum::crc32(data).to_le_bytes());
    rest.extend_from_slice(&0u32.to_le_bytes()); // time
    rest.push(29); // version
    rest.push(0x30); // stored
    rest.extend_from_slice(&(name.len() as u16).to_le_bytes());
    rest.extend_from_slice(&0u32.to_le_bytes()); // attributes
    rest.extend_from_slice(name);
    let mut block = (rarkit::checksum::crc32(&rest) as u16)
        .to_le_bytes()
        .to_vec();
    block.extend_from_slice(&rest);
    block.extend_from_slice(data);
    block
}

/// The archive of [`members`] with `block` put straight after the file
/// block of member `after`.
fn with_block_after(format: WriteFormat, after: usize, block: &[u8]) -> Vec<u8> {
    let source = archive(format, &Shape::default());
    let at = open(&source)
        .blocks()
        .filter(|b| b.kind == BlockKind::File)
        .nth(after)
        .expect("the member")
        .range
        .end as usize;
    let mut out = source[..at].to_vec();
    out.extend_from_slice(block);
    out.extend_from_slice(&source[at..]);
    out
}

fn service_names(archive: &[u8]) -> Vec<Vec<u8>> {
    open(archive)
        .services()
        .map(|svc| svc.header.name.to_vec())
        .collect()
}

/// M-23: a block that depends on a removed member goes with it, and one
/// that depends on a member that stays, stays.
#[test]
fn a_removal_takes_the_blocks_that_depend_on_the_removed_member() {
    let stream = b"the stream of b.txt";
    for format in FORMATS {
        let block = match format {
            WriteFormat::Rar5 => rar5_service(b"STM", stream, true),
            WriteFormat::Rar4(_) => rar4_sub(b"STM", stream),
        };
        let source = with_block_after(format, 1, &block);
        assert_eq!(
            service_names(&source),
            vec![b"STM".to_vec()],
            "{format:?}: the fixture's block is not read as a service"
        );
        assert_eq!(read_back(&source), members(), "{format:?}: the fixture");
        let src = open(&source);

        let mut without_b = Vec::new();
        edit::remove(&src, &[b"b.txt"], &mut without_b).expect("remove b");
        assert!(
            service_names(&without_b).is_empty(),
            "{format:?}: b.txt's stream block stayed and now follows a.txt"
        );
        assert!(
            !without_b
                .windows(stream.len())
                .any(|window| window == stream),
            "{format:?}: part of the removed member is still in the archive"
        );
        let mut kept = members();
        kept.remove(1);
        assert_eq!(read_back(&without_b), kept, "{format:?}: without b");

        for other in [&b"a.txt"[..], &b"c.txt"[..]] {
            let mut out = Vec::new();
            edit::remove(&src, &[other], &mut out).expect("remove another");
            assert_eq!(
                service_names(&out),
                vec![b"STM".to_vec()],
                "{format:?}: b.txt stayed and its stream block did not"
            );
        }
    }
}

/// M-23, the other half: a RAR 5 service block that does NOT say it
/// depends on the block before it is the archive's own and stays.
#[test]
fn a_removal_keeps_a_rar5_block_that_depends_on_nothing() {
    let block = rar5_service(b"XYZ", b"the archive's own", false);
    let source = with_block_after(WriteFormat::Rar5, 1, &block);
    let mut out = Vec::new();
    edit::remove(&open(&source), &[b"b.txt"], &mut out).expect("remove");
    assert_eq!(service_names(&out), vec![b"XYZ".to_vec()]);
}

/// L-29: a rename stores a RAR 4 name the way the family and the Writer
/// store it, with a backslash between components (spec G 3.14.5).
#[test]
fn a_rar4_rename_stores_the_separator_the_family_stores() {
    let source = archive(WriteFormat::Rar4(Rar4Version::V40), &Shape::default());
    let mut out = Vec::new();
    edit::rename(&open(&source), b"a.txt", b"dir/new.txt", &mut out).expect("rename");
    let stored = |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
    assert!(
        stored(b"dir\\new.txt") && !stored(b"dir/new.txt"),
        "the header carries the name with the API's separator"
    );
    let names: Vec<Vec<u8>> = read_back(&out).into_iter().map(|m| m.0).collect();
    assert_eq!(
        names,
        vec![
            b"dir/new.txt".to_vec(),
            b"b.txt".to_vec(),
            b"c.txt".to_vec()
        ]
    );
    // The Writer's own archive of that name stores the same bytes.
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V40),
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"dir/new.txt",
            payload: Payload::Bytes(b"x"),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut written = Vec::new();
    writer.finish_into(&mut written).expect("finish");
    assert!(written.windows(11).any(|w| w == b"dir\\new.txt"));
}

/// A read whose comment limit is 4 MiB, stated: no constructor of the
/// policy goes above 2 MiB, and the comments below are 3 MiB.
fn roomy_comment() -> ReadOptions {
    ReadOptions::default().with_memory(MemoryPolicy {
        max_comment: 4 << 20,
        ..MemoryPolicy::default()
    })
}

/// L-30: a comment large enough to push the recovery record past the
/// locator's estimated width is a valid edit, not a refusal.
#[test]
fn a_large_comment_beside_a_recovery_record_is_a_valid_edit() {
    let comment = vec![b'x'; 3 << 20];
    let mut small = Vec::new();
    {
        // One member of 20 bytes: the estimate is (20 + 33 + 15) * 4096,
        // which is three bytes wide, and the record lands past 2^21.
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Stored,
            filters: rarkit::FilterPolicy::Off,
            host_os: HostOs::Unix,
            recovery_percent: Some(5),
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"a.txt",
                payload: Payload::Bytes(&[7u8; 20]),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        writer.finish_into(&mut small).expect("finish");
    }
    let mut commented = Vec::new();
    edit::set_comment(&open(&small), Some(&comment), &mut commented)
        .unwrap_or_else(|e| panic!("a 3 MiB comment beside a record: {e}"));
    let roomy = roomy_comment();
    let after = open_with(&commented, &roomy);
    assert_eq!(after.comment().map(<[u8]>::len), Some(comment.len()));
    assert!(has_record(&after), "the record is gone");
    assert_eq!(
        read_back(&commented),
        vec![(b"a.txt".to_vec(), vec![7u8; 20])]
    );
    let mut fixed = Vec::new();
    rarkit::recovery::repair_inline(&commented, &roomy, &mut fixed)
        .unwrap_or_else(|e| panic!("the record does not verify: {e}"));
}

/// L-30, the Writer's half: the same shape written in one go, over an
/// output that can be patched, is a valid archive. A debug build used to
/// stop on an assertion where the release build wrote offset 0 by design.
#[test]
fn a_writer_with_a_large_comment_and_a_recovery_record_writes_the_archive() {
    let comment = vec![b'x'; 3 << 20];
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: HostOs::Unix,
        recovery_percent: Some(5),
        comment: Some(comment.clone()),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"a.txt",
            payload: Payload::Bytes(&[7u8; 20]),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = std::io::Cursor::new(Vec::new());
    writer.finish_seek(&mut out).expect("finish");
    let written = out.into_inner();
    let roomy = roomy_comment();
    let after = open_with(&written, &roomy);
    assert_eq!(after.comment().map(<[u8]>::len), Some(comment.len()));
    assert!(has_record(&after), "the record is gone");
    assert_eq!(
        read_back(&written),
        vec![(b"a.txt".to_vec(), vec![7u8; 20])]
    );
    let mut fixed = Vec::new();
    rarkit::recovery::repair_inline(&written, &roomy, &mut fixed)
        .unwrap_or_else(|e| panic!("the record does not verify: {e}"));
}

/// L-31: an archive whose walk stopped at damage is not rewritten as a
/// complete one.
#[test]
fn a_rewrite_of_an_archive_that_stopped_at_damage_is_refused() {
    for format in FORMATS {
        let source = archive(format, &Shape::default());
        let whole = open(&source);
        let third = whole
            .blocks()
            .filter(|b| b.kind == BlockKind::File)
            .nth(2)
            .expect("the third member")
            .range;
        // One byte of the third member's header: the walk reads two
        // members whole and stops at a header whose checksum fails.
        let mut damaged = source.clone();
        damaged[third.start as usize + 9] ^= 0x55;
        let cut = &damaged[..];
        let tolerant = ReadOptions::default().with_tolerant_tail(true);
        let src = open_with(cut, &tolerant);
        assert!(src.tail().is_some(), "{format:?}: the walk did not stop");
        let mut out = Vec::new();
        let outcome = edit::lock(&src, &mut out);
        assert!(
            outcome.is_err(),
            "{format:?}: a damaged archive of {} members was rewritten as complete",
            src.members().count()
        );
        assert!(out.is_empty(), "{format:?}: bytes were written first");
    }
}
