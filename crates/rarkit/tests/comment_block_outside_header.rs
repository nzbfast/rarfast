//! Spec F 3.3.3 B2: a block of type 0x75 standing BETWEEN blocks of the
//! older container.
//!
//! No genuine writer was seen to put one there: every old comment block in
//! the census is embedded in a main or a file header. One of 13 bytes or
//! more whose checksum fits its offsets 2 to 12 is passed over (rule 1).
//! Any other is a header whose checksum failed and no more (rule 2, as
//! restated on 9 Oct 2026; 4.6): this file holds what that is for a reader
//! that was NOT asked to read through damage, which stops at the block
//! with `HeaderChecksum` and keeps the member parsed before it, and for
//! one that was, which reports the block and reads on.
//! `tests/lone_comment_block_vectors.rs` holds the section's own vectors.
//!
//! The three arms under `specs/vectors-F/evidence-06oct/old-container` put
//! a block between `a.txt` and `b.txt` (with flag 0x4000, without it, and
//! with flag 0x8000 and five data bytes); the reference exits 3 for each.
//! Until 9 Oct 2026 every such block was refused under a name of its own,
//! `Corrupt(CommentOutsideHeader)`, which no rule raises now.
//!
//! One thread throughout (the sequential driver at its default width, over
//! archives of three stored members); every archive is under 64 KiB and is
//! held in memory once, so no test needs more than a few MiB.

use std::sync::Arc;

use rarkit::{
    extract, Archive, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink,
};

const ARMS: [&str; 3] = ["type-75-skip", "type-75-noskip", "type-75-data"];

/// What a reader that does not read through damage ends with at a block
/// whose checksum does not fit, as the error prints it.
const CAUSE: &str = "HeaderChecksum";

fn arm(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/evidence-06oct/old-container/{name}/x.rar",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn legacy(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../fixtures/legacy/archives/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Where the first top level block of type 0x75 starts, found by the
/// header sizes alone: seven bytes of signature, then each block's size at
/// its byte 5 and, for a file block or one with flag 0x8000, a data length
/// at its byte 7.
fn comment_block_at(archive: &[u8]) -> u64 {
    let mut at = 7;
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        if kind == 0x75 {
            return at as u64;
        }
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        let data = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        at += size + data;
    }
    panic!("the arm has no top level block of type 0x75");
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

fn source(bytes: &[u8]) -> Arc<dyn RangeSource> {
    Arc::new(bytes.to_vec())
}

/// Extraction gives the member before the block, whole and checked, and
/// then ends on the block by name, at the block.
#[test]
fn extraction_stops_at_a_standalone_comment_block_and_keeps_the_member_before_it() {
    for name in ARMS {
        let bytes = arm(name);
        let mut sink = Keep::default();
        let ended = extract(
            vec![source(&bytes)],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        );
        let err = ended.expect_err(name);
        assert_eq!(format!("{:?}", err.kind()), CAUSE, "{name}");
        assert_eq!(err.offset(), Some(comment_block_at(&bytes)), "{name}");
        assert_eq!(
            sink.0,
            [("a.txt".to_owned(), b"alpha\n".to_vec(), Some(true))],
            "{name}: the member before the block, and none after it"
        );
    }
}

/// A listing is refused for the same reason, and with `tolerant_tail` it
/// keeps the member before the block and says why it stopped.
#[test]
fn a_listing_stops_at_a_standalone_comment_block() {
    for name in ARMS {
        let bytes = arm(name);
        let at = comment_block_at(&bytes);

        let err = Archive::open(source(&bytes), &ReadOptions::default())
            .err()
            .unwrap_or_else(|| panic!("{name}: the archive opened"));
        assert_eq!(format!("{:?}", err.kind()), CAUSE, "{name}");
        assert_eq!(err.offset(), Some(at), "{name}");

        let tolerant = ReadOptions::default().with_tolerant_tail(true);
        let archive = Archive::open(source(&bytes), &tolerant).expect(name);
        let names: Vec<String> = archive
            .members()
            .map(|m| m.name_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.txt"], "{name}");
        let tail = archive.tail().expect("the reason the walk stopped");
        assert_eq!(format!("{:?}", tail.kind()), CAUSE, "{name}");
        assert_eq!(tail.offset(), Some(at), "{name}");
    }
}

/// The comment blocks genuine writers DO make are embedded in a header and
/// are no block of their own: the two genuine archives with an archive
/// comment (DOS RAR 1.55 and 2.50) still open and extract whole.
#[test]
fn an_embedded_comment_block_is_still_read() {
    for name in ["d155_cmt.rar", "d250_cmt.rar"] {
        let bytes = legacy(name);
        let archive = Archive::open(source(&bytes), &ReadOptions::default()).expect(name);
        assert!(archive.tail().is_none(), "{name}");
        let listed = archive.members().filter(|m| !m.is_directory).count();
        let mut sink = Keep::default();
        extract(
            vec![source(&bytes)],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        )
        .expect(name);
        assert!(listed > 0 && sink.0.len() >= listed, "{name}");
        for (member, _, check) in &sink.0 {
            assert_ne!(*check, Some(false), "{name}: {member}");
        }
    }
}

/// The refusal put to hostile input: every prefix of an arm and every
/// single byte of it changed ends in a value, never a panic, and nothing
/// is allocated for the refused block, whose data area is never read.
#[test]
fn a_refused_comment_block_cut_or_damaged_anywhere_never_panics() {
    for name in ARMS {
        let whole = arm(name);
        assert!(whole.len() < 1024, "{name}");
        for cut in 0..whole.len() {
            let mut sink = Keep::default();
            let _ = extract(
                vec![source(&whole[..cut])],
                &ReadOptions::default(),
                &mut sink,
                &mut (),
            );
        }
        for at in 0..whole.len() {
            let mut damaged = whole.clone();
            damaged[at] ^= 0xA5;
            let mut sink = Keep::default();
            let _ = extract(
                vec![source(&damaged)],
                &ReadOptions::default(),
                &mut sink,
                &mut (),
            );
        }
    }
}

// ------------------------------------------------ archives built here

/// A block of the older container: its CRC16 is the low half of the
/// CRC32 of everything after the checksum field.
fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, kind];
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
    out.extend_from_slice(body);
    let sum = (crc32fast::hash(&out[2..]) & 0xffff) as u16;
    out[..2].copy_from_slice(&sum.to_le_bytes());
    out
}

/// A stored member of unpack version 20, header and data.
fn stored(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.push(0); // host
    body.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    body.extend_from_slice(&0x5a21_0000u32.to_le_bytes()); // a DOS time
    body.push(20);
    body.push(0x30);
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(&0x20u32.to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    let mut out = block(0x74, 0x8000, &body);
    out.extend_from_slice(data);
    out
}

/// A block of type 0x75 whose header is `7 + body.len()` bytes. `fits`
/// says what its checksum covers: the eleven bytes after the checksum
/// field (SPEC-F 3.3.3 B2), or the whole header after that field.
fn lone_comment(flags: u16, body: &[u8], fits: bool) -> Vec<u8> {
    let mut out = block(0x75, flags, body);
    if fits {
        let sum = (crc32fast::hash(&out[2..13]) & 0xffff) as u16;
        out[..2].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

const MEMBERS: [(&str, &[u8]); 3] = [
    ("a.txt", b"alpha\n"),
    ("b.txt", b"bravo bravo\n"),
    ("c.txt", b"charlie\n"),
];

/// Signature, main header, the three members with `between[i]` placed
/// before member `i` (and `between[3]` before the end block), end block.
fn archive_with(between: [&[u8]; 4]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend_from_slice(&block(0x73, 0, &[0; 6]));
    for (at, (name, data)) in MEMBERS.iter().enumerate() {
        out.extend_from_slice(between[at]);
        out.extend_from_slice(&stored(name, data));
    }
    out.extend_from_slice(between[3]);
    out.extend_from_slice(&block(0x7b, 0x4000, &[]));
    out
}

fn whole() -> Vec<(String, Vec<u8>, Option<bool>)> {
    MEMBERS
        .iter()
        .map(|(name, data)| (name.to_string(), data.to_vec(), Some(true)))
        .collect()
}

/// SPEC-F 3.3.3 B2, rule 1: a block of type 0x75 between blocks whose
/// header is 13 bytes or more and whose checksum fits its offsets 2 to 12
/// is passed over by its HEADER SIZE, and nothing is raised. The
/// reference lists, tests and extracts all three members of each of these
/// and exits 0 (`vectors-F/type-75-between`, the `13-bytes-*`,
/// `whole-comment-crc-of-fields` and `long-comment-crc-of-fields` arms).
#[test]
fn a_lone_comment_block_whose_checksum_fits_is_passed_over() {
    let fields: &[u8] = &[0, 0, 15, 0x30, 0, 0];
    let other: &[u8] = &[0xff, 0xff, 0x63, 0x99, 0xff, 0xff];
    let mut long = vec![44, 1, 15, 0x30, 0, 0];
    long.extend(std::iter::repeat_n(b'x', 300));
    let thirteen = lone_comment(0, fields, true);
    let odd = lone_comment(0, other, true);
    let long = lone_comment(0, &long, true);
    // Flag 0x8000 and a data length are not honoured for this type: the
    // header says five data bytes follow and none does.
    let mut sized = vec![5, 0, 0, 0];
    sized.extend_from_slice(fields);
    let sized = lone_comment(0x8000, &sized, true);
    for (label, between) in [
        ("between a and b", [&[][..], &thirteen, &[], &[]]),
        ("before a", [&thirteen[..], &[], &[], &[]]),
        ("twice", [&[][..], &thirteen, &thirteen, &[]]),
        ("after c", [&[][..], &[], &[], &thirteen]),
        ("other field bytes", [&[][..], &odd, &[], &[]]),
        ("a long text inside the header", [&[][..], &long, &[], &[]]),
        ("a data length and no data", [&[][..], &sized, &[], &[]]),
    ] {
        let bytes = archive_with(between);
        let mut sink = Keep::default();
        extract(
            vec![source(&bytes)],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(sink.0, whole(), "{label}");
        let archive = Archive::open(source(&bytes), &ReadOptions::default()).expect(label);
        assert!(archive.tail().is_none(), "{label}");
        let names: Vec<String> = archive
            .members()
            .map(|m| m.name_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.txt", "b.txt", "c.txt"], "{label}");
    }
}

/// The same block followed by the five data bytes its header declares:
/// the next block is read from the first of them, never past them, so the
/// walk loses its place there as the reference's does, and the member
/// before the block is still whole
/// (`fields-crc-data-flag-size-5-data.between-a-b`).
#[test]
fn a_passed_over_comment_blocks_data_length_is_never_stepped_over() {
    let mut sized = vec![5, 0, 0, 0];
    sized.extend_from_slice(&[0, 0, 15, 0x30, 0, 0]);
    let mut block = lone_comment(0x8000, &sized, true);
    block.extend_from_slice(b"hello");
    let bytes = archive_with([&[], &block, &[], &[]]);
    let mut sink = Keep::default();
    let ended = extract(
        vec![source(&bytes)],
        &ReadOptions::default(),
        &mut sink,
        &mut (),
    );
    assert!(ended.is_err(), "the five bytes are no block");
    assert_eq!(sink.0, whole()[..1], "the member before the block only");
}

/// SPEC-F 3.3.3 B2, rule 2: any other block of type 0x75 between blocks
/// is a header whose checksum failed: a header under 13 bytes, a checksum
/// taken over the whole header where that is not the eleven bytes, and a
/// checksum that is simply wrong. A reader that does not read through
/// damage stops there, at the block; one that does reports the block,
/// passes over it by its header size and reads the members after it.
#[test]
fn a_lone_comment_block_whose_checksum_does_not_fit_is_a_failed_header_checksum() {
    let fields: &[u8] = &[0, 0, 15, 0x30, 0, 0];
    let mut text = vec![5, 0, 15, 0x30, 0, 0];
    text.extend_from_slice(b"hello");
    let mut wrong = lone_comment(0, fields, true);
    wrong[0] ^= 1;
    for (label, block) in [
        ("7 bytes", lone_comment(0, &[], false)),
        ("9 bytes", lone_comment(0x4000, &[0, 0], false)),
        ("11 bytes", lone_comment(0, &[0; 4], false)),
        (
            "a checksum over the text too",
            lone_comment(0, &text, false),
        ),
        ("a wrong checksum", wrong),
    ] {
        let bytes = archive_with([&[], &block, &[], &[]]);
        let mut sink = Keep::default();
        let err = extract(
            vec![source(&bytes)],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        )
        .expect_err(label);
        assert_eq!(format!("{:?}", err.kind()), CAUSE, "{label}");
        assert_eq!(err.offset(), Some(comment_block_at(&bytes)), "{label}");
        assert_eq!(sink.0, whole()[..1], "{label}");

        let lenient = ReadOptions::default().with_read_damaged(true);
        let mut sink = Keep::default();
        let report = extract(vec![source(&bytes)], &lenient, &mut sink, &mut ())
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(sink.0, whole(), "{label}: every member is read");
        assert_eq!(report.damaged_headers, 1, "{label}: the block is reported");
        let archive = Archive::open(source(&bytes), &lenient).expect(label);
        let damaged = archive.damaged_headers();
        assert_eq!(damaged.len(), 1, "{label}");
    }
}
