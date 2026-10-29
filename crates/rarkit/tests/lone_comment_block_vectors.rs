//! Spec F 3.3.3 B2 over its own vectors: every archive of
//! `specs/vectors-F/type-75-between`, three stored members with a block of
//! type 0x75 placed before, between or after them, read through damage
//! ([`ReadOptions::read_damaged`]) and compared with what the reference
//! did with it (`outcomes-unrar-7.23-macos-arm64.tsv`, kept beside them).
//!
//! Rule 1: a block of 13 bytes or more whose checksum fits is passed over
//! and nothing is raised. Rule 2, as restated on 9 Oct 2026: any other is
//! a header whose checksum failed and no more than that (4.6). It is
//! reported, the walk goes on at the block's offset plus its header size,
//! and the members after it are read, each under its own header and its
//! own checksum, as the reference reads them. Until then the walk stopped
//! at the block and the members after it were lost. So for every archive
//! here rarkit delivers exactly the members the reference wrote right, and
//! the run is a success exactly where the reference exits 0.
//!
//! A reader that was not asked to read through damage stops at a header
//! whose checksum fails, this one like any other: `HeaderChecksum` at the
//! block, with the members before it kept.
//!
//! One thread throughout (the sequential driver at its default width);
//! every archive is under 1 KiB and held in memory.

use std::sync::Arc;

use rarkit::{
    extract, Archive, Disposition, ErrorKind, MemberInfo, MemberOutcome, RangeSource, ReadOptions,
    Sink,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-F/type-75-between"
);

/// The names of the members closed whole and right, in order.
#[derive(Default)]
struct Right(Vec<String>);

impl Sink for Right {
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
        let want: &[u8] = match member.name_lossy().as_ref() {
            "a.txt" => b"alpha\n",
            "b.txt" => b"bravo bravo\n",
            "c.txt" => b"charlie\n",
            other => panic!("a member the vectors do not hold: {other}"),
        };
        if outcome.checksum_ok == Some(true) && out.as_deref() == Some(want) {
            self.0.push(member.name_lossy().into_owned());
        }
        Ok(())
    }
}

/// One row of the answers file: the archive, the reference's exit code
/// from `x`, and the names it wrote right.
struct Arm {
    archive: String,
    exit: u32,
    wrote: Vec<String>,
}

fn arms() -> Vec<Arm> {
    let path = format!("{DIR}/outcomes-unrar-7.23-macos-arm64.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let arms: Vec<Arm> = text
        .lines()
        .skip(1)
        .map(|line| {
            let field: Vec<&str> = line.split('\t').collect();
            Arm {
                archive: field[1].to_owned(),
                exit: field[3].parse().expect("an exit code"),
                wrote: field[5].split_whitespace().map(str::to_owned).collect(),
            }
        })
        .collect();
    assert_eq!(arms.len(), 35, "the rows of the answers file");
    arms
}

fn source(arm: &Arm) -> Arc<dyn RangeSource> {
    let path = format!("{DIR}/{}", arm.archive);
    Arc::new(std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
}

/// Read through damage, every archive gives the members the reference
/// wrote right, and is a success exactly where the reference exits 0.
#[test]
fn every_arm_delivers_what_the_reference_wrote() {
    let lenient = ReadOptions::default().with_read_damaged(true);
    let mut lost_members_after_a_block = 0;
    for arm in arms() {
        let mut sink = Right::default();
        let ended = extract(vec![source(&arm)], &lenient, &mut sink, &mut ());
        assert_eq!(sink.0, arm.wrote, "{}", arm.archive);
        let clean = ended
            .as_ref()
            .is_ok_and(|report| report.damaged_headers == 0 && report.checksum_failures == 0);
        assert_eq!(clean, arm.exit == 0, "{}: {ended:?}", arm.archive);
        if arm.wrote.len() < 3 {
            lost_members_after_a_block += 1;
        }
    }
    // The archives whose size field or data bytes lead to no header: the
    // reference loses the members after the block there, and so does
    // rarkit, by 4.6 and 4.1 and by no rule of this block's own.
    assert_eq!(lost_members_after_a_block, 9);
}

/// A block whose checksum does not fit and whose size can be followed is
/// REPORTED and passed over: the open lists every member and counts one
/// header read through a failed checksum for each such block.
#[test]
fn a_block_whose_checksum_does_not_fit_is_reported_and_passed_over() {
    let lenient = ReadOptions::default()
        .with_read_damaged(true)
        .with_tolerant_tail(true);
    for (archive, blocks) in [
        ("7-bytes.between-a-b.rar", 1),
        ("9-bytes-flags-0000.between-a-b.rar", 1),
        ("9-bytes-flags-4000.between-a-b.rar", 1),
        ("9-bytes.before-a.rar", 1),
        ("9-bytes.between-b-c.rar", 1),
        ("9-bytes.after-c.rar", 1),
        ("9-bytes.twice.rar", 2),
        ("whole-comment.between-a-b.rar", 1),
        ("13-bytes-fields.bad-header-crc.rar", 1),
        ("40-bytes-bad-crc.between-a-b.rar", 1),
        ("data-flag-size-5-no-data.between-a-b.rar", 1),
    ] {
        let path = format!("{DIR}/{archive}");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let opened = Archive::open(Arc::new(bytes), &lenient).expect(archive);
        let names: Vec<String> = opened
            .members()
            .map(|m| m.name_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.txt", "b.txt", "c.txt"], "{archive}");
        assert!(opened.tail().is_none(), "{archive}");
        assert_eq!(opened.damaged_headers().len(), blocks, "{archive}");
    }
}

/// Without `read_damaged` a header whose checksum fails ends the walk of
/// its volume, and such a block is one: `HeaderChecksum`, not a name of
/// the block's own, and the archives whose block fits are read whole.
#[test]
fn a_reader_not_asked_to_read_damage_stops_at_the_block_as_at_any_failed_header() {
    for arm in arms() {
        let mut sink = Right::default();
        let ended = extract(
            vec![source(&arm)],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        );
        if arm.exit == 0 {
            assert!(ended.is_ok(), "{}: {ended:?}", arm.archive);
            assert_eq!(sink.0, arm.wrote, "{}", arm.archive);
            continue;
        }
        let err = ended.expect_err(&arm.archive);
        assert!(
            matches!(
                err.kind(),
                ErrorKind::HeaderChecksum | ErrorKind::Corrupt(_) | ErrorKind::Truncated
            ),
            "{}: {err:?}",
            arm.archive
        );
        assert!(
            !format!("{:?}", err.kind()).contains("CommentOutsideHeader"),
            "{}",
            arm.archive
        );
    }
}
