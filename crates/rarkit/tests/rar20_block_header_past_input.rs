//! Spec H3 3.5, "A block header that the end of the packed data cuts"
//! (SWEEP2-08OCT-54, the half its own archive is): a RAR 2.0 block header
//! met inside a member's packed data and cut by its end is read with zeros
//! for the missing bits. It is TAKEN when that read ends fewer than 8 bits
//! past the end of the packed data, and is not taken otherwise: no fault,
//! not `Truncated`, nothing of it in force. A member whose declared size
//! is not yet produced then ends at the terminator, short, with the
//! checksum's verdict, and the next member of a solid chain starts in the
//! old block under the old tables.
//!
//! Until 9 Oct 2026 the header's reads were refused past the end of the
//! packed data: such a member ended `Truncated` and failed, where the
//! genuine unrar judges the bytes it has by the checksum alone.
//!
//! The archives are the section's own, the 1,695 of
//! `specs/vectors-H/h3-block-header-past-input` with the answers of unrar
//! 7.23 beside them (`outcomes-unrar-7.23-macos-arm64.tsv`): a stream of
//! literals, the terminator and a second header with other tables, cut at
//! every bit (`ladder`, `edge`), and 24 cuts whose zeros give positions of
//! the length alphabet the length 1 (`over`). Each cut is put four ways,
//! named in the archive:
//!
//! - `made.stored`, `made.solid`: the declared size is produced before the
//!   terminator, so the header stands in the member's tail (SPEC-D 2.2),
//!   with a stored or a solid member behind;
//! - `more.true`, `more.model`: 20 bytes more are declared, with the CRC32
//!   of the uncut stream's bytes and a stored member behind, or the CRC32
//!   of the bytes written and a solid member behind.
//!
//! Whether the reference TOOK a header is read from the answers file: the
//! solid member behind is right under the new tables (`T2`) or the old
//! (`T1`).
//!
//! ONE DIFFERENCE IS RARKIT'S OWN (rarkit's rule 6): a cut header whose
//! read ends fewer than 8 bits past the end and whose zeros OVERSUBSCRIBE
//! a list is taken by the reference and NOT taken by rarkit, which builds
//! no oversubscribed table. It is no fault: the member ends at its
//! terminator. Ten cuts of the `over` group are that shape.
//!
//! One thread throughout (the sequential driver at its default width);
//! every archive is under 1 KiB and held in memory once.

use std::collections::HashSet;
use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-H/h3-block-header-past-input"
);

/// (name, bytes delivered, checksum verdict) of every member closed.
type Members = Vec<(String, usize, Option<bool>)>;

#[derive(Default)]
struct Keep(Members);

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
            out.map_or(0, |bytes| bytes.len()),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// One row of the answers file.
struct Arm {
    archive: String,
    /// The cut, without the way it is put: `ladder.z.k012`.
    cut: String,
    /// The way it is put: `made.stored`, `made.solid`, `more.true`,
    /// `more.model`.
    put: String,
    /// The reference's exit from `t`: 0, or 3 for a checksum error.
    exit: u32,
    /// The size of `ONE.BIN` as the reference wrote it.
    wrote: usize,
    declared: usize,
}

/// The rows of the answers file but the seven `stale.*`, where the
/// reference supplies an earlier member's left over bytes and rarkit
/// zeros (a chosen difference), and the cuts whose header the reference
/// took.
fn arms() -> (Vec<Arm>, HashSet<String>) {
    let path = format!("{DIR}/outcomes-unrar-7.23-macos-arm64.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut arms = Vec::new();
    let mut taken = HashSet::new();
    for line in text.lines().skip(1) {
        let field: Vec<&str> = line.split('\t').collect();
        let name = field[0].strip_suffix(".rar").expect("an archive");
        if name.starts_with("stale.") {
            continue;
        }
        let at = name
            .find(".made.")
            .or_else(|| name.find(".more."))
            .expect("the way the cut is put");
        if field[7].contains("(T2)") {
            taken.insert(name[..at].to_owned());
        }
        arms.push(Arm {
            archive: field[0].to_owned(),
            cut: name[..at].to_owned(),
            put: name[at + 1..].to_owned(),
            exit: field[1].parse().expect("an exit code"),
            wrote: field[4].parse().expect("a size"),
            declared: field[5].parse().expect("a size"),
        });
    }
    assert_eq!(arms.len(), 1688, "the ladder, edge and over arms");
    (arms, taken)
}

/// Whether the cut is one of the ten rarkit's rule 6 is stricter on: an
/// `over` cut that gives three or more positions of the length alphabet
/// the length 1, which oversubscribes it, in a header the reference took.
fn oversubscribed_and_taken(arm: &Arm, taken: &HashSet<String>) -> bool {
    let positions = arm
        .cut
        .strip_prefix("over.")
        .and_then(|cut| cut.split_once(".j"))
        .map(|(_, positions)| positions.parse::<u32>().expect("a count"));
    positions.is_some_and(|positions| positions >= 3) && taken.contains(&arm.cut)
}

fn read(arm: &Arm) -> (rarkit::Result<()>, Members) {
    let path = format!("{DIR}/{}", arm.archive);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Keep::default();
    let ended = extract(vec![source], &ReadOptions::default(), &mut sink, &mut ()).map(|_| ());
    (ended, sink.0)
}

fn member<'m>(members: &'m Members, name: &str, arm: &Arm) -> &'m (String, usize, Option<bool>) {
    members
        .iter()
        .find(|member| member.0 == name)
        .unwrap_or_else(|| panic!("{}: no {name}", arm.archive))
}

/// Rule 4: a member whose declared size is not yet produced, met by a cut
/// header that is NOT taken, ends at the terminator: short, with the bytes
/// the reference wrote and the reference's verdict, the checksum's alone;
/// no error is raised; and the member behind it is good, a solid one in
/// the old block under the old tables.
#[test]
fn a_cut_header_that_is_not_taken_ends_the_member_at_the_terminator() {
    let (arms, taken) = arms();
    let mut held = 0;
    for arm in arms
        .iter()
        .filter(|arm| arm.put.starts_with("more.") && !taken.contains(&arm.cut))
    {
        let (ended, members) = read(arm);
        let one = member(&members, "ONE.BIN", arm);
        assert!(arm.wrote < arm.declared, "{}", arm.archive);
        assert_eq!(one.1, arm.wrote, "{}: {ended:?}", arm.archive);
        assert_eq!(one.2, Some(arm.exit == 0), "{}: {ended:?}", arm.archive);
        let two = member(&members, "TWO.BIN", arm);
        assert_eq!(two.2, Some(true), "{}: {ended:?}", arm.archive);
        assert!(ended.is_ok(), "{}: {ended:?}", arm.archive);
        held += 1;
    }
    assert_eq!(held, NOT_TAKEN);
}

/// The `more` arms whose header the reference did not take, counted from
/// the answers file on 9 Oct 2026.
const NOT_TAKEN: usize = 710;

/// Rule 5: a cut header that IS taken puts the new tables in force. The
/// member is short either way and judged by its checksum; rarkit reads no
/// symbol that would begin at or past the end (section 3.5, "The packed
/// data runs out first"), where the
/// reference goes on for those begun fewer than 8 bits past it, so
/// rarkit's bytes are the reference's or fewer, and where they are the
/// same number the verdict is the reference's.
#[test]
fn a_cut_header_that_is_taken_is_in_force_and_the_member_is_judged_by_its_checksum() {
    let (arms, taken) = arms();
    let mut held = 0;
    for arm in arms
        .iter()
        .filter(|arm| arm.put.starts_with("more.") && taken.contains(&arm.cut))
        .filter(|arm| !oversubscribed_and_taken(arm, &taken))
    {
        let (ended, members) = read(arm);
        let one = member(&members, "ONE.BIN", arm);
        assert!(one.1 <= arm.wrote, "{}: {ended:?}", arm.archive);
        assert!(one.2.is_some(), "{}: {ended:?}", arm.archive);
        if one.1 == arm.wrote {
            assert_eq!(one.2, Some(arm.exit == 0), "{}: {ended:?}", arm.archive);
        }
        if let Err(err) = &ended {
            assert!(
                matches!(
                    err.kind(),
                    rarkit::ErrorKind::Corrupt(rarkit::Corruption::Checksum)
                ),
                "{}: {err:?}",
                arm.archive
            );
        }
        held += 1;
    }
    assert_eq!(held, TAKEN);
}

/// The `more` arms whose header the reference took.
const TAKEN: usize = 114;

/// rarkit's rule 6, where it is stricter than the reference: a cut header
/// whose read ends fewer than 8 bits past the end and whose zeros
/// oversubscribe a list is NOT taken, and that is no fault of the member.
/// The member ends at its terminator, 20 bytes short of what it declares,
/// with a verdict and nothing raised; the reference takes the header and
/// writes more. Until this rule the header's fault was the member's.
#[test]
fn a_cut_header_the_zeros_oversubscribe_is_not_taken_and_is_no_fault() {
    let (arms, taken) = arms();
    let mut held = 0;
    for arm in arms
        .iter()
        .filter(|arm| arm.put.starts_with("more.") && oversubscribed_and_taken(arm, &taken))
    {
        let (ended, members) = read(arm);
        let one = member(&members, "ONE.BIN", arm);
        assert!(ended.is_ok(), "{}: {ended:?}", arm.archive);
        assert_eq!(
            one.1,
            arm.declared - 20,
            "{}: at the terminator",
            arm.archive
        );
        assert!(
            one.1 < arm.wrote,
            "{}: the reference wrote more",
            arm.archive
        );
        assert!(one.2.is_some(), "{}", arm.archive);
        held += 1;
    }
    // Ten cuts, each with a stored and with a solid member behind.
    assert_eq!(held, 20);
}

/// Rule 3: a member whose declared size is already produced when the cut
/// header is met is COMPLETE, wherever the cut falls: its declared bytes,
/// good, as the reference has it in every such arm. (What the member
/// behind it starts under is SPEC-D 2.2's and is not held here.)
#[test]
fn a_member_already_whole_when_the_cut_header_is_met_is_complete() {
    let (arms, _) = arms();
    let mut held = 0;
    for arm in arms.iter().filter(|arm| arm.put.starts_with("made.")) {
        let (ended, members) = read(arm);
        let one = member(&members, "ONE.BIN", arm);
        assert_eq!(arm.exit, 0, "{}", arm.archive);
        assert_eq!(
            (one.1, one.2),
            (arm.declared, Some(true)),
            "{}: {ended:?}",
            arm.archive
        );
        held += 1;
    }
    assert_eq!(held, 844);
}

/// SWEEP2-08OCT-54's own archive, `54-short-member-crc-of-short.rar` (298
/// bytes, SHA-256 `2fa1d3ee...`): one RAR 2.0 member declaring 41 bytes
/// whose header CRC32 is that of the 34 bytes its stream gives.
const ITEM_54: &[&str] = &[
    "526172211a0700cf907300000d000000000000004edb7480802500f100000029",
    "0000000021a7cd3654632d511433050020000000442e42494e11111111111111",
    "1100026666666666666666666666666666666666666666666666666666666666",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "666665dddddddddddddddddddddddddddddddd55555599999999999999999999",
    "999999999999999955555555555555540000040000000000000000000002c362",
    "b1d92cb66b3da2d36ab5db2db6eb7dc2e372b9dd2eb76bbde2f37a6132860004",
    "85680000000000000000",
];

/// The item itself. Its stream gives 34 bytes, then a block terminator
/// with 67 bits of packed data left, then a new block header whose tables
/// need more bits than are left: a cut header that is not taken. The
/// member ends at the terminator, short of the 41 bytes it declares, and
/// is GOOD by its checksum, which is of those 34 bytes; nothing is raised.
/// The genuine unrar 7.23 tests it `All OK`. Until 9 Oct 2026 the header's
/// read was refused and the member ended `Truncated`.
#[test]
fn the_items_own_archive_ends_at_its_terminator_and_is_good_by_its_checksum() {
    let bytes: Vec<u8> = ITEM_54
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex"))
        .collect();
    assert_eq!(bytes.len(), 298);
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Keep::default();
    let report = extract(vec![source], &ReadOptions::default(), &mut sink, &mut ())
        .expect("nothing is raised");
    assert_eq!(report.checksum_failures, 0);
    assert_eq!(sink.0, [("D.BIN".to_owned(), 34, Some(true))]);
}
