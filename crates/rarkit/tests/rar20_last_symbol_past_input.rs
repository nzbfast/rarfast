//! Spec H3 3.5, "A symbol that begins inside the packed data and needs
//! bits past its end" (half of SWEEP2-08OCT-54; that item's own archive is
//! the other half, a block HEADER cut by the end of the packed data, held
//! in `tests/rar20_block_header_past_input.rs`): a RAR 2.0 symbol begun inside a
//! member's packed data is read WHOLE, every field of it, the bits past
//! the end read as zeros; reading them is no fault and is not `Truncated`.
//! A symbol that would begin at or past the end is not read, and the
//! verdict is the checksum's over the bytes delivered.
//!
//! Until 9 Oct 2026 the extra bits of a length, of a distance and of a
//! short match were refused past the end of the packed data, so a member
//! whose last symbol was cut there ended `Truncated` and failed, where
//! the genuine unrar judges the bytes by the checksum alone.
//!
//! The archives are the section's own, the 790 of
//! `specs/vectors-H/h3-last-symbol-past-input` with the answers of unrar
//! 7.23 beside them (`outcomes-unrar-7.23-macos-arm64.tsv`): a member cut
//! so that the last k bits of its stream are not in its packed data, for
//! eight last symbols. rarkit follows the reference in what a cut symbol
//! reads and is STRICTER in where the decode stops: the reference also
//! decodes symbols begun up to 7 bits past the end (its stop value is 8),
//! rarkit none (rule 3). The answers file says, for each archive, which
//! stop values give the bytes the reference wrote with zeros supplied, so
//! the rows whose range begins at 0 are the ones where the two must write
//! the SAME bytes: there rarkit's member is the reference's length and has
//! the reference's verdict. On every other row the two differ by rule 3
//! or by rule 5 (zeros where the reference reads left over bytes), and
//! what is held is that the decode ends in a verdict and never in an
//! error.
//!
//! One thread throughout (the sequential driver at its default width);
//! every archive but 14 is under 1 KiB and none is over 40 KiB, each held
//! in memory once.

use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-H/h3-last-symbol-past-input"
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
    /// The reference's exit from `t`: 0, or 3 for a checksum error.
    exit: u32,
    /// The size of `ONE.BIN` as the reference wrote it.
    wrote: usize,
    /// Whether the bytes the reference wrote are the ones zeros give with
    /// NO symbol begun at or past the end: the stop range begins at 0.
    same_bytes: bool,
    /// What stands behind the cut member: `-` for nothing.
    behind: String,
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
                archive: field[0].to_owned(),
                exit: field[1].parse().expect("an exit code"),
                wrote: field[4].parse().expect("a size"),
                same_bytes: field[7].starts_with("model") && field[8].starts_with("0 to "),
                behind: field[10].to_owned(),
            }
        })
        .collect();
    assert_eq!(arms.len(), 790, "the archives of the probe");
    arms
}

fn read(arm: &Arm) -> (rarkit::Result<()>, Members) {
    let path = format!("{DIR}/{}", arm.archive);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Keep::default();
    let ended = extract(vec![source], &ReadOptions::default(), &mut sink, &mut ()).map(|_| ());
    (ended, sink.0)
}

/// Where zeros and no further symbol give the reference's bytes, rarkit
/// delivers a member of the reference's length with the reference's
/// verdict: good when the header's CRC32 is of those bytes, a checksum
/// failure when it is not, and no error of the decode's own either way.
#[test]
fn a_cut_last_symbol_is_read_whole_with_zeros_and_judged_by_the_checksum() {
    let mut held = 0;
    let mut good = 0;
    for arm in arms().iter().filter(|arm| arm.same_bytes) {
        let (ended, members) = read(arm);
        let one = members
            .iter()
            .find(|member| member.0 == "ONE.BIN")
            .unwrap_or_else(|| panic!("{}: no ONE.BIN: {ended:?}", arm.archive));
        assert_eq!(one.1, arm.wrote, "{}: {ended:?}", arm.archive);
        assert_eq!(one.2, Some(arm.exit == 0), "{}: {ended:?}", arm.archive);
        if arm.exit == 0 {
            assert!(ended.is_ok(), "{}: {ended:?}", arm.archive);
            good += 1;
        }
        held += 1;
    }
    // Counted from the answers file on 9 Oct 2026: a change there shows
    // here first.
    assert_eq!((held, good), (HELD, GOOD));
}

/// The rows of the answers file whose stop range begins at 0, and those
/// of them the reference passes.
const HELD: usize = 339;
const GOOD: usize = 241;

/// On every archive, the ones where rarkit is stricter than the reference
/// or supplies zeros where it reads left over bytes included, the cut
/// member ends in a checksum verdict: it is delivered, it is never
/// `Truncated`, and the decode raises no fault of its own.
#[test]
fn no_cut_member_ends_in_an_error_of_the_decode() {
    for arm in arms() {
        let (ended, members) = read(&arm);
        let one = members
            .iter()
            .find(|member| member.0 == "ONE.BIN")
            .unwrap_or_else(|| panic!("{}: no ONE.BIN: {ended:?}", arm.archive));
        assert!(one.2.is_some(), "{}: no verdict: {ended:?}", arm.archive);
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
        // A stored member behind the cut one is read whole whatever the
        // cut member's bytes were.
        if arm.behind == "right" && !arm.archive.contains("solid") {
            let two = members.iter().find(|member| member.0 == "TWO.BIN");
            assert!(two.is_some(), "{}: {members:?}", arm.archive);
        }
    }
}
