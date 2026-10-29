//! SPEC-J 5.4: the kept arms of the four probes of 6 Oct 2026, under
//! `specs/vectors-J/j33-record`, `j34-identify`, `j36-queue` and
//! `j37-transforms`. For each `X.rar` the reference prints `X.want`.
//!
//! And the row wider than its span (SPEC-J 3.5), where the reference is
//! not the judge: the arms of `j35-rgb-short-span`, whose `X.want` is
//! what genuine unrar 4.20 prints, and the ten genuine archives of
//! `j35-genuine-tails`, each judged by the checksum its own writer put in
//! its header.
//!
//! rarkit prints `X.want` for every arm on which the reference gives a
//! whole member and the specification does not refuse it, and fails the
//! member by the named error where the specification refuses or the
//! reference itself stops short (the table of 5.4, which [`expected`]
//! is).
//!
//! One worker, no pool of its own; the members are under 2 KiB but for
//! `j37-transforms`, whose longest is under 200 KiB, and each extraction
//! holds under 8 MiB.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-J");

/// What SPEC-J 5.4 asks of one arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// The bytes of `X.want`.
    Want,
    /// `Unsupported(FilterProgram { .. })`.
    NoSuchProgram,
    /// `Corrupt(FilterRecord)`.
    BadRecord,
    /// `Corrupt(FilterParameters)`.
    BadParameters,
    /// `j33_reset-forgets-slots`: the member whole with all three filters
    /// run, where the reference does not run the first, so `X.want` is
    /// the same length and other bytes.
    EveryFilterRun,
}

fn expected(arm: &str) -> Expected {
    const NO_PROGRAM: [&str; 5] = ["_xor", "_crc", "_longer", "_shorter", "_flipped"];
    // Not here since 9 Oct 2026: `j36_end-start-*` and
    // `j36_span-in-the-next-member-*`, a span that starts at or past the
    // end of the member it was read in. It is dropped when the member
    // ends and fails nothing, as the reference does (SPEC-J 3.8 and its
    // section 4 row, restated 8 Oct 2026), so those arms print `X.want`.
    const BAD_RECORD: [&str; 8] = [
        "j33_bad-",
        "j33_body-0-code-7",
        "j33_program-1-byte-short",
        "j33_start-before-the-record",
        "j33_reset-with-a-filter-waiting",
        "j36_end-one-past",
        "j36_span-across-the-boundary-",
        "j36_disorder-",
    ];
    if arm.starts_with("j34_") && NO_PROGRAM.iter().any(|end| arm.ends_with(end)) {
        Expected::NoSuchProgram
    } else if BAD_RECORD.iter().any(|start| arm.starts_with(start))
        || (arm.starts_with("j36_slot-from-a-") && arm.ends_with("-separate"))
    {
        Expected::BadRecord
    } else if arm.starts_with("j35s_odd-") {
        Expected::BadParameters
    } else if arm == "j33_reset-forgets-slots" {
        Expected::EveryFilterRun
    } else {
        Expected::Want
    }
}

#[derive(Default)]
struct Keep(Vec<u8>);

impl Sink for Keep {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.extend(out.unwrap_or_default());
        Ok(())
    }
}

/// Why rarkit's answer to one arm is not SPEC-J's, or `None`.
fn disagreement(directory: &str, arm: &str) -> Option<String> {
    let path = format!("{VECTORS}/{directory}/{arm}");
    let archive = std::fs::read(format!("{path}.rar")).unwrap_or_else(|e| panic!("{path}: {e}"));
    // An arm the reference gives no member for has no `.want`; such an
    // arm is always one the specification refuses.
    let want = std::fs::read(format!("{path}.want")).ok();
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
    let mut sink = Keep::default();
    let options = ReadOptions::default().with_workers(Some(1));
    let refusal = rarkit::extract(sources, &options, &mut sink, &mut ())
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let refused_as = |name: &str| match &refusal {
        Some(kind) if kind.contains(name) => None,
        other => Some(format!("{arm}: wanted {name}, got {other:?}")),
    };
    match expected(arm) {
        Expected::NoSuchProgram => refused_as("FilterProgram"),
        Expected::BadRecord => refused_as("Corrupt(FilterRecord)"),
        Expected::BadParameters => refused_as("Corrupt(FilterParameters)"),
        Expected::Want | Expected::EveryFilterRun if refusal.is_some() => {
            Some(format!("{arm}: refused, {refusal:?}"))
        }
        Expected::Want if Some(&sink.0) != want.as_ref() => {
            Some(format!("{arm}: other bytes than {arm}.want"))
        }
        Expected::EveryFilterRun
            if want
                .as_ref()
                .is_none_or(|want| sink.0.len() != want.len() || sink.0 == *want) =>
        {
            Some(format!("{arm}: not the member with every filter run"))
        }
        _ => None,
    }
}

fn arms(directory: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(format!("{VECTORS}/{directory}"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter_map(|name| name.strip_suffix(".rar").map(str::to_string))
        .collect();
    names.sort();
    names
}

fn held_to_the_specification(directory: &str, count: usize) {
    let arms = arms(directory);
    assert_eq!(arms.len(), count, "{directory}");
    let wrong: Vec<String> = arms
        .iter()
        .filter_map(|arm| disagreement(directory, arm))
        .collect();
    assert!(
        wrong.is_empty(),
        "{directory}: {} of {count} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_record_arms_of_section_3_3() {
    held_to_the_specification("j33-record", 63);
}

#[test]
fn the_identification_arms_of_section_3_4() {
    held_to_the_specification("j34-identify", 40);
}

#[test]
fn the_queue_arms_of_section_3_6() {
    held_to_the_specification("j36-queue", 27);
}

#[test]
fn the_transform_arms_of_section_3_7() {
    held_to_the_specification("j37-transforms", 255);
}

/// 44 arms that genuine unrar 4.20 runs (`short-*` and `tail-*`) and 15
/// whose row is not a multiple of three (`odd-*`), which stay refused.
#[test]
fn the_rgb_row_wider_than_its_span_arms_of_section_3_5() {
    held_to_the_specification("j35-rgb-short-span", 59);
}

/// The ten archives genuine rar 4.20 and rar 5.50 wrote with a row of
/// three over a last span of 1 or 2 bytes: each member comes out whole,
/// at the size its header declares and with its header's checksum
/// agreeing, which reference unrar 7.23 does not manage for any of them.
///
/// One worker; the largest is 262,145 bytes and each extraction holds
/// under 8 MiB.
#[test]
fn the_genuine_true_colour_tails_extract_whole() {
    struct Judged(Vec<(u64, Option<u64>, Option<bool>)>);
    impl Sink for Judged {
        type Out = Vec<u8>;
        fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            let bytes = out.map_or(0, |bytes| bytes.len() as u64);
            self.0
                .push((bytes, member.unpacked_size, outcome.checksum_ok));
            Ok(())
        }
    }
    let arms = arms("j35-genuine-tails");
    assert_eq!(arms.len(), 10);
    for arm in arms {
        let path = format!("{VECTORS}/j35-genuine-tails/{arm}.rar");
        let archive = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
        let mut sink = Judged(Vec::new());
        let options = ReadOptions::default().with_workers(Some(1));
        rarkit::extract(sources, &options, &mut sink, &mut ())
            .unwrap_or_else(|error| panic!("{arm}: {error:?}"));
        // The name says how long the packed file was.
        let length: u64 = arm.rsplit('_').next().unwrap().parse().unwrap();
        assert_eq!(sink.0, vec![(length, Some(length), Some(true))], "{arm}");
    }
}
