//! SPEC-H1 5.4: every archive under `specs/vectors-H/h1-evidence/streams`
//! is a test vector, and the tables beside it say what rarkit must do
//! with it.
//!
//! A case whose file headers carry the `stated` reading extracts to the
//! sizes and SHA-256 of `want.tsv` with every header checksum agreeing.
//! A case whose headers carry another reading has a `stated` row in
//! `readings.tsv`, and that row is rarkit's: the bytes it lists, or a
//! refusal. A case with neither (six of group `s36`) carries the
//! reference's reading in its headers and rarkit agrees with it.
//!
//! Every extraction here is asked for at a width of one and of two
//! workers, with the chain's decode-ahead on and off, and holds under
//! 32 MiB: the largest declared dictionary in the set is 4 MiB.

use std::collections::HashMap;
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};
use sha2::{Digest, Sha256};

const STREAMS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-H/h1-evidence/streams"
);

/// The groups, by the section of SPEC-H1 each serves.
const GROUPS: [&str; 15] = [
    "s32",
    "s33",
    "s34-lengths",
    "s34-symbols",
    "s34-short",
    "s35-ladder",
    "s35-bonus",
    "s35-low",
    "s35-repeat",
    "s36",
    "s37",
    "s38",
    "s39",
    "s310",
    "s43",
];

fn table(group: &str, name: &str) -> Vec<Vec<String>> {
    let path = format!("{STREAMS}/{group}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One member as a table writes it: `size:sha256`.
fn cell(bytes: &[u8]) -> String {
    format!("{}:{}", bytes.len(), sha256(bytes))
}

/// What the tables say rarkit does with one case.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Wanted {
    /// The members that come out whole, in order.
    members: Vec<String>,
    /// The member after those is refused.
    refused: bool,
    /// The file headers carry these very bytes, so every checksum agrees.
    headers_agree: bool,
}

/// Every case of `group`, with what rarkit must do.
fn cases(group: &str) -> Vec<(String, Wanted)> {
    let want: HashMap<String, Vec<String>> = table(group, "want.tsv")
        .into_iter()
        .map(|row| {
            (
                row[0].clone(),
                row[2].split(' ').map(str::to_string).collect(),
            )
        })
        .collect();
    let stated: HashMap<String, (String, String)> = table(group, "readings.tsv")
        .into_iter()
        .filter(|row| row[1] == "stated")
        .map(|row| (row[0].clone(), (row[2].clone(), row[3].clone())))
        .collect();
    table(group, "streams.tsv")
        .into_iter()
        .map(|row| {
            let case = row[0].clone();
            let wanted = match stated.get(&case) {
                Some((failure, members)) => Wanted {
                    members: members
                        .split(' ')
                        .filter(|member| *member != "-" && !member.is_empty())
                        .map(str::to_string)
                        .collect(),
                    refused: failure != "no failure",
                    headers_agree: false,
                },
                None => Wanted {
                    members: want[&case].clone(),
                    refused: false,
                    headers_agree: true,
                },
            };
            (case, wanted)
        })
        .collect()
}

/// One member as it was closed: its bytes, its checksum's verdict and the
/// size its header declares.
type Closed = (Vec<u8>, Option<bool>, Option<u64>);

#[derive(Default)]
struct Collect {
    members: Vec<Closed>,
}

impl Sink for Collect {
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
        self.members.push((
            out.unwrap_or_default(),
            outcome.checksum_ok,
            member.unpacked_size,
        ));
        Ok(())
    }
}

/// What rarkit made of an archive on one read path: the members closed,
/// and the error the extraction ended with, if any.
fn extract_on(bytes: &[u8], ahead: bool, workers: usize) -> (Vec<Closed>, Option<String>) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_workers(Some(workers));
    rarkit::probe::set_ahead_off(!ahead);
    let report = rarkit::extract(sources, &options, &mut sink, &mut ());
    rarkit::probe::set_ahead_off(false);
    (sink.members, report.err().map(|error| format!("{error:?}")))
}

/// What rarkit made of one case, which every read path must agree on.
fn extract(group: &str, case: &str) -> (Vec<Closed>, Option<String>) {
    let path = format!("{STREAMS}/{group}/{case}.rar");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let first = extract_on(&bytes, true, 1);
    for (ahead, workers) in [(false, 1), (true, 2), (false, 2)] {
        let other = extract_on(&bytes, ahead, workers);
        assert_eq!(
            other, first,
            "{group}/{case}: decode-ahead {ahead}, {workers} workers"
        );
    }
    first
}

/// Why rarkit's answer to one case is not the tables', or `None`.
fn disagreement(group: &str, case: &str, wanted: &Wanted) -> Option<String> {
    let (members, error) = extract(group, case);
    let whole = wanted.members.len();
    let got: Vec<String> = members.iter().map(|(bytes, _, _)| cell(bytes)).collect();
    if wanted.refused {
        if error.is_none() {
            return Some(format!("{group}/{case}: not refused, gave {got:?}"));
        }
    } else if let Some(error) = error {
        return Some(format!("{group}/{case}: refused: {error}"));
    }
    if got.len() < whole || got[..whole] != wanted.members[..] {
        return Some(format!(
            "{group}/{case}: gave {got:?}, want {:?}",
            wanted.members
        ));
    }
    if wanted.headers_agree {
        if let Some(at) = members.iter().position(|(_, ok, _)| *ok != Some(true)) {
            return Some(format!("{group}/{case}: member {at} fails its checksum"));
        }
    }
    None
}

fn disagreements(group: &str, only: &[&str]) -> Vec<String> {
    cases(group)
        .iter()
        .filter(|(case, _)| only.is_empty() || only.contains(&case.as_str()))
        .filter_map(|(case, wanted)| disagreement(group, case, wanted))
        .collect()
}

/// SPEC-F 4.2, "A member that ends short" (restated 8 Oct 2026), on
/// SPEC-H1's four early ends (3.7, E4): each declares 6 bytes and its
/// data ends at an end of block after 3. The three bytes are delivered
/// and the member is judged by its checksum against them, as the
/// reference judges it: with the checksum of six bytes in its header it
/// is not good, and with the checksum of the three it holds it is GOOD,
/// with fewer bytes than it declares. No error is raised either way. (The
/// earlier rule, "never good whatever its checksum", was stricter than
/// the reference with no reason of safety, and this test held it.)
///
/// One and two workers, the decode-ahead on and off; under 1 MiB.
#[test]
fn a_member_that_ends_short_is_judged_by_its_checksum() {
    for (case, good) in [
        ("early-end-0", false),
        ("early-end-1", false),
        ("early-end-0-own-checksum", true),
        ("early-end-1-own-checksum", true),
    ] {
        let (members, error) = extract("s37", case);
        assert_eq!(error, None, "{case}");
        assert_eq!(members.len(), 1, "{case}");
        let (bytes, verdict, declared) = &members[0];
        assert_eq!(bytes, &[0x51, 0x50, 0x51], "{case}");
        assert_eq!(*declared, Some(6), "{case}");
        assert_eq!(*verdict, Some(good), "{case}");
    }
}

/// SPEC-H1 5.4, all 250 archives, the two own-checksum early ends among
/// them: the tables record them as the reference answers them, good, and
/// since spec F 4.2 was restated that is rarkit's verdict too.
#[test]
fn every_constructed_vector_is_answered_as_the_tables_say() {
    let mut count = 0;
    let mut wrong = Vec::new();
    for group in GROUPS {
        count += cases(group).len();
        wrong.extend(disagreements(group, &[]));
    }
    assert_eq!(count, 250, "SPEC-H1 5.1 counts 250 archives");
    assert!(
        wrong.is_empty(),
        "{} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// SPEC-H1 4.4 for the member ends of 3.7 and 3.8: every archive of the
/// groups that hold bytes after a declared size, an early end or a member
/// of zero bytes, with each single bit turned over in turn and cut at
/// every length. No answer is a panic, and no member is given more bytes
/// than its header declares.
#[test]
fn a_damaged_member_end_is_answered_without_panic() {
    let mut tried = 0u32;
    for group in ["s37", "s38"] {
        for (case, _) in cases(group) {
            let path = format!("{STREAMS}/{group}/{case}.rar");
            let whole = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            let mut damaged: Vec<Vec<u8>> =
                (1..whole.len()).map(|cut| whole[..cut].to_vec()).collect();
            for at in 0..whole.len() * 8 {
                let mut flipped = whole.clone();
                flipped[at / 8] ^= 0x80 >> (at % 8);
                damaged.push(flipped);
            }
            for bytes in damaged {
                let (members, _) = extract_on(&bytes, true, 1);
                for (data, _, declared) in members {
                    assert!(
                        data.len() as u64 <= declared.unwrap_or(0),
                        "{group}/{case}: {} bytes for a member declaring {declared:?}",
                        data.len()
                    );
                }
                tried += 1;
            }
        }
    }
    assert!(tried > 20_000, "{tried} damaged archives");
}
