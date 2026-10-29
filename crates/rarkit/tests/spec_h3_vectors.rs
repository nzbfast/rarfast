//! Spec H3 section 9.1: the constructed RAR 2.0 archives of
//! `specs/vectors-H/h3a-rar20-blocks/`, driven through the public
//! `extract`.
//!
//! `cases.tsv` there has one row per member: the declared size, the
//! stated verdict, and the length and the first 64 bits of the SHA-256 of
//! the stated bytes, which are the bytes reference unrar 7.23 extracts.
//! Section 9.1 says what a rarkit decoder does with every case, and each
//! test below is one of its sentences.
//!
//! One thread, and memory of a few megabytes: every archive is read whole
//! into memory, the largest member is 3.2 MiB and the decoder's window is
//! 4 MiB at most.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors-H/h3a-rar20-blocks")
}

/// One row of `cases.tsv`.
struct Row {
    member: usize,
    verdict: String,
    bytes: usize,
    sha64: String,
}

fn cases() -> BTreeMap<String, Vec<Row>> {
    let text = std::fs::read_to_string(dir().join("cases.tsv")).expect("cases.tsv");
    let mut cases: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        let member = match fields[3] {
            "m1.bin" => 1,
            "m2.bin" => 2,
            other => panic!("a member this test does not know: {other}"),
        };
        cases.entry(fields[0].to_string()).or_default().push(Row {
            member,
            verdict: fields[5].to_string(),
            bytes: fields[6].parse().expect("a byte count"),
            sha64: fields[7].to_string(),
        });
    }
    assert_eq!(cases.len(), 70, "the specification names 70 archives");
    cases
}

/// What one member came to.
struct Got {
    bytes: Vec<u8>,
    checksum_ok: Option<bool>,
}

#[derive(Default)]
struct Keep {
    members: Vec<Got>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if let Some(bytes) = out {
            self.members.push(Got {
                bytes,
                checksum_ok: outcome.checksum_ok,
            });
        }
        Ok(())
    }
}

/// Extract one case: the members that closed, and the fault if the
/// extraction ended on one.
fn run(case: &str) -> (Vec<Got>, Option<String>) {
    let archive = std::fs::read(dir().join(format!("{case}.rar"))).expect("the archive");
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
    let mut sink = Keep::default();
    let report = extract(sources, &ReadOptions::default(), &mut sink, &mut ());
    (
        sink.members,
        report.err().map(|e| format!("{:?}", e.kind())),
    )
}

fn sha64(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The stated bytes of a member, where the directory holds them.
fn want(case: &str, member: usize) -> Option<Vec<u8>> {
    std::fs::read(dir().join(format!("{case}.m{member}.want"))).ok()
}

/// What is wrong with a member that should be the stated bytes, if
/// anything.
fn differs(case: &str, row: &Row, got: Option<&Got>) -> Option<String> {
    let Some(got) = got else {
        return Some(format!("{case} m{}: no such member came out", row.member));
    };
    if got.bytes.len() != row.bytes || sha64(&got.bytes) != row.sha64 {
        return Some(format!(
            "{case} m{}: {} bytes with digest {}, stated {} with {}",
            row.member,
            got.bytes.len(),
            sha64(&got.bytes),
            row.bytes,
            row.sha64
        ));
    }
    if let Some(want) = want(case, row.member) {
        if want != got.bytes {
            return Some(format!(
                "{case} m{}: not the bytes of its .want",
                row.member
            ));
        }
    }
    None
}

/// The three cases rarkit's own rule of 3.2 refuses though the reference
/// decodes them.
const OVERSUBSCRIBED: [&str; 3] = [
    "h32-oversubscribed-main",
    "h32-oversubscribed-distance",
    "h32-oversubscribed-level",
];

#[test]
fn spec_h3_9_1_every_h3_case_gives_the_bytes_the_reference_extracts() {
    let mut wrong = Vec::new();
    let mut seen = 0;
    for (case, rows) in cases() {
        if !case.starts_with("h3") || OVERSUBSCRIBED.contains(&case.as_str()) {
            continue;
        }
        seen += 1;
        let (members, fault) = run(&case);
        if let Some(fault) = fault {
            wrong.push(format!("{case}: ended on {fault}"));
            continue;
        }
        for row in &rows {
            assert_eq!(row.verdict, "ok", "{case}");
            let got = members.get(row.member - 1);
            if let Some(what) = differs(&case, row, got) {
                wrong.push(what);
            } else if got.and_then(|g| g.checksum_ok) != Some(true) {
                wrong.push(format!("{case} m{}: its checksum did not pass", row.member));
            }
        }
    }
    assert_eq!(seen, 37, "40 cases begin h3, and three are refused");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn spec_h3_3_2_an_oversubscribed_table_is_refused_when_it_is_built() {
    for case in OVERSUBSCRIBED {
        let (members, fault) = run(case);
        let fault = fault.unwrap_or_else(|| panic!("{case}: decoded, and rarkit refuses it"));
        assert!(fault.contains("Oversubscribed"), "{case}: {fault}");
        // Refused before any symbol is read with the table: whatever
        // came out is from the blocks before it.
        let stated = want(case, 1).expect("the stated bytes");
        for member in &members {
            assert!(stated.starts_with(&member.bytes), "{case}");
            assert!(member.bytes.len() < stated.len(), "{case}");
        }
    }
}

#[test]
fn spec_h3_9_1_the_refusals_of_part_a_give_the_bytes_before_them_and_a_fault() {
    let refused: [(&str, usize); 9] = [
        ("x32-repeat-at-first-length-keep0", 1),
        ("x32-repeat-at-first-length-keep1", 1),
        ("x33-repeated-distance-unset-first", 1),
        ("x33-repeated-distance-unset-fourth", 1),
        ("x33-distance-past-start-by-1", 1),
        ("x33-distance-past-start-by-40", 1),
        ("x33-distance-past-start-far", 1),
        ("x33-distance-past-start-1mib", 1),
        ("x35-not-solid-distances-and-window", 2),
    ];
    let cases = cases();
    let mut wrong = Vec::new();
    for (case, member) in refused {
        let rows = &cases[case];
        let (members, fault) = run(case);
        if fault.is_none() {
            wrong.push(format!("{case}: no fault"));
        }
        for row in rows {
            let got = members.get(row.member - 1);
            if row.member < member {
                // The member before the refused one is whole.
                if let Some(what) = differs(case, row, got) {
                    wrong.push(what);
                }
                continue;
            }
            assert!(row.verdict.starts_with("refused"), "{case}");
            // The bytes before the refusal are the first bytes of the
            // stated ones; how many of them a refused member hands over
            // is the implementation's.
            let stated = want(case, row.member).expect("a refused member's bytes are short");
            assert_eq!(stated.len(), row.bytes);
            let bytes = got.map(|g| g.bytes.as_slice()).unwrap_or(&[]);
            if !stated.starts_with(bytes) {
                wrong.push(format!(
                    "{case} m{}: bytes that are not the stated ones",
                    row.member
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Section 3.5, "A match that passes the declared size" (restated 8 Oct
/// 2026): a match of 40 bytes begins 15 bytes before member one's
/// declared size. Member one delivers its declared 346 bytes and FAILS,
/// whatever its checksum field holds; the 25 bytes of the match past its
/// size enter the stream and are no member's output; member two starts
/// after them. Until 9 Oct 2026 this test asserted the withdrawn rule,
/// under which those 25 bytes opened member two: `cases.tsv` still states
/// member two as 71 bytes, the 25 and then its own.
#[test]
fn spec_h3_3_5_a_match_past_the_declared_size_fails_its_member_and_opens_no_other() {
    /// How far the match runs past member one's declared size.
    const PAST: usize = 25;
    let cases = cases();
    for case in [
        "x35-match-past-declared-size",
        "x35-match-past-declared-size-crc-of-whole",
    ] {
        let (members, fault) = run(case);
        assert_eq!(fault.as_deref(), Some("Corrupt(Stream)"), "{case}");
        let rows = &cases[case];
        // Member one: its declared bytes, and not good.
        assert_eq!(differs(case, &rows[0], members.first()), None);
        assert_eq!(members[0].checksum_ok, Some(false), "{case} m1");
        // Member two: none of the match's bytes. Its own are what the
        // stated 71 hold after the first 25, and then ONE more: its
        // packed data runs out inside its last symbol, which is read
        // whole with zeros for the bits past the end (the test below) and
        // is the literal 0x00. The reference writes these 47 bytes and
        // one further, from a symbol it begins past the end. The member
        // is short of the size its header declares and is not good.
        let stated = want(case, 2).expect("member two's stated bytes");
        assert_eq!(stated.len(), rows[1].bytes, "{case} m2");
        let own = &members.get(1).expect("member two closes").bytes;
        let (symbols, cut) = own.split_at(stated.len() - PAST);
        assert_eq!(symbols, &stated[PAST..], "{case} m2: its own bytes");
        assert_eq!(cut, [0], "{case} m2: the cut symbol, read whole");
        assert_ne!(members[1].checksum_ok, Some(true), "{case} m2 is short");
    }
}

/// Section 3.5, "A symbol that begins inside the packed data and needs
/// bits past its end" (written 9 Oct 2026): the symbol is read whole, the
/// bits past the end as zeros, and that is no fault; a symbol that would
/// begin at or past the end is not read; the member ends short with the
/// checksum's verdict. Here 100 literals are in the stream and the
/// declared size is 300: the cut symbol is the literal 0x00, so 101 bytes
/// come out, not good, and nothing is raised. The reference writes 102,
/// these and one more from a symbol it begins past the end. Until that
/// day this test held rarkit's earlier rule, that packed data running out
/// inside a symbol ends the extraction on `Truncated`.
#[test]
fn spec_h3_3_5_a_symbol_cut_by_the_end_of_the_packed_data_is_read_whole() {
    let (members, fault) = run("x35-input-runs-out");
    let stated = want("x35-input-runs-out", 1).expect("the stated bytes");
    assert_eq!(fault, None);
    assert_eq!(members.len(), 1);
    let bytes = &members[0].bytes;
    assert_eq!(bytes.len(), 101);
    let common = bytes.len().min(stated.len());
    assert_eq!(bytes[..common], stated[..common]);
    assert_eq!(bytes[100], 0, "the cut symbol, read with zeros");
    assert_eq!(members[0].checksum_ok, Some(false), "short of 300");
}

#[test]
fn spec_h3_1_unpack_version_26_is_decoded_exactly_as_20() {
    let cases = cases();
    let mut bytes = Vec::new();
    for case in ["x35-unpack-version-20", "x35-unpack-version-26"] {
        let (members, fault) = run(case);
        assert_eq!(fault, None, "{case}");
        let row = &cases[case][0];
        assert_eq!(differs(case, row, members.first()), None);
        assert_eq!(members[0].checksum_ok, Some(true), "{case}");
        bytes.push(members[0].bytes.clone());
    }
    assert_eq!(bytes[0], bytes[1]);
}
