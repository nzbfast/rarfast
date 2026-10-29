//! SPEC-I 5.2: the archives of `specs/vectors-I/evidence-06oct`, 21 of
//! part M (the model) and 172 of part R (how a PPM block sits in a RAR 3
//! stream), each against the answer recorded for reference unrar 7.23.
//!
//! rarkit gives, member for member, the outcome the outcomes file records
//! for the reference, and where that is "OK" the bytes whose SHA-256 the
//! tables record. The stated exceptions are the families of [`STRICTER`]:
//! there rarkit's rule is its own, and it refuses by name a member the
//! reference accepts (SPEC-I 3.1 and 3.3, SPEC-H1 3.6).
//!
//! Every extraction here is asked for at a width of one and of two
//! workers, with the chain's decode-ahead on and off. The largest model
//! any of them starts is 256 MiB of address space for the two members
//! that send memory byte 127 and 255 and touch a few kilobytes of it.

use std::collections::HashMap;
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};
use sha2::{Digest, Sha256};

const EVIDENCE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-I/evidence-06oct"
);

/// SPEC-I 5.2's stated exceptions: rarkit refuses where the reference
/// accepts, on purpose.
fn stricter(case: &str) -> bool {
    // Not here since 9 Oct 2026: `r28_*`, `r44_*` and `r45_*`. A copy
    // that passes the declared size and the symbols after it are applied,
    // and each member's outcome is the reference's (SPEC-I 5.2 and 3.3's
    // member end, restated 8 Oct 2026).
    const FAMILIES: [&str; 5] = [
        "r42_solid_m1_nopair_",
        "r29_root_escape_at_end",
        "r52_solid_ppm_no_pair_then_lz_member",
        "r31_distance_before_start",
        "r46_nonsolid_continue",
    ];
    let odd_end =
        case.starts_with("r27_member_end_") && !case.ends_with("_E2") && !case.ends_with("_E0");
    odd_end || FAMILIES.iter().any(|family| case.starts_with(family))
}

fn text(name: &str) -> String {
    let path = format!("{EVIDENCE}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What the reference answered for one archive: per member, in order,
/// whether it reported the member OK.
fn answers(name: &str) -> Vec<(String, Vec<bool>)> {
    let mut out = Vec::new();
    for line in text(name).lines() {
        let cells: Vec<&str> = line.split('\t').collect();
        let Some(report) = cells.iter().find(|cell| cell.starts_with("[Testing ")) else {
            continue;
        };
        let members = report
            .trim_matches(|c| c == '[' || c == ']')
            .split("; ")
            .filter_map(|part| part.strip_prefix("Testing "))
            .map(|member| member.ends_with(" OK"))
            .collect();
        out.push((cells[0].to_string(), members));
    }
    out
}

/// Per archive, the length and SHA-256 of the bytes it holds under the
/// reading it was coded for, all members together.
fn recorded() -> HashMap<String, (usize, String)> {
    let mut out = HashMap::new();
    for line in text("r-cases.tsv").lines().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        out.insert(
            cells[0].to_string(),
            (cells[3].parse().unwrap(), cells[4].to_string()),
        );
    }
    for line in text("m-streams.tsv").lines().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        out.insert(
            cells[0].to_string(),
            (cells[4].parse().unwrap(), cells[6].to_string()),
        );
    }
    out
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Option<bool>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members
            .push((out.unwrap_or_default(), outcome.checksum_ok));
        Ok(())
    }
}

/// What rarkit made of an archive: per member closed, its bytes and
/// whether it came out whole; and the name of the refusal, if any.
type Made = (Vec<(Vec<u8>, bool)>, Option<String>);

fn extract_on(bytes: &[u8], ahead: bool, workers: usize) -> Made {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_workers(Some(workers));
    rarkit::probe::set_ahead_off(!ahead);
    let report = rarkit::extract(sources, &options, &mut sink, &mut ());
    rarkit::probe::set_ahead_off(false);
    let refusal = report.err().map(|error| format!("{:?}", error.kind()));
    let mut members: Vec<(Vec<u8>, bool)> = sink
        .members
        .into_iter()
        .map(|(bytes, ok)| (bytes, ok == Some(true)))
        .collect();
    // A refusal is the last closed member's, whatever its checksum said
    // of the bytes that came before it.
    if refusal.is_some() {
        if let Some(last) = members.last_mut() {
            last.1 = false;
        }
    }
    (members, refusal)
}

fn extract(case: &str) -> Made {
    let path = format!("{EVIDENCE}/{case}.rar");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let first = extract_on(&bytes, true, 1);
    for (ahead, workers) in [(false, 1), (true, 2), (false, 2)] {
        let other = extract_on(&bytes, ahead, workers);
        assert_eq!(
            other, first,
            "{case}: decode-ahead {ahead}, {workers} workers"
        );
    }
    first
}

/// SPEC-I 5.2, every archive.
#[test]
fn every_evidence_archive_has_the_recorded_outcome() {
    let linux = answers("outcomes-unrar-7.23-linux-x86_64.txt");
    assert_eq!(
        linux,
        answers("outcomes-unrar-7.23-macos-arm64.txt"),
        "the two recorded references agree"
    );
    assert_eq!(linux.len(), 193, "21 of part M and 172 of part R");
    let recorded = recorded();
    let mut wrong = Vec::new();
    let mut refused_on_purpose = 0;
    for (case, reference) in &linux {
        let (members, refusal) = extract(case);
        if stricter(case) {
            // rarkit's own rule: a named refusal, whatever the reference
            // made of the member.
            match refusal {
                Some(_) => refused_on_purpose += 1,
                None => wrong.push(format!("{case}: not refused")),
            }
            continue;
        }
        let mine: Vec<bool> = (0..reference.len())
            .map(|at| members.get(at).is_some_and(|member| member.1))
            .collect();
        if mine != *reference {
            wrong.push(format!(
                "{case}: members whole {mine:?}, the reference {reference:?}, refusal {refusal:?}"
            ));
            continue;
        }
        if reference.iter().all(|ok| *ok) {
            let all: Vec<u8> = members.iter().flat_map(|member| member.0.clone()).collect();
            let (length, sha) = &recorded[case];
            if all.len() != *length || sha256(&all) != *sha {
                wrong.push(format!("{case}: other bytes than the tables record"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(refused_on_purpose, 12, "SPEC-I 5.2's stated exceptions");
}
