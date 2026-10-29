//! SPEC-H1 5.4, its last two tables: the 105 archives of
//! `specs/vectors-H/h1-ppm-join/archives`, in which a RAR 3 stream joins
//! its LZ and PPM codings at a member's end, and the 128 of
//! `specs/vectors-H/h1-ppm-join/cut`, whose packed data runs out
//! (SPEC-H1 3.8, B4 to B6; SPEC-I 3.2, 3.3 and 3.10.1; SPEC-F 3.6.3
//! item 4).
//!
//! `cases.tsv` beside each set gives the bytes each archive's reading
//! expects, and `cut/model.tsv` says where a decoder meets the cut. What
//! rarkit owes is the tables' right hand column, row by row; each test
//! below is one row or a few and says which.
//!
//! Every extraction here is asked for at a width of one and of two
//! workers, with the chain's decode-ahead on and off, under a working
//! memory limit of 64 MiB ([`LIMIT`]): the tables' answers are the
//! answers within that limit, the models the joined headers start
//! included.

use std::collections::BTreeMap;
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};
use sha2::{Digest, Sha256};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-H/h1-ppm-join"
);

/// The working memory limit every extraction here is asked for under.
const LIMIT: u64 = 64 << 20;

/// The one failure of spec I 3.3's member end, as an error prints it: the
/// packed data running out before the end pair. (Symbols that are not the
/// pair were `BadMemberEnd` until the rule was restated on 8 Oct 2026;
/// they are decoded and applied now, as the reference does.)
const RAN_OUT: &str = "kind: Truncated";

/// Which members the reference printed as `cases.tsv` codes them, by
/// archive and member name: the answers file beside the archives, whose
/// second field lists each member as `AS CODED` or `NOT as coded`.
fn printed() -> BTreeMap<String, BTreeMap<String, bool>> {
    let path = format!("{VECTORS}/unrar-7.23-macos-arm64.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut all = BTreeMap::new();
    for line in text.lines().skip(1).filter(|line| !line.is_empty()) {
        let cells: Vec<&str> = line.split('\t').collect();
        let members = cells[2]
            .split("; ")
            .filter_map(|member| {
                let (name, said) = member.split_once(' ')?;
                Some((name.to_string(), said.starts_with("AS CODED")))
            })
            .collect();
        all.insert(cells[0].to_string(), members);
    }
    all
}

/// Every member good and as coded exactly where the reference printed it
/// as coded, and not good where it did not. No error is asserted: a
/// member coded under a reading the stream does not follow fails by
/// whatever its bytes meet, or by its checksum.
fn as_the_reference_printed(
    name: &str,
    archive: &Archive,
    printed: &BTreeMap<String, BTreeMap<String, bool>>,
    made: &Made,
) -> Wanted {
    let said = printed
        .get(name)
        .unwrap_or_else(|| panic!("{name}: no answer of the reference's"));
    let members = archive
        .members
        .iter()
        .map(|(member, _, _)| match said.get(member) {
            Some(true) => Member::AsCoded,
            Some(false) => Member::Failed,
            None => panic!("{name}: the reference says nothing of {member}"),
        })
        .collect::<Vec<_>>();
    let failing = members.iter().position(|m| *m == Member::Failed);
    Wanted {
        members,
        error: match (failing, &made.1) {
            (Some(at), Some(_)) => Some(("", at)),
            _ => None,
        },
    }
}

/// One archive of a `cases.tsv`: its case, its reading, and the name, size
/// and SHA-256 of each member under that reading, in order.
struct Archive {
    case: String,
    reading: String,
    members: Vec<(String, u64, String)>,
}

fn archives(set: &str) -> BTreeMap<String, Archive> {
    let path = format!("{VECTORS}/{set}/cases.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut all: BTreeMap<String, Archive> = BTreeMap::new();
    for line in text.lines().skip(1).filter(|line| !line.is_empty()) {
        let cells: Vec<&str> = line.split('\t').collect();
        let entry = all.entry(cells[0].to_string()).or_insert_with(|| Archive {
            case: cells[1].to_string(),
            reading: cells[2].to_string(),
            members: Vec::new(),
        });
        entry.members.push((
            cells[3].to_string(),
            cells[4].parse().expect("a size"),
            cells[6].to_string(),
        ));
    }
    all
}

/// `cut/model.tsv`: where a decoder written from SPEC-I's text meets the
/// cut, by archive.
fn met() -> BTreeMap<String, String> {
    let path = format!("{VECTORS}/cut/model.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_once('\t'))
        .map(|(archive, what)| (archive.to_string(), what.to_string()))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One member as it was closed: its bytes, its checksum's verdict and the
/// size its header declares.
type Closed = (Vec<u8>, Option<bool>, Option<u64>);

/// What rarkit made of an archive: the members closed, and the first
/// error of the extraction, if any.
type Made = (Vec<Closed>, Option<String>);

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

fn extract_on(bytes: &[u8], ahead: bool, workers: usize) -> Made {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Collect::default();
    let mut options = ReadOptions::default().with_workers(Some(workers));
    options.memory.working_limit = LIMIT;
    rarkit::probe::set_ahead_off(!ahead);
    let report = rarkit::extract(sources, &options, &mut sink, &mut ());
    rarkit::probe::set_ahead_off(false);
    (sink.members, report.err().map(|error| format!("{error:?}")))
}

/// What rarkit made of one archive, which every read path must agree on.
fn extract(set: &str, name: &str) -> Made {
    let path = format!("{VECTORS}/{set}/{name}.rar");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let first = extract_on(&bytes, true, 1);
    for (ahead, workers) in [(false, 1), (true, 2), (false, 2)] {
        let other = extract_on(&bytes, ahead, workers);
        assert_eq!(
            other, first,
            "{name}: decode-ahead {ahead}, {workers} workers"
        );
    }
    first
}

/// What a row of the tables says of one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    /// Its bytes as `cases.tsv` codes them and its checksum good.
    AsCoded,
    /// Its bytes as coded, delivered before the failure, and not good.
    WholeButFailed,
    /// Not good, whatever was delivered.
    Failed,
}

/// What a row of the tables says of one archive.
struct Wanted {
    members: Vec<Member>,
    /// The first error: what it prints, and the index of its member.
    error: Option<(&'static str, usize)>,
}

impl Wanted {
    /// Every member as coded and no error.
    fn whole(count: usize) -> Wanted {
        Wanted {
            members: vec![Member::AsCoded; count],
            error: None,
        }
    }

    /// Member `at` fails by `how`, the members before it are as coded,
    /// and those after it fail too unless `after` says otherwise.
    fn failing(count: usize, at: usize, how: &'static str) -> Wanted {
        let mut members = vec![Member::AsCoded; at];
        members.resize(count, Member::Failed);
        Wanted {
            members,
            error: Some((how, at)),
        }
    }
}

/// Why rarkit's answer is not `wanted`, or `None`.
fn differs(name: &str, archive: &Archive, made: &Made, wanted: &Wanted) -> Option<String> {
    let (closed, error) = made;
    if closed.len() != wanted.members.len() {
        return Some(format!("{name}: {} members closed", closed.len()));
    }
    for (at, want) in wanted.members.iter().enumerate() {
        let (_, size, sha) = &archive.members[at];
        let (bytes, verdict, _) = &closed[at];
        let bytes_as_coded = bytes.len() as u64 == *size && sha256(bytes) == *sha;
        let good = *verdict == Some(true);
        let right = match want {
            Member::AsCoded => bytes_as_coded && good,
            Member::WholeButFailed => bytes_as_coded && !good,
            Member::Failed => !good,
        };
        if !right {
            return Some(format!(
                "{name}: member {at} is not {want:?} ({} bytes, {verdict:?}, {error:?})",
                bytes.len()
            ));
        }
    }
    match (&wanted.error, error) {
        (None, None) => None,
        (Some((how, at)), Some(e)) => {
            let holder = format!("member: Some({:?})", archive.members[*at].0.as_bytes());
            (!e.contains(how) || !e.contains(&holder))
                .then(|| format!("{name}: want {how} at member {at}, got {e}"))
        }
        (None, Some(e)) => Some(format!("{name}: refused: {e}")),
        (Some((how, _)), None) => Some(format!("{name}: want {how}, got no error")),
    }
}

/// Run `wanted` over the archives of `set` it answers for, and assert
/// there are `count` of them and none differs.
fn assert_rows(set: &str, count: usize, mut wanted: impl FnMut(&str, &Archive) -> Option<Wanted>) {
    let mut seen = 0;
    let mut wrong = Vec::new();
    for (name, archive) in &archives(set) {
        let Some(wanted) = wanted(name, archive) else {
            continue;
        };
        seen += 1;
        wrong.extend(differs(name, archive, &extract(set, name), &wanted));
    }
    assert_eq!(seen, count, "SPEC-H1 5.4 counts {count} archives here");
    assert!(
        wrong.is_empty(),
        "{} of {count} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The four shapes that put something after a header where nothing is
/// owed, by the end of a case's name.
fn has_family(case: &str, families: &[&str]) -> bool {
    families.iter().any(|family| case.ends_with(family))
}

/// The member after a refused one: as coded where it begins with a START
/// header, which starts the model anew (spec I 3.10.1), and failed where
/// it continues the model or has no header.
fn member_after(reading: &str) -> Member {
    match reading {
        "then-start" => Member::AsCoded,
        _ => Member::Failed,
    }
}

/// A header, or symbols, in the packed data of a member that still has
/// bytes of its own: that member fails by `how`, and the one after it as
/// [`member_after`] says.
fn in_a_members_tail(archive: &Archive, how: &'static str) -> Wanted {
    let count = archive.members.len();
    let mut wanted = Wanted::failing(count, count - 2, how);
    wanted.members[count - 2] = Member::WholeButFailed;
    wanted.members[count - 1] = member_after(&archive.reading);
    wanted
}

/// The same in a member of zero bytes: that member is reported good (spec
/// F 3.6.3 item 4), and the failure it raised, `kept`, is the failure of
/// the member after it where that one begins with a CONTINUE header.
/// Where it has no header it fails by whatever its first bytes meet, or
/// by its checksum, and no error is asserted.
fn in_a_member_of_zero_bytes(archive: &Archive, kept: &'static str, made: &Made) -> Wanted {
    let count = archive.members.len();
    match archive.reading.as_str() {
        "then-start" => Wanted::whole(count),
        "read-then-no-header" => {
            let mut wanted = Wanted::failing(count, count - 1, kept);
            wanted.error = made.1.as_ref().map(|_| ("", count - 1));
            wanted
        }
        _ => Wanted::failing(count, count - 1, kept),
    }
}

/// The joined archives' first row: 23 archives answered as the reference
/// answers them. 20 are printed as coded. The 3 coded under
/// `not-read-then-continue` have a judged member, the last, coded under a
/// model the stream no longer holds, and it fails.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn the_23_archives_answered_as_the_reference_answers_them() {
    let mut failing = 0;
    assert_rows("archives", 23, |_, archive| {
        let case = archive.case.as_str();
        let listed = case.starts_with("c1-")
            || case.starts_with("c2-")
            || case.ends_with("-pair")
            || case == "p-lz";
        if !listed {
            return None;
        }
        let count = archive.members.len();
        Some(if archive.reading == "not-read-then-continue" {
            failing += 1;
            // The table says "a failed member": by a fault of the text
            // model, which is what a block coded under another model
            // meets.
            Wanted::failing(count, count - 1, "Ppmd(")
        } else {
            Wanted::whole(count)
        })
    });
    assert_eq!(failing, 3, "the reference prints 20 of the 23 as coded");
}

/// The second row: a START header and nothing after it, in the packed
/// data of an LZ member after its declared size. The data ran out inside
/// the header's four range bytes: `Truncated` at that member (spec I
/// 3.2), kept (3.10.1).
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn a_ppm_header_cut_in_its_range_bytes_in_a_members_tail_is_truncated() {
    assert_rows("archives", 9, |_, archive| {
        let case = archive.case.as_str();
        (case.starts_with("t-") && case.ends_with("-header"))
            .then(|| in_a_members_tail(archive, RAN_OUT))
    });
}

/// The third row (restated 8 Oct 2026, spec I 3.3's member end): a
/// header, 40 symbols and the end pair where nothing is owed. The symbols
/// are decoded and applied, the member that holds them is good, and the
/// member after it is as coded under the reading the reference printed.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn symbols_after_a_ppm_header_in_a_members_tail_are_decoded_and_applied() {
    let printed = printed();
    let mut as_coded = 0;
    let mut wrong = Vec::new();
    let mut seen = 0;
    for (name, archive) in &archives("archives") {
        let case = archive.case.as_str();
        let listed = (case.starts_with("t-") && has_family(case, &["-symbols", "-continue"]))
            || case == "p-symbols";
        if !listed {
            continue;
        }
        seen += 1;
        let made = extract("archives", name);
        let wanted = as_the_reference_printed(name, archive, &printed, &made);
        let holder = wanted.members.len() - 2;
        assert_eq!(
            wanted.members[holder],
            Member::AsCoded,
            "{name}: the reference prints the member that holds the symbols"
        );
        as_coded += usize::from(wanted.members.iter().all(|m| *m == Member::AsCoded));
        wrong.extend(differs(name, archive, &made, &wanted));
    }
    assert_eq!(
        seen, 22,
        "22 of the 35 archives with symbols in a tail end in a pair"
    );
    assert_eq!(as_coded, 12, "the reference prints 12 of the 22 whole");
    assert!(
        wrong.is_empty(),
        "{} of {seen} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The row after it: a header and 40 symbols with NO end pair. The packed
/// data runs out before `E, 2` or `E, 0`: `Truncated` at the member that
/// holds them, after its bytes were delivered (spec I 3.3), and kept
/// (3.10.1).
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn symbols_with_no_end_pair_in_a_members_tail_are_truncated() {
    assert_rows("archives", 13, |_, archive| {
        let case = archive.case.as_str();
        (case.starts_with("t-") && case.ends_with("-open"))
            .then(|| in_a_members_tail(archive, RAN_OUT))
    });
}

/// The last row: the same shapes in a member of ZERO bytes, 38 archives.
/// The member of zero bytes is reported good, by its checksum against
/// zero bytes (spec F 3.6.3 item 4).
///
/// With an end pair (`-symbols`, `-continue`, 16) nothing is raised: the
/// symbols are decoded and applied, and the member after it is as coded
/// under the reading the reference printed.
///
/// With none (`-header`, `-open`, 22) the packed data runs out:
/// `Truncated` is raised there and kept, so the member after it fails
/// with that same failure where it begins with a CONTINUE header, decodes
/// as coded where it begins with a START header, and fails where it has
/// no header.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn the_same_in_a_member_of_zero_bytes_is_never_that_members_failure() {
    let printed = printed();
    let mut by_shape = [0usize; 2];
    let all = archives("archives");
    let mut wrong = Vec::new();
    for (name, archive) in &all {
        let case = archive.case.as_str();
        if !(case.starts_with("z-")
            && has_family(case, &["-header", "-symbols", "-open", "-continue"]))
        {
            continue;
        }
        let made = extract("archives", name);
        let ends = has_family(case, &["-symbols", "-continue"]);
        by_shape[usize::from(!ends)] += 1;
        let wanted = match ends {
            true => as_the_reference_printed(name, archive, &printed, &made),
            false => in_a_member_of_zero_bytes(archive, RAN_OUT, &made),
        };
        let zero = wanted.members.len() - 2;
        assert_eq!(
            archive.members[zero].1, 0,
            "{name}: the member of zero bytes"
        );
        assert_eq!(wanted.members[zero], Member::AsCoded, "{name}");
        wrong.extend(differs(name, archive, &made, &wanted));
    }
    assert_eq!(by_shape, [16, 22], "SPEC-H1 5.4 counts 38 archives here");
    assert!(
        wrong.is_empty(),
        "{} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Whether a cut archive's packed data, and not the file, was cut.
fn data_cut(archive: &Archive) -> bool {
    archive.reading.starts_with("data-cut-")
}

/// The cut archives' first three rows, 52 archives whose member's packed
/// data was shortened and its header rewritten to match:
///
/// - the end pair read whole (12): the member good, the bytes gone are
///   past the PPM data's end and are not read (SPEC-H1 3.8, B8);
/// - the data running out inside the two symbols after the declared size
///   (13): `Truncated` at that member, after its bytes were delivered;
/// - the data running out before the declared size (27): `Truncated` at
///   that member.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn packed_data_cut_at_or_before_a_ppm_members_end_pair() {
    let met = met();
    let mut rows = [0usize; 3];
    assert_rows("cut", 52, |name, archive| {
        if !data_cut(archive) {
            return None;
        }
        let count = archive.members.len();
        let what = met[name].as_str();
        Some(if what.contains("end pair read") {
            rows[0] += 1;
            Wanted::whole(count)
        } else if what.contains("after the declared size") {
            rows[1] += 1;
            let mut wanted = Wanted::failing(count, count - 1, RAN_OUT);
            wanted.members[count - 1] = Member::WholeButFailed;
            wanted
        } else {
            assert!(what.contains("before the declared size"), "{name}: {what}");
            rows[2] += 1;
            Wanted::failing(count, count - 1, RAN_OUT)
        })
    });
    assert_eq!(rows, [12, 13, 27]);
}

/// The fourth row, 56 archives whose FILE ends early or lacks only its
/// end block. What a source that ends early is reported as is spec F's:
/// here, nothing but `Truncated`, and every member closed before it is as
/// coded. The archive that lacks only its end block opens whole.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn a_file_cut_short_is_truncated_and_nothing_else() {
    let mut whole = 0;
    let mut seen = 0;
    for (name, archive) in &archives("cut") {
        if !archive.reading.starts_with("file-cut-") {
            continue;
        }
        seen += 1;
        let (closed, error) = extract("cut", name);
        match error {
            None => {
                whole += 1;
                let wanted = Wanted::whole(archive.members.len());
                assert_eq!(differs(name, archive, &(closed, None), &wanted), None);
            }
            Some(e) => {
                assert!(e.contains(RAN_OUT), "{name}: {e}");
                for (at, (bytes, verdict, _)) in closed.iter().enumerate() {
                    let (_, size, sha) = &archive.members[at];
                    assert_eq!(bytes.len() as u64, *size, "{name}: member {at}");
                    assert_eq!(&sha256(bytes), sha, "{name}: member {at}");
                    assert_eq!(*verdict, Some(true), "{name}: member {at}");
                }
            }
        }
    }
    assert_eq!(seen, 56, "SPEC-H1 5.4 counts 56 archives here");
    assert_eq!(
        whole, 4,
        "one of each of the four sources lacks only its end block"
    );
}

/// The last two rows, 20 archives: a START header of three bytes cut to
/// its first one or two, where nothing is owed. Nothing of a header the
/// packed data does not hold whole takes effect (spec I 3.2).
///
/// In an LZ member's tail (10): `Truncated` at the member that holds it;
/// the member after it fails with the kept `Truncated` where it begins
/// with a CONTINUE header (8) and decodes as coded where it begins with a
/// START header (2). In a member of zero bytes (10): that member is
/// reported good, and the member after it is the same.
///
/// One and two workers, the decode-ahead on and off; under 64 MiB.
#[test]
fn a_ppm_header_cut_in_its_own_bytes_where_nothing_is_owed() {
    let mut tails = 0;
    let mut zeros = 0;
    for (name, archive) in &archives("cut") {
        let case = archive.case.as_str();
        let made = extract("cut", name);
        let count = archive.members.len();
        let wanted = if case.starts_with("t-ppm-cut-header-") {
            tails += 1;
            let wanted = in_a_members_tail(archive, RAN_OUT);
            if archive.reading != "then-start" {
                // The member after it fails by the kept failure; the
                // first error stays the holder's.
                assert!(made.0[count - 1].1 != Some(true), "{name}");
            }
            wanted
        } else if case.starts_with("z-ppm-cut-header-") {
            zeros += 1;
            in_a_member_of_zero_bytes(archive, RAN_OUT, &made)
        } else {
            continue;
        };
        assert_eq!(differs(name, archive, &made, &wanted), None);
    }
    assert_eq!((tails, zeros), (10, 10), "SPEC-H1 5.4 counts 10 and 10");
}

/// One archive of each shape a join takes, for the damage test.
const DAMAGED: [&str; 6] = [
    "z-lz-pair.read-then-continue",
    "z-ppm-pair.read-then-continue",
    "t-none-pair.read-then-continue",
    "t-ppm-pair.read-then-continue",
    "p-pair.read-then-continue",
    "p-lz.read-then-kept-tables",
];

/// SPEC-H1 4.4 for these member ends, and the hostile input check this
/// change owes for reading what was left unread before: six of the
/// joined archives, one of each shape, cut at every length and with each
/// single bit turned over in turn. No answer is a panic or a hang, and no
/// member is given more bytes than its header declares. A header read in
/// a tail starts its model within the caller's limit like any other (spec
/// I 4.2), so a damaged memory byte is refused by that limit and
/// allocates nothing.
///
/// One worker, the decode-ahead on, a working memory limit of 64 MiB.
#[test]
fn a_damaged_join_is_answered_without_panic_within_the_memory_limit() {
    let mut tried = 0u32;
    for name in DAMAGED {
        let path = format!("{VECTORS}/archives/{name}.rar");
        let whole = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut damaged: Vec<Vec<u8>> = (1..whole.len()).map(|cut| whole[..cut].to_vec()).collect();
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
                    "{name}: {} bytes for a member declaring {declared:?}",
                    data.len()
                );
            }
            tried += 1;
        }
    }
    assert!(tried > 20_000, "{tried} damaged archives");
}
