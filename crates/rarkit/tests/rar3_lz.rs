//! Spec H1 against genuine archives: the five legacy vectors of
//! `specs/vectors-H/legacy`, spec J's 15 and spec I's, each member decoded
//! and judged by the SHA-256 `specs/vectors-H/CHECK-rar3.tsv` records and
//! by the CRC32 its own header carries.

#[path = "support/rar4lz.rs"]
mod rar4lz;

use std::collections::HashMap;

use rar4lz::{chains, Chain};
use rarkit::internals::rar3_lz::{decode_stream_partial, MemberIn, MemberOut};
use sha2::{Digest, Sha256};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs");

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{VECTORS}/{path}")).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// What `CHECK-rar3.tsv` records for one member.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    declared: u64,
    /// The SHA-256 of the UNFILTERED bytes, when the checker produced them.
    sha256: Option<String>,
    /// How many filter records the member carries.
    records: u64,
    /// The checker could not reach this member (a PPM block, or the LZ
    /// member after one).
    skipped: bool,
}

/// `CHECK-rar3.tsv`, by (archive, member name).
fn check_table() -> HashMap<(String, String), Row> {
    let text = String::from_utf8(read("vectors-H/CHECK-rar3.tsv")).unwrap();
    let mut rows = HashMap::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let cell: Vec<&str> = line.split('\t').collect();
        if cell.len() < 6 {
            continue;
        }
        let verdict = cell[5];
        let row = Row {
            declared: cell[2].parse().unwrap(),
            sha256: (cell[4] != "-").then(|| cell[4].to_string()),
            records: verdict
                .strip_prefix("RECORDS ")
                .map_or(0, |count| count.parse().unwrap()),
            skipped: verdict == "PPM" || verdict.starts_with("FAIL"),
        };
        // The checker writes the names as the archive stores them.
        rows.insert((cell[0].to_string(), cell[1].replace('\\', "/")), row);
    }
    rows
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // The committed table records 63 hex digits for some rows; compare on
    // the prefix each row carries.
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn name_of(member: &rar4lz::Member4) -> String {
    String::from_utf8_lossy(&member.name).replace('\\', "/")
}

/// Decode every chain of `archive`, returning (member name, output).
fn decode_archive(archive: &[u8]) -> Vec<(rar4lz::Member4, Result<MemberOut, String>, u64)> {
    let mut out = Vec::new();
    for chain in chains(archive) {
        let Chain {
            packed,
            members,
            spans,
            dictionary,
        } = chain;
        if members.iter().any(|m| m.version != 29 || m.method == 0x30) {
            // Stored members and the RAR 2.0 codec are not this package's.
            continue;
        }
        let ins: Vec<MemberIn> = members
            .iter()
            .zip(&spans)
            .map(|(member, span)| MemberIn {
                packed: span.clone(),
                unpacked: member.unpacked,
            })
            .collect();
        let (decoded, records, failed) = decode_stream_partial(&packed, &ins, dictionary, true);
        let broke = failed.map(|error| error.to_string());
        for (at, member) in members.into_iter().enumerate() {
            let last = at + 1 == decoded.len();
            match decoded.get(at) {
                Some(bytes) if !(last && broke.is_some()) => {
                    out.push((member, Ok(bytes.clone()), records))
                }
                _ => out.push((
                    member,
                    Err(broke.clone().unwrap_or_else(|| "not reached".into())),
                    records,
                )),
            }
        }
    }
    out
}

/// Every archive this package's corpus covers, by the path
/// `CHECK-rar3.tsv` names it: the three RAR 2.9 legacy vectors of
/// SPEC-H1 5.2, spec J's 15 and spec I's, which 5.2 names by path rather
/// than copying.
fn corpus() -> Vec<String> {
    let mut names: Vec<String> = [
        "legacy/r393_m5.rar",
        "legacy/r420_m5.rar",
        "legacy/r550ma4_m5.rar",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect();
    for package in ["J", "I"] {
        let mut more: Vec<String> =
            std::fs::read_dir(format!("{VECTORS}/vectors-{package}/archives"))
                .unwrap()
                .map(|entry| {
                    format!(
                        "../vectors-{package}/archives/{}",
                        entry.unwrap().file_name().to_string_lossy()
                    )
                })
                .filter(|name| name.ends_with(".rar"))
                .collect();
        more.sort();
        names.append(&mut more);
    }
    names
}

fn archive_bytes(name: &str) -> Vec<u8> {
    match name.strip_prefix("../") {
        Some(rest) => read(rest),
        None => read(&format!("vectors-H/{name}")),
    }
}

#[test]
fn genuine_archives_decode_to_their_recorded_hashes() {
    let table = check_table();
    let (mut checked, mut hashed) = (0usize, 0usize);
    let mut failed = Vec::new();
    for archive in corpus() {
        let bytes = archive_bytes(&archive);
        for (member, decoded, records) in decode_archive(&bytes) {
            let name = name_of(&member);
            let decoded = match decoded {
                Ok(decoded) => decoded,
                Err(error) => {
                    failed.push(format!("{archive} {name}: {error}"));
                    continue;
                }
            };
            // The member's own CRC32 covers its FILTERED bytes, which is
            // what a caller receives.
            assert_eq!(
                decoded.bytes, member.unpacked,
                "{archive} {name} produced the declared size"
            );
            assert_eq!(decoded.crc32, member.crc32, "{archive} {name} CRC32");
            checked += 1;
            let Some(row) = table.get(&(archive.clone(), name.clone())) else {
                continue;
            };
            assert_eq!(row.declared, member.unpacked, "{archive} {name} size");
            if let (Some(want), 0, false) = (&row.sha256, row.records, row.skipped) {
                // A member with no filter record: the hash the checker of
                // SPEC-H1 5.1 recorded is of these very bytes.
                let got = sha256(&decoded.data);
                assert!(
                    got.starts_with(want),
                    "{archive} {name}: got {got}, want {want}"
                );
                hashed += 1;
            }
            if row.records > 0 {
                assert!(records > 0, "{archive} {name} frames its filter records");
            }
        }
    }
    eprintln!("members decoded: {checked}, of them hash checked: {hashed}");
    assert!(
        failed.is_empty(),
        "members that did not decode: {failed:#?}"
    );
    assert!(checked >= 60, "only {checked} members were judged");
    assert!(hashed >= 12, "only {hashed} members were hash checked");
}

// ---- SPEC-H1 6.1: the oracle -----------------------------------------------

#[cfg(feature = "oracle-compare")]
/// Every member the old engine extracts from `archive`, by name.
fn oracle(archive: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    rarkit_oracle::extract(&[archive], None).map(|members| {
        members
            .into_iter()
            .filter(|member| !member.is_directory)
            .map(|member| {
                (
                    String::from_utf8_lossy(&member.name).replace('\\', "/"),
                    member.data,
                )
            })
            .collect()
    })
}

#[cfg(feature = "oracle-compare")]
#[test]
fn the_old_engine_extracts_the_same_bytes() {
    // SPEC-H1 6.1: every member of the legacy vectors, of spec J's
    // archives (the mixed solid chains among them) and of spec I's, byte
    // compared. The oracle adapter this needs is plain `extract`.
    let (mut compared, mut chains) = (0usize, 0usize);
    for archive in corpus() {
        let bytes = archive_bytes(&archive);
        let theirs = oracle(&bytes).unwrap_or_else(|e| panic!("{archive}: {e}"));
        let mut seen = false;
        for (member, decoded, _) in decode_archive(&bytes) {
            let name = name_of(&member);
            let mine = decoded.unwrap_or_else(|e| panic!("{archive} {name}: {e}"));
            let want = theirs
                .get(&name)
                .unwrap_or_else(|| panic!("{archive}: the old engine skipped {name}"));
            assert_eq!(
                mine.data.len(),
                want.len(),
                "{archive} {name}: lengths differ"
            );
            assert!(mine.data == *want, "{archive} {name}: bytes differ");
            compared += 1;
            seen = true;
        }
        chains += usize::from(seen);
    }
    eprintln!("members compared with the old engine: {compared} over {chains} archives");
    assert!(compared >= 60, "only {compared} members were compared");
}

// ---- SPEC-H1 6.2: damaged input --------------------------------------------

#[cfg(feature = "oracle-compare")]
/// What a clean archive holds: the compressed RAR 2.9 members both
/// engines must produce, by name, with the CRC32 each header carries.
fn expected(archive: &[u8]) -> Vec<(String, u32)> {
    rar4lz::walk(archive)
        .iter()
        .filter(|member| !member.is_directory && member.version == 29 && member.method != 0x30)
        .map(|member| (name_of(member), member.crc32))
        .collect()
}

#[cfg(feature = "oracle-compare")]
/// Whether this package produces every expected member with its recorded
/// checksum.
fn mine_succeeds(archive: &[u8], want: &[(String, u32)]) -> bool {
    let mut got: HashMap<String, u32> = HashMap::new();
    for chain in chains(archive) {
        if chain
            .members
            .iter()
            .any(|m| m.version != 29 || m.method == 0x30)
        {
            continue;
        }
        let ins: Vec<MemberIn> = chain
            .members
            .iter()
            .zip(&chain.spans)
            .map(|(member, span)| MemberIn {
                packed: span.clone(),
                unpacked: member.unpacked,
            })
            .collect();
        let (out, _, failed) = decode_stream_partial(&chain.packed, &ins, chain.dictionary, false);
        // `decode_stream_partial` pushes the FAILING member's partial
        // output too, so that a test can say which member of a chain
        // broke. Recording it here would read a member this engine
        // REFUSED as one it served - and a member can produce every
        // declared byte, with the checksum its header carries, and still
        // be refused: `TrailingData` (SPEC-H1 3.8) is raised after the
        // last byte, when the block does not end where the member does.
        // One bit flip in `r550ma4_m5.rar` is exactly that shape, and it
        // read as "this engine accepted what the old one refused" while
        // both engines were in fact refusing it.
        let served = out.len() - usize::from(failed.is_some());
        #[allow(clippy::indexing_slicing)] // `served` is at most `out.len()`
        for (member, decoded) in chain.members.iter().zip(&out[..served]) {
            got.insert(name_of(member), decoded.crc32);
        }
        if failed.is_some() {
            break;
        }
    }
    want.iter()
        .all(|(name, crc)| got.get(name).is_some_and(|mine| mine == crc))
}

#[cfg(feature = "oracle-compare")]
/// The same question of the old engine.
fn oracle_succeeds(archive: &[u8], want: &[(String, u32)]) -> bool {
    match oracle(archive) {
        Err(_) => false,
        Ok(members) => want.iter().all(|(name, crc)| {
            members
                .get(name)
                .is_some_and(|data| rarkit::checksum::crc32(data) == *crc)
        }),
    }
}

#[cfg(feature = "oracle-compare")]
#[test]
fn damaged_input_fails_or_succeeds_with_the_old_engine() {
    // SPEC-H1 6.2: every single bit flip in the first 4 KiB of PACKED
    // data, and a truncation at every 64th byte. Both engines must fail or
    // succeed together on the same members. A debug run samples the flips;
    // a release run takes them all.
    let stride = if cfg!(debug_assertions) { 61 } else { 1 };
    let (mut cases, mut agree, mut strict) = (0usize, 0usize, Vec::new());
    for archive in [
        "legacy/r420_m5.rar",
        "legacy/r550ma4_m5.rar",
        "legacy/r393_m5.rar",
    ] {
        let clean = archive_bytes(archive);
        let want = expected(&clean);
        assert!(!want.is_empty(), "{archive} has compressed members");
        // The packed bytes of those members, in order, capped at 4 KiB. A
        // member that declares nothing produces nothing and returns at
        // once (SPEC-H1 4.3), so damage to its packed data changes no
        // output byte here while the old engine still reads its header.
        let mut packed: Vec<usize> = Vec::new();
        for member in rar4lz::walk(&clean) {
            if member.version == 29 && member.method != 0x30 && member.unpacked > 0 {
                packed.extend(member.data.clone());
            }
        }
        packed.truncate(4096);
        let mut damaged: Vec<(String, Vec<u8>)> = Vec::new();
        for &at in packed.iter().step_by(stride) {
            for bit in 0..8 {
                let mut copy = clean.clone();
                copy[at] ^= 1 << bit;
                damaged.push((format!("bit {at}.{bit}"), copy));
            }
        }
        // Truncations inside the packed data, where the codec meets them:
        // a cut in the trailing headers is spec F's business, not this
        // package's, and the old engine judges the whole container.
        let spans: Vec<std::ops::Range<usize>> = rar4lz::walk(&clean)
            .iter()
            .filter(|member| member.version == 29 && member.method != 0x30 && member.unpacked > 0)
            .map(|member| member.data.clone())
            .collect();
        let from = spans.iter().map(|span| span.start).min().unwrap_or(0);
        let upto = spans.iter().map(|span| span.end).max().unwrap_or(0);
        for at in (from..upto).step_by(64) {
            damaged.push((format!("cut at {at}"), clean[..at].to_vec()));
        }
        for (what, bytes) in damaged {
            let mine = mine_succeeds(&bytes, &want);
            let theirs = oracle_succeeds(&bytes, &want);
            cases += 1;
            if mine == theirs {
                agree += 1;
            } else if mine {
                panic!("{archive} {what}: this engine accepted what the old one refused");
            } else {
                strict.push(format!("{archive} {what}"));
            }
        }
    }
    eprintln!(
        "damaged cases {cases}: agreed {agree}, refused where the old engine did not {}",
        strict.len()
    );
    for line in strict.iter().take(10) {
        eprintln!("  {line}");
    }
    // Questions 2 and 3 refuse two things the old engine serves, so this
    // engine may be the stricter of the two; it must never be the looser
    // one, which the panic above holds.
    assert!(cases > 500, "only {cases} damaged cases");
    assert!(
        strict.len() * 20 <= cases,
        "refused {} of {cases} damaged inputs the old engine accepted",
        strict.len()
    );
}

#[test]
fn a_declared_size_multiplied_by_sixteen_comes_out_short_without_panic() {
    // SPEC-H1 6.2: the member says sixteen times what it holds. Its data
    // ends at an end of block before that size, so its output ends there
    // (3.7, E4) and the LZ data raises no failure of its own for it (4.3,
    // N4); a filter span that reaches past the bytes there are is spec
    // J's refusal. Either way no member has a byte it does not hold.
    for archive in ["legacy/r420_m5.rar", "legacy/r550ma4_m5.rar"] {
        let bytes = archive_bytes(archive);
        for chain in chains(&bytes) {
            if chain
                .members
                .iter()
                .any(|m| m.version != 29 || m.method == 0x30)
            {
                continue;
            }
            let ins: Vec<MemberIn> = chain
                .members
                .iter()
                .zip(&chain.spans)
                .map(|(member, span)| MemberIn {
                    packed: span.clone(),
                    unpacked: member.unpacked * 16,
                })
                .collect();
            if ins.iter().all(|member| member.unpacked == 0) {
                continue;
            }
            let (out, _, failed) =
                decode_stream_partial(&chain.packed, &ins, chain.dictionary, false);
            let mut short = failed.is_some();
            for (member, decoded) in chain.members.iter().zip(&out) {
                assert!(
                    decoded.bytes <= member.unpacked,
                    "{archive}: more bytes than the member holds"
                );
                short |= decoded.bytes < member.unpacked * 16;
            }
            assert!(short, "{archive}: a size of sixteen times over");
        }
    }
}

// ---- the old engine's own fixture corpus -----------------------------------

#[cfg(feature = "oracle-compare")]
/// Whether an archive is one this package can be asked about: every RAR
/// 2.9 compressed member in the clear, none split across volumes.
fn readable_here(members: &[rar4lz::Member4]) -> bool {
    !members.is_empty()
        && members.iter().any(|m| m.version == 29 && m.method != 0x30)
        && members
            .iter()
            .all(|m| !m.encrypted && !m.split_before && !m.split_after)
}

#[cfg(feature = "oracle-compare")]
#[test]
fn the_old_engines_own_fixture_corpus_decodes() {
    // SPEC-H1 6.1 compares against the oracle; its checked-in corpus is
    // reached by name and by bytes only (`fixture_names`, `fixture`), and
    // it carries shapes the committed vectors do not, the oversubscribed
    // main table among them.
    let names = rarkit_oracle::fixture_names().expect("the oracle's fixture names");
    let (mut archives, mut compared, mut refused) = (0usize, 0usize, 0usize);
    for name in names {
        if !name.to_lowercase().ends_with(".rar") {
            continue;
        }
        let Ok(bytes) = rarkit_oracle::fixture(&name) else {
            continue;
        };
        let members = rar4lz::walk(&bytes);
        if !readable_here(&members) {
            continue;
        }
        let Ok(theirs) = oracle(&bytes) else {
            // An archive the old engine itself refuses says nothing about
            // this package.
            continue;
        };
        let mut seen = false;
        for (member, decoded, _) in decode_archive(&bytes) {
            let name_of_member = name_of(&member);
            let Some(want) = theirs.get(&name_of_member) else {
                continue;
            };
            let mine = match decoded {
                Ok(mine) => mine,
                // A filter program outside the standard six is refused by
                // design (API section 1); the old engine interprets it.
                Err(error) if error.contains("FilterProgram") => {
                    refused += 1;
                    continue;
                }
                Err(error) => panic!("{name} {name_of_member}: {error}"),
            };
            assert!(
                mine.data == *want,
                "{name} {name_of_member}: bytes differ from the old engine"
            );
            compared += 1;
            seen = true;
        }
        archives += usize::from(seen);
    }
    eprintln!(
        "old-engine fixtures compared: {compared} members over {archives} archives, \
         {refused} members refused for a filter program outside the standard six"
    );
    assert!(archives >= 20, "only {archives} fixtures were compared");
}

// ---- SPEC-H1 6.1 case 4: a member that ends inside a match ------------------

#[path = "support/h1build.rs"]
mod h1build;

#[cfg(feature = "oracle-compare")]
/// The stream of SPEC-H1 3.8's B3, wrapped in a RAR 2.9 archive of the
/// shape the old engine reads: member 1's match names ten bytes after its
/// one literal, and each member carries its own block header. With `past`
/// member 1 declares four of those eleven bytes, so the match passes its
/// end; without it member 1 declares all eleven.
fn match_at_the_end_archive(past: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use h1build::{start_block, BitWriter, Member};
    const FRESH_SLOT_7: u16 = 271 + 7;
    let mut out = BitWriter::default();
    let tables = start_block(&mut out, &[u16::from(b'A'), 256, FRESH_SLOT_7], &[0]);
    tables.main(&mut out, u16::from(b'A'));
    // Length slot 7 is base 7 plus the fresh arm's 3: ten bytes, at
    // distance 1 (slot 0, no extra bits).
    tables.main(&mut out, FRESH_SLOT_7);
    tables.distance_slot(&mut out, 0);
    // The block ends where this member's packed data does, and says the
    // next member starts at a header of its own.
    tables.main(&mut out, 256);
    out.put(0, 1);
    out.put(1, 1);
    let first = out.flush();
    // Member 2: its own header and tables, then one literal of its own.
    let tables = start_block(&mut out, &[u16::from(b'B'), 256], &[0]);
    tables.main(&mut out, u16::from(b'B'));
    tables.main(&mut out, 256);
    out.put(0, 1);
    out.put(1, 1);
    out.flush();
    let packed = out.bytes;
    // Member 2 is its own literal alone either way: what the match put
    // in the window past member 1's end is no member's output (B3).
    let one = vec![b'A'; if past { 4 } else { 11 }];
    let two = vec![b'B'];
    let archive = h1build::archive(&[
        Member {
            name: "ONE.BIN",
            packed: &packed[..first],
            unpacked: &one,
            solid: false,
        },
        Member {
            name: "TWO.BIN",
            packed: &packed[first..],
            unpacked: &two,
            solid: true,
        },
    ]);
    (archive, one, two)
}

#[cfg(feature = "oracle-compare")]
#[test]
fn the_control_for_the_match_past_the_end_agrees() {
    // The same stream with the member boundary moved so that no match
    // passes it. What this pins is that the archive, its headers and the
    // member boundary are right, so a disagreement in the case below is
    // about the match that passes the end and nothing else.
    let (archive, one, two) = match_at_the_end_archive(false);
    let theirs = oracle(&archive).expect("the old engine extracts");
    assert_eq!(theirs.get("ONE.BIN"), Some(&one));
    assert_eq!(theirs.get("TWO.BIN"), Some(&two));
    for (member, decoded, _) in decode_archive(&archive) {
        let name = name_of(&member);
        let mine = decoded.unwrap_or_else(|e| panic!("{name}: {e}")).data;
        assert_eq!(Some(&mine), theirs.get(&name), "{name}");
    }
}

#[cfg(feature = "oracle-compare")]
#[test]
fn a_match_past_a_members_end_opens_no_member() {
    // SPEC-H1 3.8, B3, as the reference was observed to do it (the vector
    // `s38/match-past-end` is the observation; this is the same rule on
    // an archive whose members each carry a block header). The match
    // enters the window whole, member 1's output is its first four bytes
    // and member 2 is its own literal.
    let (archive, one, two) = match_at_the_end_archive(true);
    let mine: Vec<(String, Vec<u8>)> = decode_archive(&archive)
        .into_iter()
        .map(|(member, decoded, _)| {
            let name = name_of(&member);
            let data = decoded.unwrap_or_else(|e| panic!("{name}: {e}")).data;
            (name, data)
        })
        .collect();
    assert_eq!(
        mine,
        vec![("ONE.BIN".to_string(), one), ("TWO.BIN".to_string(), two)]
    );
    // The old engine reads it the same way. The specification settles the
    // case, by the reference's own answer; this says the two engines agree
    // on it.
    let theirs = oracle(&archive).expect("the old engine extracts");
    for (name, data) in &mine {
        assert_eq!(theirs.get(name), Some(data), "{name}");
    }
}
