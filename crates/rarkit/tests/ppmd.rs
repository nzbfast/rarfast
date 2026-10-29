//! Spec I's vectors, its differential plan and its derived unit vectors.
//!
//! Spec H's RAR 3 LZ decoder does not exist yet, so a member that is not
//! PPM from its first block is listed and not decoded; the
//! manifest's `packed_read` column of `-` marks exactly those.

#[path = "support/rar4ppm.rs"]
mod rar4ppm;

use std::collections::BTreeMap;
use std::path::PathBuf;

use rarkit::internals::ppmd::{decode_ppm_run, MemberIn};
use sha2::{Digest, Sha256};

/// A generous ceiling: only a header's own memory byte should ever decide.
const LIMIT: u64 = 512 << 20;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors-I")
}

#[derive(Debug, Clone)]
struct Row {
    archive: String,
    committed: bool,
    member: String,
    unpacked: u64,
    output_sha256: String,
    block_head: String,
    model_starts: Option<u64>,
    packed_read: Option<usize>,
}

/// The manifest, grouped by archive and kept in file order.
fn manifest() -> Vec<(String, Vec<Row>)> {
    let text = std::fs::read_to_string(vectors().join("MANIFEST.tsv")).expect("MANIFEST.tsv");
    let mut order: Vec<String> = Vec::new();
    let mut by_archive: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 13 {
            continue;
        }
        let row = Row {
            archive: f[0].to_owned(),
            committed: f[3] == "y",
            member: f[5].to_owned(),
            unpacked: f[6].parse().unwrap_or(0),
            output_sha256: f[7].to_owned(),
            block_head: f[8].to_owned(),
            model_starts: f[10].parse().ok(),
            packed_read: f[11].parse().ok(),
        };
        if !order.contains(&row.archive) {
            order.push(row.archive.clone());
        }
        by_archive.entry(row.archive.clone()).or_default().push(row);
    }
    order
        .into_iter()
        .map(|a| {
            let rows = by_archive.remove(&a).unwrap();
            (a, rows)
        })
        .collect()
}

fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What [`in_scope`] found: the members to decode, the rows and CRC32s they
/// answer, whether the run is solid, and what was left to spec H.
type Scope<'a> = (
    Vec<MemberIn<'a>>,
    Vec<(Row, u32)>,
    bool,
    Vec<(String, String)>,
);

/// The members of one archive this package can decode: the leading run that
/// is PPM from its own first block.
fn in_scope<'a>(arc: &'a [u8], rows: &[Row]) -> Scope<'a> {
    let frags = rar4ppm::walk4(arc);
    assert_eq!(frags.len(), rows.len(), "manifest and archive disagree");
    let solid = frags.iter().any(|f| f.solid);
    let (mut members, mut answered, mut owed) = (Vec::new(), Vec::new(), Vec::new());
    for (frag, row) in frags.iter().zip(rows) {
        assert_eq!(frag.name, row.member.as_bytes(), "member order");
        assert_eq!(frag.unpacked, row.unpacked, "declared size");
        if row.packed_read.is_none() {
            if row.unpacked == 0 {
                // An empty member holds no PPM block and touches nothing.
                continue;
            }
            owed.push((row.archive.clone(), row.member.clone()));
            break;
        }
        assert_eq!(frag.version, 29, "spec I decodes unpack version 29");
        members.push(MemberIn {
            packed: &arc[frag.data.clone()],
            unpacked: frag.unpacked,
        });
        answered.push((row.clone(), frag.crc32));
    }
    (members, answered, solid, owed)
}

/// Differential test 1 (spec I section 6): every committed vector, every
/// member, byte-exact against the manifest, with `packed_read` and the
/// member's own CRC32 checked too.
#[test]
fn vectors_are_byte_exact() {
    let (mut checked, mut owed) = (0usize, Vec::new());
    for (archive, rows) in manifest() {
        if !rows[0].committed {
            continue;
        }
        let path = vectors().join("archives").join(&archive);
        let arc = std::fs::read(&path).expect("committed archive");
        let (members, answered, solid, left) = in_scope(&arc, &rows);
        owed.extend(left);
        if members.is_empty() {
            continue;
        }
        let run =
            decode_ppm_run(&members, solid, LIMIT).unwrap_or_else(|e| panic!("{archive}: {e}"));
        assert_eq!(run.members.len(), answered.len());
        for (got, (row, crc)) in run.members.iter().zip(&answered) {
            assert_eq!(
                sha256(&got.data),
                row.output_sha256,
                "{archive} {} output",
                row.member
            );
            assert_eq!(
                got.data.len() as u64,
                row.unpacked,
                "{archive} {} size",
                row.member
            );
            assert_eq!(
                crc32fast::hash(&got.data),
                *crc,
                "{archive} {} CRC32",
                row.member
            );
            assert_eq!(
                got.packed_read,
                row.packed_read.unwrap(),
                "{archive} {} packed_read",
                row.member
            );
            checked += 1;
        }
        // Differential test 2: the model starts the manifest counted. The
        // column is per member for a non-solid archive and cumulative for a
        // solid one, so compare the total.
        let want: u64 = answered.iter().filter_map(|(r, _)| r.model_starts).sum();
        assert_eq!(run.model_starts, want, "{archive} model starts");
    }
    println!(
        "{checked} members decoded byte-exact from {} committed archives",
        manifest()
            .iter()
            .filter(|(a, r)| r[0].committed && std::path::Path::new(a).extension().is_some())
            .count()
    );
    assert!(checked >= 25, "only {checked} members checked");
    if !owed.is_empty() {
        println!("left to spec H (member not PPM from its first block): {owed:?}");
    }
}

/// The block header bytes the manifest records, read back through spec I
/// section 3.2 (order map, memory byte, escape byte).
#[test]
fn block_headers_read_as_the_spec_says() {
    for (archive, rows) in manifest() {
        for row in &rows {
            if row.block_head.len() != 6 || row.packed_read.is_none() {
                continue;
            }
            let head = u8::from_str_radix(&row.block_head[..2], 16).unwrap();
            assert_eq!(head & 0x80, 0x80, "{archive} {} is a PPM block", row.member);
            let starting = head & 0x20 != 0;
            let code = u32::from(head & 0x1f) + 1;
            let order = if code <= 16 {
                code
            } else {
                16 + 3 * (code - 16)
            };
            assert!((2..=64).contains(&order), "{archive} order {order}");
            if starting {
                // `h, m, e`: the memory byte before the escape byte.
                let m = u8::from_str_radix(&row.block_head[2..4], 16).unwrap();
                let size = (u64::from(m) + 1) << 20;
                assert!(((1 << 20)..=(256 << 20)).contains(&size));
            } else {
                assert_eq!(head & 0x40, 0, "a continuing header carries no escape");
            }
        }
    }
    // The documented order sweep: `-mc<o>` maps to the header byte the
    // manifest recorded, and back to `o` for `o <= 16`.
    let rows = manifest();
    for (archive, r) in &rows {
        let Some(rest) = archive.strip_prefix("sweep_o") else {
            continue;
        };
        let asked: u32 = rest.trim_end_matches(".rar").parse().unwrap();
        let head = u8::from_str_radix(&r[0].block_head[..2], 16).unwrap();
        let code = u32::from(head & 0x1f) + 1;
        let order = if code <= 16 {
            code
        } else {
            16 + 3 * (code - 16)
        };
        if asked == 1 {
            assert_eq!(order, 8, "an order-1 request gets rar's default");
        } else if asked <= 16 {
            assert_eq!(order, asked, "{archive}");
        } else {
            // rar documents -mc2 to -mc63; 64 is clamped to 63.
            let asked = asked.min(63);
            assert_eq!(code, 16 + (asked - 16) / 3, "{archive}");
            assert!(order <= asked && asked - order < 3, "{archive}");
        }
    }
}

/// The derived unit vectors of spec I section 5: the start state.
#[test]
fn model_start_state_is_derived_from_order_and_size() {
    // `units_floor = B + S - 84 * floor(S / 96)`, with B = 4.
    let s: u64 = 1 << 20;
    assert_eq!(4 + s - 84 * (s / 96), 4 + 131_128);
    // `P[0][0] = 16,384 - floor(0x3CDD / 2)`.
    assert_eq!(16_384 - 0x3CDDu32 / 2, 8_594);
    // `Q[24][15].sum = (5 * 24 + 10) * 8`.
    assert_eq!((5 * 24 + 10) * 8, 1_040);
}

#[cfg(feature = "oracle-compare")]
/// Every committed vector, decoded by this package and by the old engine
/// through `rarkit-oracle`, member by member (spec I section 6, oracles).
#[test]
fn the_old_engine_decodes_the_same_bytes() {
    let mut compared = 0usize;
    for (archive, rows) in manifest() {
        if !rows[0].committed {
            continue;
        }
        let arc = std::fs::read(vectors().join("archives").join(&archive)).expect("archive");
        let (members, answered, solid, _) = in_scope(&arc, &rows);
        if members.is_empty() {
            continue;
        }
        let run = decode_ppm_run(&members, solid, LIMIT).expect("decodes");
        let old = rarkit_oracle::extract(&[&arc], None).expect("the old engine extracts");
        for (got, (row, _)) in run.members.iter().zip(&answered) {
            let theirs = old
                .iter()
                .find(|m| m.name == row.member.as_bytes())
                .unwrap_or_else(|| panic!("{archive}: the old engine skipped {}", row.member));
            assert_eq!(
                got.data, theirs.data,
                "{archive} {} differs from the old engine",
                row.member
            );
            compared += 1;
        }
    }
    assert!(compared >= 20, "only {compared} members compared");
}

#[cfg(feature = "oracle-compare")]
/// This package's verdict on a whole archive: every in-scope member decoded
/// and checked against its own CRC32.
fn ours(arc: &[u8], rows: &[Row]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let (members, answered, solid, _) = in_scope(arc, rows);
    let run = decode_ppm_run(&members, solid, LIMIT).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (got, (row, crc)) in run.members.iter().zip(&answered) {
        if crc32fast::hash(&got.data) != *crc {
            return Err(format!("{} checksum", row.member));
        }
        out.push((row.member.clone(), got.data.clone()));
    }
    Ok(out)
}

#[cfg(feature = "oracle-compare")]
/// Differential test 3 (spec I section 6): one flipped byte at a time must
/// not panic, must end in bounded time, and should agree with the old
/// engine on ok-versus-error. Disagreements are listed, not failed: the old
/// engine's checks are not all the same as section 3's.
#[test]
fn a_flipped_byte_never_panics_and_is_judged_like_the_old_engine() {
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let mut rng = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut tried, mut agreed, mut disagreed, mut both_ok) = (0usize, 0usize, 0usize, 0usize);
    let mut notes: Vec<String> = Vec::new();
    for (archive, rows) in manifest() {
        if !rows[0].committed {
            continue;
        }
        let arc = std::fs::read(vectors().join("archives").join(&archive)).expect("archive");
        // Only archives this package can answer whole are comparable.
        if rows
            .iter()
            .any(|r| r.packed_read.is_none() && r.unpacked > 0)
        {
            continue;
        }
        if ours(&arc, &rows).is_err() {
            panic!("{archive} does not decode clean");
        }
        // Only packed bytes: a flipped header byte is spec F's business,
        // not this package's.
        let packed: Vec<usize> = rar4ppm::walk4(&arc)
            .iter()
            .flat_map(|f| f.data.clone())
            .collect();
        let mut sites: Vec<usize> = packed.iter().copied().take(64).collect();
        if packed.len() > 64 {
            for _ in 0..64 {
                sites.push(packed[64 + rng() as usize % (packed.len() - 64)]);
            }
        }
        for at in sites {
            let mut bad = arc.clone();
            bad[at] ^= 1 << (rng() % 8);
            if bad == arc {
                continue;
            }
            tried += 1;
            let mine = ours(&bad, &rows);
            let theirs = rarkit_oracle::extract(&[&bad], None);
            match (mine.is_ok(), theirs.is_ok()) {
                (true, true) => {
                    both_ok += 1;
                    agreed += 1;
                    let mine = mine.unwrap();
                    let theirs = theirs.unwrap();
                    for (name, data) in &mine {
                        let other = theirs.iter().find(|m| m.name == name.as_bytes());
                        if let Some(other) = other {
                            assert_eq!(
                                data, &other.data,
                                "{archive} at {at}: a mutant both engines accept differs"
                            );
                        }
                    }
                }
                (a, b) if a == b => agreed += 1,
                _ => {
                    disagreed += 1;
                    if notes.len() < 12 {
                        notes.push(format!(
                            "{archive} byte {at}: rarkit ok={}, old ok={}",
                            mine.is_ok(),
                            theirs.is_ok()
                        ));
                    }
                }
            }
        }
    }
    // Reviewed on 18 Sep 2026: every disagreement seen on this corpus is
    // at the member end, where spec I 3.3's check is tagged [OLD] and the
    // reference's reaction is unobserved - the old engine sometimes stops
    // at the declared size without demanding the escape byte then 0 or 2 -
    // or inside the one LZ member this package leaves to spec H.
    println!(
        "mutation differential: {tried} mutants, {agreed} agreed ({both_ok} both ok), \
         {disagreed} disagreed"
    );
    for note in &notes {
        println!("  {note}");
    }
    assert!(tried > 1_000, "only {tried} mutants tried");
    assert!(
        disagreed * 100 <= tried * 5,
        "{disagreed} of {tried} mutants disagreed with the old engine"
    );
}

/// Spec I 3.2 and 4.1: the header's own refusals.
#[test]
fn a_block_header_refuses_what_the_spec_says_it_must() {
    use rarkit::{Corruption, ErrorKind, PpmFault, Resource};
    let fault = |bytes: &[u8], limit: u64| -> PpmFault {
        match rarkit::internals::ppmd::begin_block_only(bytes, limit, 0)
            .expect_err("refused")
            .kind()
        {
            ErrorKind::Corrupt(Corruption::Ppmd(f)) => *f,
            other => panic!("{other:?}"),
        }
    };
    // Order code 0 is order 1, which the model cannot hold.
    assert_eq!(fault(&[0xA0, 0x00, 1, 2, 3, 4], LIMIT), PpmFault::BadOrder);
    // A continuing header with no model to continue.
    assert_eq!(fault(&[0x87, 1, 2, 3, 4], LIMIT), PpmFault::NoModel);
    // The range decoder's four bytes must be there.
    assert!(matches!(
        rarkit::internals::ppmd::begin_block_only(&[0xE7, 0x00, 0xFF, 1, 2], LIMIT, 0)
            .expect_err("truncated")
            .kind(),
        ErrorKind::Truncated
    ));
    // Spec I 4.2: the arena is judged before it is allocated, and the
    // resource named is the text model (open question 2, recommended).
    let head = [0xE7u8, 0xFF, 0xFF, 1, 2, 3, 4];
    let refusal =
        rarkit::internals::ppmd::begin_block_only(&head, 8 << 20, 0).expect_err("over the limit");
    let ErrorKind::LimitExceeded {
        resource,
        needed,
        limit,
    } = refusal.kind()
    else {
        panic!("wanted a LimitExceeded, got {:?}", refusal.kind());
    };
    assert_eq!(*resource, Resource::TextModel);
    assert_eq!(*needed, (256 << 20) + 84 * 1024);
    assert_eq!(*limit, 8 << 20);
    // A hostile 256 MiB model under a limit that allows it: exactly
    // `S + 84 KiB`, and not a byte more.
    let held = rarkit::internals::ppmd::begin_block_only(&head, u64::MAX, 0).expect("accepted");
    assert!(held <= (256u64 << 20) + 84 * 1024, "held {held}");
    assert!(held > 256u64 << 20, "the arena is really there");
    // The window's share counts against the same limit.
    assert!(rarkit::internals::ppmd::begin_block_only(&head, (256 << 20) + 84 * 1024, 1).is_err());
}

/// Spec I 3.6 and 4.4: a damaged binary decision faults, and does not take
/// the caller's process down with it.
///
/// One byte of a genuine RAR 3.93 PPMd archive, exclusive-or 0xA5, is
/// enough: the binary decision at spec I 3.7 path B reads `v >= 16,384`
/// and raises `RangeOutOfBounds`, the member is reported failed, and the
/// solid stream carries the same decoder into the next member. Before the
/// fix that fault left `range` shifted down by 14 bits, so the next binary
/// decision divided by zero and panicked. A library must answer untrusted
/// input with an error whatever the caller does next.
#[test]
fn a_damaged_binary_context_faults_instead_of_dividing_by_zero() {
    use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};
    use std::sync::Arc;

    #[derive(Default)]
    struct Count {
        failed: usize,
        closed: usize,
    }

    impl Sink for Count {
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
            _out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> rarkit::Result<()> {
            self.closed += 1;
            if outcome.checksum_ok == Some(false) {
                self.failed += 1;
            }
            Ok(())
        }
    }

    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives/r393_md.rar"
    ));
    let Ok(good) = std::fs::read(&path) else {
        eprintln!("fixtures/legacy is not in this checkout: skipped");
        return;
    };
    assert_eq!(good.len(), 59_135, "the fixture this recipe was made on");
    let mut bad = good.clone();
    bad[29_567] ^= 0xA5;

    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bad)];
    let mut sink = Count::default();
    let report = extract(sources, &ReadOptions::default(), &mut sink, &mut ());
    // Whether the damage is reported member by member or as one error of
    // the whole run is spec F's business; what this pins is that the run
    // ends, and says something went wrong.
    let failed = sink.failed;
    assert!(
        report.is_err() || failed > 0,
        "the damaged archive passed as sound"
    );
    assert!(sink.closed > 0, "the run never got to a member");

    // The same archive undamaged still extracts clean, so the byte, and
    // not the recipe, is what the decoder refuses.
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(good)];
    let mut sink = Count::default();
    let report = extract(sources, &ReadOptions::default(), &mut sink, &mut ());
    assert!(report.is_ok(), "the sound fixture: {report:?}");
    assert_eq!(sink.failed, 0, "the sound fixture had a failed member");
}

/// The same class, swept: every legacy fixture the RAR 3 and RAR 4 writers
/// made, damaged a byte at a time, extracted whole. Nothing here may panic.
///
/// Ignored because it is minutes of work and `make ci` already carries the
/// mutation differential of section 6 over the vectors; run it by hand
/// after any change to `ppmd/`:
///
/// ```text
/// cargo test -p rarkit --test ppmd -- --ignored --nocapture
/// ```
#[test]
#[ignore = "minutes: the whole legacy corpus, a byte at a time"]
fn a_mutation_sweep_of_the_legacy_fixtures_never_panics() {
    use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};
    use std::sync::Arc;

    #[derive(Default)]
    struct Drop_ {
        failed: usize,
    }

    impl Sink for Drop_ {
        type Out = Vec<u8>;

        fn open(&mut self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }

        fn close(
            &mut self,
            _member: &MemberInfo<'_>,
            _out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> rarkit::Result<()> {
            if outcome.checksum_ok == Some(false) {
                self.failed += 1;
            }
            Ok(())
        }
    }

    let corpus = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ));
    let Ok(dir) = std::fs::read_dir(&corpus) else {
        eprintln!("fixtures/legacy is not in this checkout: skipped");
        return;
    };
    let mut names: Vec<String> = dir
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rar") && !n.contains("_pw") && !n.contains("_hp"))
        .collect();
    names.sort();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rng = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut tried, mut clean) = (0usize, 0usize);
    for name in &names {
        let Ok(good) = std::fs::read(corpus.join(name)) else {
            continue;
        };
        if good.len() < 64 {
            continue;
        }
        for _ in 0..48 {
            let at = 20 + rng() as usize % (good.len() - 20);
            let mut bad = good.clone();
            bad[at] ^= 1 << (rng() % 8);
            let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bad)];
            let mut sink = Drop_::default();
            tried += 1;
            // The assertion is the absence of a panic and of a hang: an
            // error, or a clean extract of a damage the format tolerates,
            // are both fine answers.
            if extract(sources, &ReadOptions::default(), &mut sink, &mut ()).is_ok()
                && sink.failed == 0
            {
                clean += 1;
            }
        }
    }
    println!(
        "legacy mutation sweep: {} archives, {tried} mutants, {clean} extracted clean",
        names.len()
    );
    assert!(tried > 1_000, "only {tried} mutants tried");
}

/// Spec I 3.9.3 and 4.4: every pinned `ppm_member` seed answers, and none
/// of them panics.
///
/// `re-entry-after-fault-successor` is the 1,387 byte input the 20 Sep
/// 2026 campaign found three seconds after the target learned to carry on
/// past a member's fault. It raised `RangeOutOfBounds` in one member and
/// the next member's decode then read a successor as a context position:
/// `range start index 2,407,334,982 out of range for slice of length
/// 3,145,744`, in `Arena::unit_pair` by way of `Model::successors`. A
/// model that has faulted is no longer decoded from, so it now answers
/// with the fault it already raised.
#[test]
fn every_pinned_ppm_member_seed_answers_without_panicking() {
    let seeds = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/ppm_member"
    ));
    let Ok(dir) = std::fs::read_dir(&seeds) else {
        panic!("the pinned seeds are missing: {}", seeds.display());
    };
    let mut seen = 0;
    for entry in dir.flatten() {
        let Ok(data) = std::fs::read(entry.path()) else {
            continue;
        };
        seen += 1;
        // Either answer is sound; the assertion is that it returns at all.
        match rarkit::internals::ppmd::fuzz_ppm_member(&data) {
            Ok(produced) => println!("{:?}: {produced} bytes", entry.file_name()),
            Err(e) => println!("{:?}: {}", entry.file_name(), e),
        }
    }
    assert!(seen > 0, "no seed was read");
}
