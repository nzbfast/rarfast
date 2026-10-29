//! A member whose header declares MORE bytes than its data yields, on the
//! specification's own archives (SPEC-F 4.2, "A member that ends short",
//! as restated on 8 Oct 2026; bug sweep item SWEEP2-08OCT-29).
//!
//! `specs/vectors-F/declared-long` holds genuine RAR 5 archives with one
//! member's declared size raised by 1 or by 5,000 and nothing else
//! changed (`.kept.`), and the same with that member's checksum field
//! removed as well (`.none.`), beside the answers of rar 7.23 and unrar
//! 7.23. The rule:
//!
//! - the bytes produced are delivered, in order;
//! - a member that carries a checksum is judged by it against those
//!   bytes: here it matches, so the member is GOOD with fewer bytes than
//!   it declares, as the reference reports it, and `MemberOutcome::bytes`
//!   says how many;
//! - a member that carries NO checksum and ends short FAILS: the chosen
//!   difference, where the reference does not judge the member and exits
//!   0, because nothing vouches for the short file;
//! - the chain goes on: every other member is good, before it and after.
//!
//! Before the rule was restated a short member was never good, and a
//! reader failed a member the reference extracts whole.
//!
//! Stored and `-m3` members, alone and in a solid chain, with a CRC32 and
//! with a BLAKE2sp hash. Read at the default width, at one worker and by
//! `extract_parallel` at two; every archive is under 4 KiB.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Sink,
};

fn vector(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/declared-long/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// One member as it closed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Came {
    name: String,
    data: Vec<u8>,
    checksum_ok: Option<bool>,
    bytes: u64,
    declared: Option<u64>,
}

#[derive(Default)]
struct Keep(Mutex<Vec<Came>>);

impl Keep {
    fn closed(&self, member: &MemberInfo<'_>, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.0.lock().expect("lock").push(Came {
            name: member.name_lossy().into_owned(),
            data: out.unwrap_or_default(),
            checksum_ok: outcome.checksum_ok,
            bytes: outcome.bytes,
            declared: member.unpacked_size,
        });
    }
}

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
        self.closed(member, out, outcome);
        Ok(())
    }
}

impl ParallelSink for Keep {
    type Out = Vec<u8>;

    fn open(&self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed(member, out, outcome);
        Ok(())
    }
}

/// Every read path over one archive, labelled: the members by name and
/// whether the operation ended in an error.
fn every_path(bytes: &[u8]) -> Vec<(String, Vec<Came>, bool)> {
    let source = || -> Vec<Arc<dyn RangeSource>> { vec![Arc::new(bytes.to_vec())] };
    let sorted = |keep: Keep| {
        let mut came = keep.0.into_inner().expect("lock");
        came.sort_by(|a, b| a.name.cmp(&b.name));
        came
    };
    let mut reads = Vec::new();
    for workers in [None, Some(1)] {
        let mut keep = Keep::default();
        let options = ReadOptions::default().with_workers(workers);
        let failed = extract(source(), &options, &mut keep, &mut ()).is_err();
        reads.push((format!("workers {workers:?}"), sorted(keep), failed));
    }
    let keep = Keep::default();
    let failed = extract_parallel(source(), &ReadOptions::default(), &keep, 2).is_err();
    reads.push(("extract_parallel, 2 wide".to_owned(), sorted(keep), failed));
    reads
}

/// One row of the reference's answers that has an archive kept here.
struct Arm {
    file: String,
    member: String,
    true_size: u64,
    declares: u64,
    kept: bool,
}

fn arms() -> Vec<Arm> {
    let text = String::from_utf8(vector("outcomes-unrar-7.23-macos-arm64.tsv")).expect("text");
    let mut arms = Vec::new();
    for line in text.lines().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        let (archive, member) = (cells[1], cells[2]);
        let true_size: u64 = cells[4].parse().expect("a size");
        let declares: u64 = cells[5].parse().expect("a size");
        let file = format!(
            "{archive}.{member}.plus-{}.{}.rar",
            declares - true_size,
            cells[6]
        );
        let path = format!(
            "{}/../../specs/vectors-F/declared-long/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        if !std::path::Path::new(&path).exists() {
            // Over 4 KiB: the probe makes it again, it is not kept.
            continue;
        }
        // The reference's own answer for the rows read here: exit 0, the
        // member written with its true size and its true bytes.
        assert_eq!((cells[7], cells[8]), ("0", "0"), "{file}");
        assert_eq!(cells[10], cells[4], "{file}");
        assert_eq!(cells[11], "true", "{file}");
        arms.push(Arm {
            file,
            member: member.to_owned(),
            true_size,
            declares,
            kept: cells[6] == "kept",
        });
    }
    arms
}

#[test]
fn a_member_declared_too_long_is_judged_by_its_checksum_and_fails_without_one() {
    let arms = arms();
    assert_eq!(arms.len(), 18, "the RAR 5 arms kept under 4 KiB");
    assert_eq!(arms.iter().filter(|arm| arm.kept).count(), 10);
    // The member's true bytes: its untouched twin does not exist here, so
    // they are the bytes of the same member in an arm whose checksum
    // vouches for them, taken once the arm is seen to be good.
    let mut truth: Vec<(String, u64, Vec<u8>)> = Vec::new();
    for arm in arms.iter().filter(|arm| arm.kept) {
        for (path, came, failed) in every_path(&vector(&arm.file)) {
            let case = format!("{}, {path}", arm.file);
            assert!(!failed, "{case}: the operation ended in an error");
            for member in &came {
                assert_eq!(member.checksum_ok, Some(true), "{case}: {}", member.name);
                assert_eq!(member.bytes, member.data.len() as u64, "{case}");
            }
            let altered = came
                .iter()
                .find(|member| member.name == arm.member)
                .unwrap_or_else(|| panic!("{case}: no member {}", arm.member));
            assert_eq!(altered.declared, Some(arm.declares), "{case}");
            assert_eq!(altered.bytes, arm.true_size, "{case}");
            let key = (arm.member.clone(), arm.true_size);
            match truth
                .iter()
                .find(|(name, size, _)| (name, size) == (&key.0, &key.1))
            {
                Some((_, _, bytes)) => assert_eq!(&altered.data, bytes, "{case}"),
                None => truth.push((key.0, key.1, altered.data.clone())),
            }
        }
    }
    for arm in arms.iter().filter(|arm| !arm.kept) {
        for (path, came, failed) in every_path(&vector(&arm.file)) {
            let case = format!("{}, {path}", arm.file);
            // The failure is the member's verdict. A compressed member's
            // decoder also names the short end, which ends the read in
            // that error; a stored member has no decoder and no name.
            assert_eq!(
                failed,
                arm.file.starts_with("f03") || arm.file.starts_with("f04"),
                "{case}"
            );
            for member in &came {
                if member.name == arm.member {
                    // Its bytes are delivered and it is not good.
                    assert_eq!(member.checksum_ok, Some(false), "{case}");
                    assert_eq!(member.bytes, arm.true_size, "{case}");
                    let (_, _, bytes) = truth
                        .iter()
                        .find(|(name, size, _)| (name, size) == (&arm.member, &arm.true_size))
                        .expect("the kept arm of the same member");
                    assert_eq!(&member.data, bytes, "{case}");
                } else {
                    // The chain goes on.
                    assert_eq!(member.checksum_ok, Some(true), "{case}: {}", member.name);
                }
            }
            assert!(
                came.iter().any(|member| member.name == arm.member),
                "{case}"
            );
        }
    }
}
