//! Spec F 3.5.6 C4: which leading fragment fields are judged depends on
//! the CONTAINER. In RAR 5 every leading fragment's CRC32 field is judged,
//! `FFFFFFFF` and `00000000` included; `FFFFFFFF` is no checksum in the
//! older container alone.
//!
//! The four arms are the specification's own, under
//! `specs/vectors-F/evidence-06oct/volume-sets`, each a set of two volumes
//! in which `b.txt` crosses from the first to the second, with the
//! reference's answer beside it: its `packed data checksum error in volume`
//! line for the two RAR 5 arms and for a wrong field at version 29, no line
//! for `FFFFFFFF` at version 29, and in all four the member tested OK,
//! "All OK", exit 0. A disagreeing field is a diagnostic about the volume
//! (`fragment_mismatch`, `MemberOutcome::fragment_mismatches`) and never
//! the member's verdict.
//!
//! Each arm is read through the sequential driver at thread widths 1 and 4
//! and through the pool at widths 1, 2 and 4 (2 is the narrowest hosted
//! runner's), under both `SplitCheck` settings. Every volume is under
//! 1 KiB and is held in memory once: no test needs more than a few MiB
//! whatever the width.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result, Sink, SplitCheck,
};

fn set(name: &str) -> Vec<Arc<dyn RangeSource>> {
    ["x.part1.rar", "x.part2.rar"]
        .iter()
        .map(|volume| {
            let path = format!(
                "{}/../../specs/vectors-F/evidence-06oct/volume-sets/{name}/{volume}",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            Arc::new(bytes) as Arc<dyn RangeSource>
        })
        .collect()
}

/// What the sink was told: each `fragment_mismatch` call as (member,
/// volume), and each `close` as (member, checksum verdict, the count of
/// mismatches the outcome states).
#[derive(Default)]
struct Told {
    mismatches: Mutex<Vec<(String, u32)>>,
    closed: Mutex<Vec<(String, Option<bool>, u32)>>,
}

impl Told {
    fn mismatch(&self, member: &MemberInfo<'_>, volume: u32) {
        self.mismatches
            .lock()
            .expect("the sink's own lock")
            .push((member.name_lossy().into_owned(), volume));
    }

    fn close(&self, member: &MemberInfo<'_>, outcome: &MemberOutcome) {
        self.closed.lock().expect("the sink's own lock").push((
            member.name_lossy().into_owned(),
            outcome.checksum_ok,
            outcome.fragment_mismatches,
        ));
    }
}

impl Sink for Told {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        Told::close(self, member, outcome);
        Ok(())
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatch(member, volume);
        Ok(())
    }
}

impl ParallelSink for Told {
    type Out = Vec<u8>;

    fn open(&self, _: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        _: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        Told::close(self, member, outcome);
        Ok(())
    }

    fn fragment_mismatch(&self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatch(member, volume);
        Ok(())
    }
}

/// Read `name` through every driver and both `SplitCheck` settings and
/// list each arm in which the operation failed, a member's own verdict was
/// not OK, or the mismatches told were not exactly `expected` (as calls
/// and as the count on `b.txt`'s outcome).
fn faults_of(name: &str, expected: &[(&str, u32)]) -> Vec<String> {
    let expected: Vec<(String, u32)> = expected
        .iter()
        .map(|&(member, volume)| (member.to_owned(), volume))
        .collect();
    let mut faults = Vec::new();
    for check in [SplitCheck::Streaming, SplitCheck::Strict] {
        // (the pool's width or None for the sequential driver, thread width)
        for (pool, width) in [
            (None, 1),
            (None, 4),
            (Some(1), 1),
            (Some(2), 2),
            (Some(4), 4),
        ] {
            let arm = format!("{name}, {check:?}, pool {pool:?}, width {width}");
            let options = ReadOptions::default()
                .with_split_check(check)
                .with_workers(Some(width));
            let mut told = Told::default();
            let ended = match pool {
                None => extract(set(name), &options, &mut told, &mut ()),
                Some(pool) => extract_parallel(set(name), &options, &told, pool),
            };
            if let Err(e) = ended {
                faults.push(format!("{arm}: the operation answered {e:?}"));
            }
            let closed = told.closed.into_inner().expect("the sink's own lock");
            let mismatches = told.mismatches.into_inner().expect("the sink's own lock");
            if closed.len() != 3 {
                faults.push(format!("{arm}: {} members closed", closed.len()));
            }
            for (member, verdict, count) in &closed {
                if *verdict != Some(true) {
                    faults.push(format!("{arm}: {member}'s own check was {verdict:?}"));
                }
                let stated = expected.iter().filter(|(m, _)| m == member).count() as u32;
                if *count != stated {
                    faults.push(format!(
                        "{arm}: {member}'s outcome states {count} mismatches, not {stated}"
                    ));
                }
            }
            if mismatches != expected {
                faults.push(format!("{arm}: told {mismatches:?}, not {expected:?}"));
            }
        }
    }
    faults
}

fn judged(name: &str, expected: &[(&str, u32)]) {
    let faults = faults_of(name, expected);
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// C4: in RAR 5 a leading field of `FFFFFFFF` is a checksum like any
/// other, and one that disagrees is told. The reference prints its line.
#[test]
fn a_rar5_leading_field_of_all_ones_is_judged() {
    judged("v5-lead-crc-ffffffff", &[("b.txt", 0)]);
}

/// C4: and so is `00000000`.
#[test]
fn a_rar5_leading_field_of_zero_is_judged() {
    judged("v5-lead-crc-zero", &[("b.txt", 0)]);
}

/// C4: in the older container `FFFFFFFF` is no checksum at version 29, as
/// at 15 and 20: nothing is told. The reference prints nothing.
#[test]
fn an_older_container_leading_field_of_all_ones_is_not_judged() {
    let streaming = faults_of("v4-lead-crc-ffffffff-v29", &[]);
    // `SplitCheck::Strict` refuses a leading fragment that carries no
    // checksum, which is what this field says: only the arms read under
    // `Streaming` are this test's.
    let streaming: Vec<&String> = streaming
        .iter()
        .filter(|fault| fault.contains("Streaming"))
        .collect();
    assert!(streaming.is_empty(), "{streaming:?}");
}

/// C4: a wrong field at version 29 is told. The reference prints its line.
#[test]
fn an_older_container_wrong_leading_field_is_judged() {
    judged("v4-lead-crc-wrong-v29", &[("b.txt", 0)]);
}
