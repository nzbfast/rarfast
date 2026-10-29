//! A COMPRESSED or ENCRYPTED member split across volumes is dispatched to
//! the concurrent pool over its fragment list (`extract::Split`,
//! `extract::split_job_kind`), as a stored clear one has been since 29 Sep
//! 2026, and says and writes exactly what the walk's own read of it says
//! and writes.
//!
//! Each case reads a set three ways, as `split_stored_member_jobs.rs`
//! does, and compares the error (kind, member, volume), every member's
//! close and every closed member's bytes:
//!
//! - the SEQUENTIAL `extract`;
//! - `extract_parallel` with only stored clear split jobs (the old rule),
//!   the walk joining a compressed or encrypted split member itself;
//! - `extract_parallel` with every split member a job, asserted to have
//!   dispatched at least one, so two walk-joined reads cannot pass for it.
//!
//! A member cut short by a failure is held to a correct PREFIX of itself
//! in all three, and to nothing longer (29 Sep 2026).

#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Password, Payload, Progress, RangeSource, ReadOptions, Result, WriteMethod,
    WriteOptions, Writer,
};

/// Eight members of 3 MiB and a bit in volumes of 5 MiB and a bit, so
/// most members cross a boundary somewhere that is no whole number of
/// anything, whatever the compressor makes of them.
const MEMBER_LEN: usize = (3 << 20) + 333;
const PER: u64 = (5 << 20) + 7;

/// Half noise and half text in 4 KiB runs, so a compressed member has both
/// literals and matches to decode.
fn member(i: usize) -> Vec<u8> {
    let mut x = (29 + i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..MEMBER_LEN)
        .map(|n| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if (n >> 12) & 1 == 0 {
                (x >> 24) as u8
            } else {
                b"the quick brown fox "[(x % 20) as usize]
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Compressed,
    EncryptedStored,
    EncryptedCompressed,
    HeadersEncrypted,
}

const KINDS: [Kind; 4] = [
    Kind::Compressed,
    Kind::EncryptedStored,
    Kind::EncryptedCompressed,
    Kind::HeadersEncrypted,
];

const PASSWORD: &str = "Secret";

impl Kind {
    fn password(self) -> Option<&'static str> {
        match self {
            Kind::Compressed => None,
            _ => Some(PASSWORD),
        }
    }
}

fn many(prefix: &str, kind: Kind) -> Vec<Vec<u8>> {
    let compressed = WriteMethod::Compressed {
        level: 3,
        // NAMED, the 2 MiB these sets were always written at: the damage
        // tests below flip bytes at fixed places of this stream, and
        // level 3's own default in a non-solid RAR 5 archive is 16 MiB
        // under one far link since 9 Oct 2026, which is another stream.
        dictionary: Some(2 << 20),
    };
    let method = match kind {
        Kind::EncryptedStored => WriteMethod::Stored,
        _ => compressed,
    };
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        method,
        password: kind.password().map(Password::from),
        encrypt_headers: matches!(kind, Kind::HeadersEncrypted),
        ..WriteOptions::default()
    })
    .expect("options");
    let parts: Vec<Vec<u8>> = (0..8).map(member).collect();
    let names: Vec<String> = (0..8).map(|i| format!("{prefix}0{i}.mkv")).collect();
    for (data, name) in parts.iter().zip(&names) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    assert!(out.len() >= 3, "a set of {} volumes", out.len());
    out
}

type Written = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct Keep {
    name: String,
    written: Written,
}

impl Write for Keep {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = self.written.lock().unwrap();
        held.entry(self.name.clone())
            .or_default()
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink {
    written: Written,
    closes: Mutex<Vec<(String, Option<bool>, u64)>>,
    verify: bool,
}

impl ParallelSink for Sink {
    type Out = Keep;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
        if self.verify {
            return Ok(Disposition::Verify);
        }
        Ok(Disposition::Write(Keep {
            name: String::from_utf8_lossy(member.name).into_owned(),
            written: Arc::clone(&self.written),
        }))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Keep>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closes.lock().unwrap().push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
            outcome.bytes,
        ));
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct Said {
    error: Option<String>,
    closes: Vec<(String, Option<bool>, u64)>,
    /// Each writer's bytes: length, CRC32, and whether they are a prefix
    /// of the member's true bytes.
    written: BTreeMap<String, (usize, u32, bool)>,
}

impl Said {
    fn closed_writes(&self) -> Vec<(String, (usize, u32, bool))> {
        self.written
            .iter()
            .filter(|(n, _)| self.closes.iter().any(|c| &c.0 == *n))
            .map(|(n, w)| (n.clone(), *w))
            .collect()
    }
}

fn truth(name: &str) -> Vec<u8> {
    let i: usize = name[2..3].parse().expect("<prefix>0<i>.mkv");
    member(i)
}

fn options(kind: Kind) -> ReadOptions {
    ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(Some(true))
        .with_password(kind.password().map(Password::from))
}

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

fn sink(verify: bool) -> Sink {
    Sink {
        written: Arc::default(),
        closes: Mutex::default(),
        verify,
    }
}

/// `extract_parallel` with every split member a job (`all`) or with only
/// stored clear ones; and how many split jobs it took.
fn read(volumes: &[Vec<u8>], kind: Kind, all: bool, verify: bool) -> (Said, u64) {
    let sink = sink(verify);
    probe::set_split_jobs_all(Some(all));
    probe::reset_split_jobs_taken();
    let outcome = extract_parallel(sources(volumes), &options(kind), &sink, 8);
    let taken = probe::split_jobs_taken();
    probe::set_split_jobs_all(None);
    (said(outcome.err(), sink), taken)
}

fn read_sequential(volumes: &[Vec<u8>], kind: Kind, verify: bool) -> Said {
    struct Seq<'a>(&'a Sink);
    impl rarkit::Sink for Seq<'_> {
        type Out = Keep;
        fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
            self.0.open(member)
        }
        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Keep>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            self.0.close(member, out, outcome)
        }
    }
    struct Quiet;
    impl Progress for Quiet {}
    let sink = sink(verify);
    let outcome = extract(
        sources(volumes),
        &options(kind),
        &mut Seq(&sink),
        &mut Quiet,
    );
    said(outcome.err(), sink)
}

fn said(error: Option<rarkit::Error>, sink: Sink) -> Said {
    let error = error.map(|e| {
        format!(
            "{:?} member {:?} volume {:?}",
            e.kind(),
            e.member().map(|m| String::from_utf8_lossy(m).into_owned()),
            e.volume()
        )
    });
    let written = sink
        .written
        .lock()
        .unwrap()
        .iter()
        .map(|(n, b)| {
            let t = truth(n);
            let prefix = b.len() <= t.len() && b[..] == t[..b.len()];
            (n.clone(), (b.len(), rarkit::checksum::crc32(b), prefix))
        })
        .collect();
    Said {
        error,
        closes: sink.closes.into_inner().unwrap(),
        written,
    }
}

/// Read all three ways and compare; the new rule must have taken a split
/// job where the set still has its first volume.
fn three_ways(volumes: &[Vec<u8>], kind: Kind, verify: bool) -> Said {
    compare(volumes, kind, verify, true)
}

/// [`three_ways`], with the dispatch asked for or not: a set cut inside a
/// member may be refused at that member's header, before any job exists.
fn compare(volumes: &[Vec<u8>], kind: Kind, verify: bool, dispatch: bool) -> Said {
    let sequential = read_sequential(volumes, kind, verify);
    let (old, old_taken) = read(volumes, kind, false, verify);
    let (new, taken) = read(volumes, kind, true, verify);
    assert_eq!(
        old_taken, 0,
        "{kind:?}: the old rule dispatched a split member"
    );
    assert!(
        taken >= 1 || !dispatch,
        "{kind:?}: no split member was dispatched"
    );
    for (arm, other) in [("sequential", &sequential), ("old rule", &old)] {
        assert_eq!(
            (&new.error, &new.closes),
            (&other.error, &other.closes),
            "{kind:?}: the error and the closes, against the {arm}"
        );
        assert_eq!(
            new.closed_writes(),
            other.closed_writes(),
            "{kind:?}: every closed member's bytes, against the {arm}"
        );
    }
    for said in [&sequential, &old, &new] {
        for (name, (_, _, prefix)) in &said.written {
            if !said.closes.iter().any(|c| &c.0 == name) {
                assert!(prefix, "{kind:?}: {name}'s bytes are not a prefix of it");
            }
        }
    }
    new
}

#[test]
fn a_whole_set_writes_every_member_three_ways() {
    for kind in KINDS {
        let set = many("E", kind);
        let said = three_ways(&set, kind, false);
        assert_eq!(said.error, None, "{kind:?}");
        assert_eq!(said.closes.len(), 8, "{kind:?}");
        for (i, (name, ok, bytes)) in said.closes.iter().enumerate() {
            assert_eq!(name, &format!("E0{i}.mkv"));
            assert_eq!(*ok, Some(true), "{kind:?} {name}");
            assert_eq!(*bytes, MEMBER_LEN as u64);
            assert_eq!(
                said.written[name],
                (MEMBER_LEN, rarkit::checksum::crc32(&member(i)), true),
                "{kind:?} {name}"
            );
        }
        // Every boundary a member crosses is a split job.
        let (_, taken) = read(&set, kind, true, false);
        assert!(
            taken + 1 >= set.len() as u64 - 1,
            "{kind:?}: {taken} split jobs over {} volumes",
            set.len()
        );
    }
}

/// `t`: every member verified and none written, three ways.
#[test]
fn a_whole_set_verifies_three_ways() {
    for kind in KINDS {
        let set = many("E", kind);
        let said = three_ways(&set, kind, true);
        assert_eq!(said.error, None, "{kind:?}");
        assert!(said.closes.iter().all(|c| c.1 == Some(true)), "{kind:?}");
    }
}

/// A flipped byte in the LEADING fragment of the member that crosses out
/// of volume 0, in its packed bytes well clear of every header.
#[test]
fn a_flipped_byte_in_a_leading_fragment_fails_the_same_three_ways() {
    for kind in KINDS {
        let mut set = many("E", kind);
        let at = set[0].len() - 200_000;
        set[0][at] ^= 0x10;
        let said = three_ways(&set, kind, false);
        let failed = said.closes.iter().filter(|c| c.1 != Some(true)).count();
        assert!(
            failed >= 1 || said.error.is_some(),
            "{kind:?}: a damaged leading fragment went unnoticed"
        );
    }
}

/// A flipped byte in the LAST fragment of that member, which opens
/// volume 1.
#[test]
fn a_flipped_byte_in_a_last_fragment_fails_the_same_three_ways() {
    for kind in KINDS {
        let mut set = many("E", kind);
        set[1][100_000] ^= 0x10;
        let said = three_ways(&set, kind, false);
        let failed = said.closes.iter().filter(|c| c.1 != Some(true)).count();
        assert!(
            failed >= 1 || said.error.is_some(),
            "{kind:?}: a damaged last fragment went unnoticed"
        );
    }
}

#[test]
fn a_volume_missing_mid_member_ends_the_same_three_ways() {
    for kind in KINDS {
        let set = many("E", kind);
        let gapped: Vec<Vec<u8>> = set
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, v)| v.clone())
            .collect();
        let said = three_ways(&gapped, kind, false);
        assert!(said.error.is_some(), "{kind:?}: a gapped set is an error");
    }
}

#[test]
fn a_volume_cut_inside_a_split_member_ends_the_same_three_ways() {
    for kind in KINDS {
        let mut set = many("E", kind);
        let at = set[0].len() - 100_000;
        set[0].truncate(at);
        let said = compare(&set, kind, false, false);
        assert!(said.error.is_some(), "{kind:?}: a cut volume is an error");
    }
}

/// A continuation header that does not join (spec F 3.5.4).
#[test]
fn a_continuation_that_does_not_join_ends_the_same_three_ways() {
    for kind in KINDS {
        let mut set = many("E", kind);
        let other = many("X", kind);
        set[1] = other[1].clone();
        let said = three_ways(&set, kind, false);
        assert!(
            said.error.is_some(),
            "{kind:?}: a mismatched continuation is an error"
        );
    }
}

/// The wrong password: every member refused the same way three ways.
#[test]
fn a_wrong_password_is_refused_the_same_three_ways() {
    for kind in [Kind::EncryptedStored, Kind::EncryptedCompressed] {
        let set = many("E", kind);
        let wrong = |all: Option<bool>| {
            let sink = sink(false);
            let options = options(kind).with_password(Some(Password::from("wrong")));
            let outcome = match all {
                None => {
                    struct Seq<'a>(&'a Sink);
                    impl rarkit::Sink for Seq<'_> {
                        type Out = Keep;
                        fn open(&mut self, m: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
                            self.0.open(m)
                        }
                        fn close(
                            &mut self,
                            m: &MemberInfo<'_>,
                            out: Option<Keep>,
                            o: &MemberOutcome,
                        ) -> Result<()> {
                            self.0.close(m, out, o)
                        }
                    }
                    struct Quiet;
                    impl Progress for Quiet {}
                    extract(sources(&set), &options, &mut Seq(&sink), &mut Quiet).map(|_| ())
                }
                Some(all) => {
                    probe::set_split_jobs_all(Some(all));
                    let outcome = extract_parallel(sources(&set), &options, &sink, 8).map(|_| ());
                    probe::set_split_jobs_all(None);
                    outcome
                }
            };
            said(outcome.err(), sink)
        };
        let sequential = wrong(None);
        let old = wrong(Some(false));
        let new = wrong(Some(true));
        assert!(sequential.error.is_some(), "{kind:?}: a wrong password");
        assert_eq!((&new.error, &new.closes), (&old.error, &old.closes));
        assert_eq!(
            (&new.error, &new.closes),
            (&sequential.error, &sequential.closes)
        );
    }
}
