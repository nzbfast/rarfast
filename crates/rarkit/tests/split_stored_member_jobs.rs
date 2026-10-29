//! A stored member SPLIT across volumes is dispatched to the concurrent
//! pool over its fragment list (`extract::Split`), so a stored volume set
//! (a set of many big members in `-v4g` volumes) writes its members in parallel
//! across every volume boundary as one archive does, and says and writes
//! exactly what the walk's own read of it says and writes.
//!
//! Every case reads a set three ways and compares the error (its kind,
//! member and volume), every member's close and every byte each member's
//! writer received, partial output included:
//!
//! - the SEQUENTIAL `extract`, which is where `rarfast` sent every set
//!   holding a split member until this change (its `any_selected_is_split`)
//!   and so the behaviour a damaged set must keep;
//! - `extract_parallel` with split jobs forced OFF, the walk joining the
//!   split member itself: the error and the closes must match it too;
//! - `extract_parallel` with split jobs ON, asserted to have dispatched a
//!   split member first, so a comparison of two walk-joined reads cannot
//!   pass for one of a split job.
//!
//! **Partial output.** A member that closed wrote the same bytes every way.
//! A member cut short by a failure wrote a correct PREFIX of itself every
//! way, but its length is the arrangement's and differs even between the
//! two old arms: the sequential path hands its writes through the seam's
//! ring and the walk-joined pool through a 64 KiB pipe, and each drops
//! what it had not yet delivered when the walk fails. A split job writes
//! each read as it arrives. So a cut-short member is held to "a correct
//! prefix" in all three and to nothing longer. That is the bar the
//! damage-parity condition was
//! decided to mean (29 Sep 2026): a member cut short writes a
//! CORRECT PREFIX of its source and never a wrong byte; its length is the
//! arrangement's and is not pinned.

#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rarkit::{
    extract, extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Payload, Progress, RangeSource, ReadOptions, Result, WriteOptions, Writer,
};

/// Eight members of 12 MiB and a bit, in volumes of 40 MiB and a bit, so
/// that several members cross a boundary at an offset that is no whole
/// number of anything.
const MEMBER_LEN: usize = (12 << 20) + 333;
const PER: u64 = (40 << 20) + 7;

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn member(i: usize) -> Vec<u8> {
    noise(MEMBER_LEN, 29 + i as u64)
}

/// The set of eight, its members named `<prefix>0<i>.mkv`.
fn many(prefix: &str) -> Vec<Vec<u8>> {
    let parts: Vec<Vec<u8>> = (0..8).map(member).collect();
    let names: Vec<String> = (0..8).map(|i| format!("{prefix}0{i}.mkv")).collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        ..WriteOptions::default()
    })
    .expect("options");
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

/// Where the first byte of `data` sits inside `volume`, to damage a
/// member's bytes and nothing else.
fn find(volume: &[u8], data: &[u8]) -> usize {
    let probe = &data[..64];
    volume
        .windows(64)
        .position(|w| w == probe)
        .expect("the member's bytes are in this volume")
}

/// Every byte each member's writer received, by name, and the writers'
/// last write times.
type Written = Arc<Mutex<BTreeMap<String, (Vec<u8>, Option<Instant>)>>>;

struct Keep {
    name: String,
    written: Written,
    /// A pause before every write, to make this member finish last.
    slow: Option<Duration>,
}

impl Write for Keep {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(pause) = self.slow {
            std::thread::sleep(pause);
        }
        let mut held = self.written.lock().unwrap();
        let entry = held.entry(self.name.clone()).or_default();
        entry.0.extend_from_slice(data);
        entry.1 = Some(Instant::now());
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink {
    written: Written,
    closes: Mutex<Vec<(String, Option<bool>, u64)>>,
    slow: Option<(String, Duration)>,
}

impl ParallelSink for Sink {
    type Out = Keep;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
        let name = String::from_utf8_lossy(member.name).into_owned();
        let slow = self
            .slow
            .as_ref()
            .filter(|(n, _)| *n == name)
            .map(|(_, d)| *d);
        Ok(Disposition::Write(Keep {
            name,
            written: Arc::clone(&self.written),
            slow,
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

/// What one read said: the error (kind, member, volume) or none, the
/// closes in order, and a digest of each writer's bytes.
#[derive(Debug, PartialEq)]
struct Said {
    error: Option<String>,
    closes: Vec<(String, Option<bool>, u64)>,
    /// Each writer's bytes: length and CRC32, and whether they are a
    /// prefix of the member's true bytes.
    written: BTreeMap<String, (usize, u32, bool)>,
}

impl Said {
    /// The writers of members that CLOSED, whose bytes are the member's
    /// whole output and must match exactly.
    fn closed_writes(&self) -> Vec<(String, (usize, u32, bool))> {
        self.written
            .iter()
            .filter(|(n, _)| self.closes.iter().any(|c| &c.0 == *n))
            .map(|(n, w)| (n.clone(), *w))
            .collect()
    }
}

/// The true bytes of a member of either set, by name.
fn truth(name: &str) -> Vec<u8> {
    let i: usize = name[2..3].parse().expect("<prefix>0<i>.mkv");
    member(i)
}

fn read(volumes: &[Vec<u8>], split: bool, slow: Option<(String, Duration)>) -> (Said, u64) {
    read_sources(
        volumes
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect(),
        split,
        slow,
    )
}

fn read_sources(
    sources: Vec<Arc<dyn RangeSource>>,
    split: bool,
    slow: Option<(String, Duration)>,
) -> (Said, u64) {
    let sink = Sink {
        written: Arc::default(),
        closes: Mutex::default(),
        slow,
    };
    let options = ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(Some(true));
    probe::set_split_jobs(Some(split));
    probe::reset_split_jobs_taken();
    let outcome = extract_parallel(sources, &options, &sink, 8);
    let taken = probe::split_jobs_taken();
    probe::set_split_jobs(None);
    (said(outcome.err(), sink), taken)
}

/// The same through the sequential `extract` and the caller's `Sink`.
fn read_sequential(volumes: &[Vec<u8>]) -> Said {
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
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let sink = Sink {
        written: Arc::default(),
        closes: Mutex::default(),
        slow: None,
    };
    let options = ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(Some(true));
    let outcome = extract(sources, &options, &mut Seq(&sink), &mut Quiet);
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
        .map(|(n, (b, _))| {
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

/// Read all three ways and compare; the ON arm must have taken a split job.
fn both(volumes: &[Vec<u8>]) -> Said {
    let sequential = read_sequential(volumes);
    let (off, none) = read(volumes, false, None);
    let (on, taken) = read(volumes, true, None);
    assert_eq!(none, 0, "the knob's OFF arm dispatched a split member");
    assert!(taken >= 1, "no split member was dispatched");
    for (arm, other) in [("sequential", &sequential), ("walk-joined pool", &off)] {
        assert_eq!(
            (&on.error, &on.closes),
            (&other.error, &other.closes),
            "the error and the closes, against the {arm}"
        );
        assert_eq!(
            on.closed_writes(),
            other.closed_writes(),
            "every closed member's bytes, against the {arm}"
        );
    }
    // A member cut short (never closed) wrote a correct prefix of itself.
    for said in [&sequential, &off, &on] {
        for (name, (_, _, prefix)) in &said.written {
            if !said.closes.iter().any(|c| &c.0 == name) {
                assert!(prefix, "{name}'s bytes are not a prefix of it");
            }
        }
    }
    on
}

#[test]
fn a_whole_set_writes_every_member_both_ways() {
    let set = many("E");
    let said = both(&set);
    assert_eq!(said.error, None);
    assert_eq!(said.closes.len(), 8);
    for (i, (name, ok, bytes)) in said.closes.iter().enumerate() {
        assert_eq!(name, &format!("E0{i}.mkv"));
        assert_eq!(*ok, Some(true), "{name}");
        assert_eq!(*bytes, MEMBER_LEN as u64);
        assert_eq!(
            said.written[name],
            (MEMBER_LEN, rarkit::checksum::crc32(&member(i)), true),
            "{name}"
        );
    }
    let (_, taken) = read(&set, true, None);
    assert!(taken >= 2, "only {taken} split members dispatched");
}

/// Split members across every boundary go in parallel with the rest: the
/// members' writes overlap across a volume boundary where the walk's own
/// read of the split member held them apart.
#[test]
fn members_after_a_split_one_start_before_it_ends() {
    let set = many("E");
    let written: Written = Arc::default();
    let sink = Sink {
        written: Arc::clone(&written),
        closes: Mutex::default(),
        // A split member made slow: nothing after it may wait for it.
        slow: Some(("E03.mkv".into(), Duration::from_millis(2))),
    };
    let sources: Vec<Arc<dyn RangeSource>> = set
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(Some(true));
    probe::reset_split_jobs_taken();
    extract_parallel(sources, &options, &sink, 8).expect("a whole set reads");
    assert!(probe::split_jobs_taken() >= 1);
    let held = written.lock().unwrap();
    let last = |n: &str| held[n].1.expect("written");
    // E07 sits after every boundary; it is done before the slow split
    // member E03 is.
    assert!(last("E07.mkv") < last("E03.mkv"));
}

#[test]
fn a_flipped_byte_in_a_leading_fragment_fails_that_member_both_ways() {
    let mut set = many("E");
    // Member 3 is the first to cross a boundary: its first byte is in
    // volume 0 and its tail in volume 1. Damage its leading fragment.
    let at = find(&set[0], &member(3)) + 1000;
    set[0][at] ^= 0x10;
    let said = both(&set);
    let e3 = said
        .closes
        .iter()
        .find(|c| c.0 == "E03.mkv")
        .expect("closed");
    assert_eq!(e3.1, Some(false));
}

#[test]
fn a_flipped_byte_in_a_last_fragment_fails_that_member_both_ways() {
    let mut set = many("E");
    // Member 3's last fragment opens volume 1: its bytes there are its
    // own tail, found by the tail's first 64 bytes.
    let e3 = member(3);
    let head = find(&set[0], &e3);
    let in_first = set[0].len() - head;
    let tail = &e3[in_first + 4096..];
    let at = find(&set[1], tail) + 10;
    set[1][at] ^= 0x10;
    let said = both(&set);
    let closed = said
        .closes
        .iter()
        .find(|c| c.0 == "E03.mkv")
        .expect("closed");
    assert_eq!(closed.1, Some(false));
}

#[test]
fn a_volume_missing_mid_member_ends_the_same_way_both_ways() {
    let set = many("E");
    let gapped: Vec<Vec<u8>> = set
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, v)| v.clone())
        .collect();
    let said = both(&gapped);
    assert!(said.error.is_some(), "a gapped set is an error");
}

#[test]
fn a_set_cut_off_after_its_first_volume_ends_the_same_way_both_ways() {
    let set = many("E");
    let said = both(&set[..1]);
    assert!(said.error.is_some(), "a cut set is an error");
}

#[test]
fn a_volume_cut_inside_a_split_member_ends_the_same_way_both_ways() {
    let mut set = many("E");
    let at = find(&set[0], &member(3)) + 5000;
    set[0].truncate(at);
    let said = both(&set);
    assert!(said.error.is_some(), "a cut volume is an error");
}

/// A continuation header that does not join (spec F 3.5.4): the second
/// volume of a set whose members have other names.
#[test]
fn a_continuation_that_does_not_join_ends_the_same_way_both_ways() {
    let mut set = many("E");
    let other = many("X");
    set[1] = other[1].clone();
    let said = both(&set);
    assert!(
        said.error.is_some(),
        "a mismatched continuation is an error"
    );
}

/// A source that records when the walk and the workers let it go.
struct Held {
    data: Vec<u8>,
    dropped: Arc<Mutex<Option<Instant>>>,
}

impl RangeSource for Held {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        self.data.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        *self.dropped.lock().unwrap() = Some(Instant::now());
    }
}

/// Drop-behind: the split member's FIRST volume is held until its job has
/// written its last byte, with the job forced to finish last; no volume is
/// let go under a member in flight.
#[test]
fn a_split_job_holds_its_first_volume_until_it_ends() {
    let set = many("E");
    let drops: Vec<Arc<Mutex<Option<Instant>>>> = set.iter().map(|_| Arc::default()).collect();
    let sources: Vec<Arc<dyn RangeSource>> = set
        .iter()
        .zip(&drops)
        .map(|(v, d)| {
            Arc::new(Held {
                data: v.clone(),
                dropped: Arc::clone(d),
            }) as Arc<dyn RangeSource>
        })
        .collect();
    let written: Written = Arc::default();
    let sink = Sink {
        written: Arc::clone(&written),
        closes: Mutex::default(),
        slow: Some(("E03.mkv".into(), Duration::from_millis(3))),
    };
    let options = ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(Some(true));
    probe::reset_split_jobs_taken();
    extract_parallel(sources, &options, &sink, 8).expect("a whole set reads");
    assert!(probe::split_jobs_taken() >= 1);
    let held = written.lock().unwrap();
    let e3_last = held["E03.mkv"].1.expect("written");
    // It finished last.
    for (name, (_, at)) in held.iter() {
        assert!(
            at.expect("written") <= e3_last,
            "{name} ended after the slow split member"
        );
    }
    // Its first volume went only after it was done.
    let first = drops[0].lock().unwrap().expect("volume 0 was let go");
    assert!(
        first >= e3_last,
        "volume 0 was dropped under the split member"
    );
    assert_eq!(held["E03.mkv"].0, member(3), "the slow member's bytes");
}

/// A writer that refuses part way through a split member (SPEC-F 3.7.6):
/// the same error and the same prefix both ways.
#[test]
fn a_refusing_writer_on_a_split_member_ends_the_same_way_both_ways() {
    struct Refuse(Written);
    impl ParallelSink for Refuse {
        type Out = Keep2;
        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Keep2>> {
            Ok(Disposition::Write(Keep2 {
                name: String::from_utf8_lossy(member.name).into_owned(),
                written: Arc::clone(&self.0),
            }))
        }
    }
    struct Keep2 {
        name: String,
        written: Written,
    }
    impl Write for Keep2 {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let mut held = self.written.lock().unwrap();
            let entry = held.entry(self.name.clone()).or_default();
            if self.name == "E03.mkv" && entry.0.len() + data.len() > (5 << 20) {
                return Err(std::io::Error::other("full"));
            }
            entry.0.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let set = many("E");
    let run = |split: bool| {
        let written: Written = Arc::default();
        let sources: Vec<Arc<dyn RangeSource>> = set
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect();
        let options = ReadOptions::default()
            .with_workers(Some(8))
            .with_sink_is_file(Some(true));
        probe::set_split_jobs(Some(split));
        probe::reset_split_jobs_taken();
        let outcome = extract_parallel(sources, &options, &Refuse(Arc::clone(&written)), 8);
        let taken = probe::split_jobs_taken();
        probe::set_split_jobs(None);
        let e3 = written
            .lock()
            .unwrap()
            .get("E03.mkv")
            .map(|(b, _)| b.clone())
            .unwrap_or_default();
        (outcome.err().map(|e| format!("{:?}", e.kind())), e3, taken)
    };
    let (off_err, off_e3, _) = run(false);
    let (on_err, on_e3, taken) = run(true);
    assert!(taken >= 1);
    assert!(off_err.is_some(), "a refusing writer is an error");
    assert_eq!(on_err, off_err);
    // Short of the refusal, a correct prefix, each way.
    let t = member(3);
    for e3 in [&off_e3, &on_e3] {
        assert!(e3.len() <= 5 << 20 && e3[..] == t[..e3.len()]);
    }
}
