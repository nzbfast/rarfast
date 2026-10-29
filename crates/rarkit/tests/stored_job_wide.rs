//! A STORED member dispatched to the concurrent pool is read wide by its
//! worker (`concurrent::job_wide`, 1 Oct 2026): an ENCRYPTED one
//! (SPEC-K 2.1, 3.7.4) verified or written, and a CLEAR one that is
//! only verified, as the walk's own stream reads both. It says and writes
//! exactly what the one-worker read and the sequential `extract` say and
//! write.
//!
//! Each case reads a set four ways and compares the error (kind, member,
//! volume), every member's close and every closed member's bytes:
//!
//! - the SEQUENTIAL `extract`;
//! - `extract_parallel` with the workers' wide read OFF (the arrangement
//!   before);
//! - `extract_parallel` with it ON at any grant, asserted to have offered
//!   at least one range to the wide read, so two narrow reads cannot pass
//!   for it;
//! - `extract_parallel` with it on only from a grant no pool can make, so
//!   every range is offered, declined for too few lanes, and read a buffer
//!   at a time on the worker (the path a member takes while the pool's
//!   width is spent on its neighbours).
//!
//! The sets are an archive of several members (the shape `rarfast t` and
//! `x` send through the pool: a big member beside a sample) and the same
//! members over volumes whose size is no whole number of cipher blocks, with
//! every split member a job; clear, under `-p` and under `-hp`. The big
//! members are over the wide read's floor and are neither whole blocks nor whole
//! pieces long.
//!
//! A stored member a worker WRITES is CUT by that worker into aligned
//! pieces at whole offsets (`read::handed::cut_here`, 1 Oct 2026), clear
//! and under AES-CBC, with one reader in order or with the window's pieces
//! read at once. The four ways above run with the cut OFF, which is the
//! arrangement they were written for; each case then reads the set again
//! with the cut ON in both orders and holds it to the same answers, with
//! the number of ranges cut asserted so an arm that never cut cannot pass.
//!
//! The knobs are one word each for the process, because a WORKER reads
//! them, so every test here holds [`KNOB`] while it reads.

#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Password, Payload, Progress, RangeSource, ReadOptions, Result, WriteOptions,
    Writer,
};

static KNOB: Mutex<()> = Mutex::new(());

/// More lanes than any grant here holds (the reads run at a width of
/// eight), so every range a worker offers is declined.
const NO_SUCH_GRANT: usize = 1000;

const PASSWORD: &str = "hpjob";
/// Not a multiple of 16, so the fragments are not whole blocks.
const PER: u64 = (20 << 20) + 7;

/// The members: two big members over the wide floor (16 MiB), neither a whole
/// number of blocks, and a sample under it between them.
const MEMBERS: [(&str, usize); 3] = [
    ("Full.mkv", (40 << 20) + 5),
    ("Sample.mkv", (1 << 20) + 9),
    ("Extras.mkv", (24 << 20) + 3),
];

/// Incompressible, deterministic bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
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

/// A member under the pool's offload floor, which the walk decodes itself.
const NFO: (&str, usize) = ("Full.nfo", 4096);

fn truth(name: &str) -> Vec<u8> {
    if name == NFO.0 {
        return noise(7, NFO.1);
    }
    let (at, (_, len)) = MEMBERS
        .iter()
        .enumerate()
        .find(|(_, (n, _))| *n == name)
        .expect("a member of the set");
    noise(41 + at as u64, *len)
}

/// The members stored and encrypted, their headers too where `headers`,
/// in one archive or in volumes of [`PER`], by this crate's own writer.
fn set(split: bool, headers: bool) -> Vec<Vec<u8>> {
    stored(split, Some(headers))
}

/// The same members stored CLEAR.
fn clear_set(split: bool) -> Vec<Vec<u8>> {
    stored(split, None)
}

/// The members stored: clear (`None`), or encrypted with the headers
/// clear or encrypted too.
fn stored(split: bool, encrypted: Option<bool>) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        volume_size: split.then_some(PER),
        password: encrypted.map(|_| Password::from(PASSWORD)),
        encrypt_headers: encrypted == Some(true),
        ..WriteOptions::default()
    })
    .expect("options");
    let bytes: Vec<Vec<u8>> = MEMBERS.iter().map(|(name, _)| truth(name)).collect();
    for ((name, _), data) in MEMBERS.iter().zip(&bytes) {
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
    if !split {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        return vec![one];
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    assert!(out.len() >= 3, "a set of {} volumes", out.len());
    out
}

type Written = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

/// Every write one member's writer was given: its length, and whether its
/// buffer began on a page.
type Calls = Arc<Mutex<Writes>>;

/// Those writes, by member.
type Writes = BTreeMap<String, Vec<(usize, bool)>>;

/// A writer that refuses once its member holds `limit` bytes, as a full
/// disk would, and raises `cancel` once it holds `cancel_after`.
struct Keep {
    name: String,
    written: Written,
    calls: Calls,
    limit: Option<usize>,
    cancel: Option<(Arc<AtomicBool>, usize)>,
}

impl Write for Keep {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = self.written.lock().unwrap();
        let bytes = held.entry(self.name.clone()).or_default();
        if self.limit.is_some_and(|l| bytes.len() + data.len() > l) {
            return Err(std::io::Error::other("full"));
        }
        bytes.extend_from_slice(data);
        if let Some((cancel, after)) = &self.cancel {
            if bytes.len() >= *after {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        self.calls
            .lock()
            .unwrap()
            .entry(self.name.clone())
            .or_default()
            .push((data.len(), (data.as_ptr() as usize).is_multiple_of(4096)));
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink {
    written: Written,
    calls: Calls,
    closes: Mutex<Vec<(String, Option<bool>, u64)>>,
    verify: bool,
    limit: Option<usize>,
    cancel: Option<(Arc<AtomicBool>, usize)>,
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
            calls: Arc::clone(&self.calls),
            limit: self.limit,
            cancel: self.cancel.clone(),
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

#[derive(Clone, Copy)]
struct How {
    verify: bool,
    password: &'static str,
    limit: Option<usize>,
    /// `x` to a file, where an encrypted stored member is read wide too
    /// (`extract::cipher_to_file`).
    sink_is_file: Option<bool>,
    /// Raise the caller's cancel flag once a member holds this many bytes.
    cancel_after: Option<usize>,
}

const X: How = How {
    verify: false,
    password: PASSWORD,
    limit: None,
    sink_is_file: Some(true),
    cancel_after: None,
};
const T: How = How { verify: true, ..X };

fn options(how: How) -> ReadOptions {
    ReadOptions::default()
        .with_workers(Some(8))
        .with_sink_is_file(how.sink_is_file)
        .with_password(Some(Password::from(how.password)))
}

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

fn sink(how: How) -> Sink {
    Sink {
        written: Arc::default(),
        calls: Arc::default(),
        closes: Mutex::default(),
        verify: how.verify,
        limit: how.limit,
        cancel: how
            .cancel_after
            .map(|after| (Arc::new(AtomicBool::new(false)), after)),
    }
}

/// The options of one read: `sink`'s own cancel flag, where it has one.
fn options_for(how: How, sink: &Sink) -> ReadOptions {
    options(how).with_cancel(sink.cancel.as_ref().map(|(flag, _)| Arc::clone(flag)))
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

/// `extract_parallel` with the workers' wide read taken from a grant of
/// `lanes` (zero for never), every split member a job; and how many ranges
/// the workers offered the wide read. The caller holds [`KNOB`].
fn read(volumes: &[Vec<u8>], how: How, lanes: usize) -> (Said, u64) {
    read_with(volumes, how, lanes, false)
}

/// [`read`], with the wide read of a clear member that is WRITTEN
/// (`wide_write`, `RARKIT_JOB_WIDE_WRITE`) as asked.
fn read_with(volumes: &[Vec<u8>], how: How, lanes: usize, wide_write: bool) -> (Said, u64) {
    read_as(volumes, how, lanes, wide_write, ALWAYS)
}

/// When a pool worker cuts its member (`probe::set_stored_cut_when`):
/// whenever the lanes allow, or only while no other member is decoded.
const WHENEVER: u8 = 1;
const ALONE: u8 = 2;

/// How a member its worker WRITES is cut (`probe::set_stored_cut`): not at
/// all, by one reader in order, or with the window's pieces read at once.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Cut {
    Off,
    InOrder,
    AtOnce,
}

/// `extract_parallel` with the cut as named, the wide read from a grant of
/// `lanes` and the written rule stated; what it said, how many ranges were
/// cut, and every write each member's writer was given.
fn read_cut(
    volumes: &[Vec<u8>],
    how: How,
    lanes: usize,
    written: u8,
    cut: Cut,
    when: u8,
) -> (Said, u64, Writes) {
    let sink = sink(how);
    probe::set_job_wide(Some(lanes));
    probe::set_job_wide_written(written);
    probe::set_job_wide_write(Some(false));
    probe::set_split_jobs_all(Some(true));
    probe::set_stored_cut(
        Some(cut != Cut::Off),
        (cut != Cut::Off).then_some(cut == Cut::InOrder),
    );
    probe::set_stored_cut_when(when);
    // The cipher's cut is a system's default; these arms hold it on.
    probe::set_stored_cut_cipher(Some(cut != Cut::Off));
    probe::reset_stored_cuts();
    let outcome = extract_parallel(sources(volumes), &options_for(how, &sink), &sink, 8);
    let cuts = probe::stored_cuts();
    probe::set_stored_cut_cipher(None);
    probe::set_stored_cut_when(0);
    probe::set_stored_cut(None, None);
    probe::set_split_jobs_all(None);
    probe::set_job_wide_write(None);
    probe::set_job_wide_written(0);
    probe::set_job_wide(None);
    let calls = sink.calls.lock().unwrap().clone();
    (said(outcome.err(), sink), cuts, calls)
}

/// A written member read wide whenever the lanes allow, only beside
/// another member, or never (`probe::set_job_wide_written`).
const ALWAYS: u8 = 1;
const BESIDE: u8 = 2;
const NEVER: u8 = 3;

/// [`read_with`], with the rule for a WRITTEN member stated.
fn read_as(
    volumes: &[Vec<u8>],
    how: How,
    lanes: usize,
    wide_write: bool,
    written: u8,
) -> (Said, u64) {
    let sink = sink(how);
    probe::set_job_wide(Some(lanes));
    probe::set_job_wide_written(written);
    probe::set_job_wide_write(Some(wide_write));
    probe::set_split_jobs_all(Some(true));
    // The cut is OFF in these arms: they are the arrangement before it.
    probe::set_stored_cut(Some(false), None);
    let before = probe::job_spans();
    let outcome = extract_parallel(sources(volumes), &options_for(how, &sink), &sink, 8);
    let spans = probe::job_spans() - before;
    probe::set_stored_cut(None, None);
    probe::set_split_jobs_all(None);
    probe::set_job_wide_write(None);
    probe::set_job_wide_written(0);
    probe::set_job_wide(None);
    (said(outcome.err(), sink), spans)
}

fn read_sequential(volumes: &[Vec<u8>], how: How) -> Said {
    read_walk(volumes, how).0
}

/// The sequential `extract`, and every write each member's writer was
/// given. The caller sets the cut and holds [`KNOB`].
fn read_walk(volumes: &[Vec<u8>], how: How) -> (Said, Writes) {
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
    let sink = sink(how);
    let outcome = extract(
        sources(volumes),
        &options_for(how, &sink),
        &mut Seq(&sink),
        &mut Quiet,
    );
    let calls = sink.calls.lock().unwrap().clone();
    (said(outcome.err(), sink), calls)
}

/// Which arms a case holds the wide read to.
#[derive(Clone, Copy, PartialEq)]
enum Against {
    /// The narrow pool and the sequential `extract`: the error, the closes
    /// and every closed member's bytes.
    Both,
    /// The narrow pool alone. A set that ENDS the operation inside a
    /// member is named differently by the pool and by the sequential walk
    /// whatever the workers' read is (the walk refuses a member whose data
    /// runs past its source at the header; the pool names the member whose
    /// worker met the end), and that difference is not this arrangement's.
    Narrow,
    /// The narrow pool's ERROR alone: members the pool decodes beside the
    /// failing one may or may not have closed when it fails.
    NarrowError,
}

/// Read all three ways and compare. With `went_wide`, the wide arm must
/// have offered the wide read a range (a set refused before any member is
/// read offers none). A member that did not close is held to a correct
/// PREFIX of itself in every arm.
fn three_ways(volumes: &[Vec<u8>], how: How, went_wide: bool, against: Against) -> Said {
    three_ways_cut(volumes, how, went_wide, against, went_wide && !how.verify)
}

/// [`three_ways`], with whether the cut arms must have cut a range stated
/// (`cuts`): a written CLEAR member offers the wide read nothing with the
/// cut off, and is cut with it on.
fn three_ways_cut(
    volumes: &[Vec<u8>],
    how: How,
    went_wide: bool,
    against: Against,
    cuts: bool,
) -> Said {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let sequential = read_sequential(volumes, how);
    let (narrow, narrow_spans) = read(volumes, how, 0);
    let (wide, spans) = read(volumes, how, 1);
    let (declined, declined_spans) = read(volumes, how, NO_SUCH_GRANT);
    assert_eq!(narrow_spans, 0, "the narrow arm offered a range");
    assert!(spans >= 1 || !went_wide, "no worker read wide");
    assert!(
        declined_spans >= 1 || !went_wide,
        "no worker was offered a range to decline"
    );
    assert_eq!(wide.error, narrow.error, "the error, against the narrow");
    // A declined range is read as the narrow arm reads it, so the two say
    // the same of everything a case holds the wide arm to.
    assert_eq!(declined.error, narrow.error, "the declined arm's error");
    if against != Against::NarrowError {
        assert_eq!(declined.closes, narrow.closes, "the declined arm's closes");
        assert_eq!(
            declined.closed_writes(),
            narrow.closed_writes(),
            "the declined arm's bytes"
        );
    }
    let arms: &[(&str, &Said)] = match against {
        Against::Both => &[("narrow", &narrow), ("sequential", &sequential)],
        Against::Narrow => &[("narrow", &narrow)],
        Against::NarrowError => &[],
    };
    for (arm, other) in arms {
        assert_eq!(
            (&wide.error, &wide.closes),
            (&other.error, &other.closes),
            "the error and the closes, against the {arm}"
        );
        assert_eq!(
            wide.closed_writes(),
            other.closed_writes(),
            "every closed member's bytes, against the {arm}"
        );
    }
    // The knob arm (`RARKIT_JOB_WIDE_WRITE`), with the wide read at any
    // grant and with it declined: a clear written member read wide says
    // what the narrow pool says.
    let mut knobs = Vec::new();
    for (lanes, wide_write, written) in [
        (1, true, ALWAYS),
        (NO_SUCH_GRANT, true, ALWAYS),
        // A written member wide only beside another member, and never.
        (1, false, BESIDE),
        (1, true, BESIDE),
        (1, false, NEVER),
    ] {
        let (arm, _) = read_as(volumes, how, lanes, wide_write, written);
        assert_eq!(
            arm.error, narrow.error,
            "the error with lanes {lanes}, wide write {wide_write}, written rule {written}"
        );
        if against != Against::NarrowError {
            assert_eq!(
                (&arm.closes, arm.closed_writes()),
                (&narrow.closes, narrow.closed_writes()),
                "the closes and bytes with lanes {lanes}, wide write {wide_write}, written rule {written}"
            );
        }
        knobs.push(arm);
    }
    // The CUT arms (`read::handed`): in order and at once, whenever the
    // lanes allow, only beside another member, and from a grant no pool
    // makes (which a clear member's two readers still take).
    for (lanes, written, cut, when) in [
        (1, ALWAYS, Cut::InOrder, WHENEVER),
        (1, ALWAYS, Cut::AtOnce, WHENEVER),
        (1, BESIDE, Cut::InOrder, WHENEVER),
        (NO_SUCH_GRANT, ALWAYS, Cut::AtOnce, WHENEVER),
        // Cut only while alone: beside another member the worker reads as
        // it did before the cut, under either rule for the joined read.
        (1, ALWAYS, Cut::InOrder, ALONE),
        (1, BESIDE, Cut::AtOnce, ALONE),
    ] {
        let (arm, cut_ranges, _) = read_cut(volumes, how, lanes, written, cut, when);
        // A grant no pool makes cuts only a clear member, and a member is
        // alone only for part of a run.
        assert!(
            cut_ranges >= 1 || !cuts || lanes != 1 || when != WHENEVER,
            "no range was cut with lanes {lanes}, written rule {written}, {cut:?}, when {when}"
        );
        assert!(
            cut_ranges == 0 || !how.verify,
            "a member that is only verified was cut ({cut:?})"
        );
        assert_eq!(
            arm.error, narrow.error,
            "the error with lanes {lanes}, written rule {written}, {cut:?}, when {when}"
        );
        if against != Against::NarrowError {
            assert_eq!(
                (&arm.closes, arm.closed_writes()),
                (&narrow.closes, narrow.closed_writes()),
                "the closes and bytes with lanes {lanes}, written rule {written}, {cut:?}, when {when}"
            );
        }
        knobs.push(arm);
    }
    for said in [&sequential, &narrow, &wide, &declined]
        .into_iter()
        .chain(&knobs)
    {
        for (name, (_, _, prefix)) in &said.written {
            if !said.closes.iter().any(|c| &c.0 == name) {
                assert!(prefix, "{name}'s bytes are not a prefix of it");
            }
        }
    }
    wide
}

fn whole(said: &Said, written: bool) {
    assert_eq!(said.error, None);
    assert_eq!(said.closes.len(), MEMBERS.len());
    for ((name, len), close) in MEMBERS.iter().zip(&said.closes) {
        assert_eq!(close, &(name.to_string(), Some(true), *len as u64));
        if written {
            assert_eq!(
                said.written[*name],
                (*len, rarkit::checksum::crc32(&truth(name)), true),
                "{name}"
            );
        }
    }
}

/// `x` and `t` of an archive of several members, under `-p` and `-hp`.
#[test]
fn an_archive_of_members_reads_the_same_three_ways() {
    for headers in [false, true] {
        let set = set(false, headers);
        whole(&three_ways(&set, X, true, Against::Both), true);
        whole(&three_ways(&set, T, true, Against::Both), false);
        // A writer the caller says nothing about (`sink_is_file` unset).
        let plain = How {
            sink_is_file: None,
            ..X
        };
        whole(&three_ways(&set, plain, true, Against::Both), true);
    }
}

/// The same members over volumes that are no whole number of blocks,
/// every split member a job: the worker crosses each fragment the walk
/// sends it and the chain runs through them (SPEC-K 3.6.2, 3.7.4).
#[test]
fn a_volume_set_reads_the_same_three_ways() {
    for headers in [false, true] {
        let set = set(true, headers);
        whole(&three_ways(&set, X, true, Against::Both), true);
        whole(&three_ways(&set, T, true, Against::Both), false);
    }
}

/// A flipped ciphertext byte deep inside the first big member: its close says
/// the checksum failed, the other members' say it held, three ways.
#[test]
fn a_flipped_byte_fails_the_member_the_same_three_ways() {
    for split in [false, true] {
        let mut set = set(split, false);
        set[0][9 << 20] ^= 0x40;
        for how in [X, T] {
            let said = three_ways(&set, how, true, Against::Both);
            assert_eq!(said.error, None, "split {split}");
            let big = said.closes.iter().find(|c| c.0 == "Full.mkv").unwrap();
            assert_eq!(big.1, Some(false), "split {split}: a damaged big member");
            let extras = said.closes.iter().find(|c| c.0 == "Extras.mkv").unwrap();
            assert_eq!(extras.1, Some(true), "split {split}");
        }
    }
}

/// A flipped byte in a LATER fragment of a split big member, and in the last
/// volume's.
#[test]
fn a_flipped_byte_in_a_later_fragment_fails_the_same_three_ways() {
    let whole = set(true, false);
    for volume in [1, whole.len() - 1] {
        let mut set = whole.clone();
        let at = set[volume].len() / 2;
        set[volume][at] ^= 0x01;
        let said = three_ways(&set, X, true, Against::Both);
        let failed = said.closes.iter().filter(|c| c.1 != Some(true)).count();
        assert!(
            failed >= 1 || said.error.is_some(),
            "volume {volume}: a damaged fragment went unnoticed"
        );
    }
}

/// An archive cut inside the first big member: `Truncated`, naming it, and what
/// was written of it a prefix, three ways.
#[test]
fn an_archive_cut_inside_a_member_ends_the_same_three_ways() {
    let mut set = set(false, false);
    set[0].truncate((23 << 20) + 11);
    for how in [X, T] {
        let said = three_ways(&set, how, true, Against::Narrow);
        let error = said.error.expect("a cut archive is an error");
        assert!(error.contains("Truncated"), "{error}");
    }
}

/// A volume cut inside a split member, and a volume missing.
#[test]
fn a_cut_or_missing_volume_ends_the_same_three_ways() {
    let whole = set(true, false);
    let mut cut = whole.clone();
    let at = cut[1].len() - 100_000;
    cut[1].truncate(at);
    assert!(
        three_ways(&cut, X, false, Against::Both).error.is_some(),
        "a cut volume"
    );
    let gapped: Vec<Vec<u8>> = whole
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, v)| v.clone())
        .collect();
    assert!(
        three_ways(&gapped, X, false, Against::Both).error.is_some(),
        "a gapped set"
    );
}

/// The wrong password: refused the same way, and nothing read wide that
/// the narrow arm did not read.
#[test]
fn a_wrong_password_is_refused_the_same_three_ways() {
    for (split, headers) in [(false, false), (false, true), (true, false)] {
        let set = set(split, headers);
        let wrong = How {
            password: "wrong",
            ..X
        };
        let said = three_ways(&set, wrong, false, Against::Both);
        assert!(
            said.error.is_some() || said.closes.iter().all(|c| c.1 != Some(true)),
            "split {split} headers {headers}: a wrong password passed"
        );
    }
}

/// A writer that fills part way through the big member: the caller's error ends
/// the run three ways, and no arm wrote past the limit.
#[test]
fn a_refusing_writer_ends_the_same_three_ways() {
    let set = set(false, false);
    let limit = (18 << 20) + 1234;
    let full = How {
        limit: Some(limit),
        ..X
    };
    let said = three_ways(&set, full, true, Against::NarrowError);
    assert!(said.error.is_some(), "a full writer is an error");
    assert!(said.written.values().all(|w| w.0 <= limit));
}

/// A CLEAR stored member a worker only verifies is read wide too
/// (`concurrent::job_wide_clear`): `t` of the archive and of the volume
/// set, four ways. Written (`x`), it keeps its one worker, and no range is
/// offered at all.
#[test]
fn a_clear_set_verifies_the_same_and_is_written_on_one_worker() {
    for split in [false, true] {
        let set = clear_set(split);
        whole(&three_ways(&set, T, true, Against::Both), false);
        // With the cut off no range is offered; with it on the member is
        // cut, and says the same.
        whole(&three_ways_cut(&set, X, false, Against::Both, true), true);
        let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
        let (_, spans) = read(&set, X, 1);
        assert_eq!(spans, 0, "split {split}: a written clear member went wide");
        // Under the knob it does, and says the same (`three_ways` above
        // compared it).
        let (_, spans) = read_with(&set, X, 1, true);
        assert!(spans >= 1, "split {split}: the wide write arm read narrow");
    }
}

/// A flipped byte in a clear big member fails its checksum the same four ways,
/// in the archive and in a later fragment of the set.
#[test]
fn a_flipped_byte_in_a_clear_member_fails_the_same() {
    for split in [false, true] {
        let mut set = clear_set(split);
        let volume = if split { 1 } else { 0 };
        let at = set[volume].len() / 2;
        set[volume][at] ^= 0x08;
        let said = three_ways(&set, T, true, Against::Both);
        assert_eq!(said.error, None, "split {split}");
        let big = said.closes.iter().find(|c| c.0 == "Full.mkv").unwrap();
        assert_eq!(big.1, Some(false), "split {split}: a damaged big member");
    }
}

/// A clear archive cut inside the big member, and a clear set with a volume cut:
/// the same error four ways.
#[test]
fn a_cut_clear_set_ends_the_same() {
    let mut one = clear_set(false);
    one[0].truncate((23 << 20) + 11);
    let said = three_ways(&one, T, true, Against::Narrow);
    assert!(said.error.expect("a cut archive").contains("Truncated"));
    let mut cut = clear_set(true);
    let at = cut[1].len() - 100_000;
    cut[1].truncate(at);
    assert!(
        three_ways(&cut, T, false, Against::Both).error.is_some(),
        "a cut volume"
    );
}

/// What the cut is for: every write of a cut member but its first and its
/// last is one whole piece from a page-aligned buffer, in both orders,
/// clear and under a cipher, in one archive (a member alone on its worker,
/// its range in slices) and over volumes (a range a fragment, each brought
/// back to a multiple of the piece by one short write).
#[test]
fn a_cut_member_is_written_in_whole_aligned_pieces() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for (split, encrypted) in [(false, None), (false, Some(true)), (true, Some(false))] {
        let set = stored(split, encrypted);
        for cut in [Cut::InOrder, Cut::AtOnce] {
            let (said, cuts, calls) = read_cut(&set, X, 1, ALWAYS, cut, WHENEVER);
            whole(&said, true);
            assert!(
                cuts >= 1,
                "split {split} {encrypted:?} {cut:?}: nothing cut"
            );
            for name in ["Full.mkv", "Extras.mkv"] {
                let calls = &calls[name];
                let piece = calls.iter().map(|c| c.0).max().expect("writes");
                assert!(
                    piece.is_multiple_of(4096) && piece >= 64 * 1024,
                    "{name} split {split} {encrypted:?} {cut:?}: a piece of {piece}"
                );
                let whole = calls.iter().filter(|c| **c == (piece, true)).count();
                let total: usize = calls.iter().map(|c| c.0).sum();
                // Each range costs at most a short write either end, and
                // what a fragment leaves under the wide read's floor (16
                // MiB) is read the ordinary way, a buffer at a time.
                let ranges = if split { set.len() } else { 1 };
                let floor = if split { 16 << 20 } else { 0 };

                assert!(
                    whole * piece + ranges * 2 * piece + floor + (1 << 20) >= total,
                    "{name} split {split} {encrypted:?} {cut:?}: {whole} whole pieces of {piece} in {total} bytes, {} writes",
                    calls.len()
                );
                assert!(
                    calls.iter().all(|c| c.0 != piece || c.1),
                    "{name} split {split} {encrypted:?} {cut:?}: a whole piece off its page"
                );
            }
        }
    }
}

/// The caller's cancel flag, raised part way through the big member, ends the
/// run as `Cancelled` with the cut on in both orders, clear and under a
/// cipher, and what was written of each member is a prefix of it.
#[test]
fn a_cancel_ends_a_cut_member() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for encrypted in [None, Some(false)] {
        let set = stored(false, encrypted);
        let cancelled = How {
            cancel_after: Some((9 << 20) + 77),
            ..X
        };
        for cut in [Cut::Off, Cut::InOrder, Cut::AtOnce] {
            let (said, _, _) = read_cut(&set, cancelled, 1, ALWAYS, cut, WHENEVER);
            let error = said.error.expect("a cancelled run is an error");
            assert!(
                error.contains("Cancelled"),
                "{encrypted:?} {cut:?}: {error}"
            );
            assert!(
                said.written.values().all(|w| w.2),
                "{encrypted:?} {cut:?}: bytes that are not the member's"
            );
            let big = said.written["Full.mkv"].0;
            assert!(
                big < MEMBERS[0].1,
                "{encrypted:?} {cut:?}: the big member ran to its end"
            );
        }
    }
}

/// The WALK cuts its own encrypted stored member unless the caller says
/// the writer is NOT a file (`x` of a big member alone in its archive, or of a
/// split set, says nothing or says a file): the same bytes and closes as
/// with the cut off, in both orders, in whole aligned pieces. A clear
/// member is the seam's and is not cut, nor is any member whose writer is
/// said to be a stream (`p`).
#[test]
fn the_walk_cuts_its_own_encrypted_member() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let walk = |volumes: &[Vec<u8>], how: How, cut: Cut| {
        probe::set_stored_cut(
            Some(cut != Cut::Off),
            (cut != Cut::Off).then_some(cut == Cut::InOrder),
        );
        probe::set_stored_cut_cipher(Some(cut != Cut::Off));
        probe::reset_stored_cuts();
        let (said, calls) = read_walk(volumes, how);
        let cuts = probe::stored_cuts();
        probe::set_stored_cut_cipher(None);
        probe::set_stored_cut(None, None);
        (said, calls, cuts)
    };
    for (split, headers) in [(false, false), (false, true), (true, false)] {
        let set = set(split, headers);
        let (off, _, none) = walk(&set, X, Cut::Off);
        whole(&off, true);
        assert_eq!(none, 0, "split {split}: the cut is off");
        for cut in [Cut::InOrder, Cut::AtOnce] {
            let (on, calls, cuts) = walk(&set, X, cut);
            assert_eq!(on, off, "split {split} headers {headers} {cut:?}");
            assert!(
                cuts >= 1,
                "split {split} headers {headers} {cut:?}: nothing cut"
            );
            let big = &calls["Full.mkv"];
            let piece = big.iter().map(|c| c.0).max().expect("writes");
            assert!(piece.is_multiple_of(4096), "{cut:?}: a piece of {piece}");
            assert!(
                big.iter().all(|c| c.0 != piece || c.1),
                "split {split} {cut:?}: a whole piece off its page"
            );
            // Nothing said (`rarfast x` of a set that is not solid): cut.
            let unsaid = How {
                sink_is_file: None,
                ..X
            };
            let (plain, _, cuts) = walk(&set, unsaid, cut);
            assert_eq!(
                plain, off,
                "split {split} headers {headers} {cut:?}: unsaid"
            );
            assert!(cuts >= 1, "split {split} {cut:?}: nothing cut, unsaid");
            // A stream (`p`): the walk's wide read as before.
            let stream = How {
                sink_is_file: Some(false),
                ..X
            };
            let (plain, _, cuts) = walk(&set, stream, cut);
            whole(&plain, true);
            assert_eq!(cuts, 0, "cut for a writer said to be a stream");
        }
        // Damage inside the big member: the same failed close with the cut on.
        let mut damaged = set.clone();
        damaged[0][9 << 20] ^= 0x40;
        let (off, _, _) = walk(&damaged, X, Cut::Off);
        for cut in [Cut::InOrder, Cut::AtOnce] {
            let (on, _, _) = walk(&damaged, X, cut);
            assert_eq!(on, off, "damaged, split {split} {cut:?}");
        }
    }
    let clear = clear_set(false);
    let (said, _, cuts) = walk(&clear, X, Cut::InOrder);
    whole(&said, true);
    assert_eq!(cuts, 0, "a clear member on the walk is the seam's");
}

/// Cut only while ALONE (the macOS rule): a big member beside nothing but a
/// member the walk decodes itself is cut; with the rule at `Never` for the
/// joined read and a second big member in flight it is read on its worker,
/// and the answers are the narrow pool's either way.
#[test]
fn a_member_alone_is_cut_and_one_beside_another_is_not_required_to_be() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    // A big member and a member under the offload floor, which the walk
    // decodes itself: the big member is alone in the pool.
    let mut writer = Writer::new(WriteOptions {
        password: Some(Password::from(PASSWORD)),
        ..WriteOptions::default()
    })
    .expect("options");
    let (big, nfo) = (truth("Full.mkv"), truth(NFO.0));
    // The small member FIRST: the walk has decoded it before the big member
    // is dispatched, so the big member's first grant finds it alone whatever
    // the threads' timing.
    for (name, data) in [(NFO.0, &nfo), ("Full.mkv", &big)] {
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
    let mut one = Vec::new();
    writer.finish_into(&mut one).expect("finish");
    let set = vec![one];
    for cut in [Cut::InOrder, Cut::AtOnce] {
        let (said, cuts, _) = read_cut(&set, X, 1, BESIDE, cut, ALONE);
        assert_eq!(said.error, None, "{cut:?}");
        assert!(
            cuts >= 1,
            "{cut:?}: a big member alone in the pool was not cut"
        );
        assert_eq!(
            said.written["Full.mkv"],
            (big.len(), rarkit::checksum::crc32(&big), true),
            "{cut:?}"
        );
    }
}
