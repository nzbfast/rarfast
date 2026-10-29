//! A CLEAR stored member checked by BLAKE2sp that a POOL WORKER writes to
//! a file, CUT by that worker (`read::handed::cut_hashed_here`,
//! `RARKIT_B2SP_CUT`, 2 Oct 2026): one reader reads its ranges in order,
//! the member's hasher is fed every piece in stream order off the writing
//! thread (on the reader, or on one lane behind it), and the worker writes
//! whole aligned pieces. It says and writes exactly what the worker's own
//! loop says and writes, which reads, hashes and writes one buffer at a
//! time on one thread.
//!
//! Each case reads a set through `extract_parallel` with the knob OFF, ON
//! with the hasher on a lane and ON with it on the reader, and compares the
//! error, every member's close (the digest's verdict) and every closed
//! member's bytes. Where the big member is alone in the pool the ON arms are
//! asserted to have cut a range, so three ordinary reads cannot pass for
//! them; the arms the knob must NOT reach (a member only tested, an
//! encrypted member, a CRC32 member, the walk, a width of one) are asserted
//! to have cut none.
//!
//! THE WALK's own member is cut the same way under `RARKIT_B2SP_CUT_WALK`
//! (in place of the seam, whose source unit reads and hashes on one
//! thread): the last cases read through the sequential `extract` with that
//! knob on, against the same three arms.
//!
//! The sets are this crate's own writer's. The knobs are one word for the
//! process, because a WORKER reads them, so every test here holds [`KNOB`]
//! while it reads. The cut itself is forced on and its rule set to
//! `always`, so the test reads the same on every system (the cut's own
//! defaults are each system's: `read::handed`, `concurrent`).

#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, probe, ChecksumKind, Disposition, MemberInfo, MemberOutcome,
    MemberSpec, ParallelSink, Password, Payload, Progress, RangeSource, ReadOptions, Result,
    WriteMethod, WriteOptions, Writer,
};

static KNOB: Mutex<()> = Mutex::new(());

const PASSWORD: &str = "b2cut";
/// No multiple of 512, so a fragment is no whole number of groups.
const PER: u64 = (20 << 20) + 7;

/// A big member over the wide floor (16 MiB) and no whole number of groups
/// or pieces, an nfo under the pool's offload floor (so the big member is
/// ALONE in the pool and its lanes are its own), and two more members a
/// worker takes.
const MEMBERS: [(&str, usize); 4] = [
    ("Full.mkv", (40 << 20) + 5),
    ("Full.nfo", 4096),
    ("Sample.mkv", (1 << 20) + 9),
    ("Extras.mkv", (24 << 20) + 301),
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

fn truth(name: &str) -> Vec<u8> {
    let (at, (_, len)) = MEMBERS
        .iter()
        .enumerate()
        .find(|(_, (n, _))| *n == name)
        .expect("a member of the set");
    noise(91 + at as u64, *len)
}

/// The first `count` members stored under `checksum`, clear or encrypted,
/// in one archive or in volumes of [`PER`].
fn set(count: usize, split: bool, checksum: ChecksumKind, encrypted: bool) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum,
        volume_size: split.then_some(PER),
        password: encrypted.then(|| Password::from(PASSWORD)),
        ..WriteOptions::default()
    })
    .expect("options");
    let bytes: Vec<Vec<u8>> = MEMBERS[..count].iter().map(|(n, _)| truth(n)).collect();
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
    assert!(out.len() >= 2, "a set of {} volumes", out.len());
    out
}

type Written = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

/// A writer that refuses once its member holds `limit` bytes, and raises
/// `cancel` once it holds `cancel_after`.
struct Keep {
    name: String,
    written: Written,
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
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink {
    written: Written,
    closes: Mutex<Vec<(String, Option<bool>, u64)>>,
    how: How,
    cancel: Option<Arc<AtomicBool>>,
}

impl Sink {
    fn open_one(&self, member: &MemberInfo<'_>) -> Disposition<Keep> {
        if self.how.verify {
            return Disposition::Verify;
        }
        Disposition::Write(Keep {
            name: String::from_utf8_lossy(member.name).into_owned(),
            written: Arc::clone(&self.written),
            limit: self.how.limit,
            cancel: self.cancel.clone().zip(self.how.cancel_after),
        })
    }
    fn close_one(&self, member: &MemberInfo<'_>, outcome: &MemberOutcome) {
        self.closes.lock().unwrap().push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
            outcome.bytes,
        ));
    }
}

impl ParallelSink for Sink {
    type Out = Keep;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
        Ok(self.open_one(member))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Keep>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.close_one(member, outcome);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct Said {
    error: Option<String>,
    closes: Vec<(String, Option<bool>, u64)>,
    /// Each closed member's bytes: length, CRC32, and whether they are a
    /// prefix of the member's true bytes.
    written: BTreeMap<String, (usize, u32, bool)>,
}

#[derive(Clone, Copy)]
struct How {
    verify: bool,
    limit: Option<usize>,
    /// `Some(false)` is `p` (the writer is no file); `Some(true)` is `x`.
    sink_is_file: Option<bool>,
    cancel_after: Option<usize>,
    width: usize,
    /// A NAMED working limit, where the read is given one.
    budget: Option<u64>,
}

const T: How = How {
    verify: true,
    limit: None,
    sink_is_file: None,
    cancel_after: None,
    width: 8,
    budget: None,
};
const P: How = How {
    verify: false,
    sink_is_file: Some(false),
    ..T
};
const X: How = How {
    sink_is_file: Some(true),
    ..P
};

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// Whether the walk's own cut (`RARKIT_B2SP_CUT_WALK`) is on for the
/// reads that follow; set and cleared by [`walk_cut`], under [`KNOB`].
static WALK: AtomicBool = AtomicBool::new(false);

/// Run `f` with the walk's own cut on. The caller holds [`KNOB`].
fn walk_cut<T>(f: impl FnOnce() -> T) -> T {
    WALK.store(true, Ordering::SeqCst);
    let out = f();
    WALK.store(false, Ordering::SeqCst);
    out
}

/// Which driver reads.
#[derive(Clone, Copy, Debug, PartialEq)]
enum By {
    Walk,
    Pool,
}

/// The knob's three arms.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Cut {
    Off,
    Lane,
    Reader,
}

/// One read with the knob as named; what it said, and how many ranges of
/// BLAKE2sp members a worker cut. The caller holds [`KNOB`].
fn read(volumes: &[Vec<u8>], how: How, by: By, cut: Cut) -> (Said, u64) {
    let cancel = how.cancel_after.map(|_| Arc::new(AtomicBool::new(false)));
    let sink = Sink {
        written: Arc::default(),
        closes: Mutex::default(),
        how,
        cancel: cancel.clone(),
    };
    let mut options = ReadOptions::default()
        .with_workers(Some(how.width))
        .with_sink_is_file(how.sink_is_file)
        .with_password(Some(Password::from(PASSWORD)))
        .with_cancel(cancel);
    if let Some(limit) = how.budget {
        options = options.with_memory(rarkit::MemoryPolicy::from_limit(limit));
    }
    // The cut a CRC32 member takes, on and whenever the lanes allow, and
    // the written member not read wide instead: every system's test.
    probe::set_stored_cut(Some(true), None);
    probe::set_stored_cut_when(1);
    probe::set_job_wide_write(Some(false));
    probe::set_job_wide_written(1);
    probe::set_b2sp_cut(Some(cut != Cut::Off), cut == Cut::Lane);
    probe::set_b2sp_cut_walk(Some(WALK.load(Ordering::SeqCst)));
    probe::reset_b2sp_cuts();
    let outcome = match by {
        By::Pool => extract_parallel(sources(volumes), &options, &sink, how.width),
        By::Walk => {
            struct Seq<'a>(&'a Sink);
            impl rarkit::Sink for Seq<'_> {
                type Out = Keep;
                fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
                    Ok(self.0.open_one(member))
                }
                fn close(
                    &mut self,
                    member: &MemberInfo<'_>,
                    _out: Option<Keep>,
                    outcome: &MemberOutcome,
                ) -> Result<()> {
                    self.0.close_one(member, outcome);
                    Ok(())
                }
            }
            struct Quiet;
            impl Progress for Quiet {}
            extract(sources(volumes), &options, &mut Seq(&sink), &mut Quiet)
        }
    };
    let ranges = probe::b2sp_cuts();
    probe::set_b2sp_cut(None, false);
    probe::set_b2sp_cut_walk(None);
    probe::set_stored_cut(None, None);
    probe::set_stored_cut_when(0);
    probe::set_job_wide_write(None);
    probe::set_job_wide_written(0);
    let error = outcome.err().map(|e| {
        format!(
            "{:?} member {:?} volume {:?}",
            e.kind(),
            e.member().map(|m| String::from_utf8_lossy(m).into_owned()),
            e.volume()
        )
    });
    let mut closes = sink.closes.into_inner().unwrap();
    closes.sort();
    let written = sink
        .written
        .lock()
        .unwrap()
        .iter()
        .filter(|(n, _)| closes.iter().any(|c| &c.0 == *n))
        .map(|(n, b)| {
            let t = truth(n);
            let prefix = b.len() <= t.len() && b[..] == t[..b.len()];
            (n.clone(), (b.len(), rarkit::checksum::crc32(b), prefix))
        })
        .collect();
    (
        Said {
            error,
            closes,
            written,
        },
        ranges,
    )
}

/// Whether the ON arms must have cut a range, must have cut none, or may
/// have (the pool's own timing decides a member's lanes).
#[derive(Clone, Copy, PartialEq)]
enum Reached {
    Yes,
    No,
    Maybe,
}

/// Off against both placements, by one driver. Returns what the lane arm
/// said. The caller holds [`KNOB`].
fn three(volumes: &[Vec<u8>], how: How, by: By, reached: Reached) -> Said {
    let (off, off_ranges) = read(volumes, how, by, Cut::Off);
    assert_eq!(off_ranges, 0, "{by:?}: the knob off cut a range");
    let mut said = None;
    for cut in [Cut::Lane, Cut::Reader] {
        let (on, ranges) = read(volumes, how, by, cut);
        match reached {
            Reached::Yes => assert!(ranges >= 1, "{by:?} {cut:?}: the knob on cut nothing"),
            Reached::No => assert_eq!(ranges, 0, "{by:?} {cut:?}: a range the knob must not reach"),
            Reached::Maybe => {}
        }
        assert_eq!(
            on, off,
            "{by:?} {cut:?}: the cut against the worker's own loop"
        );
        said.get_or_insert(on);
    }
    said.expect("two arms")
}

/// Every member closed with its digest right and, where it was written,
/// every byte its own.
fn whole(said: &Said, count: usize, written: bool) {
    assert_eq!(said.error, None);
    assert_eq!(said.closes.len(), count);
    for (name, ok, bytes) in &said.closes {
        assert_eq!(*ok, Some(true), "{name}: the digest's verdict");
        assert_eq!(*bytes as usize, truth(name).len(), "{name}: bytes");
    }
    if written {
        assert_eq!(said.written.len(), count);
        for (name, (len, crc, prefix)) in &said.written {
            let t = truth(name);
            assert!(*prefix && *len == t.len(), "{name}: the bytes written");
            assert_eq!(*crc, rarkit::checksum::crc32(&t), "{name}: their CRC32");
        }
    }
}

/// The big member beside its nfo: the nfo stays on the walk, so the big
/// member is alone in the pool, its worker is granted the lanes, and both
/// placements of the hasher cut it and say what the worker's own loop says.
#[test]
fn a_big_member_beside_its_nfo_is_cut_by_its_worker() {
    let volumes = set(2, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    whole(&three(&volumes, X, By::Pool, Reached::Yes), 2, true);
    // A writer the caller names no cost class for is a pool worker's too.
    let unsaid = How {
        sink_is_file: None,
        ..X
    };
    whole(&three(&volumes, unsaid, By::Pool, Reached::Yes), 2, true);
}

/// Several members in flight: whether each is granted its lanes is the
/// pool's own timing, so the arms are held equal and the count is not
/// asserted.
#[test]
fn several_members_in_flight_agree() {
    let volumes = set(4, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..3 {
        whole(&three(&volumes, X, By::Pool, Reached::Maybe), 4, true);
    }
}

/// A volume set whose fragments are no whole number of groups or pieces:
/// a split member a worker takes over its fragment list is cut a fragment
/// at a time, each fragment's own packed CRC32 judged from the pieces, and
/// the digest is the member's own.
#[test]
fn a_volume_set_of_unaligned_fragments_keeps_the_digest() {
    let volumes = set(4, true, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    whole(&three(&volumes, X, By::Pool, Reached::Maybe), 4, true);
}

/// What the knob must not reach: a member that is only tested, an
/// encrypted member, a CRC32 member (its own cut, which feeds no hasher),
/// the walk's own member, and a width of one.
#[test]
fn the_knob_reaches_only_a_clear_member_a_worker_writes() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let clear = set(2, false, ChecksumKind::Blake2sp, false);
    whole(&three(&clear, T, By::Pool, Reached::No), 2, false);
    whole(&three(&clear, X, By::Walk, Reached::No), 2, true);
    whole(
        &three(&clear, How { width: 1, ..X }, By::Pool, Reached::No),
        2,
        true,
    );
    let encrypted = set(2, false, ChecksumKind::Blake2sp, true);
    whole(&three(&encrypted, X, By::Pool, Reached::No), 2, true);
    let crc = set(2, false, ChecksumKind::Crc32, false);
    whole(&three(&crc, X, By::Pool, Reached::No), 2, true);
}

/// A flipped byte, in the first piece, a middle one and the last bytes of
/// the big member: the digest refuses the member the same way cut and not,
/// and the bytes written are the same.
#[test]
fn a_flipped_byte_is_refused_the_same_way() {
    let good = set(2, false, ChecksumKind::Blake2sp, false);
    let big = truth("Full.mkv").len();
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for at in [big / 50, big / 2, big - 600] {
        let mut bad = good.clone();
        bad[0][at] ^= 0x40;
        let said = three(&bad, X, By::Pool, Reached::Yes);
        let big = said
            .closes
            .iter()
            .find(|c| c.0 == "Full.mkv")
            .expect("the big member closes");
        assert_eq!(big.1, Some(false), "at {at}: the verdict");
    }
}

/// An archive cut inside the big member, and a volume cut: the same error,
/// naming the same member and volume, cut and not.
#[test]
fn a_cut_archive_ends_the_same_way() {
    let mut one = set(1, false, ChecksumKind::Blake2sp, false);
    let cut = one[0].len() * 2 / 3;
    one[0].truncate(cut);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let (off, _) = read(&one, X, By::Pool, Cut::Off);
    assert!(off.error.is_some(), "a cut archive is an error");
    for arm in [Cut::Lane, Cut::Reader] {
        let (on, _) = read(&one, X, By::Pool, arm);
        assert_eq!(on.error, off.error, "{arm:?}");
        assert_eq!(on.closes, off.closes, "{arm:?}");
    }
    let mut volumes = set(4, true, ChecksumKind::Blake2sp, false);
    let cut = volumes[1].len() / 2;
    volumes[1].truncate(cut);
    let (off, _) = read(&volumes, X, By::Pool, Cut::Off);
    assert!(off.error.is_some(), "a cut volume is an error");
    for arm in [Cut::Lane, Cut::Reader] {
        let (on, _) = read(&volumes, X, By::Pool, arm);
        assert_eq!(on.error, off.error, "{arm:?}");
    }
}

/// A writer that fills part way and a raised cancel stop the read every
/// way with the caller's own error, and what the member's writer holds is
/// a prefix of the member.
#[test]
fn a_refusing_writer_and_a_cancel_stop_every_way() {
    let volumes = set(2, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for how in [
        How {
            limit: Some(9 << 20),
            ..X
        },
        How {
            cancel_after: Some(9 << 20),
            ..X
        },
    ] {
        let (off, _) = read(&volumes, how, By::Pool, Cut::Off);
        assert!(off.error.is_some(), "the read stops");
        for arm in [Cut::Lane, Cut::Reader] {
            let (on, _) = read(&volumes, how, By::Pool, arm);
            assert_eq!(on.error, off.error, "{arm:?}");
            for (name, (_, _, prefix)) in &on.written {
                assert!(*prefix, "{arm:?} {name}: a prefix of the member");
            }
        }
    }
}

/// A host that will start no more threads: with each allowance of scoped
/// starts from none upward, the cut runs on the threads it has (no lane:
/// the reader hashes; no reader: the worker reads between its writes) and
/// says what it says with every thread.
#[test]
fn a_host_out_of_threads_reads_the_same() {
    let volumes = set(2, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let (want, _) = read(&volumes, X, By::Pool, Cut::Off);
    whole(&want, 2, true);
    for allowed in 0..6 {
        for arm in [Cut::Lane, Cut::Reader] {
            probe::allow_spawns(Some(allowed));
            let (on, _) = read(&volumes, X, By::Pool, arm);
            probe::allow_spawns(None);
            assert_eq!(on, want, "{arm:?} with {allowed} starts allowed");
        }
    }
}

/// Memory: the cut reads inside the member's window, which is the
/// policy's read-ahead. Under a NAMED budget too small for two pieces of
/// it (8 MiB names a read-ahead of 128 KiB) there is no plan and the
/// member takes the worker's own loop with the knob on; at 64 MiB (a
/// read-ahead of 1 MiB) it is cut inside that window.
#[test]
fn a_named_budget_bounds_the_cut() {
    let volumes = set(2, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let small = How {
        budget: Some(8 << 20),
        ..X
    };
    whole(&three(&volumes, small, By::Pool, Reached::No), 2, true);
    let room = How {
        budget: Some(64 << 20),
        ..X
    };
    whole(&three(&volumes, room, By::Pool, Reached::Yes), 2, true);
}

/// THE WALK's own member, with `RARKIT_B2SP_CUT_WALK` on: the lone big
/// member and the big member beside its nfo are cut on the walking thread, under a writer
/// the caller calls a file and under one it says nothing of, with both
/// placements of the hasher, and say what the seam says.
#[test]
fn the_walk_cuts_its_own_member() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    walk_cut(|| {
        for count in [1, 2] {
            let volumes = set(count, false, ChecksumKind::Blake2sp, false);
            whole(&three(&volumes, X, By::Walk, Reached::Yes), count, true);
            let unsaid = How {
                sink_is_file: None,
                ..X
            };
            whole(
                &three(&volumes, unsaid, By::Walk, Reached::Yes),
                count,
                true,
            );
        }
    });
}

/// What the walk's cut must not reach: a writer the caller says is a
/// stream (`p`), a member only tested, an encrypted member, a CRC32 member
/// and a width of one; and with the walk's knob OFF, the walk's own member
/// whatever the pool's knob says.
#[test]
fn the_walks_cut_reaches_only_a_clear_member_written_to_a_file() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let clear = set(2, false, ChecksumKind::Blake2sp, false);
    whole(&three(&clear, X, By::Walk, Reached::No), 2, true);
    walk_cut(|| {
        let stream = How {
            sink_is_file: Some(false),
            ..X
        };
        whole(&three(&clear, stream, By::Walk, Reached::No), 2, true);
        whole(&three(&clear, T, By::Walk, Reached::No), 2, false);
        whole(
            &three(&clear, How { width: 1, ..X }, By::Walk, Reached::No),
            2,
            true,
        );
        let encrypted = set(2, false, ChecksumKind::Blake2sp, true);
        whole(&three(&encrypted, X, By::Walk, Reached::No), 2, true);
        let crc = set(2, false, ChecksumKind::Crc32, false);
        whole(&three(&crc, X, By::Walk, Reached::No), 2, true);
    });
}

/// A member SPLIT across volumes is left to the seam by the walk, whose
/// source reads on across a fragment's end (the cut would start its
/// reader and hasher again at every fragment): no range of it is cut, and
/// it says what it said before.
#[test]
fn the_walk_leaves_a_member_split_across_volumes_to_the_seam() {
    let volumes = set(1, true, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    walk_cut(|| whole(&three(&volumes, X, By::Walk, Reached::No), 1, true));
}

/// The walk's cut under damage and refusal: a flipped byte in a first, a
/// middle and a last piece, a cut archive, a writer that fills part way
/// and a raised cancel each end as the seam ends them.
#[test]
fn the_walks_cut_fails_as_the_seam_fails() {
    let good = set(1, false, ChecksumKind::Blake2sp, false);
    let big = truth("Full.mkv").len();
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    walk_cut(|| {
        for at in [big / 50, big / 2, big - 600] {
            let mut bad = good.clone();
            bad[0][at] ^= 0x40;
            let said = three(&bad, X, By::Walk, Reached::Yes);
            assert_eq!(said.closes[0].1, Some(false), "at {at}: the verdict");
        }
        let mut cut = good.clone();
        let at = cut[0].len() * 2 / 3;
        cut[0].truncate(at);
        let (off, _) = read(&cut, X, By::Walk, Cut::Off);
        assert!(off.error.is_some(), "a cut archive is an error");
        for arm in [Cut::Lane, Cut::Reader] {
            let (on, _) = read(&cut, X, By::Walk, arm);
            assert_eq!(on.error, off.error, "{arm:?}");
            assert_eq!(on.closes, off.closes, "{arm:?}");
        }
        for how in [
            How {
                limit: Some(9 << 20),
                ..X
            },
            How {
                cancel_after: Some(9 << 20),
                ..X
            },
        ] {
            let (off, _) = read(&good, how, By::Walk, Cut::Off);
            assert!(off.error.is_some(), "the read stops");
            for arm in [Cut::Lane, Cut::Reader] {
                let (on, _) = read(&good, how, By::Walk, arm);
                assert_eq!(on.error, off.error, "{arm:?}");
                for (name, (_, _, prefix)) in &on.written {
                    assert!(*prefix, "{arm:?} {name}: a prefix of the member");
                }
            }
        }
    });
}

/// The walk's cut on a host that will start no more threads, at every
/// allowance from none, and under a named budget: the same bytes and
/// verdicts, and no plan under a budget too small for two pieces.
#[test]
fn the_walks_cut_keeps_to_its_threads_and_its_budget() {
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    walk_cut(|| {
        let (want, _) = read(&volumes, X, By::Walk, Cut::Off);
        whole(&want, 1, true);
        for allowed in 0..4 {
            for arm in [Cut::Lane, Cut::Reader] {
                probe::allow_spawns(Some(allowed));
                let (on, _) = read(&volumes, X, By::Walk, arm);
                probe::allow_spawns(None);
                assert_eq!(on, want, "{arm:?} with {allowed} starts allowed");
            }
        }
        let small = How {
            budget: Some(8 << 20),
            ..X
        };
        whole(&three(&volumes, small, By::Walk, Reached::No), 1, true);
        let room = How {
            budget: Some(64 << 20),
            ..X
        };
        whole(&three(&volumes, room, By::Walk, Reached::Yes), 1, true);
    });
}
