//! A CLEAR stored member checked by BLAKE2sp, read WIDE (`extract`'s
//! `b2sp_wide`, `RARKIT_B2SP_WIDE`, 1 Oct 2026): its pieces are read on
//! several threads and fed to the hasher in order by the thread that joins
//! them. It says and writes exactly what the ordinary loop says and writes,
//! which reads one buffer and then hashes it on one thread.
//!
//! It is the shipped default from 2 Oct 2026 (`the_default_reads_a_blake_
//! member_wide`). Each case reads a set with the knob OFF and ON, by the sequential
//! `extract` (the walk: `t`, and `p` to a writer that is no file) and by
//! `extract_parallel` (the pool, where a worker is the joining thread),
//! and compares the error, every member's close (the digest's verdict) and
//! every closed member's bytes. The ON arm is asserted to have read at
//! least one range wide, so two ordinary reads cannot pass for it; and the
//! arms the knob must NOT reach (a member written to a file, an encrypted
//! member, a CRC32 member) are asserted to have read none.
//!
//! The sets are this crate's own writer's, stored under BLAKE2sp: one
//! member, several in one archive, and the same over volumes whose size
//! is no whole number of the digest's 512-byte groups, so a fragment's
//! pieces start part way into a group and the hasher's own staging joins
//! them. The members are over the wide read's floor and are no whole
//! number of pieces or groups long.
//!
//! The knob is one word for the process, because a WORKER reads it, so
//! every test here holds [`KNOB`] while it reads.

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

const PASSWORD: &str = "b2wide";
/// No multiple of 512, so a fragment is no whole number of groups.
const PER: u64 = (20 << 20) + 7;

/// Two members over the wide floor (16 MiB), neither a whole number of
/// groups, and a short one between them.
const MEMBERS: [(&str, usize); 3] = [
    ("Full.mkv", (40 << 20) + 5),
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

/// Which driver reads.
#[derive(Clone, Copy, Debug, PartialEq)]
enum By {
    Walk,
    Pool,
}

/// One read with the knob as named; what it said, and how many ranges of
/// BLAKE2sp members were read wide. The caller holds [`KNOB`].
fn read(volumes: &[Vec<u8>], how: How, by: By, wide: bool) -> (Said, u64) {
    read_as(volumes, how, by, Some(wide))
}

/// [`read`], with the knob forced (`Some`) or left to the shipped default.
fn read_as(volumes: &[Vec<u8>], how: How, by: By, wide: Option<bool>) -> (Said, u64) {
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
    probe::set_b2sp_wide(wide);
    let before = probe::b2sp_wides();
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
    let ranges = probe::b2sp_wides() - before;
    probe::set_b2sp_wide(None);
    let error = outcome.err().map(|e| {
        format!(
            "{:?} member {:?} volume {:?}",
            e.kind(),
            e.member().map(|m| String::from_utf8_lossy(m).into_owned()),
            e.volume()
        )
    });
    let closes = sink.closes.into_inner().unwrap();
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

/// Off against on, by one driver. `went_wide` says whether the ON arm
/// must have read a range wide; where it must not, it must have read
/// NONE. Returns what the ON arm said.
fn both(volumes: &[Vec<u8>], how: How, by: By, went_wide: bool) -> Said {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let (off, off_ranges) = read(volumes, how, by, false);
    let (on, on_ranges) = read(volumes, how, by, true);
    assert_eq!(off_ranges, 0, "{by:?}: the knob off read a range wide");
    if went_wide {
        assert!(on_ranges >= 1, "{by:?}: the knob on read nothing wide");
    } else {
        assert_eq!(on_ranges, 0, "{by:?}: a range the knob must not reach");
    }
    assert_eq!(on, off, "{by:?}: wide against the ordinary loop");
    on
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

/// The SHIPPED DEFAULT, with nothing forced (and `RARKIT_B2SP_WIDE` unset,
/// as a test run has it): a clear stored member under BLAKE2sp is read
/// wide on `t` and `p`, says what the ordinary loop says, and a member
/// written to a file is not reached.
#[test]
fn the_default_reads_a_blake_member_wide() {
    if std::env::var_os("RARKIT_B2SP_WIDE").is_some() {
        return;
    }
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for (how, wide) in [(T, true), (P, true), (X, false)] {
        let (off, _) = read(&volumes, how, By::Walk, false);
        let (shipped, ranges) = read_as(&volumes, how, By::Walk, None);
        assert_eq!(ranges >= 1, wide, "the default read {ranges} ranges wide");
        assert_eq!(shipped, off, "the default against the ordinary loop");
        whole(&shipped, 1, !how.verify);
    }
}

/// One member alone, the walk: tested and printed wide, digest right.
#[test]
fn one_member_is_tested_and_printed_wide_by_the_walk() {
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    whole(&both(&volumes, T, By::Walk, true), 1, false);
    whole(&both(&volumes, P, By::Walk, true), 1, true);
}

/// Several members in one archive, by the walk (one at a time, each of the
/// large ones wide) and by the pool, where a worker joins its member's
/// pieces: at a width of eight a member alone in flight, or granted three
/// lanes, reads wide.
#[test]
fn several_members_agree_by_the_walk_and_by_the_pool() {
    let volumes = set(3, false, ChecksumKind::Blake2sp, false);
    whole(&both(&volumes, T, By::Walk, true), 3, false);
    whole(&both(&volumes, P, By::Walk, true), 3, true);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    // The pool: whether a worker is granted the lanes is the pool's own
    // timing, so the arms are held equal and the count is not asserted.
    let (off, _) = read(&volumes, T, By::Pool, false);
    let (on, _) = read(&volumes, T, By::Pool, true);
    assert_eq!(on, off);
    whole(&on, 3, false);
}

/// A volume set whose fragments are no whole number of groups: the walk
/// joins the fragments, each range's pieces start part way into a group,
/// and the digest is the member's own.
#[test]
fn a_volume_set_of_unaligned_fragments_keeps_the_digest() {
    let volumes = set(3, true, ChecksumKind::Blake2sp, false);
    whole(&both(&volumes, T, By::Walk, true), 3, false);
    whole(&both(&volumes, P, By::Walk, true), 3, true);
}

/// What the knob must not reach: a member written to a FILE (the seam's,
/// or a worker's own loop), an encrypted member (the overlapped cipher),
/// a CRC32 member (its own wide read, which feeds no hasher), and a width
/// of one.
#[test]
fn the_knob_reaches_only_a_clear_member_tested_or_printed() {
    let clear = set(1, false, ChecksumKind::Blake2sp, false);
    whole(&both(&clear, X, By::Walk, false), 1, true);
    whole(
        &both(&clear, How { width: 1, ..T }, By::Walk, false),
        1,
        false,
    );
    let encrypted = set(1, false, ChecksumKind::Blake2sp, true);
    whole(&both(&encrypted, T, By::Walk, false), 1, false);
    whole(&both(&encrypted, P, By::Walk, false), 1, true);
    let crc = set(1, false, ChecksumKind::Crc32, false);
    whole(&both(&crc, T, By::Walk, false), 1, false);
    whole(&both(&crc, P, By::Walk, false), 1, true);
}

/// A flipped byte, in the first piece, a middle one and the last bytes:
/// the digest refuses the member the same way wide and not.
#[test]
fn a_flipped_byte_is_refused_the_same_way() {
    let good = set(1, false, ChecksumKind::Blake2sp, false);
    let len = good[0].len();
    for at in [len / 50, len / 2, len - 600] {
        let mut bad = good.clone();
        bad[0][at] ^= 0x40;
        let said = both(&bad, T, By::Walk, true);
        assert_eq!(said.closes.len(), 1, "at {at}");
        assert_eq!(said.closes[0].1, Some(false), "at {at}: the verdict");
        let said = both(&bad, P, By::Walk, true);
        assert_eq!(said.closes[0].1, Some(false), "at {at}: printed");
    }
}

/// An archive cut inside the member, and a volume cut: the same error,
/// naming the same member and volume, wide and not.
#[test]
fn a_cut_archive_ends_the_same_way() {
    let mut one = set(1, false, ChecksumKind::Blake2sp, false);
    let cut = one[0].len() * 2 / 3;
    one[0].truncate(cut);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let (off, _) = read(&one, T, By::Walk, false);
    let (on, _) = read(&one, T, By::Walk, true);
    assert!(off.error.is_some(), "a cut archive is an error");
    assert_eq!(on, off);
    let mut volumes = set(3, true, ChecksumKind::Blake2sp, false);
    let cut = volumes[1].len() / 2;
    volumes[1].truncate(cut);
    let (off, _) = read(&volumes, T, By::Walk, false);
    let (on, _) = read(&volumes, T, By::Walk, true);
    assert!(off.error.is_some(), "a cut volume is an error");
    assert_eq!(on.error, off.error);
    assert_eq!(on.closes, off.closes);
}

/// A writer that fills part way and a raised cancel stop the read both
/// ways with the caller's own error, and what the member's writer holds
/// is a prefix of the member.
#[test]
fn a_refusing_writer_and_a_cancel_stop_both_ways() {
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for how in [
        How {
            limit: Some(9 << 20),
            ..P
        },
        How {
            cancel_after: Some(9 << 20),
            ..P
        },
    ] {
        let (off, _) = read(&volumes, how, By::Walk, false);
        let (on, _) = read(&volumes, how, By::Walk, true);
        assert!(off.error.is_some(), "the read stops");
        assert_eq!(on.error, off.error);
        assert_eq!(on.closes, off.closes);
    }
}

/// `RARKIT_B2SP_TEAM` (`extract::TeamRule`): the allowance a member's
/// hasher is armed with under each rule, read where the rule is applied,
/// and the digest's verdict the same under every one. The policy's figure
/// is the memory policy's own. `larger` (the shipped default, rule 0)
/// takes a wider read's width, stated or not, under the DEFAULT
/// WHOLE-PROCESS policy alone (what `rarfast` reads under with no `-mm`),
/// and never falls under the policy's figure; under a library caller's
/// policy and under a named budget it is the policy's figure, so a caller
/// that sets one worker keeps its CPU (SPEC-API 8.4.1). `width` is the
/// read's width alone.
#[test]
fn the_team_rule_arms_the_hasher_with_its_allowance() {
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    // The three policies: the default whole-process one, the library's
    // own default, and a named process budget.
    let process = rarkit::MemoryPolicy::process_default(0);
    let library = rarkit::MemoryPolicy::default();
    let named = rarkit::MemoryPolicy::for_process(256 << 20, 0);
    let one = rarkit::MemoryPolicy {
        max_workers: 1,
        ..library
    };
    for (memory, lifts) in [
        (process, true),
        (library, false),
        (named, false),
        (one, false),
    ] {
        let policy = memory.max_workers;
        let wide = policy + 5;
        // (rule, stated width, the allowance wanted; `None` is the read's own
        // default width, which is at least one and is the box's to say)
        for (rule, stated, want) in [
            (1u8, Some(3usize), Some(policy)),
            (1, None, Some(policy)),
            (2, Some(1), Some(policy)),
            (2, Some(wide), Some(if lifts { wide } else { policy })),
            (0, Some(1), Some(policy)),
            (0, Some(wide), Some(if lifts { wide } else { policy })),
            (3, Some(3), Some(3)),
            (3, Some(1), Some(1)),
            (2, None, None),
            (3, None, None),
        ] {
            struct Check(Vec<Option<bool>>);
            impl rarkit::Sink for Check {
                type Out = std::io::Sink;
                fn open(&mut self, _: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
                    Ok(Disposition::Verify)
                }
                fn close(
                    &mut self,
                    _: &MemberInfo<'_>,
                    _: Option<std::io::Sink>,
                    outcome: &MemberOutcome,
                ) -> Result<()> {
                    self.0.push(outcome.checksum_ok);
                    Ok(())
                }
            }
            struct Quiet;
            impl Progress for Quiet {}
            probe::set_b2sp_team(rule);
            probe::take_b2sp_allowance();
            let mut sink = Check(Vec::new());
            let options = ReadOptions::default()
                .with_workers(stated)
                .with_memory(memory);
            let outcome = extract(sources(&volumes), &options, &mut sink, &mut Quiet);
            let armed = probe::take_b2sp_allowance();
            probe::set_b2sp_team(0);
            assert!(outcome.is_ok(), "rule {rule} width {stated:?}");
            assert_eq!(sink.0, vec![Some(true)], "rule {rule} width {stated:?}");
            match want {
                Some(want) => assert_eq!(armed, want, "rule {rule} width {stated:?}"),
                // The default width: never under one, and under `larger`
                // never under the policy's figure.
                None => assert!(
                    armed >= if rule == 2 { policy } else { 1 },
                    "rule {rule} at the default width armed {armed}"
                ),
            }
        }
    }
}

/// Memory: the wide read holds its window, which is the policy's
/// read-ahead, and under a NAMED budget too small for two pieces of it
/// (8 MiB names a read-ahead of 128 KiB, one piece) there is no wide plan:
/// the member takes the ordinary loop with the knob on, and says the same.
/// At 64 MiB (a read-ahead of 1 MiB) it is read wide inside that window.
#[test]
fn a_named_small_budget_returns_to_the_ordinary_loop() {
    let volumes = set(1, false, ChecksumKind::Blake2sp, false);
    let small = How {
        budget: Some(8 << 20),
        ..T
    };
    whole(&both(&volumes, small, By::Walk, false), 1, false);
    let room = How {
        budget: Some(64 << 20),
        ..T
    };
    whole(&both(&volumes, room, By::Walk, true), 1, false);
}
