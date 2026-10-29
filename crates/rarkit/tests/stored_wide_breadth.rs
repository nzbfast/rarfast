//! The wide read's BREADTH RULE (`read::wide`, `RARKIT_WIDE_BREADTH`, 2 Oct
//! 2026): a stored member read wide at a width the caller did NOT state
//! keeps no more readers at work than the rule's cores (the physical
//! cores, or the fast ones) WHILE ITS READERS RUN, and it says and writes
//! exactly what it says and writes with the rule off. Readers that wait on
//! their source are not held, and a STATED width is the caller's word.
//!
//! No output byte shows how many readers worked at once, so each case
//! reads the decisions that put a hold on and the most readers at work
//! under one (`probe::take_wide_held`), states the machine to the rule
//! (`probe::set_wide_cores`) so the same assertion holds on a laptop, a 16
//! thread box and a 96 core one, and states what the readers say of
//! themselves (`probe::set_wide_running`), because whether a reader had
//! the CPU is the test machine's load and not the engine's doing. The arms
//! are compared by the error, every member's close and every member's
//! bytes, by the sequential `extract` (the walk: `t`, and `p` to a writer
//! that is no file) and by `extract_parallel` (the pool).
//!
//! The sets are this crate's own writer's, stored under CRC32: two members
//! over the wide read's floor with a short one between them, in one
//! archive and over volumes, clear and encrypted (whose pieces are
//! deciphered on the readers). They are read at an 8 MiB read-ahead, so
//! the plan has eight readers or more on every system.
//!
//! The rule, the machine and the readers' word are one word each for the
//! process, because a WORKER reads them, so every test here holds [`KNOB`]
//! while it reads.

#![cfg(all(feature = "test-support", feature = "parallel"))]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, probe, ChecksumKind, Disposition, MemberInfo, MemberOutcome,
    MemberSpec, ParallelSink, Password, Payload, Progress, RangeSource, ReadOptions, Result,
    WriteMethod, WriteOptions, Writer,
};

static KNOB: Mutex<()> = Mutex::new(());

const PASSWORD: &str = "breadth";
const PER: u64 = (20 << 20) + 7;

/// Two members over the wide floor (16 MiB), neither a whole number of
/// pieces, and a short one between them.
const MEMBERS: [(&str, usize); 3] = [
    ("Full.mkv", (72 << 20) + 5),
    ("Sample.mkv", (1 << 20) + 9),
    ("Extras.mkv", (48 << 20) + 301),
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
    noise(17 + at as u64, *len)
}

/// The set, stored under CRC32: in one archive or in volumes of [`PER`],
/// clear or encrypted.
fn set(split: bool, encrypted: bool) -> Vec<Vec<u8>> {
    set_under(split, encrypted, ChecksumKind::Crc32)
}

/// [`set`] under a stated checksum.
fn set_under(split: bool, encrypted: bool, checksum: ChecksumKind) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum,
        volume_size: split.then_some(PER),
        password: encrypted.then(|| Password::from(PASSWORD)),
        ..WriteOptions::default()
    })
    .expect("options");
    let bytes: Vec<Vec<u8>> = MEMBERS.iter().map(|(n, _)| truth(n)).collect();
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

impl Sink {
    fn open_one(&self, member: &MemberInfo<'_>) -> Disposition<Keep> {
        if self.verify {
            return Disposition::Verify;
        }
        Disposition::Write(Keep {
            name: String::from_utf8_lossy(member.name).into_owned(),
            written: Arc::clone(&self.written),
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
    /// Each member's bytes: length and CRC32.
    written: BTreeMap<String, (usize, u32)>,
}

/// Which driver reads.
#[derive(Clone, Copy, Debug, PartialEq)]
enum By {
    Walk,
    Pool,
}

/// How a read is asked for: tested or printed, by which driver, at a width
/// stated or not.
#[derive(Clone, Copy, Debug)]
struct How {
    verify: bool,
    by: By,
    stated: Option<usize>,
}

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// What the breadth rule did in one read: the decisions that put a hold
/// on, and the most readers at work under one.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Held {
    decisions: u64,
    most_out: usize,
}

/// One read under `rule` on a machine stated as `cores` (physical, fast),
/// its readers saying they ran (`true`) or waited on the source (`false`):
/// what it said, and what the rule did. The caller holds [`KNOB`].
fn read(
    volumes: &[Vec<u8>],
    how: How,
    rule: &str,
    cores: (usize, Option<usize>),
    running: bool,
) -> (Said, Held) {
    read_under(volumes, how, rule, cores, running, 8 << 20)
}

/// [`read`] under a stated read-ahead.
fn read_under(
    volumes: &[Vec<u8>],
    how: How,
    rule: &str,
    cores: (usize, Option<usize>),
    running: bool,
    read_ahead: u64,
) -> (Said, Held) {
    let sink = Sink {
        written: Arc::default(),
        closes: Mutex::default(),
        verify: how.verify,
    };
    let memory = rarkit::MemoryPolicy {
        read_ahead,
        ..rarkit::MemoryPolicy::default()
    };
    let options = ReadOptions::default()
        .with_workers(how.stated)
        .with_memory(memory)
        .with_sink_is_file(Some(false))
        .with_password(Some(Password::from(PASSWORD)));
    probe::set_wide_breadth(Some(rule));
    probe::set_wide_cores(Some(cores));
    probe::set_wide_running(Some(running));
    let _ = probe::take_wide_held();
    let outcome = match how.by {
        By::Pool => extract_parallel(
            sources(volumes),
            &options,
            &sink,
            options.read_width().max(2),
        ),
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
    let (decisions, most_out) = probe::take_wide_held();
    probe::set_wide_breadth(None);
    probe::set_wide_cores(None);
    probe::set_wide_running(None);
    let error = outcome.err().map(|e| format!("{:?}", e.kind()));
    let mut closes = sink.closes.into_inner().unwrap();
    closes.sort();
    let written = sink
        .written
        .lock()
        .unwrap()
        .iter()
        .map(|(n, b)| (n.clone(), (b.len(), rarkit::checksum::crc32(b))))
        .collect();
    (
        Said {
            error,
            closes,
            written,
        },
        Held {
            decisions,
            most_out,
        },
    )
}

/// Every member closed with its checksum right and, where it was written,
/// every byte its own.
fn whole(said: &Said, written: bool) {
    assert_eq!(said.error, None);
    assert_eq!(said.closes.len(), MEMBERS.len());
    for (name, ok, bytes) in &said.closes {
        assert_eq!(*ok, Some(true), "{name}: the checksum's verdict");
        assert_eq!(*bytes as usize, truth(name).len(), "{name}: bytes");
    }
    if written {
        assert_eq!(said.written.len(), MEMBERS.len());
        for (name, (len, crc)) in &said.written {
            let t = truth(name);
            assert_eq!(*len, t.len(), "{name}: the bytes written");
            assert_eq!(*crc, rarkit::checksum::crc32(&t), "{name}: their CRC32");
        }
    }
}

const NONE: Held = Held {
    decisions: 0,
    most_out: 0,
};

/// The rule off against the rule on, on a machine of `cores`, the readers
/// saying what `running` says: the same words and bytes, whole, and no
/// hold with the rule off. Returns what the rule did when on.
fn both(
    volumes: &[Vec<u8>],
    how: How,
    rule: &str,
    cores: (usize, Option<usize>),
    running: bool,
) -> Held {
    let (off, off_held) = read(volumes, how, "width", cores, running);
    let (on, on_held) = read(volumes, how, rule, cores, running);
    assert_eq!(off_held, NONE, "{how:?}: a hold with the rule off");
    assert_eq!(on, off, "{how:?} {rule}: the rule against the width");
    whole(&on, !how.verify);
    on_held
}

const T: How = How {
    verify: true,
    by: By::Walk,
    stated: None,
};
const P: How = How { verify: false, ..T };

/// Whether this machine's own width gives the plan more readers than
/// `most`, which is where a hold has something to keep.
fn wider_than(most: usize) -> bool {
    ReadOptions::default().read_width() > most
}

/// An unstated width on a machine of three physical cores, the readers
/// running: the walk keeps no more than three readers of a large member
/// at work once the hold is on, and says and writes what the rule off does.
#[test]
fn no_more_running_readers_are_at_work_than_the_cores() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let volumes = set(false, false);
    for how in [T, P] {
        let held = both(&volumes, how, "cores", (3, None), true);
        if wider_than(3) {
            assert!(
                held.decisions >= 1 && held.most_out >= 1,
                "{how:?}: no hold was put on: {held:?}"
            );
            assert!((1..=3).contains(&held.most_out), "{how:?}: {held:?}");
        }
    }
}

/// Readers that WAIT on their source are not held: the range stays at its
/// width, as with the rule off.
#[test]
fn waiting_readers_are_not_held() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let volumes = set(false, false);
    for how in [T, P] {
        assert_eq!(
            both(&volumes, how, "cores", (3, None), false),
            NONE,
            "{how:?}"
        );
    }
}

/// The fast cores, where the machine names them: two of eight here; and
/// the physical cores where it names none.
#[test]
fn the_fast_rule_holds_to_the_fast_cores() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let volumes = set(false, false);
    let held = both(&volumes, T, "fast", (8, Some(2)), true);
    if wider_than(2) {
        assert!(
            held.decisions >= 1 && (1..=2).contains(&held.most_out),
            "{held:?}"
        );
    }
    let held = both(&volumes, T, "fast", (3, None), true);
    if wider_than(3) {
        assert!(
            held.decisions >= 1 && (1..=3).contains(&held.most_out),
            "{held:?}"
        );
    }
}

/// A STATED width is the caller's word: no hold under any rule, whatever
/// the readers say.
#[test]
fn a_stated_width_is_not_held() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let volumes = set(false, false);
    for stated in [1usize, 2, 4, 8] {
        let how = How {
            stated: Some(stated),
            ..T
        };
        assert_eq!(
            both(&volumes, how, "cores", (1, None), true),
            NONE,
            "{stated}"
        );
        assert_eq!(
            both(&volumes, how, "fast", (8, Some(1)), true),
            NONE,
            "{stated}"
        );
    }
}

/// A volume set, whose member carries its hold from fragment to fragment,
/// and the pool, where a worker reads its member wide: the same words and
/// bytes under the rule, and never more readers at work than the cores.
#[test]
fn a_volume_set_and_the_pool_agree_under_the_rule() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let volumes = set(true, false);
    for how in [T, P] {
        let held = both(&volumes, how, "cores", (3, None), true);
        assert!(held.most_out <= 3, "{how:?}: {held:?}");
        if wider_than(3) {
            assert!(
                held.decisions >= 1 && held.most_out >= 1,
                "{how:?}: no hold was put on: {held:?}"
            );
        }
    }
    let one = set(false, false);
    for verify in [true, false] {
        let how = How {
            verify,
            by: By::Pool,
            stated: None,
        };
        // Whether a worker is granted the lanes is the pool's own timing,
        // so only the ceiling is asserted.
        let held = both(&one, how, "cores", (3, None), true);
        assert!(held.most_out <= 3, "{how:?}: {held:?}");
    }
}

/// An ENCRYPTED stored member, deciphered piece by piece on its readers:
/// the same words and bytes with fewer of them at work at once.
#[test]
fn an_encrypted_member_is_held_as_a_clear_one_is() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    for split in [false, true] {
        let volumes = set(split, true);
        for how in [T, P] {
            let held = both(&volumes, how, "cores", (3, None), true);
            assert!(held.most_out <= 3, "{how:?}: {held:?}");
            if wider_than(3) {
                assert!(
                    held.decisions >= 1 && held.most_out >= 1,
                    "{how:?}: no hold was put on: {held:?}"
                );
            }
        }
    }
}

/// A CLEAR member under BLAKE2sp, read wide with its pieces fed to the
/// hasher in order by the joining thread: the same digest's verdict and
/// the same bytes with fewer readers at work.
///
/// **On macOS a tested or printed member of this kind plans pieces of
/// 4 MiB first** (`read::wide::plan_hashed`), which moves two things this
/// row turns on. Under this file's 8 MiB of read-ahead its plan is two
/// readers, and the rule never holds a plan under two, so there the set
/// is asked only that no more than the cores are at work. And the rule
/// decides on thirty-two pieces, which is 128 MiB of a member in pieces
/// of 4 MiB where it was 32 MiB in pieces of one: a member under that
/// length is read at its plan's own readers and no decision is made. So
/// the hold itself is shown on one member of 192 MiB under a read-ahead
/// of 16 MiB, four readers against a rule of two cores. The window is the
/// readers times the piece and is the read-ahead it was given throughout.
#[test]
fn a_blake2sp_member_is_held_as_a_crc32_one_is() {
    let _knob = KNOB.lock().unwrap_or_else(|e| e.into_inner());
    let four_first = cfg!(target_os = "macos");
    for split in [false, true] {
        let volumes = set_under(split, false, ChecksumKind::Blake2sp);
        for how in [T, P] {
            let held = both(&volumes, how, "cores", (3, None), true);
            assert!(held.most_out <= 3, "{how:?}: {held:?}");
            if wider_than(3) && !four_first {
                assert!(
                    held.decisions >= 1 && held.most_out >= 1,
                    "{how:?}: no hold was put on: {held:?}"
                );
            }
        }
    }
    if four_first {
        let long = long_hashed();
        for how in [T, P] {
            let (off, off_held) = read_under(&long, how, "width", (2, None), true, 16 << 20);
            let (on, held) = read_under(&long, how, "cores", (2, None), true, 16 << 20);
            println!("HASHED HOLD {how:?}: {held:?}");
            assert_eq!(off_held, NONE, "{how:?}: a hold with the rule off");
            assert_eq!(on, off, "{how:?}: the rule against the width");
            assert_eq!(on.error, None, "{how:?}");
            assert!(held.most_out <= 2, "{how:?}: {held:?}");
            if wider_than(2) {
                assert!(
                    held.decisions >= 1 && held.most_out >= 1,
                    "{how:?}: no hold was put on: {held:?}"
                );
            }
        }
    }
}

/// One stored member of 192 MiB under BLAKE2sp, in one archive: long
/// enough for a plan of 4 MiB pieces to reach the rule's first decision.
fn long_hashed() -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Blake2sp,
        ..WriteOptions::default()
    })
    .expect("options");
    let data = noise(23, (192 << 20) + 11);
    writer
        .add(MemberSpec {
            name: b"Long.mkv",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut one = Vec::new();
    writer.finish_into(&mut one).expect("finish");
    vec![one]
}
