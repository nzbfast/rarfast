//! A read that meets a host out of threads, or a panic on one of its own
//! threads, still ends, and ends cleanly.
//!
//! Two defects found on 30 Sep 2026:
//!
//! 1. Under `ulimit -v` a stated width died in thread creation: `Scope::spawn`
//!    panics ("failed to spawn thread") when the host refuses a thread, and
//!    SPEC-API promise 2.1 is no panic. Every scoped spawn on the read path
//!    now hands its work back on a refusal (`crate::threads`), and the read
//!    runs narrower or on the thread that asked. These tests refuse threads
//!    on purpose (`probe::allow_spawns`) and hold the bytes, verdicts and
//!    report to those of the same read with every thread it asked for.
//! 2. A panic on the solid path's walk thread left the caller parked on a
//!    member's slot for ever, and one on the delivering thread left the walk
//!    blocked for a caller that had gone. Both now reach the caller as the
//!    panic they were (promise 2.1: a caller's own panic inside a trait
//!    method propagates unchanged), within a bound, and nothing is left
//!    parked.

#![cfg(feature = "parallel")]

use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, MemberSpec, ParallelSink,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const MIB: usize = 1 << 20;

/// One archive this crate writes, of these members, in this order.
fn archive(members: &[(String, Vec<u8>)], method: WriteMethod, solid: bool) -> Vec<u8> {
    let options = WriteOptions {
        solid,
        // The solid default dictionary (10 Oct 2026) is not this file's
        // subject: its archives keep the 2 MiB window they were written
        // for. `solid_default_dictionary` holds the default.
        solid_dictionary_2mib: true,
        order: rarkit::MemberOrder::AsAdded,
        method,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in members {
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
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn members(count: usize, size: usize, seed: u32) -> Vec<(String, Vec<u8>)> {
    (0..count)
        .map(|k| {
            let len = size + (k * 977) % (size / 2 + 1);
            (
                format!("m{k:03}.txt"),
                rarkit_testdata::chatter((seed + k as u32) as u64, len),
            )
        })
        .collect()
}

fn compressed(level: u8) -> WriteMethod {
    WriteMethod::Compressed {
        level,
        dictionary: None,
    }
}

fn one(bytes: Vec<u8>) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes) as Arc<dyn RangeSource>]
}

/// One member as a caller saw it: its name, the bytes its writer got
/// (`None` verified), and its verdict.
type Record = (Vec<u8>, Option<Vec<u8>>, Option<bool>);

/// Everything a caller sees of one read: its members, and the report or
/// error.
type Seen = (Vec<Record>, String);

/// A sequential sink that writes, or verifies, every member.
struct Collect {
    verify: bool,
    got: Vec<Record>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Vec::new())
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.got
            .push((member.name.to_vec(), out, outcome.checksum_ok));
        Ok(())
    }
}

/// The parallel entry's sink: the same record, closed in archive order.
struct ParCollect {
    verify: bool,
    got: Mutex<Vec<Record>>,
}

impl ParallelSink for ParCollect {
    type Out = Vec<u8>;

    fn open(&self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Vec::new())
        })
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.got
            .lock()
            .unwrap()
            .push((member.name.to_vec(), out, outcome.checksum_ok));
        Ok(())
    }
}

fn verdict(outcome: Result<rarkit::ExtractReport>) -> String {
    match outcome {
        Ok(r) => format!("ok {} {} {}", r.members, r.bytes, r.checksum_failures),
        Err(e) => format!("err {:?}", e.kind()),
    }
}

/// Run `read` on its own thread with `allowed` thread starts (all, when
/// `None`), and answer what it saw and how many starts were refused. The
/// probes are per thread, so the read sets them on its own.
fn under<F>(allowed: Option<usize>, read: F) -> (Seen, usize)
where
    F: FnOnce() -> Seen + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        rarkit::probe::allow_spawns(allowed);
        let seen = read();
        let refused = rarkit::probe::spawns_refused();
        rarkit::probe::allow_spawns(None);
        let _ = tx.send((seen, refused));
    });
    rx.recv_timeout(Duration::from_secs(300))
        .expect("the read neither finished nor failed within 300 s")
}

fn sequential(volumes: Vec<Arc<dyn RangeSource>>, opts: ReadOptions, verify: bool) -> Seen {
    let mut sink = Collect {
        verify,
        got: Vec::new(),
    };
    let outcome = extract(volumes, &opts, &mut sink, &mut ());
    (sink.got, verdict(outcome))
}

fn parallel(volumes: Vec<Arc<dyn RangeSource>>, opts: ReadOptions, width: usize) -> Seen {
    let sink = ParCollect {
        verify: false,
        got: Mutex::new(Vec::new()),
    };
    let outcome = extract_parallel(volumes, &opts, &sink, width);
    (sink.got.into_inner().unwrap(), verdict(outcome))
}

/// Every allowance from none at all to a few, against every thread asked.
const ALLOWANCES: [usize; 5] = [0, 1, 2, 3, 6];

fn same(label: &str, want: &Seen, have: &Seen) {
    assert_eq!(want.1, have.1, "{label}: the report");
    assert_eq!(want.0.len(), have.0.len(), "{label}: the members closed");
    for (a, b) in want.0.iter().zip(&have.0) {
        assert_eq!(a.0, b.0, "{label}: the order of the closes");
        assert_eq!(
            a.2,
            b.2,
            "{label}: {:?}'s verdict",
            String::from_utf8_lossy(&a.0)
        );
        assert!(
            a.1 == b.1,
            "{label}: {:?}'s bytes",
            String::from_utf8_lossy(&a.0)
        );
    }
}

// ---------------------------------------------------------------------------
// Defect 1: a host out of threads
// ---------------------------------------------------------------------------

/// The concurrent pool at width 8 over independent members: every worker
/// the host refuses retires its slot, down to none, where the walk decodes
/// every member itself.
#[test]
fn a_refused_worker_narrows_the_parallel_pool_and_nothing_else_moves() {
    let archive = archive(&members(24, 60_000, 11), compressed(3), false);
    let run = |allowed| {
        let archive = archive.clone();
        under(allowed, move || {
            rarkit::probe::set_offload_floor(Some(0));
            let opts = ReadOptions::default().with_workers(Some(8));
            let seen = parallel(one(archive), opts, 8);
            rarkit::probe::set_offload_floor(None);
            seen
        })
    };
    let (want, _) = run(None);
    assert!(want.1.starts_with("ok 24 "), "the control: {}", want.1);
    for allowed in ALLOWANCES {
        let (have, refused) = run(Some(allowed));
        same(&format!("{allowed} threads allowed"), &want, &have);
        if allowed == 0 {
            assert!(refused > 0, "nothing was refused, so this proves nothing");
        }
    }
}

/// The sequential entry decoding AHEAD: a look-ahead worker the host
/// refuses retires, and a member with no worker is decoded by the walk in
/// its turn.
#[test]
fn a_refused_worker_sends_the_look_ahead_s_member_home_in_its_turn() {
    let archive = archive(&members(24, 60_000, 21), compressed(3), false);
    for verify in [false, true] {
        let run = |allowed| {
            let archive = archive.clone();
            under(allowed, move || {
                rarkit::probe::set_offload_floor(Some(0));
                rarkit::probe::set_seq_ahead(Some(true));
                let opts = ReadOptions::default().with_workers(Some(4));
                let seen = sequential(one(archive), opts, verify);
                rarkit::probe::set_seq_ahead(None);
                rarkit::probe::set_offload_floor(None);
                seen
            })
        };
        let (want, _) = run(None);
        assert!(want.1.starts_with("ok 24 "), "the control: {}", want.1);
        for allowed in ALLOWANCES {
            let (have, refused) = run(Some(allowed));
            same(&format!("verify {verify}, {allowed} allowed"), &want, &have);
            if allowed == 0 {
                assert!(refused > 0, "verify {verify}: nothing was refused");
            }
        }
    }
}

/// The solid path: with no thread for the walk it walks on the caller's
/// thread instead, and with one it runs as before however many of the
/// threads inside it are refused.
#[test]
fn a_refused_solid_walk_runs_on_the_caller_s_thread() {
    let archive = archive(&members(30, 40_000, 31), compressed(3), true);
    let run = |allowed, ahead: bool| {
        let archive = archive.clone();
        under(allowed, move || {
            rarkit::probe::set_solid_ahead(Some(ahead));
            rarkit::probe::reset_solid_ahead_seen();
            let mut opts = ReadOptions::default().with_workers(Some(4));
            opts.sink_is_file = Some(true);
            let (got, report) = sequential(one(archive), opts, false);
            let taken = rarkit::probe::solid_ahead_seen().0;
            rarkit::probe::set_solid_ahead(None);
            (got, format!("{report} taken {taken}"))
        })
    };
    // The control is the sequential path with nothing on a worker.
    let (want, _) = run(None, false);
    assert!(want.1.starts_with("ok 30 "), "the control: {}", want.1);
    let strip = |seen: &Seen| {
        (
            seen.0.clone(),
            seen.1.split(" taken").next().unwrap().to_string(),
        )
    };
    let (whole, _) = run(None, true);
    assert!(
        whole.1.ends_with("taken 1"),
        "the solid path was not taken: {}",
        whole.1
    );
    for allowed in ALLOWANCES {
        let (have, refused) = run(Some(allowed), true);
        same(&format!("{allowed} allowed"), &strip(&want), &strip(&have));
        if allowed == 0 {
            assert!(refused > 0, "nothing was refused");
            assert!(
                have.1.ends_with("taken 0"),
                "no thread, yet the walk left: {}",
                have.1
            );
        } else {
            assert!(
                have.1.ends_with("taken 1"),
                "{allowed} allowed: the walk did not leave"
            );
        }
    }
}

/// One large member of each kind that spends threads INSIDE itself: an LZ
/// member wide enough for the tape lanes and the seam, and a stored one at
/// the wide verify's floor, written and verified.
#[test]
fn a_member_whose_own_threads_are_refused_decodes_to_the_same_bytes() {
    let big = vec![
        (
            "lz.txt".to_string(),
            rarkit_testdata::chatter(41, 12 * MIB + 4_321),
        ),
        (
            "stored.bin".to_string(),
            rarkit_testdata::chatter(42, 20 * MIB + 17),
        ),
    ];
    for (method, label) in [(compressed(1), "lz"), (WriteMethod::Stored, "stored")] {
        let archive = archive(&big, method, false);
        for verify in [false, true] {
            // A caller whose writer is not a file (the wide write), and one
            // whose writer is (the seam).
            for sink_is_file in [Some(false), Some(true)] {
                let run = |allowed| {
                    let archive = archive.clone();
                    under(allowed, move || {
                        let mut opts = ReadOptions::default().with_workers(Some(8));
                        opts.sink_is_file = sink_is_file;
                        sequential(one(archive), opts, verify)
                    })
                };
                let (want, _) = run(None);
                assert!(want.1.starts_with("ok 2 "), "the control: {}", want.1);
                for allowed in ALLOWANCES {
                    let (have, _) = run(Some(allowed));
                    same(
                        &format!(
                            "{label}, verify {verify}, file {sink_is_file:?}, {allowed} allowed"
                        ),
                        &want,
                        &have,
                    );
                }
                // Non-vacuity, once per shape: with none allowed, some
                // thread the read wanted was refused. A stored member
                // written to a file takes the seam only where the policy
                // engages it, so that shape proves only its bytes.
                let (_, refused) = run(Some(0));
                if label == "lz" || verify || sink_is_file == Some(false) {
                    assert!(
                        refused > 0,
                        "{label}, verify {verify}, file {sink_is_file:?}: nothing was refused"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Defect 2: a panic on either thread of the solid path
// ---------------------------------------------------------------------------

/// A source that PANICS at the first read reaching `at`, as a caller's own
/// source may.
struct Bomb {
    bytes: Vec<u8>,
    at: u64,
}

const SOURCE_PANIC: &str = "injected source panic";
const WRITER_PANIC: &str = "injected writer panic";

impl RangeSource for Bomb {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset.saturating_add(buf.len() as u64) > self.at {
            panic!("{}", SOURCE_PANIC);
        }
        self.bytes.as_slice().read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// The payload of a panic, as text.
fn said(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "a payload that is not text".into())
}

/// Run a solid extract on its own thread, catching a panic, within `bound`.
fn solid_bounded<F>(bound: Duration, read: F) -> std::result::Result<String, String>
where
    F: FnOnce() -> String + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        rarkit::probe::set_solid_ahead(Some(true));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(read));
        rarkit::probe::set_solid_ahead(None);
        let _ = tx.send(caught.map_err(|p| said(&*p)));
    });
    rx.recv_timeout(bound)
        .expect("the solid extract HUNG: neither a return nor a panic within the bound")
}

fn file_opts(width: usize) -> ReadOptions {
    let mut opts = ReadOptions::default().with_workers(Some(width));
    opts.sink_is_file = Some(true);
    opts
}

/// A panic on the WALK's thread, wherever in the archive it falls (in a
/// header, between members, inside one), reaches the caller as that panic
/// and nothing is left parked.
#[test]
fn a_panic_on_the_solid_walk_reaches_the_caller_and_nothing_hangs() {
    let bytes = archive(&members(30, 40_000, 51), compressed(3), true);
    let len = bytes.len() as u64;
    // The solid path is the one taken for this archive and these options.
    let control = {
        let bytes = bytes.clone();
        solid_bounded(Duration::from_secs(60), move || {
            rarkit::probe::reset_solid_ahead_seen();
            let (_, report) = sequential(one(bytes), file_opts(4), false);
            format!("{report} taken {}", rarkit::probe::solid_ahead_seen().0)
        })
    };
    let control = control.expect("the control read panicked");
    assert!(
        control.ends_with("taken 1"),
        "the solid path was not taken: {control}"
    );
    for k in 1..=16u64 {
        let at = len * k / 17;
        let bytes = bytes.clone();
        let got = solid_bounded(Duration::from_secs(60), move || {
            let volumes = vec![Arc::new(Bomb { bytes, at }) as Arc<dyn RangeSource>];
            sequential(volumes, file_opts(4), false).1
        });
        match got {
            Err(payload) => assert_eq!(payload, SOURCE_PANIC, "a panic at {at} of {len} changed"),
            Ok(report) => panic!("a panic at {at} of {len} was swallowed into {report}"),
        }
    }
}

/// A writer that panics at its `n`th write, on the caller's thread.
struct Fuse {
    left: usize,
}

impl Write for Fuse {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            panic!("{}", WRITER_PANIC);
        }
        self.left -= 1;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Fused {
    writes: usize,
}

impl Sink for Fused {
    type Out = Fuse;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Fuse>> {
        Ok(Disposition::Write(Fuse { left: self.writes }))
    }
}

/// A panic on the DELIVERING thread (the caller's own writer) while the walk
/// is far ahead and blocked on the bytes between the two: the walk is told
/// to stop and drained, the scope joins it, and the caller sees its panic.
#[test]
fn a_panic_on_the_delivering_thread_reaches_the_caller_and_the_walk_ends() {
    let long = vec![
        (
            "long0.bin".to_string(),
            rarkit_testdata::chatter(61, 8 * MIB + 12_345),
        ),
        (
            "long1.bin".to_string(),
            rarkit_testdata::chatter(62, 8 * MIB + 777),
        ),
        ("tail.bin".to_string(), rarkit_testdata::chatter(63, 3_000)),
    ];
    let bytes = archive(&long, compressed(1), true);
    // A small budget and a short queue, so the walk is blocked on the
    // caller when the caller's writer panics.
    let opts = || {
        let mut opts = file_opts(4);
        opts.memory = rarkit::MemoryPolicy::from_limit(16 << 20);
        opts
    };
    let control = {
        let bytes = bytes.clone();
        solid_bounded(Duration::from_secs(120), move || {
            rarkit::probe::set_solid_queue_depth(Some(2));
            rarkit::probe::reset_solid_ahead_seen();
            let (_, report) = sequential(one(bytes), opts(), false);
            rarkit::probe::set_solid_queue_depth(None);
            format!("{report} taken {}", rarkit::probe::solid_ahead_seen().0)
        })
    };
    let control = control.expect("the control read panicked");
    assert!(
        control.ends_with("taken 1"),
        "the solid path was not taken: {control}"
    );
    // A member arrives in a handful of writes, so every fuse here fires.
    for writes in [0usize, 1, 2, 3] {
        let bytes = bytes.clone();
        let got = solid_bounded(Duration::from_secs(120), move || {
            rarkit::probe::set_solid_queue_depth(Some(2));
            let mut sink = Fused { writes };
            let outcome = extract(one(bytes), &opts(), &mut sink, &mut ());
            rarkit::probe::set_solid_queue_depth(None);
            verdict(outcome)
        });
        match got {
            Err(payload) => assert_eq!(payload, WRITER_PANIC, "a panic after {writes} writes"),
            Ok(report) => panic!("a writer panic after {writes} writes became {report}"),
        }
    }
}
