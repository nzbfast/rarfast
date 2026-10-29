//! The pool's memory admission, and the one dispatch it must never refuse.
//!
//! `extract_parallel` admits a member only while the working memory its
//! workers hold, plus the window this member needs, fits under
//! `MemoryPolicy::working_limit` (API 5.2, 8.4.1). Each worker's figure is
//! the window the member DECLARED at dispatch, raised to what the worker
//! MEASURED once it answers - its decoder windows, its scratch and its read
//! buffer - and never lowered, because the worker keeps them for the next
//! member.
//!
//! **The defect this file pins (22 Sep 2026, the Windows
//! width measurement).** Admitted on declared figures, a full pool's measured
//! figures carry the sum PAST the limit. From then on the admission test
//! refused every dispatch into a non-empty flight, including one handed to
//! a worker already holding a window large enough, which costs nothing new.
//! So the pool took a member only once the flight had drained to nothing:
//! a breadth of ONE for the rest of the archive. Sixteen workers of 33 MiB
//! under the default 512 MiB did exactly that on a 2,571 member `-m5`
//! archive, at 7.7 s where fifteen workers read 1.4 s, on Windows and on
//! macOS alike, which is every box with sixteen cores or more at the
//! default width.
//!
//! The fixture reproduces the arithmetic at a small scale: a limit of
//! exactly `width` declared windows, which the measured figures overrun.
//! The signal is how many members the SINK holds open at once in the second
//! half of the archive, which the pool's outputs bound (twice the breadth)
//! makes deterministic: a pool that refuses reuse never holds more than the
//! one in flight plus the one being opened, and a pool that admits it fills
//! its outputs whatever the decode speed, because a member is closed only
//! when the outputs bound is reached.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rarkit::{
    extract, extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, ParallelSink, Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod,
    WriteOptions, Writer,
};

/// `probe::peak_workers` is PROCESS-wide, so every test here takes this.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

const MEMBERS: usize = 64;
const MEMBER_BYTES: usize = 256 * 1024;

/// Half compressible, half not, so every member is a real decode and well
/// above the offload floor.
fn body(seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MEMBER_BYTES + 128);
    let mut s = 0x2026_0922_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    while out.len() < MEMBER_BYTES {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", s >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..4 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&s.to_le_bytes());
        }
    }
    out.truncate(MEMBER_BYTES);
    out
}

/// A non-solid `-m3` archive of [`MEMBERS`] distinct members.
fn archive() -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(1 << 20),
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let bodies: Vec<Vec<u8>> = (0..MEMBERS as u64).map(body).collect();
    let names: Vec<Vec<u8>> = (0..MEMBERS)
        .map(|i| format!("m{i:02}.dat").into_bytes())
        .collect();
    for (name, bytes) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(bytes),
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

fn sources(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// The window the members declare, read from the archive.
fn window_of(bytes: &[u8]) -> u64 {
    let archive =
        rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default()).expect("open");
    archive
        .members()
        .filter_map(|m| match m.method {
            rarkit::Method::Compressed { dictionary, .. } => Some(dictionary),
            rarkit::Method::Stored => None,
        })
        .max()
        .expect("a compressed member")
}

/// Every member's name and digest, in archive order.
type Digests = Vec<(Vec<u8>, (u64, u32))>;

/// A length and a CRC32, so two runs compare byte for byte.
struct Digest {
    len: u64,
    hash: crc32fast::Hasher,
}

impl Write for Digest {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.len += data.len() as u64;
        self.hash.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Digest {
    fn new() -> Digest {
        Digest {
            len: 0,
            hash: crc32fast::Hasher::new(),
        }
    }
    fn value(self) -> (u64, u32) {
        (self.len, self.hash.finalize())
    }
}

/// Records every member's digest, and how many members were open at once
/// each time one was opened.
#[derive(Default)]
struct Watch {
    open_now: AtomicUsize,
    open_at_each: Mutex<Vec<usize>>,
    got: Mutex<Digests>,
}

impl ParallelSink for Watch {
    type Out = Digest;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        let now = self.open_now.fetch_add(1, Ordering::SeqCst) + 1;
        self.open_at_each
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(now);
        Ok(Disposition::Write(Digest::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(outcome.checksum_ok, Some(false), "checksum failed");
        if let Some(out) = out {
            self.open_now.fetch_sub(1, Ordering::SeqCst);
            self.got
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((member.name.to_vec(), out.value()));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Serial {
    got: Digests,
}

impl Sink for Serial {
    type Out = Digest;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(outcome.checksum_ok, Some(false), "checksum failed");
        if let Some(out) = out {
            self.got.push((member.name.to_vec(), out.value()));
        }
        Ok(())
    }
}

struct Wide {
    got: Digests,
    /// The most members open at once over the SECOND half of the opens.
    late_open: usize,
    peak_workers: usize,
}

/// The one-member floor for this archive (SPEC-API 8.4.1): the
/// smallest NAMED budget a read accepts. Every limit below is the floor
/// plus so many declared windows, so "exactly `k` windows" of room above
/// what the walk itself holds is what each test still states, and a budget
/// under the floor, which the tests used to name, is refused up front
/// since the floor was introduced (this file's tests predate it and were
/// corrected afterwards).
fn floor(bytes: &[u8]) -> u64 {
    rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default())
        .expect("open")
        .minimum_working_memory(&MemoryPolicy::from_limit(8 << 20))
        + (256 << 10)
}

fn wide(bytes: &[u8], width: usize, limit: u64) -> Wide {
    // The POOL's own admission is what these tests pin, so the limit is
    // one the caller did not name (`limit_named` false). A NAMED budget of
    // a few windows sits under this fixture's one-member floor and is
    // refused before any member, and a named one above the
    // floor has its breadth capped before the pool sees it.
    let mut policy = MemoryPolicy::from_limit(limit);
    policy.limit_named = false;
    let opts = ReadOptions::default()
        .with_workers(Some(width))
        .with_memory(policy);
    let sink = Watch::default();
    probe::reset_peak_workers();
    extract_parallel(sources(bytes), &opts, &sink, width).expect("parallel");
    let at_each = sink
        .open_at_each
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    let late_open = at_each[at_each.len() / 2..]
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    Wide {
        got: sink.got.into_inner().unwrap_or_else(|e| e.into_inner()),
        late_open,
        peak_workers: probe::peak_workers(),
    }
}

fn serial(bytes: &[u8]) -> Digests {
    let mut sink = Serial::default();
    extract(sources(bytes), &ReadOptions::default(), &mut sink, &mut ()).expect("serial");
    sink.got
}

/// A pool whose measured holdings have passed the limit keeps its breadth:
/// a worker that already holds a large enough window is handed members for
/// the whole archive, not only once the flight is empty. Byte-identical to
/// the sequential form.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_pool_over_its_limit_on_measured_figures_keeps_its_breadth() {
    let _guard = counter();
    let bytes = archive();
    let window = window_of(&bytes);
    let width = 4;
    // Exactly `width` declared windows: every worker is admitted on its
    // declared figure, and its measured one (window plus scratch plus read
    // buffer) then carries the sum over.
    let run = wide(&bytes, width, floor(&bytes) + window * (width as u64 - 1));
    assert_eq!(run.got, serial(&bytes), "output differs from sequential");
    assert_eq!(run.got.len(), MEMBERS);
    // Refusing reuse holds at most the one member in flight plus the one
    // being opened; admitting it fills the outputs bound, twice the
    // breadth. Three is the smallest count only the second can reach.
    assert!(
        run.late_open >= 3,
        "the pool fell to a breadth of one once its measured holdings passed \
         the limit: at most {} members open at once over the second half",
        run.late_open
    );
}

/// And the limit still BINDS: a caller's budget of two windows
/// never has more than two members decoding, however wide the read, because
/// a worker holding nothing is still refused a window that does not fit.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_callers_small_limit_still_bounds_the_decoders() {
    let _guard = counter();
    let bytes = archive();
    let window = window_of(&bytes);
    let run = wide(&bytes, 8, floor(&bytes) + window);
    assert_eq!(run.got, serial(&bytes), "output differs from sequential");
    assert!(
        run.peak_workers <= 2,
        "{} members decoded at once under a budget of two windows",
        run.peak_workers
    );
}

/// A read WIDER than its budget holds keeps the pool its budget holds,
/// waiting on whichever worker answers first, and never on the head of
/// the queue alone (the measured width cliff above
/// sixteen). Before the fix a slot never spawned stayed on the free list
/// for ever, so the pool never waited on any worker: the budget refused
/// that slot on every dispatch, and each refusal closed the OLDEST member
/// first. The pool then held about as many members open as it had
/// workers. Once the refused slot is retired, the free list empties the
/// way it does at a width the budget holds, and finished members queue
/// up to the outputs bound.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_read_wider_than_its_budget_waits_on_any_worker() {
    let _guard = counter();
    let bytes = archive();
    let window = window_of(&bytes);
    let affordable = 3u64;
    let run = wide(&bytes, 8, floor(&bytes) + window * (affordable - 1));
    assert_eq!(run.got, serial(&bytes), "output differs from sequential");
    // Under the one-member floor a NAMED budget pays for its workers up front
    // (`extract::budget_floor`), so no slot is
    // ever spawned that the budget then refuses: the pool IS the width the
    // budget holds, never wider, and the head-of-queue wait this test was
    // written against has nothing to wait on. What remains to pin is the
    // bound itself: never more members decoding at once than the budget's
    // windows, at a width far above it. (The unnamed default, where the
    // slots are still retired one by one, keeps the fix; the outputs
    // signal of this test read 16 there before the floor.)
    assert!(
        run.peak_workers as u64 <= affordable,
        "{} members decoded at once under a budget of {affordable} windows",
        run.peak_workers
    );
}
