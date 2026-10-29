//! THE TEN ACCEPTANCE TESTS OF SPEC F 3.7.7: one member's read, decrypt,
//! decode and checksum running while the walking thread writes.
//!
//! Each is testable without a stopwatch, which is what makes the seam
//! landable before it is measured. The one that the section exists for is
//! the fourth: a caller's writer returning an error must stop the WORK and
//! not merely end the call with the right error, and it is priced in
//! SOURCE BYTES READ after the refusal rather than in wall clock. A fuzz
//! campaign found the concurrent member path decoding for 7.92 s after a
//! refusal at a ceiling of zero where the sequential path took 0.20 ms,
//! and a seam that adds a second unit adds a
//! second place for that to happen.
//!
//! **How the two arms are taken.** SPEC-API 8.5 promises nothing about
//! whether a given member is overlapped, so the engine's own floor is a
//! measured constant and not an API fact, and `probe::set_seam_floor`
//! moves it for the length of one test: `Some(0)` overlaps every written
//! member, `Some(u64::MAX)` overlaps none. That is what lets these
//! fixtures be small enough to run in a test suite and still exercise the
//! path a 2 GiB member takes.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{
    probe, ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Password, Payload, Progress, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions,
    Writer,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Material that half compresses and half does not, so an `-m3` member is
/// a real decode and not a run of one byte.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0920_0737_u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// How one fixture archive is written.
#[derive(Clone, Copy)]
struct Shape {
    label: &'static str,
    method: WriteMethod,
    checksum: ChecksumKind,
    password: Option<&'static str>,
    /// The volume file cap, for the split-member shape.
    volume_cap: Option<u64>,
}

const SHAPES: &[Shape] = &[
    Shape {
        label: "stored crc32",
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Crc32,
        password: None,
        volume_cap: None,
    },
    Shape {
        label: "-m3",
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        checksum: ChecksumKind::Crc32,
        password: None,
        volume_cap: None,
    },
    Shape {
        label: "stored blake2sp",
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Blake2sp,
        password: None,
        volume_cap: None,
    },
    Shape {
        label: "stored encrypted",
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Blake2sp,
        password: Some("seam"),
        volume_cap: None,
    },
    Shape {
        label: "stored, split across volumes",
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Crc32,
        password: None,
        volume_cap: Some(1 << 20),
    },
];

/// One member of `payload` bytes, written the way `shape` says.
fn archive(shape: Shape, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method: shape.method,
        checksum: shape.checksum,
        password: shape.password.map(Password::from),
        volume_file_size: shape.volume_cap,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"one.dat",
            payload: Payload::Bytes(payload),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    if shape.volume_cap.is_some() {
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).expect("finish_volumes");
        assert!(
            volumes.len() > 2,
            "{}: one volume is not a split member",
            shape.label
        );
        volumes
    } else {
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        vec![out]
    }
}

fn options(shape: Shape) -> ReadOptions {
    ReadOptions::default().with_password(shape.password.map(Password::from))
}

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// `probe::peak_seam` is PROCESS-wide and has to be - the source unit is
/// another thread by construction - so EVERY test in this file takes
/// this, not only the two that read the counter: cargo runs a binary's tests on several threads at once and one
/// test's seam would otherwise land in another's reading.
/// `breadth_width.rs` says the same at its own counter.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> std::sync::MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run the next extraction on this thread with the seam on, or off.
struct Seam;

impl Seam {
    fn on() -> Seam {
        probe::set_seam_floor(Some(0));
        Seam
    }
    fn off() -> Seam {
        probe::set_seam_floor(Some(u64::MAX));
        Seam
    }
}

impl Drop for Seam {
    fn drop(&mut self) {
        probe::set_seam_floor(None);
    }
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// Keeps every member's bytes, its verdict and the thread every call was
/// made on.
#[derive(Default)]
struct Keep {
    bytes: Vec<u8>,
    verdict: Option<Option<bool>>,
    reported: u64,
    /// `open`, every `write` and `close`, as thread ids, in call order.
    threads: Vec<std::thread::ThreadId>,
    calls: Vec<&'static str>,
}

/// A writer that records the thread every write was made on, into the
/// sink it belongs to.
struct Recorder(Arc<Mutex<Keep>>);

impl Write for Recorder {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        held.bytes.extend_from_slice(data);
        held.threads.push(std::thread::current().id());
        held.calls.push("write");
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Recording(Arc<Mutex<Keep>>);

impl Sink for Recording {
    type Out = Recorder;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Recorder>> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        held.threads.push(std::thread::current().id());
        held.calls.push("open");
        drop(held);
        Ok(Disposition::Write(Recorder(Arc::clone(&self.0))))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Recorder>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        held.threads.push(std::thread::current().id());
        held.calls.push("close");
        held.verdict = Some(outcome.checksum_ok);
        held.reported = outcome.bytes;
        Ok(())
    }
}

/// Extract with the seam as `seam` says, and answer what the sink saw.
fn run(shape: Shape, volumes: &[Vec<u8>], on: bool) -> (Keep, Result<rarkit::ExtractReport>) {
    let _seam = if on { Seam::on() } else { Seam::off() };
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording(Arc::clone(&held));
    let report = rarkit::extract(sources(volumes), &options(shape), &mut sink, &mut ());
    drop(sink);
    let keep = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (keep, report)
}

// ---------------------------------------------------------------------------
// 1. BYTES
// ---------------------------------------------------------------------------

/// **Test 1.** The output of an overlapped member is byte-identical to the
/// same member with the seam disabled, over every shape 3.7.7 names:
/// stored, `-m3`, encrypted and BLAKE2sp members, and a member split
/// across volumes.
#[test]
fn overlapped_bytes_are_the_sequential_paths_bytes() {
    let _guard = counter();
    let payload = body(3 << 20);
    for shape in SHAPES {
        let volumes = archive(*shape, &payload);
        probe::reset_peak_seam();
        let (with, report_with) = run(*shape, &volumes, true);
        // NOT VACUOUS: the overlapped arm really did overlap. Without
        // this the test passes just as happily when `engages` answers
        // false for every shape and both arms are the sequential path.
        assert_eq!(
            probe::peak_seam(),
            1,
            "{}: the overlapped arm never spawned a source unit",
            shape.label
        );
        let (without, report_without) = run(*shape, &volumes, false);
        report_with
            .as_ref()
            .unwrap_or_else(|e| panic!("{}: overlapped extract failed: {e}", shape.label));
        report_without
            .as_ref()
            .unwrap_or_else(|e| panic!("{}: sequential extract failed: {e}", shape.label));
        assert_eq!(
            with.bytes.len(),
            payload.len(),
            "{}: the overlapped member is the wrong length",
            shape.label
        );
        assert!(
            with.bytes == without.bytes,
            "{}: the overlapped member's bytes differ from the sequential path's",
            shape.label
        );
        assert!(
            with.bytes == payload,
            "{}: the overlapped member is not what was written",
            shape.label
        );
        assert_eq!(
            with.verdict, without.verdict,
            "{}: the verdict moved with the seam",
            shape.label
        );
        assert_eq!(
            report_with.expect("checked").bytes,
            report_without.expect("checked").bytes,
            "{}: the report's byte count moved with the seam",
            shape.label
        );
    }
}

// ---------------------------------------------------------------------------
// 2. VERDICT
// ---------------------------------------------------------------------------

/// **Test 2.** A damaged member still reports `checksum_ok == Some(false)`
/// at `close`, with the same `MemberOutcome::bytes`, overlapped or not.
/// The checksum finishing before the last write does must not move the
/// verdict.
#[test]
fn a_damaged_member_reports_the_same_verdict_either_way() {
    let _guard = counter();
    let payload = body(3 << 20);
    for shape in SHAPES.iter().filter(|s| s.password.is_none()) {
        let volumes = archive(*shape, &payload);
        // One byte of the FIRST volume's payload area, well past every
        // header: a damaged member, not a damaged archive.
        let mut damaged = volumes.clone();
        let at = damaged[0].len() / 2;
        damaged[0][at] ^= 0xff;

        let (with, _) = run(*shape, &damaged, true);
        let (without, _) = run(*shape, &damaged, false);
        assert_eq!(
            with.verdict,
            Some(Some(false)),
            "{}: a damaged member was not reported as failing its checksum",
            shape.label
        );
        assert_eq!(
            with.verdict, without.verdict,
            "{}: the verdict moved with the seam",
            shape.label
        );
        assert_eq!(
            with.reported, without.reported,
            "{}: MemberOutcome::bytes moved with the seam",
            shape.label
        );
    }
}

// ---------------------------------------------------------------------------
// 3. ORDER
// ---------------------------------------------------------------------------

/// **Test 3.** `open`, then every write in member order, then `close`, on
/// ONE thread. A caller cannot tell from its own traffic that anything
/// overlapped (SPEC-API 8.5, promise 2.6).
#[test]
fn every_call_the_caller_sees_is_on_the_calling_thread() {
    let _guard = counter();
    let payload = body(3 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let (keep, report) = run(shape, &volumes, true);
    report.expect("extract");
    let here = std::thread::current().id();
    assert!(
        keep.threads.iter().all(|id| *id == here),
        "the sink saw {} calls from another thread; every call belongs to \
         the one that called extract",
        keep.threads.iter().filter(|id| **id != here).count()
    );
    assert_eq!(keep.calls.first(), Some(&"open"), "open came first");
    assert_eq!(keep.calls.last(), Some(&"close"), "close came last");
    assert!(
        keep.calls[1..keep.calls.len() - 1]
            .iter()
            .all(|c| *c == "write"),
        "nothing but writes between open and close"
    );
}

// ---------------------------------------------------------------------------
// 4. A REFUSING WRITER STOPS THE WORK
// ---------------------------------------------------------------------------

/// A source that counts the bytes it has handed over, so a refusal can be
/// priced in source bytes read rather than in seconds.
struct Counted {
    bytes: Vec<u8>,
    read: AtomicU64,
}

impl RangeSource for Counted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let taken = self.bytes.read_at(offset, buf)?;
        self.read.fetch_add(taken as u64, Ordering::Relaxed);
        Ok(taken)
    }
    fn available(&self) -> u64 {
        self.bytes.available()
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// A writer whose FIRST write refuses, recording what the source had read
/// by then and what it was OFFERED in the write that refused.
struct Refusing {
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
    offered: Arc<AtomicU64>,
}

impl Write for Refusing {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.offered.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.at_refusal
            .store(self.source.read.load(Ordering::Relaxed), Ordering::Relaxed);
        Err(std::io::Error::other("the caller refuses this member"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// [`Refusing`], but only once `after` bytes have been taken.
#[cfg(feature = "parallel")]
struct LateRefusing {
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
    after: u64,
    given: u64,
}

#[cfg(feature = "parallel")]
impl Write for LateRefusing {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.given + data.len() as u64 <= self.after {
            self.given += data.len() as u64;
            return Ok(data.len());
        }
        self.at_refusal
            .store(self.source.read.load(Ordering::Relaxed), Ordering::Relaxed);
        Err(std::io::Error::other("the caller refuses this member"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "parallel")]
struct LateRefusingSink {
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
    after: u64,
}

#[cfg(feature = "parallel")]
impl Sink for LateRefusingSink {
    type Out = LateRefusing;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<LateRefusing>> {
        Ok(Disposition::Write(LateRefusing {
            source: Arc::clone(&self.source),
            at_refusal: Arc::clone(&self.at_refusal),
            after: self.after,
            given: 0,
        }))
    }
}

struct RefusingSink {
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
    offered: Arc<AtomicU64>,
}

impl Sink for RefusingSink {
    type Out = Refusing;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Refusing>> {
        Ok(Disposition::Write(Refusing {
            source: Arc::clone(&self.source),
            at_refusal: Arc::clone(&self.at_refusal),
            offered: Arc::clone(&self.offered),
        }))
    }
}

/// A writer that takes `ceiling` bytes and then refuses, counting every
/// byte it was OFFERED along the way.
///
/// It is the shape `tests/parallel.rs` prices the two DRIVERS against each
/// other with, and it is here to price the SEAM against the path it
/// replaces: a refusal is answered in the slice that refuses it, so the
/// number a caller can observe is how much the engine handed over before
/// it stopped.
struct Ceiling {
    given: u64,
    ceiling: u64,
    offered: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
}

impl Write for Ceiling {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.offered.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.given += data.len() as u64;
        if self.given > self.ceiling {
            return Err(std::io::Error::other("past this test's ceiling"));
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Ceilings {
    ceiling: u64,
    offered: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
}

impl Sink for Ceilings {
    type Out = Ceiling;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Ceiling>> {
        Ok(Disposition::Write(Ceiling {
            given: 0,
            ceiling: self.ceiling,
            offered: Arc::clone(&self.offered),
            writes: Arc::clone(&self.writes),
        }))
    }
}

/// **Test 4, and the one this section exists for.** A sink whose first
/// write returns an error, over a member with megabytes of packed bytes
/// still ahead: the SOURCE BYTES READ after the refusal are bounded by one
/// ring plus one read, and are not a wall clock.
///
/// The bound asserted is the whole read-ahead budget plus a megabyte of
/// slack for the read that was already in flight and the fragment the
/// decode was holding. It is generous and still a bound: the member is
/// 32 MiB, so a seam that carried on decoding after the refusal - which
/// `f_extract_parallel` found costing 7.92 s against 0.20 ms - reads tens
/// of megabytes here and fails this by an order of magnitude.
#[test]
fn a_refusing_writer_stops_the_source_unit() {
    let _guard = counter();
    let payload = body(32 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let policy = MemoryPolicy::default();

    let mut offered_by_arm = Vec::new();
    for on in [true, false] {
        let _seam = if on { Seam::on() } else { Seam::off() };
        let source = Arc::new(Counted {
            bytes: volumes[0].clone(),
            read: AtomicU64::new(0),
        });
        let at_refusal = Arc::new(AtomicU64::new(0));
        let offered = Arc::new(AtomicU64::new(0));
        let mut sink = RefusingSink {
            source: Arc::clone(&source),
            at_refusal: Arc::clone(&at_refusal),
            offered: Arc::clone(&offered),
        };
        let err = rarkit::extract(
            vec![Arc::clone(&source) as Arc<dyn RangeSource>],
            &ReadOptions::default(),
            &mut sink,
            &mut (),
        )
        .expect_err("a refusing writer ends the operation");
        assert!(
            err.into_caller_error().is_ok(),
            "a refused write comes back as the caller's own error"
        );
        let after = source.read.load(Ordering::Relaxed) - at_refusal.load(Ordering::Relaxed);
        let bound = policy.read_ahead + (1 << 20);
        println!(
            "seam={on}: {after} source bytes read after the refusal, \
             bound {bound}, member {} bytes",
            payload.len()
        );
        assert!(
            after <= bound,
            "seam={on}: {after} source bytes were read AFTER the refusal, \
             where one ring plus one read is at most {bound}, over a \
             {} byte member",
            payload.len()
        );
        offered_by_arm.push(offered.load(Ordering::Relaxed));
    }
    // THE SIZE OF A PIECE IS NO PROMISE. Spec F 3.7.6 bounds the source
    // bytes read after the refusal, asserted above, and says nothing of
    // how large a piece a writer is offered (read again on 11 Oct 2026);
    // this used to hold the seam to the sequential path's piece, which
    // was stricter than the specification. A member the seam takes
    // on its size reads into the ring a whole slab at a time
    // (`extract::lent`), so what a refusing writer is offered is ONE SLAB
    // of the ring at most: half the read-ahead budget, the ring being two
    // slabs. A ring's worth of coalescing would still fail this.
    let slab = policy.read_ahead / 2;
    assert!(
        offered_by_arm[0] <= slab,
        "the seam offered the refusing writer {} bytes, over one slab \
         of the ring ({slab}); the sequential path offered {}",
        offered_by_arm[0],
        offered_by_arm[1]
    );
}

/// **Test 4, priced against the PRE-SEAM PATH.** The seam must offer a
/// refusing writer no more than the sequential path does, over every shape
/// 3.7.7 names and at a ceiling the writer does not refuse on its first
/// write.
///
/// The relation is "no more", not "the same". Two shapes legitimately give
/// the seam a TIGHTER bound than the sequential path has: the decode runs
/// on half the read-ahead budget (`seam::ring_plan`), so a BLAKE2sp stored
/// member's copy buffer is smaller inside the seam than outside it, and a
/// single write larger than a whole ring chunk is split. Both offer a
/// refusing writer LESS. What is forbidden is the other direction.
///
/// This is the test whose absence let the seam loosen the promise by 8x:
/// `tests/one_member_seam.rs` priced the seam against itself, so a deliver
/// unit coalescing a megabyte of the decoder's writes into one `write_all`
/// read as correct here and failed `tests/parallel.rs`'s parity assertion
/// between the two DRIVERS instead. The engine's answer is that the ring
/// carries the source unit's write boundaries with the bytes, so the
/// caller's writer sees the same calls with the seam as without it.
#[test]
fn the_seam_offers_a_refusing_writer_no_more_than_the_sequential_path() {
    let _guard = counter();
    let payload = body(6 << 20);
    for shape in SHAPES {
        let volumes = archive(*shape, &payload);
        // Three ceilings: refuse on the first write, refuse inside the
        // first ring, and refuse well past it.
        for ceiling in [0u64, 100 << 10, 3 << 20] {
            let mut seen = Vec::new();
            for on in [true, false] {
                let _seam = if on { Seam::on() } else { Seam::off() };
                let offered = Arc::new(AtomicU64::new(0));
                let writes = Arc::new(AtomicU64::new(0));
                let mut sink = Ceilings {
                    ceiling,
                    offered: Arc::clone(&offered),
                    writes: Arc::clone(&writes),
                };
                let err = rarkit::extract(sources(&volumes), &options(*shape), &mut sink, &mut ())
                    .expect_err("a refusing writer ends the operation");
                assert!(
                    err.into_caller_error().is_ok(),
                    "{}: a refused write comes back as the caller's own error",
                    shape.label
                );
                seen.push((
                    offered.load(Ordering::Relaxed),
                    writes.load(Ordering::Relaxed),
                ));
            }
            let (on_bytes, on_writes) = seen[0];
            let (off_bytes, off_writes) = seen[1];
            println!(
                "{}: ceiling {ceiling}: seam on offered {on_bytes} in \
                 {on_writes} writes, off {off_bytes} in {off_writes}",
                shape.label
            );
            assert!(
                on_bytes <= off_bytes,
                "{}: ceiling {ceiling}: the seam offered the refusing \
                 writer {on_bytes} bytes where the sequential path \
                 offered {off_bytes}",
                shape.label
            );
            assert!(
                on_writes >= off_writes,
                "{}: ceiling {ceiling}: the seam made {on_writes} write \
                 calls where the sequential path made {off_writes}: \
                 FEWER calls for the same bytes is the ring coalescing \
                 the source unit's writes, which is how the bound was \
                 lost",
                shape.label
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. THE CANCEL FLAG
// ---------------------------------------------------------------------------

/// Notes every `released` and `volume_done`, and answers how far the
/// engine said it had got.
#[derive(Default)]
struct Watch {
    released: Vec<(u32, u64)>,
    output: Vec<u64>,
}

impl Progress for Watch {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        self.released.push((volume, offset));
        Ok(())
    }
    fn output(&mut self, total: u64) -> Result<()> {
        self.output.push(total);
        Ok(())
    }
}

/// A writer that raises the cancel flag once it has taken `after` bytes.
struct Canceller {
    flag: Arc<AtomicBool>,
    seen: u64,
    after: u64,
}

impl Write for Canceller {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.seen += data.len() as u64;
        if self.seen >= self.after {
            self.flag.store(true, Ordering::Relaxed);
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct CancelSink {
    flag: Arc<AtomicBool>,
    after: u64,
}

impl Sink for CancelSink {
    type Out = Canceller;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Canceller>> {
        Ok(Disposition::Write(Canceller {
            flag: Arc::clone(&self.flag),
            seen: 0,
            after: self.after,
        }))
    }
}

/// **Test 5.** The cancel flag set mid-member: `Cancelled`, with
/// `released` reported before the error leaves `extract`, the scope joined
/// and no thread left running.
#[test]
fn the_cancel_flag_ends_the_member_with_released_reported_first() {
    let _guard = counter();
    let payload = body(16 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let _seam = Seam::on();

    let flag = Arc::new(AtomicBool::new(false));
    let mut sink = CancelSink {
        flag: Arc::clone(&flag),
        after: 1 << 20,
    };
    let mut watch = Watch::default();
    let err = rarkit::extract(
        sources(&volumes),
        &ReadOptions::default().with_cancel(Some(Arc::clone(&flag))),
        &mut sink,
        &mut watch,
    )
    .expect_err("a raised cancel flag ends the operation");
    assert!(
        matches!(err.kind(), rarkit::ErrorKind::Cancelled),
        "a raised cancel flag is Cancelled, not {:?}",
        err.kind()
    );
    assert!(
        !watch.released.is_empty(),
        "released is reported on every error path before the error is \
         returned (spec F 3.7.3)"
    );
    assert_eq!(
        probe::seam_now(),
        0,
        "the scope joined: no source unit is still running"
    );
}

// ---------------------------------------------------------------------------
// 6, 7. ONE READ EACH, AND RELEASED
// ---------------------------------------------------------------------------

/// A source that records every range it was asked for.
struct Ranges {
    bytes: Vec<u8>,
    seen: Mutex<Vec<(u64, u64)>>,
}

impl RangeSource for Ranges {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let taken = self.bytes.read_at(offset, buf)?;
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((offset, taken as u64));
        Ok(taken)
    }
    fn available(&self) -> u64 {
        self.bytes.available()
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// Records what the engine said it had released, beside what it had
/// actually read, so the two can be compared at every step.
struct Together {
    source: Arc<Ranges>,
    /// Every released offset, with the highest byte the source had been
    /// asked for by then.
    released: Mutex<Vec<(u64, u64)>>,
}

impl Progress for &Together {
    fn released(&mut self, _volume: u32, offset: u64) -> Result<()> {
        let high = self
            .source
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(at, len)| at + len)
            .max()
            .unwrap_or(0);
        self.released
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((offset, high));
        Ok(())
    }
}

/// **Tests 6 and 7.** Each byte range is read once (3.7.2), nothing is read
/// further ahead of the byte being delivered than `read_ahead`, and
/// `released` is monotone and never names an offset the source unit may
/// still read below.
#[test]
fn each_range_is_read_once_and_released_stays_behind_the_read() {
    let _guard = counter();
    let payload = body(8 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let _seam = Seam::on();

    let source = Arc::new(Ranges {
        bytes: volumes[0].clone(),
        seen: Mutex::new(Vec::new()),
    });
    let together = Together {
        source: Arc::clone(&source),
        released: Mutex::new(Vec::new()),
    };
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording(Arc::clone(&held));
    let mut watch = &together;
    rarkit::extract(
        vec![Arc::clone(&source) as Arc<dyn RangeSource>],
        &ReadOptions::default(),
        &mut sink,
        &mut watch,
    )
    .expect("extract");

    // 6: no byte of the member's DATA area is fetched twice. Header reads
    // go through a buffered cursor that may re-read a header's own bytes,
    // so what is asserted is that the total fetched is within a cursor
    // window of the archive's size, which a second pass over a member
    // could not be.
    let seen = source.seen.lock().unwrap_or_else(|e| e.into_inner());
    let total: u64 = seen.iter().map(|(_, len)| *len).sum();
    let size = volumes[0].len() as u64;
    assert!(
        total <= size + (64 << 10),
        "{total} bytes were fetched from a {size} byte archive, so \
         something was read twice"
    );

    // 7: released is monotone, and never names an offset above what the
    // source has actually been asked for.
    let released = together.released.lock().unwrap_or_else(|e| e.into_inner());
    assert!(!released.is_empty(), "released was never reported");
    let mut last = 0u64;
    for (offset, high) in released.iter() {
        assert!(
            *offset >= last,
            "released went backwards: {offset} after {last}"
        );
        last = *offset;
        assert!(
            *offset <= *high,
            "released named offset {offset} where the source had only been \
             read to {high}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. THREADS
// ---------------------------------------------------------------------------

/// **Test 8.** At most ONE extra thread alive per member in flight, and
/// the seam's units stay inside the read width, counted the way
/// `tests/breadth_width.rs` counts lanes.
///
/// `extract` has a breadth of one by construction (one member decodes at a
/// time), so the seam may hold one unit and no more, and a ceiling of one
/// leaves nothing to spend and must hold none.
#[test]
fn the_seam_costs_one_unit_per_member_in_flight() {
    let _guard = counter();
    let payload = body(3 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);

    // THE WIDTH IS `ReadOptions::workers`, NOT THE MEMORY BUDGET (API
    // 8.4.2). A width of one has no unit to spend on a seam; anything
    // wider may hold exactly one per member in flight.
    for workers in [1usize, 2, 8] {
        let _seam = Seam::on();
        probe::reset_peak_seam();
        let held = Arc::new(Mutex::new(Keep::default()));
        let mut sink = Recording(Arc::clone(&held));
        rarkit::extract(
            sources(&volumes),
            &ReadOptions::default().with_workers(Some(workers)),
            &mut sink,
            &mut (),
        )
        .expect("extract");
        let peak = probe::peak_seam();
        if workers < 2 {
            assert_eq!(
                peak, 0,
                "a read width of {workers} has no unit to spend on a seam"
            );
        } else {
            assert!(
                peak <= 1,
                "a breadth of one may hold one seam unit, not {peak}"
            );
        }
        assert_eq!(probe::seam_now(), 0, "every scope joined");
    }

    // AND `MemoryPolicy::max_workers` NO LONGER GATES IT. Before the
    // width dial of API 8.4.2 this test set that field and the seam read
    // it; it is a ceiling over BYTES now, which the driver lowers the
    // members in flight with, and a thread is spent out of the width and
    // never re-derived from a memory figure. A budget of one worker and a
    // read width of eight still overlaps the member.
    for max_workers in [1usize, 8] {
        let _seam = Seam::on();
        probe::reset_peak_seam();
        let held = Arc::new(Mutex::new(Keep::default()));
        let mut sink = Recording(Arc::clone(&held));
        rarkit::extract(
            sources(&volumes),
            &ReadOptions::default()
                .with_workers(Some(8))
                .with_memory(MemoryPolicy {
                    max_workers,
                    ..MemoryPolicy::default()
                }),
            &mut sink,
            &mut (),
        )
        .expect("extract");
        assert_eq!(
            probe::peak_seam(),
            1,
            "a read width of 8 spends its unit whatever `max_workers` is, \
             and it is {max_workers} here"
        );
        assert_eq!(probe::seam_now(), 0, "every scope joined");
    }
}

// ---------------------------------------------------------------------------
// 9. MEMORY
// ---------------------------------------------------------------------------

/// **Test 9.** `peak_working_memory` rises by at most the ring per member
/// in flight, and a policy too small for a ring still extracts the member
/// - which is never an error (SPEC-API 8.5).
#[test]
fn the_ring_stays_inside_the_callers_budget() {
    let _guard = counter();
    let payload = body(3 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let policy = MemoryPolicy::default();

    let (_, with) = run(shape, &volumes, true);
    let (_, without) = run(shape, &volumes, false);
    let with = with.expect("overlapped extract");
    let without = without.expect("sequential extract");
    let rise = with
        .peak_working_memory
        .saturating_sub(without.peak_working_memory);
    assert!(
        rise <= policy.read_ahead,
        "the seam raised the reported working memory by {rise} bytes, \
         where the whole ring is inside read_ahead ({})",
        policy.read_ahead
    );
    // NOT VACUOUS: the ring is counted at all. A report that simply
    // forgot it would pass the bound above and would be exactly the
    // hidden allocation SPEC-API 8.5 asks to be testable from outside.
    assert!(
        rise > 0,
        "the seam's ring does not reach ExtractReport::peak_working_memory"
    );

    // A budget with no room for a ring: the member still extracts, on the
    // sequential path, and nothing is reported as an error.
    let _seam = Seam::on();
    let tiny = MemoryPolicy::from_limit(4 << 20);
    probe::reset_peak_seam();
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording(Arc::clone(&held));
    rarkit::extract(
        sources(&volumes),
        &ReadOptions::default().with_memory(tiny),
        &mut sink,
        &mut (),
    )
    .expect("a budget too small for a ring is never an error");
    let bytes = held.lock().unwrap_or_else(|e| e.into_inner()).bytes.clone();
    assert!(
        bytes == payload,
        "a member run without a ring still delivers its own bytes"
    );
}

// ---------------------------------------------------------------------------
// 10. NO FEATURE, NO THREAD; AND PROGRESS NEEDS NO `Send`
// ---------------------------------------------------------------------------

/// A `Progress` that is deliberately NOT `Send`, to hold SPEC-API 8.5's
/// promise that neither `Progress` nor `Sink::Out` gains a bound: this
/// file would not COMPILE if the seam had needed one.
#[derive(Default)]
struct Rooted {
    here: std::cell::Cell<u64>,
    /// A raw pointer is the plainest way to say "not `Send`" without
    /// depending on an unstable marker.
    _anchor: std::marker::PhantomData<*const ()>,
}

impl Progress for Rooted {
    fn output(&mut self, total: u64) -> Result<()> {
        self.here.set(total);
        Ok(())
    }
}

/// **Test 10.** Without the `parallel` feature there is no thread and the
/// bytes are the same; and a `Progress` that is not `Send` still compiles
/// against the whole read path either way.
#[test]
fn a_progress_that_is_not_send_still_drives_the_read_path() {
    let _guard = counter();
    let payload = body(3 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let _seam = Seam::on();
    probe::reset_peak_seam();

    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording(Arc::clone(&held));
    let mut progress = Rooted::default();
    rarkit::extract(
        sources(&volumes),
        &ReadOptions::default(),
        &mut sink,
        &mut progress,
    )
    .expect("extract");
    let bytes = held.lock().unwrap_or_else(|e| e.into_inner()).bytes.clone();
    assert!(bytes == payload, "the member's own bytes came back");

    #[cfg(not(feature = "parallel"))]
    assert_eq!(
        probe::peak_seam(),
        0,
        "without the parallel feature the stages run in sequence on the \
         calling thread and no thread is spawned"
    );
    #[cfg(feature = "parallel")]
    assert_eq!(
        probe::peak_seam(),
        1,
        "with the feature on and the floor at zero, this member is \
         overlapped - so test 10's negative is measuring something"
    );
}

// ---------------------------------------------------------------------------
// 11. THE OTHER REFUSAL ON THE WALKING THREAD: a `Progress` that says no
// ---------------------------------------------------------------------------

/// A writer that takes everything, so the refusal under test is the only
/// one in the member.
struct Taking;

impl Write for Taking {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct TakingSink;

impl Sink for TakingSink {
    type Out = Taking;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Taking>> {
        Ok(Disposition::Write(Taking))
    }
}

/// A `Progress` whose FIRST `released` refuses, recording what the source
/// had read by then and counting the calls it was given.
struct RefusingProgress {
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
}

impl Progress for RefusingProgress {
    fn released(&mut self, _volume: u32, _offset: u64) -> Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.at_refusal
            .store(self.source.read.load(Ordering::Relaxed), Ordering::Relaxed);
        Err(rarkit::Error::caller("the caller's observer refuses"))
    }
    fn output(&mut self, _total: u64) -> Result<()> {
        Ok(())
    }
}

/// **The eleventh, and it is test 4's other half.** Test 4 prices the
/// refusal that arrives through the caller's WRITER. The walking thread
/// has a second refusal to relay and the seam is the reason it exists: a
/// member's `released` news no longer goes straight into `Progress` from
/// the stream, it is recorded into `walk::Notes` by the source unit and
/// drained on the walking thread, so a `Progress` that returns an error
/// is a refusal raised on the DELIVER side about work the SOURCE side
/// already did. It must stop that work under the same bound, and nothing
/// in test 4 covers it: a refusing writer never reaches
/// `Notes::drain_into` at all.
///
/// This is the seam's share of the promise an earlier revision made for the
/// piped path (spec F 3.7.6, a caller's refusal reaching a member's
/// DECODE and not only its close). The two paths are disjoint - a member
/// decoded on `extract_parallel`'s walking thread does not take the seam
/// (`Driver::overlaps`) - so neither test stands in for the other.
///
/// Bounded exactly as test 4 is, in SOURCE BYTES READ and never in wall
/// clock, and non-vacuous on both arms: the assertion that `released` was
/// called at all is what stops an arm that never refused from passing.
#[test]
fn a_refusing_progress_stops_the_source_unit() {
    let _guard = counter();
    let payload = body(32 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let policy = MemoryPolicy::default();

    for on in [true, false] {
        let _seam = if on { Seam::on() } else { Seam::off() };
        let source = Arc::new(Counted {
            bytes: volumes[0].clone(),
            read: AtomicU64::new(0),
        });
        let at_refusal = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let mut progress = RefusingProgress {
            source: Arc::clone(&source),
            at_refusal: Arc::clone(&at_refusal),
            calls: Arc::clone(&calls),
        };
        let err = rarkit::extract(
            vec![Arc::clone(&source) as Arc<dyn RangeSource>],
            &ReadOptions::default(),
            &mut TakingSink,
            &mut progress,
        )
        .expect_err("a refusing observer ends the operation");
        assert!(
            err.into_caller_error().is_ok(),
            "seam={on}: a refused `released` comes back as the caller's own error"
        );
        let asked = calls.load(Ordering::Relaxed);
        assert!(
            asked >= 1,
            "seam={on}: this arm really did raise the refusal under test \
             rather than passing because nothing ever asked"
        );
        let by_refusal = at_refusal.load(Ordering::Relaxed);
        let after = source.read.load(Ordering::Relaxed) - by_refusal;
        let bound = policy.read_ahead + (1 << 20);
        println!(
            "seam={on}: `released` asked {asked} time(s); {by_refusal} source \
             bytes read by the refusal, {after} after it, bound {bound}, \
             member {} bytes",
            payload.len()
        );
        // Without this the bound above could be met by a source that had
        // already read the whole archive before the observer was ever
        // called, which would stop nothing and prove nothing.
        assert!(
            by_refusal < volumes[0].len() as u64,
            "seam={on}: the observer refused with only {by_refusal} of the \
             archive's {} bytes read, so there was work left for the \
             refusal to stop",
            volumes[0].len()
        );
        assert!(
            after <= bound,
            "seam={on}: {after} source bytes were read AFTER the observer \
             refused, where one ring plus one read is at most {bound}, over \
             a {} byte member",
            payload.len()
        );
    }
}

// ---------------------------------------------------------------------------
// 11. THE FLOOR ITSELF
// ---------------------------------------------------------------------------

/// **The floor, asserted rather than benched.** A member BELOW the floor
/// takes no seam at all: `engages` is false, and what runs is the code the
/// sequential path always ran.
///
/// That is why no `off` against `<floor>` bench sweep was taken. A
/// row comparing the two would be measuring the box, not the engine: for
/// a member under the floor the two settings select the same instructions,
/// so any difference between them is noise by construction and any
/// agreement is a tautology. What a bench CAN say is where the seam's sign
/// flips with SIZE, which is the measured size ladder, and the
/// floor is then the rung above the crossover.
///
/// What is worth asserting is the thing the ladder assumes: that the floor
/// is obeyed at all, in both directions, on the same member. Below it the
/// seam never starts a source unit; at it and above, it does.
#[test]
fn the_floor_decides_whether_a_member_is_overlapped_at_all() {
    let _guard = counter();
    let payload = body(4 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let member = payload.len() as u64;

    for (floor, want) in [
        (0u64, true),
        (member / 2, true),
        (member, true),
        (member + 1, false),
        (member * 2, false),
        (u64::MAX, false),
    ] {
        probe::reset_peak_seam();
        probe::set_seam_floor(Some(floor));
        let held = Arc::new(Mutex::new(Keep::default()));
        let mut sink = Recording(Arc::clone(&held));
        let report = rarkit::extract(sources(&volumes), &options(shape), &mut sink, &mut ())
            .expect("the member extracts either way");
        drop(sink);
        probe::set_seam_floor(None);
        let seen = probe::peak_seam();
        assert_eq!(
            seen > 0,
            want,
            "floor {floor} over a {member} byte member: {seen} source \
             unit(s) ran, wanted {}",
            if want { "at least one" } else { "none" }
        );
        let keep = Arc::try_unwrap(held)
            .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            keep.bytes, payload,
            "floor {floor}: the bytes are the member's either way"
        );
        assert_eq!(
            keep.verdict,
            Some(Some(true)),
            "floor {floor}: the verdict is the member's either way"
        );
        assert!(
            report.peak_working_memory > 0,
            "floor {floor}: a report is still a report"
        );
    }
}

/// **The measurement knob is real, and the default is the tight one.**
/// `probe::set_seam_coalesce(Some(true))` restores the deliver unit that
/// wrote each ring buffer with one call, which is the shape that loosened
/// spec F 3.7.6's bound. It exists only so the wall that shape was buying
/// can be priced against the shape that ships. It has to be
/// a knob and not a second sha: code
/// layout alone moves an untouched leg about 7 percent, so a before and
/// after is ONE BINARY against itself.
///
/// A knob nothing checks is a knob that can quietly stop working and take
/// a timed run's answer with it. This asserts both ends: with it ON a
/// refusing writer is offered strictly MORE than the sequential path, and
/// with it at its default it is offered no more.
#[test]
fn the_coalescing_deliver_unit_is_reachable_and_is_not_the_default() {
    let _guard = counter();
    let payload = body(6 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let ceiling = 100 << 10;

    let offer = |coalesce: Option<bool>, seam_on: bool| -> (u64, u64) {
        let _seam = if seam_on { Seam::on() } else { Seam::off() };
        probe::set_seam_coalesce(coalesce);
        let offered = Arc::new(AtomicU64::new(0));
        let writes = Arc::new(AtomicU64::new(0));
        let mut sink = Ceilings {
            ceiling,
            offered: Arc::clone(&offered),
            writes: Arc::clone(&writes),
        };
        rarkit::extract(sources(&volumes), &options(shape), &mut sink, &mut ())
            .expect_err("a refusing writer ends the operation");
        probe::set_seam_coalesce(None);
        (
            offered.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed),
        )
    };

    let (sequential, seq_writes) = offer(None, false);
    let (shipped, shipped_writes) = offer(None, true);
    let (coalescing, coalescing_writes) = offer(Some(true), true);
    println!(
        "sequential {sequential} in {seq_writes}; seam {shipped} in \
         {shipped_writes}; seam coalescing {coalescing} in \
         {coalescing_writes}"
    );

    assert!(
        shipped <= sequential,
        "the shipped seam offered {shipped} where the sequential path \
         offered {sequential}"
    );
    assert!(
        coalescing > sequential,
        "the coalescing knob is not reaching the deliver unit: it offered \
         {coalescing}, no more than the sequential path's {sequential}, so \
         a timing taken with it would be pricing nothing"
    );
    assert!(
        coalescing_writes < shipped_writes,
        "coalescing must make FEWER, bigger calls: {coalescing_writes} \
         against the shipped {shipped_writes}"
    );
}

/// **The seam does not narrow the decode it wraps.** A member decoded
/// inside a source unit opens the same tape lanes as the same member
/// decoded on the walking thread, because the seam is handed the walking
/// thread's own `Decoders` and never builds or re-derives a width of its
/// own.
///
/// Worth an assertion rather than a reading of the code, because the
/// width dial of API 8.4.2 landed by setting `Decoders::decode_width` in
/// exactly one place, and anything that decodes through a `Decoders` it
/// did not get from there silently decodes at a width of one. The seam is
/// the newest such caller. Nothing here fixes another caller in that
/// position: this pins the seam.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_seam_decodes_at_the_width_the_walking_thread_would_have() {
    let _guard = counter();
    // 24 MiB, which is what `tests/breadth_width.rs` needs before the RAR
    // 5 tape opens a lane at all: a chunk has to hold several blocks
    // before there is anything to spread. At 6 MiB both arms read ZERO
    // lanes and the assertion below is a tautology, which is worse than
    // no test.
    let payload = body(24 << 20);
    // The `-m3` shape, which is the only one here with a tape to widen:
    // a stored member has no decoder at all.
    let shape = SHAPES[1];
    let volumes = archive(shape, &payload);

    let lanes = |on: bool| -> usize {
        let _seam = if on { Seam::on() } else { Seam::off() };
        probe::reset_peak_lanes();
        let held = Arc::new(Mutex::new(Keep::default()));
        let mut sink = Recording(Arc::clone(&held));
        rarkit::extract(
            sources(&volumes),
            &options(shape).with_workers(Some(8)),
            &mut sink,
            &mut (),
        )
        .expect("extract");
        drop(sink);
        let keep = Arc::try_unwrap(held)
            .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(keep.bytes, payload, "the member's bytes either way");
        probe::peak_lanes()
    };

    let off = lanes(false);
    let on = lanes(true);
    println!("tape lanes: seam off {off}, seam on {on}, read width 8");
    // THE MACHINE THIS STATES: a read width of eight BY NAME, the shape's
    // own memory policy, one member of 24 MiB. A stated width meets the
    // machine's lanes, the hardware threads less one for the apply stage,
    // and a member is spread only from two lanes: three hardware threads
    // or more. The engine is asked (`probe::tape_host_lanes`). A hosted
    // Windows runner of two threads gives one lane and read "seam off 0,
    // seam on 0" on 6 Oct 2026; there the member decodes on the walking
    // thread alone on both arms, which is pinned, beside its bytes above.
    let host = probe::tape_host_lanes(true);
    if host < 2 {
        assert_eq!(
            (off, on),
            (0, 0),
            "this machine gives a stated width {host} lane(s), under the two a spread \
             needs, and yet lane threads were alive"
        );
        eprintln!(
            "the seam's width is NOT READ: this machine gives a stated width {host} \
             lane(s) and a spread needs two (three hardware threads); the member's bytes \
             were held on both arms"
        );
        return;
    }
    // NON-VACUOUS FIRST. A test that reads zero lanes on both arms proves
    // nothing and looks like a guard, which is how a width regression
    // gets past one.
    assert!(
        off > 1,
        "this fixture opened {off} tape lane(s) on the sequential path at \
         a read width of 8, so it cannot tell whether the seam narrows \
         the decode: widen the member until it does"
    );
    assert_eq!(
        on, off,
        "the seam decoded at {on} tape lane(s) where the sequential path \
         used {off}: it is not carrying the walking thread's width"
    );
}

// ---------------------------------------------------------------------------
// 12. THE CALLER'S COST CLASS: `ReadOptions::sink_is_file`
// ---------------------------------------------------------------------------

/// [`options`], with the caller's seam cost class set.
fn hinted(shape: Shape, hint: Option<bool>) -> ReadOptions {
    options(shape).with_sink_is_file(hint)
}

/// One extraction at `floor` with `hint`: whether a source unit ran, and
/// what the sink saw.
///
/// The seam is read from `probe::peak_seam` and not from the thread ids
/// the sink records, and the difference matters. The DELIVER unit is the
/// walking thread whether the seam is engaged or not (test 3), so every
/// call a caller sees is on one thread in both arms and the thread ids
/// cannot tell them apart. The counter can: the SOURCE unit is the second
/// thread, and it is the thing the field moves.
#[cfg(feature = "parallel")]
fn taken(shape: Shape, volumes: &[Vec<u8>], floor: u64, hint: Option<bool>) -> (bool, Keep) {
    probe::reset_peak_seam();
    probe::set_seam_floor(Some(floor));
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording(Arc::clone(&held));
    let report = rarkit::extract(sources(volumes), &hinted(shape, hint), &mut sink, &mut ())
        .expect("the member extracts whatever the hint says");
    drop(sink);
    probe::set_seam_floor(None);
    let engaged = probe::peak_seam() > 0;
    assert!(
        report.peak_working_memory > 0,
        "hint {hint:?} at floor {floor}: a report is still a report"
    );
    let keep = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (engaged, keep)
}

/// **The acceptance test SPEC-API 8.5 names for the hint, and it has no
/// stopwatch in it.** A member BELOW the measured size floor, extracted
/// three times: once with `sink_is_file: None`, once with `Some(true)` and
/// once with `Some(false)`. The seam is OFF for `None` and `Some(false)`
/// and ON for `Some(true)`, and all three runs produce byte-identical
/// output and the same verdict, so the field is proven to move the gate
/// and nothing else.
///
/// Then the other half of the rule, which is the half a boolean makes easy
/// to get wrong: ABOVE the floor `Some(false)` does NOT force the seam
/// off. It falls back to the floor's own answer, which above the floor is
/// on. The field can only ever move the threshold the ladder measured, and
/// never contradict a later measurement over the top of it.
///
/// Skipped without the `parallel` feature, where there is no seam for any
/// value of the field: the negative that says so is test 10's.
#[test]
#[cfg(feature = "parallel")]
fn the_sink_cost_class_moves_the_gate_and_nothing_else() {
    let _guard = counter();
    let payload = body(4 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let member = payload.len() as u64;

    // BELOW the floor: only the caller's "this is a real file" reaches
    // past it.
    let above_the_member = member + 1;
    let mut seen = Vec::new();
    for (hint, want) in [(None, false), (Some(true), true), (Some(false), false)] {
        let (engaged, keep) = taken(shape, &volumes, above_the_member, hint);
        assert_eq!(
            engaged,
            want,
            "a {member} byte member under a floor of {above_the_member}, \
             sink_is_file {hint:?}: the seam was {}, wanted {}",
            if engaged { "engaged" } else { "not engaged" },
            if want { "engaged" } else { "not engaged" }
        );
        assert_eq!(
            keep.verdict,
            Some(Some(true)),
            "sink_is_file {hint:?}: the verdict is the member's whatever \
             the cost class says"
        );
        assert_eq!(
            keep.reported, member,
            "sink_is_file {hint:?}: the member's own byte count"
        );
        seen.push(keep.bytes);
    }
    assert_eq!(
        seen[0], payload,
        "sink_is_file None: the bytes are the member's"
    );
    assert!(
        seen[1] == seen[0] && seen[2] == seen[0],
        "the three runs are not byte-identical: {} bytes with None, {} \
         with Some(true), {} with Some(false)",
        seen[0].len(),
        seen[1].len(),
        seen[2].len()
    );

    // ABOVE the floor, `Some(false)` asks the floor rather than refusing.
    let (engaged, keep) = taken(shape, &volumes, member / 2, Some(false));
    assert!(
        engaged,
        "above the floor, sink_is_file Some(false) falls back to the \
         floor's own answer rather than forcing the seam off"
    );
    assert_eq!(
        keep.bytes, payload,
        "above the floor with Some(false): the bytes are still the \
         member's"
    );
    assert_eq!(
        keep.verdict,
        Some(Some(true)),
        "above the floor with Some(false): the verdict is unmoved"
    );
}

/// **`None` is today's behaviour exactly, at every size the floor test
/// asks about.** The field is additive in BEHAVIOUR as well as in source,
/// and that is a claim about the whole of the floor's range and not about
/// one member.
///
/// The table is the one
/// [`the_floor_decides_whether_a_member_is_overlapped_at_all`] uses, run
/// again with `sink_is_file: None` explicitly set rather than defaulted:
/// the engage decision it gives is the floor's own at every rung, and the
/// bytes and the verdict never move. A caller that never touches the field
/// gets what it got before the field existed, and a caller that writes
/// `None` gets the same thing.
#[test]
#[cfg(feature = "parallel")]
fn the_unset_cost_class_is_the_size_floor_at_every_rung() {
    let _guard = counter();
    let payload = body(4 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let member = payload.len() as u64;

    for (floor, want) in [
        (0u64, true),
        (member / 2, true),
        (member, true),
        (member + 1, false),
        (member * 2, false),
        (u64::MAX, false),
    ] {
        // The floor alone, as the engine has always asked it.
        let (by_floor, from_floor) = taken(shape, &volumes, floor, None);
        assert_eq!(
            by_floor,
            want,
            "floor {floor}, sink_is_file None: the seam was {}, wanted \
             the floor's own answer",
            if by_floor { "engaged" } else { "not engaged" }
        );
        assert_eq!(
            from_floor.bytes, payload,
            "floor {floor}, sink_is_file None: the bytes are the member's"
        );
        assert_eq!(
            from_floor.verdict,
            Some(Some(true)),
            "floor {floor}, sink_is_file None: the verdict is the \
             member's"
        );
        // And `Some(false)` agrees with it at every rung, which is what
        // "keeps the seam off BELOW the floor" means once it is read as a
        // rule over the whole range rather than as one assertion.
        let (by_hint, from_hint) = taken(shape, &volumes, floor, Some(false));
        assert_eq!(
            by_hint, by_floor,
            "floor {floor}: sink_is_file Some(false) answered {} where \
             the floor answered {}",
            by_hint, by_floor
        );
        assert_eq!(
            from_hint.bytes, from_floor.bytes,
            "floor {floor}: Some(false) moved the bytes"
        );
    }
}

/// **The cancellation bound of 8.5 is unchanged with the hint set**, which
/// is the promise a new way of engaging the seam is most likely to break:
/// the field reaches the gate, so it reaches the seam, so the bound test 4
/// exists for has to hold on the path the field opens.
///
/// This is test 4's shape at the ENGINE'S OWN floor, which a 32 MiB member
/// is far below, so the only thing engaging the seam here is
/// `sink_is_file: Some(true)`. That the source unit ran at all is asserted
/// first: without it this would be test 4's sequential arm wearing a new
/// name, and would pass while proving nothing.
#[test]
#[cfg(feature = "parallel")]
fn the_refusal_bound_holds_on_the_path_the_hint_opens() {
    let _guard = counter();
    let payload = body(32 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let policy = MemoryPolicy::default();

    probe::reset_peak_seam();
    let source = Arc::new(Counted {
        bytes: volumes[0].clone(),
        read: AtomicU64::new(0),
    });
    let at_refusal = Arc::new(AtomicU64::new(0));
    let offered = Arc::new(AtomicU64::new(0));
    let mut sink = RefusingSink {
        source: Arc::clone(&source),
        at_refusal: Arc::clone(&at_refusal),
        offered: Arc::clone(&offered),
    };
    let err = rarkit::extract(
        vec![Arc::clone(&source) as Arc<dyn RangeSource>],
        &hinted(shape, Some(true)),
        &mut sink,
        &mut (),
    )
    .expect_err("a refusing writer ends the operation, hint or no hint");
    assert!(
        err.into_caller_error().is_ok(),
        "a refused write comes back as the caller's own error"
    );
    assert!(
        probe::peak_seam() > 0,
        "sink_is_file Some(true) did not engage the seam on a {} byte \
         member, so this is test 4's sequential arm and proves nothing",
        payload.len()
    );
    let after = source.read.load(Ordering::Relaxed) - at_refusal.load(Ordering::Relaxed);
    let bound = policy.read_ahead + (1 << 20);
    println!(
        "sink_is_file Some(true): {after} source bytes read after the \
         refusal, bound {bound}, member {} bytes",
        payload.len()
    );
    assert!(
        after <= bound,
        "with the hint set, {after} source bytes were read AFTER the \
         refusal, where one ring plus one read is at most {bound}, over a \
         {} byte member",
        payload.len()
    );
}

/// **The same bound on the wide read**, which a stored CRC32 member of 32
/// MiB takes when the caller says its writer is NOT a file
/// (`sink_is_file` of `Some(false)`, as `p` does): its pieces are read at most
/// `read_ahead` ahead of the byte being written, so a writer that refuses
/// costs at most the pieces already in flight. That the wide read ran is
/// asserted first, for the reason the test above gives.
#[test]
#[cfg(feature = "parallel")]
fn the_refusal_bound_holds_on_the_wide_path() {
    let _guard = counter();
    let payload = body(32 << 20);
    let shape = SHAPES[0];
    let volumes = archive(shape, &payload);
    let policy = MemoryPolicy::default();

    probe::reset_wide_verifies();
    let source = Arc::new(Counted {
        bytes: volumes[0].clone(),
        read: AtomicU64::new(0),
    });
    let at_refusal = Arc::new(AtomicU64::new(0));
    // Refusing only past 8 MiB, so the refusal lands INSIDE the wide read
    // and not on the fragment's head, which the walk's own buffer already
    // holds and which is read the ordinary way first.
    let mut sink = LateRefusingSink {
        source: Arc::clone(&source),
        at_refusal: Arc::clone(&at_refusal),
        after: 8 << 20,
    };
    let err = rarkit::extract(
        vec![Arc::clone(&source) as Arc<dyn RangeSource>],
        &hinted(shape, Some(false)).with_workers(Some(4)),
        &mut sink,
        &mut (),
    )
    .expect_err("a refusing writer ends the operation on the wide path too");
    assert!(
        err.into_caller_error().is_ok(),
        "a refused write comes back as the caller's own error"
    );
    assert!(
        probe::wide_verifies() > 0,
        "a {} byte stored CRC32 member did not take the wide read, so this \
         proves nothing about it",
        payload.len()
    );
    let after = source.read.load(Ordering::Relaxed) - at_refusal.load(Ordering::Relaxed);
    let bound = policy.read_ahead + (1 << 20);
    println!(
        "wide read: {after} source bytes read after the refusal, bound \
         {bound}, member {} bytes",
        payload.len()
    );
    assert!(
        after <= bound,
        "on the wide read, {after} source bytes were read AFTER the \
         refusal, where the pieces in flight are at most {bound}, over a \
         {} byte member",
        payload.len()
    );
}

// ---------------------------------------------------------------------------
// 13. A MEMBER WITH A DECODER: its own floor, and its checksum on the
//     deliver unit (22 Sep 2026)
// ---------------------------------------------------------------------------

/// A sink that answers `Verify`: the `t` command's shape, no writer at all.
struct Verifying(Arc<Mutex<Keep>>);

impl Sink for Verifying {
    type Out = Recorder;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Recorder>> {
        Ok(Disposition::Verify)
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Recorder>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        held.verdict = Some(outcome.checksum_ok);
        held.reported = outcome.bytes;
        Ok(())
    }
}

/// One extraction at the ENGINE'S OWN floors (no harness knob set), with
/// `hint`, written or verified: whether a source unit ran, and what the
/// sink saw.
#[cfg(feature = "parallel")]
fn at_the_engines_floor(
    shape: Shape,
    volumes: &[Vec<u8>],
    hint: Option<bool>,
    verify: bool,
) -> (bool, Keep) {
    probe::reset_peak_seam();
    probe::set_seam_floor(None);
    let held = Arc::new(Mutex::new(Keep::default()));
    let opts = hinted(shape, hint);
    let report = if verify {
        let mut sink = Verifying(Arc::clone(&held));
        rarkit::extract(sources(volumes), &opts, &mut sink, &mut ())
    } else {
        let mut sink = Recording(Arc::clone(&held));
        rarkit::extract(sources(volumes), &opts, &mut sink, &mut ())
    }
    .expect("the member extracts");
    let engaged = probe::peak_seam() > 0;
    assert!(report.peak_working_memory > 0, "a report is still a report");
    let keep = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (engaged, keep)
}

/// **A member with a decoder is overlapped from a floor of its own, and a
/// stored member is not.** `seam::COMPRESSED_FLOOR` is 16 MiB and
/// `SEAM_FLOOR` a gigabyte, both measured constants and neither an API
/// fact (SPEC-API 8.5), so what this pins is the SHAPE of the rule and
/// not the figures: at 20 MiB with no hint an `-m3` member engages and a
/// stored one does not, at 8 MiB neither does, and the bytes and the
/// verdict are the member's own in every arm.
#[test]
#[cfg(feature = "parallel")]
fn a_member_with_a_decoder_is_overlapped_from_its_own_floor() {
    let _guard = counter();
    let compressed = SHAPES[1];
    let stored = SHAPES[0];
    assert_eq!(compressed.label, "-m3");
    assert_eq!(stored.label, "stored crc32");
    for (size, want_compressed) in [(20usize << 20, true), (8 << 20, false)] {
        let payload = body(size);
        for (shape, want) in [(compressed, want_compressed), (stored, false)] {
            let volumes = archive(shape, &payload);
            let (engaged, keep) = at_the_engines_floor(shape, &volumes, None, false);
            assert_eq!(
                engaged,
                want,
                "{} at {size} bytes, no hint: the seam was {}",
                shape.label,
                if engaged { "engaged" } else { "not engaged" }
            );
            assert_eq!(keep.bytes, payload, "{} at {size}: the bytes", shape.label);
            assert_eq!(
                keep.verdict,
                Some(Some(true)),
                "{} at {size}: the verdict",
                shape.label
            );
            // `Some(false)` says the writer is in memory, and for a member
            // with a decoder that is exactly the writer the deliver unit
            // has room for: it engages the same.
            let (with_hint, keep) = at_the_engines_floor(shape, &volumes, Some(false), false);
            assert_eq!(
                with_hint, engaged,
                "{} at {size}: Some(false) answered {} where None answered {}",
                shape.label, with_hint, engaged
            );
            assert_eq!(keep.bytes, payload);
        }
    }
}

/// **A stored member that reads into the ring is overlapped from a floor
/// of its own, and the other stored members are not.** A clear member
/// under a CRC32 lands its reads in the seam's ring, so the seam costs it
/// no copy and it is taken from `seam::LENT_FLOOR` (32 MiB; a measured
/// constant, SPEC-API 8.5, so the figure is this test's to follow). A
/// member under BLAKE2sp or a cipher would get the hand-over alone and
/// keeps `SEAM_FLOOR`, a gibibyte. Pinned on both sides of 32 MiB with no
/// hint (under `Some(false)` a member this size is the wide read's and
/// never asks); the bytes and the verdict are the member's in every arm.
///
/// ON WINDOWS every stored member keeps a gibibyte (NOT MEASURED there:
/// no Windows box sat the count), so there this pins the other answer:
/// none of the six members is overlapped. It runs in the shipped feature
/// set on every system, which the tool's say line (a count build's) does
/// not. Needs a read width of two or more (the default wherever there are
/// two threads) and holds about 150 MiB at once.
#[test]
#[cfg(feature = "parallel")]
fn a_stored_member_that_reads_into_the_ring_is_overlapped_from_its_own_floor() {
    let _guard = counter();
    let (clear, hashed, keyed) = (SHAPES[0], SHAPES[2], SHAPES[3]);
    assert_eq!(clear.label, "stored crc32");
    assert_eq!(hashed.label, "stored blake2sp");
    assert_eq!(keyed.label, "stored encrypted");
    for (size, want_clear) in [(33usize << 20, !cfg!(windows)), (31 << 20, false)] {
        let payload = body(size);
        for (shape, want) in [(clear, want_clear), (hashed, false), (keyed, false)] {
            let volumes = archive(shape, &payload);
            let (engaged, keep) = at_the_engines_floor(shape, &volumes, None, false);
            assert_eq!(
                engaged,
                want,
                "{} at {size} bytes, no hint: the seam was {}",
                shape.label,
                if engaged { "engaged" } else { "not engaged" }
            );
            assert!(
                keep.bytes == payload,
                "{} at {size}: the bytes",
                shape.label
            );
            assert_eq!(
                keep.verdict,
                Some(Some(true)),
                "{} at {size}: the verdict",
                shape.label
            );
        }
    }
}

/// **A VERIFIED member is NOT overlapped, decoder or no decoder.** The
/// floor ladder measured a verified member's seam a wash to a loss (one
/// checksum pass hidden behind one ring copy and the hand-overs), so
/// `engages` keeps every `Verify` member in sequence; this pins that the
/// rule is by DISPOSITION and not by size, at a size where the written
/// twin engages, and that the verdict is the member's either way.
#[test]
#[cfg(feature = "parallel")]
fn a_verified_member_stays_in_sequence_whatever_its_codec() {
    let _guard = counter();
    let payload = body(20 << 20);
    for shape in [SHAPES[1], SHAPES[0]] {
        let volumes = archive(shape, &payload);
        let (engaged, keep) = at_the_engines_floor(shape, &volumes, None, true);
        assert!(
            !engaged,
            "{}, verified, 20 MiB: a source unit ran for a member with no writer",
            shape.label
        );
        assert_eq!(
            keep.verdict,
            Some(Some(true)),
            "{}: the verdict",
            shape.label
        );
        assert_eq!(keep.reported, payload.len() as u64);
    }
    // And the written twin of the decoded shape DOES engage at this size,
    // which is what makes the assertion above about the disposition.
    let volumes = archive(SHAPES[1], &payload);
    let (engaged, keep) = at_the_engines_floor(SHAPES[1], &volumes, None, false);
    assert!(engaged, "-m3, written, 20 MiB: the seam did not engage");
    assert_eq!(keep.bytes, payload);
}

/// **The deliver unit's CRC32 is the member's, on a WRITTEN member with a
/// decoder at the engine's own floor**: a damaged 20 MiB `-m3` member
/// fails its checksum exactly as it does in sequence, and the bytes the
/// caller was handed are the same wrong bytes.
#[test]
#[cfg(feature = "parallel")]
fn the_deliver_units_checksum_is_the_members() {
    let _guard = counter();
    let payload = body(20 << 20);
    let compressed = SHAPES[1];
    let mut damaged = archive(compressed, &payload);
    let at = damaged[0].len() / 2;
    damaged[0][at] ^= 0xff;
    let (engaged, with) = at_the_engines_floor(compressed, &damaged, None, false);
    assert!(engaged, "-m3, written, 20 MiB: the seam did not engage");
    let (without, _) = run(compressed, &damaged, false);
    assert_eq!(with.verdict, Some(Some(false)));
    assert_eq!(
        with.verdict, without.verdict,
        "the verdict moved with the seam"
    );
    assert_eq!(with.bytes, without.bytes, "the bytes moved with the seam");
    assert_eq!(with.reported, without.reported);
}

// ---------------------------------------------------------------------------
// The lent path's whole-slab request (29 Sep 2026)
// ---------------------------------------------------------------------------

/// Keeps a member's bytes and the length of every write the seam made.
#[derive(Default)]
struct Lengths {
    seen: Arc<Mutex<(Vec<u8>, Vec<usize>)>>,
}

struct LengthsOut(Arc<Mutex<(Vec<u8>, Vec<usize>)>>);

impl Write for LengthsOut {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut seen = self.0.lock().unwrap_or_else(|e| e.into_inner());
        seen.0.extend_from_slice(data);
        seen.1.push(data.len());
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Lengths {
    type Out = LengthsOut;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<LengthsOut>> {
        Ok(Disposition::Write(LengthsOut(Arc::clone(&self.seen))))
    }
}

/// A clear stored member on the seam's lent path, asked for WHOLE SLABS
/// (`extract::lent::WHOLE_SLAB_FLOOR`, forced here through the probe dial
/// so a 6 MiB fixture takes the big member's shape), is written one slab
/// at a time: the ring is the whole default read-ahead (4 MiB) in two slabs
/// of 2 MiB (`seam::ring_plan`), each slab filled across its reads (the
/// first read is short, the walk's header window's remainder) and handed
/// over as one write, so six megabytes reach the writer in exactly three
/// writes of a slab each, at slab-aligned offsets of the member. Asked
/// for its ordinary request, the same member arrives one write per read,
/// none over `STORED_REQUEST` (128 KiB). The bytes are the payload both
/// ways.
#[cfg(feature = "parallel")]
#[test]
fn a_lent_stored_member_asked_for_whole_slabs_is_written_a_slab_at_a_time() {
    let _guard = counter();
    let payload = body(6 << 20);
    let shape = SHAPES[0];
    assert_eq!(shape.label, "stored crc32");
    let volumes = archive(shape, &payload);
    let run = |whole: bool| -> (Vec<u8>, Vec<usize>) {
        let _seam = Seam::on();
        probe::set_lent_whole_slab(Some(whole));
        let mut sink = Lengths::default();
        let report = rarkit::extract(
            sources(&volumes),
            &options(shape).with_workers(Some(4)),
            &mut sink,
            &mut (),
        );
        probe::set_lent_whole_slab(None);
        report.expect("extracts");
        let seen = sink.seen.lock().unwrap_or_else(|e| e.into_inner());
        (seen.0.clone(), seen.1.clone())
    };
    let (whole_bytes, whole_lengths) = run(true);
    let (piece_bytes, piece_lengths) = run(false);
    assert!(whole_bytes == payload, "whole slabs: the bytes differ");
    assert!(piece_bytes == payload, "pieces: the bytes differ");
    let chunk = 2usize << 20;
    assert_eq!(
        whole_lengths,
        vec![chunk, chunk, chunk],
        "whole slabs: the writes were {whole_lengths:?}"
    );
    assert!(
        piece_lengths.iter().all(|&n| n <= 128 << 10) && piece_lengths.len() >= 48,
        "pieces: {} writes, the largest {}",
        piece_lengths.len(),
        piece_lengths.iter().max().copied().unwrap_or(0)
    );
}

/// A member's bytes and, for every write the seam made, its length and
/// whether its address lay on a 4,096 byte boundary.
type Seen = Arc<Mutex<(Vec<u8>, Vec<(usize, bool)>)>>;

/// Keeps what [`Seen`] holds.
#[derive(Default)]
struct Shapes {
    seen: Seen,
}

struct ShapesOut(Seen);

impl Write for ShapesOut {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut seen = self.0.lock().unwrap_or_else(|e| e.into_inner());
        seen.0.extend_from_slice(data);
        let aligned = (data.as_ptr() as usize).is_multiple_of(4096);
        seen.1.push((data.len(), aligned));
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Shapes {
    type Out = ShapesOut;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<ShapesOut>> {
        Ok(Disposition::Write(ShapesOut(Arc::clone(&self.seen))))
    }
}

/// **Test 11's second sentence: a member with a DECODER (section 3.7.7).** An `-m3`
/// member asked for whole slabs (the same 1 GiB floor and dial as the lent
/// stored member's, forced here so a 9 MiB fixture takes the big member's
/// shape) reaches the writer one slab at a time: every write but the last
/// exactly `read_ahead / 2` and at a 4,096 aligned address, at the engine's
/// 4 MiB read-ahead and at rarfast's 8 MiB, whatever size the window's
/// drain pieces were. Not asked, the same member arrives as the window's
/// pieces, none of them a whole slab. The bytes are the payload every way,
/// and the seam's off arm agrees.
#[cfg(feature = "parallel")]
#[test]
fn a_compressed_member_asked_for_whole_slabs_is_written_a_slab_at_a_time() {
    let _guard = counter();
    let payload = body(9 << 20);
    let shape = SHAPES[1];
    assert_eq!(shape.label, "-m3");
    let volumes = archive(shape, &payload);
    let slabbed = |whole: bool, read_ahead: u64| -> (Vec<u8>, Vec<(usize, bool)>) {
        let _seam = Seam::on();
        probe::set_lent_whole_slab(Some(whole));
        let mut sink = Shapes::default();
        let options = options(shape)
            .with_memory(MemoryPolicy {
                read_ahead,
                ..MemoryPolicy::default()
            })
            .with_workers(Some(4));
        let report = rarkit::extract(sources(&volumes), &options, &mut sink, &mut ());
        probe::set_lent_whole_slab(None);
        report.expect("extracts");
        let seen = sink.seen.lock().unwrap_or_else(|e| e.into_inner());
        (seen.0.clone(), seen.1.clone())
    };
    for read_ahead in [4u64 << 20, 8 << 20] {
        let chunk = (read_ahead / 2) as usize;
        let (bytes, writes) = slabbed(true, read_ahead);
        assert!(
            bytes == payload,
            "{read_ahead}: whole slabs: the bytes differ"
        );
        let (last, whole) = writes.split_last().expect("at least one write");
        assert_eq!(
            whole.len(),
            payload.len() / chunk,
            "{read_ahead}: {writes:?}"
        );
        assert!(
            whole.iter().all(|&(n, aligned)| n == chunk && aligned),
            "{read_ahead}: whole slabs: the writes were {writes:?}"
        );
        assert_eq!(last.0, payload.len() - whole.len() * chunk);
        assert!(last.1, "{read_ahead}: the last slab starts off a page");

        let (bytes, writes) = slabbed(false, read_ahead);
        assert!(bytes == payload, "{read_ahead}: pieces: the bytes differ");
        assert!(
            writes.len() > payload.len() / chunk + 1 && writes.iter().all(|&(n, _)| n < chunk),
            "{read_ahead}: pieces: {} writes, the largest {}",
            writes.len(),
            writes.iter().map(|&(n, _)| n).max().unwrap_or(0)
        );
    }
    let (off, report) = run(shape, &volumes, false);
    report.expect("extracts in sequence");
    assert!(off.bytes == payload, "the seam's off arm: the bytes differ");
}
