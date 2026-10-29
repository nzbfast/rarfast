//! SPEC-F 3.7.7: ONE member's read, decrypt, decode and checksum running
//! while the walking thread writes, against the same member run in
//! sequence.
//!
//! The seam is the path that carries a downloaded archive's one large
//! member, and until this target it was fuzzed by nothing: the ten
//! acceptance tests of `crates/rarkit/tests/one_member_seam.rs` drive it
//! at fixtures a human chose. What this adds is an arbitrary member shape
//! on both arms at once, and the property 3.7.7 states in its first
//! acceptance test: **the overlapped member's bytes, its verdict and its
//! reported size are the sequential path's, whatever the member is.**
//!
//! ## Why this target does not feed the input through as the member
//!
//! The seam's engage decision (`read/seam.rs::engages`) has a SIZE FLOOR,
//! and both floors are far above anything libFuzzer offers: 16 MiB for a
//! member with a decoder and a gigabyte for a stored one. A target that
//! made its member out of the input bytes alone would therefore run the
//! SEQUENTIAL path on both arms, pass every assertion here and prove
//! nothing at all. Two things follow, and they are the whole of this
//! target's shape:
//!
//! 1. the member is grown past the floor it has to clear, by REPEATING
//!    the input (`payload`), and never by the input's own length;
//! 2. the seam is asserted to have ENGAGED, from `probe::peak_seam`,
//!    which counts source units and is the only thing that can see one:
//!    the deliver unit is the walking thread on both arms, so the thread
//!    ids a sink records cannot tell the arms apart.
//!
//! The two ways a member reaches the seam are both driven, because they
//! engage on different terms and put the member's CRC32 on different
//! units (`read/seam.rs::checksum_on_deliver`):
//!
//! - a member with a DECODER at or above its 16 MiB floor, on the
//!   engine's own answer with no hint set. Its checksum rides the deliver
//!   unit;
//! - any member at all with `ReadOptions::sink_is_file: Some(true)`, the
//!   caller's cost hint, which engages the seam whatever the
//!   size. Its checksum stays on the source unit.
//!
//! The OFF arm of every pair is the hint unset and the floor lifted to
//! `u64::MAX` through `probe::set_seam_floor`, which is sequential for
//! certain, and is asserted to have spawned no source unit at all.
//!
//! ## The real floor is OPT IN, and this is what it cost to learn
//!
//! The 16 MiB arm was first taken on one input in 256, on the reasoning
//! that a rare expensive arm is affordable. It is not, and the reason is
//! libFuzzer's own economics rather than arithmetic: a member that
//! clears the real floor reaches branches nothing else reaches, so the
//! input that built it is INTERESTING, enters the corpus and is run
//! again and again. MEASURED in a 600 s campaign sweep on an M3 Mac
//! (22 Sep 2026, `fuzzseam22sep`): **162 executions**, slowest unit 24 s,
//! against `rar5_member`'s 2.53 million in the same sweep. The floor the
//! campaign runner itself sets for a target it will call clean rather
//! than broken is five executions a second.
//!
//! So the arm is behind `RARKIT_SEAM_REAL_FLOOR`, which a campaign sets
//! for no target, and the engine's own floor is held to by
//! `crates/rarkit/tests/one_member_seam.rs`'s
//! `a_member_with_a_decoder_is_overlapped_from_its_own_floor`, which
//! takes it at 20 MiB and 8 MiB without a sanitizer under it. What this
//! target keeps in every execution is the thing a test cannot give it:
//! an arbitrary member shape on both arms, with the source unit asserted
//! to have run.
//!
//! ## What the resident set does, and why it is not a leak
//!
//! The campaign runner's slope column NOTES this target at 43.22 KB an
//! execution, reaching libFuzzer's 2048 MB limit at execution 41,429,
//! which is 9.9 more runs like the 600 s sweep that measured it. **The
//! engine is CLEARED**, by the same reading that cleared
//! `rar5_solid_chain` earlier: built with
//! `--sanitizer=none` and run 18,896 times over the same corpus, the
//! resident set goes 85 MB at execution 32 to 128 MB at 9,021 and then
//! FLAT, 127 to 128 MB over the ten thousand executions after it.
//! What grows under the sanitizer is the sanitizer's own accounting of
//! an execution that allocates an archive, two or three ring buffers of
//! a megabyte and three scoped threads. A future campaign that gives
//! this target ten times a sweep in ONE process is the case the note is
//! for; a 600 s sweep is nowhere near it.
//!
//! ## Why the pool is held to two threads
//!
//! A compressed member above 16 MiB opens the RAR 5 tape path's lanes,
//! one per thread the process's pool reports. Under the address
//! sanitizer, which is how a campaign builds, every thread ever created
//! costs about 116 bytes that are never given back, and
//! `fuzz/fuzz_targets/rar5_solid_chain.rs` records a target dying of that
//! inside a 600 s campaign. The pool is named here at two for the same
//! reason and to the same number.
#![no_main]

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use rarkit::{
    probe, ChecksumKind, Disposition, ExtractReport, HostOs, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, Password, Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod,
    WriteOptions, Writer,
};

/// The lanes the tape path may open, and the width of the process's pool.
/// See the note at the head of the file.
const LANES: usize = 2;

/// The read width the seam's own unit is spent out of (SPEC-API 8.4.2).
/// Named rather than defaulted: `engages` refuses a width below two, so
/// on a narrow box the engine's default would make every execution of
/// this target vacuous and the assertions would still pass.
const WIDTH: usize = 2;

/// `read/seam.rs::COMPRESSED_FLOOR`: a member with a decoder is
/// overlapped from here up. Restated rather than imported, because it is
/// a measured constant inside the engine and this target must notice if
/// it moves, by failing its own non-vacuity assertion rather than by
/// silently testing the sequential path twice.
const COMPRESSED_FLOOR: usize = 16 << 20;

/// The password an encrypted shape is written and read with.
const SECRET: &str = "seam";

/// Whether this process takes the real-floor arm at all: set
/// `RARKIT_SEAM_REAL_FLOOR` to anything to take it.
///
/// Read ONCE, so a campaign's executions do not each pay for an
/// environment lookup, and so the answer cannot change under the
/// corpus.
fn real_floor_wanted() -> bool {
    static WANTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WANTED.get_or_init(|| std::env::var_os("RARKIT_SEAM_REAL_FLOOR").is_some())
}

/// Hold the process's pool to [`LANES`] threads, once, before the first
/// decode. A second call is refused by rayon rather than being an error
/// here: the pool is then already this width, or a host built one first.
fn hold_the_pool() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(LANES)
            .build_global();
    });
}

// ---------------------------------------------------------------------------
// The member's bytes
// ---------------------------------------------------------------------------

/// `want` bytes made by REPEATING `seed`, with a counter stamped through
/// it.
///
/// The repetition is what carries the member over the floor, since the
/// input never will. The stamp is what keeps the result from being one
/// long match: a member that is a single run of one byte decodes through
/// one copy and would leave the apply stage, which is the seam's whole
/// reason for existing on a compressed member, barely touched.
fn payload(seed: &[u8], want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want + 64);
    let unit: &[u8] = if seed.is_empty() { b"seam" } else { seed };
    let mut stamp: u64 = 0x2026_0922_u64;
    while out.len() < want {
        out.extend_from_slice(unit);
        stamp = stamp.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(&stamp.to_le_bytes());
    }
    out.truncate(want);
    out
}

// ---------------------------------------------------------------------------
// The archive
// ---------------------------------------------------------------------------

/// How one fixture archive is written, and what has to be true of the
/// read that follows it.
struct Shape {
    method: WriteMethod,
    checksum: ChecksumKind,
    encrypted: bool,
    /// The volume file cap, for a member split across volumes.
    volume_cap: Option<u64>,
    /// The members, in the order they are written.
    members: Vec<Vec<u8>>,
    /// How the seam is engaged on the ON arm: the caller's cost hint, or
    /// the engine's own floor with no hint at all.
    by_hint: bool,
    /// The read-ahead budget, which is where the ring comes from.
    read_ahead: u64,
    /// Whether this shape clears the engine's own 16 MiB floor with a
    /// real member, which is the expensive arm and is off unless
    /// `RARKIT_SEAM_REAL_FLOOR` is set.
    real_floor: bool,
    /// The floor this shape's ON arm asks the engine for, or `None` to
    /// let the engine's own measured floor decide.
    ///
    /// **Every execution a campaign runs forces it, and the real floor
    /// is a deliberate run of its own, and that division is what keeps
    /// this target both honest and affordable.** The
    /// engine's floor for a member with a decoder is 16 MiB, and a
    /// member that size costs seconds to write and to read twice under
    /// the address sanitizer, and a corpus that has found one keeps
    /// running it: a 600 s sweep took 162 executions. So the opt-in arm
    /// clears the real floor with a real member, and every other
    /// execution asks for a floor of zero and drives the same seam over
    /// a small one. What is never
    /// done is the thing the floor exists to stop us doing by accident:
    /// running the SEQUENTIAL path on both arms and calling it a pass,
    /// which is why every arm asserts the source unit ran.
    force_floor: Option<u64>,
    /// Whether that budget leaves room for a ring at all. Where it does
    /// not, 8.5 says the member runs in sequence and that this is never
    /// an error, so the ON arm is asserted to spawn NO source unit and to
    /// deliver the same bytes anyway.
    ring_fits: bool,
}

/// The whole of what the input decides.
fn shape(data: &[u8]) -> Option<Shape> {
    let (head, seed) = data.split_at_checked(4)?;
    let decoded = head[0] % 2 == 0;
    // The engine's own 16 MiB floor, with a member that really clears
    // it: only under `RARKIT_SEAM_REAL_FLOOR`, and then for the inputs
    // that ask for it, of which `fuzz/seeds/read_seam/real-floor-16mib`
    // is one. See the head of this file for what it cost to run it
    // unconditionally.
    let real_floor = head[0] == 0 && real_floor_wanted();
    // A ring needs two chunks of at least `extract::COPY` (64 KiB) out of
    // half the read-ahead budget for a stored member and out of all of it
    // for a decoded one. The smallest value here has room for neither,
    // which is the branch 8.5's "a policy too small for a ring" names.
    let read_ahead: u64 = match head[1] % 4 {
        0 => 64 << 10,
        1 => 256 << 10,
        2 => 1 << 20,
        _ => 4 << 20,
    };
    let ring_fits = if decoded {
        read_ahead / 2 >= (64 << 10)
    } else {
        read_ahead / 4 >= (64 << 10)
    };
    let method = if decoded {
        WriteMethod::Compressed {
            // The cheapest level for the 16 MiB member, and the input's
            // own choice for the small ones.
            level: if real_floor { 1 } else { 1 + head[2] % 5 },
            dictionary: Some(128 << 10),
        }
    } else {
        WriteMethod::Stored
    };
    let checksum = if head[2] & 0x40 == 0 {
        ChecksumKind::Crc32
    } else {
        ChecksumKind::Blake2sp
    };
    let encrypted = head[2] & 0x80 != 0;
    let members = if real_floor {
        // The floor is the engine's, so the member must clear it: a
        // little over, by a fuzz-chosen amount, so the tail of the last
        // ring buffer is not always the same size.
        let extra = usize::from(head[3]) * 4096;
        vec![payload(seed, COMPRESSED_FLOOR + extra)]
    } else if decoded {
        // The floor is forced to zero, so the member is small and the
        // seam is the same seam: a decoder's source unit, its apply
        // stage, and its CRC32 on the DELIVER unit
        // (`read/seam.rs::checksum_on_deliver`, which reads the codec
        // and the hint and never the size).
        vec![payload(seed, (64 << 10) + usize::from(head[3]) * 2048)]
    } else {
        // Stored members are engaged by the HINT, so they are small and
        // several: this is where the deliver unit's ORDER across members
        // is driven, and where a member fits in one ring buffer or in
        // eight depending on the budget above.
        let count = usize::from(head[3] % 3) + 1;
        let each = (64 << 10) + usize::from(head[3]) * 2048;
        (0..count)
            .map(|index| {
                let mut body = payload(seed, each);
                // Every member its own bytes, so a delivery that ran two
                // members' rings together could not pass unnoticed.
                body[0] = index as u8;
                body
            })
            .collect()
    };
    let volume_cap = if !decoded && head[1] & 0x80 != 0 {
        Some(((members.iter().map(Vec::len).sum::<usize>() / 3) as u64).max(64 << 10))
    } else {
        None
    };
    Some(Shape {
        method,
        checksum,
        encrypted,
        volume_cap,
        members,
        by_hint: !decoded,
        real_floor,
        force_floor: (!real_floor && decoded).then_some(0),
        read_ahead,
        ring_fits,
    })
}

impl Shape {
    /// The archive this shape describes, as its volumes.
    fn archive(&self) -> Option<Vec<Vec<u8>>> {
        let mut writer = Writer::new(WriteOptions {
            method: self.method,
            checksum: self.checksum,
            password: self.encrypted.then(|| Password::from(SECRET)),
            volume_file_size: self.volume_cap,
            ..WriteOptions::default()
        })
        .ok()?;
        // The names outlive the writer: a `MemberSpec` borrows its name
        // for as long as the writer holds the member.
        let names: Vec<String> = (0..self.members.len())
            .map(|index| format!("m{index}.dat"))
            .collect();
        for (index, body) in self.members.iter().enumerate() {
            writer
                .add(MemberSpec {
                    name: names[index].as_bytes(),
                    payload: Payload::Bytes(body),
                    mtime: None,
                    attributes: 0,
                    host_os: HostOs::Unix,
                    is_directory: false,
                })
                .ok()?;
        }
        if self.volume_cap.is_some() {
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            writer.finish_volumes(&mut volumes).ok()?;
            Some(volumes)
        } else {
            let mut out = Vec::new();
            writer.finish_into(&mut out).ok()?;
            Some(vec![out])
        }
    }

    /// The options one arm reads with.
    fn options(&self, hint: Option<bool>) -> ReadOptions {
        let mut policy = MemoryPolicy::default();
        policy.read_ahead = self.read_ahead;
        let mut opts = ReadOptions::default()
            .with_password(self.encrypted.then(|| Password::from(SECRET)))
            .with_workers(Some(WIDTH))
            .with_sink_is_file(hint);
        opts.memory = policy;
        opts
    }
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

/// What one arm's sink saw: every member's bytes and verdict, and the
/// thread every call was made on, in call order.
#[derive(Default)]
struct Seen {
    members: Vec<(Vec<u8>, Option<bool>, u64)>,
    open: usize,
    threads: Vec<std::thread::ThreadId>,
    calls: Vec<&'static str>,
}

struct Collector(Arc<Mutex<Seen>>);

impl Write for Collector {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = lock(&self.0);
        let last = held.members.len() - 1;
        held.members[last].0.extend_from_slice(data);
        held.threads.push(std::thread::current().id());
        held.calls.push("write");
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Collecting(Arc<Mutex<Seen>>);

impl Sink for Collecting {
    type Out = Collector;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Collector>> {
        let mut held = lock(&self.0);
        held.members.push((Vec::new(), None, 0));
        held.open += 1;
        held.threads.push(std::thread::current().id());
        held.calls.push("open");
        drop(held);
        Ok(Disposition::Write(Collector(Arc::clone(&self.0))))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Collector>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = lock(&self.0);
        let last = held.members.len() - 1;
        held.members[last].1 = outcome.checksum_ok;
        held.members[last].2 = outcome.bytes;
        held.threads.push(std::thread::current().id());
        held.calls.push("close");
        Ok(())
    }
}

fn lock<T>(held: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// A refusing writer, and a source that counts what it read
// ---------------------------------------------------------------------------

/// A source that counts the bytes it has handed over, so a refusal is
/// priced in SOURCE BYTES READ and never in wall clock (3.7.7's fourth
/// acceptance test, and the bound this target holds the seam to).
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

/// A writer that takes `ceiling` bytes and then refuses, recording what
/// the source had read by the time it did.
struct Refusing {
    given: u64,
    ceiling: u64,
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
}

impl Write for Refusing {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.given + data.len() as u64 > self.ceiling {
            self.at_refusal
                .store(self.source.read.load(Ordering::Relaxed), Ordering::Relaxed);
            return Err(std::io::Error::other("the caller refuses this member"));
        }
        self.given += data.len() as u64;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RefusingSink {
    ceiling: u64,
    source: Arc<Counted>,
    at_refusal: Arc<AtomicU64>,
}

impl Sink for RefusingSink {
    type Out = Refusing;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Refusing>> {
        Ok(Disposition::Write(Refusing {
            given: 0,
            ceiling: self.ceiling,
            source: Arc::clone(&self.source),
            at_refusal: Arc::clone(&self.at_refusal),
        }))
    }
}

// ---------------------------------------------------------------------------
// The arms
// ---------------------------------------------------------------------------

/// Run this arm's extractions at `floor`, and put the engine's own back
/// afterwards. `Some(u64::MAX)` is the sequential arm, `Some(0)` the
/// forced one, and `None` the engine's own measured answer.
struct Floor;

impl Floor {
    fn at(floor: Option<u64>) -> Floor {
        probe::set_seam_floor(floor);
        Floor
    }
}

impl Drop for Floor {
    fn drop(&mut self) {
        probe::set_seam_floor(None);
    }
}

/// One extraction: what the sink saw, what the report said, and how many
/// source units were alive at once while it ran.
fn run(
    shape: &Shape,
    volumes: &[Vec<u8>],
    hint: Option<bool>,
) -> (Seen, Result<ExtractReport>, usize) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let held = Arc::new(Mutex::new(Seen::default()));
    let mut sink = Collecting(Arc::clone(&held));
    probe::reset_peak_seam();
    let report = rarkit::extract(sources, &shape.options(hint), &mut sink, &mut ());
    let seam = probe::peak_seam();
    drop(sink);
    let seen = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (seen, report, seam)
}

/// 3.7.7's third acceptance test, which holds on BOTH arms: `open`, then
/// every write in member order, then `close`, every call on one thread.
fn order_holds(seen: &Seen, arm: &str) {
    if seen.threads.is_empty() {
        return;
    }
    let first = seen.threads[0];
    assert!(
        seen.threads.iter().all(|t| *t == first),
        "{arm}: the caller's sink was called on more than one thread"
    );
    let mut depth = 0i32;
    for call in &seen.calls {
        match *call {
            "open" => {
                assert_eq!(depth, 0, "{arm}: a member opened inside another");
                depth = 1;
            }
            "write" => assert_eq!(depth, 1, "{arm}: a write outside open and close"),
            _ => {
                assert_eq!(depth, 1, "{arm}: a close with no open");
                depth = 0;
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    hold_the_pool();
    let Some(shape) = shape(data) else {
        return;
    };
    let Some(volumes) = shape.archive() else {
        return;
    };

    // THE ON ARM. A member with a decoder is engaged by the engine's own
    // floor, which the payload was grown past; a stored member by the
    // caller's cost hint, which engages it at any size.
    let hint = shape.by_hint.then_some(true);
    let (with, report_with, seam) = {
        let _floor = Floor::at(shape.force_floor);
        run(&shape, &volumes, hint)
    };
    if shape.ring_fits {
        // NOT VACUOUS. Without this the target passes just as happily
        // when `engages` answers false for every shape and both arms are
        // the sequential path, which is the whole failure mode a seam
        // target has.
        assert!(
            seam >= 1,
            "the overlapped arm never spawned a source unit: {} member(s), \
             {} bytes each, hint {hint:?}, read-ahead {}",
            shape.members.len(),
            shape.members.first().map_or(0, Vec::len),
            shape.read_ahead
        );
    } else {
        // 8.5: a policy with no room for a ring runs the member in
        // sequence, and that is never an error.
        assert_eq!(
            seam, 0,
            "a read-ahead budget of {} has no room for a ring, yet a \
             source unit ran",
            shape.read_ahead
        );
    }

    // THE OFF ARM, sequential for certain: no hint, and the floor lifted
    // out of reach of any member.
    let (without, report_without, none) = {
        let _off = Floor::at(Some(u64::MAX));
        run(&shape, &volumes, None)
    };
    assert_eq!(
        none, 0,
        "the sequential arm spawned a source unit with the floor at u64::MAX"
    );

    // 1. BYTES, 2. VERDICT: the overlapped member is the sequential
    // path's, and it is what was written.
    let report_with = report_with.expect("the overlapped arm failed on an archive rarkit wrote");
    let report_without =
        report_without.expect("the sequential arm failed on an archive rarkit wrote");
    assert_eq!(
        with.open,
        shape.members.len(),
        "the overlapped arm opened {} of {} members",
        with.open,
        shape.members.len()
    );
    assert_eq!(
        with.members.len(),
        without.members.len(),
        "the arms delivered a different number of members"
    );
    for (index, ((got, verdict, reported), body)) in
        with.members.iter().zip(shape.members.iter()).enumerate()
    {
        let (other, other_verdict, other_reported) = &without.members[index];
        assert!(
            got == other,
            "member {index}: the overlapped bytes differ from the sequential path's"
        );
        assert!(
            got == body,
            "member {index}: the overlapped member is not what was written"
        );
        assert_eq!(
            verdict, other_verdict,
            "member {index}: the verdict moved with the seam"
        );
        assert!(
            *verdict == Some(true),
            "member {index}: an archive rarkit wrote fails its own checksum"
        );
        assert_eq!(
            reported, other_reported,
            "member {index}: MemberOutcome::bytes moved with the seam"
        );
        assert_eq!(
            *reported,
            body.len() as u64,
            "member {index}: MemberOutcome::bytes is not the member's length"
        );
    }
    assert_eq!(
        report_with.bytes, report_without.bytes,
        "the report's byte count moved with the seam"
    );

    // 3. ORDER: one thread, and members delivered whole and in turn.
    order_holds(&with, "overlapped");
    order_holds(&without, "sequential");

    // 4. A REFUSING WRITER STOPS THE WORK, priced in source bytes read
    // after the refusal and not in seconds. Only on the arm that engages
    // the seam, and only where a ring exists to bound.
    if !shape.ring_fits || shape.real_floor {
        return;
    }
    let source = Arc::new(Counted {
        bytes: volumes[0].clone(),
        read: AtomicU64::new(0),
    });
    let at_refusal = Arc::new(AtomicU64::new(0));
    let ceiling = u64::from(data[0]) * 1024;
    let mut sink = RefusingSink {
        ceiling,
        source: Arc::clone(&source),
        at_refusal: Arc::clone(&at_refusal),
    };
    let _floor = Floor::at(shape.force_floor);
    probe::reset_peak_seam();
    let refused = rarkit::extract(
        vec![Arc::clone(&source) as Arc<dyn RangeSource>],
        &shape.options(hint),
        &mut sink,
        &mut (),
    );
    let seam = probe::peak_seam();
    if shape.members.len() == 1
        && shape.volume_cap.is_none()
        && ceiling < shape.members[0].len() as u64
    {
        let err = refused.expect_err("a refusing writer ends the operation");
        assert!(
            err.into_caller_error().is_ok(),
            "a refused write comes back as the caller's own error"
        );
        assert!(
            seam >= 1,
            "the refusal arm ran no source unit, so it is the sequential \
             path wearing the seam's name"
        );
        let after = source.read.load(Ordering::Relaxed) - at_refusal.load(Ordering::Relaxed);
        // 3.7.7: after the stop flag the source unit does at most one
        // more buffer's worth of work plus the read already in flight.
        let bound = shape.read_ahead + (1 << 20);
        assert!(
            after <= bound,
            "{after} source bytes were read AFTER the refusal, where one \
             ring plus one read is at most {bound}"
        );
    }
});
