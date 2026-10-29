//! The worker ceiling: what it bounds, and what it may never change.
//!
//! API section 8 gives the engine ONE worker control,
//! `MemoryPolicy::max_workers`, and section 4's `extract_parallel` takes a
//! `workers` argument bounded by it. Two properties follow, and neither is
//! visible in an output byte, which is why they are counted here rather
//! than timed:
//!
//! - a ceiling of one really means one worker, not "fewer than the box
//!   has". Timing cannot tell those apart, so the decode wave is counted
//!   through `probe::peak_workers`.
//! - nothing the engine emits depends on the width, reading or writing.
//!
//! Written for the thread-width work of 19 Sep 2026, which found `-mt<n>`
//! reaching neither path.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::sync::{Arc, Mutex, MutexGuard};

use rarkit::{
    extract, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// `probe::peak_workers` is PROCESS-wide, as its own comment says it has
/// to be, so EVERY test in this file takes this, not only the two that
/// read the counter: cargo runs a binary's tests on several threads at
/// once, so a test decoding at width 8 beside a test asserting a ceiling
/// of 1 puts its own workers into the reading. That is how the first run
/// of this file failed, and the engine was right.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

/// A member big enough to take the parallel decode arm.
///
/// The wave has a size floor (a member under it decodes on the calling
/// thread and enters no wave at all), so a test of the WIDTH has to clear
/// it. Compressible, so the archive stays small, but not a single run:
/// one byte repeated gives a block chain too short to spread.
fn body() -> Vec<u8> {
    let mut out = Vec::with_capacity(24 << 20);
    let mut seed = 0x2026_0919_u64;
    while out.len() < (24 << 20) {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let word = format!("{:016x} ", seed >> 24);
        // Three quarters of it repeats, so it compresses; the rest moves.
        out.extend_from_slice(word.as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
    }
    out.truncate(24 << 20);
    out
}

/// One archive of `members` copies of `body`, written at `workers`.
///
/// BOTH write-side dials are set to the figure, which is deliberate: the
/// encoder's width is `WriteOptions::workers` (API 7.2) and
/// the memory ceiling is `MemoryPolicy::max_workers` (API 8.2), and a
/// test of "the bytes do not move with the width" wants neither of them
/// left at a default where it could not have moved anything. Between
/// 19 and 20 Sep 2026 this helper set the memory field alone; when the
/// encoder was taken off that field the helper stopped reaching the
/// encoder at all, and the test below would have passed without varying
/// the thing it names.
fn archive(body: &[u8], members: usize, workers: usize) -> Vec<u8> {
    let memory = rarkit::MemoryPolicy {
        max_workers: workers,
        ..Default::default()
    };
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        memory,
        workers: Some(workers),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members)
        .map(|i| format!("m{i}.dat").into_bytes())
        .collect();
    for name in &names {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(body),
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

/// Collects every member's bytes, in archive order.
#[derive(Default)]
struct Collect {
    got: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "checksum failed for a member this test wrote itself"
        );
        self.got
            .push((member.name.to_vec(), out.unwrap_or_default()));
        Ok(())
    }
}

/// Extract at a READ WIDTH of `workers`.
///
/// `ReadOptions::workers` (API 8.4.2) since 20 Sep 2026, and
/// `MemoryPolicy::max_workers` before it: the read side's width moved off
/// the memory policy for the reason the encoder's moved, which
/// is that a field derived from a memory budget was bounding something
/// that is not memory. The property below is unchanged.
fn extract_at(bytes: &[u8], workers: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let opts = ReadOptions::default().with_workers(Some(workers));
    let mut sink = Collect::default();
    let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
    extract(sources, &opts, &mut sink, &mut ()).expect("extract");
    sink.got
}

/// FOUND 19 Sep 2026 by this test failing, and FIXED the same day.
///
/// The wave this was written against took `width = max_workers` and then
/// handed a wave of `width * 2` blocks to the caller's pool through one
/// `par_iter_mut`, so on a pool wider than the wave every one of those
/// blocks ran at once: a ceiling of 1 decoded 2 blocks concurrently and a
/// ceiling of 2 decoded 4. The wave's own comment said the doubling was a
/// PIPELINE BUFFER, so the intent was `width` workers with two blocks in
/// flight, and `par_iter` over the whole wave is what turned the buffer
/// into concurrency. This test pinned the measured contract and left the
/// question open, because restructuring the wave was separate work.
///
/// The `wide-pool-cpu` work restructured it. The decode is a PIPELINE of
/// `lanes` threads, `lanes` at most `max_workers`, each holding the tape
/// it is filling and the one it has handed over: the buffer is back to
/// being a buffer and the ceiling means what API section 8.2 says it
/// means. So the assertion is now the ceiling ITSELF, and the open
/// question is answered in the direction the API text implied.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_ceiling_bounds_the_blocks_decoded_at_once() {
    let _guard = counter();
    let body = body();
    let bytes = archive(&body, 2, 8);

    for workers in [1usize, 2, 4] {
        probe::reset_peak_workers();
        let got = extract_at(&bytes, workers);
        let peak = probe::peak_workers();
        assert_eq!(got.len(), 2, "both members came back at width {workers}");
        assert!(
            peak <= workers,
            "a read width of {workers} and the decode ran {peak} blocks at once"
        );
    }
}

/// And the CALLER'S POOL no longer decides anything about the width.
///
/// This test used to assert the opposite, and say so: the tape overlap of
/// an earlier revision put the decode of wave N+1 on a scoped OS thread outside the
/// pool, so a ceiling of one still decoded two blocks at once whatever the
/// pool was, and "one worker" was not reachable through either control.
/// That was recorded here as an open question.
///
/// The pipeline answers it. The decode lanes are this stage's own threads
/// and there are `min(the read's width, blocks)` of them, so a ceiling of
/// one decodes one block at a time and the caller's pool is not consulted.
/// The pool is consulted for ONE thing since 8.4.3, and this test does not
/// touch it: it is what `ReadOptions::workers` of `None` resolves to, and
/// every width here is set explicitly.
///
/// | rayon pool | read width | blocks at once |
/// |---|---|---|
/// | 1 | 1 | 1 |
/// | 2 | 1 | 1 |
/// | 4 | 1 | 1 |
///
/// Measured here, at each of those pool sizes.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_callers_pool_does_not_set_the_width() {
    let _guard = counter();
    let body = body();
    let bytes = archive(&body, 2, 8);

    for pool_size in [1usize, 2, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(pool_size)
            .build()
            .expect("a pool");
        probe::reset_peak_workers();
        let got = pool.install(|| extract_at(&bytes, 1));
        let peak = probe::peak_workers();
        assert_eq!(got.len(), 2, "both members came back");
        assert_eq!(
            peak, 1,
            "a pool of {pool_size} and a ceiling of one decoded {peak} \
             blocks at once, where the ceiling says one"
        );
    }
}

/// THE REGRESSION TEST FOR THE WIDE POOL DEFECT (19 Sep 2026).
///
/// The defect: a decode over a 768 MiB solid set took TWICE the wall and
/// TWELVE TIMES the CPU on a pool of 32 that it took on a pool of 6, and
/// half of every thread sample was the pool's own idle spin. The cause was
/// not the width of anything the engine chose. It was that the engine
/// handed the caller's pool a batch of `2 * W` blocks about two thousand
/// times per member and waited for every batch, so the pool was woken,
/// barriered and stood down at sixty microsecond intervals, and the cost
/// of that grew with the pool because a wider pool has more threads to
/// wake and a longer queue for each of them to search.
///
/// So the property to pin is not a time. It is that THE DECODE HANDS THE
/// CALLER'S POOL NOTHING: the lanes are this stage's own threads, sized to
/// the work in front of them, and a caller who brings a 32 thread pool
/// gets exactly the same schedule as one who brings none. A count of
/// scheduling decisions reads the same on a loaded box as on a quiet one,
/// which a wall figure does not.
///
/// This fails before the fix at every pool size: the wave path it replaced
/// hands over one batch per `2 * W` blocks, and the member here is 24 MiB
/// of compressible text, well past the 16 MiB floor the parallel arm
/// switches on at, so it crosses many batches.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_decode_hands_no_work_to_the_callers_pool() {
    let _guard = counter();
    let body = body();
    let bytes = archive(&body, 2, 8);

    for pool_size in [1usize, 4, 16] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(pool_size)
            .build()
            .expect("a pool");
        probe::reset_pool_handoffs();
        probe::reset_peak_workers();
        let got = pool.install(|| extract_at(&bytes, 8));
        let handoffs = probe::pool_handoffs();
        let peak = probe::peak_workers();
        assert_eq!(got.len(), 2, "both members came back");
        assert_eq!(
            handoffs, 0,
            "a pool of {pool_size} was handed {handoffs} batches of blocks; \
             the decode is meant to run on its own lanes and consult no pool"
        );
        // And the lanes are still doing the work: a decode that had gone
        // serial would also hand the pool nothing, and would not be a fix.
        assert!(
            peak > 1,
            "a pool of {pool_size}: the decode ran {peak} blocks at once, \
             so the lanes are not running at all"
        );
    }
}

/// The bytes a READ delivers do not depend on the width.
///
/// The property the whole change rests on: a width is a performance knob and
/// may never be an output one.
#[test]
fn extracted_bytes_do_not_depend_on_the_width() {
    let _guard = counter();
    let body = body();
    let bytes = archive(&body, 3, 8);

    let one = extract_at(&bytes, 1);
    assert_eq!(one.len(), 3);
    for (name, got) in &one {
        assert_eq!(got.as_slice(), &body[..], "member {name:?} at width 1");
    }
    for workers in [2usize, 4, 8, 32] {
        let wide = extract_at(&bytes, workers);
        assert_eq!(
            wide, one,
            "extracted bytes differ between width 1 and width {workers}"
        );
    }
}

/// And the bytes a WRITE produces do not depend on it either.
///
/// The create path already measured sha-identical from 1 to 32 threads
/// before this change; the ceiling now actually reaches the encoder, so the
/// property is pinned here rather than left to a measurement nobody reruns.
///
/// This is the NARROW form, over one shape at level 3. The broad form of
/// promise 2.6, every format, solid and not, a volume set and every level
/// of the ladder, is `tests/encoder_width.rs`.
#[test]
fn written_bytes_do_not_depend_on_the_width() {
    let _guard = counter();
    let body = body();
    let one = archive(&body, 2, 1);
    for workers in [2usize, 4, 8, 32] {
        assert!(
            archive(&body, 2, workers) == one,
            "the archive written at width {workers} differs from the one \
             written at width 1"
        );
    }
}
