//! The helper threads of an encrypted stored read, counted ALIVE across a
//! cipher chain's end: a run at a width of N has never more than N of them
//! alive, and not only at work.
//!
//! Each range an encrypted stored member is deciphered over (a member of
//! one archive, a fragment of a split one) is read by helper threads the
//! engine starts for that range and ends with it. A helper that has
//! finished its work is not yet gone: its thread-local destructors run and
//! its stack is unmapped after its work is over. So unless the engine
//! waits for the threads themselves, the next range's helpers are started
//! beside the last range's, and a host that counts threads (a container's
//! pids limit, `RLIMIT_NPROC`) sees up to twice the width for a moment.
//!
//! The test's own allocator is what counts them. A thread the engine
//! starts allocates or frees at least once (the state it is handed is
//! freed on it), and the first time it does, a thread-local is planted on
//! it whose destructor is slow: the thread is counted from then until the
//! destructor has finished, which is strictly inside its life. The
//! slowness stands for a loaded host, where a finished thread is not
//! descheduled for the last time at once; it makes the overlap certain
//! instead of occasional, and it changes nothing the engine is told.
//! Counting in the allocator rather than in the source sees the helpers
//! that never read: the cipher's lanes behind the one reader of a range
//! written to a file.
//!
//! THREADS AND MEMORY. The read runs on the test's own rayon pool of
//! exactly [`WIDTH`] threads with `ReadOptions::workers` stated as
//! [`WIDTH`], under `MemoryPolicy::default()` (a read-ahead of 4 MiB, so
//! the wide plan is [`WIDTH`] readers on every system). The pool's own
//! threads and the calling thread are not helpers and are not counted.
//! Nor are the threads of rayon's global pool, which the writer that makes
//! the input starts (it is called outside the test's pool): they never
//! leave, and one of them allocates when it first goes to sleep (the lock
//! it sleeps on is made on first use on some systems), which on a loaded
//! host is after a count has begun. A thread counted that never leaves
//! would hold the count above nought for ever, so every one of them is
//! let off before the first count ([`let_off_the_global_pool`]).
//! ONE test function, so the harness's own thread does nothing while the
//! count is on.

#![cfg(all(feature = "test-support", feature = "parallel"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rarkit::{
    extract, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteOptions, Writer,
};

const SECRET: &str = "alive";
/// The stated width, and the pool's.
const WIDTH: usize = 4;
/// Over the wide read's floor of 16 MiB, so every member goes wide.
const MEMBER: usize = 20 << 20;
const MEMBERS: usize = 4;
/// How long a finished helper takes to go.
const LINGER: Duration = Duration::from_millis(40);
/// How long the last read's helpers are waited for before the next count.
/// A helper lingers for [`LINGER`] and they are at most a few; a thread
/// still counted after this is no helper, and the test says so and fails.
const GONE_BY: Duration = Duration::from_secs(120);

/// The helpers alive now, and the most there have been.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The helpers that have been counted at all.
static SEEN: AtomicUsize = AtomicUsize::new(0);

/// One helper's life from its first read to the end of its thread-local
/// destructors.
struct Alive;

impl Alive {
    fn enter() -> Alive {
        let now = LIVE.fetch_add(1, SeqCst) + 1;
        PEAK.fetch_max(now, SeqCst);
        SEEN.fetch_add(1, SeqCst);
        Alive
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        std::thread::sleep(LINGER);
        LIVE.fetch_sub(1, SeqCst);
    }
}

thread_local! {
    static HERE: Alive = Alive::enter();
    /// Whether this thread has been looked at: counted, or let off.
    static LOOKED: Cell<bool> = const { Cell::new(false) };
    /// The calling thread and the pool's: not helpers.
    static EXEMPT: Cell<bool> = const { Cell::new(false) };
}

/// Whether threads are being counted now.
static COUNTING: AtomicBool = AtomicBool::new(false);

/// Count the thread this is called on, once, if it is a helper.
fn look() {
    if !COUNTING.load(SeqCst) {
        return;
    }
    // Set before the count is planted: planting may allocate.
    if LOOKED.try_with(|l| l.replace(true)).unwrap_or(true) {
        return;
    }
    if !EXEMPT.try_with(Cell::get).unwrap_or(true) {
        let _ = HERE.try_with(|_| ());
    }
}

/// The system's allocator, looking at each thread that uses it.
struct Looking;

// SAFETY: every call is the system allocator's own, unchanged; `look`
// touches thread-locals and atomics only.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Looking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        look();
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        look();
        // SAFETY: the caller's contract, passed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Looking = Looking;

/// Let off every thread of rayon's global pool, starting the pool if
/// nothing has yet: called on a thread of no pool, before any count. The
/// global pool has the threads it starts with and no others, and
/// `broadcast` returns when each of them has run this.
fn let_off_the_global_pool() {
    assert!(
        rayon::current_thread_index().is_none(),
        "called on a pool's thread: this would not reach the global pool"
    );
    rayon::broadcast(|_| EXEMPT.with(|e| e.set(true)));
}

/// Incompressible, deterministic bytes.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x2929_0929_7f4a_7c15 ^ seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// [`MEMBERS`] stored members of [`MEMBER`] bytes each, encrypted, in one
/// archive or in volumes of `per` bytes, by this crate's own writer.
fn encrypted_set(per: Option<u64>) -> Vec<Vec<u8>> {
    let members: Vec<(String, Vec<u8>)> = (0..MEMBERS)
        .map(|k| (format!("Element.{k}.mkv"), noise(MEMBER, k as u64 + 1)))
        .collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: per,
        password: Some(Password::from(SECRET)),
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in &members {
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
    if per.is_none() {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        return vec![one];
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    out
}

struct Verdicts {
    written: bool,
    outcomes: Vec<MemberOutcome>,
}

impl Sink for Verdicts {
    type Out = std::io::Sink;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(if self.written {
            Disposition::Write(std::io::sink())
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.outcomes.push(*outcome);
        Ok(())
    }
}

/// Read the set at [`WIDTH`], checked (`t`) or written to what the caller
/// says is a file (`x`), and answer the most helpers alive at once and how
/// many ranges went wide.
fn peak_alive(set: Vec<Vec<u8>>, written: bool) -> (usize, u64) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(WIDTH)
        .start_handler(|_| EXEMPT.with(|e| e.set(true)))
        .build()
        .expect("a thread pool");
    // Every thread of the pool has started, and is known for the pool's,
    // before anything is counted: a pool starts its threads behind the
    // call that builds it.
    pool.broadcast(|_| EXEMPT.with(|e| e.set(true)));
    // The last read's helpers are gone before this one's are counted.
    let waiting = Instant::now();
    while LIVE.load(SeqCst) != 0 {
        assert!(
            waiting.elapsed() < GONE_BY,
            "{} counted threads have not left after {GONE_BY:?}: they are not helpers of \
             the read, and the count is this test's own fault",
            LIVE.load(SeqCst)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    PEAK.store(0, SeqCst);
    SEEN.store(0, SeqCst);
    let (outcomes, wide) = pool.install(|| {
        let sources: Vec<Arc<dyn RangeSource>> = set
            .into_iter()
            .map(|bytes| Arc::new(bytes) as Arc<dyn RangeSource>)
            .collect();
        let options = ReadOptions::default()
            .with_workers(Some(WIDTH))
            .with_memory(MemoryPolicy::default())
            .with_sink_is_file(written.then_some(true))
            .with_password(Some(Password::from(SECRET)));
        let mut sink = Verdicts {
            written,
            outcomes: Vec::new(),
        };
        probe::reset_wide_verifies();
        COUNTING.store(true, SeqCst);
        let read = extract(sources, &options, &mut sink, &mut ());
        COUNTING.store(false, SeqCst);
        read.expect("the set reads");
        (sink.outcomes, probe::wide_verifies())
    });
    assert_eq!(outcomes.len(), MEMBERS);
    for outcome in &outcomes {
        assert_eq!(outcome.checksum_ok, Some(true));
        assert_eq!(outcome.bytes, MEMBER as u64);
    }
    // Helpers were counted at all. How many there were says nothing: an
    // engine that keeps its helpers from range to range has the width's
    // and no more, and one that starts them a range has the width's a
    // range. That the set crosses a chain's end is the caller's `wide`.
    assert!(SEEN.load(SeqCst) >= 1, "no helper thread was counted");
    (PEAK.load(SeqCst), wide)
}

/// One archive of several encrypted members (each member is a cipher chain
/// of its own) and the same members in volumes (a member's chain is read a
/// fragment at a time), checked and written: a range's helpers are gone
/// before the next range's are started.
#[test]
fn never_more_than_the_width_alive_across_a_chains_end() {
    // This thread is the caller's, not a helper.
    EXEMPT.with(|e| e.set(true));
    // Nor are the global pool's threads, which the writer below uses.
    let_off_the_global_pool();
    // Not whole blocks; two fragments a member and more.
    let per = (34 << 20) + 7;
    let mut over = Vec::new();
    for (what, per, least) in [
        ("members", None, MEMBERS as u64),
        ("fragments", Some(per), 2),
    ] {
        for written in [false, true] {
            let (peak, wide) = peak_alive(encrypted_set(per), written);
            assert!(
                wide >= least,
                "{what}, written {written}: only {wide} ranges went wide"
            );
            if peak > WIDTH {
                over.push(format!("{what}, written {written}: {peak}"));
            }
        }
    }
    assert!(
        over.is_empty(),
        "helpers alive at once at a width of {WIDTH}: {over:?}"
    );
}
