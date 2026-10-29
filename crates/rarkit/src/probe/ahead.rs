//! The decode ahead's counts and dials: claims, stalls, peak lanes, the
//! growth, the small and off switches, the carry and the allocations.

use super::*;

/// Members the SOLID CHAIN's decode-ahead had already decoded when the
/// apply stage reached them (SPEC-H2 3.8, `rar5_lz::ahead`).
///
/// A count of scheduling outcomes and not a timing, so a loaded box reads
/// it the same as a quiet one; PROCESS-wide, because the lanes that fill
/// the queue are other threads by construction. It is what a test asserts
/// the lever FIRED on, which no output byte can show: the whole of the
/// stage's contract is that the bytes are identical either way.
pub(super) static AHEAD_CLAIMS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The thread [`ahead_claims`] is scoped to, if a test has asked for one
/// with [`begin_ahead_claim_scope`]. `None`, the default, counts a claim
/// from whichever thread makes it, which is what a benchmark or any other
/// production reader of the process-wide total wants.
///
/// A test harness runs many tests at once, several of which decode a
/// solid chain ahead of its apply stage as part of what THEY check, on
/// their own threads, with no interest in this counter at all. Without a
/// scope their claims land in a concurrent test's count the moment both
/// run at once, though the two never touch the same data: the counter is
/// process-wide by design (the doc comment above says why), so nothing
/// about a claim says which test's decode it came from except the thread
/// that made it. `counting()` in `rar5_lz::tests` opens a scope on the one
/// thread whose count it is about to read and closes it when that thread
/// is done, so a foreign thread's claims pass through unwitnessed instead
/// of landing in a total someone else is about to assert on.
///
/// A bare `u64` rather than a `Mutex<Option<ThreadId>>`: `note_ahead_claim`
/// reads this on every claim, on the walking thread of whatever member is
/// being applied, which under `h2-probes` is the same thread the apply
/// stage's own timing runs on. A lock there is a lock the shipped path
/// never pays (this whole module compiles out without `h2-probes`), but a
/// `h2-probes` test that also budgets allocations per member DOES pay it,
/// and paid enough to move that budget (`tests/allocations.rs`,
/// `a_solid_chain_decode_ahead_allocates_nothing_per_member`, found flaky
/// under this change until it moved to an atomic). `0` is never a real
/// thread's tag (`claim_thread_tag` starts its counter at 1), so it is
/// exactly "no scope".
pub(super) static AHEAD_CLAIM_SCOPE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// A small per-thread tag for [`AHEAD_CLAIM_SCOPE`], assigned once and
/// cached in a thread-local. `std::thread::ThreadId` carries no stable
/// integer form (`as_u64` is nightly-only), and comparing `ThreadId`
/// itself would put a whole `ThreadId` in the atomic; a counter minted on
/// first use is simpler and just as unique for this process's lifetime.
pub(super) fn claim_thread_tag() -> u64 {
    thread_local! {
        static TAG: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    TAG.with(|cell| {
        let tag = cell.get();
        if tag != 0 {
            return tag;
        }
        let tag = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cell.set(tag);
        tag
    })
}

/// Count one member applied from a tape another thread decoded, unless a
/// scope is open on some other thread than this one.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_ahead_claim() {
    let scope = AHEAD_CLAIM_SCOPE.load(std::sync::atomic::Ordering::Relaxed);
    if scope == 0 || scope == claim_thread_tag() {
        AHEAD_CLAIMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Scope [`ahead_claims`] to the calling thread: claims made from any
/// other thread stop counting until [`end_ahead_claim_scope`]. Test
/// support only; a production or benchmark reader of the total never
/// calls this and sees every thread as it always has.
pub fn begin_ahead_claim_scope() {
    AHEAD_CLAIM_SCOPE.store(claim_thread_tag(), std::sync::atomic::Ordering::Relaxed);
}

/// Stop scoping [`ahead_claims`] to one thread; every thread's claims
/// count again, the default a production or benchmark reader expects.
pub fn end_ahead_claim_scope() {
    AHEAD_CLAIM_SCOPE.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Members claimed from the decode-ahead since [`reset_ahead_claims`].
pub fn ahead_claims() -> u64 {
    AHEAD_CLAIMS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Start counting claims again from zero, stalls with them: the two are
/// read together or not at all.
pub fn reset_ahead_claims() {
    AHEAD_CLAIMS.store(0, std::sync::atomic::Ordering::Relaxed);
    AHEAD_STALLS.store(0, std::sync::atomic::Ordering::Relaxed);
    AHEAD_ALLOCS.store(0, std::sync::atomic::Ordering::Relaxed);
    AHEAD_PEAK_LANES.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Claims the apply stage had to WAIT for: the lanes had not finished the
/// member it reached (SPEC-H2 3.8, `rar5_lz::ahead`).
///
/// The one number that says whether the decode-ahead is actually ahead.
/// A claim that waits is a member whose decode was not hidden behind the
/// member in front of it, so the lever bought nothing for that member;
/// a count near zero over a chain is the stage working as intended.
///
/// It is a SCHEDULING outcome and not a wall, so it is worth reading on a
/// box too loaded to time. It is not free of the box either: a box with
/// no spare core will stall where a quiet one does not, and that is the
/// honest reading rather than a defect in the counter.
pub(super) static AHEAD_STALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one claim that had to wait for its lane.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_ahead_stall() {
    AHEAD_STALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Claims that waited, since [`reset_ahead_claims`], which resets this too.
pub fn ahead_stalls() -> u64 {
    AHEAD_STALLS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The most lanes any solid chain's decode-ahead had open at once since
/// [`reset_ahead_claims`], which resets this too. It says where a stage
/// that GROWS on the apply stage's waits (`rar5_lz::ahead`) ended up.
pub(super) static AHEAD_PEAK_LANES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Record a decode-ahead stage holding `lanes` lanes open.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_ahead_lanes(lanes: usize) {
    AHEAD_PEAK_LANES.fetch_max(lanes as u64, std::sync::atomic::Ordering::Relaxed);
}

/// A PRICING KNOB for the decode-ahead's default growth: the lanes a
/// default stage opens with and the waits that open one more, 0 for the
/// shipped figure. Process wide, test-support only, and never set by
/// anything but a measuring harness; the shipped build compiles it out.
pub(super) static AHEAD_GROW_START: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static AHEAD_GROW_AFTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Set the default decode-ahead's starting lanes and growth threshold for
/// a pricing sweep; `0` restores the shipped figure for either.
pub fn set_ahead_growth(start: usize, grow_after: usize) {
    AHEAD_GROW_START.store(start, std::sync::atomic::Ordering::Relaxed);
    AHEAD_GROW_AFTER.store(grow_after, std::sync::atomic::Ordering::Relaxed);
}

/// The knob's starting lanes, if a harness set one.
pub(crate) fn ahead_grow_start() -> Option<usize> {
    match AHEAD_GROW_START.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// The knob's growth threshold, if a harness set one.
pub(crate) fn ahead_grow_after() -> Option<usize> {
    match AHEAD_GROW_AFTER.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// The most decode-ahead lanes open at once since [`reset_ahead_claims`].
pub fn ahead_peak_lanes() -> u64 {
    AHEAD_PEAK_LANES.load(std::sync::atomic::Ordering::Relaxed)
}

thread_local! {
    /// Whether the SOLID CHAIN's decode-ahead is refused for this thread's
    /// next extractions (SPEC-H2 3.8, `rar5_lz::ahead`).
    ///
    /// Per THREAD for the reason `SEAM_FLOOR` is: the offers are made on
    /// the WALKING thread, which is the thread that called `extract`, so a
    /// thread-local reaches exactly the run that set it.
    ///
    /// It exists because the lever's worth cannot be read off one arm.
    /// The stage changes no byte, so a run with it on and a run with it
    /// off are the same extraction twice, and the pair measured in ONE
    /// PROCESS is what survives a box too loaded to time: a contaminant
    /// that inflates both arms cancels in their ratio. Nothing in the API
    /// promises whether any given member is decoded ahead (8.2: running
    /// narrower is in contract), so neither answer is an API fact.
    pub(super) static AHEAD_OFF: Cell<bool> = const { Cell::new(false) };
}

thread_local! {
    /// The chain lookahead's SMALL MEMBER floor for this thread's next
    /// extractions (`read::ahead::SMALL_MEMBER`), where a test states one.
    /// Per thread for the reason [`AHEAD_OFF`] is: the lookahead walks on
    /// the thread that called `extract`.
    pub(super) static AHEAD_SMALL: Cell<Option<u64>> = const { Cell::new(None) };
}

/// State the declared size under which the chain's lookahead leaves a
/// member that carries no table set to the walking thread, for this
/// thread's next extractions; `None` gives the shipped figure back.
pub fn set_ahead_small(bytes: Option<u64>) {
    AHEAD_SMALL.with(|cell| cell.set(bytes));
}

/// The floor a test stated for this thread, if it stated one.
pub(crate) fn ahead_small() -> Option<u64> {
    AHEAD_SMALL.with(|cell| cell.get())
}

/// Refuse the chain's decode-ahead for this thread's next extractions, or
/// allow it again.
pub fn set_ahead_off(off: bool) {
    AHEAD_OFF.with(|cell| cell.set(off));
}

/// Whether this thread's extractions are refusing the decode-ahead.
pub(crate) fn ahead_off() -> bool {
    AHEAD_OFF.with(|cell| cell.get())
}

/// Make the chain's decode-ahead carry a STALE table set across a run
/// boundary (SPEC-H2 3.2, `rar5_lz::ahead`): a run's head keeps the set
/// its lane carried out of the previous run instead of the one its own
/// first block builds, so every member behind the head decodes under the
/// wrong set.
///
/// The one deliberate corruption the solid chain equivalence tests are
/// SHOWN TO FAIL under. The carry is invisible in every output byte when
/// it is right, so a test that only ever saw it right would pass just as
/// well with the carry replaced by anything at all; this knob is what
/// proves the comparison has teeth. PROCESS-wide and not per thread,
/// because the lanes that read it are other threads by construction, so
/// a test that sets it holds a lock against every other test that reads
/// the stage.
pub(super) static AHEAD_CARRY_STALE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Corrupt the carried table set at every run head, or stop.
pub fn set_ahead_carry_stale(stale: bool) {
    AHEAD_CARRY_STALE.store(stale, std::sync::atomic::Ordering::SeqCst);
}

/// Whether the carried set is being corrupted at run heads.
#[cfg(feature = "parallel")]
pub(crate) fn ahead_carry_stale() -> bool {
    AHEAD_CARRY_STALE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Fresh allocations the SOLID CHAIN's decode-ahead made that its pools
/// could not answer (SPEC-H2 4.2, `rar5_lz::ahead`).
///
/// **Why this exists beside the allocation counter in `tests/allocations.rs`
/// and not instead of it.** That counter is a thread-local: it sees the
/// CALLING thread only, and the decode-ahead does its work on lanes of its
/// own, so every buffer a lane grows is invisible to it. A stage that
/// allocated a tape per member on a lane would read as perfectly pooled.
///
/// So the stage counts its own. It is incremented where a pool could not
/// answer and something fresh had to be made: a work item, and a tape for
/// a block the work item did not already have one for. Section 4.2 says
/// no allocation per member, and what that means here is that this number
/// is bounded by the QUEUE and does not grow with the chain.
pub(super) static AHEAD_ALLOCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Count one thing the stage's pools could not answer.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_ahead_alloc() {
    AHEAD_ALLOCS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Fresh allocations the stage made since [`reset_ahead_claims`].
pub fn ahead_allocs() -> u64 {
    AHEAD_ALLOCS.load(std::sync::atomic::Ordering::Relaxed)
}
