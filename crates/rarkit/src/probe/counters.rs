//! The read's counters: members decoded, header clones, the worker, lane
//! and member guards and their peaks, the pool hand-offs and the chunk plans.

use super::*;

thread_local! {
    /// Per THREAD, not per process: a test binary runs its tests
    /// concurrently in one process, and a process-wide counter would have
    /// each test reading another's work. Extraction decodes on the thread
    /// that called it, so the two are the same count.
    pub(super) static DECODED: Cell<u64> = const { Cell::new(0) };
}

/// Count one member whose packed bytes were read and run through a codec
/// (the copy of a stored member included: it reads the bytes too).
pub(crate) fn note_decoded() {
    let _ = DECODED.try_with(|c| c.set(c.get() + 1));
}

/// How many members this thread has decoded since its last [`reset`].
pub fn decoded_members() -> u64 {
    DECODED.try_with(Cell::get).unwrap_or(0)
}

/// Start counting again from zero on this thread.
pub fn reset() {
    let _ = DECODED.try_with(|c| c.set(0));
}

thread_local! {
    /// Member headers COPIED by the walking thread, which after 21 Sep
    /// 2026 is once per extra FRAGMENT and never once per member.
    ///
    /// Per thread for the same reason [`DECODED`] is: the suite runs its
    /// tests concurrently in one process and extraction copies on the
    /// thread that called it.
    pub(super) static HEADER_CLONES: Cell<u64> = const { Cell::new(0) };
}

/// Count one member header copied out of a block.
pub(crate) fn note_header_clone() {
    let _ = HEADER_CLONES.try_with(|c| c.set(c.get() + 1));
}

/// How many member headers this thread has copied since its last
/// [`reset_header_clones`].
///
/// A member with ONE fragment must cost none: its header is the caller's
/// own and the stream borrows it (`read/walk.rs`). A member that
/// CONTINUES costs one per later fragment, because by then the walk has
/// moved past the block the first one sat in.
pub fn header_clones() -> u64 {
    HEADER_CLONES.try_with(Cell::get).unwrap_or(0)
}

/// Start counting header copies again from zero on this thread.
pub fn reset_header_clones() {
    let _ = HEADER_CLONES.try_with(|c| c.set(0));
}

/// The widest the decode wave has actually run, in workers.
///
/// PROCESS-wide, unlike [`decoded_members`], and it has to be: the workers
/// are other threads by construction, so a thread-local would count one.
/// A test that reads it therefore owns the process for the length of its
/// measurement; the suite's worker tests take one lock between them and say
/// so at their own call sites.
pub(super) static WORKERS_NOW: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static WORKERS_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A worker is inside the decode wave for as long as this lives.
///
/// RAII rather than a pair of calls, so a decode that returns early or
/// unwinds cannot leave the counter high and every later reading wrong.
#[cfg(feature = "h2-probes")]
pub(crate) struct WorkerGuard;

#[cfg(feature = "h2-probes")]
impl WorkerGuard {
    pub(crate) fn enter() -> WorkerGuard {
        use std::sync::atomic::Ordering;
        let now = WORKERS_NOW.fetch_add(1, Ordering::Relaxed) + 1;
        WORKERS_PEAK.fetch_max(now, Ordering::Relaxed);
        WorkerGuard
    }
}

#[cfg(feature = "h2-probes")]
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        WORKERS_NOW.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The most workers seen inside the decode wave at once since [`reset`].
///
/// Zero means the parallel arm never ran: a member below the size floor
/// decodes on the calling thread and enters no wave at all.
pub fn peak_workers() -> usize {
    WORKERS_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget the worker high-water mark.
pub fn reset_peak_workers() {
    WORKERS_PEAK.store(
        WORKERS_NOW.load(std::sync::atomic::Ordering::Relaxed),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The most tape LANES alive at once, anywhere in the process.
///
/// [`peak_workers`] counts a lane only while it is inside `decode_one`,
/// and a lane spends much of its life blocked handing a tape over, so that
/// counter reads well below the number of THREADS the engine has running.
/// API section 8.3 states its scoped-thread constant in threads alive
/// ("at most `max_workers` per member being decoded"), and a lane blocked
/// on the hand-over still holds its tapes, so the memory the ceiling is
/// really about tracks this count and not the other. Both are kept: one
/// says how wide the decode RAN, this says how wide it was SPREAD.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is.
pub(super) static LANES_NOW: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static LANES_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A tape lane is alive for as long as this lives.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) struct LaneGuard;

#[cfg(all(feature = "parallel", feature = "h2-probes"))]
impl LaneGuard {
    pub(crate) fn enter() -> LaneGuard {
        use std::sync::atomic::Ordering;
        let now = LANES_NOW.fetch_add(1, Ordering::Relaxed) + 1;
        LANES_PEAK.fetch_max(now, Ordering::Relaxed);
        LaneGuard
    }
}

#[cfg(all(feature = "parallel", feature = "h2-probes"))]
impl Drop for LaneGuard {
    fn drop(&mut self) {
        LANES_NOW.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The most tape lanes alive at once since [`reset_peak_lanes`].
pub fn peak_lanes() -> usize {
    LANES_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget the lane high-water mark.
pub fn reset_peak_lanes() {
    LANES_PEAK.store(
        LANES_NOW.load(std::sync::atomic::Ordering::Relaxed),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The most tape lanes THIS MACHINE gives one large RAR 5 member, as the
/// engine counts them (`rar5_lz::tape::workers` with no width to hold it):
/// for a width a caller `stated`, the hardware threads less one; for the
/// engine's own default, the physical cores less one; `RARKIT_TAPE_HOST`
/// in place of either. A member is SPREAD only from two lanes, so a test
/// that asserts a spread asks this first and says which machine it is on:
/// on two hardware threads the figure is one, whatever width is named, and
/// the member decodes on the walking thread alone.
#[cfg(feature = "parallel")]
pub fn tape_host_lanes(stated: bool) -> usize {
    crate::rar5_lz::tape::workers(u64::MAX, usize::MAX, stated)
}

/// How many times the decode has handed a batch of blocks to the CALLER'S
/// thread pool since [`reset_pool_handoffs`].
///
/// The counter behind the defect of 19 Sep 2026 and the test that pins it.
/// The tape path used to hand every wave of `2 * W` blocks to the pool
/// through one `par_iter`, which on a real `-m3` archive is a barrier
/// every sixty microseconds and about two thousand of them per member; a
/// pool wider than the wave then spent as long hunting for work as doing
/// it, so a WIDER pool cost twice the wall and twelve times the CPU. The
/// pipeline hands the pool nothing at all, and this counts that: it is a
/// count of scheduling decisions and not a timing, so a loaded box reads
/// it the same as a quiet one.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is: the batches go
/// to other threads by construction.
pub(super) static POOL_HANDOFFS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Count one batch of blocks handed to the caller's pool.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_pool_handoff() {
    POOL_HANDOFFS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Batches handed to the caller's pool since [`reset_pool_handoffs`].
pub fn pool_handoffs() -> u64 {
    POOL_HANDOFFS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Start counting pool hand-offs again from zero.
pub fn reset_pool_handoffs() {
    POOL_HANDOFFS.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// The blocks each planned CHUNK had to spread over its lanes.
///
/// **The quantity the narrowed-breadth measurements leave open, and
/// it was never measured because no counter for it existed.** A rule
/// telling the narrowing's winners from its losers wants
/// the number of blocks a chunk has to spread over lanes; those
/// measurements could not test it, and the figure they reported as
/// `probe::peak_blocks` came from a column in
/// `examples/breadth_lanes.rs` that is MISLABELLED and filled from
/// [`peak_workers`]. There is no counter to unclamp. This is the
/// counter to write, and the label is corrected beside it.
///
/// **A DISTRIBUTION rather than a number**, which is the whole reason
/// the series is kept and not only the scalars below.
/// `Rar5Lz::member_planned` runs once per CHUNK, so a member of any
/// size contributes many readings, and a mean over them can sit flat
/// while the shape that decides the question moves. A caller that wants
/// a scalar takes one from the series knowing what it threw away.
///
/// **Read where the count is the CHUNK'S OWN**, after `tape::plan` and
/// before any `min` against the width, the wave or the grant: the
/// derived `lanes` twenty lines below is capped three ways over and
/// says nothing about the chain. There is a second reason for that
/// placement and it is the load-bearing one (found in the arm 6 work):
/// the cells where narrowing moves the wall furthest are the ones where
/// the shipped share is ONE lane, and a member at one lane never enters
/// `member_piped` at all, so a counter inside the piped path would go
/// silent on exactly the cells the question is about.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is: chunks are
/// planned on each member's own decode thread, which is never the
/// thread that reads this.
pub(super) static CHUNK_PLANS: std::sync::Mutex<ChunkPlans> = std::sync::Mutex::new(ChunkPlans {
    blocks: Vec::new(),
    groups: Vec::new(),
    dropped: 0,
});

/// The chunk-plan readings this process has taken.
pub(super) struct ChunkPlans {
    /// Blocks per planned chunk, in the order the chunks were planned.
    pub(super) blocks: Vec<u32>,
    /// Table groups per planned chunk, alongside `blocks`.
    pub(super) groups: Vec<u32>,
    /// Readings past [`SERIES_CAP`] that the series did not keep.
    pub(super) dropped: u64,
}

/// The most chunk readings the series keeps.
///
/// A hostile stream plans chunks without bound (the 25-byte slow units
/// of the 20 Sep 2026 `f_extract_parallel` campaign are the case in
/// hand), and a counter that grew forever would be a memory defect in
/// the very builds the fuzz targets run. What the cap turns away is
/// COUNTED rather than dropped in silence, so a truncated series says
/// it is truncated instead of quietly reading short, and the scalars
/// below stay exact whatever the cap does.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(super) const SERIES_CAP: usize = 1 << 16;

pub(super) static CHUNK_BLOCKS_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static CHUNK_BLOCKS_LEAST: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

pub(super) static CHUNK_BLOCKS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) static CHUNKS_PLANNED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Record one planned chunk: its blocks, and the table groups they fall in.
#[cfg(all(feature = "parallel", feature = "h2-probes"))]
pub(crate) fn note_chunk_plan(blocks: usize, groups: usize) {
    use std::sync::atomic::Ordering;
    // THE BIMODALITY INSTRUMENT'S COUNTER IS FED FROM HERE, not from a second
    // call beside this one in `member_planned`. Both landed on 21 Sep
    // 2026 asking different questions of the same event: [`planned`]
    // asks whether a narrow grant makes the decode plan the same blocks
    // more than once, and the counters below ask how long the chain in
    // one chunk is. One planned chunk is one notification, so the two
    // adjacent calls the rebase produced are one call. [`planned`] and
    // [`reset_planned`] keep their own statics and their own reset, so
    // a test that resets one does not silently clear the other.
    note_planned(blocks);
    CHUNKS_PLANNED.fetch_add(1, Ordering::Relaxed);
    CHUNK_BLOCKS_TOTAL.fetch_add(blocks as u64, Ordering::Relaxed);
    CHUNK_BLOCKS_PEAK.fetch_max(blocks, Ordering::Relaxed);
    CHUNK_BLOCKS_LEAST.fetch_min(blocks, Ordering::Relaxed);
    let mut held = CHUNK_PLANS.lock().unwrap_or_else(|e| e.into_inner());
    if held.blocks.len() >= SERIES_CAP {
        held.dropped += 1;
        return;
    }
    held.blocks.push(u32::try_from(blocks).unwrap_or(u32::MAX));
    held.groups.push(u32::try_from(groups).unwrap_or(u32::MAX));
}

/// Blocks per planned chunk since [`reset_chunk_plans`], in order.
pub fn chunk_blocks() -> Vec<u32> {
    CHUNK_PLANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .blocks
        .clone()
}

/// Table groups per planned chunk since [`reset_chunk_plans`], in order.
pub fn chunk_groups() -> Vec<u32> {
    CHUNK_PLANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .groups
        .clone()
}

/// Readings [`SERIES_CAP`] turned away, which [`chunk_blocks`] does not
/// hold. Zero means the series is the whole of what was planned.
pub fn chunk_plans_dropped() -> u64 {
    CHUNK_PLANS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .dropped
}

/// The most blocks any one chunk held, or zero if none was planned.
///
/// Exact whatever [`SERIES_CAP`] turned away, which is why the scalars
/// are kept beside the series rather than derived from it.
pub fn peak_chunk_blocks() -> usize {
    CHUNK_BLOCKS_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// The fewest blocks any one chunk held, or zero if none was planned.
pub fn least_chunk_blocks() -> usize {
    match CHUNK_BLOCKS_LEAST.load(std::sync::atomic::Ordering::Relaxed) {
        usize::MAX => 0,
        least => least,
    }
}

/// Blocks over every chunk planned since [`reset_chunk_plans`].
pub fn chunk_blocks_total() -> u64 {
    CHUNK_BLOCKS_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Chunks planned since [`reset_chunk_plans`], the series' own cap
/// included, so that the mean is `chunk_blocks_total / chunks_planned`
/// whether or not the series is whole.
pub fn chunks_planned() -> u64 {
    CHUNKS_PLANNED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget every chunk-plan reading, series and scalars together.
pub fn reset_chunk_plans() {
    use std::sync::atomic::Ordering;
    let mut held = CHUNK_PLANS.lock().unwrap_or_else(|e| e.into_inner());
    held.blocks.clear();
    held.groups.clear();
    held.dropped = 0;
    CHUNK_BLOCKS_PEAK.store(0, Ordering::Relaxed);
    CHUNK_BLOCKS_LEAST.store(usize::MAX, Ordering::Relaxed);
    CHUNK_BLOCKS_TOTAL.store(0, Ordering::Relaxed);
    CHUNKS_PLANNED.store(0, Ordering::Relaxed);
}

/// The most members being DECODED at once, anywhere in the process.
///
/// The breadth, as opposed to [`peak_lanes`]'s width. The two together
/// are the engine's thread count under `extract_parallel`: one worker
/// thread per member in flight, plus that member's lanes when it has
/// any. Counted rather than inferred from the breadth the caller asked
/// for, because a member below the offload floor is never dispatched at
/// all and the walk decodes it itself.
///
/// PROCESS-wide, for the same reason [`peak_workers`] is.
pub(super) static MEMBERS_NOW: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) static MEMBERS_PEAK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A dispatched member is being decoded for as long as this lives.
#[cfg(feature = "parallel")]
pub(crate) struct MemberGuard;

#[cfg(feature = "parallel")]
impl MemberGuard {
    pub(crate) fn enter() -> MemberGuard {
        use std::sync::atomic::Ordering;
        let now = MEMBERS_NOW.fetch_add(1, Ordering::Relaxed) + 1;
        MEMBERS_PEAK.fetch_max(now, Ordering::Relaxed);
        MemberGuard
    }
}

#[cfg(feature = "parallel")]
impl Drop for MemberGuard {
    fn drop(&mut self) {
        MEMBERS_NOW.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The most members decoded at once since [`reset_peak_members`].
pub fn peak_members() -> usize {
    MEMBERS_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forget the member high-water mark.
pub fn reset_peak_members() {
    MEMBERS_PEAK.store(
        MEMBERS_NOW.load(std::sync::atomic::Ordering::Relaxed),
        std::sync::atomic::Ordering::Relaxed,
    );
}
